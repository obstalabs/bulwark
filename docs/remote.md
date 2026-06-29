# Remote enforcement — Bulwark over SSH

```
bulwark ssh user@host --protect <path> [--protect <path>...] -- <agent>
```

When an agent runs on a remote host, the `open()` happens on the *remote*
kernel. A local guard sees only encrypted SSH traffic — it cannot tell whether
the agent is reading `/etc/shadow` or a harmless log. So enforcement must run on
the remote machine. `bulwark ssh` bootstraps the gate there; SSH is only
transport.

## The kernel-deadline problem, and the split that solves it

The consent round-trip now crosses the network *and* human thinking-time. But
fanotify has a kernel response deadline — you cannot hold a remote `open()`
paused while a local human deliberates (a blocked read on production is its own
incident). Bulwark splits the decision from the prompt:

1. **The remote gate answers the kernel immediately** from a session cache. If
   the inode is not already allowed, it **denies at once** — the agent gets
   "permission denied" and never hangs.
2. **In parallel it emits an async prompt** to the local operator (host, path,
   process ancestry). The operator answers `allow-session`, which updates the
   cache for next time.

So the first touch of a protected file is an immediate deny plus a prompt; once
you grant `allow-session`, the next read of that inode passes from cache with no
network round-trip. This is the same default-deny-on-timeout discipline used
locally, applied across the wire.

## Control lanes, not terminal chatter

Prompts and verdicts travel on control lanes that are separate from the agent's
own stdio:

- **prompt lane** — remote gate → local operator (structured consent events)
- **verdict lane** — local operator → remote gate (`allow-session` replies)
- **data lane** — the agent's stdin/stdout/stderr, untouched

The operator never types into a shared terminal stream with the agent.

## Grants are scoped, not bare inodes

An `allow-session` does not authorize "this inode for anyone." Each grant is
scoped to the requester identity (uid), the session, and the policy epoch — so a
different process in the same remote environment touching the same file does not
inherit the grant, and a policy change invalidates old grants.

## Carrying hivebus key material at dispatch (optional)

A freshly dispatched remote worker often needs a trustworthy *first* key
introduction — the architect's public key to verify signed messages, and its own
signing identity to answer with. `bulwark ssh` can carry this at dispatch, as
pure transport (it makes no trust decisions about the keys):

```
bulwark ssh user@host --protect <path> \
  --hivebus-architect-pub architect.pub \
  --hivebus-worker-seed-generate \
  -- <agent>
```

- `--hivebus-architect-pub <FILE>` relays a base64 ed25519 **public** key (the
  form hivebus `answer --print-public-key` emits) to the remote.
- `--hivebus-worker-seed-generate` generates a **fresh per-dispatch** worker
  ed25519 seed, places it on the remote, and prints the worker's pinnable public
  fingerprint locally so you can pin it on the hivebus side **before** first
  contact.

Both files land under `{remote_run_dir}/hivebus/`:

| file            | mode | owner            | what it is                          |
|-----------------|------|------------------|-------------------------------------|
| `architect.pub` | 0644 | gate uid (root)  | architect public key (relayed)      |
| `worker.seed`   | 0600 | gate uid (root)  | fresh worker signing seed (secret)  |

Two properties make this safe:

- **The seed never appears in argv.** Each value is streamed over a separate SSH
  session's stdin to `tee` — it is never an argument on the local `ssh` command
  line or in a remote `bash -c`, so it never shows up in any process listing.
- **Freshness is the security property.** A new seed is generated every dispatch;
  no key is reused across hosts or runs. The seed is the worker's *own* identity,
  not an operator secret withheld from the agent — so root-owned `0600` is key
  hygiene (keep other remote users out), not secret isolation.

Receipts record the dispatch by **fingerprint only** — seed bytes never reach a
receipt. With neither flag set, `bulwark ssh` behaves exactly as before: no key
handoff, byte-identical remote script.

> The owner is the gate uid — root by default, or the `--worker-uid` account when
> the worker is dropped (below): the seed is `chown`ed to it so the unprivileged
> agent can read its own key, same path and mode.

## Drop the remote worker to an unprivileged uid

By default the remote gate runs `sudo bulwark run ... -- <agent>`, so the agent
inherits **root**. That is convenient but it means a misbehaving agent can
`SIGKILL` its own supervisor — and fanotify has a kernel-documented residual: when
the supervisor dies, the kernel releases any held read as *allowed*. A root agent
can reach that leak.

`--worker-uid` closes the agent's path to it:

```sh
bulwark ssh user@prod-host --worker-uid 1000 \
  --protect /etc -- claude
```

The gate **stays root** (it must, to hold the fanotify fd), but the agent is
dropped to uid 1000 before it runs. An unprivileged agent **cannot signal the root
supervisor**, so it cannot trigger the fail-open — the gate stays up for the
agent's whole life. The drop is permanent (a post-drop attempt to regain root
fails, and a botched drop refuses to exec rather than run the agent half-dropped).

- The account **must already exist** on the remote host (`--worker-uid` is the
  "bring your own account" form). For zero setup, use `--auto-worker-uid` below.
- Honest scope: this closes the **agent-reachable** SIGKILL escape. It does **not**
  fix the inherent fanotify-on-crash residual itself (an external `kill -9 root` or
  a power loss still releases a held read) — that is what `--hardened` (the
  kernel-enforced Landlock floor) closes. The two are complementary.

### Zero setup: `--auto-worker-uid`

If you do not want to pre-create an account, `--auto-worker-uid` lets bulwark pick a
free unprivileged uid on the remote and drop the agent to it:

```sh
bulwark ssh user@prod-host --auto-worker-uid \
  --protect /etc -- claude
```

The agent runs as an **anonymous** uid — bulwark scans for a free number (checked
with `getent`) and `setuid`s to it. **No account is created**, so there is nothing
to tear down and nothing to orphan: when the dispatch exits, the uid is simply
unused again. The chosen uid is recorded in the dispatch receipt (the auditable
trace). It gives the same protection as `--worker-uid` (the kill check is numeric —
a non-root agent cannot signal the root gate whether or not the uid has a name).

- The dropped agent gets `HOME`/`USER`/`LOGNAME` in its environment, so tools that
  would otherwise look up a passwd entry behave normally. A workload that *hard*
  requires a real `/etc/passwd` account should use `--worker-uid <existing-uid>`.
- `--auto-worker-uid` and `--worker-uid` are mutually exclusive.

## Crash-safe remote: `--hardened`

The default remote path uses the fanotify supervisor, which has a kernel residual:
if the gate dies while a read is held, the kernel releases that read as *allowed*.
`--worker-uid` stops the **agent** from triggering it; `--hardened` removes the
residual itself.

```sh
bulwark ssh user@prod-host --hardened \
  --allow '/var/log/**' -- claude
```

Hardened mode is **allow-list** (the agent may read only the granted globs plus the
runtime base set) and **crash-safe**: the remote `bulwark run --hardened` installs a
**Landlock** read floor in the kernel and then *becomes* the agent — there is no
supervisor to kill, and `SIGKILL`/crash/power-loss cannot widen access. It is the
same floor as local `bulwark run --hardened`, applied by the remote kernel.

- **Allow-list, not deny-list.** `--hardened` uses `--allow <glob>`, and `--protect`
  is rejected under it — they are opposite modes. Same flag grammar as local.
- **Preflight.** Before launching, `bulwark ssh --hardened` runs
  `bulwark landlock-check` on the remote; a host without Landlock (Linux < 5.13)
  fails up front with a clear message rather than silently running un-hardened.
- **Non-interactive.** There is no consent prompt in hardened mode — the floor is
  static at launch. (Use the default `--protect` path when you want a human in the
  loop.) `--worker-uid` does not combine with `--hardened` (the floor needs no
  privilege drop — there is no supervisor to protect).

Together: `--worker-uid` (the agent can't kill the gate) and `--hardened` (even if
the gate dies, the kernel keeps denying) are the two halves of a crash-safe remote.

## Gate delivery vs agent delivery

These are two different things, and Bulwark OSS handles only the first.

- **The gate** — Bulwark can bootstrap *itself* onto a remote host over SSH (the
  `--deploy` path), so the kernel-level enforcement exists where the `open()`
  happens.
- **The agent** — the command after `--` (`claude`, `codex`, your own script) is the
  workload Bulwark supervises. **Bulwark OSS does not deliver it.** It is executed as
  a normal remote command inside the gated process tree, so the remote host must
  already be able to run it (installed on `PATH`, or provided by your own
  provisioning).

In short:

- Bulwark may deliver the gate.
- Bulwark does **not** deliver the agent.
- The agent runs as a normal remote command, inside the gated tree.

This is a deliberate boundary: Bulwark is a read-gate for a process tree, not a
payload-delivery mechanism. Because of it, an agent binary or installer you place on
the host is a persistent footprint — the gate leaving no trace does not make the
*whole operation* traceless.

**Trace-free agent streaming** — delivering the agent into the already-gated remote
session without leaving an executable on disk, gated from its first instruction — is
planned for **Bulwark Pro** (the "Ephemeral Agent Runtime"). No public timeline is
committed yet.

## Honest limits (prototype-grade)

This is the first slice of the remote tier, proven end-to-end. It is not yet the
finished production trust channel:

- **Transport and auth are SSH.** The control lanes are not yet wrapped in an
  mTLS-signed, time-bounded grant channel — that (signed verdicts, `expires_at`,
  mutual host authentication) is the production hardening, and a follow-up.
- **The gate binary delivery is best-effort over SSH.** Bulwark can bootstrap the
  gate onto a bare host (`--deploy auto` uses an existing remote `bulwark`, else
  `scp`s the local binary when arch-compatible, else fetches the matching release).
  This depends on the remote having the tools that path needs (e.g. `curl`/`tar`
  for the dist fetch); a fully self-contained, trace-free in-memory delivery is a
  follow-up. The *agent* is a separate matter — see "Gate delivery vs agent
  delivery" above.
- **The interactive local operator UI is minimal.** The prototype can auto-answer
  (`--auto allow-session`) for CI; a richer operator client is a follow-up.
- **Remote gate death** on the *default* (`--protect`) path has the fanotify
  fail-open residual (a hard kill while a read is held releases it as allowed);
  `--worker-uid` bounds it by stopping the agent from causing the kill. The
  crash-safe answer is `--hardened` (above) — the Landlock floor survives gate
  death entirely. Use `--hardened` for unattended dispatch where the worst case
  includes the gate dying at the wrong moment.

Enforcement on the remote kernel, consent at the local operator, default-deny
that respects the kernel deadline — the core of "TCC for AI agents over SSH" —
is real and verified. The trust channel around it is the work that turns this
preview into the enterprise tier.
