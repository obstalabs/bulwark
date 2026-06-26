# Hardened mode — crash-safe, kernel-enforced read floor

```
bulwark run --hardened --allow '<glob>' [--allow '<glob>'...] -- <command>
```

Hardened mode enforces a default-deny read policy as a **Landlock floor in the
kernel** instead of via the fanotify supervisor. The agent may read only the
allowed paths (your grants + the runtime base set); every other read is denied
by the kernel. It is non-interactive and uses `--allow` grants like `--deny-all`,
with one difference: because Landlock is path-based and cannot enforce an
arbitrary glob, a grant that would **silently widen** to a broader subtree is
**rejected**, not quietly accepted. A grant must be a concrete path or a trailing
`/**` subtree — `'/var/log/app/**/*.log'` (which Landlock could only enforce as
all of `/var/log/app`) is refused with a message telling you to re-grant it
explicitly. A concrete grant that resolves **through a symlink** to a wider
directory is rejected for the same reason. This keeps the kernel floor exactly as
wide as the path you named, never wider.

## Why it exists: closing the fanotify fail-open

Bulwark's normal gate is fanotify: a userspace supervisor answers each open.
Verified limitation — if that supervisor is hard-killed (`SIGKILL`, crash, OOM,
power loss) while a read is held, the kernel releases the held read as *allowed*.
fanotify fails open on monitor death; this is documented kernel behavior, not a
Bulwark choice.

Hardened mode removes the supervisor from the critical path entirely:

1. Bulwark builds the allow set (runtime base set + your grants).
2. It applies a Landlock ruleset that denies all reads except those paths.
3. It sets `no_new_privs` and `exec`s into the agent — **same PID**.

After step 3 there is no Bulwark process. The restriction lives in the kernel,
bound to the agent and all its future children, for the agent's whole life.
There is nothing to kill, so `SIGKILL`/crash cannot widen access. Verified on
Linux 6.12 (Landlock ABI 6): with the launching process killed mid-run, the
floor continued to deny.

`no_new_privs` also means the agent cannot escalate around the floor via setuid
binaries — even a `sudo` inside the agent is denied.

## How it composes with the rest of Bulwark

A Landlock deny is **absolute** — Landlock has no userspace callback; it is a
static kernel ruleset. So the layers do not conflict, they nest:

- **Landlock (hardened mode) = the outer default-deny floor** — crash-safe, what
  the agent may read at all.
- **fanotify (the default gate) = an inner consent/audit layer** — interactive
  prompts, receipts, dynamic decisions, operating only within what is allowed.

For the CI / dispatch use case there is no human, so the static floor is the
whole policy and hardened mode is the right tool. For interactive use where you
want an operator prompt, the fanotify gate remains.

## What hardened mode requires — and does not do

- **It is a launcher, not a daemon.** Landlock restricts the process that
  applies it and its children, not arbitrary already-running processes. Bulwark
  must launch the agent; it cannot retro-fit a floor onto a process it did not
  start.
- **Reads only.** This floor governs file reads (the Bulwark boundary). It does
  not gate writes, execution, or the network.
- **Requires Landlock** (Linux 5.13+, best on recent kernels). Hardened mode
  refuses to start if Landlock is unavailable rather than running unprotected.
- **No interactive consent and no per-decision receipts** in this mode — the
  kernel enforces silently. Use the fanotify gate when you need the audit trail
  or a human prompt.

## Example: crash-safe ClickHouse triage

```sh
sudo bulwark run --hardened \
  --allow '/var/log/clickhouse-server/**' \
  -- triage-agent --investigate "query timeouts"
```

The triage agent reads the logs and runs; the data directory, credentials, and
every other path are denied by the kernel — and stay denied even if the agent's
parent is killed at the worst possible moment. Inspect the always-allowed
runtime base set with `bulwark base-set`.
