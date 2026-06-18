# macOS: permissions, how the gate is wired, and common problems

Bulwark's macOS gate runs as a **root-launched, signed Endpoint Security (ES)
process** — no kernel extension, no system extension, nothing installed into the OS.
That design needs two privileges, and getting them right is the difference between
"it works" and "it silently does nothing." This page explains *why* each is needed,
the one setup gotcha worth knowing, and how to diagnose the handful of errors people
actually hit.

## What the gate needs, and why

**1. Root.** Endpoint Security clients must be privileged — macOS only lets a root
process subscribe to `ES_EVENT_TYPE_AUTH_OPEN` (the event Bulwark answers to allow or
deny a file open). This is an Apple platform rule, not a Bulwark choice. So you run
`sudo bulwark run ...`. (Tempted to make that passwordless? Read
[docs/macos-sudo.md](macos-sudo.md) first — on macOS the agent runs as root, so a
`NOPASSWD` rule for `bulwark` is a root-shell hole.)

**2. Full Disk Access (FDA) for the terminal that launches Bulwark.** This is the one
that surprises people — *"a security tool is asking for Full Disk Access?"* Here's the
honest reason: macOS gates the **creation of an ES client** behind FDA. Without FDA,
`es_new_client()` returns `ERR_NOT_PERMITTED` and the gate can't start at all. It is
not that Bulwark wants to read your disk — it never reads file *contents*; it decides
*allow/deny on inode* and the bytes never flow through it. FDA is simply the TCC
permission Apple attaches to the ES capability. No FDA → no gate.

> Bulwark reports FDA as an **advisory** in `bulwark doctor`, because macOS only
> *proves* the grant when `es_new_client()` actually runs. A green doctor with the FDA
> advisory still means "grant it or the gate won't start."

## The one gotcha: FDA is granted per *terminal app*, and `sudo` complicates it

Full Disk Access is granted to an **application** (Terminal.app, iTerm, Ghostty,
WezTerm, …), not to a shell or a window. Two consequences:

- The grant applies to the **terminal app you launch Bulwark from**. If you run
  Bulwark from iTerm, iTerm needs FDA — granting it to Apple's Terminal.app does
  nothing for iTerm.
- After granting FDA, **fully quit and reopen** the terminal app. The permission only
  applies to newly-launched processes; an already-running terminal won't pick it up.
- Under `sudo`, macOS may attribute the FDA grant to a different *responsible process*
  than your terminal. If `sudo bulwark ...` still reports `ERR_NOT_PERMITTED` even
  though the terminal has FDA, either grant FDA to your shell binary
  (e.g. `/bin/zsh`), or start a root login shell first (`sudo -i`) and run Bulwark
  from there.

### Recommended (not required): a dedicated terminal for gated runs

You do **not** need a separate terminal — your normal one with FDA works. But granting
Full Disk Access to your everyday terminal is a broad permission, and an ES client in
AUTH mode holds each `open()` until it answers. Many people prefer a **dedicated
terminal profile/app used only for `bulwark run`**: it keeps the FDA grant off your
daily driver and keeps gated sessions separate from the agent sessions you're running
elsewhere. Treat it as hygiene, not a requirement.

## How the wiring fits together (so nothing surprises you)

```
sudo bulwark run --protect <path> -- <agent>
      │
      ├─ launches the signed ES edge (bulwark_es_gate.app) as root
      │     └─ es_new_client()      ← needs FDA; fails with code 4 (ERR_NOT_PERMITTED) without it
      ├─ subscribes to AUTH_OPEN     ← the kernel now pauses each open() by the tree
      ├─ starts <agent> STOPPED, resumes it only once the edge is ready
      └─ each open() by the tree → edge answers allow/deny by inode → kernel proceeds
```

- **No system extension is installed.** The gate is a normal (privileged) process.
  Recovery is just `sudo pkill bulwark_es_gate` — there is no OS state to clean up.
- **Crash posture (honest):** if the ES edge dies mid-run, enforcement stops (the
  kernel releases its AUTH_OPEN subscription) until the agent exits. macOS has no
  Landlock-style floor, so unlike Linux `--hardened`, a killed gate fails *open* for
  an already-running agent. See [docs/macos.md](macos.md) for the full crash-posture
  discussion.

## Common problems → what they mean

| You see | Cause | Fix |
|---|---|---|
| `es_new_client failed: 4` and `ES edge exited before readiness: exit status: 66` | The launching terminal lacks **Full Disk Access** (`ERR_NOT_PERMITTED`). | Grant FDA to the terminal app (System Settings → Privacy & Security → Full Disk Access), **fully quit + reopen** it. If still failing under `sudo`, grant FDA to the shell binary or use `sudo -i`. |
| `... is not an executable file` with a `~` in the path | The shell didn't expand `~` (it stays literal inside double quotes). | Use `$HOME` instead of `~` inside quotes, or don't quote the path. With a packaged install you normally don't set this at all (the CLI finds the gate automatically). |
| `cat: <file>: No such file or directory` | The file you tried to read **doesn't exist** — this is not a gate result. | Test `--protect` against a file that actually exists. A gate denial reads `Operation not permitted`, not `No such file`. |
| `doctor` says `no ES edge found` | Neither auto-discovery nor `BULWARK_MACOS_ES_GATE` located the gate bundle. | Use the packaged install (`brew install obstalabs/tap/bulwark`) so the gate ships beside the CLI, or set `BULWARK_MACOS_ES_GATE` to the gate binary. |
| The agent read a protected file anyway | The gate never started (check for the `AUTH_OPEN gate live` line), or the path wasn't actually protected. | Confirm `bulwark doctor` is fully green and you see `[bulwark-es] AUTH_OPEN gate live ...` before the agent runs. No live line → the gate isn't enforcing. |

## The 30-second sanity check

```sh
sudo bulwark doctor                    # every line [ok]; FDA advisory is fine
sudo bulwark run --protect ~/.ssh -- bash -c 'cat ~/.ssh/<a-real-key> 2>&1 | head -1'
# expect:  ... Operation not permitted
```

If `doctor` is green and the read is denied, your setup is correct. If the read is
*allowed*, it's almost always the FDA grant not reaching the gate process — re-read the
`sudo`/FDA note above.
