# macOS Quickstart

Bulwark's macOS gate uses a root-launched, signed Endpoint Security edge. No
system extension is installed; recovery is `sudo pkill bulwark_es_gate`.

**macOS docs map** — start here, then go deeper as needed:

- This page — quickstart, build/run, crash posture, consent divergence.
- **[Permissions & troubleshooting](macos-permissions.md)** — why Full Disk Access is
  required, how the gate is wired, and the common setup errors (`es_new_client failed:
  4`, etc.). Read this first if anything doesn't work.
- **[Running under sudo](macos-sudo.md)** — why root is needed and **why not to make it
  passwordless** (on macOS the agent runs as root, so a `NOPASSWD` rule is a root hole).
- **[Behavior matrix](macos-behavior-matrix.md)** — what is/isn't supported on macOS
  vs Linux at a glance.

## Crash posture (honest limitation)

The macOS gate is **not crash-safe** the way Linux `--hardened` mode is. On Linux,
`--hardened` installs a Landlock LSM floor that the kernel enforces on the agent
process itself — if the supervisor dies, the restriction remains. **macOS has no
Landlock analog.** If the Endpoint Security edge dies (crash, kill, panic), the
kernel releases its `AUTH_OPEN` subscription and, for a brief window before the
supervisor reaps the tree, opens by the agent are **allowed** (the kernel
default-allows when no ES client is subscribed). The supervisor watches the edge
and SIGKILLs the supervised tree the instant it sees the edge exit, but that
detection is not instantaneous, so a determined external killer can race that
window.

**What is closed: the agent cannot trigger this itself.** By default a would-be-root
agent is dropped to the invoking user (see below), and an unprivileged agent
**cannot** `SIGKILL` the root edge — so it cannot open the fail-open window on its
own. Verified on macOS 26: an unprivileged supervised agent's `kill -9` of the edge
returns `Operation not permitted`, and the protected read stays denied. The residual
is an **external** root process killing the edge, which is outside the agent's reach
(a host with a hostile root process is already compromised by any measure). Keep the
agent unprivileged (the default; `--allow-root` opts out) so this stays closed, and
prefer an unattended/CI agent that does not need root at all.

This gap is inherent to the ES interface — there is no kernel-enforced macOS floor
today — and is documented rather than hidden.

**Two further macOS residuals, stated plainly:**

- **The privilege drop is not irreversible on macOS.** On Linux the drop sets
  `no_new_privs`, so a dropped agent cannot regain root by `exec`ing a setuid-root
  binary. macOS has no equivalent primitive, so a dropped agent that execs a
  setuid-root binary *can* regain root — and a re-rooted agent could then `SIGKILL`
  the edge (re-opening the window above). The mitigations that still hold: the agent
  runs unprivileged for its own opens, and the ES membership set lives in the gate's
  memory (not an agent-writable filesystem), so a re-rooted agent cannot rewrite tree
  membership the way a Linux root agent can rewrite its cgroup. For an untrusted macOS
  agent, do not place setuid-root binaries on its path.
- **Off-band consent membership is by ancestry on macOS.** The consent socket refuses
  an answerer that is part of the supervised tree; on Linux that test uses cgroup
  membership (a double-forked orphan is still caught), but on macOS it currently uses
  the process-ancestry walk, which a double-fork sheds. The Endpoint-Security
  process-set analog of the Linux cgroup check is planned. Until it lands, prefer the
  static deny-list path on macOS for adversarial agents rather than live consent.

## Build the CLI and ES edge

```sh
cargo build
cd macos-es-proof
./build-gate-bundle.sh
export BULWARK_MACOS_ES_GATE="$PWD/bulwark_es_gate.app/Contents/MacOS/bulwark_es_gate"
```

The edge bundle must carry `com.apple.developer.endpoint-security.client`, be
signed, notarized, stapled, and launched from a terminal with Full Disk Access.

## Preflight

```sh
sudo -E ../target/debug/bulwark doctor
sudo -E ../target/debug/bulwark doctor --format json
```

`doctor` fails when the OS, root privilege, ES edge path, executable bit, or ES
entitlement is missing. Full Disk Access is reported as an advisory because macOS
only proves it when `es_new_client` starts.

## Static deny-list run

```sh
sudo -E ../target/debug/bulwark run \
  --protect "$HOME/.ssh" \
  --receipts macos-receipts.jsonl \
  -- /bin/bash -c 'cat "$HOME/.ssh/id_ed25519"'
```

The supervised read is denied and a receipt is appended. An unsupervised process
reading the same file is unaffected because Bulwark only governs the tree it
launches.

```sh
../target/debug/bulwark audit macos-receipts.jsonl
../target/debug/bulwark audit macos-receipts.jsonl --format json
```

## Consent (platform divergence)

bulwark's consent model differs by platform, by design. **This divergence is
intentional and is documented here rather than hidden.**

| | Linux (fanotify) | macOS (Endpoint Security) |
|---|---|---|
| Default (`--consent static`) | Protected inodes deny by default, no prompt. | **Same** — protected inodes deny by default, no prompt. (Proven on real hardware.) |
| Live socket consent (`--consent socket`) | **Supported** — a running supervisor binds a Unix socket; you answer from another terminal with `bulwark consent --verdict <v>` while the agent runs. | **Not available** — `--consent socket` and `bulwark consent` return an error on macOS. |
| Operator allow grants (`allow-once` / `allow-session`) | A live operator (or the session cache) can grant an allow for a protected inode mid-run. | **Not available yet.** macOS today is **deny-only** for protected inodes: there is no operator path to grant an allow (no live socket, no static-allow flag, no `Bulwark.toml` pre-allow). The edge *can* consume seeded allow verdicts, but nothing currently produces them on macOS. |

**Why macOS is deny-only today, and why a live loop is hard:** an Endpoint
Security `AUTH_OPEN` handler must answer the kernel within a hard deadline or the
kernel kills the client (and stalls every watched open until it dies). A live
"wait for a human" prompt cannot satisfy that deadline. The macOS gate therefore
needs a **decision/prompt split** — answer the kernel immediately (deny) and
update an allow cache asynchronously — the same model the remote Linux gate uses.
That split, plus an operator grant channel to drive it, is **future work**. Until
it lands, the macOS gate provides:

- **`--protect` deny-by-default** (the quickstart above) — proven, and
- **default-deny `--deny-all --allow`** allow-list mode (below) — proven,

but **not** mid-run operator allow grants for individual protected inodes.

The verdict vocabulary (`allow-once`, `allow-session`, `deny`, `deny-forever`) is
shared across platforms; on macOS only `deny` is currently reachable for the
`--protect` path.

## Default-deny allow-list run

```sh
mkdir -p /tmp/bulwark-allowed /tmp/bulwark-denied
echo ok >/tmp/bulwark-allowed/readme.txt
echo no >/tmp/bulwark-denied/secret.txt

sudo -E ../target/debug/bulwark run \
  --deny-all \
  --allow /tmp/bulwark-allowed/** \
  -- /bin/bash -c 'cat /tmp/bulwark-allowed/readme.txt; cat /tmp/bulwark-denied/secret.txt'
```

Only the grant plus the printed macOS runtime base set are readable:

```sh
../target/debug/bulwark base-set
```
