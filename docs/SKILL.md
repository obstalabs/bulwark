---
name: bulwark
description: "Kernel-boundary file-read gate for AI agent process trees — pause a protected file open at the Linux kernel and decide before any bytes reach the agent"
user-invocable: false
metadata: {"requires":{"bins":["bulwark"]},"platform":["linux"]}
---

# bulwark

A read gate for AI agent process trees. Launch an agent under Bulwark; when any
process in its tree opens a protected file, the Linux kernel pauses the open and
Bulwark decides — deny, or ask a human off-band — before a single byte reaches
the agent. Decisions are by inode, so a rename or symlink to a protected file is
still gated. Linux only (fanotify / Landlock); requires root.

**This tool is agent-operable on purpose.** An orchestrator agent dispatching a
sub-agent onto a sensitive host uses Bulwark to clamp what that sub-agent can
read — see "What this does NOT do" for the one rule that makes that safe.

## Install

```bash
curl -fsSL https://github.com/obstalabs/bulwark/releases/latest/download/bulwark-<version>-<arch>-unknown-linux-gnu.tar.gz | tar xz
sudo install -m 0755 bulwark /usr/local/bin/bulwark
```

Browse releases at https://github.com/obstalabs/bulwark/releases/latest.

## Commands

### bulwark doctor

Preflight: report whether this host can actually enforce — OS, root/CAP_SYS_ADMIN
for fanotify, kernel version, and Landlock for `--hardened`. Run it first.

**Flags:**
- `--format json` — output as JSON

**JSON output:**
```json
{
  "status": "healthy",
  "ok": true,
  "version": "0.7.0",
  "source": {"repo": "obstalabs/bulwark"},
  "checks": [
    {"name": "os-linux", "status": "pass", "ok": true, "required": true, "detail": "Linux"},
    {"name": "root-or-cap", "status": "pass", "ok": true, "required": true, "detail": "running as root (CAP_SYS_ADMIN available)"},
    {"name": "kernel", "status": "pass", "ok": true, "required": false, "detail": "6.12.0"},
    {"name": "landlock", "status": "pass", "ok": true, "required": false, "detail": "Landlock available (--hardened supported)"}
  ]
}
```

**Exit codes:**
- 0: every required capability present (this host can enforce)
- 1: a required capability is missing

### bulwark init

Write a default `Bulwark.toml` policy in the current directory so you can edit
what is protected. Idempotent: refuses to overwrite unless `--force`.

**Flags:**
- `--policy <FILE>` — path to write (default: `Bulwark.toml`)
- `--profile <NAME>` — start from a built-in profile (`default`, `dev`)
- `--force` — overwrite an existing policy file

**Exit codes:**
- 0: policy written
- 1: file already exists (use `--force`) or write failed

### bulwark run

Run a command under the read gate. Opens of protected inodes by the supervised
process tree are denied at the kernel (EPERM) before any bytes reach the reader.

**Flags:**
- `--protect <PATH>` — protect a path by inode (repeatable)
- `--profile <NAME>` / `--policy <FILE>` — use a built-in profile or a `Bulwark.toml`
- `--consent <static|socket|remote>` — deny by default, or ask an operator off-band
- `--deny-all` `--allow <GLOB>` — default-deny allowlist mode (CI/dispatch)
- `--hardened` — enforce the allowlist as a kernel Landlock floor (crash-safe)
- `--receipts <FILE>` — append one JSON-line receipt per decision

**Exit codes:**
- 0: the supervised command exited 0
- non-zero: the supervised command's exit code, or a setup error

### bulwark ssh

Run an agent on a REMOTE host under enforcement, with consent routed to the local
operator. Enforcement is on the remote kernel; SSH is only transport.

**Flags:**
- `--protect <PATH>` — protect a path on the remote host (repeatable)
- `--deploy <auto|never|scp|dist>` — how to obtain the remote binary if absent
- `--auto <VERDICT>` — answer every prompt non-interactively (CI)

**Exit codes:**
- 0: the remote agent exited 0
- non-zero: the remote exit code, or a transport/deploy error

### bulwark check

Report what the active policy decides for a path, without running anything.

**Flags:**
- `--profile <NAME>` / `--policy <FILE>` — policy to evaluate against
- `--format json` — output as JSON

**JSON output:**
```json
{"path": "/etc/shadow", "decision": "outside_prompt", "effect": "read DENIED"}
```

**Exit codes:**
- 0: classification printed
- 1: policy load error

### bulwark audit

Render a receipts file (the JSON-line decision log written by `run`) as a table
or one JSON object with counts and per-decision records.

**Flags:**
- `--format json` — output as JSON

**JSON output:**
```json
{
  "allow": 12,
  "deny": 3,
  "unparsed": 0,
  "decisions": [
    {"ts_ms": 1717000000000, "pid": 4011, "decision": "deny", "source": "static", "path": "/home/u/.ssh/id_ed25519", "ancestry": "cat(4011) <- bash(4000)"}
  ]
}
```

**Exit codes:**
- 0: receipts rendered
- 1: receipts file could not be read

### bulwark reset

Clear the integrity taint marker after an unclean restart or object drift, once
you have reviewed the audit event. Explicit operator acknowledgement.

**Exit codes:**
- 0: taint cleared (or nothing to clear)
- 1: state file could not be written

### bulwark base-set

Print the runtime base set: the read paths allowlist mode permits so a program
can execute (linker, libc, locale). These are allowed reads.

**Exit codes:**
- 0: base set printed

### bulwark consent

Answer one pending off-band consent request (operator side), connecting to the
consent socket of a running `bulwark run --consent socket`.

**Exit codes:**
- 0: a verdict was delivered
- 1: no socket / no pending request

## What this does NOT do

- **Does not modify a clamp to be wider on an agent's say-so.** A restraint tool
  is only safe to hand an agent if the lever is a ratchet. Tightening scope
  (adding `--protect`, narrowing an allowlist) is agent-initiated and free.
  Widening or removing a clamp must route through the off-band consent path
  (`--consent socket`), where a human answers over a channel the supervised tree
  cannot see or forge. An agent can clamp; it cannot un-clamp.
- **Does not control consequences, only gate reads.** It decides whether a process
  may open an inode — not use of data already read, environment-variable
  credentials, or network exfiltration. Pair it with an egress control.
- **Does not store or redact content.** It stops the open; it does not persist or
  scrub bytes already read.
- **Does not monitor a process it did not launch**, or a file descriptor opened
  before the gate was installed.
- **Does not execute on macOS or Windows.** Linux only (fanotify / Landlock).
- **Does not own the host's trust.** It reduces what an *agent* can access; the
  same root that runs it can stop it. A deliberate boundary, not a defense against
  a malicious administrator.

## Handoffs

- Output: structured per-decision receipts (JSON). Next: an audit/SIEM pipeline,
  or an orchestrator parsing `decision`/`path`/`ancestry` to confirm a clamp held.
- `doctor --format json` output is the preflight an orchestrator reads before
  dispatching an agent to a host — `ok:false` means do not rely on the gate here.
- Refused questions: whether the data an agent read should have been read (that is
  the operator's call), and anything about network egress (out of scope).

## Failure Modes

- **fanotify fails open on hard supervisor death.** If `bulwark run` is `SIGKILL`ed
  or crashes while a read is held, the kernel releases that held read as *allowed*
  (documented kernel behavior). A graceful `SIGTERM` fails closed. Distrust:
  "nothing leaked" after an unclean kill. Use `--hardened` (Landlock) where this
  matters — it removes the supervisor from the critical path.
- **Unclean restart / object drift → tainted mode.** After an unclean exit or a
  protected file changing identity, the next run denies protected reads until an
  operator runs `bulwark reset`. Distrust a run that printed `INTEGRITY TAINTED`
  until it is acknowledged.
- **Not root → cannot enforce.** Without `CAP_SYS_ADMIN`, `run` errors at setup
  rather than running ungated. Check with `bulwark doctor` first.

## Parsing examples

```bash
# Will this host enforce? (CI / pre-dispatch gate)
bulwark doctor --format json | jq -e '.ok'

# What does the policy decide for a path?
bulwark check /etc/shadow --format json | jq -r '.effect'

# How many denies in the receipts log?
bulwark audit receipts.jsonl --format json | jq '.deny'

# List every protected open that was denied, with the process chain:
bulwark audit receipts.jsonl --format json \
  | jq -r '.decisions[] | select(.decision=="deny") | "\(.path)\t\(.ancestry)"'
```
