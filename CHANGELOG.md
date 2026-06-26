# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.2] - 2026-06-XX

Security-hardening release. The read gate was put through repeated adversarial review —
attacking the gate, fixing what was found, then attacking the fixes — until two
consecutive rounds found nothing a supervised agent could reach. Around a dozen-and-a-half
issues were closed, each with a regression test that fails on the pre-fix code and passes
on the fixed code, verified on real hardware (Linux kernel 6.12, macOS 26). No CLI behavior
changes for existing users; all changes tighten enforcement or correct fail-open paths.

### Fixed
- **Grants are gated by inode identity, not path.** Allow-list (`--deny-all`) grants are
  snapshotted by `(inode, generation)` at launch, so a foreign file hardlinked, renamed, or
  (via inode-number reuse) swapped into a granted location is denied. macOS grants are
  gated by inode as well, not by path-beneath the grant root.
- **`--protect <dir>` covers nested and post-launch files** under the directory, not only
  the entries present at launch.
- **`--hardened` grants can no longer silently widen.** A grant that would floor a broader
  subtree than its pattern names is rejected; grants must be absolute and may not resolve
  through a symlink in any path component (the prefix is opened with
  `openat2(RESOLVE_NO_SYMLINKS)`).
- **Off-band consent is reparent-proof and live-checked.** The consent channel refuses an
  answerer that is part of the supervised tree (by cgroup membership, not ancestry alone)
  and refuses a peer that has exited before its identity can be verified — so a supervised
  process cannot answer its own consent.
- **Fail-closed corrections.** The fanotify permission queue is unbounded
  (`FAN_UNLIMITED_QUEUE`) so a flood applies backpressure instead of overflowing and failing
  open; an in-tree open whose event-fd `fstat` fails is denied; the worker drop sets
  `PR_SET_NO_NEW_PRIVS` so a dropped process cannot regain root via a setuid binary; the
  remote consent run directory uses an unguessable name and fails closed on a pre-existing
  path or control FIFO.

## [0.7.1] - 2026-06-XX

macOS install becomes zero-setup: the gate ships with the CLI and the CLI finds it
automatically, so `brew install obstalabs/tap/bulwark` gives kernel enforcement, not
just the binary. No CLI behavior changes for existing users; Linux is unchanged.

### Added
- macOS CLI auto-discovers the signed Endpoint Security gate beside its own install
  location (`<bin>/../libexec/bulwark_es_gate.app`, then beside the binary), so no
  `BULWARK_MACOS_ES_GATE` environment variable is needed for a packaged install. The
  variable still works as an explicit override. `bulwark doctor` reports which path it
  resolved.

### Changed
- macOS release tarballs are now self-contained: each bundles the signed, notarized,
  stapled `bulwark_es_gate.app` alongside the CLI. The Homebrew formula installs both;
  the gate no longer has to be fetched or built separately.

### Docs
- New macOS guides: Full Disk Access (why it's required) and troubleshooting, running
  under sudo (and why not passwordless), choosing a mode and wrapping an agent runner,
  and a documentation index.

## [0.7.0] - 2026-06-06

Makes Bulwark agent-operable (ANCC-compliant): an orchestrator agent can read its
contract and apply a read-clamp to a sub-agent programmatically. Adds the
machine-facing surface that requires — and the ratchet that makes it safe.

### Added
- `bulwark init` — write a default `Bulwark.toml` policy in the current directory
  (refuses to overwrite without `--force`).
- `bulwark doctor` — preflight: report whether this host can enforce (OS,
  root/`CAP_SYS_ADMIN`, kernel version, Landlock for `--hardened`). Exit 0 when
  every required capability is present. `--format json`.
- `--format json` on `bulwark audit` (counts + per-decision records) and
  `bulwark check` (the classification as one object) — the agent interface.
- `docs/SKILL.md` (in bulwark-dist): the ANCC agent contract, documenting the
  clamp ratchet — an agent can tighten a clamp freely, but widening or removing
  one routes through off-band consent. An agent can clamp; it cannot un-clamp.

Makes `bulwark ssh` operationally complete: the consent prompt now runs on the
local operator's machine, and the gate binary auto-deploys to a remote host that
does not have it.

### Added
- `bulwark ssh` now runs the consent prompt **on the local operator's machine**
  instead of auto-answering on the remote host. The remote host runs only the
  gate; prompts (host, path, process ancestry) stream back over SSH to a local
  loop, and the operator's `allow-session`/`deny` reply travels back over a
  separate control channel — SSH is transport, the operator UI is local, the
  enforcement point stays remote, and the control lanes stay separate from the
  agent's own stdio. `--auto <verdict>` still answers non-interactively for CI.
- `bulwark ssh --deploy <auto|never|scp|dist>`: auto-deploy the `bulwark` binary
  to a remote host that does not have it. `auto` (default) uses an existing
  remote binary, else scp's the local one when it is arch-compatible, else
  fetches the matching `bulwark-dist` release tarball and verifies its sha256
  before running. `never` requires an existing remote binary; `scp`/`dist` force
  a path. A macOS binary is never scp'd to Linux (the dist path covers the common
  cross-OS case); a checksum mismatch is a hard failure.

## [0.5.0] - 2026-06-05

Adds an integrity circuit-breaker that bounds the blast radius after an unclean
recovery, plus `bulwark reset` to acknowledge and clear a taint.

### Added
- Integrity circuit-breaker: Bulwark records each run's integrity context (a
  generation counter, a clean-shutdown marker, the policy epoch, and the inode
  identity of every protected object) in a persistent state file. On the next
  run it enters **tainted mode** if the prior run ended uncleanly (no
  clean-shutdown marker, e.g. a `SIGKILL` or crash) or if a protected path now
  resolves to a different inode (object-identity drift). A tainted run denies
  protected reads by default and, in socket mode, bypasses the allow-session
  cache so every protected open is freshly decided — no pre-taint grant
  survives. The taint is sticky and persists across restarts until an operator
  acknowledges it; a taint audit receipt (`source: "integrity"`) records the
  reason. This bounds the blast radius after an unclean recovery; it does not
  change the documented fail-open behaviour of a held event at the moment of a
  hard kill.
- `bulwark reset` clears the integrity taint marker after operator review.

## [0.4.0] - 2026-06-05

Adds remote enforcement over SSH — run an agent on a remote host with the gate
on the remote kernel and consent routed to the local operator.

### Added
- Remote enforcement (`bulwark ssh user@host --protect <paths> -- <agent>`):
  run an agent on a remote host with enforcement on the *remote* kernel (SSH is
  only transport) and consent routed back to the local operator. Uses a
  decision/prompt split that respects the kernel deadline: a protected read is
  denied immediately, an async prompt surfaces locally, and an `allow-session`
  reply lets the next read of that inode through from cache. Grants are scoped
  per identity/session/policy-epoch, and prompt/verdict travel on control lanes
  separate from the agent's stdio. Prototype-grade: SSH provides transport/auth,
  not yet an mTLS-signed trust channel; assumes the `bulwark` binary is present
  on the remote host. See `docs/remote.md`.

## [0.3.0] - 2026-06-04

Adds hardened mode — a crash-safe, kernel-enforced read floor via Landlock.

### Added
- Hardened mode (`bulwark run --hardened --allow '<glob>' -- <cmd>`): enforces
  the allowlist as a kernel-level Landlock read floor instead of via the
  fanotify supervisor. Crash-safe — the restriction lives in the kernel on the
  agent process itself, so there is no supervisor to kill and `SIGKILL`/crash
  cannot widen access. Non-interactive; `no_new_privs` also blocks escalation
  around the floor. Requires Landlock (Linux 5.13+). See `docs/hardened-mode.md`.

## [0.2.0] - 2026-06-04

Adds default-deny allowlist mode for CI/CD dispatch, and hardens the gate to
fail closed on graceful shutdown and cover bind-mounted aliases.

### Added
- Default-deny allowlist mode for non-interactive (CI/CD) use:
  `bulwark run --deny-all --allow '<glob>' -- <cmd>` permits the supervised tree
  to read only the granted paths plus a runtime base set, denying every other
  read with no prompt. `bulwark base-set` prints exactly what the base set
  allows. See `docs/ci-allowlist.md` for a ClickHouse-triage worked example and
  CI snippets. Allow-list mode marks every mounted filesystem so default-deny
  holds across separate mounts (tmpfs, data volumes), not just the root.

### Changed
- Gate now marks the whole filesystem (`FAN_MARK_FILESYSTEM`) instead of a
  single mount, so a `mount --bind` alias of a protected inode is gated too.
- Graceful termination fails closed: on `SIGTERM`/`SIGINT`/`SIGHUP`, the
  supervisor denies any outstanding read before exiting. (Hard kills —
  `SIGKILL`, crash, OOM, power loss — remain an inherent fanotify limitation:
  the kernel releases held permission events as allowed on fd close. A
  kernel-enforced floor for that case is planned, not yet shipped.)
- Receipts gained a `shutdown` decision source for reads denied during teardown.

## [0.1.0] - 2026-06-03

First release — the Linux read-gate MVP. Gates file opens by a supervised
process tree at the kernel, by inode, with off-band operator consent. Linux
only; macOS (Endpoint Security) and remote consent are tracked for later.

### Added
- Linux fanotify `FAN_OPEN_PERM` read gate (MVP): `bulwark run --protect <path>
  -- <cmd>` supervises a process tree and denies opens of protected inodes,
  returning `EPERM` to the reader before any bytes are read.
- Inode-based protection (`dev + ino`) that defeats symlink and rename bypass.
- Process-tree attribution from `/proc/<pid>/stat`; only opens by the supervised
  tree are judged.
- Per-decision JSON-line receipts (pid, dev+ino, decision, path, ancestry,
  reason).
- `Bulwark.toml` policy schema (workspace allow globs, protected globs,
  `default.outside_workspace`, `default.on_timeout`) with a shipped default
  profile and a built-in `dev` profile.
- Deterministic glob matcher (`*`, `?`, `**`, `~/` expansion) — no regex
  dependency.
- `bulwark run --profile <name>` / `--policy <file>` to select policy;
  `bulwark allow <glob>` / `bulwark deny <glob>` to mutate it;
  `bulwark audit <receipts>` to render the decision log.
- Off-band interactive consent (`--consent socket`): a protected open is held at
  the kernel while the operator is asked over a Unix socket the agent has no
  descriptor on; `bulwark consent` answers it. Verdicts: allow-once,
  allow-session (inode-cached), deny, deny-forever (persisted to policy).
  Off-band is enforced structurally — `SO_PEERCRED` rejects any answerer inside
  the supervised tree, so an agent cannot approve its own access. Timeout denies
  (kernel-deadline safe). Receipts now record the decision source
  (operator/cache/timeout/static). Policy file name accepted case-insensitively
  (`Bulwark.toml` or `bulwark.toml`).
