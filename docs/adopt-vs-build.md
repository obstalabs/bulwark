# Adopt-vs-Build Evaluation

**Status:** Decided — 2026-06-02
**Decision:** BUILD a standalone fanotify supervisor on Linux. REUSE Santa's *architecture* (not code) as the macOS reference. Do NOT wrap Sandlock, Fence, or YoloFS.
**Gate result:** Linux-core build child PROCEEDS. macOS child PROCEEDS as a Santa-shaped Endpoint Security client. No build child is descoped.

---

## Why this evaluation existed

Bulwark's wedge is an **interactive, per-file READ gate** that pauses an `open()` at the kernel, attributes it to a process subtree, decides by **inode** (not string path), prompts a human operator, and logs a receipt. Reimplementing a static sandbox layer would waste that wedge. So before any build: does an existing tool already give us the interactive read-gate primitive — enough to wrap or integrate rather than rebuild?

Operator steer (2026-06-02): *"if Sandlock gets you 70% on Linux, wrap or integrate it instead of reimplementing the static sandbox layer."*

## The four capability criteria

Every candidate was scored against the exact primitives Bulwark needs:

- **(a) Interactive per-file OPEN gate** — pause a specific `open()` and ask a human allow/deny *at that moment* (vs. a static ruleset applied at launch).
- **(b) Userspace allow/deny hook** — a userspace decision point on file access (the `fanotify FAN_OPEN_PERM` shape).
- **(c) Process-tree tracking** — attribute the access to `claude → bash → cat` lineage.
- **(d) Inode-based decision** — decide on the resolved inode, defeating symlink/hard-link name tricks (vs. string path/glob).

## Capability matrix

| Tool | (a) Interactive open gate | (b) Userspace hook | (c) Process tree | (d) Inode decision | Mechanism | License | Shippable today |
|---|---|---|---|---|---|---|---|
| **Sandlock** † | NO — static Landlock, by design | PARTIAL — seccomp-user-notif exists but `openat` handler omits path; reserved for COW/`/proc` | YES — `ProcessIndex`, ptrace-traced fork | NO — path-prefix (Landlock) | Landlock + seccomp user-notif | Apache-2.0 | Yes (Rust, Linux 6.12+) |
| **Fence** † | NO — static, compiled before exec | NO — Landlock in-kernel; eBPF observe-only | PARTIAL — subtree inherits, not attributed | NO — path/glob | bubblewrap + Landlock + seccomp | Apache-2.0 | Yes (Go) |
| **YoloFS** | **YES** — blocks thread → daemon verdict | YES — kernel module → userspace daemon | PARTIAL — process *name* only | NO — hierarchical path | Stackable kernel FS + daemon | **None / no public code** | **No** — research prototype |
| **Santa** (macOS ref) | PARTIAL — ES AUTH pends event, but rule-DB driven, not a live prompt; FAA gates open/read | YES — `santad` decides via Endpoint Security | PARTIAL — lineage as telemetry | HASH-first for exec; PATH for FAA (symlink/hardlink gaps) | Endpoint Security framework | Apache-2.0 | Yes (macOS-only) |
| **Claude Code / Codex / Tabnine sandboxes** | NO — static allowed-dirs | NO | Subtree only | Path | Seatbelt / bubblewrap / Landlock+seccomp | Mixed | Yes |
| **Bulwark fanotify spike** (this WO) | **YES** | **YES** | **YES** | **YES** | `fanotify FAN_OPEN_PERM` + `/proc` ancestry + `fstat` inode | — | Proven primitive |

† Installed, built, and run hands-on on the Debian 13 arm64 VM (see "Hands-on confirmation of the candidates" below) — not assessed from docs alone.

**Reading the matrix:** No shipping, code-available tool clears all four. The only tool that clears (a) is YoloFS, which has no public code, no inode decisioning, and no process-tree — it is a paper, not a dependency. Every adoptable tool (Sandlock, Fence, Santa, the CLI sandboxes) is **static or policy-DB-driven by design** — none pends an `open()` for a live operator decision. That "pend the open, ask the human, ACK before the kernel deadline" loop is precisely Bulwark's contribution; it is the part you build, not borrow.

## Hands-on evidence (Debian 13 arm64, kernel 6.12.74)

The build alternative — a standalone fanotify supervisor — was proven hands-on on a real Linux kernel, not just from docs. Two spikes (`/tmp/bulwark_spike.c`, `/tmp/bulwark_spike2.c`, ~110 lines C total):

**Spike 1 — interactive allow/deny by name:**
```
[gate] pid=959327 ... path=/tmp/guard/notes.txt  -> ALLOW   (read succeeds)
[gate] pid=959328 ... path=/tmp/guard/secret.env -> DENY    (cat: Operation not permitted)
```
Proves (a) the kernel pauses each `open()`, (b) a userspace daemon decides, and the deny surfaces as `EPERM` to the reader.

**Spike 2 — inode-decision (symlink defeat) + ancestry:**
```
[bulwark-spike2] protected inode: dev=43 ino=192214 (secret.env)
[gate] pid=959596 opened name=/tmp/guard/innocent.txt (dev=43 ino=192214) -> DENY
        ancestry: cat(959596) <- bash(959591) <- sudo(959589) <- sshd-session(...) <- sshd(851)
```
A benign-named symlink (`innocent.txt`) resolving to the protected inode is **still denied** — decision is by `dev+ino`, not name (d). Full parent chain walked from `/proc/<pid>/stat` (c).

Kernel surface confirmed present: `FAN_OPEN_PERM`, `FAN_REPORT_PIDFD`, `FAN_REPORT_FID`, Landlock LSM active (`/sys/kernel/security/lsm`).

**Hands-on confirmation of the candidates (Debian 13 arm64, kernel 6.12.74):** Sandlock and Fence were also installed, built, and run on the VM — not just read from source.

- **Sandlock** (`sandlock` v0.8.2, Rust, built from `multikernel/sandlock`): `sandlock check` reports Landlock ABI v6 OK. Its `run` CLI exposes only `--fs-read` / `--fs-write` / `--fs-deny <PATH>` — all declared at launch, **no interactive/prompt/ask flag exists**. Live: `sandlock run -r / -w /tmp -r /tmp/sltest --fs-deny /tmp/sltest/secret.env -- bash -c 'cat ok.txt; cat secret.env'` allowed `ok.txt` and denied `secret.env` with `Permission denied` and **zero prompts**. Static, declare-before-exec — exactly as documented.
- **Fence** (Go, built from `fencesandbox/fence`): config-file driven (`fence.jsonc` static `denyRead`/`allowWrite` lists); no interactive flag (its only `--*interact*` match is `--force-new-session`, a PTY option). Live (with `socat`+`bubblewrap` installed): static `denyRead` on `secret.env` produced `Permission denied`, **zero prompts**.

Both confirm the documented negative by execution: purely static, no per-`open()` operator prompt. The decision (build) is unchanged.

## Decision

**BUILD a standalone fanotify `FAN_OPEN_PERM` supervisor for Linux.** Rationale:

1. **No tool offers the wedge.** The interactive per-open prompt + inode decision + process-tree attribution is unmet by every adoptable candidate.
2. **Wrapping Sandlock would mean forking it.** Its one runtime hook (`openat` user-notif) deliberately omits the path string and is reserved for COW/`/proc`. Surfacing paths to an operator prompt means modifying Sandlock's supervisor — that is a fork, not a wrap, and inherits its path-based (non-inode) model.
3. **fanotify is the native primitive.** `FAN_OPEN_PERM` *is* the userspace permit/deny hook Sandlock chose not to use. The spike clears all four criteria in ~110 lines. The primitive is a weekend; a fork of someone else's static sandbox is not.
4. **Trust flows up, not down.** Folding Bulwark into a static-sandbox dependency inherits that tool's path-based fragility into the security layer. Bulwark must own inode-truth structurally.

**Do NOT wrap** — so the "if wrap, define integration seam" branch is N/A for Linux. The one productive reuse is conceptual, on macOS (below).

## What we keep from the survey

- **Santa = the macOS architectural template.** It already gates file open/read via File Access Authorization on the exact Endpoint Security AUTH primitive will use — de-risking "can you AUTH-gate reads on macOS within the ES deadline" (answer: yes, FAA proves it). Reuse the *shape*: ES AUTH client + userspace decision daemon + persistent rule DB + audit/sync log + system-extension packaging + the Apple entitlement/notarization path. Build the *interactive* decision loop ourselves — Santa's FAA is policy-DB-driven, not a live prompt, and it documents a "deadline reached → deny" hazard that the interactive design must respect.
- **Santa's identity gaps are a warning, not a model.** FAA is path-based with documented symlink/hard-link bypasses. Bulwark decides by inode specifically to avoid this class — the spike demonstrates the fix.
- **YoloFS validates the thesis.** An independent research group built the same "block the thread, ask userspace" loop and motivated it with secret-read scenarios — confirming the primitive is real and needed. Its CoW staging is a *write* defense (orthogonal to our read gate) and out of scope.

## Build children: proceed / descope

- **(Linux MVP, fanotify) — PROCEED.** Primitive proven hands-on. This is the core.
- **(macOS, Endpoint Security) — PROCEED**, modeled on Santa's architecture, interactive loop built in-house, inode/identity model owned.
- **(policy + receipts) — PROCEED** unchanged; the receipt schema must carry `dev+ino`, `pid` chain, decision, operator, reason (the spike already emits all of these).
- **(NR seam) — PROCEED** unchanged.
- **Descoped:** nothing. No wrap/integration child is created, since the decision is build.

## References

- Sandlock — github.com/multikernel/sandlock · arXiv 2605.26298 ("path-based control remains in static Landlock rules")
- Fence — github.com/fencesandbox/fence · fencesandbox.com
- YoloFS — arXiv 2604.13536 (UW-Madison / MSR; no public code located)
- Santa — github.com/northpolesec/santa · santa.dev File Access Authorization
- Claude Code sandbox — code.claude.com/docs/en/sandboxing
- Kernel: fanotify(7) `FAN_OPEN_PERM`; Landlock LSM (kernel.org)
