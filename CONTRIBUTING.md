# Contributing to Bulwark

Thanks for your interest. Bulwark is a small, deliberately-scoped security tool, so
contributions are most welcome when they keep it sharp rather than broaden it.

## Build & test

Bulwark is Rust (edition 2021, MSRV 1.74). The kernel gate is Linux (fanotify) and
macOS (Endpoint Security); the portable core builds everywhere.

```sh
make build        # cargo build
make test         # cargo test (unit + portable)
make lint         # cargo clippy --all-targets -- -D warnings
make fmt-check    # cargo fmt --check
```

The live-gate **integration tests** (`make it`) need a Linux host with root
(fanotify needs `CAP_SYS_ADMIN`, Landlock for `--hardened`) and are `#[ignore]`d in
the normal run. CI runs them on a Linux runner.

Before opening a PR: `make fmt-check && make lint && make test` should pass.

<!-- WO-140@v1: keep enforcement-boundary changes tied to reproducible seal evidence. -->
<!-- WO-175@v1: explain which revision supplies the acknowledgement control. -->
Changes matching [`scripts/boundary-paths.txt`](scripts/boundary-paths.txt) must
carry the exact commit-body line `Seal-required: acknowledged`; macOS seal receipts
bind the tested binary, source commit, and signed gate, and the release upload
refuses evidence from another build. Every defect observed in use must produce a
reproduction and a permanent unit, integration, or seal check, plus a new boundary
path when the defect crossed that boundary through a path the list did not cover. The
check runs from the base branch, so a pull request cannot weaken the control that judges
it; workflow edits remain protected by branch protection and required approval, not by
this job.

## Sign your commits (DCO)

We use the **Developer Certificate of Origin** — no CLA, no copyright assignment.
You keep your copyright; you just certify you have the right to contribute the code
(see <https://developercertificate.org>). Add a sign-off line to each commit:

```sh
git commit -s -m "fix: ..."
```

which appends `Signed-off-by: Your Name <your@email>`. Set `git config user.name` /
`user.email` to a real identity first.

## What fits, what doesn't

Bulwark does **one thing**: gate the read at the kernel. Good contributions:

- correctness and safety of the gate (inode handling, fail-closed behavior, the
  privilege drop, crash posture),
- platform parity (Linux/macOS), portability, smaller dependency surface,
- tests, docs, and honest documentation of limits.

Please open an issue to discuss before large changes or anything that **widens
scope** beyond a read gate — Bulwark is intentionally not a network gate, not
redaction, not a general sandbox (see the README "What Bulwark is NOT"). Scope
discipline is a feature.

## Licensing & the open-core line

Bulwark Core — everything in this repository — is **AGPL-3.0-or-later**. Local
enforcement is open; Obsta-operated managed trust (fleet policy, identity, audit,
signed grants) is a separate commercial tier and not part of this repo. Contributions
here are accepted under AGPL-3.0-or-later via the DCO above.

### External contributions

We welcome **issues, discussion, bug reports, and small fixes** now. Before merging
**substantive external code**, we will finalize the contributor-licensing policy
(the DCO above, or a lightweight CLA — to keep the open-core/commercial line clean).
If you're considering a larger change, please **open an issue first** so we can
confirm the licensing path before you invest in the PR. Maintainer commits are
unaffected.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
