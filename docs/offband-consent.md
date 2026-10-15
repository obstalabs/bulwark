# WO-8 — Off-band interactive consent: evidence

**Target:** Debian 13 arm64, kernel 6.12.74. **Date:** 2026-06-03.

## What shipped

The interactive consent layer deferred from WO-3. A protected open by the
supervised tree is held at the kernel while the operator is asked over a channel
the agent has no descriptor on; the agent only ever sees `EPERM` or success.

**Bulwark owns its native channel** (operator correction 2026-06-03: a standalone
AGPL install cannot hard-depend on the proprietary nr-pro/hivebus stack). The
provider is a trait; the open-core default is a Unix-socket channel answered by
`bulwark consent`. nr-pro/hivebus remain optional providers behind the same
trait.

- `bulwark run --consent socket` — hold protected opens, ask the operator.
- `bulwark consent --socket <s> [--verdict ...]` — operator answers off-band.
- Verdicts: `allow-once`, `allow-session` (inode-cached), `deny`,
  `deny-forever` (persisted to the policy as a protected glob).
- Timeout ⇒ deny (kernel-deadline safe; default 30s).
- Receipts record the decision **source** (operator / cache / timeout / static).

## Off-band enforced structurally (not by a secret)

On every connection the supervisor reads the peer PID via `SO_PEERCRED` and
**refuses any answerer that is the supervised root or its descendant**. An agent
cannot approve its own access even if it knows the socket path. No password: on a
single Unix user a secret the operator client can read, the agent can read too —
peer-credential rejection is the correct, forgery-proof guard. The socket node
is `0600` and chowned to the invoking user (`SUDO_UID`), inside a root-owned
`0711` directory. **Root always uses `/run/bulwark/consent.sock` on Linux
(`/var/run/bulwark` on macOS), regardless of `$XDG_RUNTIME_DIR`**; a non-root run
uses `$XDG_RUNTIME_DIR/bulwark-consent.sock`, else `/tmp/bulwark-consent.sock`.
So the operator (not just root) can answer while no other user can reach or
replace the node. Every chmod/chown goes through an
`O_DIRECTORY|O_NOFOLLOW` fd (`fchmod`, `fchownat … AT_SYMLINK_NOFOLLOW`), and the
opened directory is revalidated by `fstat` before any chmod, so a
plant-and-swap at the directory name can never make root act on a foreign path.

## Verification gates

- `cargo fmt --check` / `cargo clippy --all-targets -- -D warnings` — clean
- `cargo test --bin bulwark` — unit suite incl. the umask stress test and the
  sun_path-length refusal (deterministic)
- `cargo test --test consent_socket -- --ignored` (sudo) — the refusal,
  node-mode and root-default socket tests

## Live evidence

**Operator DENIES** (off-band, separate process):
```
OPERATOR saw:  ── Bulwark consent request ──
                 pid: 1070492   ino: 43:220370
                path: /tmp/wo8/secret.env
              reason: protected inode opened by supervised tree
            ancestry: cat(1070492) <- bash <- bulwark <- sudo <- ...
              sent: deny
AGENT saw:    cat: /tmp/wo8/secret.env: Operation not permitted
receipt:      {"decision":"deny","source":"operator","ino":220370,...}
```

**Operator ALLOWS once** → agent reads the file; `{"decision":"allow","source":"operator"}`.

**Agent tries to answer its OWN consent** (the integrity test):
```
supervisor:  refused consent connection from supervised pid 1070570
             (agent may not answer its own consent)
agent self-answer:  Error: malformed consent request   (never received one)
agent read:         cat: secret.env: Operation not permitted
receipt:            {"decision":"deny","source":"timeout",...}
```
The agent cannot forge its own approval — `SO_PEERCRED` rejects it; the read
times out to deny.

## Acceptance mapping

| # | Requirement | Evidence |
|---|---|---|
| 1 | Protected open → operator consent off-band, gate on reply | live deny/allow above |
| 2 | Agent never sees prompt/path-list/decision — only EPERM/success | agent saw neither the consent exchange nor (on deny) the content |
| 3 | allow-once / allow-session (inode) / deny / deny-forever (persisted) | `consent.rs` + persistence to policy; unit tests |
| 4 | Timeout ⇒ deny; receipt records it | `source:timeout` receipts |
| 5 | Native channel, optional nr-pro/hivebus; degrade to static-deny | `--consent static\|socket`; trait-based providers |
| 6 | Receipts record decision + source + inode + ancestry, never content | receipts above |
| 7 | VM: real off-band prompt; deny ⇒ EPERM; agent context shows nothing | this document |
| 8 | Linux first; macOS parity tracked with WO-4 | Linux shipped; WO-4 carries macOS |

## Deviation from spec (recorded)

Acceptance #5 originally said "the shared nr-pro/hivebus channel, **not a new
one**." Overridden by operator direction 2026-06-03: Bulwark must own an
independent channel because not every install has nr-pro/hivebus. The shared
transports become optional providers behind the `ConsentProvider` trait.
