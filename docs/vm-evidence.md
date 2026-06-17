# — Linux fanotify MVP: VM closure evidence

**Target:** Debian 13 arm64, kernel `6.12.74+deb13+1-arm64`, Landlock LSM + fanotify `FAN_OPEN_PERM` present.
**Binary:** `bulwark run` (debug), run as root (fanotify needs `CAP_SYS_ADMIN`).
**Date:** 2026-06-02.

## Verification gates (all green on the VM)

- `cargo fmt --check` — clean
- `cargo clippy --all-targets -- -D warnings` — clean
- `cargo test` (unit) — 6 passed
- `cargo test --test gate_integration -- --ignored` under sudo (live fanotify) — **6 passed, 0 failed**

```
test allowed_file_open_succeeds ... ok
test child_process_inherits_the_gate ... ok
test denied_protected_open_blocks_with_eperm ... ok
test deny_receipt_carries_ancestry_attribution ... ok
test renamed_protected_file_same_inode_still_denied ... ok
test symlink_with_benign_name_is_still_denied_by_inode ... ok
```

## Headline demo — the one-sentence goal

> Run a command under the wrapper; when it tries to open a protected inode, the
> kernel blocks the read before the bytes enter the process.

```
$ sudo bulwark run --protect /tmp/demo/secret.env --receipts r.jsonl -- cat /tmp/demo/notes.txt
benign notes                          # allowed — not protected

$ sudo bulwark run --protect /tmp/demo/secret.env --receipts r.jsonl -- bash -c 'cat /tmp/demo/secret.env'
(exit 1)                              # denied — no content reached the reader

$ sudo bulwark run --protect /tmp/demo/secret.env --receipts r.jsonl -- cat /tmp/demo/innocent.txt
(exit 1)                              # symlink to the protected inode — still denied
```

## Receipt log (real output, JSON lines)

```json
{"decision":"allow","pid":987323,"dev":43,"ino":203910,"path":"/tmp/demo/notes.txt","ancestry":"cat(987323) <- bulwark(987322) <- sudo(987320) <- bash(987317) <- ...","reason":"not protected"}
{"decision":"deny","pid":987327,"dev":43,"ino":203911,"path":"/tmp/demo/secret.env","ancestry":"cat(987327) <- bulwark(987326) <- sudo(987324) <- bash(987317) <- ...","reason":"protected inode opened by supervised tree"}
{"decision":"deny","pid":987331,"dev":43,"ino":203911,"path":"/tmp/demo/secret.env","ancestry":"cat(987331) <- bulwark(987330) <- ...","reason":"protected inode opened by supervised tree"}
```

Note the third line: the open was issued against `innocent.txt` (a symlink), but
the receipt resolved it to the real inode `203911` and real path `secret.env`.
The decision is by `(dev, ino)` — the benign name cannot lie.

## Acceptance mapping (operator-narrowed MVP slice)

| Requirement | Evidence |
|---|---|
| Supervise a target process tree | `bulwark run -- <cmd>` forks/execs; ancestry walked from `/proc` |
| Install `FAN_OPEN_PERM` gate | `fanotify_init` + `FAN_MARK_MOUNT` before fork |
| Compare by inode/dev, not path | `fstat` on event fd → `(dev, ino)`; symlink + rename tests pass |
| Allow/deny per protected inode list | static `ProtectedSet`; deny on hit, allow otherwise |
| Return EPERM on deny | `FAN_DENY`; reader exits non-zero, no content |
| Log pid, ancestry, inode/dev, decision, path | receipts above |
| Tests: allow / deny / symlink / inheritance / ancestry / rename-same-inode | 6/6 live integration pass |
| Closure on real VM, not unit tests alone | this document |

Deferred to a follow-up WO (explicitly out of this MVP slice): interactive
operator prompt (allow-once / allow-session / deny), decision persistence, and
`on_timeout=deny` UX. See parent / notes.
