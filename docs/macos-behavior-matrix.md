# macOS Endpoint Security Behavior Matrix

Bulwark's macOS gate mirrors the Linux fanotify model where Endpoint Security
has equivalent primitives, and calls out where it does not.

| Case | Linux fanotify gate | macOS Endpoint Security gate |
|---|---|---|
| Protected file open by supervised tree | Denied by `(dev, ino)` before bytes enter the process. | Denied by `st_dev/st_ino` from the `AUTH_OPEN` file record. |
| Same file opened by an unsupervised process | Allowed; Bulwark only governs the tree it launched. | Allowed; the ES edge checks the supervised PID set before denying. |
| Symlink with benign name | Denied because the event fd resolves to the target inode. | Denied because the ES file record carries the target vnode's `st_dev/st_ino`. |
| Hardlink with benign name | Denied when it resolves to the protected inode; link name is not authority. | Denied for the same reason: hardlinks share the same `st_dev/st_ino`. |
| File replaced after launch | New inode is outside the resolved protected set until the next run. | Same; the pushed policy is an inode snapshot for this run. |
| `mmap` after a fresh open | The open is gated; mapping through a pre-existing fd is outside the gate. | Same practical boundary: `AUTH_OPEN` gates the open, not capabilities already held before launch. |
| Process descendants | `/proc` ancestry decides membership in the supervised tree. | ES fork/exec/exit notifications maintain the supervised PID set; a ppid walk is a fallback. |
| Socket consent verdicts | `allow-once`, `allow-session`, `deny`, and `deny-forever` are decided through the Linux Unix-socket provider while a protected open is held. | The same verdict strings are accepted, but startup-seeded into the ES edge before the child is resumed so AUTH_OPEN callbacks never wait on a human. |
| Default-deny allow list | `--deny-all --allow <path>` allows only grants plus the Linux runtime base set. | Same operator contract, with a distinct macOS runtime base set for dyld, frameworks, cryptex paths, and Darwin locale/name-service files. |
| Deadline miss | A blocked fanotify permission event is released by kernel behavior when the supervisor dies. | macOS can kill the ES client if it misses an AUTH deadline; enforcement is gone after client death. |
| Crash-safe floor | Linux has Landlock hardened mode as a separate kernel floor. | No Landlock analog exists on macOS in ; a sandbox-profile floor is future research, not claimed here. |

Receipts remain append-only JSONL. The macOS edge emits the Linux fields
`ts_ms`, `pid`, `dev`, `ino`, `decision`, `source`, `path`, `ancestry`, and
`reason`, plus `host` so hardware receipts identify the machine that produced
them.
