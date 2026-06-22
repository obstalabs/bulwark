# Containment boundaries — what Bulwark gates, and what it doesn't

Bulwark governs a **process tree**: the command you launch under `bulwark run` and its
descendants. That boundary is precise, and being precise about it matters more than
sounding comprehensive. This page is the tested map — every cell below was verified on
real hardware (Linux kernel 6.12 with Landlock + Docker; macOS Endpoint Security on
Apple Silicon), not asserted.

## The coverage matrix

| Read path | Deny-list (`--protect`) | Allow-list (`--deny-all`) | Hardened (`--hardened`, Landlock) | macOS (Endpoint Security) |
|---|---|---|---|---|
| Direct read by the supervised tree | **denied** | **denied** | **denied** | **denied** |
| Symlink / rename / hardlink to a protected file | **denied** (by inode) | **denied** | **denied** | **denied** |
| Bind-mount alias of a protected file | **denied** (`FAN_MARK_FILESYSTEM`) | **denied** | **denied** | **denied** |
| Deep descendant (child of a child …) | **denied** | **denied** | **denied** | **denied** (PID ancestry) |
| Deliberately-orphaned descendant (double-`fork()`, reparents to init) | **leaks** ⚠️ | **leaks** ⚠️ | **denied** | **leaks (expected)** ⚠️ |
| Agent creating its own mount namespace (`unshare`) to escape | n/a | n/a | **blocked** (`no_new_privs`) | n/a |
| Read delegated to a separate daemon (`docker run`) | **not gated** | **not gated** | **not gated** | **not gated** |
| A process you did not launch under Bulwark | **not gated** | **not gated** | **not gated** | **not gated** |

The container/unwrapped-process rows are the same fact, and they are the honest edge of
the *design*. The orphaned-descendant row is different: it is a current limitation of the
*fanotify/ES attribution mechanism*, with a verified mitigation today (`--hardened`) and a
fix in progress. The two are not the same kind of edge — see below.

## The orphaned-descendant limitation (and how to avoid it today)

The fanotify gate and the macOS ES gate decide whether an open belongs to the supervised
tree by walking the opener's parent-PID chain (`/proc/<pid>/stat` on Linux, the audit
token on macOS) up to the launched root. That walk is what makes a deep grandchild still
gated — membership is by ancestry, which a process cannot forge by *renaming* itself.

It can, however, *re-parent* itself. A process that **double-`fork()`s** — forks a child
that immediately forks a grandchild and exits — leaves the grandchild orphaned, and the
kernel reparents an orphan to `init` (PID 1). Its parent-PID chain no longer leads back to
the supervised root, so the ancestry walk concludes "not in the tree" and the read is
**allowed**. Verified on Linux (kernel 6.12) under both `--protect` and `--deny-all`. This
is not the agent escaping *the machine* — the orphan is still the agent's own descendant —
it is the ancestry-walk attribution being severed by a one-line `fork()` trick.

**`--hardened` is immune, and is the answer for an adversarial or unattended agent.** The
Landlock floor is a kernel ruleset bound to the agent's threads and **inherited by every
descendant for life**, regardless of re-parenting — there is no parent chain to sever.
Verified: the same double-fork read that leaks under `--protect` is denied under
`--hardened` (`Permission denied`). If the agent is untrusted enough to try a deliberate
escape, run it under `--hardened`, not the fanotify deny-list.

**The fix in progress** is to stop attributing tree-membership by parent-PID walk and use
**control-group membership** instead: a re-parented orphan keeps the run's cgroup, while
`init` lives in a different one, so the membership test survives the double-fork. (Verified
on the VM: an orphaned descendant retains the launch cgroup; PID 1 is in `/init.scope`; an
unprivileged process cannot move itself out of a delegated cgroup.) Until that ships,
`--hardened` is the structural answer and the deny-list/ES modes carry this documented
limitation.

The macOS cell is marked **expected** rather than hardware-verified: the macOS gate uses
the same audit-token ancestry walk and has no Landlock-style floor, so the same re-parent
severs it by construction — but it has not yet been run on hardware for this specific
attack, so it is named as expected, not asserted as tested.

## The container case, precisely

`docker run` looks like the agent reading a file, but it isn't. The `docker` CLI is a
thin client that hands the request to **`dockerd`** — a separate, root-owned daemon that
is **not** in the tree Bulwark launched. `dockerd`'s children do the actual mount and
read. So the read never enters Bulwark's supervised tree, and neither the fanotify gate
(it watches the marked filesystems, not the container's own overlay) nor the Landlock
floor (it binds the *agent's* process tree, not `dockerd`'s) sees it.

This is not a gate failure — it is the boundary working as designed. **Bulwark governs a
process tree; a daemon is a different tree.** It is the same fact as the README's "not
protection against an unwrapped process," seen from the container angle.

The general principle here is well known outside Bulwark: **an agent with access to the
Docker socket (`/var/run/docker.sock`) is unconfined by *any* process-scoped control** —
the socket is root-equivalent (see the CIS Docker Benchmark). That is true of seccomp,
AppArmor, SELinux user policy, and Bulwark alike. The mitigation is not a Bulwark mode:

- **Don't give a confined agent access to the Docker socket.** If it can talk to
  `dockerd`, it can read anything `dockerd` can — by definition, not by a Bulwark gap.
- Or **supervise the daemon's tree too**, if you control how containers are launched.
- Reads the agent performs *itself* — including its own attempt to `unshare` into a new
  namespace — stay gated. `--hardened` blocks the agent-driven namespace escape outright
  (`no_new_privs` + the Landlock ruleset); it just cannot reach a separate privileged
  daemon, which nothing process-scoped can.

## Why `--hardened` is strictly stronger (for what the agent does itself)

`--hardened` (the Landlock floor) is enforced in the kernel on the agent's own threads
and all their children, for life — no supervisor to kill, so it is crash-safe, and it
denies the agent's own attempts to escape via a new mount namespace. Use it for
unattended/CI dispatch. It does **not** change the daemon-delegation boundary above —
that is outside any process-tree control.

## macOS: gated by process ancestry, not by Full Disk Access

A note because it is a common misreading: the macOS gate decides *which* process to
govern by walking the **audit-token PID ancestry** up to the supervised root — a kernel
fact the process cannot forge. Full Disk Access is what lets the *gate itself* exist
(`es_new_client` requires it); a supervised child inheriting FDA is irrelevant, because
membership is by ancestry, not by capability. Verified: a grandchild two levels deep,
fully FDA-inheriting, is still denied. See
[docs/macos-permissions.md](macos-permissions.md).

## Summary

Bulwark gates reads by a supervised process tree, by inode, at the kernel — including
deep descendants, symlink/rename/hardlink, and bind-mount aliases. It does **not** gate
reads a process performs outside that tree: a process you didn't launch under it, or work
the agent delegates to a separate daemon such as `dockerd`. That edge is the principled
boundary of a process-scoped control, not a bypass — and the practical rule that follows
is the standard one: don't hand a confined agent a root-equivalent socket.
