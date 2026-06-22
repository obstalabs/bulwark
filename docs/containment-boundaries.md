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
| Deliberately-orphaned descendant (double-`fork()`, reparents to init) | **denied** (cgroup) | **denied** (cgroup) | **denied** | **denied** (ES set-tracking) |
| Agent creating its own mount namespace (`unshare`) to escape | n/a | n/a | **blocked** (`no_new_privs`) | n/a |
| Read delegated to a separate daemon (`docker run`) | **not gated** | **not gated** | **not gated** | **not gated** |
| A process you did not launch under Bulwark | **not gated** | **not gated** | **not gated** | **not gated** |

The container/unwrapped-process rows are the same fact, and they are the honest edge of
the *design*: a process Bulwark did not launch, or work handed to a separate daemon, is
outside the tree it governs. Everything *inside* the launched tree is gated — including a
descendant that deliberately orphans itself, which is what the next section is about.

## Orphaned descendants: gated by membership, not by ancestry

A process can try to escape the gate by **double-`fork()`ing** — forking a child that
immediately forks a grandchild and exits, so the kernel reparents the orphaned grandchild
to PID 1 (`init` on Linux, `launchd` on macOS). A naive supervisor decides tree membership
by walking the opener's parent-PID chain to the launched root; the re-parent severs that
chain, and such a supervisor would wrongly conclude "not in the tree" and allow the read.
The orphan is still the agent's own descendant — it has just shed its parent link.

Bulwark does **not** decide membership by the parent-chain walk alone. It records
membership *at process-creation time*, by a label that survives re-parenting:

- **Linux (`--protect` and `--deny-all`):** the supervised tree is launched into a
  dedicated **cgroup-v2 scope**. A re-parented orphan keeps that cgroup (PID 1 lives in a
  different one, e.g. `/init.scope`), and an unprivileged process cannot move itself out of
  a root-owned cgroup — so the open is still attributed to the tree and gated. The
  supervisor also keeps enforcing until the scope fully drains, so an orphan that outlives
  the foreground process cannot win by racing teardown. Verified on the VM (kernel 6.12):
  the double-fork read is **denied** under both modes.
- **macOS (Endpoint Security):** the gate tracks the supervised PID set from
  `NOTIFY_FORK`/`EXEC`/`EXIT` events, inserting each child *at fork time* — before it can
  run or reparent — and decides `AUTH_OPEN` by set membership. The edge keeps enforcing
  until the set drains to empty, so an orphan that outlives the foreground process is still
  gated. Verified on hardware (macOS 26, Apple Silicon): the double-fork read is
  **denied**.
- **`--hardened` (Landlock)** was always immune: its kernel ruleset is inherited by every
  descendant for life, with no parent chain to sever. It remains the strongest option for
  an adversarial or unattended agent (it is also crash-safe; see below).

The ancestry walk is still used — but only as an *additive* fallback for a just-forked PID
whose creation event has not yet been processed, never as the sole signal. Membership by
cgroup (Linux) or tracked set (macOS) is what makes the boundary reparent-proof.

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

## Root agents and cgroup migration

The Linux reparent-proof attribution (above) binds a process through its **cgroup**
membership. That binding holds for any process that cannot write the cgroup tree — i.e. an
unprivileged one. A **root** agent is different: writing your own PID into a
`cgroup.procs` file is an owner-write (uid 0 owns the cgroup filesystem), and a root agent
with `CAP_SYS_ADMIN` can go further and `mount` a fresh `cgroup2` filesystem that re-exposes
the whole hierarchy. Either way a root agent can migrate *out* of the supervised scope and,
combined with a double-`fork()` to shed the ancestry fallback, evade the deny-list/allow-list
gate. This is the same class as the Docker-socket boundary: **a root agent with
`CAP_SYS_ADMIN` is not containable by any process-scoped control** — it can also `ptrace`
the supervisor or unmount state. Trying to "half-contain" root would give false confidence.

So Bulwark does not pretend to. Instead it makes the safe path the default:

- **By default, a would-be-root agent is dropped to the invoking user.** When
  `bulwark run` is invoked via `sudo` and the agent would otherwise run as root, Bulwark
  drops the supervised child to `SUDO_UID` (printing a one-line notice). The agent then
  runs as *you*, not root, and cannot migrate cgroups. The supervisor stays root and keeps
  the fanotify fd.
- **`--worker-uid <uid>`** drops to a specific unprivileged account (the explicit form).
- **`--hardened`** needs none of this: Landlock binds the process regardless of uid, so
  there is no cgroup to leave.
- **`--allow-root`** opts out and keeps uid 0 — only safe for a *trusted* agent. Without a
  `sudo` origin to infer a user from, Bulwark cannot pick a safe uid, so it warns and
  proceeds at uid 0; pass `--allow-root` to silence that deliberately.

macOS is unaffected: its membership set lives in the gate's own memory (built from kernel
fork/exec/exit events), not a filesystem the agent can write, so there is nothing to
migrate.

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
