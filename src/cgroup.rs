//! Reparent-proof tree attribution via cgroup-v2 membership.
//!
//! The supervisor decides whether an `open()` belongs to the launched tree.
//! Walking `/proc/<pid>/stat` parent links (see `proctree`) answers that for a
//! normal descendant, but a process that double-`fork()`s orphans itself to
//! `init` (PID 1), severing the parent chain — so the ancestry walk concludes
//! "not in the tree" and the read is wrongly allowed.
//!
//! cgroup membership does not have that hole: a re-parented orphan keeps the
//! cgroup it was launched in, `init` lives in a different one, and an
//! unprivileged process cannot move itself out of a root-owned cgroup. So we
//! place the supervised child in a dedicated cgroup-v2 scope at launch and
//! decide membership by that scope, not by ancestry.
//!
//! This is best-effort: where cgroup-v2 is not available (v1/hybrid hierarchy,
//! or a host that does not let us create a scope) we fall back to the ancestry
//! walk and say so at startup — never worse than the prior behaviour.
//!
//! Linux only.

use std::ffi::CString;
use std::fs;
use std::path::PathBuf;

/// The unified cgroup-v2 mount. On a v2 or hybrid host the unified hierarchy is
/// mounted here; a pure-v1 host has only per-controller mounts and no
/// `cgroup.procs` at this root, which is how we detect "no v2".
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// A dedicated cgroup-v2 scope owning the supervised tree for one run. Created
/// at launch, removed on drop. Membership in this scope is the tree-membership
/// signal: it survives re-parenting, which the ancestry walk does not.
pub struct CgroupScope {
    /// Absolute path of the scope directory, e.g.
    /// `/sys/fs/cgroup/bulwark.run-12345`.
    dir: PathBuf,
    /// The scope's path *relative to the cgroup root*, with a leading slash,
    /// e.g. `/bulwark.run-12345`. This is the suffix `/proc/<pid>/cgroup`
    /// reports for a member (`0::/bulwark.run-12345`).
    rel: String,
    /// Pre-built `cgroup.procs` path for the async-signal-safe child join.
    procs_cstr: CString,
}

impl CgroupScope {
    /// Create a fresh scope for a run supervised by `supervisor_pid`. Returns
    /// `None` (with a reason logged by the caller) when cgroup-v2 is not usable,
    /// so the gate can fall back to the ancestry walk.
    pub fn create(supervisor_pid: i32) -> Option<Self> {
        // Detect cgroup-v2: the unified hierarchy exposes `cgroup.procs` at the
        // root. A pure-v1 host does not, so we decline and fall back.
        let root = PathBuf::from(CGROUP_ROOT);
        if !root.join("cgroup.procs").exists() {
            return None;
        }

        // Find a free scope name and create it atomically with `create_dir`
        // (which fails if the path already exists). We do NOT reuse or rmdir an
        // existing directory: an occupied `bulwark.run-<pid>` must not silently
        // downgrade us to the ancestry-only fallback (that would let anyone able
        // to pre-create the predictable path disable reparent-proof attribution).
        // Instead we pick the next free `bulwark.run-<pid>-<n>` — so a squatted
        // name costs the attacker nothing and changes nothing.
        let mut dir = PathBuf::new();
        let mut name = String::new();
        let mut created = false;
        for n in 0..64 {
            let candidate = if n == 0 {
                format!("bulwark.run-{supervisor_pid}")
            } else {
                format!("bulwark.run-{supervisor_pid}-{n}")
            };
            let path = root.join(&candidate);
            match fs::create_dir(&path) {
                Ok(()) => {
                    name = candidate;
                    dir = path;
                    created = true;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Name taken (stale run or a squatter) — try the next.
                    continue;
                }
                Err(_) => {
                    // No permission to create a scope (not root, or delegation
                    // denied). Genuine no-cgroup host → fall back.
                    return None;
                }
            }
        }
        if !created {
            return None;
        }

        let rel = format!("/{name}");
        let procs = dir.join("cgroup.procs");
        let procs_cstr = CString::new(procs.as_os_str().to_string_lossy().as_bytes()).ok()?;

        Some(CgroupScope {
            dir,
            rel,
            procs_cstr,
        })
    }

    /// The `cgroup.procs` path to write the joining pid into. Used by the
    /// forked child before exec (raw libc, see `join_self`).
    pub fn procs_path(&self) -> &CString {
        &self.procs_cstr
    }

    /// The scope's cgroup path relative to the cgroup root (e.g.
    /// `/bulwark.run-12345`). The off-band consent channel takes this so it can
    /// reject in-tree answerers by the same membership primitive as the gate.
    pub fn rel(&self) -> &str {
        &self.rel
    }

    /// True if `pid` is a member of this scope. Reads `/proc/<pid>/cgroup`,
    /// whose v2 line is `0::<relpath>`, and compares `<relpath>` to ours.
    ///
    /// A re-parented orphan still reports our scope here; a process outside the
    /// tree reports a different path. Unreadable (process gone, or a race) →
    /// `false`, and the caller's ancestry-walk fallback decides.
    pub fn contains(&self, pid: i32) -> bool {
        pid_in_scope(pid, &self.rel)
    }

    /// True while the scope still has at least one member process. Reads the
    /// kernel's `cgroup.events` `populated` key — `1` while any process remains,
    /// `0` once the scope is empty.
    ///
    /// This is how the supervisor knows an orphaned descendant is still alive
    /// after the foreground child exited: a double-fork()'d process that
    /// outlives its parent keeps the scope populated, so the gate keeps
    /// enforcing until it too is gone. Unreadable → `false` (treat as drained so
    /// teardown is never wedged on a missing file).
    pub fn is_populated(&self) -> bool {
        let events = match fs::read_to_string(self.dir.join("cgroup.events")) {
            Ok(s) => s,
            Err(_) => return false,
        };
        events_populated(&events)
    }
}

impl Drop for CgroupScope {
    fn drop(&mut self) {
        // The scope is empty once the supervised tree has drained (the gate does
        // not return until `is_populated()` is false). The kernel may take a
        // brief moment after the last process exits to let the directory be
        // removed, so retry a few times before giving up. A lingering dir is
        // cosmetic, not a safety issue — never fail teardown over it.
        for _ in 0..50 {
            if fs::remove_dir(&self.dir).is_ok() || !self.dir.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// Join the calling process to the scope at `procs_cstr`, before exec, while
/// still root. Async-signal-safe: runs in the forked child, so it uses only raw
/// libc calls (no allocation, no panics) — mirroring `gate::drop_to`.
///
/// Joining must happen *before* the privilege drop: writing to a root-owned
/// `cgroup.procs` needs privilege, and it must happen *before* exec so the child
/// is already a scope member when it (or any descendant it later orphans) opens
/// a file.
///
/// Returns `Err(errno)` on failure; the caller decides whether that is fatal.
///
/// # Safety
/// Must be called in the child between `fork()` and `execvp()`.
pub unsafe fn join_self(procs_cstr: &CString) -> std::result::Result<(), i32> {
    // Format our own pid into a stack buffer without allocating. getpid() is
    // async-signal-safe; decimal-encode it manually.
    let pid = libc::getpid();
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    // Write a trailing newline, then digits right-to-left.
    i -= 1;
    buf[i] = b'\n';
    let mut n = pid as i64;
    if n <= 0 {
        // getpid never returns <= 0 for a live process; guard anyway.
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 && i > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    let len = buf.len() - i;

    let fd = libc::open(procs_cstr.as_ptr(), libc::O_WRONLY);
    if fd < 0 {
        return Err(errno());
    }
    let written = libc::write(fd, buf.as_ptr().add(i) as *const libc::c_void, len);
    libc::close(fd);
    if written < 0 || written as usize != len {
        return Err(errno());
    }
    Ok(())
}

unsafe fn errno() -> i32 {
    *libc::__errno_location()
}

/// True if `pid` reports cgroup-v2 membership in scope `rel` (or a cgroup nested
/// under it). Standalone — needs no [`CgroupScope`] handle — so the consent
/// socket and other off-band lanes can reject an in-tree answerer by the gate's
/// own membership primitive rather than the defeatable ancestry walk. The read
/// is from the supervisor's `/proc` view (the root cgroup namespace), so a peer
/// that enters its own cgroup namespace cannot hide its true scope. Unreadable
/// (process gone, or a race) → `false`.
pub fn pid_in_scope(pid: i32, rel: &str) -> bool {
    let raw = match fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        Ok(s) => s,
        Err(_) => return false,
    };
    proc_cgroup_is(&raw, rel)
}

/// True if a `/proc/<pid>/cgroup` body places the process in the v2 scope `rel`
/// **or any cgroup nested under it**.
///
/// The v2 unified line is `0::<relpath>`. Hybrid hosts may also list v1
/// controllers as `N:ctrl:<relpath>`; we trust only the unified `0::` line so a
/// v1 controller path can never be mistaken for scope membership.
///
/// Membership is hierarchical, not exact: an agent can `mkdir` a child cgroup
/// (`<rel>/esc`) and move itself into it, which is still inside the supervised
/// scope. We must treat `<rel>` and everything under `<rel>/` as members —
/// otherwise a sub-cgroup move (combined with a double-fork to evade the ancestry
/// fallback) escapes the gate. The `/` boundary is required so `/bulwark.run-1`
/// does not spuriously match a sibling `/bulwark.run-12`.
fn proc_cgroup_is(body: &str, rel: &str) -> bool {
    for line in body.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            return path == rel || path.starts_with(&format!("{rel}/"));
        }
    }
    false
}

/// True if a `cgroup.events` body reports the scope still has a member process.
fn events_populated(body: &str) -> bool {
    for line in body.lines() {
        if let Some(v) = line.strip_prefix("populated ") {
            return v.trim() == "1";
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_matches_unified_line_only() {
        let rel = "/bulwark.run-123";
        // Pure v2: single unified line.
        assert!(proc_cgroup_is("0::/bulwark.run-123\n", rel));
        // A different scope is not a member (the reparent-to-init case: init is
        // in /init.scope, not ours).
        assert!(!proc_cgroup_is("0::/init.scope\n", rel));
        assert!(!proc_cgroup_is("0::/\n", rel));
        // Hybrid: a v1 controller line with our path must NOT count — only 0::.
        assert!(!proc_cgroup_is("1:name=systemd:/bulwark.run-123\n", rel));
        // Hybrid where the unified line IS ours still counts.
        assert!(proc_cgroup_is(
            "1:name=systemd:/something\n0::/bulwark.run-123\n",
            rel
        ));
        // A cgroup NESTED under our scope is still a member: an agent that
        // mkdir's a child cgroup and moves into it has not left the tree.
        assert!(proc_cgroup_is("0::/bulwark.run-123/esc\n", rel));
        assert!(proc_cgroup_is("0::/bulwark.run-123/a/b/c\n", rel));
        // But a SIBLING scope sharing a name prefix is NOT a member — the `/`
        // boundary prevents /bulwark.run-123 from matching /bulwark.run-1234.
        assert!(!proc_cgroup_is("0::/bulwark.run-1234\n", rel));
        assert!(!proc_cgroup_is("0::/bulwark.run-123x\n", rel));
        // Empty / garbage → not a member (fail safe to the ancestry fallback).
        assert!(!proc_cgroup_is("", rel));
    }

    /// `pid_in_scope` must not report membership in a scope the process is not
    /// in, and must fail safe (false) for an unreadable pid. The positive case
    /// (an orphan genuinely in a bulwark scope) needs a live cgroup and is a VM
    /// integration test. This is the standalone primitive the consent socket
    /// uses to refuse in-tree answerers by membership rather than ancestry.
    #[test]
    fn pid_in_scope_negative_controls() {
        assert!(!pid_in_scope(
            std::process::id() as i32,
            "/bulwark.run-does-not-exist"
        ));
        assert!(!pid_in_scope(-1, "/whatever")); // unreadable pid → false
    }

    #[test]
    fn populated_key_parsed() {
        assert!(events_populated("populated 1\nfrozen 0\n"));
        assert!(!events_populated("populated 0\nfrozen 0\n"));
        assert!(!events_populated("frozen 0\n")); // key absent → treat as drained
        assert!(!events_populated(""));
    }
}
