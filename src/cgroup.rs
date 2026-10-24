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
//! Where no scope can be created (v1/hybrid hierarchy, or a host that does not
//! let us create one) the default mode refuses to start rather than silently
//! fall back to the ancestry walk — a dead gate must never leave a live
//! unsupervised tree; `--hardened` keeps its per-process Landlock floor and
//! still runs. The ancestry walk survives only as the per-open membership
//! fallback for a single unreadable pid, never as a substitute for a scope.
//!
//! Linux only.

use std::ffi::CString;
use std::fs;
// WO-188@v1: keep scope I/O errors explicit when preparing safe gate teardown.
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The unified cgroup-v2 mount. On a v2 or hybrid host the unified hierarchy is
/// mounted here; a pure-v1 host has only per-controller mounts and no
/// `cgroup.procs` at this root, which is how we detect "no v2".
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// WO-187@v1: prefer the agent tree under memory pressure without making a
/// leaking gate unreclaimable, which `-1000` would do.
const GATE_OOM_SCORE_ADJ: i32 = -900;

const PROC_SELF_OOM_SCORE_ADJ: &str = "/proc/self/oom_score_adj";
const PROC_SELF_OOM_SCORE_ADJ_C: &[u8] = b"/proc/self/oom_score_adj\0";
const AGENT_OOM_SCORE_ADJ: &[u8] = b"0\n";
const MEMORY_OOM_GROUP: &str = "memory.oom.group";

/// A dedicated cgroup-v2 scope owning the supervised tree for one run. Created
/// at launch, removed on drop. Membership in this scope is the tree-membership
/// signal: it survives re-parenting, which the ancestry walk does not.
// WO-59@v1: make supervised-tree membership survive process reparenting.
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

// WO-59@v1: keep cgroup attribution operations behind the run-scope handle.
impl CgroupScope {
    /// Create a fresh scope for a run supervised by `supervisor_pid`. Returns
    /// `None` when cgroup-v2 is not usable; the caller then refuses to start (a
    /// dead gate must never leave a live unsupervised tree) rather than fall back
    /// to the ancestry walk.
    // WO-59@v1: create a dedicated scope before the supervised process starts.
    pub fn create(supervisor_pid: i32) -> Option<Self> {
        // WO-155@v1: fault-injection: a test-only switch simulates a host with no
        // writable cgroup-v2 scope (compiled in only under `fault-injection`).
        // It exercises the scope-less teardown and the default-mode refusal.
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("BULWARK_TEST_NO_SCOPE").is_some() {
            return None;
        }
        // Detect cgroup-v2: the unified hierarchy exposes `cgroup.procs` at the
        // root. A pure-v1 host does not, so we decline (the caller refuses).
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
                    // denied). Genuine no-cgroup host → the caller refuses.
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
    // WO-59@v1: expose the scope join path used before child exec.
    pub fn procs_path(&self) -> &CString {
        &self.procs_cstr
    }

    /// Lower the current supervisor's OOM score and make an OOM victim inside
    /// the supervised scope take that entire process tree with it. A missing
    /// memory controller is non-fatal because the score adjustment still makes
    /// the untrusted tree the kernel's preferred victim.
    // WO-187@v1: keep agent-created memory pressure from selecting its gate.
    pub fn configure_oom_protection(&self) -> io::Result<Option<String>> {
        configure_oom_protection_at(&self.dir, Path::new(PROC_SELF_OOM_SCORE_ADJ))
    }

    /// The scope's cgroup path relative to the cgroup root (e.g.
    /// `/bulwark.run-12345`). The off-band consent channel takes this so it can
    /// reject in-tree answerers by the same membership primitive as the gate.
    // WO-71@v1: share the gate's membership boundary with off-band consent.
    pub fn rel(&self) -> &str {
        &self.rel
    }

    /// WO-155: the `cgroup.kill` trigger path. Writing `1` to it makes the
    /// kernel SIGKILL every process in this scope, reparent-proof — the way the
    /// gate's watcher reaps the whole supervised tree if the gate dies. Only
    /// present on cgroup-v2 with a recent kernel (5.14+); the caller tolerates
    /// its absence (the direct child is also covered by a parent-death signal).
    pub fn kill_path(&self) -> PathBuf {
        self.dir.join("cgroup.kill")
    }

    /// WO-155@v1: SIGKILL every process in the scope by writing `1` to
    /// `cgroup.kill`, reparent-proof (a double-fork()'d orphan still carries the
    /// scope). Best-effort: returns `false` when the trigger file is absent
    /// (kernel < 5.14), so the caller can fall back to draining. Used on a
    /// normal-exit with a lingering descendant, so a daemonized orphan never
    /// outlives the run.
    pub fn kill_all(&self) -> bool {
        // WO-155@v1: fault-injection: a test-only switch makes `cgroup.kill`
        // fail, forcing the freeze + per-pid SIGKILL fallback (compiled in only
        // under `fault-injection`).
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("BULWARK_TEST_NO_CGROUP_KILL").is_some() {
            return false;
        }
        use std::io::Write;
        let mut f = match std::fs::OpenOptions::new()
            .write(true)
            .open(self.kill_path())
        {
            Ok(f) => f,
            Err(_) => return false,
        };
        f.write_all(b"1").is_ok()
    }

    /// WO-155@v1: the `cgroup.freeze` trigger path. Writing `1` freezes every
    /// process in the scope (they stop running, so no more members can fork in);
    /// the caller then SIGKILLs each pid in `cgroup.procs` to empty the scope by
    /// hand. This is the fallback where `cgroup.kill` (5.14+) is absent.
    pub fn freeze_path(&self) -> PathBuf {
        self.dir.join("cgroup.freeze")
    }

    /// WO-155@v1: the `cgroup.events` path. Its `populated 1|0` key is how the
    /// watcher knows the scope is empty after a freeze + per-pid SIGKILL sweep.
    pub fn events_path(&self) -> PathBuf {
        self.dir.join("cgroup.events")
    }

    /// Freeze the scope (best-effort). Returns `false` when `cgroup.freeze` is
    /// absent (kernel < 5.2), so the caller knows the fallback is unavailable.
    // WO-155@v1: freeze descendants before the per-pid reap fallback.
    pub fn freeze(&self) -> bool {
        use std::io::Write;
        let mut f = match std::fs::OpenOptions::new()
            .write(true)
            .open(self.freeze_path())
        {
            Ok(f) => f,
            Err(_) => return false,
        };
        f.write_all(b"1").is_ok()
    }

    /// The pids currently in the scope, from `cgroup.procs`. Empty when the scope
    /// has drained (or is unreadable — the caller treats that as drained).
    // WO-155@v1: enumerate members for the frozen-scope reap fallback.
    pub fn procs(&self) -> Vec<i32> {
        let body = match fs::read_to_string(self.dir.join("cgroup.procs")) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        body.lines()
            .filter_map(|l| l.trim().parse::<i32>().ok())
            .collect()
    }

    /// WO-155@v1: whether this scope can be reaped at all — either
    /// `cgroup.kill` (one trigger, 5.14+) or the `cgroup.freeze` + per-pid
    /// SIGKILL fallback (5.2+). `false` means a dead gate would leave a live
    /// unsupervised tree, so default mode must refuse to start here.
    pub fn can_reap(&self) -> bool {
        self.kill_path().exists() || self.freeze_path().exists()
    }

    /// True if `pid` is a member of this scope. Reads `/proc/<pid>/cgroup`,
    /// whose v2 line is `0::<relpath>`, and compares `<relpath>` to ours.
    ///
    /// A re-parented orphan still reports our scope here; a process outside the
    /// tree reports a different path. Unreadable (process gone, or a race) →
    /// `false`, and the caller's ancestry-walk fallback decides.
    // WO-59@v1: decide membership from the inherited cgroup identity.
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
    /// enforcing until it too is gone. Unreadable → `true` (fail closed: never
    /// treat a read failure as "empty"; the gate keeps enforcing).
    // WO-155@v1: keep enforcement alive until the scope is positively empty.
    pub fn is_populated(&self) -> bool {
        let events = match fs::read_to_string(self.dir.join("cgroup.events")) {
            Ok(s) => s,
            Err(_) => return true,
        };
        events_populated(&events)
    }
}

// WO-155@v1: remove an emptied run scope without weakening enforcement teardown.
impl Drop for CgroupScope {
    // WO-155@v1: retry removal only after the run scope has drained.
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

/// Apply the two OOM controls through caller-supplied paths so their contract
/// can be tested without root or a live cgroup hierarchy.
// WO-187@v1: keep the score adjustment active when cgroup memory is unavailable.
fn configure_oom_protection_at(scope_dir: &Path, score_path: &Path) -> io::Result<Option<String>> {
    let mut score = fs::OpenOptions::new().write(true).open(score_path)?;
    score.write_all(format!("{GATE_OOM_SCORE_ADJ}\n").as_bytes())?;
    let group_path = scope_dir.join(MEMORY_OOM_GROUP);
    let group_result = fs::OpenOptions::new()
        .write(true)
        .open(&group_path)
        .and_then(|mut group| group.write_all(b"1\n"));
    match group_result {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(format!(
            "could not enable {} for the supervised tree: {e}",
            group_path.display()
        ))),
    }
}

/// Undo the gate's inherited OOM preference in the forked agent before exec.
/// Async-signal-safe: only raw `open`, `write` and `close` calls run here.
///
/// # Safety
/// Must be called in the child between `fork()` and `execvp()`.
// WO-187@v1: never let the untrusted child inherit the gate's low OOM score.
pub unsafe fn reset_agent_oom_score() -> std::result::Result<(), i32> {
    let fd = libc::open(
        PROC_SELF_OOM_SCORE_ADJ_C.as_ptr() as *const libc::c_char,
        libc::O_WRONLY,
    );
    if fd < 0 {
        return Err(errno());
    }
    let written = libc::write(
        fd,
        AGENT_OOM_SCORE_ADJ.as_ptr() as *const libc::c_void,
        AGENT_OOM_SCORE_ADJ.len(),
    );
    libc::close(fd);
    if written < 0 || written as usize != AGENT_OOM_SCORE_ADJ.len() {
        return Err(errno());
    }
    Ok(())
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
// WO-59@v1: join the child before exec so descendants inherit membership.
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

// WO-59@v1: preserve the raw join failure across child-side libc calls.
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
// WO-59@v1: recognize reparented descendants by their inherited scope.
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
// WO-59@v1: include nested sub-cgroups without matching sibling name prefixes.
fn proc_cgroup_is(body: &str, rel: &str) -> bool {
    for line in body.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            return path == rel || path.starts_with(&format!("{rel}/"));
        }
    }
    false
}

/// True if a `cgroup.events` body reports the scope still has a member process.
/// A body whose `populated` key is missing is treated as STILL POPULATED (fail
/// closed): the caller must not conclude "empty" from a malformed read.
// WO-155@v1: require positive empty-scope evidence before teardown completes.
fn events_populated(body: &str) -> bool {
    for line in body.lines() {
        if let Some(v) = line.strip_prefix("populated ") {
            return v.trim() == "1";
        }
    }
    true
}

#[cfg(test)]
// WO-59@v1: pin the cgroup membership boundary and its fail-safe parsing.
mod tests {
    use super::*;

    #[test]
    // WO-59@v1: accept only the unified scope and its descendants.
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
    // WO-71@v1: reject peers not proven to occupy the supervised scope.
    fn pid_in_scope_negative_controls() {
        assert!(!pid_in_scope(
            std::process::id() as i32,
            "/bulwark.run-does-not-exist"
        ));
        assert!(!pid_in_scope(-1, "/whatever")); // unreadable pid → false
    }

    #[test]
    // WO-155@v1: malformed status must never be mistaken for an empty scope.
    fn populated_key_parsed() {
        assert!(events_populated("populated 1\nfrozen 0\n"));
        assert!(!events_populated("populated 0\nfrozen 0\n"));
        // Key absent / empty → fail closed to "still populated" (never empty).
        assert!(events_populated("frozen 0\n"));
        assert!(events_populated(""));
    }

    #[test]
    // WO-187@v1: keep OOM pressure inside the agent tree and away from its gate.
    fn oom_setup_groups_agent_tree_and_lowers_supervisor_score() {
        let scratch = crate::test_scratch_dir("oom-protection");
        let scope = scratch.join("scope");
        let score = scratch.join("oom_score_adj");
        fs::create_dir(&scope).unwrap();
        fs::write(scope.join("memory.oom.group"), "0\n").unwrap();
        fs::write(&score, "0\n").unwrap();

        let warning = configure_oom_protection_at(&scope, &score).unwrap();
        assert!(warning.is_none(), "unexpected warning: {warning:?}");
        assert_eq!(fs::read_to_string(&score).unwrap(), "-900\n");
        assert_eq!(
            fs::read_to_string(scope.join("memory.oom.group")).unwrap(),
            "1\n"
        );

        fs::remove_file(scope.join("memory.oom.group")).unwrap();
        fs::write(&score, "0\n").unwrap();
        let warning = configure_oom_protection_at(&scope, &score)
            .unwrap()
            .expect("missing memory controller must warn");
        assert!(warning.contains("memory.oom.group"), "{warning}");
        assert_eq!(fs::read_to_string(&score).unwrap(), "-900\n");
        assert!(!scope.join("memory.oom.group").exists());

        fs::remove_dir_all(scratch).unwrap();
    }
}
