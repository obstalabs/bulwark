//! Hardened mode: a crash-safe, kernel-enforced default-deny read floor via
//! Landlock.
//!
//! The fanotify gate is a *dynamic* consent layer — a userspace supervisor
//! answers each open. Its limit (verified) is that on hard supervisor death
//! the kernel releases held permission events as *allowed*: fanotify fails open
//! on `SIGKILL`/crash. For a crash-safe guarantee the default must already be
//! DENY in the kernel, independent of any process staying alive.
//!
//! Landlock provides exactly that. We apply a ruleset that denies all reads
//! except an explicit allow set, then `execvp` into the agent — same PID, no
//! separate supervisor. The restriction lives in the kernel, bound to the
//! process and all its future children, for life. There is nothing to kill, so
//! the floor is crash-safe by construction. Landlock also composes cleanly with
//! the rest of Bulwark: its deny is absolute (no userspace callback), so it is
//! the *outer* boundary; a fanotify consent layer, where used, operates only
//! within what Landlock already allows.
//!
//! This is a launcher, not a daemon: Landlock restricts the thread that applies
//! it and its children, not arbitrary already-running processes.

use std::ffi::CString;
use std::os::unix::io::RawFd;

use anyhow::{anyhow, bail, Context, Result};

// ---- Landlock ABI (not exposed by the libc crate; declared from the kernel
// uapi, which is stable). -----------------------------------------------------

const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

fn create_ruleset(attr: Option<&RulesetAttr>, flags: u32) -> i64 {
    let (ptr, size) = match attr {
        Some(a) => (
            a as *const _ as *const libc::c_void,
            std::mem::size_of::<RulesetAttr>(),
        ),
        None => (std::ptr::null(), 0),
    };
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, ptr, size, flags) }
}

fn add_rule(ruleset_fd: RawFd, attr: &PathBeneathAttr) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            attr as *const _ as *const libc::c_void,
            0u32,
        )
    }
}

fn restrict_self(ruleset_fd: RawFd) -> i64 {
    unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) }
}

/// The Landlock ABI version the running kernel supports, or `None` if Landlock
/// is unavailable.
pub fn abi_version() -> Option<i32> {
    let v = create_ruleset(None, LANDLOCK_CREATE_RULESET_VERSION);
    if v >= 1 {
        Some(v as i32)
    } else {
        None
    }
}

/// Apply a default-deny read floor allowing only `allow_paths`, then return.
/// After this call the current process (and any it forks/execs) can read only
/// files at or beneath an allowed path. Call immediately before `exec`ing the
/// agent.
///
/// `allow_paths` should include the runtime base set (so the agent can load its
/// interpreter and libc) plus the operator's grants. A path that does not exist
/// is skipped with a warning rather than failing the whole floor.
pub fn apply_read_floor(allow_paths: &[String]) -> Result<()> {
    if abi_version().is_none() {
        bail!("Landlock is not available on this kernel — hardened mode requires Landlock (Linux 5.13+)");
    }

    let attr = RulesetAttr {
        handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
        handled_access_net: 0,
        scoped: 0,
    };
    let ruleset_fd = create_ruleset(Some(&attr), 0);
    if ruleset_fd < 0 {
        return Err(anyhow!(std::io::Error::last_os_error())).context("landlock_create_ruleset");
    }
    let ruleset_fd = ruleset_fd as RawFd;

    let mut allowed = 0usize;
    for p in allow_paths {
        // Landlock rules are added by an O_PATH fd to the directory/file. A
        // glob like `/lib/**` is reduced to its concrete prefix `/lib` — a
        // path_beneath rule already means "this path and everything below it".
        let concrete = crate::glob::landlock_prefix(p);
        let cpath = match CString::new(concrete.as_bytes()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let parent_fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if parent_fd < 0 {
            eprintln!("[bulwark] hardened: skip allow {concrete} (not present)");
            continue;
        }
        let rule = PathBeneathAttr {
            allowed_access: LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
            parent_fd,
        };
        let rc = add_rule(ruleset_fd, &rule);
        unsafe {
            libc::close(parent_fd);
        }
        if rc != 0 {
            eprintln!("[bulwark] hardened: could not add allow rule for {concrete}");
        } else {
            allowed += 1;
        }
    }
    if allowed == 0 {
        bail!("hardened: no allow paths could be applied — the agent would be unable to run");
    }

    // no_new_privs is required before restrict_self, and also stops the agent
    // from escalating around the floor via setuid binaries.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(anyhow!(std::io::Error::last_os_error())).context("prctl(PR_SET_NO_NEW_PRIVS)");
    }
    if restrict_self(ruleset_fd) != 0 {
        return Err(anyhow!(std::io::Error::last_os_error())).context("landlock_restrict_self");
    }
    unsafe {
        libc::close(ruleset_fd);
    }
    eprintln!("[bulwark] hardened: kernel-enforced read floor applied ({allowed} allow path(s))");
    Ok(())
}
