//! Process-tree attribution.
//!
//! Walks `/proc/<pid>/stat` parent links to build the ancestry chain for a
//! PID, so a denied open can be attributed to `cat <- bash <- claude`. Also
//! answers "is this PID a descendant of the supervised root" so the gate only
//! judges opens from the tree it launched.

#[cfg(target_os = "linux")]
use std::fs;

/// One node in an ancestry chain.
#[derive(Debug, Clone)]
pub struct ProcNode {
    pub pid: i32,
    pub comm: String,
}

/// Read `(comm, ppid)` from `/proc/<pid>/stat`.
///
/// `comm` may contain spaces and parentheses, so parse from the LAST ')' —
/// everything before it (after the first '(') is the command name.
#[cfg(target_os = "linux")]
fn read_stat(pid: i32) -> Option<(String, i32)> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = raw[open + 1..close].to_string();
    // After ") " comes: state ppid ...
    let rest = raw[close + 2..].trim_start();
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    let ppid: i32 = fields.next()?.parse().ok()?;
    Some((comm, ppid))
}

/// read `(comm, ppid)` from libproc on macOS, where `/proc` is absent.
#[cfg(target_os = "macos")]
fn read_stat(pid: i32) -> Option<(String, i32)> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
        )
    };
    if size <= 0 {
        return None;
    }

    let mut name = [0 as libc::c_char; 128];
    let rc = unsafe { libc::proc_name(pid, name.as_mut_ptr().cast(), name.len() as u32) };
    let comm = if rc > 0 {
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        let bytes: Vec<u8> = name[..end].iter().map(|c| *c as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        "pid".to_string()
    };
    Some((comm, info.pbi_ppid as i32))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_stat(_pid: i32) -> Option<(String, i32)> {
    None
}

/// Build the ancestry chain for `pid`, nearest first: `[pid, parent, ...]`,
/// stopping at pid 1 or after `max_depth` hops.
pub fn ancestry(pid: i32, max_depth: usize) -> Vec<ProcNode> {
    let mut chain = Vec::new();
    let mut cur = pid;
    let mut depth = 0;
    while cur > 1 && depth < max_depth {
        match read_stat(cur) {
            Some((comm, ppid)) => {
                chain.push(ProcNode { pid: cur, comm });
                cur = ppid;
                depth += 1;
            }
            None => break,
        }
    }
    chain
}

/// Render an ancestry chain as `comm(pid) <- comm(pid) <- ...`.
pub fn render(chain: &[ProcNode]) -> String {
    chain
        .iter()
        .map(|n| format!("{}({})", n.comm, n.pid))
        .collect::<Vec<_>>()
        .join(" <- ")
}

/// True if `pid` is `root` or has `root` somewhere in its ancestry — i.e. it
/// belongs to the supervised process tree.
pub fn is_descendant_of(pid: i32, root: i32, max_depth: usize) -> bool {
    if pid == root {
        return true;
    }
    let mut cur = pid;
    let mut depth = 0;
    while cur > 1 && depth < max_depth {
        match read_stat(cur) {
            Some((_, ppid)) => {
                if ppid == root {
                    return true;
                }
                cur = ppid;
                depth += 1;
            }
            None => break,
        }
    }
    false
}

// proctree reads /proc (Linux-only), so its tests are Linux-meaningful.
// Gate them to Linux so `cargo test` is green on macOS without --skip, while
// keeping full proctree coverage on Linux (the cfg keeps them ON there).
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn ancestry_of_self_is_nonempty_and_starts_with_self() {
        let me = std::process::id() as i32;
        let chain = ancestry(me, 16);
        assert!(!chain.is_empty(), "self ancestry should not be empty");
        assert_eq!(chain[0].pid, me, "nearest node should be self");
    }

    #[test]
    fn self_is_descendant_of_self() {
        let me = std::process::id() as i32;
        assert!(is_descendant_of(me, me, 16));
    }

    #[test]
    fn self_is_descendant_of_parent() {
        let me = std::process::id() as i32;
        // Our parent is whoever launched the test binary.
        if let Some((_, ppid)) = read_stat(me) {
            if ppid > 1 {
                assert!(is_descendant_of(me, ppid, 16));
            }
        }
    }

    #[test]
    fn unrelated_low_pid_is_not_descendant() {
        let me = std::process::id() as i32;
        // pid 2 (kthreadd) is never our child.
        assert!(!is_descendant_of(2, me, 16));
    }
}
