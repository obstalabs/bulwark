//! Native off-band consent channel over a Unix domain socket.
//!
//! The supervisor (`bulwark run`) binds a listening socket. When the gate needs
//! a verdict it accepts one connection, sends a one-line request, and reads a
//! one-line verdict, all under a deadline. The `bulwark consent` operator
//! client connects to the same socket, shows the request, and sends the
//! operator's choice back.
//!
//! Off-band is enforced structurally, not by obscurity: on accept, the
//! supervisor reads the peer's process identity (`SO_PEERCRED` on Linux,
//! `LOCAL_PEERPID` on macOS) and REJECTS any
//! connection whose PID belongs to the supervised process tree. So even if a
//! prompt-injected agent discovered the socket path, it cannot answer its own
//! consent request — consent the subject can forge is not consent.
//!
//! Wire protocol (newline-terminated, never carries file content):
//!   request:  `REQUEST\tpid=<pid>\tino=<dev>:<ino>\tpath=<path>\treason=<reason>\tancestry=<chain>\n`
//!   reply:    `<verdict>\n`  where verdict ∈ allow-once|allow-session|deny|deny-forever

use std::ffi::CString;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use crate::consent::{ConsentProvider, ConsentRequest, Source, Verdict};
use crate::proctree;
use crate::receipt::LogSink;

const ANCESTRY_MAX_DEPTH: usize = 16;

/// WO-147/154@v1: the maximum length (bytes) of a verdict line accepted from the
/// operator. A longer reply is malformed — and a bounded read defeats a peer
/// that trickles an unbounded line to hold the event open — so it is denied.
const VERDICT_LINE_MAX: usize = 64;

/// Read the peer PID of a connected Unix socket via `SO_PEERCRED`.
#[cfg(target_os = "linux")]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(cred.pid)
}

/// WO-24: macOS preserves off-band consent with `LOCAL_PEERPID`.
#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(pid)
}

/// Encode a request as the wire line (tab-separated, newline-terminated).
fn encode_request(req: &ConsentRequest) -> String {
    // Tabs/newlines in fields would corrupt the framing; paths/ancestry from
    // /proc don't contain tabs, but sanitize defensively.
    let clean = |s: &str| s.replace(['\t', '\n', '\r'], " ");
    format!(
        "REQUEST\tpid={}\tino={}:{}\tpath={}\treason={}\tancestry={}\n",
        req.pid,
        req.key.dev,
        req.key.ino,
        clean(&req.path),
        clean(&req.reason),
        clean(&req.ancestry),
    )
}

/// Parse a wire request line into its fields (for the operator client display).
pub fn parse_request(line: &str) -> Option<Vec<(String, String)>> {
    let line = line.strip_prefix("REQUEST\t")?;
    let mut out = Vec::new();
    for part in line.trim_end().split('\t') {
        if let Some((k, v)) = part.split_once('=') {
            out.push((k.to_string(), v.to_string()));
        }
    }
    Some(out)
}

/// WO-147@v1: the invoking user under sudo (`SUDO_UID`/`SUDO_GID`),
/// or `None` when not launched via sudo. Only the node (never the directory) is
/// chowned to this user, through the directory fd, so `bulwark consent` can
/// connect.
fn invoking_user() -> Option<(u32, u32)> {
    match (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        (Ok(u), Ok(g)) => match (u.parse::<u32>(), g.parse::<u32>()) {
            (Ok(u), Ok(g)) => Some((u, g)),
            _ => None,
        },
        _ => None,
    }
}

/// WO-147@v1: the on-disk socket node for a requested socket path. The node
/// lives inside a sibling directory (`<requested>.d`) that [`SocketProvider::bind`]
/// creates, so the socket's own mode — and therefore the process-wide umask —
/// never matters. The supervisor and the operator derive this from the same
/// requested path, so `bulwark consent --socket <requested>` reaches it.
pub fn bound_path(requested: &Path) -> PathBuf {
    let mut dir = requested.as_os_str().to_os_string();
    dir.push(".d");
    std::path::PathBuf::from(dir).join("s")
}

/// WO-147@v3: a relative socket path is resolved against the current working
/// directory, so the supervisor and the operator derive the same absolute node
/// and the safe-path walk always starts from a real path.
pub(crate) fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|d| d.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// WO-147@v1: the longest node path this platform's `sockaddr_un`
/// accepts — the `sun_path` field's size minus its trailing NUL (Linux 107,
/// macOS 103). Not a hard-coded constant.
fn sun_path_max() -> usize {
    let su: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    std::mem::size_of_val(&su.sun_path) - 1
}

/// WO-147@v1: a directory may be reused only if it is a real
/// directory owned by `uid` with no group/other write bit (mode & 0o022 == 0).
/// A symlink, a regular file, a dir owned by someone else, or a
/// group/other-writable dir is refused — never deleted, never chmod'd.
fn dir_reusable(st: &libc::stat, uid: u32) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFDIR && st.st_uid == uid && (st.st_mode & 0o022) == 0
}

/// WO-147@v1: open `dir` as a directory without following a symlink
/// in the final component (`O_DIRECTORY|O_NOFOLLOW`), so every later metadata
/// change goes through this fd and cannot race a path swap.
fn open_dir_nofollow(dir: &Path) -> Result<RawFd> {
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| anyhow!("consent socket dir contains a NUL: {}", dir.display()))?;
    // SAFETY: c is a valid NUL-terminated path; the fd is closed by the caller.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if fd < 0 {
        return Err(anyhow!(std::io::Error::last_os_error()))
            .with_context(|| format!("open consent socket dir {}", dir.display()));
    }
    Ok(fd)
}

/// WO-147@v2: revalidate a just-opened consent socket dir fd and return its
/// `fstat`. Refuses (closing the fd) unless the OPENED object is a real
/// directory owned by `uid` with no group/other write. This is the check the
/// whole rest of the bind depends on: `fchmod(fd)` and every later
/// `fchmodat(dirfd, "s", 0600, 0)` is safe only if the fd names a directory we
/// own and nobody else can write — a same-uid process that swapped the path
/// between mkdir/lstat and open must be refused here, not after we have chmod'd
/// the attacker's dir.
fn verified_dir_fd(fd: RawFd, uid: u32, what: &Path) -> Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: st is a valid out-param; fd is a held O_DIRECTORY|O_NOFOLLOW fd.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(anyhow!(e))
            .with_context(|| format!("fstat consent socket dir {}", what.display()));
    }
    if !dir_reusable(&st, uid) {
        unsafe { libc::close(fd) };
        anyhow::bail!(
            "refusing consent socket dir {}: the opened directory is not owned by \
             uid {uid} without group/other write",
            what.display()
        );
    }
    Ok(st)
}

/// WO-147@v3: the verified socket directory handed back by
/// [`prepare_socket_dir`]: the held `O_DIRECTORY|O_NOFOLLOW` fd plus its pinned
/// dev/ino, so the provider can later refuse to act on a swapped-in replacement.
struct PreparedDir {
    fd: RawFd,
    dev: libc::dev_t,
    ino: libc::ino_t,
}

/// WO-147@v1: prepare the socket directory. Create it fresh with
/// `mkdir` (a fresh create proves ownership — an attacker cannot pre-create a
/// dir owned by us), or, if it already exists, reuse it only under
/// [`dir_reusable`]. Returns an `O_DIRECTORY|O_NOFOLLOW` fd and the verified
/// dir's dev/ino; never deletes or chmods a foreign node, never follows a
/// symlink.
fn prepare_socket_dir(dir: &Path) -> Result<PreparedDir> {
    use std::os::unix::ffi::OsStrExt;
    let euid = unsafe { libc::geteuid() };
    let mode: libc::mode_t = if euid == 0 { 0o711 } else { 0o700 };
    let c = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| anyhow!("consent socket dir contains a NUL: {}", dir.display()))?;
    // `Some((dev, ino))` when mkdir succeeded (we created the object), so the
    // subsequent open of the same path must land on that object.
    let created: Option<(libc::dev_t, libc::ino_t)> =
        if unsafe { libc::mkdir(c.as_ptr(), mode) } == 0 {
            // WO-147@v2: lstat the path IMMEDIATELY after a fresh mkdir and pin its
            // dev/ino, so the opened fd can be required to name the same object.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: lstat on the path; st is a valid out-param.
            if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
                let e = std::io::Error::last_os_error();
                return Err(anyhow!(e))
                    .with_context(|| format!("stat consent socket dir {}", dir.display()));
            }
            Some((st.st_dev, st.st_ino))
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                return Err(anyhow!(err))
                    .with_context(|| format!("mkdir consent socket dir {}", dir.display()));
            }
            // Pre-existing: lstat (never follow) and reuse only under dir_reusable.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: lstat on the path; st is a valid out-param.
            if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
                let e = std::io::Error::last_os_error();
                return Err(anyhow!(e))
                    .with_context(|| format!("stat consent socket dir {}", dir.display()));
            }
            if !dir_reusable(&st, euid) {
                anyhow::bail!(
                    "refusing consent socket dir {}: it exists and is not a directory owned by \
                 uid {euid} without group/other write",
                    dir.display()
                );
            }
            None
        };
    let fd = open_dir_nofollow(dir)?;
    let fdst = verified_dir_fd(fd, euid, dir)?;
    // A fresh create must open onto the very object we just mkdir'd; a swap in a
    // user-writable parent defeats the mkdir proof, so refuse the mismatch.
    if let Some((dev, ino)) = created {
        if (fdst.st_dev, fdst.st_ino) != (dev, ino) {
            unsafe { libc::close(fd) };
            anyhow::bail!(
                "refusing consent socket dir {}: it changed between mkdir and open",
                dir.display()
            );
        }
    }
    // Fix the mode through the opened fd (defeats a permissive umask on the
    // fresh create, and a pre-existing loose mode). Safe: verified_dir_fd proved
    // the fd names a directory owned by euid with no group/other write.
    if unsafe { libc::fchmod(fd, mode) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(anyhow!(e))
            .with_context(|| format!("chmod consent socket dir {}", dir.display()));
    }
    Ok(PreparedDir {
        fd,
        dev: fdst.st_dev,
        ino: fdst.st_ino,
    })
}

/// WO-147@v1: when root, the default socket's parent is the
/// root-owned runtime dir. Ensure it exists 0711 root-owned, or refuse if it
/// is a foreign node (a symlink, another owner, or group/other-writable).
/// No-op for any other parent (explicit `--consent-socket`, or a non-root run).
fn ensure_root_parent(parent: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let is_runtime = parent == Path::new("/run/bulwark") || parent == Path::new("/var/run/bulwark");
    if !is_runtime {
        return Ok(());
    }
    let c = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| anyhow!("consent parent dir contains a NUL: {}", parent.display()))?;
    // SAFETY: mkdir 0711; a fresh create proves ownership.
    if unsafe { libc::mkdir(c.as_ptr(), 0o711) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(anyhow!(err))
                .with_context(|| format!("mkdir consent parent dir {}", parent.display()));
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: lstat never follows the final component; st is a valid out-param.
        if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(anyhow!(e))
                .with_context(|| format!("stat consent parent dir {}", parent.display()));
        }
        if !dir_reusable(&st, 0) {
            anyhow::bail!(
                "refusing consent parent dir {}: it exists and is not a root-owned directory \
                 without group/other write",
                parent.display()
            );
        }
    }
    // WO-147@v3: fix the mode through a verified
    // O_DIRECTORY|O_NOFOLLOW fd even on a fresh create — a permissive umask
    // (077) would otherwise leave a root-only 0700 dir the invoking user cannot
    // traverse to reach the chowned node.
    let fd = open_dir_nofollow(parent)?;
    let _ = verified_dir_fd(fd, 0, parent)?;
    if unsafe { libc::fchmod(fd, 0o711) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(anyhow!(e))
            .with_context(|| format!("chmod consent parent dir {}", parent.display()));
    }
    unsafe { libc::close(fd) };
    Ok(())
}

/// WO-147@v3: a StrictModes-style safe-path check. Canonicalize the parent of
/// `<sock>.d`, then walk every ancestor component from the filesystem root down;
/// each must be a real directory owned by root or the effective uid and either
/// have no group/other write or carry the sticky bit. Checking only the
/// immediate parent is not enough — an ancestor writable by another user (e.g. a
/// root-owned runtime dir inside that user's home) lets that user rename the
/// whole subtree away between the check and the bind. `/tmp` (1777 sticky)
/// passes; `/home/<uid>` (0755) passes; a foreign-owned or 0777-non-sticky
/// component is refused, naming it.
fn check_parent(parent: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let euid = unsafe { libc::geteuid() };
    // Canonicalize first (resolves symlinks and `.`/`..`) so the walk follows
    // the path the kernel will actually resolve.
    let canon = std::fs::canonicalize(parent).with_context(|| {
        format!(
            "cannot resolve consent socket parent dir {}",
            parent.display()
        )
    })?;
    let mut cur = std::path::PathBuf::from("/");
    for comp in canon.components() {
        match comp {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(part) => cur.push(part),
            // CurDir/ParentDir do not survive canonicalize; skip defensively.
            _ => continue,
        }
        let c = CString::new(cur.as_os_str().as_bytes())
            .map_err(|_| anyhow!("consent socket parent component contains a NUL"))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: lstat never follows a final-component symlink; st is a valid
        // out-param. A symlink planted in an ancestor after canonicalize is
        // refused (S_IFLNK is not S_IFDIR) rather than followed.
        if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(anyhow!(e)).with_context(|| {
                format!("stat consent socket parent component {}", cur.display())
            });
        }
        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let owned = st.st_uid == 0 || st.st_uid == euid;
        let no_grp_other_write = (st.st_mode & 0o022) == 0;
        let sticky = (st.st_mode & libc::S_ISVTX) != 0;
        if !(is_dir && owned && (no_grp_other_write || sticky)) {
            anyhow::bail!(
                "refusing consent socket parent dir {}: component {} is not a directory owned by root or uid {euid} without group/other write (or sticky)",
                canon.display(),
                cur.display()
            );
        }
    }
    Ok(())
}

/// The supervisor side: owns the listening socket and answers gate requests by
/// talking to whichever operator client connects.
pub struct SocketProvider {
    listener: UnixListener,
    path: PathBuf,
    supervised_root: i32,
    timeout: Duration,
    /// WO-147@v3: the exclusivity `flock` on `<sock>.d/lock`, held for
    /// the provider's lifetime so a second run on the same path is refused.
    lock_fd: RawFd,
    /// WO-147@v3: the verified socket dir's dev/ino, pinned at bind.
    /// Drop must refuse to touch a replacement directory whose dev/ino differs,
    /// so a real-directory swap after bind leaves the replacement intact.
    dir_dev: libc::dev_t,
    dir_ino: libc::ino_t,
    /// The supervised tree's cgroup scope (relative path), set by `bind_scope`
    /// once the gate creates the scope. When present (Linux with cgroup-v2), a
    /// peer in this scope is refused as an answerer — reparent-proof, so a
    /// double-fork()'d orphan that sheds its ancestry still cannot self-answer.
    /// `None` falls back to the ancestry check alone (macOS, or a v1 host).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    scope_rel: Option<String>,
    /// WO-147/154@v1: the gate's log sink, attached once the gate has its log.
    /// Peer-refusal and socket-error diagnostics go through it (never a
    /// synchronous stderr write) so the consent worker cannot stall on output.
    /// `None` until `attach_log`; the refusal is enforced regardless.
    sink: Option<LogSink>,
}

impl SocketProvider {
    /// Bind the consent socket for the requested `path`, rejecting requests not
    /// answered within `timeout`. `supervised_root` is the agent tree's root
    /// pid; peers in that tree are refused as answerers.
    ///
    /// WO-147@v1: the node lives inside a sibling directory that is
    /// created fresh with `mkdir` (or reused only if owned by us and not
    /// group/other-writable); every metadata change goes through an
    /// `O_DIRECTORY|O_NOFOLLOW` fd, so nothing ever acts on a swappable path.
    /// The directory stays owned by the effective uid; only the node is chowned
    /// (0600, to the invoking user under sudo), so the agent cannot rename or
    /// replace the node. Peer checks are unchanged.
    pub fn bind(path: &Path, supervised_root: i32, timeout: Duration) -> Result<Self> {
        // WO-147@v3: resolve a relative request against the cwd before deriving
        // the node, so the supervisor and the client reach the same absolute path.
        let path = absolutize(path);
        let socket = bound_path(&path);
        // WO-147@v1: the node path must fit a sockaddr_un sun_path
        // (108 bytes including the NUL). Refuse up front with the limit, rather
        // than fail deep inside the bind with an opaque error.
        {
            use std::os::unix::ffi::OsStrExt;
            let sun_max = sun_path_max();
            let node_len = socket.as_os_str().as_bytes().len();
            if node_len > sun_max {
                anyhow::bail!(
                    "consent socket path {} is {} bytes; the unix-socket sun_path limit is {}",
                    socket.display(),
                    node_len,
                    sun_max
                );
            }
        }
        let dir = socket
            .parent()
            .ok_or_else(|| anyhow!("consent socket path has no parent: {}", socket.display()))?;
        let parent = dir
            .parent()
            .ok_or_else(|| anyhow!("consent socket dir has no parent: {}", dir.display()))?;
        // ensure the root-only runtime parent when root (no-op for
        // an explicit --consent-socket or a non-root run).
        ensure_root_parent(parent)?;
        // WO-147@v3: the parent must be a directory root/euid cannot
        // have renamed out from under us before mkdir of <sock>.d.
        check_parent(parent)?;
        let prepared = prepare_socket_dir(dir)?;
        let dir_dev = prepared.dev;
        let dir_ino = prepared.ino;
        let dirfd = prepared.fd;

        // WO-147@v3: take an exclusive run lock inside <sock>.d before
        // ever unlinking a stale node, so a second run on the same path cannot
        // silently steal the first run's live socket and its verdicts. The lock
        // fd is held for the provider's lifetime.
        let lock = CString::new("lock").expect("static lock leaf has no NUL");
        // SAFETY: openat within the pinned dir fd, no symlink follow, close-on-exec.
        let lock_fd = unsafe {
            libc::openat(
                dirfd,
                lock.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if lock_fd < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(dirfd) };
            return Err(anyhow!(e)).with_context(|| "open consent socket lock");
        }
        // SAFETY: flock on the held lock fd; EWOULDBLOCK means another run still
        // owns the node.
        if unsafe { libc::flock(lock_fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error();
            unsafe {
                libc::close(lock_fd);
                libc::close(dirfd);
            }
            if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                anyhow::bail!(
                    "another bulwark run is using consent socket {}; pass --consent-socket <other path>",
                    path.display()
                );
            }
            return Err(anyhow!(e)).with_context(|| "flock consent socket lock");
        }

        // Remove a stale node from a prior run (ours; through the dir fd, so a
        // path swap cannot redirect it). Only after the lock is held may the
        // stale node be unlinked. ENOENT (no stale node) is the only tolerated
        // error.
        let node = CString::new("s").expect("static node leaf has no NUL");
        // SAFETY: unlinkat on the pinned dir fd.
        if unsafe { libc::unlinkat(dirfd, node.as_ptr(), 0) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ENOENT) {
                unsafe {
                    libc::close(lock_fd);
                    libc::close(dirfd);
                }
                return Err(anyhow!(e)).with_context(|| "unlinkat stale consent node");
            }
        }

        let listener = match UnixListener::bind(&socket) {
            Ok(l) => l,
            Err(e) => {
                // WO-147@v1: don't leak the dir fd, or the lock, if the bind fails.
                unsafe {
                    libc::close(lock_fd);
                    libc::close(dirfd);
                }
                return Err(anyhow!(e))
                    .with_context(|| format!("cannot bind consent socket {}", socket.display()));
            }
        };

        // WO-147@v1: set the node 0600 with fchmodat flag 0 (the dirfd
        // is pinned, not writable by anyone else, and the node was just created by
        // bind), then VERIFY via fstatat and refuse if it is not a 0600 socket
        // owned by the intended uid. Every checked syscall names itself and its
        // errno on failure.
        let euid = unsafe { libc::geteuid() };
        let intended_uid = invoking_user().map(|(uid, _gid)| uid).unwrap_or(euid);
        unsafe {
            if libc::fchmodat(dirfd, node.as_ptr(), 0o600, 0) != 0 {
                // WO-147@v1: remove the just-bound node on every
                // failure before closing the dir fd and the lock, so no half-set
                // node lingers.
                let e = std::io::Error::last_os_error();
                libc::unlinkat(dirfd, node.as_ptr(), 0);
                libc::close(lock_fd);
                libc::close(dirfd);
                return Err(anyhow!(e)).with_context(|| "fchmodat consent node");
            }
            if let Some((uid, gid)) = invoking_user() {
                if libc::fchownat(dirfd, node.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW) != 0 {
                    let e = std::io::Error::last_os_error();
                    libc::unlinkat(dirfd, node.as_ptr(), 0);
                    libc::close(lock_fd);
                    libc::close(dirfd);
                    return Err(anyhow!(e)).with_context(|| "fchownat consent node");
                }
            }
            // Verify what we just set: a 0600 socket owned by the intended uid.
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstatat(dirfd, node.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) != 0 {
                let e = std::io::Error::last_os_error();
                libc::unlinkat(dirfd, node.as_ptr(), 0);
                libc::close(lock_fd);
                libc::close(dirfd);
                return Err(anyhow!(e)).with_context(|| "fstatat consent node");
            }
            let ok = (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK
                && (st.st_mode & 0o777) == 0o600
                && st.st_uid == intended_uid;
            if !ok {
                libc::unlinkat(dirfd, node.as_ptr(), 0);
                libc::close(lock_fd);
                libc::close(dirfd);
                anyhow::bail!(
                    "consent node is not a 0600 socket owned by uid {intended_uid} \
                     (mode {:o} uid {})",
                    st.st_mode & 0o777,
                    st.st_uid
                );
            }
        }

        // Non-blocking accept so we can enforce the deadline via poll. The dirfd
        // is kept open through this step: on failure the just-bound node is
        // unlinked through it before it is closed, so no stale node lingers.
        if let Err(e) = listener.set_nonblocking(true) {
            unsafe {
                libc::unlinkat(dirfd, node.as_ptr(), 0);
                libc::close(lock_fd);
                libc::close(dirfd);
            }
            return Err(anyhow!(e)).context("set_nonblocking on consent socket");
        }
        // SAFETY: the dirfd has served its purpose; every later node operation is
        // done through the held fd in SocketProvider without needing the dir.
        unsafe { libc::close(dirfd) };

        Ok(SocketProvider {
            listener,
            path: socket,
            supervised_root,
            timeout,
            scope_rel: None,
            sink: None,
            lock_fd,
            dir_dev,
            dir_ino,
        })
    }

    /// True if `pid` belongs to the supervised tree and so must be refused as a
    /// consent answerer — "consent the subject can forge is not consent". Tree
    /// membership is the cgroup scope when known (reparent-proof) OR the ancestry
    /// walk. The two are OR'd so cgroup can only *add* members ancestry misses:
    /// the double-fork()'d orphan that reparented to init still carries the
    /// scope. Where no scope is bound (macOS, v1 host) ancestry is the only
    /// check — a documented residual for those hosts.
    fn peer_in_tree(&self, pid: i32) -> bool {
        #[cfg(target_os = "linux")]
        if let Some(rel) = &self.scope_rel {
            if crate::cgroup::pid_in_scope(pid, rel) {
                return true;
            }
        }
        pid == self.supervised_root
            || proctree::is_descendant_of(pid, self.supervised_root, ANCESTRY_MAX_DEPTH)
    }

    /// True only if `pid` is a process we can still observe (its `/proc/<pid>`
    /// exists). `SO_PEERCRED` reports the pid captured at `connect()`, which
    /// survives the peer's death — so a supervised child can connect, send a
    /// verdict, and `exit()` before we check membership; its `/proc` entry then
    /// vanishes, the in-tree test silently fails to prove membership, and a
    /// "reject only if provably in-tree" rule would accept the dead in-tree peer.
    /// We therefore require the peer to be LIVE: a peer we cannot observe cannot
    /// be proven off-band, so it is refused (fail closed). The connection's own
    /// open fd keeps the socket alive for the verdict exchange even if the writer
    /// process has exited — but we will not *trust* a verdict from a process we
    /// can no longer attribute.
    #[cfg(target_os = "linux")]
    fn peer_is_live(pid: i32) -> bool {
        pid > 0 && std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(target_os = "macos")]
    fn peer_is_live(pid: i32) -> bool {
        // kill(pid, 0) succeeds iff the process exists and we may signal it.
        pid > 0 && unsafe { libc::kill(pid, 0) } == 0
    }

    /// Queue a diagnostic through the gate's log sink. A no-op before the sink is
    /// attached (and on the socket unit tests, which bind without a gate behind
    /// them) — the refusal is enforced regardless; this is observability only.
    fn warn(&self, line: &str) {
        if let Some(sink) = &self.sink {
            sink.warn(line);
        }
    }

    /// Wait until `deadline` for an operator client to connect, refusing any
    /// peer inside the supervised tree. `deadline` is the request's absolute
    /// cut-off (arrival + consent timeout), shared with the write/read phases, so
    /// a queued request is bounded to what remains of its own consent window.
    fn accept_operator_for(&self, deadline: std::time::Instant) -> Result<Option<UnixStream>> {
        let lfd = self.listener.as_raw_fd();
        loop {
            // Fail closed on shutdown, graceful or a draining normal exit: if a
            // termination signal arrived or the supervisor is tearing the tree
            // down, abandon the operator wait and deny (the poll cap below
            // bounds how long until we notice).
            if crate::gate::shutdown_requested() || crate::gate::draining() {
                return Ok(None);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let mut pfd = libc::pollfd {
                fd: lfd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = remaining.as_millis().min(1000) as libc::c_int;
            let pr = unsafe { libc::poll(&mut pfd, 1, ms) };
            if pr < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(anyhow!(e)).context("poll consent socket");
            }
            if pr == 0 {
                continue; // timeout slice; loop re-checks the deadline
            }
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    // OFF-BAND ENFORCEMENT (fail closed): accept ONLY a peer we can
                    // positively prove is a live process outside the agent tree.
                    // A peer that is in the tree (cgroup membership / ancestry), one
                    // we cannot identify (no SO_PEERCRED), or one that has already
                    // EXITED (so we can no longer attribute it — the dead-peer race,
                    // where a supervised child connects, sends a verdict, and dies
                    // before this check) is refused. "Reject only if provably
                    // in-tree" would accept the dead in-tree peer; "accept only if
                    // provably live and out-of-tree" does not.
                    match peer_pid(&stream) {
                        None => {
                            self.warn(
                                "refused consent connection with unidentifiable peer \
                                 (no SO_PEERCRED); cannot prove it is off-band",
                            );
                            continue;
                        }
                        Some(pid) if !Self::peer_is_live(pid) => {
                            self.warn(&format!(
                                "refused consent connection from pid {pid} that is no \
                                 longer observable (cannot attribute; a supervised child may not \
                                 answer its own consent by exiting before the check)"
                            ));
                            continue;
                        }
                        Some(pid) if self.peer_in_tree(pid) => {
                            self.warn(&format!(
                                "refused consent connection from supervised pid {pid} \
                                 (agent may not answer its own consent)"
                            ));
                            continue;
                        }
                        Some(_) => return Ok(Some(stream)),
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(anyhow!(e)).context("accept consent connection"),
            }
        }
    }
}

impl Drop for SocketProvider {
    fn drop(&mut self) {
        // Unlink the node while still holding the run lock, then release the
        // lock last — so a racing second bind cannot publish its node while this
        // run's teardown is still live and have it deleted out from under it.
        // The lock file itself is never unlinked: it is a permanent sibling.
        remove_consent_node(&self.path, self.dir_dev, self.dir_ino);
        unsafe { libc::close(self.lock_fd) };
    }
}

/// WO-147@v3: unlink the node through the directory fd, never by path — and only
/// after confirming that the directory the path now resolves to is still the one
/// pinned at bind (`dir_dev`/`dir_ino`), so a real-directory swap is never
/// touched. The lock file (and the directory) are left in place: the lock is a
/// permanent sibling and the directory is re-validated and reused on every bind.
fn remove_consent_node(node: &Path, dir_dev: libc::dev_t, dir_ino: libc::ino_t) {
    let Some(dir) = node.parent() else { return };
    let Ok(dirfd) = open_dir_nofollow(dir) else {
        return;
    };
    let mut fd_st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat on the held fd; the stat is a valid out-param. The held
    // `O_DIRECTORY|O_NOFOLLOW` fd names whatever the path currently resolves to,
    // so comparing its dev/ino against the pinned pair detects a swapped-in dir.
    let same = unsafe { libc::fstat(dirfd, &mut fd_st) } == 0
        && fd_st.st_dev == dir_dev
        && fd_st.st_ino == dir_ino;
    if same {
        let leaf = CString::new("s").expect("static leaf has no NUL");
        // SAFETY: unlinkat on the pinned dir fd; ignores a missing node.
        unsafe { libc::unlinkat(dirfd, leaf.as_ptr(), 0) };
    }
    unsafe { libc::close(dirfd) };
}

impl ConsentProvider for SocketProvider {
    fn bind_scope(&mut self, scope_rel: Option<&str>) {
        self.scope_rel = scope_rel.map(|s| s.to_string());
    }

    fn attach_log(&mut self, sink: LogSink) {
        self.sink = Some(sink);
    }

    fn request(&mut self, req: &ConsentRequest) -> (Verdict, Source) {
        self.request_for(req, self.timeout)
    }

    fn request_with_timeout(
        &mut self,
        req: &ConsentRequest,
        timeout: Duration,
    ) -> (Verdict, Source) {
        self.request_for(req, timeout)
    }
}

impl SocketProvider {
    /// Answer one request. The accept, write, and read phases all share one
    /// absolute deadline (arrival + `timeout`), enforced by `poll()` before every
    /// syscall on the non-blocking stream — so a peer that stalls, trickles bytes
    /// one at a time, or overflows the verdict line is denied at (or before) the
    /// deadline, never blocked past it.
    fn request_for(&mut self, req: &ConsentRequest, timeout: Duration) -> (Verdict, Source) {
        // WO-147/154@v1: ONE absolute deadline per request (arrival + timeout),
        // shared by accept, write and read and never reset per phase.
        let deadline = std::time::Instant::now() + timeout;
        let stream = match self.accept_operator_for(deadline) {
            Ok(Some(s)) => s,
            Ok(None) => return (Verdict::Deny, Source::Timeout),
            Err(e) => {
                self.warn(&format!("consent socket error: {e}; denying"));
                return (Verdict::Deny, Source::Timeout);
            }
        };
        // Keep the stream non-blocking: every read/write below is gated by
        // poll() against the absolute deadline (a per-syscall SO_RCVTIMEO/SNDTIMEO
        // would re-arm on each trickled byte and let the peer hold the event
        // forever). A setup that cannot switch to non-blocking is a denial.
        if stream.set_nonblocking(true).is_err() {
            return (Verdict::Deny, Source::Timeout);
        }
        let fd = stream.as_raw_fd();
        let mut stream = stream;

        // Write the request line: poll(writable) before each write until done, all
        // against the one absolute deadline.
        let bytes = encode_request(req).into_bytes();
        let mut written = 0usize;
        while written < bytes.len() {
            if !poll_ready(fd, libc::POLLOUT, deadline) {
                return (Verdict::Deny, Source::Timeout);
            }
            match stream.write(&bytes[written..]) {
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => return (Verdict::Deny, Source::Timeout),
            }
        }

        // Read the verdict line, capped, one poll(readable)+read at a time, all
        // against the same deadline.
        let mut line = [0u8; VERDICT_LINE_MAX];
        let mut len = 0usize;
        loop {
            if len > 0 && line[..len].contains(&b'\n') {
                break;
            }
            if len >= VERDICT_LINE_MAX {
                return (Verdict::Deny, Source::Timeout); // verdict line too long
            }
            if !poll_ready(fd, libc::POLLIN, deadline) {
                return (Verdict::Deny, Source::Timeout);
            }
            match stream.read(&mut line[len..len + 1]) {
                Ok(0) => break, // peer closed mid-line
                Ok(n) => len += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => return (Verdict::Deny, Source::Timeout),
            }
        }
        let text = String::from_utf8_lossy(&line[..len]);
        match Verdict::parse(&text) {
            Some(v) => (v, Source::Operator),
            None => (Verdict::Deny, Source::Operator),
        }
    }
}

/// WO-147/154@v1: poll `fd` for `events`, bounded by the absolute `deadline`.
/// True only when the event becomes ready before then; false at the deadline, on
/// a real poll error, or on shutdown. Each poll slice stays ≤ 1 s (so a signal is
/// noticed promptly) but the slices LOOP until the deadline — a slice expiring is
/// not a deny, so an operator who answers at, say, 1.5 s of a 30 s window is
/// still heard.
fn poll_ready(fd: RawFd, events: libc::c_short, deadline: std::time::Instant) -> bool {
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        if crate::gate::shutdown_requested() || crate::gate::draining() {
            return false;
        }
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // The 1 s cap keeps shutdown noticed within a second; the outer loop
        // re-polls until the deadline, never treating an expired slice as a deny.
        let ms = remaining.as_millis().min(1000) as libc::c_int;
        let pr = unsafe { libc::poll(&mut pfd, 1, ms) };
        if pr < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue; // re-derive the deadline and re-poll
            }
            return false; // a real poll error
        }
        if pr > 0 && (pfd.revents & events) != 0 {
            return true;
        }
        // pr == 0: the slice expired without readiness — loop, don't deny.
    }
}

/// Operator-client side of `bulwark consent`: connect to the socket, print the
/// request, and send the operator's verdict. One-shot (answers a single
/// pending request). Returns the verdict string sent.
pub fn answer_once(socket: &Path, verdict: Option<Verdict>) -> Result<String> {
    // WO-147@v3: resolve a relative request against the cwd (the supervisor
    // does the same in `bind`), then both sides derive the same on-disk node.
    let socket = absolutize(socket);
    let node = bound_path(&socket);
    // Retry the connect briefly: the operator may invoke `bulwark consent` a
    // moment before the supervised tree triggers a protected open (so the
    // supervisor is not yet accepting), or just after binding. A short backoff
    // makes the client robust instead of failing the race.
    let stream = connect_with_retry(&node, Duration::from_secs(5))?;
    // WO-147@v3: a bounded read timeout, so the client can never block forever
    // if the gate does not answer (a stale or foreign node).
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .context("set consent read timeout")?;
    let mut writer = stream.try_clone().context("clone consent stream")?;
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| {
        anyhow!(
            "did not receive a consent request from {} within the timeout (is a `bulwark run` holding this socket?): {e}",
            socket.display()
        )
    })?;
    let fields = parse_request(&line).ok_or_else(|| anyhow!("malformed consent request"))?;

    eprintln!("── Bulwark consent request ──");
    for (k, v) in &fields {
        eprintln!("  {k:>8}: {v}");
    }

    // If a verdict was supplied non-interactively, use it; else prompt stdin.
    let v = match verdict {
        Some(v) => v,
        None => prompt_verdict()?,
    };
    writer
        .write_all(format!("{}\n", v.as_str()).as_bytes())
        .context("send verdict")?;
    Ok(v.as_str().to_string())
}

/// Connect to the consent socket, retrying with a short backoff until `budget`
/// elapses. Tolerates the socket not yet existing or refusing connections while
/// the supervisor is between accepts.
fn connect_with_retry(socket: &Path, budget: Duration) -> Result<UnixStream> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        match UnixStream::connect(socket) {
            Ok(s) => return Ok(s),
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    return Err(anyhow!(e)).with_context(|| {
                        format!("cannot connect to consent socket {}", socket.display())
                    });
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Read a verdict from stdin interactively.
fn prompt_verdict() -> Result<Verdict> {
    eprint!("  decision [o=allow-once, s=allow-session, d=deny, f=deny-forever]: ");
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("read decision")?;
    Verdict::parse(&input).ok_or_else(|| anyhow!("unrecognized decision: {}", input.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protect::InodeKey;

    fn req() -> ConsentRequest {
        ConsentRequest {
            pid: 4242,
            key: InodeKey {
                dev: 43,
                ino: 192214,
            },
            path: "/tmp/guard/secret.env".into(),
            ancestry: "cat(4242) <- bash(10)".into(),
            reason: "protected inode".into(),
        }
    }

    #[test]
    fn request_encode_parse_round_trip() {
        let line = encode_request(&req());
        let fields = parse_request(&line).unwrap();
        let get = |k: &str| {
            fields
                .iter()
                .find(|(fk, _)| fk == k)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(get("pid"), "4242");
        assert_eq!(get("ino"), "43:192214");
        assert_eq!(get("path"), "/tmp/guard/secret.env");
        assert_eq!(get("reason"), "protected inode");
        assert_eq!(get("ancestry"), "cat(4242) <- bash(10)");
    }

    #[test]
    fn encode_sanitizes_framing_chars() {
        let mut r = req();
        r.path = "/tmp/with\ttab\nand-newline".into();
        let line = encode_request(&r);
        // exactly one trailing newline, no embedded ones
        assert_eq!(line.matches('\n').count(), 1);
        let fields = parse_request(&line).unwrap();
        let path = fields.iter().find(|(k, _)| k == "path").unwrap().1.clone();
        assert!(!path.contains('\t') && !path.contains('\n'));
    }

    #[test]
    fn parse_request_rejects_non_request_line() {
        assert!(parse_request("allow-once\n").is_none());
    }

    // WO-147@v2 (P1): verified_dir_fd must refuse an opened directory it cannot
    // prove is owned by the claimed uid with no group/other write. Hand it an fd
    // of a directory the process owns but claim a different owner: the fstat is
    // of a directory not owned by that uid, so the verified-open path refuses.
    #[test]
    fn verified_dir_fd_refuses_a_dir_not_owned_by_the_claimed_uid() {
        let base = std::path::PathBuf::from(format!(
            "/tmp/bulwark-verified-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let fd = open_dir_nofollow(&base).expect("open scratch dir");
        // u32::MAX is never this process's euid, so the fd names a directory the
        // claimed uid does not own.
        let err = verified_dir_fd(fd, u32::MAX, &base)
            .expect_err("a foreign-owner claim must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not owned by uid"),
            "the refusal must name the ownership mismatch; got: {msg}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // WO-147@v1: bind() must not change the process-wide umask. A thread that
    // binds consent sockets in a tight loop runs concurrently with a thread
    // that creates directories and records any that come out mode 0600. With
    // the old umask(0177) swap a dir created in that window lost its traverse
    // bits; once the umask is untouched this can never fire.
    #[test]
    fn bind_does_not_change_the_process_umask() {
        use std::io::ErrorKind;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        let stop = Arc::new(AtomicBool::new(false));
        let bad = Arc::new(AtomicUsize::new(0));
        let attempted = Arc::new(AtomicUsize::new(0));
        let succeeded = Arc::new(AtomicUsize::new(0));
        let temp = std::env::temp_dir();

        let binder = {
            let stop = Arc::clone(&stop);
            let temp = temp.clone();
            let attempted = Arc::clone(&attempted);
            let succeeded = Arc::clone(&succeeded);
            std::thread::spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let sock = temp.join(format!(
                        "bulwark-umask-bind-{}-{n}.sock",
                        std::process::id()
                    ));
                    attempted.fetch_add(1, Ordering::Relaxed);
                    if SocketProvider::bind(&sock, i32::MAX, Duration::from_millis(1)).is_ok() {
                        succeeded.fetch_add(1, Ordering::Relaxed);
                    }
                    n = n.wrapping_add(1);
                }
            })
        };

        let mker = {
            let stop = Arc::clone(&stop);
            let bad = Arc::clone(&bad);
            let temp = temp.clone();
            std::thread::spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let dir = temp.join(format!("bulwark-umask-dir-{}-{n}", std::process::id()));
                    match std::fs::create_dir(&dir) {
                        Ok(()) => {
                            if let Ok(m) = std::fs::metadata(&dir) {
                                if m.permissions().mode() & 0o777 == 0o600 {
                                    bad.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            let _ = std::fs::remove_dir(&dir);
                        }
                        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                            let _ = std::fs::remove_dir_all(&dir);
                        }
                        Err(_) => {}
                    }
                    n = n.wrapping_add(1);
                }
            })
        };

        std::thread::sleep(std::time::Duration::from_secs(1));
        stop.store(true, Ordering::Relaxed);
        binder.join().unwrap();
        mker.join().unwrap();
        assert_eq!(
            bad.load(Ordering::Relaxed),
            0,
            "bind() must leave the process umask alone; a concurrent mkdir came out mode 0600"
        );
        let attempts = attempted.load(Ordering::Relaxed);
        let successes = succeeded.load(Ordering::Relaxed);
        assert!(
            attempts > 0,
            "the stress test must attempt at least one bind"
        );
        assert_eq!(
            successes, attempts,
            "every bind must succeed ({successes} of {attempts}); a failing bind weakens the test"
        );
    }

    // WO-147@v1: an over-long --socket path must be refused
    // up front, naming the platform sun_path limit, not fail deep inside the bind.
    #[test]
    fn bind_refuses_a_path_whose_node_exceeds_sun_path() {
        // The node is `long/s.d/s` — just over the platform limit by a few bytes.
        let long = format!("/{}", "x".repeat(sun_path_max()));
        let err = match SocketProvider::bind(
            std::path::Path::new(&long),
            i32::MAX,
            Duration::from_millis(1),
        ) {
            Ok(_) => panic!("an over-long node path must be refused up front"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("sun_path limit"), "{msg}");
    }

    // WO-147@v1: cleanup must not follow a swapped DIRECTORY. After
    // bind, rename <sock>.d away and plant a symlink <sock>.d -> a sentinel dir
    // holding a file named `s`; drop must not unlink that file. Red on a
    // path-based cleanup (remove_file follows the symlink), green on the fd-based
    // one (O_DIRECTORY|O_NOFOLLOW refuses the symlink).
    #[test]
    fn drop_does_not_follow_a_swapped_directory_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base = std::path::PathBuf::from(format!(
            "/tmp/bulwark-swap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        // The parent of <sock>.d must be non-group/other-writable for bind's
        // parent check; force a safe mode regardless of the process umask.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let requested = base.join("consent.sock");
        let node = bound_path(&requested);
        let ddir = node.parent().unwrap().to_path_buf(); // <sock>.d
        let sentinel_dir = base.join("sentinel-dir");
        std::fs::create_dir_all(&sentinel_dir).unwrap();
        let s_file = sentinel_dir.join("s");
        std::fs::write(&s_file, "s-sentinel").unwrap();
        let second = sentinel_dir.join("second.txt");
        std::fs::write(&second, "second-sentinel").unwrap();

        let provider =
            SocketProvider::bind(&requested, i32::MAX, Duration::from_millis(1)).unwrap();

        // Swap the directory: rename it away, plant a symlink at its name.
        let moved = base.join("moved-away");
        std::fs::rename(&ddir, &moved).unwrap();
        symlink(&sentinel_dir, &ddir).unwrap();

        drop(provider);

        assert_eq!(
            std::fs::read_to_string(&s_file).unwrap(),
            "s-sentinel",
            "cleanup must not follow a swapped directory symlink to delete `s`"
        );
        assert_eq!(
            std::fs::read_to_string(&second).unwrap(),
            "second-sentinel",
            "the second sentinel file must be intact"
        );
        // WO-147@v1: leave no scratch behind.
        let _ = std::fs::remove_dir_all(&base);
    }

    // WO-147@v3: cleanup must not touch a swapped-in REAL directory. After bind,
    // rename <sock>.d away and create a fresh directory at the same name holding
    // its own `s`; drop must leave both files intact. Red on the old cleanup,
    // which compares against a fresh open (a real swap then matches itself and
    // unlinks `s` inside the replacement).
    #[test]
    fn drop_does_not_touch_a_replacement_directory_after_a_real_swap() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::path::PathBuf::from(format!(
            "/tmp/bulwark-realswap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let requested = base.join("consent.sock");
        let ddir = bound_path(&requested).parent().unwrap().to_path_buf();

        let provider =
            SocketProvider::bind(&requested, i32::MAX, Duration::from_millis(1)).unwrap();

        // A real (non-symlink) directory swap: move ours away, plant a new one.
        let moved = base.join("moved-away");
        std::fs::rename(&ddir, &moved).unwrap();
        std::fs::create_dir(&ddir).unwrap();
        let s_file = ddir.join("s");
        std::fs::write(&s_file, "s-sentinel").unwrap();
        let second = ddir.join("second.txt");
        std::fs::write(&second, "second-sentinel").unwrap();

        drop(provider);

        assert_eq!(
            std::fs::read_to_string(&s_file).unwrap(),
            "s-sentinel",
            "cleanup must not unlink `s` inside a swapped-in real directory"
        );
        assert_eq!(
            std::fs::read_to_string(&second).unwrap(),
            "second-sentinel",
            "the second sentinel file must be intact"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // WO-147@v3: bind must refuse a parent of <sock>.d that is a directory
    // group/other-writable WITHOUT the sticky bit (a non-sticky 0777 here), so no
    // one can rename <sock>.d away between its verification and the bind.
    #[test]
    fn parent_with_group_or_other_write_and_no_sticky_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::path::PathBuf::from(format!(
            "/tmp/bulwark-parent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).unwrap();
        let requested = base.join("consent.sock");

        let err = match SocketProvider::bind(&requested, i32::MAX, Duration::from_millis(1)) {
            Ok(_) => panic!("a group/other-writable non-sticky parent must be refused"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refusing consent socket parent dir"),
            "must name the parent refusal; got: {msg}"
        );

        let ddir = bound_path(&requested).parent().unwrap().to_path_buf();
        assert!(
            !ddir.exists(),
            "no <sock>.d must be created under a refused parent"
        );
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    // WO-147@v3: a run on a path another provider already bound must be refused —
    // not silently take over the live node — and the first provider must keep
    // answering. Red when the second bind replaces the first (the old unlink-then-
    // bind), green once the exclusivity lock is held for the provider's lifetime.
    #[cfg(target_os = "linux")]
    #[test]
    fn bind_refuses_a_second_run_on_the_same_path_while_the_first_lives() {
        let sock = unique_sock("lock");
        let mut first = SocketProvider::bind(&sock, i32::MAX, Duration::from_secs(60))
            .unwrap_or_else(|e| panic!("first bind {} failed: {e}", sock.display()));

        let err = match SocketProvider::bind(&sock, i32::MAX, Duration::from_millis(1)) {
            Ok(_) => panic!("a second run on the same path must be refused while the first lives"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("another bulwark run is using consent socket"),
            "the refusal must name the running provider; got: {msg}"
        );

        // The first provider must still answer: the refused bind must not have
        // unlinked or replaced its node.
        let sock2 = sock.clone();
        let op = std::thread::spawn(move || {
            answer_once(&sock2, Some(Verdict::AllowSession)).unwrap();
        });
        let (verdict, source) = first.request(&req());
        op.join().unwrap();
        assert_eq!(verdict, Verdict::AllowSession);
        assert_eq!(source, Source::Operator);

        // Once the first drops (releasing the lock), a fresh bind succeeds.
        drop(first);
        let _again = SocketProvider::bind(&sock, i32::MAX, Duration::from_millis(1))
            .unwrap_or_else(|e| panic!("bind after the first dropped must succeed: {e}"));
    }

    // WO-147@v3: teardown must never unlink the run lock. Red when drop removed
    // the lock file (so a successor run's lock could vanish under it); green once
    // the lock is a permanent sibling and only `s` is unlinked.
    #[test]
    fn drop_leaves_the_lock_file_in_place() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::path::PathBuf::from(format!(
            "/tmp/bulwark-lockpersist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let requested = base.join("consent.sock");
        let lock = bound_path(&requested).parent().unwrap().join("lock");

        let provider =
            SocketProvider::bind(&requested, i32::MAX, Duration::from_millis(1)).unwrap();
        drop(provider);

        assert!(
            lock.exists(),
            "the run lock must survive teardown (never unlinked); got gone"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // WO-147@v3: the safe-path walk must catch a writable ANCESTOR, not just the
    // immediate parent. Here the immediate parent (`inner`, 0755 owned by us) is
    // safe, but its parent (`base`, 0777 non-sticky) is not — red when only the
    // immediate parent was checked and the bind proceeded.
    #[test]
    fn safe_path_walk_refuses_a_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::path::PathBuf::from(format!(
            "/tmp/bulwark-ancestor-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        // base is group/other-writable and NOT sticky: an attacker in the same
        // group (or any user, at 0777) can rename the whole subtree away.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).unwrap();
        let inner = base.join("inner");
        std::fs::create_dir(&inner).unwrap();
        let sock = inner.join("consent.sock");

        let err = match SocketProvider::bind(&sock, i32::MAX, Duration::from_millis(1)) {
            Ok(_) => panic!("a writable ancestor must be refused"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not a directory owned by root or uid"),
            "the refusal must name the offending ancestor; got: {msg}"
        );

        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    // WO-147@v3: a relative socket path resolves against the cwd before the
    // `<sock>.d` derivation, so bind no longer fails on the empty parent. Scoped
    // to an euid-owned temp dir (and the cwd restored) so it passes under both
    // root and non-root runs.
    #[test]
    fn relative_socket_path_binds_successfully() {
        use std::os::unix::fs::PermissionsExt;
        // Keep the path short: the derived node must fit the platform sun_path
        // (103 on macOS), and a long per-user temp dir would overflow it.
        let base = std::path::PathBuf::from("/tmp").join(format!(
            "bwrel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        // euid-owned so the safe-path walk of this (relative) cwd passes.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let prev = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(&base).expect("set cwd");
        let provider = SocketProvider::bind(
            std::path::Path::new("consent.sock"),
            i32::MAX,
            Duration::from_millis(1),
        )
        .unwrap_or_else(|e| panic!("a relative consent socket must resolve against the cwd: {e}"));
        drop(provider);
        std::env::set_current_dir(&prev).expect("restore cwd");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// End-to-end over a real socket pair: an "operator" thread connects and
    /// answers; the provider returns that verdict with Source::Operator.
    #[cfg(target_os = "linux")]
    fn unique_sock(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Keep the path short: the sockaddr_un sun_path limit is ~108 bytes, so
        // a long /tmp path + nested dir can overflow it and fail the bind. Put
        // the socket directly in the temp dir with a compact unique name.
        let name = format!("blwk-{tag}-{}-{n}-{nanos}.sock", std::process::id());
        let dir = if cfg!(target_os = "macos") {
            std::path::PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        dir.join(name)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_round_trip_operator_allows() {
        let sock = unique_sock("rt");

        // Use i32::MAX as the supervised root: nothing descends from it, so the
        // test's own connection is never refused by the off-band check. The
        // timeout is generous (60s) so the test is deterministic even when the
        // operator thread is starved under heavy parallel test load — in
        // practice it completes in milliseconds.
        let mut provider = SocketProvider::bind(&sock, i32::MAX, Duration::from_secs(60))
            .unwrap_or_else(|e| panic!("bind {} failed: {e}", sock.display()));

        let sock2 = sock.clone();
        let op = std::thread::spawn(move || {
            // answer_once retries the connect, so no explicit readiness wait is
            // needed; it tolerates the provider not yet accepting.
            answer_once(&sock2, Some(Verdict::AllowSession)).unwrap();
        });

        let (verdict, source) = provider.request(&req());
        op.join().unwrap();
        assert_eq!(verdict, Verdict::AllowSession);
        assert_eq!(source, Source::Operator);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_times_out_to_deny_when_no_operator() {
        let sock = unique_sock("to");
        let mut provider =
            SocketProvider::bind(&sock, i32::MAX, Duration::from_millis(200)).unwrap();
        let (verdict, source) = provider.request(&req());
        assert_eq!(verdict, Verdict::Deny);
        assert_eq!(source, Source::Timeout);
    }

    // WO-147/154@v1: ONE absolute deadline per consent request, shared by the
    // accept, write and read phases. A peer that connects when only a sliver of
    // the consent window remains, then stalls its reply, must not stretch the
    // wait past that deadline (plus scheduling slack) — under the old per-phase
    // timeouts the reply got a fresh full window and this overshot ~2x.
    #[test]
    fn a_late_peer_cannot_stretch_the_consent_deadline() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;

        let base = std::path::PathBuf::from(format!(
            "/tmp/bulwark-deadline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let requested = base.join("consent.sock");
        let node = bound_path(&requested);

        let mut provider =
            SocketProvider::bind(&requested, i32::MAX, Duration::from_millis(1000)).unwrap();

        // A barrier anchors the peer's timer to the request start, so the peer's
        // connect lands with ~100 ms of the 1000 ms window left — deterministically,
        // not subject to thread-spawn scheduling jitter.
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let b = std::sync::Arc::clone(&barrier);
        let hold = std::thread::spawn(move || {
            b.wait();
            std::thread::sleep(Duration::from_millis(900));
            // Bind the stream so it stays open through the hold (a dropped temp
            // would close it and let the provider read EOF immediately).
            let _conn = UnixStream::connect(&node).unwrap();
            // Hold (no reply) well past the deadline.
            std::thread::sleep(Duration::from_millis(2000));
        });

        barrier.wait();
        let began = std::time::Instant::now();
        let (verdict, source) = provider.request(&req());
        let elapsed = began.elapsed();

        assert_eq!(verdict, Verdict::Deny);
        assert_eq!(source, Source::Timeout);
        assert!(
            elapsed <= Duration::from_millis(1000 + 250),
            "a peer with 100 ms of window left held the event for {elapsed:?}; \
             accept/write/read must share one absolute deadline"
        );

        hold.join().unwrap();
        drop(provider);
        let _ = std::fs::remove_dir_all(&base);
    }

    // WO-147/154@v1: a peer that trickles bytes one at a time (no verdict line)
    // must not hold the event past the absolute deadline — poll() bounds every
    // read, so `remaining == 0` denies instead of a per-syscall timeout re-arming
    // on each trickled byte.
    #[test]
    fn a_trickling_peer_cannot_hold_the_consent_deadline_open() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;

        let base = std::path::PathBuf::from(format!(
            "/tmp/bulwark-trickle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let requested = base.join("consent.sock");
        let node = bound_path(&requested);

        let mut provider =
            SocketProvider::bind(&requested, i32::MAX, Duration::from_millis(300)).unwrap();

        // Trickle one byte every 50 ms, never a newline, for ~600 ms total.
        let hold = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&node).unwrap();
            for _ in 0..12 {
                std::thread::sleep(Duration::from_millis(50));
                let _ = stream.write(b"x");
            }
        });

        let began = std::time::Instant::now();
        let (verdict, source) = provider.request(&req());
        let elapsed = began.elapsed();

        assert_eq!(verdict, Verdict::Deny);
        assert_eq!(source, Source::Timeout);
        assert!(
            elapsed <= Duration::from_millis(300 + 100),
            "a trickling peer held the event for {elapsed:?}; the read must be \
             cut off at the absolute deadline"
        );

        hold.join().unwrap();
        drop(provider);
        let _ = std::fs::remove_dir_all(&base);
    }

    // WO-147/154@v1: when the operator's window is already spent by the accept,
    // the write/read phases must deny at once (remaining <= 0), never block.
    #[test]
    fn a_peer_connecting_with_zero_millis_left_is_denied_without_blocking() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;

        let base = std::path::PathBuf::from(format!(
            "/tmp/bulwark-zero-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let requested = base.join("consent.sock");
        let node = bound_path(&requested);

        // 300 ms window; the peer connects at ~300 ms, leaving ~0 ms.
        let mut provider =
            SocketProvider::bind(&requested, i32::MAX, Duration::from_millis(300)).unwrap();
        let hold = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let _ = UnixStream::connect(&node);
            std::thread::sleep(Duration::from_millis(500));
        });

        let began = std::time::Instant::now();
        let (verdict, source) = provider.request(&req());
        let elapsed = began.elapsed();

        assert_eq!(verdict, Verdict::Deny);
        assert_eq!(source, Source::Timeout);
        assert!(
            elapsed <= Duration::from_millis(300 + 150),
            "a peer connecting with ~0 ms left blocked the request for {elapsed:?}"
        );

        hold.join().unwrap();
        drop(provider);
        let _ = std::fs::remove_dir_all(&base);
    }

    // WO-147/154@v1: an operator who answers past one second (the old poll slice
    // cap) must still be heard — the read loop slices until the absolute deadline,
    // never denying on an expired 1 s slice.
    #[test]
    fn an_operator_who_answers_past_one_second_is_still_heard() {
        use std::io::{Read as _, Write as _};
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;

        let base = std::path::PathBuf::from(format!(
            "/tmp/bulwark-slowop-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let requested = base.join("consent.sock");
        let node = bound_path(&requested);

        // 3 s window; the operator consumes the request, waits ~1.5 s, answers.
        let mut provider =
            SocketProvider::bind(&requested, i32::MAX, Duration::from_millis(3000)).unwrap();
        let hold = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&node).unwrap();
            let mut reqbuf = [0u8; 512];
            let _ = stream.read(&mut reqbuf); // consume the request line
            std::thread::sleep(Duration::from_millis(1500));
            let _ = stream.write_all(b"allow-once\n");
        });

        let began = std::time::Instant::now();
        let (verdict, source) = provider.request(&req());
        let elapsed = began.elapsed();

        assert_eq!(
            verdict,
            Verdict::AllowOnce,
            "the 1.5 s reply must be honored"
        );
        assert_eq!(source, Source::Operator);
        assert!(
            elapsed >= Duration::from_millis(1200),
            "the reply must not be heard before the operator answered (elapsed {elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_millis(3000),
            "the 3 s deadline must allow the 1.5 s reply (elapsed {elapsed:?})"
        );

        hold.join().unwrap();
        drop(provider);
        let _ = std::fs::remove_dir_all(&base);
    }
}
