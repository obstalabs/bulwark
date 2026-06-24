//! Grant-directory create/move witness for allow-list mode (Linux).
//!
//! Layer 1 (`allowlist.rs`) gates grants on a launch inode snapshot, which is
//! safe but denies EVERY post-launch file in a grant — including files the
//! agent legitimately creates and logs rotated into a granted directory. This
//! module re-permits genuinely-created files WITHOUT reopening the
//! hardlink/rename hole that snapshotting closed.
//!
//! A second fanotify group (`FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME`) marks each
//! grant filesystem for `FAN_CREATE` and `FAN_MOVED_TO`. The inode of a file
//! whose *creation* under a grant we witness joins a trusted set; an inode
//! *moved into* a grant is evicted from it (a rename-in is untrusted, and
//! eviction also defeats inode reuse after delete+recreate). The gate then
//! allows a non-snapshot grant inode iff it was witnessed-created AND has link
//! count 1 — a hardlink fires `FAN_CREATE` too, but carries `nlink > 1`.
//!
//! Fail-closed: if the notif group cannot be created (a kernel without FID/DFID
//! reporting), [`GrantWatch::new`] returns `None` and the caller stays on the
//! Layer-1 strict snapshot — post-launch files are denied, never leaked.

use std::collections::HashSet;
use std::os::fd::RawFd;
use std::path::PathBuf;

use crate::glob;
use crate::protect::InodeKey;

/// Cap on the witnessed-created set so a long run with heavy create churn cannot
/// grow it without bound. When full we stop recording (a not-yet-recorded create
/// is simply denied — fail closed).
const MAX_WITNESSED: usize = 1_000_000;

/// Witness of files created (vs moved) under the grant directories.
pub struct GrantWatch {
    fd: RawFd,
    /// `O_PATH` fds to the grant directories. A created entry's name (from the
    /// notif event) is resolved by `openat(dir_fd, name)` against each — `O_PATH`
    /// so the supervisor's own resolution generates no fanotify open event (and
    /// so cannot deadlock against its own permission mark).
    grant_dir_fds: Vec<RawFd>,
    /// Grant globs — only creates whose resolved path matches one are recorded,
    /// bounding the set to grant-relevant inodes.
    grants: Vec<String>,
    /// Inodes whose creation under a grant we witnessed.
    created: HashSet<InodeKey>,
    full_logged: bool,
}

impl GrantWatch {
    /// Set up the notif group and mark the filesystem of each grant directory.
    /// Returns `None` (caller falls back to strict snapshot) if anything the
    /// witness depends on is unavailable, so the gate never silently weakens.
    pub fn new(grant_dirs: &[PathBuf], grants: &[String]) -> Option<Self> {
        if grant_dirs.is_empty() {
            return None;
        }
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_NOTIF | libc::FAN_REPORT_DFID_NAME | libc::FAN_CLOEXEC,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u32,
            )
        };
        if fd < 0 {
            eprintln!(
                "[bulwark] note: grant create-witness unavailable ({}); post-launch files in \
                 grants will be denied (strict snapshot)",
                std::io::Error::last_os_error()
            );
            return None;
        }
        // Non-blocking is load-bearing on the GROUP fd (not the per-event fds, so
        // it must be set here, not via fanotify_init's event_f_flags): `drain`
        // reads until the queue is empty, and a blocking read would wedge the
        // supervisor's event loop on an empty queue — which, with the allow-list
        // filesystem-wide permission mark, would stall every open() on the host.
        // Non-block makes the drained read return EAGAIN instead.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if fl < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            unsafe { libc::close(fd) };
            eprintln!(
                "[bulwark] note: grant create-witness could not set non-blocking; \
                 post-launch files in grants will be denied (strict snapshot)"
            );
            return None;
        }

        let mut dir_fds = Vec::new();
        let mut marked = 0usize;
        for dir in grant_dirs {
            let c = match std::ffi::CString::new(dir.as_os_str().to_string_lossy().as_bytes()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            // Mark the whole filesystem of the grant so creates in nested grant
            // subdirectories are seen too (a per-dir inode mark would miss them).
            let rc = unsafe {
                libc::fanotify_mark(
                    fd,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                    libc::FAN_CREATE | libc::FAN_MOVED_TO | libc::FAN_ONDIR,
                    libc::AT_FDCWD,
                    c.as_ptr(),
                )
            };
            if rc != 0 {
                continue;
            }
            marked += 1;
            // O_PATH fd to the grant dir, used to resolve created entries by
            // openat without generating a fanotify open event.
            let dfd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if dfd >= 0 {
                dir_fds.push(dfd);
            }
        }
        if marked == 0 || dir_fds.is_empty() {
            unsafe { libc::close(fd) };
            eprintln!(
                "[bulwark] note: grant create-witness could not mark any grant filesystem; \
                 post-launch files in grants will be denied (strict snapshot)"
            );
            return None;
        }
        Some(GrantWatch {
            fd,
            grant_dir_fds: dir_fds,
            grants: grants.to_vec(),
            created: HashSet::new(),
            full_logged: false,
        })
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// True if a (link-count-1) inode opened on a grant path was witnessed as
    /// created — not moved — under a grant.
    pub fn witnessed(&self, key: &InodeKey) -> bool {
        self.created.contains(key)
    }

    /// Read and apply all currently-queued create/move notifications. Called
    /// before each permission decision so a just-created file is witnessed
    /// before its open is judged. Non-blocking.
    pub fn drain(&mut self) {
        let mut buf = [0u8; 16384];
        loop {
            let n =
                unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                return; // EAGAIN (nothing queued) or error → stop
            }
            self.parse(&buf[..n as usize]);
        }
    }

    /// Parse a buffer of `fanotify_event_metadata` + info records.
    fn parse(&mut self, bytes: &[u8]) {
        let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut off = 0usize;
        while off + meta_size <= bytes.len() {
            let meta: libc::fanotify_event_metadata =
                unsafe { std::ptr::read_unaligned(bytes[off..].as_ptr() as *const _) };
            let ev_len = meta.event_len as usize;
            if ev_len < meta_size || off + ev_len > bytes.len() {
                break;
            }
            let is_create = meta.mask & libc::FAN_CREATE != 0;
            let is_moved_in = meta.mask & libc::FAN_MOVED_TO != 0;
            if is_create || is_moved_in {
                if let Some((key, path)) = self.resolve_child(&bytes[off + meta_size..off + ev_len])
                {
                    if self.grants.iter().any(|g| glob::matches(g, &path)) {
                        if is_moved_in {
                            // Untrusted: a file moved into a grant is denied, and
                            // eviction defeats inode reuse over a witnessed inode.
                            self.created.remove(&key);
                        } else if self.created.len() < MAX_WITNESSED {
                            self.created.insert(key);
                        } else if !self.full_logged {
                            self.full_logged = true;
                            eprintln!(
                                "[bulwark] note: grant create-witness set is full; further \
                                 created files in grants will be denied (fail closed)"
                            );
                        }
                    }
                }
            }
            off += ev_len;
        }
    }

    /// Resolve the child object's `(InodeKey, path)` from a DFID_NAME info
    /// record: the directory file handle + the entry name. `open_by_handle_at`
    /// resolves the parent directory, `openat(name)` the child.
    fn resolve_child(&self, info: &[u8]) -> Option<(InodeKey, String)> {
        let hdr_size = std::mem::size_of::<libc::fanotify_event_info_header>();
        let mut off = 0usize;
        while off + hdr_size <= info.len() {
            let hdr: libc::fanotify_event_info_header =
                unsafe { std::ptr::read_unaligned(info[off..].as_ptr() as *const _) };
            let rec_len = hdr.len as usize;
            if rec_len < hdr_size || off + rec_len > info.len() {
                break;
            }
            if hdr.info_type == libc::FAN_EVENT_INFO_TYPE_DFID_NAME {
                // layout: header | __kernel_fsid_t (8) | file_handle | name\0
                let fsid_size = 8usize;
                let fh_off = off + hdr_size + fsid_size;
                // file_handle: handle_bytes(u32) handle_type(i32) f_handle[handle_bytes]
                if fh_off + 8 > off + rec_len {
                    break;
                }
                let handle_bytes =
                    u32::from_ne_bytes(info[fh_off..fh_off + 4].try_into().ok()?) as usize;
                let fh_total = 8 + handle_bytes;
                let name_off = fh_off + fh_total;
                if name_off > off + rec_len {
                    break;
                }
                // Name is null-terminated and fills the rest of the record.
                let name_bytes = &info[name_off..off + rec_len];
                let name_end = name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_bytes.len());
                let name = &name_bytes[..name_end];
                return self.open_child(name);
            }
            off += rec_len;
        }
        None
    }

    /// Resolve the created entry `name` by `openat(grant_dir_fd, name)` against
    /// each held grant-directory `O_PATH` fd, then `fstat` it to `(dev, ino)` +
    /// path. We resolve via the held grant fds rather than `open_by_handle_at`
    /// because the latter rejects an `O_PATH` mount fd with `EBADF`, and a
    /// non-`O_PATH` mount fd cannot be opened safely once the allow-list
    /// filesystem permission mark is live (the supervisor's own open would block
    /// on its own gate). All opens here are `O_PATH`, which generate no fanotify
    /// open event, so there is no self-deadlock.
    ///
    /// Limitation: this matches a file created DIRECTLY in a granted directory
    /// (the rotation / agent-output case). A file created in a nested
    /// subdirectory of a grant is not resolved here and stays denied — fail
    /// closed, never leaked.
    fn open_child(&self, name: &[u8]) -> Option<(InodeKey, String)> {
        let name_c = std::ffi::CString::new(name).ok()?;
        for &dfd in &self.grant_dir_fds {
            let childfd = unsafe {
                libc::openat(
                    dfd,
                    name_c.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if childfd < 0 {
                continue; // name is not in this grant directory
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::fstat(childfd, &mut st) };
            let path = std::fs::read_link(format!("/proc/self/fd/{childfd}"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            unsafe { libc::close(childfd) };
            if rc != 0 {
                return None;
            }
            return Some((
                InodeKey {
                    dev: st.st_dev as u64,
                    ino: st.st_ino as u64,
                },
                path,
            ));
        }
        None
    }
}

impl Drop for GrantWatch {
    fn drop(&mut self) {
        for &mfd in &self.grant_dir_fds {
            unsafe { libc::close(mfd) };
        }
        unsafe { libc::close(self.fd) };
    }
}

/// Number of link-count probes is one `fstat`; small helper kept here so the
/// gate's allow-list arm can require `nlink == 1` for a witnessed-created file
/// (a hardlinked foreign inode also fires `FAN_CREATE`, but has `nlink > 1`).
pub fn nlink_of_fd(fd: RawFd) -> u64 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return u64::MAX; // unknown → treat as "many links" so it cannot pass the ==1 gate
    }
    st.st_nlink as u64
}
