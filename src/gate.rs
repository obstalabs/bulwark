//! Supervisor + fanotify `FAN_OPEN_PERM` read gate.
//!
//! `run` forks the target command, installs a mount-level `FAN_OPEN_PERM`
//! mark, and answers every permission event: if the opened file's `(dev, ino)`
//! is in the protected set AND the opener belongs to the supervised tree, the
//! open is denied (`FAN_DENY` → the reader sees `EPERM`); otherwise allowed.
//!
//! The decision is by inode, resolved from the event's own file descriptor —
//! so a symlink or a rename to a benign-looking name cannot smuggle a
//! protected inode past the gate.
//!
//! Linux only: this module compiles and runs solely where fanotify permission
//! events exist. fanotify requires `CAP_SYS_ADMIN` (run as root).

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, bail, Context, Result};

use crate::allowlist::AllowList;
use crate::consent::{ConsentRequest, Source, Verdict};
use crate::proctree;
use crate::protect::{InodeKey, ProtectedSet};
use crate::receipt::{Decision, Receipt, ReceiptLog};

const ANCESTRY_MAX_DEPTH: usize = 16;

/// How the gate decides. Deny-list is the interactive default ("protect these,
/// ask about them"); allow-list is the non-interactive CI mode ("allow only
/// these, deny everything else").
pub enum GateMode<'a> {
    /// Deny-list: a protected inode opened by the tree is referred to consent.
    DenyList {
        protected: &'a ProtectedSet,
        consent: &'a mut dyn ConsentDecider,
    },
    /// Allow-list: an open by the tree is allowed iff its path matches the
    /// allowlist; everything else is denied with no prompt.
    AllowList { allow: &'a AllowList },
}

/// Set by the signal handler on SIGTERM/SIGINT/SIGHUP. The event loop polls it
/// and, on a graceful shutdown, denies any outstanding permission events before
/// exiting — so a graceful stop fails CLOSED.
///
/// This is the trappable half of the fail-closed story. SIGKILL / hard crash /
/// OOM / power loss cannot be intercepted, and the kernel releases an
/// outstanding permission event as *allowed* when the fanotify fd closes
/// (documented in fanotify(7)). That residual is inherent to the interface and
/// is handled by a future kernel-enforced floor, not here.
pub(crate) static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// True once a graceful-termination signal has been received. Other modules
/// (e.g. the consent socket wait) consult this to abandon a blocking wait and
/// fail closed.
pub(crate) fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Async-signal-safe handler: only flips the atomic. The event loop does the
/// actual deny-and-exit work, where it is safe to touch the fanotify fd.
extern "C" fn on_shutdown_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install handlers for the trappable termination signals so the event loop can
/// fail closed on a graceful stop.
fn install_shutdown_handlers() {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_shutdown_signal as extern "C" fn(libc::c_int) as usize;
    action.sa_flags = 0;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

/// The gate's consent dependency: given a request for a protected open, return
/// a verdict and how it was reached. Implemented by `consent::CachingProvider`
/// (wrapped in `main`) so the gate stays agnostic to the transport.
pub trait ConsentDecider {
    fn decide(&mut self, req: &ConsentRequest) -> (Verdict, Source);

    /// Inform the decider of the supervised tree's cgroup scope (relative path),
    /// so an off-band consent channel can reject answerers that are members of
    /// the tree by the same reparent-proof primitive the gate uses — not just by
    /// ancestry, which a double-fork()'d orphan sheds. Default: no-op (modes with
    /// no off-band channel, or where no cgroup scope exists).
    fn bind_scope(&mut self, _scope_rel: Option<&str>) {}
}

/// Run `command` under the gate.
///
/// `protected` is the resolved inode set to deny; `mark_paths` are the paths
/// whose mounts must be marked for `FAN_OPEN_PERM` (one mark per distinct
/// mount). The caller builds both — from explicit `--protect` paths or from a
/// policy profile — keeping the gate agnostic to policy. Returns the child's
/// exit code.
pub fn run(
    mut mode: GateMode,
    mark_paths: &[PathBuf],
    receipts: Option<&Path>,
    command: &[String],
    worker: Option<WorkerCreds>,
) -> Result<i32> {
    if command.is_empty() {
        bail!("no command given");
    }
    match &mode {
        GateMode::DenyList { protected, .. } => {
            if protected.is_empty() {
                bail!("no protected inodes resolved — nothing to guard");
            }
            eprintln!(
                "[bulwark] deny-list: guarding {} inode(s) for FAN_OPEN_PERM",
                protected.len()
            );
        }
        GateMode::AllowList { allow } => {
            eprintln!(
                "[bulwark] allow-list (default-deny): {} allow rule(s) including runtime base set",
                allow.allowed_globs().len()
            );
        }
    }

    let mut log = ReceiptLog::new(receipts)?;

    // Fail closed on graceful termination: a trapped SIGTERM/SIGINT/SIGHUP lets
    // the event loop deny any outstanding read before exiting.
    install_shutdown_handlers();

    // Set up the fanotify fd BEFORE forking the child, so no open() by the
    // child can race ahead of the mark being in place.
    let fan = FanFd::init()?;
    // Mark the filesystem of every path. Marking by filesystem (not per-mount)
    // guarantees the gate fires wherever the relevant inodes are reachable —
    // including bind-mounted aliases. Allow-list mode passes every mount so each
    // open the agent makes is seen and judged.
    //
    // Deny-list marks a few specific paths: a mark failure is fatal (we cannot
    // guard what we cannot mark). Allow-list marks many mounts, some of which
    // (pseudo filesystems) may reject a mark — there we warn and continue, since
    // an unmarkable pseudo-fs cannot hold a readable on-disk secret.
    let tolerant = matches!(mode, GateMode::AllowList { .. });
    let mut marked = 0usize;
    for m in mark_paths {
        match fan.mark_filesystem(m) {
            Ok(()) => marked += 1,
            Err(e) if tolerant => {
                eprintln!(
                    "[bulwark] note: could not mark {} ({e}); skipping",
                    m.display()
                );
            }
            Err(e) => {
                return Err(e).with_context(|| format!("fanotify_mark on {}", m.display()));
            }
        }
    }
    if tolerant && marked == 0 {
        bail!("allow-list: could not mark any filesystem — cannot enforce default-deny");
    }

    // Create a dedicated cgroup-v2 scope for the supervised tree. Membership in
    // it is reparent-proof: a process that double-fork()s to escape the parent
    // chain still carries the scope, so it stays attributed to the tree. Falls
    // back to the ancestry walk where cgroup-v2 is unavailable.
    let scope = crate::cgroup::CgroupScope::create(std::process::id() as i32);
    match &scope {
        Some(_) => eprintln!("[bulwark] tree attribution: cgroup-v2 membership (reparent-proof)"),
        None => eprintln!(
            "[bulwark] note: cgroup-v2 scope unavailable; tree attribution falls back to \
             process-ancestry (a deliberately-orphaned descendant may escape — use --hardened)"
        ),
    }

    // Hand the consent decider the tree's cgroup scope so the off-band channel
    // rejects in-tree answerers by membership, not ancestry: a double-fork()'d
    // orphan that sheds its parent chain still carries the scope and so cannot
    // self-answer its own consent prompt. No-op for modes without an off-band
    // channel, and when no cgroup scope exists (ancestry remains the only check).
    if let GateMode::DenyList { consent, .. } = &mut mode {
        consent.bind_scope(scope.as_ref().map(|s| s.rel()));
    }

    // Allow-list mode: set up the grant create/move witness so a file genuinely
    // CREATED under a grant (or a log rotated in) becomes readable, while a
    // foreign inode hardlinked/renamed in stays denied by the inode snapshot.
    // `None` (kernel without FID, or mark failure) leaves the strict snapshot in
    // force — post-launch files denied, never leaked.
    let mut grant_watch = match &mode {
        GateMode::AllowList { allow } => {
            let w = crate::grantwatch::GrantWatch::new(
                &allow.grant_concrete_dirs(),
                allow.grants_list(),
            );
            if w.is_some() {
                eprintln!("[bulwark] allow-list: grant create-witness active (rotated/created files allowed)");
            }
            w
        }
        _ => None,
    };

    // Fork + exec the supervised command. The supervisor (this process) stays
    // root and holds the fanotify fd; `worker` drops only the agent child. The
    // child joins the cgroup scope (if any) before exec, while still root.
    let child = spawn(command, worker, scope.as_ref())?;
    // The effective uid is shown inline on the supervising line (no separate
    // drop banner) — so the auto-drop success path adds no extra noise, while the
    // uid in effect stays visible for every run.
    match worker {
        Some(w) => eprintln!(
            "[bulwark] supervising pid {child} (uid={} gid={}): {}",
            w.uid,
            w.gid,
            command.join(" ")
        ),
        None => eprintln!("[bulwark] supervising pid {child}: {}", command.join(" ")),
    }

    // Event loop: answer permission events until the child exits.
    let exit_code = event_loop(
        &fan,
        child,
        &mut log,
        mode,
        scope.as_ref(),
        grant_watch.as_mut(),
    )?;
    Ok(exit_code)
}

// ---- fanotify FFI wrapper ---------------------------------------------------

/// Owned fanotify file descriptor.
struct FanFd {
    fd: RawFd,
}

impl FanFd {
    fn init() -> Result<Self> {
        // FAN_CLASS_CONTENT: permission events on content access.
        // O_RDONLY|O_LARGEFILE: how the event fds are opened.
        //
        // FAN_UNLIMITED_QUEUE is load-bearing for security, not a tuning knob. The
        // default permission-event queue is bounded (fs.fanotify.max_queued_events,
        // 16384). When a bounded queue overflows, the kernel drops the undeliverable
        // permission event and lets the access proceed *as allowed* — a fail-OPEN: an
        // unprivileged supervised process can flood opens to overflow the queue and
        // read protected files in the window. FAN_UNLIMITED_QUEUE removes the bound, so
        // the gate applies backpressure (slows the agent) instead of leaking. Verified:
        // with a forced-tiny queue the bounded build leaks ~160k protected reads under
        // flood; with this flag, zero. Needs CAP_SYS_ADMIN, which the gate already has.
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_UNLIMITED_QUEUE,
                (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
            )
        };
        if fd < 0 {
            return Err(anyhow!(std::io::Error::last_os_error()))
                .context("fanotify_init (need CAP_SYS_ADMIN / root)");
        }
        Ok(FanFd { fd })
    }

    /// Mark the whole filesystem containing `path` for `FAN_OPEN_PERM`.
    ///
    /// We use `FAN_MARK_FILESYSTEM` rather than `FAN_MARK_MOUNT` deliberately: a
    /// `mount --bind` of a protected file exposes the same inode under a
    /// *different mount*, which a per-mount mark would miss (a verified bypass).
    /// A filesystem mark covers every mount of the superblock, so a bind-mounted
    /// alias of a protected inode is still gated. The cost is more events (every
    /// open on the filesystem), but the decision is already inode-filtered in
    /// userspace, so non-protected opens are simply allowed.
    fn mark_filesystem(&self, path: &Path) -> Result<()> {
        let cpath = CString::new(path.as_os_str().to_string_lossy().as_bytes())?;
        let rc = unsafe {
            libc::fanotify_mark(
                self.fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                libc::FAN_OPEN_PERM,
                libc::AT_FDCWD,
                cpath.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(anyhow!(std::io::Error::last_os_error())).context("fanotify_mark");
        }
        Ok(())
    }
}

impl Drop for FanFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Resolve the `(dev, ino)` and observed path of an event's file descriptor.
fn inode_of_fd(fd: RawFd) -> Option<(InodeKey, String)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return None;
    }
    let key = InodeKey {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
    };
    let link = format!("/proc/self/fd/{fd}");
    let path = std::fs::read_link(&link)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "?".to_string());
    Some((key, path))
}

/// Reply to a permission event.
fn respond(fan_fd: RawFd, event_fd: RawFd, allow: bool) {
    let resp = libc::fanotify_response {
        fd: event_fd,
        response: if allow {
            libc::FAN_ALLOW
        } else {
            libc::FAN_DENY
        },
    };
    let n = unsafe {
        libc::write(
            fan_fd,
            &resp as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::fanotify_response>(),
        )
    };
    if n < 0 {
        eprintln!(
            "[bulwark] WARN failed to write fanotify response: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Core permission-event loop. Reads events, decides, responds, and returns
/// the child's exit code once it terminates.
fn event_loop(
    fan: &FanFd,
    child: libc::pid_t,
    log: &mut ReceiptLog,
    mut mode: GateMode,
    scope: Option<&crate::cgroup::CgroupScope>,
    mut grant_watch: Option<&mut crate::grantwatch::GrantWatch>,
) -> Result<i32> {
    const BUF_LEN: usize = 8192;
    let mut buf = [0u8; BUF_LEN];

    // Once the foreground child is reaped we record its code but keep enforcing
    // until the cgroup scope drains (orphaned double-fork descendants). `None`
    // until the foreground child exits; `Some(code)` while draining the rest.
    let mut foreground_exit: Option<i32> = None;

    loop {
        // Graceful shutdown requested (SIGTERM/SIGINT/SIGHUP): deny every
        // outstanding permission event before exiting, so the stop fails CLOSED
        // rather than letting the kernel release held reads as allowed.
        if SHUTDOWN.load(Ordering::SeqCst) {
            let denied = drain_and_deny(fan, &mut buf, log);
            eprintln!("[bulwark] shutdown: denied {denied} outstanding event(s), exiting");
            return Ok(130); // 128 + SIGINT, conventional for signal termination
        }

        // Poll the permission fd, plus the grant create-witness notif fd when
        // present, with a timeout so we can reap the child even when idle.
        let gw_fd = grant_watch.as_ref().map(|w| w.fd());
        let mut pfds = [
            libc::pollfd {
                fd: fan.fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: gw_fd.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let nfds = if gw_fd.is_some() { 2 } else { 1 };
        let pr = unsafe { libc::poll(pfds.as_mut_ptr(), nfds, 200) };
        if pr < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue; // a signal interrupted poll — loop re-checks SHUTDOWN
            }
            return Err(anyhow!(err)).context("poll");
        }

        // Drain create/move notifications BEFORE judging opens, so a file just
        // created under a grant is witnessed before its open is decided.
        if let Some(w) = grant_watch.as_deref_mut() {
            w.drain();
        }

        if pr > 0 && (pfds[0].revents & libc::POLLIN) != 0 {
            let n = unsafe { libc::read(fan.fd, buf.as_mut_ptr() as *mut libc::c_void, BUF_LEN) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(anyhow!(err)).context("read fanotify");
            }
            handle_events(
                fan,
                &buf[..n as usize],
                child,
                log,
                &mut mode,
                scope,
                grant_watch.as_deref_mut(),
            );
        }

        // Reap the foreground child once (a second waitpid would return ECHILD).
        // Its exit is not the end of the tree: a process that double-fork()s
        // leaves an orphan (reparented to init) that may still read after its
        // parent is gone. We keep the gate enforcing until the cgroup scope
        // drains — otherwise the canonical double-fork attack wins by racing the
        // supervisor's teardown.
        if foreground_exit.is_none() {
            if let Some(code) = try_wait(child)? {
                foreground_exit = Some(code);
            }
        }

        if let Some(code) = foreground_exit {
            // Foreground gone. Exit only once no orphan remains in the scope.
            // Without a cgroup scope we have no drain signal, so exit as before.
            match scope {
                Some(s) if s.is_populated() => { /* orphan alive: keep enforcing */ }
                _ => return Ok(code),
            }
        }
    }
}

/// On graceful shutdown, read every immediately-available permission event and
/// deny it, so no held read is released as allowed when we exit. Returns the
/// number of events denied. Best-effort and non-blocking: we drain what the
/// kernel has queued right now.
fn drain_and_deny(fan: &FanFd, buf: &mut [u8], log: &mut ReceiptLog) -> usize {
    let mut denied = 0usize;
    loop {
        // Non-blocking poll: stop as soon as nothing more is queued.
        let mut pfd = libc::pollfd {
            fd: fan.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, 0) };
        if pr <= 0 || (pfd.revents & libc::POLLIN) == 0 {
            break;
        }
        let n = unsafe { libc::read(fan.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
        let bytes = &buf[..n as usize];
        let mut offset = 0usize;
        while offset + meta_size <= bytes.len() {
            let meta = unsafe {
                std::ptr::read_unaligned(
                    bytes[offset..].as_ptr() as *const libc::fanotify_event_metadata
                )
            };
            let ev_len = meta.event_len as usize;
            if ev_len < meta_size || offset + ev_len > bytes.len() {
                break;
            }
            if meta.mask & libc::FAN_OPEN_PERM != 0 && meta.fd >= 0 {
                // Record a receipt for the shutdown-deny, then deny.
                if let Some((key, path)) = inode_of_fd(meta.fd) {
                    let chain = proctree::ancestry(meta.pid, ANCESTRY_MAX_DEPTH);
                    log.record(&Receipt {
                        pid: meta.pid,
                        dev: key.dev,
                        ino: key.ino,
                        decision: Decision::Deny,
                        path: &path,
                        ancestry: &proctree::render(&chain),
                        reason: "denied on supervisor shutdown",
                        source: "shutdown",
                    });
                }
                respond(fan.fd, meta.fd, false);
                denied += 1;
            }
            if meta.fd >= 0 {
                unsafe {
                    libc::close(meta.fd);
                }
            }
            offset += ev_len;
        }
    }
    denied
}

/// Decode and answer all events in a read buffer.
fn handle_events(
    fan: &FanFd,
    bytes: &[u8],
    child: libc::pid_t,
    log: &mut ReceiptLog,
    mode: &mut GateMode,
    scope: Option<&crate::cgroup::CgroupScope>,
    mut grant_watch: Option<&mut crate::grantwatch::GrantWatch>,
) {
    let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut offset = 0usize;
    while offset + meta_size <= bytes.len() {
        // Safety: we validated there are at least meta_size bytes remaining.
        let meta = unsafe {
            std::ptr::read_unaligned(
                bytes[offset..].as_ptr() as *const libc::fanotify_event_metadata
            )
        };
        let ev_len = meta.event_len as usize;
        if ev_len < meta_size || offset + ev_len > bytes.len() {
            break;
        }

        if meta.mask & libc::FAN_OPEN_PERM != 0 && meta.fd >= 0 {
            decide(
                fan,
                &meta,
                child,
                log,
                mode,
                scope,
                grant_watch.as_deref_mut(),
            );
        }
        if meta.fd >= 0 {
            unsafe {
                libc::close(meta.fd);
            }
        }
        offset += ev_len;
    }
}

/// Disposition of an open already known to belong to the supervised tree, once
/// we know whether its inode could be resolved. Kept pure (no FFI) so the
/// fail-closed contract is unit-testable: an in-tree open whose inode cannot be
/// identified is DENIED, never allowed. Membership and inode-resolution ordering
/// live in `decide`; this captures only the in-tree fstat-fail ruling.
#[derive(Debug, PartialEq, Eq)]
enum InTreeOpen {
    /// Inode resolved — hand to the gate mode for the real allow/deny ruling.
    Judge,
    /// Inode unknown (fstat on the event fd failed) — fail closed.
    DenyUnknownInode,
}

fn in_tree_open(inode_resolved: bool) -> InTreeOpen {
    if inode_resolved {
        InTreeOpen::Judge
    } else {
        InTreeOpen::DenyUnknownInode
    }
}

/// Decide allow/deny for a single permission event and respond.
///
/// An open by the supervised tree of a protected inode is referred to the
/// consent decider, which may allow (once/session), deny, or deny-forever —
/// over an off-band channel the agent has no descriptor on. Opens that are not
/// protected, or come from outside the supervised tree, are allowed without
/// asking. The receipt records the verdict and how it was reached.
fn decide(
    fan: &FanFd,
    meta: &libc::fanotify_event_metadata,
    child: libc::pid_t,
    log: &mut ReceiptLog,
    mode: &mut GateMode,
    scope: Option<&crate::cgroup::CgroupScope>,
    mut grant_watch: Option<&mut crate::grantwatch::GrantWatch>,
) {
    let pid = meta.pid;

    // Tree membership decides whether this open is ours to judge — and it depends
    // only on the pid, not on the file's inode, so it is evaluated FIRST. Prefer
    // cgroup membership: it is reparent-proof, so a process that double-fork()s to
    // orphan itself past the ancestry walk is still attributed to the tree. Where
    // no cgroup scope exists, fall back to the ancestry walk. The two are OR'd so
    // the cgroup result can only *add* members the walk would miss — a reparented
    // orphan whose ppid chain no longer reaches the root.
    let in_tree = match scope {
        Some(s) => s.contains(pid) || proctree::is_descendant_of(pid, child, ANCESTRY_MAX_DEPTH),
        None => proctree::is_descendant_of(pid, child, ANCESTRY_MAX_DEPTH),
    };

    // Opens from outside the supervised tree are never judged — Bulwark only
    // governs the tree it launched. Crucially this is decided BEFORE inode_of_fd,
    // so an out-of-tree open whose fstat would fail is still allowed: it is not
    // ours to deny, and the inode is never consulted.
    if !in_tree {
        respond(fan.fd, meta.fd, true);
        return;
    }

    let chain = proctree::ancestry(pid, ANCESTRY_MAX_DEPTH);
    let ancestry = proctree::render(&chain);

    // The open is in-tree, so we MUST be able to name the inode we are judging.
    // If fstat on the event fd fails we cannot identify it — and a read-gate fails
    // CLOSED when it cannot identify the inode it is about to rule on. Deny the
    // in-tree open rather than release it as allowed (the prior code allowed here,
    // a fail-OPEN: an in-tree open whose stat was made to fail — e.g. by severing
    // a stale network mount between open and stat — escaped the gate). Out-of-tree
    // opens never reach this point, so a stat failure on an unrelated open is not
    // turned into a spurious deny. The disposition is computed by the pure
    // `in_tree_open` so the fail-closed contract is unit-testable.
    let resolved = inode_of_fd(meta.fd);
    let (key, path) = match in_tree_open(resolved.is_some()) {
        InTreeOpen::Judge => resolved.expect("Judge disposition implies the inode resolved"),
        InTreeOpen::DenyUnknownInode => {
            log.record(&Receipt {
                pid,
                dev: 0,
                ino: 0,
                decision: Decision::Deny,
                path: "?",
                ancestry: &ancestry,
                reason: "in-tree open denied: cannot stat event fd (inode unknown)",
                source: "fstat-fail",
            });
            respond(fan.fd, meta.fd, false);
            return;
        }
    };

    match mode {
        GateMode::DenyList { protected, consent } => {
            decide_denylist(
                fan, meta, pid, key, &path, &ancestry, protected, log, *consent,
            );
        }
        GateMode::AllowList { allow } => {
            // Default-deny. Allow iff:
            //   (a) the base set matches the path (documented read floor), OR a
            //       grant glob matches the path AND the inode is in the launch
            //       snapshot — the inode gate that defeats hardlink/rename of a
            //       foreign file into a granted path (B2 / A-2); OR
            //   (b) the inode was WITNESSED as created (not moved) under a grant
            //       AND has link count 1 AND is opened on a grant path — so a file
            //       the agent genuinely creates, or a log rotated into the grant,
            //       is readable, while a hardlinked foreign inode (nlink>1) and a
            //       renamed-in inode (no create witness / evicted) stay denied.
            let (allowed, reason) = if allow.allows_open(&path, &key) {
                (true, "allowlist match")
            } else if allow.grant_path_matches(&path) {
                // Tighten the create/open race: drain any just-arrived create
                // notifications before consulting the witness, then fail closed.
                if let Some(w) = grant_watch.as_deref_mut() {
                    w.drain();
                }
                let witnessed = grant_watch.as_deref().is_some_and(|w| w.witnessed(&key))
                    && crate::grantwatch::nlink_of_fd(meta.fd) == 1;
                if witnessed {
                    (true, "allowlist grant (created in grant, single link)")
                } else {
                    (false, "not in allowlist (default deny)")
                }
            } else {
                (false, "not in allowlist (default deny)")
            };
            log.record(&Receipt {
                pid,
                dev: key.dev,
                ino: key.ino,
                decision: if allowed {
                    Decision::Allow
                } else {
                    Decision::Deny
                },
                path: &path,
                ancestry: &ancestry,
                reason,
                source: "allowlist",
            });
            respond(fan.fd, meta.fd, allowed);
        }
    }
}

/// Deny-list decision: a protected inode opened by the tree is referred to the
/// consent decider; everything else is allowed.
#[allow(clippy::too_many_arguments)]
fn decide_denylist(
    fan: &FanFd,
    meta: &libc::fanotify_event_metadata,
    pid: i32,
    key: InodeKey,
    path: &str,
    ancestry: &str,
    protected: &ProtectedSet,
    log: &mut ReceiptLog,
    consent: &mut dyn ConsentDecider,
) {
    // `protects` matches the inode against the launch snapshot AND, for files
    // not in it, against the inodes of protected ancestor directories — so a
    // nested or post-launch file under a protected directory is still denied.
    if !protected.protects(&key, path) {
        log.record(&Receipt {
            pid,
            dev: key.dev,
            ino: key.ino,
            decision: Decision::Allow,
            path,
            ancestry,
            reason: "not protected",
            source: "",
        });
        respond(fan.fd, meta.fd, true);
        return;
    }

    let req = ConsentRequest {
        pid,
        key,
        path: path.to_string(),
        ancestry: ancestry.to_string(),
        reason: "protected inode opened by supervised tree".to_string(),
    };
    let (verdict, source) = consent.decide(&req);
    let allow = verdict.allows();
    log.record(&Receipt {
        pid,
        dev: key.dev,
        ino: key.ino,
        decision: if allow {
            Decision::Allow
        } else {
            Decision::Deny
        },
        path,
        ancestry,
        reason: verdict_reason(verdict),
        source: source_str(source),
    });
    respond(fan.fd, meta.fd, allow);
}

/// Human-readable reason for a verdict, for the receipt.
fn verdict_reason(v: Verdict) -> &'static str {
    match v {
        Verdict::AllowOnce => "operator allowed once",
        Verdict::AllowSession => "operator allowed for session",
        Verdict::Deny => "denied",
        Verdict::DenyForever => "denied forever",
    }
}

fn source_str(s: Source) -> &'static str {
    s.as_str()
}

// ---- child process management ----------------------------------------------

/// Credentials to drop the supervised child to before exec. The supervisor stays
/// root (it holds the fanotify fd); only the agent child becomes unprivileged, so
/// it cannot signal — and therefore cannot `SIGKILL` — the supervisor. That makes
/// the kernel's fail-open-on-supervisor-death residual unreachable by the agent.
#[derive(Clone, Copy)]
pub struct WorkerCreds {
    pub uid: u32,
    pub gid: u32,
}

/// Drop the calling process to `creds`, permanently, in the security-critical
/// order: supplementary groups, then gid, then uid. Returns `Err` on any failure
/// — the caller MUST NOT exec if this fails. Runs in the forked child before exec,
/// so it uses only raw libc calls (no allocation, no panics).
///
/// Order matters: `setgroups`/`setgid` require privilege, so they must happen
/// while still root, before `setuid` drops it. After dropping, a `setuid(0)` must
/// fail — we assert that, so a saved-set-uid that could be restored is caught
/// rather than silently leaving the agent able to regain root.
///
/// `PR_SET_NO_NEW_PRIVS` is set FIRST and is load-bearing: without it the uid drop
/// is reversible — a dropped agent can `execve` a setuid-root binary (stock hosts
/// ship `mount`, `su`, `sudo`, `pkexec`) to regain euid 0 and then do exactly what
/// the drop was meant to prevent (remount cgroupfs, migrate out of the supervised
/// scope, kill the supervisor). The `setuid(0)`-must-fail check below only proves
/// the *current* credentials cannot regain root, not that a later setuid-exec
/// cannot. `no_new_privs` makes the kernel ignore the setuid bit on every
/// subsequent exec, closing that path. (`hardened.rs` sets the same flag for the
/// Landlock floor, for the same reason.)
///
/// # Safety
/// Must be called in the child between `fork()` and `execvp()`.
unsafe fn drop_to(creds: WorkerCreds) -> std::result::Result<(), i32> {
    // No-new-privs first, while still privileged: makes the uid drop irreversible
    // by ignoring setuid/setgid bits on all future execs in this process tree.
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return Err(libc::EPERM);
    }
    // Supplementary groups: clear to exactly the target gid. We do not call
    // initgroups() (it reads NSS, not async-signal-safe in the forked child);
    // setgroups([gid]) is the minimal, predictable set for an unprivileged worker.
    let groups = [creds.gid as libc::gid_t];
    if libc::setgroups(1, groups.as_ptr()) != 0 {
        return Err(libc::EPERM);
    }
    // gid before uid — once uid drops, setgid loses privilege.
    if libc::setgid(creds.gid as libc::gid_t) != 0 {
        return Err(libc::EPERM);
    }
    if libc::setuid(creds.uid as libc::uid_t) != 0 {
        return Err(libc::EPERM);
    }
    // The drop must be permanent: regaining root must now fail. If setuid(0)
    // succeeds, the privilege drop did not take — refuse to exec.
    if libc::setuid(0) == 0 {
        return Err(libc::EPERM);
    }
    Ok(())
}

/// Fork and exec the command, returning the child pid. When `worker` is `Some`,
/// the child drops to those credentials before exec (the supervisor parent stays
/// root). A failed drop exits the child 126 — never execs the agent half-dropped.
fn spawn(
    command: &[String],
    worker: Option<WorkerCreds>,
    scope: Option<&crate::cgroup::CgroupScope>,
) -> Result<libc::pid_t> {
    let prog = CString::new(command[0].as_bytes())?;
    let argv: Vec<CString> = command
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<std::result::Result<_, _>>()?;
    let mut argv_ptr: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptr.push(std::ptr::null());

    // The cgroup.procs path, resolved before fork so the child uses only the
    // pre-built CString (no allocation in the post-fork path).
    let procs = scope.map(|s| s.procs_path());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(anyhow!(std::io::Error::last_os_error())).context("fork");
    }
    if pid == 0 {
        // Child: join the cgroup scope (while still root), drop privileges (if
        // requested), then exec the target. Order is load-bearing: the cgroup
        // write needs privilege, and membership must be established before exec
        // so the agent — and anything it later orphans — is already in the scope.
        unsafe {
            if let Some(p) = procs {
                if crate::cgroup::join_self(p).is_err() {
                    // Fail closed: if we cannot place the child in the scope, the
                    // reparent-proof attribution would silently not apply — refuse
                    // to run rather than enforce with a hole the operator can't see.
                    libc::_exit(125);
                }
            }
            if let Some(creds) = worker {
                if drop_to(creds).is_err() {
                    // Fail closed: a botched/partial drop must never run the agent.
                    libc::_exit(126);
                }
            }
            libc::execvp(prog.as_ptr(), argv_ptr.as_ptr());
            // Only reached if execvp failed (command not found).
            libc::_exit(127);
        }
    }
    Ok(pid)
}

/// Non-blocking reap. Returns Some(exit_code) once the child has terminated.
fn try_wait(child: libc::pid_t) -> Result<Option<i32>> {
    let mut status: libc::c_int = 0;
    let r = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
    if r < 0 {
        return Err(anyhow!(std::io::Error::last_os_error())).context("waitpid");
    }
    if r == 0 {
        return Ok(None); // still running
    }
    if libc::WIFEXITED(status) {
        return Ok(Some(libc::WEXITSTATUS(status)));
    }
    if libc::WIFSIGNALED(status) {
        return Ok(Some(128 + libc::WTERMSIG(status)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B6 negative control: an in-tree open whose inode cannot be resolved must
    /// fail CLOSED. The pre-fix code allowed on stat failure (fail-OPEN); this
    /// asserts the disposition is now DenyUnknownInode, so reverting the fix
    /// turns this red.
    #[test]
    fn in_tree_open_with_unresolved_inode_fails_closed() {
        assert_eq!(in_tree_open(false), InTreeOpen::DenyUnknownInode);
    }

    /// Control: an in-tree open with a resolved inode is still judged by the
    /// gate mode (the fail-closed branch does not swallow normal opens).
    #[test]
    fn in_tree_open_with_resolved_inode_is_judged() {
        assert_eq!(in_tree_open(true), InTreeOpen::Judge);
    }
}
