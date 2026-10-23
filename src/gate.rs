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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::allowlist::AllowList;
use crate::consent::{ConsentRequest, Source, Verdict};
use crate::proctree;
use crate::protect::{InodeKey, ProtectedSet};
use crate::receipt::{Decision, LogSink, Receipt, ReceiptLog};

const ANCESTRY_MAX_DEPTH: usize = 16;

/// WO-188@v1: one requested response plus one fail-closed DENY retry. A third
/// write would leave the permission event held for longer without adding safety.
const RESPONSE_WRITE_ATTEMPTS: usize = 2;

/// WO-188@v1: test-only count of response writes rejected with EINVAL. The
/// switch is absent from default and release builds with the fault-injection feature off.
#[cfg(feature = "fault-injection")]
static TEST_RESPONSE_WRITE_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// How the gate decides. Deny-list is the interactive default ("protect these,
/// ask about them"); allow-list is the non-interactive CI mode ("allow only
/// these, deny everything else").
// WO-154@v1: separate interactive consent from the permission-event loop.
pub enum GateMode<'a> {
    /// Deny-list: a protected inode opened by the tree is referred to consent.
    DenyList { protected: &'a ProtectedSet },
    /// Allow-list: an open by the tree is allowed iff its path matches the
    /// allowlist; everything else is denied with no prompt.
    AllowList { allow: &'a AllowList },
}

/// WO-154: a protected open handed to the consent worker. The event fd stays
/// open (the kernel holds the open) until the worker writes its verdict. Owned
/// strings (`req`) so the record outlives the loop iteration.
pub(crate) struct DeferredConsent {
    event_fd: RawFd,
    req: ConsentRequest,
    pid: i32,
    key: InodeKey,
    /// When the loop queued it, so a request that sat in the (bounded) queue for
    /// the full consent timeout is denied on dequeue instead of re-prompting.
    arrival: Instant,
}

/// WO-154: bounded capacity of the consent worker's queue. Past this many
/// pending protected opens, later ones are denied immediately ("consent queue
/// full") — the supervisor holds one event fd per pending request, and an
/// unbounded queue would let a flood pin an unbounded number of open fds.
const CONSENT_QUEUE_CAP: usize = 256;

/// WO-155@v1: fault-injection: test-only switches that disable one reaping
/// layer so each can be proven independently. Compiled in ONLY under the
/// `fault-injection` cargo feature — without it these symbols (and the reads
/// below) do not exist, so a release binary cannot have its reaping layers
/// disabled by a stray environment variable.
#[cfg(feature = "fault-injection")]
const SWITCH_NO_CGROUP_KILL: &str = "BULWARK_TEST_NO_CGROUP";
#[cfg(feature = "fault-injection")]
const SWITCH_NO_PDEATHSIG: &str = "BULWARK_TEST_NO_PDEATHSIG";

/// Read a test-only switch. Present (regardless of value) = layer off. Feature-
/// gated like its constants; the call sites use `#[cfg]` to hard-code the
/// enabled answer when the feature is absent.
#[cfg(feature = "fault-injection")]
// WO-155@v1: isolate reaping-layer fault switches to test-only builds.
fn test_layer_disabled(name: &str) -> bool {
    std::env::var_os(name).is_some()
}

/// WO-188@v1: arm a bounded number of synthetic EINVAL response writes for the
/// privileged regression test; no environment read exists in a default build.
#[cfg(feature = "fault-injection")]
fn arm_response_write_failures() {
    let failures = std::env::var("BULWARK_TEST_RESPONSE_WRITE_FAILURES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    TEST_RESPONSE_WRITE_FAILURES.store(failures, Ordering::SeqCst);
}

#[cfg(not(feature = "fault-injection"))]
// WO-188@v1: keep the production build free of response fault injection.
fn arm_response_write_failures() {}

/// Result of a supervised run: the child's exit code plus the deny-forever
/// paths the operator chose this session (for the caller to persist).
// WO-154@v1: return persisted consent outcomes with the supervised exit status.
pub struct RunOutcome {
    pub exit_code: i32,
    pub deny_forever_paths: Vec<String>,
}

/// Set by the signal handler on SIGTERM/SIGINT/SIGHUP. The event loop polls it
/// and, on a graceful shutdown, denies any outstanding permission events before
/// exiting — so a graceful stop fails CLOSED.
///
/// A hard death (SIGKILL / OOM / power loss) that cannot run this handler is
/// covered by the crash watcher instead: it reaps the supervised cgroup so a
/// dead gate never leaves a live unsupervised tree (see `spawn_watcher`). Where
/// the host cannot reap, default mode refuses to start, and `--hardened` keeps
/// its Landlock floor regardless.
pub(crate) static SHUTDOWN: AtomicBool = AtomicBool::new(false);

// WO-12@v1: stop permission decisions when gate shutdown begins.
/// True once a graceful-termination signal has been received. Other modules
/// (e.g. the consent socket wait) consult this to abandon a blocking wait and
/// fail closed.
pub(crate) fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// WO-155@v1: true once the supervisor has begun tearing the run down, by any
/// cause (a graceful signal, the foreground child exiting, or an error). While
/// draining, the permission loop denies protected opens inline and the consent
/// worker denies every deferred request — so, before the fanotify fd closes,
/// every held open has been answered and the tree is confirmed dead, with no
/// timer ever releasing enforcement.
pub(crate) static DRAINING: AtomicBool = AtomicBool::new(false);

// WO-155@v1: let every enforcement path observe teardown synchronously.
pub(crate) fn draining() -> bool {
    DRAINING.load(Ordering::SeqCst)
}

// WO-155@v1: switch all protected opens to fail-closed teardown handling.
fn begin_draining() {
    DRAINING.store(true, Ordering::SeqCst);
}

/// WO-155@v1: fault-injection: set by a SIGUSR2 handler to make the supervisor
/// PANIC in the event loop, so a test can prove a panic-unwind drop of the
/// watcher guard leaves the watcher REAPING (never releasing). Compiled in ONLY
/// under the `fault-injection` feature — a release binary has no such trigger.
#[cfg(feature = "fault-injection")]
static TEST_PANIC: AtomicBool = AtomicBool::new(false);

/// WO-155@v1: fault-injection: async-signal-safe; the event loop does the actual
/// panic, where unwinding is safe.
#[cfg(feature = "fault-injection")]
// WO-155@v1: exercise panic teardown without adding a production trigger.
extern "C" fn on_test_panic(_sig: libc::c_int) {
    TEST_PANIC.store(true, Ordering::SeqCst);
}

/// WO-155@v1: the number of protected opens the loop has deferred to the consent
/// worker but that have not yet been answered. The worker decrements it after
/// each answer, so `0` means every deferred consent has been answered — the gate
/// on which the tree is reaped (never "the child exited", which an uncooperative
/// child never does).
pub(crate) static OUTSTANDING_DEFERRED: AtomicUsize = AtomicUsize::new(0);

/// WO-155@v1: on a graceful stop, how long the supervisor keeps enforcing while
/// it waits for an uncooperative foreground child to observe its forwarded
/// SIGTERM before it escalates to a cgroup reap. Enforcement continues
/// throughout; the timer only escalates (to SIGKILL), it never releases.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// WO-155@v1: after SIGTERM is forwarded to the child's process group, how long
/// the supervisor keeps enforcing while a SIGTERM-cooperative child observes the
/// signal and exits BEFORE the reap escalates to SIGKILL. The forward happens at
/// `SHUTDOWN_GRACE`; the SIGKILL reap waits a further `SIGTERM_TO_KILL` — never
/// in the same pass, so a cooperative child gets its SIGTERM grace.
const SIGTERM_TO_KILL: Duration = Duration::from_secs(2);

// WO-12@v1: stop permission decisions when gate shutdown begins.
/// Async-signal-safe handler: only flips the atomic. The event loop does the
/// actual deny-and-exit work, where it is safe to touch the fanotify fd.
extern "C" fn on_shutdown_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install handlers for the trappable termination signals so the event loop can
/// fail closed on a graceful stop.
// WO-155@v1: convert graceful termination into enforced tree teardown.
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
    // WO-155@v1: fault-injection: arm the supervisor-panic trigger (SIGUSR2),
    // only when the test sets the switch — a stray SIGUSR2 never panics an
    // unrelated fault-injection build.
    #[cfg(feature = "fault-injection")]
    if std::env::var_os("BULWARK_TEST_PANIC_AFTER_SPAWN").is_some() {
        let mut paction: libc::sigaction = unsafe { std::mem::zeroed() };
        paction.sa_sigaction = on_test_panic as extern "C" fn(libc::c_int) as usize;
        paction.sa_flags = 0;
        unsafe {
            libc::sigemptyset(&mut paction.sa_mask);
            libc::sigaction(libc::SIGUSR2, &paction, std::ptr::null_mut());
        }
    }
}

/// The gate's consent dependency: given a request for a protected open, return
/// a verdict and how it was reached. Implemented by `consent::CachingProvider`
/// (wrapped in `main`) so the gate stays agnostic to the transport.
// WO-154@v1: define the worker-owned consent contract used off the event loop.
pub trait ConsentDecider {
    // WO-8@v1: keep consent decisions off the supervised process's channel.
    fn decide(&mut self, req: &ConsentRequest) -> (Verdict, Source);

    /// Decide with a caller-chosen deadline (shorter than the provider's
    /// configured one), so a request that sat in the consent queue is bounded to
    /// what remains of its own consent window. Default: `decide`.
    // WO-154@v1: preserve the original absolute deadline after queueing.
    fn decide_deadline(&mut self, req: &ConsentRequest, _deadline: Duration) -> (Verdict, Source) {
        self.decide(req)
    }

    /// Inform the decider of the supervised tree's cgroup scope (relative path),
    /// so an off-band consent channel can reject answerers that are members of
    /// the tree by the same reparent-proof primitive the gate uses — not just by
    /// ancestry, which a double-fork()'d orphan sheds. Default: no-op (modes with
    /// no off-band channel, or where no cgroup scope exists).
    // WO-71@v1: authenticate consent against the gate's cgroup membership boundary.
    fn bind_scope(&mut self, _scope_rel: Option<&str>) {}

    /// WO-154@v1: attach the gate's log sink so this decider's diagnostics
    /// (e.g. a refused off-band peer) go through the bounded queue instead of a
    /// synchronous stderr write that could stall the consent worker. Default:
    /// no-op (the static-deny floor, and providers with no peer diagnostics).
    // WO-154@v1: route provider diagnostics through the asynchronous log sink.
    fn attach_log(&mut self, _sink: crate::receipt::LogSink) {}

    /// Paths the operator denied forever this session, for the caller to persist
    /// as protected globs. Default: empty (providers without a standing-deny
    /// cache). `run` returns the worker's result so the caller can persist them.
    // WO-154@v1: return standing denials after the consent worker drains.
    fn deny_forever_paths(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Run `command` under the gate.
///
/// `protected` is the resolved inode set to deny; `mark_paths` are the paths
/// whose mounts must be marked for `FAN_OPEN_PERM` (one mark per distinct
/// mount). The caller builds both — from explicit `--protect` paths or from a
/// policy profile — keeping the gate agnostic to policy. Returns the child's
/// exit code.
// WO-155@v1: keep enforcement active until every supervised process is reaped.
pub fn run(
    mode: GateMode,
    consent: Option<Box<dyn ConsentDecider + Send>>,
    consent_timeout: Duration,
    mark_paths: &[PathBuf],
    receipts: Option<&Path>,
    command: &[String],
    worker: Option<WorkerCreds>,
) -> Result<RunOutcome> {
    if command.is_empty() {
        bail!("no command given");
    }
    // WO-188@v1: reset the test-only write fault budget for this one gate run.
    arm_response_write_failures();
    // Open the log before any output, so EVERY diagnostic — the startup banner
    // included — flows through the bounded queue and can never block the event
    // loop (or a post-mark open anywhere on the host) on a stalled reader.
    let mut log = ReceiptLog::new(receipts)?;
    match &mode {
        GateMode::DenyList { protected } => {
            if protected.is_empty() {
                bail!("no protected inodes resolved — nothing to guard");
            }
            log.note(&format!(
                "deny-list: guarding {} inode(s) for FAN_OPEN_PERM",
                protected.len()
            ));
        }
        GateMode::AllowList { allow } => {
            log.note(&format!(
                "allow-list (default-deny): {} allow rule(s) including runtime base set",
                allow.allowed_globs().len()
            ));
        }
    }

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
                log.note(&format!(
                    "note: could not mark {} ({e}); skipping",
                    m.display()
                ));
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
    // chain still carries the scope, so it stays attributed to the tree. Where
    // no scope can be made, this gate refuses below rather than run unguarded.
    let scope = crate::cgroup::CgroupScope::create(std::process::id() as i32);
    // WO-155@v1: this gate (the default, non-hardened path) has no kernel floor
    // that survives gate death, so it MUST be able to reap
    // the whole supervised tree. On a host with no writable cgroup-v2 scope, or
    // with neither cgroup.kill nor the cgroup.freeze + per-pid SIGKILL fallback,
    // a dead gate would leave a live unsupervised agent — refuse now rather than
    // run with that hole. `--hardened` is a separate, Landlock-only launch that
    // never reaches this gate, so it keeps working on such a host.
    match &scope {
        None => {
            bail!(
                "this host cannot reap the supervised tree: no writable cgroup-v2 \
                 scope, so a dead gate would leave a live unsupervised agent. Use \
                 --hardened (its Landlock floor survives gate death) or run on a \
                 cgroup-v2 host"
            );
        }
        Some(s) if !s.can_reap() => {
            bail!(
                "this host cannot reap the supervised tree: the kernel has neither \
                 cgroup.kill (>= 5.14) nor cgroup.freeze (>= 5.2), so a dead gate \
                 would leave a live unsupervised agent. Use --hardened (its Landlock \
                 floor survives gate death) or a newer kernel"
            );
        }
        Some(_) => {}
    }
    match &scope {
        Some(_) => log.note("tree attribution: cgroup-v2 membership (reparent-proof)"),
        None => log.note(
            "note: cgroup-v2 scope unavailable; --hardened covers a deliberately-orphaned \
             descendant with its per-process Landlock floor",
        ),
    }

    // WO-187@v1: group agent OOM victims and make the gate and watcher less
    // attractive than the untrusted tree before either process is forked.
    if let Some(scope) = &scope {
        if let Some(warning) = scope
            .configure_oom_protection()
            .context("cannot lower the gate OOM score")?
        {
            log.note(&format!(
                "warning: {warning}; continuing with OOM score protection"
            ));
        }
    }

    // Hand the consent decider the tree's cgroup scope, then move it onto its
    // own worker thread so a pending prompt never blocks the permission loop
    // (and thereby delays unrelated opens host-wide — WO-154).
    // WO-188@v1: a persistent worker-side response failure wakes the event loop
    // into its existing fatal teardown instead of leaving the opener held.
    let response_write_failed = Arc::new(AtomicBool::new(false));
    let consent_tx: Option<mpsc::SyncSender<DeferredConsent>>;
    let consent_worker: Option<std::thread::JoinHandle<Vec<String>>>;
    match consent {
        Some(mut decider) => {
            decider.bind_scope(scope.as_ref().map(|s| s.rel()));
            let (tx, rx) = mpsc::sync_channel::<DeferredConsent>(CONSENT_QUEUE_CAP);
            let sink = log.sink();
            // The decider's own diagnostics (a refused off-band peer, a socket
            // error) go through the same queue, never a synchronous stderr write.
            decider.attach_log(sink.clone());
            let fan_fd = fan.fd;
            let response_write_failed = Arc::clone(&response_write_failed);
            consent_worker = Some(
                std::thread::Builder::new()
                    .name("bulwark-consent".into())
                    .spawn(move || {
                        consent_thread(
                            rx,
                            fan_fd,
                            decider,
                            sink,
                            consent_timeout,
                            &response_write_failed,
                        )
                    })?,
            );
            consent_tx = Some(tx);
        }
        None => {
            consent_tx = None;
            consent_worker = None;
        }
    }

    // WO-155: a watcher that reaps the whole supervised cgroup if this process
    // dies, for any reason, so a dead supervisor never leaves a live
    // unsupervised tree. Held for the run's lifetime; released by positive proof
    // of an empty scope before this function returns (see below). A panic or any
    // early `?` return drops the guard, closing the write end (EOF) so the
    // watcher REAPS instead of releasing.
    let gate_watcher = spawn_watcher(scope.as_ref())?;

    // Fork + exec the supervised command. The supervisor (this process) stays
    // root and holds the fanotify fd; `worker` drops only the agent child. The
    // child joins the cgroup scope (if any) before exec, while still root.
    let child = spawn(command, worker, scope.as_ref())?;
    // The effective uid is shown inline on the supervising line (no separate
    // drop banner) — so the auto-drop success path adds no extra noise, while the
    // uid in effect stays visible for every run.
    match worker {
        Some(w) => log.note(&format!(
            "supervising pid {child} (uid={} gid={}): {}",
            w.uid,
            w.gid,
            command.join(" ")
        )),
        None => log.note(&format!("supervising pid {child}: {}", command.join(" "))),
    }

    // Event loop: answer permission events until the tree is being torn down
    // (the child exits or a graceful signal arrives). The loop keeps enforcing —
    // denying protected opens and reaping the scope — and returns only once the
    // tree is confirmed dead, never on a timer.
    let exit_code = match event_loop(
        &fan,
        child,
        &mut log,
        mode,
        scope.as_ref(),
        consent_tx.as_ref(),
        &response_write_failed,
    ) {
        Ok(code) => code,
        Err(e) => {
            // Error path: the fanotify fd may already be unusable, but the
            // invariant still holds — deny every deferred consent and reap the
            // tree before the fd closes.
            begin_draining();
            drop(consent_tx);
            reap_tree(&scope, child);
            if let Some(w) = consent_worker {
                let _ = w.join();
            }
            // Only now that the scope is proven empty may the watcher be released.
            if let Some(w) = gate_watcher {
                w.release_proven_empty();
            }
            return Err(e);
        }
    };

    // Normal/graceful teardown: the loop already reaped the tree. Deny any
    // deferred consent (the worker denies them now that draining is set), then
    // re-confirm the tree is empty before the fanotify fd closes on return.
    begin_draining();
    drop(consent_tx);
    let deny_forever_paths = match consent_worker {
        Some(w) => w.join().unwrap_or_default(),
        None => Vec::new(),
    };
    reap_tree(&scope, child);
    // Positive proof the scope is empty: release (not reap) the watcher.
    if let Some(w) = gate_watcher {
        w.release_proven_empty();
    }

    Ok(RunOutcome {
        exit_code,
        deny_forever_paths,
    })
}

// ---- fanotify FFI wrapper ---------------------------------------------------

// WO-3@v1: key the Linux permission gate to stable inode identity.
/// Owned fanotify file descriptor.
struct FanFd {
    fd: RawFd,
}

// WO-3@v1: key the Linux permission gate to stable inode identity.
impl FanFd {
    // WO-66@v1: prevent bounded fanotify queue overflow from releasing reads.
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

    // WO-3@v1: key the Linux permission gate to stable inode identity.
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

// WO-3@v1: key the Linux permission gate to stable inode identity.
impl Drop for FanFd {
    // WO-3@v1: key the Linux permission gate to stable inode identity.
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

// WO-3@v1: key the Linux permission gate to stable inode identity.
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

/// WO-188@v1: the only two response values the encoder can emit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FanDecision {
    Allow,
    Deny,
}

impl FanDecision {
    // WO-188@v1: map the typed response to the Linux ABI constant at one boundary.
    fn encode(self, event_fd: RawFd) -> libc::fanotify_response {
        libc::fanotify_response {
            fd: event_fd,
            response: match self {
                FanDecision::Allow => libc::FAN_ALLOW,
                FanDecision::Deny => libc::FAN_DENY,
            },
        }
    }

    // WO-188@v1: report the response the kernel actually accepted after retry.
    fn allows(self) -> bool {
        self == FanDecision::Allow
    }
}

/// WO-188@v1: write exactly one complete response and reject every short write.
fn write_response_once(fan_fd: RawFd, response: libc::fanotify_response) -> std::io::Result<()> {
    #[cfg(feature = "fault-injection")]
    if TEST_RESPONSE_WRITE_FAILURES
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
            (left > 0).then(|| left - 1)
        })
        .is_ok()
    {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }

    let n = unsafe {
        libc::write(
            fan_fd,
            &response as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::fanotify_response>(),
        )
    };
    if n == std::mem::size_of::<libc::fanotify_response>() as isize {
        Ok(())
    } else if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            format!(
                "short fanotify response write: {n}/{} bytes",
                std::mem::size_of::<libc::fanotify_response>()
            ),
        ))
    }
}

/// WO-188@v1: write the requested response once, then retry exactly once as
/// DENY. A second rejection is gate-fatal so teardown closes the fanotify group.
fn write_response(
    fan_fd: RawFd,
    event_fd: RawFd,
    requested: FanDecision,
) -> std::io::Result<FanDecision> {
    let first = match write_response_once(fan_fd, requested.encode(event_fd)) {
        Ok(()) => return Ok(requested),
        Err(e) => e,
    };
    match write_response_once(fan_fd, FanDecision::Deny.encode(event_fd)) {
        Ok(()) => Ok(FanDecision::Deny),
        Err(retry) => Err(std::io::Error::new(
            retry.kind(),
            format!(
                "fanotify response write failed after {RESPONSE_WRITE_ATTEMPTS} attempts \
                 (first: {first}; DENY retry: {retry})"
            ),
        )),
    }
}

/// Reply to a permission event from the loop. The failure warning is queued
/// off-loop, so even a broken response path cannot block the loop on output.
// WO-188@v1: return the response the kernel accepted and propagate a persistent failure.
fn respond(
    fan_fd: RawFd,
    event_fd: RawFd,
    allow: bool,
    log: &mut ReceiptLog,
) -> std::io::Result<bool> {
    let requested = if allow {
        FanDecision::Allow
    } else {
        FanDecision::Deny
    };
    match write_response(fan_fd, event_fd, requested) {
        Ok(actual) => {
            if actual != requested {
                log.warn("fanotify ALLOW write failed; event denied on retry");
            }
            Ok(actual.allows())
        }
        Err(e) => {
            log.warn(&format!("failed to write fanotify response: {e}"));
            Err(e)
        }
    }
}

/// WO-154: the consent worker. Owns the decider, and for each deferred
/// protected open decides (blocking — this is the whole point: the block is
/// here, off the permission loop), answers it, closes its event fd, and records
/// the receipt. On channel close it returns the decider's deny-forever paths
/// for the caller to persist.
// WO-188@v1: signal a persistent worker-side response failure to the event loop.
fn consent_thread(
    rx: mpsc::Receiver<DeferredConsent>,
    fan_fd: RawFd,
    mut decider: Box<dyn ConsentDecider + Send>,
    log: LogSink,
    timeout: Duration,
    response_write_failed: &AtomicBool,
) -> Vec<String> {
    while let Ok(d) = rx.recv() {
        // Deny promptly (a) on graceful shutdown — the loop is about to close the
        // fanotify fd, so every deferred open must be answered first — or (b) if
        // the request already sat in the queue past its consent deadline.
        // Otherwise prompt for what REMAINS of the request's deadline (measured
        // from its arrival), so a queue never extends past the consent timeout.
        let remaining = timeout.saturating_sub(d.arrival.elapsed());
        let (verdict, source) = if shutdown_requested() || draining() || remaining.is_zero() {
            (Verdict::Deny, Source::Timeout)
        } else {
            decider.decide_deadline(&d.req, remaining)
        };
        answer_deferred(fan_fd, &log, d, verdict, source, response_write_failed);
        // Once the supervisor is draining (or a signal arrived), empty the rest
        // of the queue non-blockingly so OUTSTANDING_DEFERRED reaches zero and the
        // loop may reap — never left waiting for a cooperative child to exit.
        if draining() || shutdown_requested() {
            while let Ok(more) = rx.try_recv() {
                answer_deferred(
                    fan_fd,
                    &log,
                    more,
                    Verdict::Deny,
                    Source::Timeout,
                    response_write_failed,
                );
            }
        }
    }
    // Drain anything still queued at channel close (deny it) before returning.
    while let Ok(more) = rx.try_recv() {
        answer_deferred(
            fan_fd,
            &log,
            more,
            Verdict::Deny,
            Source::Timeout,
            response_write_failed,
        );
    }
    decider.deny_forever_paths()
}

/// WO-154: answer (and close, and log) one deferred protected open, and release
/// its outstanding-deferred slot so the loop knows it has been answered.
// WO-188@v1: retry a rejected deferred verdict as DENY before declaring gate failure.
fn answer_deferred(
    fan_fd: RawFd,
    log: &LogSink,
    d: DeferredConsent,
    verdict: Verdict,
    source: Source,
    response_write_failed: &AtomicBool,
) {
    // WO-188@v1: an ALLOW rejection becomes DENY; two rejected writes make the
    // whole gate fatal, which the event loop observes before its next decision.
    let requested = if verdict.allows() {
        FanDecision::Allow
    } else {
        FanDecision::Deny
    };
    let (actual, response_reason) = match write_response(fan_fd, d.event_fd, requested) {
        Ok(actual) => {
            if actual != requested {
                log.warn("fanotify ALLOW write failed; deferred event denied on retry");
            }
            (actual, None)
        }
        Err(e) => {
            log.warn(&format!("failed to write fanotify response: {e}"));
            response_write_failed.store(true, Ordering::SeqCst);
            (
                FanDecision::Deny,
                Some("fanotify response failed; gate teardown"),
            )
        }
    };
    unsafe {
        libc::close(d.event_fd);
    }
    log.record(&Receipt {
        pid: d.pid,
        dev: d.key.dev,
        ino: d.key.ino,
        decision: if actual.allows() {
            Decision::Allow
        } else {
            Decision::Deny
        },
        path: &d.req.path,
        ancestry: &d.req.ancestry,
        reason: response_reason.unwrap_or_else(|| verdict_reason(verdict)),
        source: source_str(source),
    });
    OUTSTANDING_DEFERRED.fetch_sub(1, Ordering::SeqCst);
}

/// Core permission-event loop. Reads events, decides, responds, and returns the
/// child's exit code once the supervised tree is confirmed dead.
///
/// WO-155@v1: on EVERY exit path (child done, graceful signal) the loop drains
/// rather than returning at once — it keeps answering events (denying protected
/// opens inline) while reaping the scope, and returns only once the tree is
/// confirmed dead (cgroup.events `populated 0`, or the direct child reaped with
/// no scope). No timer releases enforcement.
// WO-188@v1: treat every persistent response rejection as fatal to the gate.
fn event_loop(
    fan: &FanFd,
    child: libc::pid_t,
    log: &mut ReceiptLog,
    mut mode: GateMode,
    scope: Option<&crate::cgroup::CgroupScope>,
    consent_tx: Option<&mpsc::SyncSender<DeferredConsent>>,
    response_write_failed: &AtomicBool,
) -> Result<i32> {
    const BUF_LEN: usize = 8192;
    let mut buf = [0u8; BUF_LEN];

    // Once the foreground child is reaped we record its code but keep enforcing
    // until the cgroup scope drains (orphaned double-fork descendants).
    let mut foreground_exit: Option<i32> = None;
    // `Some(130)` once a graceful signal arrived; `foreground_exit` carries the
    // child's code. The two combine into the run's exit code at the end.
    let mut shutdown_code: Option<i32> = None;
    // Whether the one-shot reap triggers have run for this teardown.
    let mut reaped = false;
    // When a graceful signal arrived (for the grace escalation), and whether we
    // have forwarded SIGTERM to the child's process group yet.
    let mut shutdown_started: Option<Instant> = None;
    let mut sigterm_sent = false;

    loop {
        // WO-188@v1: a consent-worker response failure is gate-fatal; the caller
        // reaps the tree before dropping the fanotify group and releasing the event.
        if response_write_failed.load(Ordering::SeqCst) {
            return Err(anyhow!(
                "persistent fanotify response failure in consent worker"
            ));
        }
        // WO-155@v1: fault-injection: the SIGUSR2 handler set this; panic HERE
        // (the main loop), so the unwind is safe but observable — the dropped
        // watcher guard must leave the watcher reaping, and a still-held
        // grandchild read must never be released as allowed.
        #[cfg(feature = "fault-injection")]
        if TEST_PANIC.load(Ordering::SeqCst) {
            panic!("BULWARK_TEST_PANIC_AFTER_SPAWN");
        }

        // Graceful shutdown: deny every buffered permission event once, then
        // drain (below) — fail closed, never let the kernel release a held read
        // as allowed.
        if SHUTDOWN.load(Ordering::SeqCst) && shutdown_code.is_none() {
            let denied = drain_and_deny(fan, &mut buf, log)?;
            log.note(&format!(
                "shutdown: denied {denied} outstanding event(s), draining the tree"
            ));
            shutdown_code = Some(130);
        }

        // Poll and answer: a protected open is denied inline while draining, so
        // the loop keeps enforcing and the drain never holds an open.
        let mut pfd = libc::pollfd {
            fd: fan.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, 200) };
        if pr < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue; // a signal interrupted poll — loop re-checks SHUTDOWN
            }
            return Err(anyhow!(err)).context("poll");
        }

        if pr > 0 && (pfd.revents & libc::POLLIN) != 0 {
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
                consent_tx,
            )?;
        }

        // Reap the foreground child once (a second waitpid would return ECHILD).
        if foreground_exit.is_none() {
            if let Some(code) = try_wait(child)? {
                foreground_exit = Some(code);
            }
        }

        // Exiting (signal arrived, or the foreground child is gone): keep
        // enforcing while reaping, and return only once the tree is dead.
        if shutdown_code.is_some() || foreground_exit.is_some() {
            begin_draining();
            // Reap only once every deferred consent has been answered DENY (so a
            // held open is never released as allowed when the fd closes) AND the
            // tree is ready to die — the child exited, or the grace elapsed and
            // we escalate. Enforcement continues throughout; the grace only
            // escalates to a reap, it never releases the tree to a later read.
            let drained = OUTSTANDING_DEFERRED.load(Ordering::SeqCst) == 0;
            let child_done = foreground_exit.is_some();
            // Start the shutdown clock once the deferred are all answered DENY,
            // so a cooperative child finishes its denied reads first.
            if drained && shutdown_started.is_none() {
                shutdown_started = Some(Instant::now());
            }
            let grace_elapsed = shutdown_started
                .map(|t| Instant::now() >= t + SHUTDOWN_GRACE)
                .unwrap_or(false);
            // Forward SIGTERM to the child's process group once every deferred
            // consent is answered DENY and the grace elapsed. A SIGTERM-
            // cooperative child observes this and exits BEFORE any reap.
            if shutdown_code.is_some() && drained && grace_elapsed && !sigterm_sent && !child_done {
                sigterm_sent = true;
                unsafe {
                    libc::killpg(child, libc::SIGTERM);
                }
            }
            // SIGKILL-reap only AFTER a further SIGTERM_TO_KILL (never in the
            // same pass as the SIGTERM forward), or once the child has already
            // exited. Enforcement continues throughout this window.
            let kill_escalates = sigterm_sent
                && shutdown_started
                    .map(|t| Instant::now() >= t + SHUTDOWN_GRACE + SIGTERM_TO_KILL)
                    .unwrap_or(false);
            if drained && (child_done || kill_escalates) {
                reap_step(scope, child, &mut reaped);
            }
            let dead = match scope {
                Some(s) => !s.is_populated(),
                None => foreground_exit.is_some(),
            };
            if dead {
                return Ok(shutdown_code.or(foreground_exit).unwrap());
            }
            // else: loop again — answer more events, reap again. No timer.
        }
    }
}

/// WO-155@v1: one step of reaping the supervised tree, idempotent, called from
/// the loop between answering events so enforcement never pauses. Prefers the
/// one-shot `cgroup.kill`; where it is absent, freezes the scope (so no new
/// member forks in) and SIGKILLs every pid in `cgroup.procs`. Without a scope,
/// SIGKILLs the direct child's process group (a deliberately-orphaned descendant
/// is then behind the Landlock floor in `--hardened`).
fn reap_step(scope: Option<&crate::cgroup::CgroupScope>, child: libc::pid_t, reaped: &mut bool) {
    match scope {
        Some(s) => {
            if !*reaped {
                *reaped = true;
                if !s.kill_all() {
                    let _ = s.freeze();
                }
            }
            for pid in s.procs() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        None => unsafe {
            libc::killpg(child, libc::SIGKILL);
        },
    }
}

/// WO-155@v1: blocking reap for the teardown paths that no longer answer events
/// (e.g. after an error). Loops `reap_step` until the scope is empty — no timer.
fn reap_tree(scope: &Option<crate::cgroup::CgroupScope>, child: libc::pid_t) {
    let mut reaped = false;
    loop {
        reap_step(scope.as_ref(), child, &mut reaped);
        let dead = match scope {
            Some(s) => !s.is_populated(),
            None => true,
        };
        if dead {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// On graceful shutdown, read every immediately-available permission event and
/// deny it, so no held read is released as allowed when we exit. Returns the
/// number of events denied. Best-effort and non-blocking: we drain what the
/// kernel has queued right now.
// WO-155@v1: deny every queued permission event before the gate closes.
// WO-188@v1: a rejected shutdown response is fatal instead of silently held.
fn drain_and_deny(fan: &FanFd, buf: &mut [u8], log: &mut ReceiptLog) -> Result<usize> {
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
                respond(fan.fd, meta.fd, false, log)?;
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
    Ok(denied)
}

/// Decode and answer all events in a read buffer.
// WO-154@v1: hand protected opens to consent without blocking unrelated events.
// WO-188@v1: propagate a persistent response failure to gate teardown.
fn handle_events(
    fan: &FanFd,
    bytes: &[u8],
    child: libc::pid_t,
    log: &mut ReceiptLog,
    mode: &mut GateMode,
    scope: Option<&crate::cgroup::CgroupScope>,
    consent_tx: Option<&mpsc::SyncSender<DeferredConsent>>,
) -> Result<()> {
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
            // `decide` returns true when it handed the event fd to the consent
            // worker (deferred): then the worker, not this loop, owns and closes
            // it. Otherwise the loop answers inline and closes the fd here.
            let deferred = match decide(fan, &meta, child, log, mode, scope, consent_tx) {
                Ok(deferred) => deferred,
                Err(e) => {
                    // WO-188@v1: the group teardown releases the held event; close
                    // our event-fd copy while propagating the fatal response error.
                    unsafe {
                        libc::close(meta.fd);
                    }
                    return Err(e);
                }
            };
            if !deferred {
                unsafe {
                    libc::close(meta.fd);
                }
            }
        } else if meta.fd >= 0 {
            unsafe {
                libc::close(meta.fd);
            }
        }
        offset += ev_len;
    }
    Ok(())
}

/// Disposition of an open already known to belong to the supervised tree, once
/// we know whether its inode could be resolved. Kept pure (no FFI) so the
/// fail-closed contract is unit-testable: an in-tree open whose inode cannot be
/// identified is DENIED, never allowed. Membership and inode-resolution ordering
/// live in `decide`; this captures only the in-tree fstat-fail ruling.
#[derive(Debug, PartialEq, Eq)]
// WO-70@v1: represent failed in-tree inode resolution as an explicit denial.
enum InTreeOpen {
    /// Inode resolved — hand to the gate mode for the real allow/deny ruling.
    Judge,
    /// Inode unknown (fstat on the event fd failed) — fail closed.
    DenyUnknownInode,
}

// WO-70@v1: fail closed when an in-tree event fd cannot be identified.
fn in_tree_open(inode_resolved: bool) -> InTreeOpen {
    if inode_resolved {
        InTreeOpen::Judge
    } else {
        InTreeOpen::DenyUnknownInode
    }
}

/// Decide allow/deny for a single permission event. Returns `true` when the
/// event was deferred to the consent worker (the fd is now the worker's to
/// answer and close); `false` when it was answered inline.
///
/// An open by the supervised tree of a protected inode is referred to the
/// consent worker, which may allow (once/session), deny, or deny-forever —
/// over an off-band channel the agent has no descriptor on. Opens that are not
/// protected, or come from outside the supervised tree, are allowed without
/// asking. The receipt records the verdict and how it was reached.
// WO-70@v1: establish tree membership before resolving the event inode.
// WO-188@v1: bubble persistent response failures into the fatal event-loop path.
fn decide(
    fan: &FanFd,
    meta: &libc::fanotify_event_metadata,
    child: libc::pid_t,
    log: &mut ReceiptLog,
    mode: &mut GateMode,
    scope: Option<&crate::cgroup::CgroupScope>,
    consent_tx: Option<&mpsc::SyncSender<DeferredConsent>>,
) -> Result<bool> {
    let pid = meta.pid;

    // Tree membership decides whether this open is ours to judge — and it depends
    // only on the pid, not on the file's inode, so it is evaluated FIRST. Prefer
    // cgroup membership: it is reparent-proof, so a process that double-fork()s to
    // orphan itself past the ancestry walk is still attributed to the tree. The
    // ancestry walk is OR'd on as a per-open fallback for a single unreadable pid
    // (a process gone between lookup and decision); default mode never reaches the
    // scope-less arm — it refuses to start without a reapable scope.
    let in_tree = match scope {
        Some(s) => s.contains(pid) || proctree::is_descendant_of(pid, child, ANCESTRY_MAX_DEPTH),
        None => proctree::is_descendant_of(pid, child, ANCESTRY_MAX_DEPTH),
    };

    // Opens from outside the supervised tree are never judged — Bulwark only
    // governs the tree it launched. Crucially this is decided BEFORE inode_of_fd,
    // so an out-of-tree open whose fstat would fail is still allowed: it is not
    // ours to deny, and the inode is never consulted.
    if !in_tree {
        respond(fan.fd, meta.fd, true, log)?;
        return Ok(false);
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
            respond(fan.fd, meta.fd, false, log)?;
            return Ok(false);
        }
    };

    match mode {
        GateMode::DenyList { protected } => decide_denylist(
            fan, meta, pid, key, &path, &ancestry, protected, log, consent_tx,
        ),
        GateMode::AllowList { allow } => {
            // Default-deny: allow iff the base set matches the path, OR a grant
            // glob matches the path AND the opened (inode, generation) is in the
            // grant launch snapshot. The inode gate defeats hardlink/rename of a
            // foreign file into a granted path; the generation defeats
            // inode-number REUSE of a deleted granted file. No prompt.
            let opened_gen = crate::allowlist::fs_generation_fd(meta.fd);
            let allowed = allow.allows_open(&path, &key, opened_gen);
            let answered_allow = respond(fan.fd, meta.fd, allowed, log)?;
            log.record(&Receipt {
                pid,
                dev: key.dev,
                ino: key.ino,
                decision: if answered_allow {
                    Decision::Allow
                } else {
                    Decision::Deny
                },
                path: &path,
                ancestry: &ancestry,
                reason: if allowed && !answered_allow {
                    "fanotify allow response failed; denied on retry"
                } else if allowed {
                    "allowlist match"
                } else {
                    "not in allowlist (default deny)"
                },
                source: "allowlist",
            });
            Ok(false)
        }
    }
}

/// Deny-list decision: a protected inode opened by the tree is deferred to the
/// consent worker; everything else is allowed inline. Returns `true` when the
/// event was deferred (the worker owns and will close the event fd).
#[allow(clippy::too_many_arguments)]
// WO-154@v1: defer protected deny-list opens to the consent worker.
// WO-188@v1: propagate a persistent response failure instead of holding the opener.
fn decide_denylist(
    fan: &FanFd,
    meta: &libc::fanotify_event_metadata,
    pid: i32,
    key: InodeKey,
    path: &str,
    ancestry: &str,
    protected: &ProtectedSet,
    log: &mut ReceiptLog,
    consent_tx: Option<&mpsc::SyncSender<DeferredConsent>>,
) -> Result<bool> {
    // `protects` matches the inode against the launch snapshot AND, for files
    // not in it, against the inodes of protected ancestor directories — so a
    // nested or post-launch file under a protected directory is still denied.
    if !protected.protects(&key, path) {
        let answered_allow = respond(fan.fd, meta.fd, true, log)?;
        log.record(&Receipt {
            pid,
            dev: key.dev,
            ino: key.ino,
            decision: if answered_allow {
                Decision::Allow
            } else {
                Decision::Deny
            },
            path,
            ancestry,
            reason: if answered_allow {
                "not protected"
            } else {
                "fanotify allow response failed; denied on retry"
            },
            source: "",
        });
        return Ok(false);
    }

    // A protected inode opened by the supervised tree. While draining the tree
    // there is no operator left to prompt and the consent worker is being torn
    // down — answer DENY inline rather than defer (the loop keeps enforcing, so
    // a held open is never released as allowed).
    if draining() {
        log.record(&Receipt {
            pid,
            dev: key.dev,
            ino: key.ino,
            decision: Decision::Deny,
            path,
            ancestry,
            reason: "denied on supervisor teardown",
            source: "shutdown",
        });
        respond(fan.fd, meta.fd, false, log)?;
        return Ok(false);
    }

    // A protected inode opened by the supervised tree. Defer it: send the event
    // (fd still open) to the consent worker and return, so no prompt blocks the
    // loop — and therefore no prompt delays an unrelated open host-wide. The
    // queue is bounded: when it is full the open is denied immediately instead
    // of holding an unbounded number of event fds.
    let d = DeferredConsent {
        event_fd: meta.fd,
        req: ConsentRequest {
            pid,
            key,
            path: path.to_string(),
            ancestry: ancestry.to_string(),
            reason: "protected inode opened by supervised tree".to_string(),
        },
        pid,
        key,
        arrival: Instant::now(),
    };
    match consent_tx {
        Some(tx) => match tx.try_send(d) {
            Ok(()) => {
                // Deferred: the worker owns and will close the fd. Count it so
                // the loop can reap exactly when the last one is answered.
                OUTSTANDING_DEFERRED.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            }
            Err(e) => {
                // Queue full (or the worker is gone): fail closed inline rather
                // than queue an unboundedly growing number of open event fds.
                let reason = match e {
                    mpsc::TrySendError::Full(_) => "consent queue full",
                    mpsc::TrySendError::Disconnected(_) => "consent worker unavailable",
                };
                log.record(&Receipt {
                    pid,
                    dev: key.dev,
                    ino: key.ino,
                    decision: Decision::Deny,
                    path,
                    ancestry,
                    reason,
                    source: Source::Static.as_str(),
                });
                respond(fan.fd, meta.fd, false, log)?;
                Ok(false)
            }
        },
        None => {
            // No consent channel (defensive): fail closed inline.
            log.record(&Receipt {
                pid,
                dev: key.dev,
                ino: key.ino,
                decision: Decision::Deny,
                path,
                ancestry,
                reason: "consent worker unavailable",
                source: Source::Static.as_str(),
            });
            respond(fan.fd, meta.fd, false, log)?;
            Ok(false)
        }
    }
}

// WO-8@v1: keep consent decisions off the supervised process's channel.
/// Human-readable reason for a verdict, for the receipt.
fn verdict_reason(v: Verdict) -> &'static str {
    match v {
        Verdict::AllowOnce => "operator allowed once",
        Verdict::AllowSession => "operator allowed for session",
        Verdict::Deny => "denied",
        Verdict::DenyForever => "denied forever",
    }
}

// WO-8@v1: keep consent decisions off the supervised process's channel.
fn source_str(s: Source) -> &'static str {
    s.as_str()
}

// ---- child process management ----------------------------------------------

// WO-49@v1: drop the supervised worker below the privileged gate.
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
// WO-67@v1: make the worker credential drop irreversible across later execs.
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
// WO-59@v1: place the child in its inherited membership scope before exec.
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
    // The supervisor pid and the PDPDEATHSIG reaping layer are read BEFORE fork
    // (only async-signal-safe values cross into the child). `no_pdeathsig` is
    // hard-coded false in a default (non-fault-injection) build — the switch-
    // reading path does not compile in at all there.
    let supervisor_pid = unsafe { libc::getpid() };
    #[cfg(feature = "fault-injection")]
    let no_pdeathsig = test_layer_disabled(SWITCH_NO_PDEATHSIG);
    #[cfg(not(feature = "fault-injection"))]
    let no_pdeathsig = false;

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
            // WO-155@v1: place the child in its OWN process group so the
            // scope-less --hardened teardown can killpg(pid) the tree (its
            // descendants that did not setsid) without hitting the supervisor's
            // own group.
            libc::setpgid(0, 0);
            if let Some(p) = procs {
                if crate::cgroup::join_self(p).is_err() {
                    // Fail closed: if we cannot place the child in the scope, the
                    // reparent-proof attribution would silently not apply — refuse
                    // to run rather than enforce with a hole the operator can't see.
                    libc::_exit(125);
                }
            }
            // WO-187@v1: the watcher keeps the gate's low OOM score, but the
            // untrusted child must return to the default before it can allocate.
            if crate::cgroup::reset_agent_oom_score().is_err() {
                libc::_exit(125);
            }
            if let Some(creds) = worker {
                if drop_to(creds).is_err() {
                    // Fail closed: a botched/partial drop must never run the agent.
                    libc::_exit(126);
                }
            }
            // WO-155: PR_SET_PDEATHSIG is cleared by the kernel when euid/egid
            // change, so it must be set AFTER the credential drop, immediately
            // before exec. Then confirm the parent is still the supervisor — a
            // reparent between fork and here means the supervisor already died,
            // so refuse to run rather than exec under a dead one.
            if !no_pdeathsig {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                if libc::getppid() != supervisor_pid {
                    libc::_exit(125);
                }
            }
            libc::execvp(prog.as_ptr(), argv_ptr.as_ptr());
            // Only reached if execvp failed (command not found).
            libc::_exit(127);
        }
    }
    Ok(pid)
}

/// WO-155: owns the watcher pipe's write end and closes it on drop, so a
/// hard supervisor death (SIGKILL is covered by the kernel closing the fd,
/// whatever the cause) leaves the watcher reaping. A plain `Drop` closes only —
/// closing the write end is an EOF, so the watcher reaps. A supervisor PANIC
/// unwinds and drops this guard in the same way (EOF => reap), never releasing
/// the scope unwatched. Only `release_proven_empty` (below) writes the graceful
/// byte, and only the supervisor calls that AFTER `reap_tree` has proven the
/// scope empty.
struct WatcherGuard(RawFd);
// WO-155@v1: make every unreleased watcher guard trigger tree reaping.
impl Drop for WatcherGuard {
    // WO-155@v1: trigger reaping when teardown unwinds before proven release.
    fn drop(&mut self) {
        // Close only: EOF => the watcher reaps. No graceful byte — that is
        // reserved for release_proven_empty, and must never fire on an unwinding
        // panic (which would release the tree unwatched).
        if self.0 >= 0 {
            unsafe { libc::close(self.0) };
        }
    }
}

// WO-155@v1: release the watcher only after positive empty-tree proof.
impl WatcherGuard {
    /// Release the watcher WITH positive proof: write the graceful byte (the
    /// watcher reads `1` and skips reaping — the scope is already gone), then
    /// close. Call ONLY after `reap_tree` has proven the scope empty, on the
    /// graceful path and the event-loop error path. Any other drop (an early
    /// return or a panic) closes without the byte, so the watcher reaps instead.
    // WO-155@v1: distinguish proven graceful release from crash-triggered EOF.
    fn release_proven_empty(mut self) {
        let fd = self.0;
        self.0 = -1; // Drop must not double-close.
        unsafe {
            let one = b"1";
            let _ = libc::write(fd, one.as_ptr() as *const libc::c_void, 1);
            libc::close(fd);
        }
    }
}

/// WO-155: fork a watcher that outlives the supervisor and reaps the run's
/// cgroup when the supervisor dies — by any cause, including ones where the
/// supervisor's own cleanup cannot run. The watcher blocks reading one end of a
/// pipe while the supervisor holds the other; the kernel closes the supervisor's
/// end on its death, the watcher's `read` returns EOF, and it reaps the scope:
/// `cgroup.kill` where present, else `cgroup.freeze` + a per-pid SIGKILL sweep
/// until `cgroup.events` reports `populated 0`. Returns the write end (guarded)
/// for the supervisor to hold; `None` when there is no cgroup scope.
fn spawn_watcher(scope: Option<&crate::cgroup::CgroupScope>) -> Result<Option<WatcherGuard>> {
    // WO-155@v1: fault-injection: a test-only switch disables the watcher so
    // a test can prove the direct-child parent-death signal alone. Compiled in
    // only under the `fault-injection` feature.
    #[cfg(feature = "fault-injection")]
    if test_layer_disabled(SWITCH_NO_CGROUP_KILL) {
        return Ok(None);
    }
    let scope = match scope {
        Some(s) => s,
        None => return Ok(None),
    };

    // WO-155@v1: fault-injection: read before fork so the watcher's raw-libc
    // body needs no getenv. `kill_write_fails` makes the cgroup.kill write fail;
    // `events_read_failures` fails the first N cgroup.events reads; `no_procs_events`
    // makes the membership/status files unopenable (a refusal host). Together they
    // force the fail-closed paths in a hard-SIGKILL test.
    #[cfg(feature = "fault-injection")]
    let kill_write_fails = std::env::var_os("BULWARK_TEST_KILL_WRITE_FAIL").is_some();
    #[cfg(not(feature = "fault-injection"))]
    let kill_write_fails = false;
    #[cfg(feature = "fault-injection")]
    let events_read_failures = std::env::var_os("BULWARK_TEST_EVENTS_READ_FAILS")
        .and_then(|v| v.to_string_lossy().parse::<u32>().ok())
        .unwrap_or(0);
    #[cfg(not(feature = "fault-injection"))]
    let events_read_failures = 0u32;
    #[cfg(feature = "fault-injection")]
    let procs_read_failures = std::env::var_os("BULWARK_TEST_PROCS_READ_FAILS")
        .and_then(|v| v.to_string_lossy().parse::<u32>().ok())
        .unwrap_or(0);
    #[cfg(not(feature = "fault-injection"))]
    let procs_read_failures = 0u32;
    #[cfg(feature = "fault-injection")]
    let events_populated_for = std::env::var_os("BULWARK_TEST_EVENTS_READ_POPULATED_FOR")
        .and_then(|v| v.to_string_lossy().parse::<u32>().ok())
        .unwrap_or(0);
    #[cfg(not(feature = "fault-injection"))]
    let events_populated_for = 0u32;
    #[cfg(feature = "fault-injection")]
    let no_procs_events = std::env::var_os("BULWARK_TEST_NO_PROCS_EVENTS").is_some();
    #[cfg(not(feature = "fault-injection"))]
    let no_procs_events = false;

    // Open every reaping file BEFORE fork: after fork in this multithreaded
    // supervisor only async-signal-safe syscalls may run, so the child must not
    // open() pathnames itself. Each fd is CLOEXEC so the agent's exec drops
    // them; the watcher child never execs, so it keeps its copies.
    let kill_fd = {
        // WO-155@v1: fault-injection: the "no cgroup.kill" switch applies to the
        // watcher too — on a host without cgroup.kill the watcher must use the
        // freeze + SIGKILL sweep, not silently fail.
        #[cfg(feature = "fault-injection")]
        let no_kill = std::env::var_os("BULWARK_TEST_NO_CGROUP_KILL").is_some();
        #[cfg(not(feature = "fault-injection"))]
        let no_kill = false;
        if no_kill {
            -1
        } else {
            open_cgroup_writer(&scope.kill_path())
        }
    };
    let freeze_fd = open_cgroup_writer(&scope.freeze_path());
    let procs_fd = if no_procs_events {
        -1
    } else {
        unsafe {
            libc::open(
                scope.procs_path().as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        }
    };
    let events_fd = if no_procs_events {
        -1
    } else {
        open_cgroup_reader(&scope.events_path())
    };

    // The watcher can only prove the tree is dead by reading cgroup.procs (to
    // sweep pids) and cgroup.events (to confirm `populated 0`). If either cannot
    // be opened, a dead gate could never confirm a reaped tree — refuse rather
    // than run with that hole (`--hardened` is the Landlock-only path and never
    // reaches this gate).
    if procs_fd < 0 || events_fd < 0 {
        unsafe {
            libc::close(kill_fd);
            libc::close(freeze_fd);
            libc::close(procs_fd);
            libc::close(events_fd);
        }
        return Err(anyhow!(
            "this host cannot reap the supervised tree: the cgroup exposes no readable \
             cgroup.procs/cgroup.events, so a dead gate cannot confirm the tree is reaped. \
             Use --hardened (its Landlock floor survives gate death) or a cgroup-v2 host \
             that exposes both files"
        ));
    }

    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        unsafe {
            libc::close(kill_fd);
            libc::close(freeze_fd);
            libc::close(procs_fd);
            libc::close(events_fd);
        }
        return Err(anyhow!(std::io::Error::last_os_error())).context("pipe for gate watcher");
    }
    let (read_end, write_end) = (fds[0], fds[1]);
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(read_end);
            libc::close(write_end);
            libc::close(kill_fd);
            libc::close(freeze_fd);
            libc::close(procs_fd);
            libc::close(events_fd);
        }
        return Err(anyhow!(std::io::Error::last_os_error())).context("fork gate watcher");
    }
    if pid == 0 {
        // Watcher child: raw libc only (no allocation, no panics after fork).
        // Block until the supervisor is gone (graceful byte) or dies (EOF).
        unsafe {
            libc::close(write_end);
            let mut byte = [0u8; 1];
            // 0 (EOF) = the supervisor DIED -> reap the scope. 1 = a graceful-
            // exit byte the WatcherGuard wrote -> the scope is already reaped and
            // removed; release without reaping (reaping a removed scope's stale
            // fds would only fail forever).
            let n = libc::read(read_end, byte.as_mut_ptr() as *mut libc::c_void, 1);
            if n != 1 {
                watcher_reap(
                    kill_fd,
                    freeze_fd,
                    procs_fd,
                    events_fd,
                    WatcherFaults {
                        kill_write_fails,
                        events_read_failures,
                        procs_read_failures,
                        events_populated_for,
                    },
                );
            }
            libc::_exit(0);
        }
    }
    // Supervisor: keep only the write end; the child owns the reaping fds.
    unsafe {
        libc::close(read_end);
        libc::close(kill_fd);
        libc::close(freeze_fd);
        libc::close(procs_fd);
        libc::close(events_fd);
    }
    Ok(Some(WatcherGuard(write_end)))
}

/// Open a cgroup trigger file for writing (best-effort: -1 when absent).
// WO-155@v1: open watcher trigger fds before the post-fork raw-libc path.
fn open_cgroup_writer(path: &Path) -> RawFd {
    use std::os::unix::ffi::OsStrExt;
    let c = match CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) }
}

/// Open a cgroup status file for reading (best-effort: -1 when absent).
// WO-155@v1: open status fds before the watcher forks.
fn open_cgroup_reader(path: &Path) -> RawFd {
    use std::os::unix::ffi::OsStrExt;
    let c = match CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) }
}

/// How long the crash watcher sleeps between reap attempts while it has not yet
/// positively proven the scope is empty. A raw `timespec` so the post-fork body
/// can use it with no allocation.
const WATCHER_RETRY: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 10_000_000, // 10 ms
};

/// The crash watcher's post-fork body. Raw libc only — stack buffers and
/// pread/write/kill/nanosleep — because this process inherited a multithreaded
/// supervisor's memory (no allocation, no locks, no panic paths). It keeps its
/// inherited fanotify fd open until it exits: a permission event held when the
/// supervisor died must stay unanswered (not released as allowed) while the tree
/// is reaped, and that fd only closes on the final `_exit`. It exits ONLY on
/// positive proof the scope is empty; on any doubt it sleeps and retries, so it
/// may stay alive indefinitely — a frozen tree is the fail-closed outcome.
/// WO-155@v1: fault-injection: the injected faults the crash watcher honors,
/// read before fork and passed in by value — the post-fork body takes no env
/// reads, and bundling them keeps the argument list to the four fds.
#[derive(Clone, Copy)]
// WO-155@v1: carry deterministic watcher faults without post-fork environment reads.
struct WatcherFaults {
    kill_write_fails: bool,
    events_read_failures: u32,
    procs_read_failures: u32,
    events_populated_for: u32,
}

// WO-155@v1: hold enforcement until the watcher proves the scope empty.
unsafe fn watcher_reap(
    kill_fd: RawFd,
    freeze_fd: RawFd,
    procs_fd: RawFd,
    events_fd: RawFd,
    mut faults: WatcherFaults,
) {
    // Try the one-shot cgroup.kill. A successful write only QUEUES the SIGKILLs;
    // it does not prove the scope is empty yet, so we still poll cgroup.events
    // below for positive proof. A failed write (kernel refused, or the injected
    // fault) falls through to the freeze + per-pid SIGKILL sweep.
    let mut killed = false;
    if kill_fd >= 0 {
        let one = b"1";
        if faults.kill_write_fails {
            // Injected fault: fall through to the freeze + sweep.
        } else {
            let n = libc::write(kill_fd, one.as_ptr() as *const libc::c_void, 1);
            if n == 1 {
                killed = true;
            } else if scope_removed() {
                // The scope was already removed (the dying supervisor's own
                // teardown emptied and rmdir'd it): provably reaped — exit.
                return;
            }
        }
    }
    if !killed {
        // Freeze so no new member can fork in under the sweep.
        if freeze_fd >= 0 {
            let one = b"1";
            let _ = libc::write(freeze_fd, one.as_ptr() as *const libc::c_void, 1);
        }
    }
    loop {
        // SIGKILL every pid currently listed in cgroup.procs, and record whether
        // the read succeeded (`procs_ok`) and whether the list was empty — a
        // successfully-read empty list is a positive "scope is empty" signal.
        let mut procs_ok = false;
        let mut procs_empty = false;
        if !killed && procs_fd >= 0 {
            let mut buf = [0u8; 8192];
            let mut real = true;
            let n = if faults.procs_read_failures > 0 {
                faults.procs_read_failures -= 1;
                real = false;
                -1
            } else {
                libc::pread(
                    procs_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 && real && scope_removed() {
                return;
            }
            if n > 0 {
                procs_ok = true;
                procs_empty = true;
                let bytes = &buf[..n as usize];
                let mut i = 0;
                while i < bytes.len() {
                    let mut pid: libc::pid_t = 0;
                    let mut digits = false;
                    while i < bytes.len() && bytes[i] != b'\n' {
                        if bytes[i] >= b'0' && bytes[i] <= b'9' {
                            pid = pid
                                .wrapping_mul(10)
                                .wrapping_add((bytes[i] - b'0') as libc::pid_t);
                            digits = true;
                        }
                        i += 1;
                    }
                    while i < bytes.len() && bytes[i] == b'\n' {
                        i += 1;
                    }
                    if digits && pid > 1 {
                        procs_empty = false;
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
        // Exit ONLY on positive proof: cgroup.events read successfully and shows
        // `populated 0`, or (events unreadable) cgroup.procs read successfully and
        // empty. Any read failure — n <= 0, a missing fd, or the injected fault —
        // is never proof of empty: back off and retry.
        let mut events_proves_empty = false;
        if events_fd >= 0 {
            let mut ebuf = [0u8; 128];
            let mut real = true;
            let n = if faults.events_read_failures > 0 {
                faults.events_read_failures -= 1;
                real = false;
                -1
            } else if faults.events_populated_for > 0 {
                // Injected fault: report a still-populated scope for N reads even
                // though the kernel may already be empty — the watcher must stay
                // alive and keep polling, not trust an earlier read.
                real = false;
                faults.events_populated_for -= 1;
                let fake = b"populated 1\n";
                let len = fake.len().min(ebuf.len());
                ebuf[..len].copy_from_slice(&fake[..len]);
                len as isize
            } else {
                libc::pread(
                    events_fd,
                    ebuf.as_mut_ptr() as *mut libc::c_void,
                    ebuf.len(),
                    0,
                )
            };
            if n < 0 && real && scope_removed() {
                return;
            }
            if n > 0 {
                events_proves_empty = populated_zero(&ebuf[..n as usize]);
            }
        }
        if events_proves_empty || (!killed && events_fd < 0 && procs_ok && procs_empty) {
            return;
        }
        libc::nanosleep(&WATCHER_RETRY, std::ptr::null_mut());
    }
}

/// Does `events` contain the literal byte sequence "populated 0"? No allocation.
// WO-155@v1: recognize only positive kernel evidence that the scope is empty.
fn populated_zero(events: &[u8]) -> bool {
    let pat = b"populated 0";
    let mut i = 0;
    while i + pat.len() <= events.len() {
        if &events[i..i + pat.len()] == pat {
            return true;
        }
        i += 1;
    }
    false
}

/// Did the last CGROUP fd op fail because the scope was removed underneath us?
/// A cgroup-v2 directory is removable only while empty, so a removed scope is
/// provably reaped — the watcher may exit instead of re-reading a deleted scope's
/// fds forever. Raw-libc and async-signal-safe (post-fork). Only meaningful
/// right after a real (non-injected) libc descriptor op.
// WO-155@v1: treat a kernel-removed cgroup as proof that no member remains.
unsafe fn scope_removed() -> bool {
    let e = *libc::__errno_location();
    e == libc::ENODEV || e == libc::ENOENT
}

// WO-3@v1: key the Linux permission gate to stable inode identity.
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
// WO-70@v1: pin fail-closed handling for unresolved in-tree event inodes.
mod tests {
    use super::*;

    // WO-188@v1: the encoder can emit only a complete ALLOW or DENY response
    // carrying the event fd the kernel supplied.
    #[test]
    fn fanotify_response_encoder_only_emits_valid_decisions() {
        let allow = FanDecision::Allow.encode(41);
        assert_eq!(allow.fd, 41);
        assert_eq!(allow.response, libc::FAN_ALLOW);
        let deny = FanDecision::Deny.encode(73);
        assert_eq!(deny.fd, 73);
        assert_eq!(deny.response, libc::FAN_DENY);
        assert_eq!(
            std::mem::size_of_val(&allow),
            std::mem::size_of::<libc::fanotify_response>()
        );
    }

    /// B6 negative control: an in-tree open whose inode cannot be resolved must
    /// fail CLOSED. The pre-fix code allowed on stat failure (fail-OPEN); this
    /// asserts the disposition is now DenyUnknownInode, so reverting the fix
    /// turns this red.
    #[test]
    // WO-70@v1: reject an in-tree open whose event inode is unknown.
    fn in_tree_open_with_unresolved_inode_fails_closed() {
        assert_eq!(in_tree_open(false), InTreeOpen::DenyUnknownInode);
    }

    /// Control: an in-tree open with a resolved inode is still judged by the
    /// gate mode (the fail-closed branch does not swallow normal opens).
    #[test]
    // WO-70@v1: continue normal policy evaluation when the inode resolves.
    fn in_tree_open_with_resolved_inode_is_judged() {
        assert_eq!(in_tree_open(true), InTreeOpen::Judge);
    }
}
