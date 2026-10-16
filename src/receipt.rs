//! Per-decision receipts.
//!
//! Every gate decision is logged: time, pid, ancestry, dev+inode, decision,
//! and the path observed at the moment of the open. Written as JSON lines so
//! the log is greppable and append-only. Receipts never contain file content.
//!
//! JSON is hand-rolled (one flat object, known fields) to keep the dependency
//! surface minimal for a security-layer binary.

use std::ffi::CString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, sync_channel, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        }
    }
}

/// One audit record for a single gated open().
pub struct Receipt<'a> {
    pub pid: i32,
    pub dev: u64,
    pub ino: u64,
    pub decision: Decision,
    pub path: &'a str,
    pub ancestry: &'a str,
    pub reason: &'a str,
    /// How the decision was reached (operator/cache/timeout/static), or "" when
    /// not applicable (e.g. a plain allow of an unprotected file).
    pub source: &'a str,
}

/// Escape a string for embedding in a JSON double-quoted value.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn now_unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

impl Receipt<'_> {
    /// Serialize to a single JSON line (no trailing newline).
    pub fn to_json_line(&self) -> String {
        format!(
            r#"{{"ts_ms":{ts},"pid":{pid},"dev":{dev},"ino":{ino},"decision":"{dec}","source":"{src}","path":"{path}","ancestry":"{anc}","reason":"{reason}"}}"#,
            ts = now_unix_millis(),
            pid = self.pid,
            dev = self.dev,
            ino = self.ino,
            dec = self.decision.as_str(),
            src = json_escape(self.source),
            path = json_escape(self.path),
            anc = json_escape(self.ancestry),
            reason = json_escape(self.reason),
        )
    }
}

/// WO-29: one record for a dispatch-time hivebus key handoff. A DIFFERENT shape
/// and lifecycle from the per-open `Receipt` above — it records WHAT key material
/// was placed on a remote at dispatch, by FINGERPRINT only. It MUST NEVER carry
/// seed bytes (the worker's private key); a test asserts this.
pub struct DispatchReceipt<'a> {
    pub target: &'a str,
    /// sha256-hex fingerprint of the worker public key placed on the remote.
    pub worker_pub_fingerprint: Option<&'a str>,
    /// sha256-hex fingerprint of the architect public key relayed to the remote.
    pub architect_pub_fingerprint: Option<&'a str>,
    /// WO-50: the uid the remote agent was dropped to (auto-picked or explicit).
    /// Recorded here so the chosen uid is auditable independent of the remote run
    /// dir (which is removed on exit). `None` when the agent was not dropped.
    pub worker_uid: Option<u32>,
}

impl DispatchReceipt<'_> {
    /// Serialize to a single JSON line (no trailing newline). Fingerprints only.
    pub fn to_json_line(&self) -> String {
        let fp = |o: Option<&str>| match o {
            Some(s) => format!("\"{}\"", json_escape(s)),
            None => "null".to_string(),
        };
        let uid = match self.worker_uid {
            Some(u) => u.to_string(),
            None => "null".to_string(),
        };
        format!(
            r#"{{"ts_ms":{ts},"kind":"hivebus_dispatch","target":"{target}","worker_pub_fingerprint":{wfp},"architect_pub_fingerprint":{afp},"worker_uid":{uid}}}"#,
            ts = now_unix_millis(),
            target = json_escape(self.target),
            wfp = fp(self.worker_pub_fingerprint),
            afp = fp(self.architect_pub_fingerprint),
            uid = uid,
        )
    }
}

/// WO-154@v1: capacity of each per-decision log queue. The permission loop
/// can enqueue up to this many records while a writer thread is slow; past that
/// it drops and counts for that sink instead of blocking.
const LOG_QUEUE_CAPACITY: usize = 4096;

/// Per-sink counters so `submitted == written + dropped` holds for EACH sink,
/// and a stalled consumer loses nothing silently (a lost line is always counted).
// WO-154@v1: account for every off-loop receipt enqueue without blocking opens.
// WO-155@v1: expose output loss when a terminal or file sink stalls.
#[derive(Default)]
struct SinkCounters {
    submitted: AtomicU64,
    written: AtomicU64,
    dropped: AtomicU64,
}

/// WO-154@v1: a message to the receipts-file writer. `Line` is one
/// decision record; `Summary` is the final accounting line — formed by the
/// writer itself against the then-drained counters, so it is always the LAST
/// line and its file numbers balance exactly.
// WO-154@v1: separate ordinary receipt records from the terminal accounting message.
// WO-155@v1: make the writer close the audit stream with bounded accounting.
enum FileMsg {
    Line(String),
    Summary,
}

/// WO-154@v1: a non-blocking, cloneable handle into BOTH log sinks —
/// the receipts file (JSON, when configured) and stderr (human lines). The
/// permission loop, and any helper threads (e.g. a consent worker), enqueue
/// owned records and return immediately; two separate writer threads perform
/// the actual `write(2)`, so a stalled stderr reader can never delay the
/// receipts file (and vice versa). Cloning shares both queues and all counters.
// WO-154@v1: enqueue gate output without blocking the permission loop.
// WO-155@v1: isolate file and terminal sinks so either may stall independently.
pub struct LogSink {
    file_tx: SyncSender<FileMsg>,
    stderr_tx: SyncSender<String>,
    file_counters: Arc<SinkCounters>,
    stderr_counters: Arc<SinkCounters>,
}

// WO-154@v1: share bounded output queues with helper threads.
// WO-155@v1: preserve per-sink accounting across cloned handles.
impl Clone for LogSink {
    // WO-154@v1: clone senders rather than writer handles for off-loop output.
    // WO-155@v1: share counters across every producer of gate output.
    fn clone(&self) -> Self {
        LogSink {
            file_tx: self.file_tx.clone(),
            stderr_tx: self.stderr_tx.clone(),
            file_counters: Arc::clone(&self.file_counters),
            stderr_counters: Arc::clone(&self.stderr_counters),
        }
    }
}

/// Build the human stderr line for a decision receipt.
// WO-155@v1: format human output before it reaches the terminal writer.
fn human_decision_line(decision: Decision, r: &Receipt) -> String {
    format!(
        "[bulwark] {} pid={} dev={} ino={} path={} ancestry={}\n",
        decision.as_str(),
        r.pid,
        r.dev,
        r.ino,
        r.path,
        r.ancestry
    )
}

/// Route one record to both sinks. `human` is the stderr line; `json` is the
/// receipts-file line (absent for warn/note diagnostics, which have no receipt).
/// A failed enqueue (queue full or a gone writer) is counted as dropped for that
/// sink immediately, so `submitted == written + dropped` stays exact.
// WO-154@v1: route each record through bounded queues outside the permission loop.
// WO-155@v1: count sink loss instead of waiting on blocked output.
fn route(
    file_tx: &SyncSender<FileMsg>,
    stderr_tx: &SyncSender<String>,
    file_counters: &SinkCounters,
    stderr_counters: &SinkCounters,
    human: String,
    json: Option<String>,
) {
    stderr_counters.submitted.fetch_add(1, Ordering::SeqCst);
    match stderr_tx.try_send(human) {
        Ok(()) => {}
        Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => {
            stderr_counters.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    if let Some(json) = json {
        file_counters.submitted.fetch_add(1, Ordering::SeqCst);
        match file_tx.try_send(FileMsg::Line(json)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => {
                file_counters.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

// WO-154@v1: expose nonblocking output operations to gate helper threads.
// WO-155@v1: keep file and terminal accounting independent.
impl LogSink {
    /// Record one decision. Enqueued to both sinks, never written synchronously.
    // WO-154@v1: enqueue decisions without delaying permission responses.
    // WO-155@v1: send each decision to independently bounded sinks.
    pub fn record(&self, r: &Receipt) {
        route(
            &self.file_tx,
            &self.stderr_tx,
            &self.file_counters,
            &self.stderr_counters,
            human_decision_line(r.decision, r),
            Some(r.to_json_line()),
        );
    }

    /// Queue a warning line (no file receipt). The gate's own error paths use
    /// this so their stderr output cannot block the permission loop either.
    // WO-154@v1: keep gate warnings off the permission loop.
    // WO-155@v1: drop and count warnings when terminal output stalls.
    pub fn warn(&self, line: &str) {
        route(
            &self.file_tx,
            &self.stderr_tx,
            &self.file_counters,
            &self.stderr_counters,
            format!("[bulwark] WARN {line}\n"),
            None,
        );
    }
}

/// Sink for receipts: a JSON file sink plus a stderr sink, each with its own
/// bounded in-memory queue and a writer thread that OWNS its handle (the file
/// writer owns the receipts `File`; no shared lock, no shared handle).
///
/// WO-154@v1: the permission loop must never block on output, and the
/// receipts FILE must never wait on stderr. Two independent queues/writers
/// provide both: `record` enqueues to each and returns immediately, each writer
/// drains its own queue, and when a queue is full that record is dropped and
/// counted for that sink. On teardown the summary is enqueued as each writer's
/// LAST message and Drop waits only a bounded time before returning regardless.
// WO-154@v1: own the bounded writers that keep output off the permission loop.
// WO-155@v1: bound sink teardown and account for every dropped line.
pub struct ReceiptLog {
    file_tx: Option<SyncSender<FileMsg>>,
    stderr_tx: Option<SyncSender<String>>,
    file_counters: Arc<SinkCounters>,
    stderr_counters: Arc<SinkCounters>,
    file_writer: Option<JoinHandle<()>>,
    stderr_writer: Option<JoinHandle<()>>,
}

/// Open a receipts file by a component-wise `openat` walk that refuses to follow
/// a symlinked ancestor unless it is a trusted root-owned system link (macOS
/// `/tmp` → `/private/tmp`, `/var` → `/private/var`). This stops an untrusted
/// workspace from redirecting root's receipts create/append to an arbitrary
/// directory via an intermediate symlink (WO-156).
// WO-156@v2: pin every receipts-path component and refuse unsafe aliases.
fn open_receipts_file(path: &Path) -> Result<std::fs::File> {
    // A relative path is walked from the process's REAL cwd, opened once as a
    // directory fd (".", O_DIRECTORY|O_CLOEXEC) so the walk is pinned to the cwd
    // inode — never a path string built from current_dir(). A rename of a cwd
    // ancestor after such a snapshot would redirect root's receipts to the
    // replacement directory; the fd pins the real cwd. An absolute path is
    // walked from "/". Every component is then opened relative to the pinned
    // parent (TOCTOU-safe) and O_NOFOLLOW refuses a symlink.
    let mut dirfd: libc::c_int = {
        let base: &[u8] = if path.is_absolute() { b"/" } else { b"." };
        let cs = CString::new(base)?;
        let fd = unsafe {
            libc::open(
                cs.as_ptr(),
                libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(anyhow!(
                "cannot open {} to walk the receipts path",
                if path.is_absolute() {
                    "/"
                } else {
                    "the current directory"
                }
            ));
        }
        fd
    };

    let comps: Vec<Vec<u8>> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(os) => Some(os.as_bytes().to_vec()),
            std::path::Component::ParentDir => Some(b"..".to_vec()),
            std::path::Component::RootDir | std::path::Component::CurDir => None,
            std::path::Component::Prefix(_) => None,
        })
        .collect();

    if comps.is_empty() {
        unsafe { libc::close(dirfd) };
        return Err(anyhow!(
            "receipts path is not a regular file: {}",
            path.display()
        ));
    }

    let last = comps.len() - 1;
    for (i, comp) in comps.iter().enumerate() {
        let c = CString::new(comp.as_slice())?;
        if i == last {
            // Final component: the file itself, never a symlink, non-blocking so a
            // FIFO/device cannot hang the open, created 0600, then fstat S_ISREG +
            // ownership checks. A hardlinked file (nlink != 1) or one owned by a
            // different uid skips O_NOFOLLOW and would let a planted file in a
            // writable dir be appended under its OWNER's identity — refuse both.
            let fd = unsafe {
                libc::openat(
                    dirfd,
                    c.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | libc::O_CREAT
                        | libc::O_APPEND
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                unsafe { libc::close(dirfd) };
                return Err(anyhow!(std::io::Error::last_os_error()))
                    .with_context(|| format!("cannot open receipts file {}", path.display()));
            }
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let meta = match file.metadata() {
                Ok(m) => m,
                Err(e) => {
                    unsafe { libc::close(dirfd) };
                    return Err(anyhow!(e).context("stat the opened receipts file"));
                }
            };
            if !meta.is_file() {
                unsafe { libc::close(dirfd) };
                return Err(anyhow!(
                    "receipts path is not a regular file: {}",
                    path.display()
                ));
            }
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() != 1 {
                unsafe { libc::close(dirfd) };
                return Err(anyhow!(
                    "receipts file {} has {} hard links; refusing (a hardlinked \
                     file can be appended through another name)",
                    path.display(),
                    meta.nlink()
                ));
            }
            let euid = unsafe { libc::geteuid() };
            if meta.uid() != euid {
                unsafe { libc::close(dirfd) };
                return Err(anyhow!(
                    "receipts file {} is owned by uid {}, not the effective uid {}; refusing",
                    path.display(),
                    meta.uid(),
                    euid
                ));
            }
            unsafe { libc::close(dirfd) };
            return Ok(file);
        }
        // Directory component: refuse a symlink unless it is a trusted root-owned
        // system link. Decide by lstat first (portable across Linux/macOS errnos),
        // then openat the pinned parent.
        let mut lst: libc::stat = unsafe { std::mem::zeroed() };
        let is_symlink = unsafe {
            libc::fstatat(dirfd, c.as_ptr(), &mut lst, libc::AT_SYMLINK_NOFOLLOW) == 0
                && lst.st_mode & libc::S_IFMT == libc::S_IFLNK
        };
        if is_symlink {
            if !system_symlink_ok_stat(dirfd, &lst)? {
                unsafe { libc::close(dirfd) };
                return Err(anyhow!(
                    "receipts path component {} must not be a symlink: {}",
                    String::from_utf8_lossy(comp),
                    path.display()
                ));
            }
            let followed =
                unsafe { libc::openat(dirfd, c.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
            if followed < 0 {
                unsafe { libc::close(dirfd) };
                return Err(anyhow!(std::io::Error::last_os_error())).with_context(|| {
                    format!(
                        "symlinked receipts component {} does not resolve to a directory",
                        String::from_utf8_lossy(comp)
                    )
                });
            }
            unsafe { libc::close(dirfd) };
            dirfd = followed;
            continue;
        }
        let next = unsafe {
            libc::openat(
                dirfd,
                c.as_ptr(),
                libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            unsafe { libc::close(dirfd) };
            return Err(anyhow!(std::io::Error::last_os_error())).with_context(|| {
                format!(
                    "receipts path component {} is not a directory",
                    String::from_utf8_lossy(comp)
                )
            });
        }
        unsafe { libc::close(dirfd) };
        dirfd = next;
    }
    unreachable!()
}

/// A symlinked directory component may be FOLLOWED only when the link itself is
/// root-owned and sits in a root-owned directory that is not group/other-writable
/// (the macOS `/tmp` → `/private/tmp` and `/var` → `/private/var` system links).
// WO-156@v2: allow only immutable system-owned links in the receipts path.
fn system_symlink_ok_stat(dirfd: libc::c_int, lst: &libc::stat) -> Result<bool> {
    let link_root = lst.st_uid == 0;
    let mut dst: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dirfd, &mut dst) } != 0 {
        return Ok(false);
    }
    let dir_root = dst.st_uid == 0;
    let dir_not_writable = dst.st_mode & 0o022 == 0;
    Ok(link_root && dir_root && dir_not_writable)
}

// WO-154@v1: construct and expose bounded off-loop receipt writers.
// WO-155@v1: own bounded writer shutdown and final accounting.
// WO-156@v2: open the receipts file through pinned directory descriptors.
impl ReceiptLog {
    // WO-154@v1: start independent file and terminal writer threads.
    // WO-155@v1: fail if either writer cannot be created.
    // WO-156@v2: validate the receipts target before gate enforcement starts.
    pub fn new(path: Option<&Path>) -> Result<Self> {
        // The receipts file is opened here — before the permission loop — by the
        // component-wise walk, so the loop itself never opens a path.
        let file = match path {
            Some(p) => Some(open_receipts_file(p)?),
            None => None,
        };

        // Two independent queues, so a stalled stderr never delays the file.
        let (file_tx, file_rx) = sync_channel::<FileMsg>(LOG_QUEUE_CAPACITY);
        let (stderr_tx, stderr_rx) = sync_channel::<String>(LOG_QUEUE_CAPACITY);
        let file_counters = Arc::new(SinkCounters::default());
        let stderr_counters = Arc::new(SinkCounters::default());

        // A writer that cannot start means every receipt would be silently lost,
        // so it is fatal rather than a quiet degrade. The file writer OWNS the
        // receipts file handle (moved in) and both counter sets (so it forms the
        // summary itself); the stderr writer owns only the human-line queue.
        let fc = Arc::clone(&file_counters);
        let sc_for_file = Arc::clone(&stderr_counters);
        // WO-155@v1: the file writer holds a stderr sender so a failed final
        // summary write is reported through the same bounded stderr path, never
        // a direct write (and never a new sink).
        let stderr_tx_for_file = stderr_tx.clone();
        let file_writer = std::thread::Builder::new()
            .name("bulwark-log-file".into())
            .spawn(move || {
                file_writer_loop(file_rx, file, fc, sc_for_file, Some(stderr_tx_for_file))
            })
            .context("cannot spawn the receipt file writer thread")?;
        let sc = Arc::clone(&stderr_counters);
        let stderr_writer = std::thread::Builder::new()
            .name("bulwark-log-stderr".into())
            .spawn(move || stderr_writer_loop(stderr_rx, sc))
            .context("cannot spawn the receipt stderr writer thread")?;

        Ok(ReceiptLog {
            file_tx: Some(file_tx),
            stderr_tx: Some(stderr_tx),
            file_counters,
            stderr_counters,
            file_writer: Some(file_writer),
            stderr_writer: Some(stderr_writer),
        })
    }

    /// A shared, cloneable handle to both queues, for helper threads (e.g. the
    /// consent worker) that log on the gate's behalf. The clone's senders are
    /// dropped when that thread ends, so each writer sees channel-close only
    /// once the gate AND its helper threads are done.
    // WO-154@v1: give helper threads bounded access to both output queues.
    // WO-155@v1: keep all producers inside shared sink accounting.
    pub fn sink(&self) -> LogSink {
        LogSink {
            file_tx: self.file_tx.as_ref().expect("file sender present").clone(),
            stderr_tx: self
                .stderr_tx
                .as_ref()
                .expect("stderr sender present")
                .clone(),
            file_counters: Arc::clone(&self.file_counters),
            stderr_counters: Arc::clone(&self.stderr_counters),
        }
    }

    /// Record one decision. Enqueued to both sinks, never written synchronously.
    // WO-154@v1: enqueue gate decisions outside the permission loop.
    // WO-155@v1: account for each file and terminal delivery independently.
    pub fn record(&mut self, r: &Receipt) {
        self.route(Some(r.to_json_line()), human_decision_line(r.decision, r));
    }

    /// Record one dispatch-time hivebus key handoff (fingerprints only — never
    /// seed bytes). Enqueued like any other line.
    // WO-29@v1: record key-handoff fingerprints without persisting seed material.
    // WO-154@v1: enqueue dispatch receipts through the bounded output path.
    pub fn record_dispatch(&mut self, r: &DispatchReceipt) {
        let human = format!(
            "[bulwark] hivebus dispatch target={} worker_fp={} architect_fp={}\n",
            r.target,
            r.worker_pub_fingerprint.unwrap_or("-"),
            r.architect_pub_fingerprint.unwrap_or("-"),
        );
        self.route(Some(r.to_json_line()), human);
    }

    /// Queue a warning line (no file receipt). The gate's own error paths use
    /// this so their stderr output cannot block the permission loop either.
    // WO-154@v1: keep warning output away from the permission loop.
    // WO-155@v1: count warnings dropped by a stalled terminal sink.
    pub fn warn(&mut self, line: &str) {
        self.route(None, format!("[bulwark] WARN {line}\n"));
    }

    /// Queue a plain informational line (no file receipt). Used for the loop's
    /// own status messages, which must also never block on output.
    // WO-154@v1: enqueue gate status without delaying permission responses.
    // WO-155@v1: bound informational output when the terminal stalls.
    pub fn note(&mut self, line: &str) {
        self.route(None, format!("[bulwark] {line}\n"));
    }

    // WO-154@v1: funnel gate output through the bounded queue pair.
    // WO-155@v1: preserve independent accounting for both sinks.
    fn route(&self, json: Option<String>, human: String) {
        route(
            self.file_tx.as_ref().expect("file sender present"),
            self.stderr_tx.as_ref().expect("stderr sender present"),
            &self.file_counters,
            &self.stderr_counters,
            human,
            json,
        );
    }
}

// WO-155@v1: finish receipt accounting without letting a sink hold gate exit.
impl Drop for ReceiptLog {
    // WO-155@v1: bound file drain time and detach best-effort terminal output.
    fn drop(&mut self) {
        // Enqueue the summary as the file writer's LAST message, then drop our
        // senders so each writer drains exactly its queued messages and sees
        // channel-close. Wait only a bounded time for the FILE writer (it writes
        // the summary as its last line); the stderr writer is abandoned without
        // waiting — stderr is best-effort human output, never the audit trail.
        if let Some(tx) = self.file_tx.take() {
            if tx.try_send(FileMsg::Summary).is_err() {
                // The summary is the audit trail's closing record: losing it to a
                // full queue must be loud and counted, even when the writer later
                // drains in time. Warn via the bounded stderr path (never a
                // direct write, never blocking) so teardown stays bounded.
                stderr_warn(
                    &self.stderr_tx,
                    &self.stderr_counters,
                    "summary skipped: queue full",
                );
            }
        }
        let file_finished = wait_bounded(&mut self.file_writer);
        if !file_finished {
            stderr_warn(
                &self.stderr_tx,
                &self.stderr_counters,
                "summary skipped: sink blocked",
            );
        }
        self.stderr_tx.take();
        // Detach, don't join: channel-close ends the stderr writer, and a blocked
        // stderr sink must not delay the gate's teardown (stderr is best-effort).
        drop(self.stderr_writer.take());
    }
}

/// How long Drop waits for a writer thread to drain its queue (and write the
/// summary) before giving up. The gate's exit — and the integrity-state write —
/// must never wait on a sink.
const WRITER_DRAIN_WAIT: Duration = Duration::from_millis(2000);

/// Wait up to `WRITER_DRAIN_WAIT` for a writer thread to finish. Returns true if
/// it joined within the bound; false if it was abandoned (still running — the
/// handle is dropped, detaching the thread) so the gate's exit never waits.
// WO-155@v1: cap how long receipt shutdown may wait for the file writer.
fn wait_bounded(writer: &mut Option<JoinHandle<()>>) -> bool {
    let Some(w) = writer.take() else {
        return true;
    };
    let deadline = Instant::now() + WRITER_DRAIN_WAIT;
    while !w.is_finished() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = w.join();
    true
}

/// Enqueue a teardown line to the stderr sink (`try_send`; dropped and counted
/// when full or gone). Teardown never blocks on stderr and never writes directly.
// WO-155@v1: report teardown loss without writing synchronously to stderr.
fn stderr_warn(tx: &Option<SyncSender<String>>, counters: &SinkCounters, line: &str) {
    let Some(tx) = tx else { return };
    let msg = format!("[bulwark] WARN {line}\n");
    counters.submitted.fetch_add(1, Ordering::SeqCst);
    match tx.try_send(msg) {
        Ok(()) => {}
        Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => {
            counters.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Form the accounting summary line. Read by the file writer at the `Summary`
/// message, after it has drained every record, so the file counters balance
/// exactly. The stderr state is a snapshot: `finished` when it balances at this
/// instant, `timed_out` when it is still draining (or was abandoned).
// WO-155@v1: close the receipt file with per-sink delivery accounting.
fn summary_json(file_counters: &SinkCounters, stderr_counters: &SinkCounters) -> String {
    let (fs, fw, fd) = (
        file_counters.submitted.load(Ordering::SeqCst),
        file_counters.written.load(Ordering::SeqCst),
        file_counters.dropped.load(Ordering::SeqCst),
    );
    let (ss, sw, sd) = (
        stderr_counters.submitted.load(Ordering::SeqCst),
        stderr_counters.written.load(Ordering::SeqCst),
        stderr_counters.dropped.load(Ordering::SeqCst),
    );
    let stderr_state = if ss == sw + sd {
        "finished"
    } else {
        "timed_out"
    };
    format!(
        r#"{{"ts_ms":{},"kind":"summary","file":{{"state":"finished","submitted":{fs},"written":{fw},"dropped":{fd}}},"stderr":{{"state":"{}","submitted":{ss},"written":{sw},"dropped":{sd}}}}}"#,
        now_unix_millis(),
        stderr_state,
    )
}

/// The receipts-file writer thread. It OWNS the receipts file handle (moved in)
/// and both counter sets. It drains the queue in order, writing each record;
/// when it reaches the `Summary` message (always last) it forms the accounting
/// summary from the then-drained counters and writes it, so its numbers balance
/// and it is the last line. It never blocks on stderr — a failed summary write is
/// reported through the bounded stderr queue (`try_send`, never a direct write) —
/// so a stopped terminal still cannot delay the audit trail.
// WO-154@v1: drain receipt records outside the permission loop.
// WO-155@v1: write the final accounting record and report sink failures safely.
fn file_writer_loop(
    rx: mpsc::Receiver<FileMsg>,
    mut file: Option<std::fs::File>,
    file_counters: Arc<SinkCounters>,
    stderr_counters: Arc<SinkCounters>,
    stderr_tx: Option<SyncSender<String>>,
) {
    #[cfg(feature = "fault-injection")]
    let block_forever = std::env::var_os("BULWARK_TEST_LOG_WRITER_BLOCK").is_some();
    while let Ok(msg) = rx.recv() {
        match msg {
            FileMsg::Line(json) => {
                #[cfg(feature = "fault-injection")]
                if block_forever {
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                match file.as_mut() {
                    Some(f) => {
                        if writeln!(f, "{json}").is_ok() {
                            file_counters.written.fetch_add(1, Ordering::SeqCst);
                        } else {
                            file_counters.dropped.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    None => {
                        // No receipts file was requested: nothing persisted.
                        file_counters.dropped.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            FileMsg::Summary => {
                if let Some(f) = file.as_mut() {
                    // WO-155@v1: the summary is the audit trail's closing record;
                    // a failed final write or flush is warned through the bounded
                    // stderr path and counted, never silent.
                    let wrote = writeln!(f, "{}", summary_json(&file_counters, &stderr_counters))
                        .and_then(|_| f.flush());
                    if let Err(e) = wrote {
                        stderr_warn(
                            &stderr_tx,
                            &stderr_counters,
                            &format!("summary write failed: {e}"),
                        );
                    }
                }
            }
        }
    }
}

/// The stderr writer thread: drains the human-line queue and writes each to
/// stderr. It MAY block on a stopped consumer — deliberately, and only HERE
/// (never the permission loop and never the file writer). Channel close ends it.
// WO-154@v1: confine blocking terminal writes to a dedicated thread.
// WO-155@v1: isolate a stopped terminal from gate enforcement and file receipts.
fn stderr_writer_loop(rx: mpsc::Receiver<String>, counters: Arc<SinkCounters>) {
    while let Ok(human) = rx.recv() {
        if std::io::stderr().write_all(human.as_bytes()).is_ok() {
            counters.written.fetch_add(1, Ordering::SeqCst);
        } else {
            counters.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_line_has_expected_fields() {
        let r = Receipt {
            pid: 42,
            dev: 7,
            ino: 99,
            decision: Decision::Deny,
            path: "/tmp/guard/secret.env",
            ancestry: "cat(42) <- bash(7)",
            reason: "protected inode",
            source: "operator",
        };
        let line = r.to_json_line();
        assert!(line.contains(r#""pid":42"#));
        assert!(line.contains(r#""dev":7"#));
        assert!(line.contains(r#""ino":99"#));
        assert!(line.contains(r#""decision":"deny""#));
        assert!(line.contains(r#""source":"operator""#));
        assert!(line.contains(r#""path":"/tmp/guard/secret.env""#));
        assert!(line.contains(r#""ancestry":"cat(42) <- bash(7)""#));
    }

    #[test]
    fn dispatch_receipt_has_fingerprints_never_seed() {
        // A plausible base64 seed value that MUST NOT leak into a receipt.
        let seed_b64 = "c2VjcmV0LXNlZWQtMzItYnl0ZXMtZG8tbm90LWxvZ2dlZA==";
        let r = DispatchReceipt {
            target: "nullbot@host",
            worker_pub_fingerprint: Some(
                "139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
            ),
            architect_pub_fingerprint: Some("abc123"),
            worker_uid: Some(63000),
        };
        let line = r.to_json_line();
        assert!(line.contains(r#""kind":"hivebus_dispatch""#));
        assert!(line.contains(r#""target":"nullbot@host""#));
        assert!(line.contains("139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070"));
        assert!(line.contains(r#""architect_pub_fingerprint":"abc123""#));
        // WO-50: the chosen worker uid is recorded (the auditable trace).
        assert!(line.contains(r#""worker_uid":63000"#));
        // The seed must never appear anywhere in the serialized record.
        assert!(
            !line.contains(seed_b64),
            "seed bytes must never reach a receipt"
        );
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn dispatch_receipt_null_when_absent() {
        let r = DispatchReceipt {
            target: "h",
            worker_pub_fingerprint: None,
            architect_pub_fingerprint: None,
            worker_uid: None,
        };
        let line = r.to_json_line();
        assert!(line.contains(r#""worker_pub_fingerprint":null"#));
        assert!(line.contains(r#""architect_pub_fingerprint":null"#));
        assert!(line.contains(r#""worker_uid":null"#));
    }

    #[test]
    fn json_escapes_quotes_and_newlines() {
        let r = Receipt {
            pid: 1,
            dev: 0,
            ino: 0,
            decision: Decision::Allow,
            path: "/x/\"weird\"\npath",
            ancestry: "",
            reason: "",
            source: "",
        };
        let line = r.to_json_line();
        assert!(line.contains(r#"\"weird\""#));
        assert!(line.contains("\\n"));
        // The serialized line itself must be single-line.
        assert_eq!(line.lines().count(), 1);
    }

    /// WO-155@v1: in a normal run the summary is the writer's LAST message —
    /// enqueued after every record and formed from the drained counters — so it is
    /// the final line and its file numbers balance exactly. Uses the system temp
    /// dir, which on macOS traverses a system symlink (`/var` → `/private/var`),
    /// so this also exercises the WO-156 component walk's system-link allowance.
    // WO-154@v1: prove normal output drains outside the permission loop.
    // WO-155@v1: prove the accounting record is last and balanced.
    // WO-156@v2: prove the pinned open accepts trusted system links.
    #[test]
    fn normal_run_writes_the_summary_last_and_balances() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-summary-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.jsonl");
        {
            let mut log = ReceiptLog::new(Some(&path)).unwrap();
            for i in 0..10u64 {
                log.record(&Receipt {
                    pid: 1,
                    dev: 0,
                    ino: i,
                    decision: Decision::Allow,
                    path: "/x",
                    ancestry: "",
                    reason: "",
                    source: "",
                });
            }
        }
        let body = std::fs::read_to_string(&path).unwrap();
        let last = body.lines().last().unwrap();
        assert!(
            last.contains(r#""kind":"summary""#),
            "the summary must be the last line; got: {last}"
        );
        // File counters balance exactly: 10 submitted, 10 written, 0 dropped.
        assert!(last.contains(r#""submitted":10"#), "{last}");
        assert!(last.contains(r#""written":10"#), "{last}");
        assert!(last.contains(r#""dropped":0"#), "{last}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// WO-156@v2: a receipts path through a user-made symlinked ancestor is refused
    /// and nothing is created at the link target — the audit trail must not be
    /// redirectable by a workspace directory symlink.
    #[test]
    fn a_symlinked_ancestor_is_refused_and_creates_nothing() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real");
        let alias = dir.join("alias");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        // Running as root (the Linux suite), a root-made symlink would read as a
        // root-owned "system link" and be followed. Make it non-root so the walk
        // sees the user-made (untrusted) symlink this test models — the WO-156
        // scenario is a user workspace redirecting root's receipts append.
        if unsafe { libc::geteuid() } == 0 {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let ca = CString::new(alias.as_os_str().as_bytes()).unwrap();
            unsafe {
                libc::lchown(ca.as_ptr(), 65534, 65534);
            }
        }

        let path = alias.join("r.jsonl");
        let err = ReceiptLog::new(Some(&path))
            .err()
            .expect("a symlinked ancestor must be refused");
        assert!(
            err.to_string().contains("must not be a symlink"),
            "the refusal must name the symlinked component; got: {err}"
        );
        assert!(
            !real.join("r.jsonl").exists(),
            "nothing may be created at the symlink target"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// WO-155@v1: a non-regular receipts path (a FIFO) is refused at startup
    /// rather than adopted as a sink — a FIFO whose reader stops consuming would
    /// block the writer and the gate's exit. The read end is held open (non-
    /// blocking) so the writer-side open succeeds and the fstat S_ISREG check is
    /// what refuses it, deterministically.
    #[test]
    fn a_fifo_receipts_path_is_refused() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!(
            "bulwark-fifo-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.jsonl");
        let st = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo available");
        assert!(st.success(), "mkfifo failed");

        let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
        let rfd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(rfd >= 0, "open FIFO read end failed");

        let err = ReceiptLog::new(Some(&path))
            .err()
            .expect("a FIFO receipts path must be refused");
        assert!(
            err.to_string().contains("not a regular file"),
            "the refusal must name the reason; got: {err}"
        );

        unsafe { libc::close(rfd) };
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// WO-156@v2: a relative receipts path is walked from the process's REAL cwd
    /// (`open(".")`), never a `current_dir()` path string. After a chdir, renaming
    /// the cwd's ancestor away and planting a replacement at the old path must
    /// still land the receipt in the real cwd (the fd pins the cwd inode) and
    /// leave the replacement untouched. The chdir/rename runs in a RE-EXECed child
    /// so the shared parallel harness cwd is never changed (it would race the
    /// cwd-sensitive socket unit test).
    #[test]
    fn a_relative_receipts_path_sticks_to_the_real_cwd_despite_an_ancestor_rename() {
        // Parent: hand the choreography to a child process, shared only through
        // these env vars and the files the child leaves behind.
        if std::env::var_os("BULWARK_TEST_CWD_CHILD").is_none() {
            let tag = format!(
                "bulwark-relcwd-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let base = std::env::temp_dir().join(&tag);
            let moved = std::env::temp_dir().join(format!("{tag}-moved"));
            std::fs::create_dir_all(base.join("sub")).unwrap();

            let exe = std::env::current_exe().expect("the test binary path");
            // libtest names this test `receipt::tests::<fn>` — the module path
            // WITHOUT the crate-name prefix that `module_path!()` adds — so strip
            // the package name before re-execing with `--exact`.
            let test_name = format!(
                "{}::a_relative_receipts_path_sticks_to_the_real_cwd_despite_an_ancestor_rename",
                module_path!()
                    .trim_start_matches(env!("CARGO_PKG_NAME"))
                    .trim_start_matches("::")
            );
            let out = std::process::Command::new(exe)
                .arg("--exact")
                .arg(test_name)
                .arg("--nocapture")
                .env("BULWARK_TEST_CWD_CHILD", "1")
                .env("BULWARK_TEST_CWD_BASE", &base)
                .env("BULWARK_TEST_CWD_MOVED", &moved)
                .output()
                .expect("re-exec the cwd-isolation child");
            assert!(
                out.status.success(),
                "the cwd-isolation child failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
            // The child ran with a cwd inside the (renamed) tree; assert the
            // files it left behind, then clean up from OUTSIDE that tree.
            assert!(
                moved.join("sub").join("r.jsonl").exists(),
                "the receipt must land in the real cwd ({})",
                moved.join("sub").join("r.jsonl").display()
            );
            assert!(
                !base.join("sub").join("r.jsonl").exists(),
                "nothing may appear at the replacement's path"
            );
            std::fs::remove_dir_all(&moved).unwrap();
            std::fs::remove_dir_all(&base).unwrap();
            return;
        }

        // Child: chdir into <base>/sub, rename its ancestor away, plant a
        // replacement at the old path, and open a RELATIVE receipts path — which
        // must follow the pinned cwd fd, not a `current_dir()` string.
        use std::io::Write;
        let base = std::path::PathBuf::from(
            std::env::var_os("BULWARK_TEST_CWD_BASE").expect("child must get the scratch dir"),
        );
        let moved = std::path::PathBuf::from(
            std::env::var_os("BULWARK_TEST_CWD_MOVED").expect("child must get the moved dir"),
        );
        std::env::set_current_dir(base.join("sub")).expect("chdir into the receipts dir");

        std::fs::rename(&base, &moved).unwrap();
        std::fs::create_dir_all(base.join("sub")).unwrap(); // replacement

        {
            let mut f = open_receipts_file(std::path::Path::new("r.jsonl"))
                .expect("a relative receipts path must open in the real cwd");
            writeln!(f, "x").unwrap();
        }
        // The child exits here; the parent asserts the files and cleans up.
    }

    /// WO-156@v2: a receipts file with more than one hard link (nlink != 1) is
    /// refused — a hardlinked inode can be appended through another name, so the
    /// audit trail must not adopt it. The file is left unchanged.
    #[test]
    fn a_hardlinked_receipts_path_is_refused_and_unchanged() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-hardlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.jsonl");
        let b = dir.join("b.jsonl");
        std::fs::write(&a, "ORIGINAL\n").unwrap();
        std::fs::hard_link(&a, &b).unwrap(); // same inode, nlink == 2

        let err = ReceiptLog::new(Some(&b))
            .err()
            .expect("a hardlinked receipts file must be refused");
        assert!(
            err.to_string().contains("hard link"),
            "the refusal must name the hard link; got: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&a).unwrap(),
            "ORIGINAL\n",
            "the hardlinked target must be unchanged"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// WO-155@v1: a Drop whose Summary `try_send` fails (a full file queue) must
    /// warn and count the lost summary through the bounded stderr path, rather
    /// than silently losing the audit trail's closing record.
    #[test]
    fn a_full_file_queue_warns_and_counts_a_lost_summary() {
        // A 1-slot file channel that is already full (and a receiver held open so
        // the channel stays full and connected), plus a stderr channel we read.
        let (file_tx, _file_rx) = sync_channel::<FileMsg>(1);
        let (stderr_tx, stderr_rx) = sync_channel::<String>(1);
        file_tx.try_send(FileMsg::Line("x".into())).unwrap();
        let stderr_dropped = Arc::new(SinkCounters::default());
        let log = ReceiptLog {
            file_tx: Some(file_tx),
            stderr_tx: Some(stderr_tx),
            file_counters: Arc::new(SinkCounters::default()),
            stderr_counters: Arc::clone(&stderr_dropped),
            file_writer: None,   // nothing to join: wait_bounded returns true
            stderr_writer: None, // nothing to detach
        };
        drop(log);

        let msg = stderr_rx
            .try_recv()
            .expect("the queue-full warning must reach stderr");
        assert!(
            msg.contains("summary skipped: queue full"),
            "the lost summary must name the full queue; got: {msg}"
        );
        assert_eq!(
            stderr_dropped.submitted.load(Ordering::SeqCst),
            1,
            "the lost summary must be counted"
        );
        assert_eq!(
            stderr_dropped.dropped.load(Ordering::SeqCst),
            0,
            "the warning enqueued (not dropped)"
        );
    }

    /// WO-155@v1: a summary whose final write FAILS (a read-only receipts handle)
    /// must warn through the bounded stderr path and be counted, rather than be
    /// silently absent from the audit trail.
    #[test]
    fn a_read_only_receipts_handle_warns_and_counts_a_failed_summary() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-rosum-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ro.jsonl");
        std::fs::write(&path, "").unwrap();
        let file = std::fs::OpenOptions::new().read(true).open(&path).unwrap();

        // The real gate's per-sink writers: spawn the FILE writer over the
        // read-only handle with a stderr sender it can warn through.
        let (file_tx, file_rx) = sync_channel::<FileMsg>(1);
        let (stderr_tx, stderr_rx) = sync_channel::<String>(1);
        let file_counters = Arc::new(SinkCounters::default());
        let stderr_counters = Arc::new(SinkCounters::default());
        let writer = std::thread::spawn({
            let fc = Arc::clone(&file_counters);
            let sfc = Arc::clone(&stderr_counters);
            let stx = stderr_tx.clone();
            move || file_writer_loop(file_rx, Some(file), fc, sfc, Some(stx))
        });

        let log = ReceiptLog {
            file_tx: Some(file_tx),
            stderr_tx: Some(stderr_tx),
            file_counters,
            stderr_counters: Arc::clone(&stderr_counters),
            file_writer: Some(writer),
            stderr_writer: None,
        };
        drop(log);

        let msg = stderr_rx
            .try_recv()
            .expect("the failed-summary warning must reach stderr");
        assert!(
            msg.contains("summary write failed"),
            "the failed summary must name the write; got: {msg}"
        );
        assert_eq!(
            stderr_counters.submitted.load(Ordering::SeqCst),
            1,
            "the failed summary must be counted"
        );
        assert_eq!(
            stderr_counters.dropped.load(Ordering::SeqCst),
            0,
            "the warning enqueued (not dropped)"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
