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
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use crate::consent::{ConsentProvider, ConsentRequest, Source, Verdict};
use crate::proctree;

const ANCESTRY_MAX_DEPTH: usize = 16;

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

/// macOS preserves off-band consent with `LOCAL_PEERPID`.
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

/// If running under sudo, chown `path` to the invoking user (`SUDO_UID`/
/// `SUDO_GID`) so the operator's `bulwark consent` can connect to the socket
/// the root-owned gate created. No-op when not under sudo or on parse failure.
fn chown_to_invoking_user(path: &Path) {
    let (uid, gid) = match (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        (Ok(u), Ok(g)) => match (u.parse::<u32>(), g.parse::<u32>()) {
            (Ok(u), Ok(g)) => (u, g),
            _ => return,
        },
        _ => return,
    };
    let cpath = match CString::new(path.as_os_str().to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let rc = unsafe { libc::chown(cpath.as_ptr(), uid, gid) };
    if rc != 0 {
        eprintln!(
            "[bulwark] warning: could not chown consent socket to uid {uid}: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// The supervisor side: owns the listening socket and answers gate requests by
/// talking to whichever operator client connects.
pub struct SocketProvider {
    listener: UnixListener,
    path: PathBuf,
    supervised_root: i32,
    timeout: Duration,
    /// The supervised tree's cgroup scope (relative path), set by `bind_scope`
    /// once the gate creates the scope. When present (Linux with cgroup-v2), a
    /// peer in this scope is refused as an answerer — reparent-proof, so a
    /// double-fork()'d orphan that sheds its ancestry still cannot self-answer.
    /// `None` falls back to the ancestry check alone (macOS, or a v1 host).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    scope_rel: Option<String>,
}

impl SocketProvider {
    /// Bind the consent socket at `path`, rejecting requests not answered
    /// within `timeout`. `supervised_root` is the agent tree's root pid; peers
    /// in that tree are refused as answerers.
    pub fn bind(path: &Path, supervised_root: i32, timeout: Duration) -> Result<Self> {
        // Remove a stale socket file from a previous run, if any.
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        // Tighten the umask so the socket is created 0600 (owner-only). The
        // off-band guarantee rests on peer-PID tree-rejection, not on the
        // perms, but 0600 is defense-in-depth against other local users.
        let old_umask = unsafe { libc::umask(0o177) };
        let listener = UnixListener::bind(path)
            .with_context(|| format!("cannot bind consent socket {}", path.display()));
        unsafe {
            libc::umask(old_umask);
        }
        let listener = listener?;

        // The gate runs as root (fanotify needs CAP_SYS_ADMIN), but the operator
        // answers as their normal user. When launched via sudo, hand ownership
        // of the socket to the invoking user so `bulwark consent` can connect —
        // otherwise a root-owned 0600 socket locks out the very operator it is
        // meant for. Peer-PID checks still enforce the off-band rule regardless of
        // ownership: a peer in the supervised tree is refused.
        chown_to_invoking_user(path);

        // Non-blocking accept so we can enforce the deadline via poll.
        listener
            .set_nonblocking(true)
            .context("set_nonblocking on consent socket")?;
        Ok(SocketProvider {
            listener,
            path: path.to_path_buf(),
            supervised_root,
            timeout,
            scope_rel: None,
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

    /// Wait up to the deadline for an operator client to connect, refusing any
    /// peer inside the supervised tree.
    fn accept_operator(&self) -> Result<Option<UnixStream>> {
        let deadline = std::time::Instant::now() + self.timeout;
        let lfd = self.listener.as_raw_fd();
        loop {
            // Fail closed on graceful shutdown: if a termination signal arrived
            // while we were waiting for the operator, abandon the wait and deny
            // (the poll cap below bounds how long until we notice).
            if crate::gate::shutdown_requested() {
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
                            eprintln!(
                                "[bulwark] refused consent connection with unidentifiable peer \
                                 (no SO_PEERCRED); cannot prove it is off-band"
                            );
                            continue;
                        }
                        Some(pid) if !Self::peer_is_live(pid) => {
                            eprintln!(
                                "[bulwark] refused consent connection from pid {pid} that is no \
                                 longer observable (cannot attribute; a supervised child may not \
                                 answer its own consent by exiting before the check)"
                            );
                            continue;
                        }
                        Some(pid) if self.peer_in_tree(pid) => {
                            eprintln!(
                                "[bulwark] refused consent connection from supervised pid {pid} \
                                 (agent may not answer its own consent)"
                            );
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
        let _ = std::fs::remove_file(&self.path);
    }
}

impl ConsentProvider for SocketProvider {
    fn bind_scope(&mut self, scope_rel: Option<&str>) {
        self.scope_rel = scope_rel.map(|s| s.to_string());
    }

    fn request(&mut self, req: &ConsentRequest) -> (Verdict, Source) {
        let stream = match self.accept_operator() {
            Ok(Some(s)) => s,
            Ok(None) => return (Verdict::Deny, Source::Timeout),
            Err(e) => {
                eprintln!("[bulwark] consent socket error: {e}; denying");
                return (Verdict::Deny, Source::Timeout);
            }
        };
        // The accepted stream inherits the listener's non-blocking mode; switch
        // it back to blocking so read/write use the timeouts below rather than
        // returning WouldBlock immediately (which would look like a reset to the
        // operator).
        if stream.set_nonblocking(false).is_err() {
            return (Verdict::Deny, Source::Timeout);
        }
        // Read/write with a per-connection deadline derived from the same budget.
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        let mut stream = stream;
        if stream.write_all(encode_request(req).as_bytes()).is_err() {
            return (Verdict::Deny, Source::Timeout);
        }
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => (Verdict::Deny, Source::Timeout),
            Ok(_) => match Verdict::parse(&line) {
                Some(v) => (v, Source::Operator),
                None => (Verdict::Deny, Source::Operator),
            },
        }
    }
}

/// Operator-client side of `bulwark consent`: connect to the socket, print the
/// request, and send the operator's verdict. One-shot (answers a single
/// pending request). Returns the verdict string sent.
pub fn answer_once(socket: &Path, verdict: Option<Verdict>) -> Result<String> {
    // Retry the connect briefly: the operator may invoke `bulwark consent` a
    // moment before the supervised tree triggers a protected open (so the
    // supervisor is not yet accepting), or just after binding. A short backoff
    // makes the client robust instead of failing the race.
    let stream = connect_with_retry(socket, Duration::from_secs(5))?;
    let mut writer = stream.try_clone().context("clone consent stream")?;
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("read consent request")?;
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
}
