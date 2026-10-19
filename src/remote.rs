//! Remote enforcement: the decision/prompt split for Bulwark over SSH.
//!
//! When an agent runs on a remote host, the `open()` happens on the *remote*
//! kernel — so enforcement must run there. SSH is only transport. But the
//! consent round-trip now crosses the network and human thinking-time, while
//! `FAN_OPEN_PERM` has a kernel response deadline: you cannot hold a remote
//! `open()` paused while a local human deliberates.
//!
//! The resolution (the load-bearing design): **split the decision from the
//! prompt.**
//!
//! - The remote gate answers the kernel *immediately* from a session cache. If
//!   the inode is not cached-allowed, it DENIES at once — the agent gets EPERM
//!   and never hangs past the deadline.
//! - In parallel it emits an async *prompt* to the local operator (host, path,
//!   process ancestry) over a control stream the agent cannot see. The operator
//!   answers `allow-session`, which updates the cache for NEXT time.
//!
//! So the first touch of a protected file is an immediate deny plus an async
//! prompt; once the operator grants `allow-session`, subsequent opens of that
//! inode pass from cache with no network round-trip. This is the same
//! default-deny-on-timeout discipline used elsewhere, applied across the wire.
//!
//! ## Two control lanes, not terminal chatter (prototype-grade)
//!
//! Prompts and verdicts are separate structured control messages, never mixed
//! with the agent's own stdio. A v0 implementation may multiplex both over the
//! same SSH session, but the code treats them as a *prompt lane* (remote → local
//! operator) and a *verdict lane* (local operator → remote gate), distinct from
//! the *data lane* (the agent's stdio). The design does not rely on an operator
//! typing into a shared terminal stream.
//!
//! ## A grant is SCOPED, not a bare inode (prototype-grade)
//!
//! `allow-session` does not authorize "this inode for anyone." It is scoped to
//! the requester identity, the session, and the policy epoch — so a different
//! process in the same remote environment touching the same file does not
//! inherit the grant. The full production grant also carries `remote_host`,
//! `expires_at`, and an operator verdict signature; this prototype carries the
//! identity/session/epoch scope and leaves signing + expiry as a documented
//! follow-up (this is not yet the production trust channel).

use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::consent::{ConsentProvider, ConsentRequest, Source, Verdict};
use crate::protect::InodeKey;

// WO-9@v1: scope remote grants to object, identity, session, and policy state.
// WO-173@v2: Linux-only: fanotify remote grants bind opened inode identity.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// A scoped allow grant. The key is deliberately NOT a bare inode: it binds the
/// inode to the requester identity, the session, and the policy epoch, so a
/// grant cannot over-authorize a different process or a stale policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantKey {
    pub dev: u64,
    pub ino: u64,
    /// Requester user id (the uid that opened the file), so a grant to one
    /// identity does not silently cover another.
    pub uid: u32,
    /// Session this grant belongs to — a new run is a new session.
    pub session_id: u64,
    /// Policy epoch — bumping the policy invalidates older grants.
    pub policy_epoch: u64,
}

// WO-9@v1: encode and recover grants carried across the remote control lanes.
impl GrantKey {
    // WO-9@v1: bind each grant to the requesting identity and supervised run.
    // WO-173@v2: Linux-only: fanotify remote grants bind requester identity.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    /// Build a grant key from an inode + the scope of the current request.
    pub fn scoped(key: InodeKey, uid: u32, session_id: u64, policy_epoch: u64) -> Self {
        GrantKey {
            dev: key.dev,
            ino: key.ino,
            uid,
            session_id,
            policy_epoch,
        }
    }

    // WO-9@v1: serialize scoped grants for the remote verdict lane.
    // WO-173@v2: Linux-only: serialize fanotify grants across remote lanes.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    /// Wire form for the verdict lane: `<dev>:<ino>:<uid>:<session>:<epoch>`.
    pub fn wire(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.dev, self.ino, self.uid, self.session_id, self.policy_epoch
        )
    }

    // WO-9@v1: reject malformed scoped grants received from the operator lane.
    // WO-173@v2: Linux-only: parse fanotify grants returned over remote lanes.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    /// Parse the wire form.
    pub fn parse_wire(s: &str) -> Option<Self> {
        let mut p = s.split(':');
        let dev = p.next()?.parse().ok()?;
        let ino = p.next()?.parse().ok()?;
        let uid = p.next()?.parse().ok()?;
        let session_id = p.next()?.parse().ok()?;
        let policy_epoch = p.next()?.parse().ok()?;
        Some(GrantKey {
            dev,
            ino,
            uid,
            session_id,
            policy_epoch,
        })
    }
}

// WO-9@v1: share session grants between gate decisions and verdict intake.
// WO-173@v2: Linux-only: fanotify remote decisions share session grants.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Scoped grants shared between the gate (reader) and the verdict-intake thread
/// (writer). The gate consults it on the prompt lane; the operator's replies,
/// arriving asynchronously on the verdict lane, populate it.
#[derive(Clone, Default)]
pub struct RemoteCache {
    allow_session: Arc<Mutex<HashSet<GrantKey>>>,
    /// Count of prompts emitted, for diagnostics/tests.
    prompts_emitted: Arc<AtomicU64>,
}

// WO-9@v1: expose synchronized operations over the remote session grant set.
impl RemoteCache {
    // WO-9@v1: initialize an empty grant cache for each remote gate session.
    // WO-173@v2: Linux-only: initialize fanotify remote session grants.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn new() -> Self {
        Self::default()
    }

    // WO-9@v1: record an operator-approved scoped grant for later opens.
    // WO-173@v2: Linux-only: cache fanotify remote grants for later opens.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn allow(&self, key: GrantKey) {
        self.allow_session.lock().unwrap().insert(key);
    }

    // WO-9@v1: decide remote opens only from an exact scoped grant match.
    // WO-173@v2: Linux-only: match fanotify remote opens to scoped grants.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn is_allowed(&self, key: &GrantKey) -> bool {
        self.allow_session.lock().unwrap().contains(key)
    }

    // WO-9@v1: expose prompt counts for deterministic remote-gate verification.
    /// Number of prompts emitted this session (tests).
    #[cfg(test)]
    pub fn prompts_emitted(&self) -> u64 {
        self.prompts_emitted.load(Ordering::SeqCst)
    }
}

// WO-181@v1: 256 slots absorb short bursts while bounding a stalled lane's memory.
#[cfg(any(test, target_os = "linux"))]
const PROMPT_QUEUE_BOUND: usize = 256;

// WO-181@v1: retain prompt-loss evidence after the queue writer moves to its thread.
#[cfg(any(test, target_os = "linux"))]
#[derive(Clone)]
pub struct PromptQueueStats {
    dropped: Arc<AtomicU64>,
}

// WO-181@v1: expose prompt drops for the remote run's terminal summary.
#[cfg(any(test, target_os = "linux"))]
impl PromptQueueStats {
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }
}

// WO-181@v1: make prompt submission bounded and nonblocking on the decision path.
#[cfg(any(test, target_os = "linux"))]
pub struct PromptQueueWriter {
    sender: std::sync::mpsc::SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
}

// WO-181@v1: isolate blocking prompt-lane writes on a dedicated worker thread.
#[cfg(any(test, target_os = "linux"))]
impl PromptQueueWriter {
    pub fn spawn<W: Write + Send + 'static>(
        mut sink: W,
    ) -> std::io::Result<(Self, PromptQueueStats)> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(PROMPT_QUEUE_BOUND);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer_dropped = Arc::clone(&dropped);
        std::thread::Builder::new()
            .name("bulwark-remote-prompts".into())
            .spawn(move || {
                while let Ok(line) = receiver.recv() {
                    if sink.write_all(&line).and_then(|()| sink.flush()).is_err() {
                        writer_dropped.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })?;
        let stats = PromptQueueStats {
            dropped: Arc::clone(&dropped),
        };
        Ok((Self { sender, dropped }, stats))
    }
}

// WO-181@v1: treat a full or closed queue as a counted prompt drop, never a wait.
#[cfg(any(test, target_os = "linux"))]
impl Write for PromptQueueWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.sender.try_send(buf.to_vec()) {
            Ok(()) => {}
            Err(
                std::sync::mpsc::TrySendError::Full(_)
                | std::sync::mpsc::TrySendError::Disconnected(_),
            ) => {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// WO-9@v1: bind a grant to the kernel identity that requested the remote open.
// WO-173@v2: Linux-only: read fanotify requester identity from procfs.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Read the uid that owns a pid, from `/proc/<pid>/status` (`Uid:` line). Used
/// to scope a grant to the requester identity. Falls back to `u32::MAX` (an
/// identity nothing matches) on failure, so a grant is never mis-scoped to uid
/// 0 by accident.
fn uid_of_pid(pid: i32) -> u32 {
    let path = format!("/proc/{pid}/status");
    if let Ok(s) = std::fs::read_to_string(path) {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                if let Some(tok) = rest.split_whitespace().next() {
                    if let Ok(uid) = tok.parse() {
                        return uid;
                    }
                }
            }
        }
    }
    u32::MAX
}

// WO-9@v1: deny uncached remote opens immediately while emitting operator prompts.
// WO-173@v2: Linux-only: fanotify remote opens emit asynchronous prompts.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// The remote-side consent provider. On a protected open that is not already
/// cached-allowed (scoped), it DENIES immediately and emits a prompt to the
/// prompt lane. It never blocks: the kernel deadline is always met.
pub struct AsyncRemoteProvider<W: Write> {
    cache: RemoteCache,
    /// The prompt lane (remote → local operator). Distinct from the agent's
    /// stdio; carries only structured control messages, never file content.
    prompt_out: W,
    /// Identifies this host in the prompt, so a local operator watching several
    /// remotes knows which one is asking.
    host_label: String,
    /// This run's session id — grants are scoped to it.
    session_id: u64,
    /// Current policy epoch — grants are scoped to it.
    policy_epoch: u64,
}

// WO-9@v1: construct prompts and grant keys without blocking remote decisions.
impl<W: Write> AsyncRemoteProvider<W> {
    // WO-9@v1: bind the remote provider to one host, session, and policy epoch.
    // WO-173@v2: Linux-only: construct the fanotify remote prompt provider.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn new(
        cache: RemoteCache,
        prompt_out: W,
        host_label: String,
        session_id: u64,
        policy_epoch: u64,
    ) -> Self {
        AsyncRemoteProvider {
            cache,
            prompt_out,
            host_label,
            session_id,
            policy_epoch,
        }
    }

    // WO-9@v1: derive the exact authorization scope for each protected open.
    // WO-173@v2: Linux-only: scope each fanotify remote grant to its opener.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    /// The scoped grant key for a request: inode + requester uid + session +
    /// policy epoch.
    fn grant_key(&self, req: &ConsentRequest) -> GrantKey {
        GrantKey::scoped(
            req.key,
            uid_of_pid(req.pid),
            self.session_id,
            self.policy_epoch,
        )
    }

    // WO-9@v1: emit structured prompts without changing the immediate deny decision.
    // WO-173@v2: Linux-only: emit fanotify remote prompts over the control lane.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    /// Emit one prompt line on the prompt lane. Tab-separated, never carries
    /// file content. The `grant` field is the SCOPED key the operator echoes
    /// back to authorize — so the operator authorizes exactly this
    /// inode+identity+session+epoch, not a bare inode for anyone.
    /// `CONSENT\thost=<h>\tgrant=<scoped>\tpath=<p>\tancestry=<chain>\n`
    fn emit_prompt(&mut self, req: &ConsentRequest, grant: &GrantKey) {
        let clean = |s: &str| s.replace(['\t', '\n', '\r'], " ");
        let line = format!(
            "CONSENT\thost={}\tgrant={}\tpath={}\tancestry={}\n",
            clean(&self.host_label),
            grant.wire(),
            clean(&req.path),
            clean(&req.ancestry),
        );
        // Best effort: a failed prompt write must not change the (already made)
        // deny decision.
        let _ = self.prompt_out.write_all(line.as_bytes());
        let _ = self.prompt_out.flush();
        self.cache.prompts_emitted.fetch_add(1, Ordering::SeqCst);
    }
}

// WO-9@v1: connect remote prompt splitting to the portable consent interface.
impl<W: Write> ConsentProvider for AsyncRemoteProvider<W> {
    // WO-9@v1: allow exact cached grants and deny first touches without waiting.
    fn request(&mut self, req: &ConsentRequest) -> (Verdict, Source) {
        let grant = self.grant_key(req);
        // Cached scoped-allow → pass immediately, no prompt.
        if self.cache.is_allowed(&grant) {
            return (Verdict::AllowSession, Source::Cache);
        }
        // Not cached → deny NOW (meet the kernel deadline) and prompt for next
        // time. The operator's allow-session reply (echoing this scoped grant)
        // will populate the cache.
        self.emit_prompt(req, &grant);
        (Verdict::Deny, Source::Timeout)
    }
}

// WO-9@v1: use the remote provider directly as the gate decision source.
/// The remote provider is itself the gate's decider — it does its own scoped
/// caching, so it does not need the generic `CachingProvider` wrapper.
impl<W: Write> crate::gate::ConsentDecider for AsyncRemoteProvider<W> {
    // WO-9@v1: delegate gate decisions to the scoped remote consent path.
    fn decide(&mut self, req: &ConsentRequest) -> (Verdict, Source) {
        self.request(req)
    }
}

// WO-9@v1: parse structured remote prompts for the local operator transport.
/// Parse a `CONSENT\t...` prompt line into fields for the local operator client
/// to display. Returns `None` for a non-prompt line. This is the seam the
/// interactive local operator UI builds on (the prototype launcher auto-answers
/// in shell; this parser is the typed entry point for a richer client).
pub fn parse_prompt(line: &str) -> Option<Vec<(String, String)>> {
    let rest = line.strip_prefix("CONSENT\t")?;
    let mut out = Vec::new();
    for part in rest.trim_end().split('\t') {
        if let Some((k, v)) = part.split_once('=') {
            out.push((k.to_string(), v.to_string()));
        }
    }
    Some(out)
}

// WO-18@v1: extract named prompt fields for the local operator display.
/// Look up one field from a parsed prompt's key/value pairs.
fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

// WO-18@v1: render remote context for an interactive local decision.
/// Render a parsed prompt for the local operator: host, path, and process
/// ancestry on a single human-readable line. The scoped grant is control state,
/// not shown — the operator decides on the path + who is asking. Pure (no I/O),
/// so it is unit-testable and the caller controls where it is written (stderr,
/// kept off the agent's stdout).
pub fn render_prompt(fields: &[(String, String)]) -> String {
    let host = field(fields, "host").unwrap_or("?");
    let path = field(fields, "path").unwrap_or("?");
    let ancestry = field(fields, "ancestry").unwrap_or("?");
    format!("[bulwark] consent needed on {host}: {path}  (via {ancestry})")
}

// WO-18@v1: preserve the remote grant token verbatim for the reply lane.
/// The verbatim scoped grant string from a parsed prompt, which the operator
/// echoes back unchanged on the verdict lane. Returns `None` if the prompt
/// carried no grant (a malformed line).
pub fn prompt_grant(fields: &[(String, String)]) -> Option<&str> {
    field(fields, "grant")
}

// WO-18@v1: encode the local operator verdict for remote intake.
/// Build a verdict-lane line from a verdict and the verbatim scoped grant string
/// taken from the prompt. The grant is echoed unchanged so the authorization
/// stays bound to that identity/session/epoch — never reconstructed locally.
/// Round-trips with [`parse_verdict_reply`].
pub fn verdict_line(verdict: Verdict, grant: &str) -> String {
    format!("{} {}", verdict.as_str(), grant)
}

// WO-9@v1: parse remote verdict replies without broadening their grant scope.
// WO-173@v2: Linux-only: parse fanotify remote verdict replies.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// A verdict reply from the operator, on the verdict lane back to the remote
/// gate. Wire form: `allow-session <dev>:<ino>:<uid>:<session>:<epoch>` — the
/// operator echoes the exact scoped grant from the prompt, so the authorization
/// is bound to that identity/session/epoch. Only allow grants are meaningful
/// remotely (deny is already the default).
pub fn parse_verdict_reply(line: &str) -> Option<(Verdict, GrantKey)> {
    let mut parts = line.split_whitespace();
    let verdict = Verdict::parse(parts.next()?)?;
    let grant = GrantKey::parse_wire(parts.next()?)?;
    Some((verdict, grant))
}

// WO-9@v1: apply asynchronous allow replies to the matching remote session cache.
// WO-173@v2: Linux-only: apply fanotify remote verdicts to the session cache.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Read operator verdict replies from `reader` (the verdict lane) and apply
/// `allow-session` decisions to `cache`. Runs until the lane closes; intended to
/// run on a background thread on the remote gate.
pub fn intake_verdicts<R: BufRead>(reader: R, cache: RemoteCache) {
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if let Some((verdict, grant)) = parse_verdict_reply(&line) {
            if matches!(verdict, Verdict::AllowSession | Verdict::AllowOnce) {
                cache.allow(grant);
            }
        }
    }
}

// WO-9@v1: verify the remote decision and control-lane contract in one module.
#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: u64 = 42;
    const EPOCH: u64 = 1;

    // WO-9@v1: build consistently scoped protected-open requests for remote tests.
    fn req(ino: u64) -> ConsentRequest {
        ConsentRequest {
            // pid 1 (init) reliably resolves uid 0 via /proc on a test host.
            pid: 1,
            key: InodeKey { dev: 5, ino },
            path: format!("/etc/secret-{ino}"),
            ancestry: "cat(1) <- bash(0)".into(),
            reason: "protected".into(),
        }
    }

    // WO-9@v1: construct a deterministic remote provider for decision tests.
    fn provider(cache: RemoteCache, out: &mut Vec<u8>) -> AsyncRemoteProvider<&mut Vec<u8>> {
        AsyncRemoteProvider::new(cache, out, "prod".into(), SESSION, EPOCH)
    }

    // WO-9@v1: prove first touches deny promptly and emit a scoped prompt.
    #[test]
    fn first_touch_denies_immediately_and_prompts() {
        let cache = RemoteCache::new();
        let mut out = Vec::new();
        let (v, s) = {
            let mut p = provider(cache.clone(), &mut out);
            p.request(&req(10))
        };
        assert_eq!(v, Verdict::Deny);
        assert_eq!(s, Source::Timeout);
        let emitted = String::from_utf8(out).unwrap();
        assert!(emitted.starts_with("CONSENT\t"));
        assert!(emitted.contains("host=prod"));
        // grant is the scoped key, not a bare inode.
        assert!(emitted.contains("grant=5:10:"));
        assert!(emitted.contains(&format!(":{SESSION}:{EPOCH}")));
        assert!(emitted.contains("/etc/secret-10"));
        assert_eq!(cache.prompts_emitted(), 1);
    }

    // WO-9@v1: prove exact cached grants allow without another operator prompt.
    #[test]
    fn cached_scoped_allow_passes_without_prompt() {
        let cache = RemoteCache::new();
        // The grant must match the SAME scope (uid of pid 1 = 0, session, epoch).
        let uid = uid_of_pid(1);
        cache.allow(GrantKey::scoped(
            InodeKey { dev: 5, ino: 11 },
            uid,
            SESSION,
            EPOCH,
        ));
        let mut out = Vec::new();
        let (v, s) = {
            let mut p = provider(cache.clone(), &mut out);
            p.request(&req(11))
        };
        assert_eq!(v, Verdict::AllowSession);
        assert_eq!(s, Source::Cache);
        assert!(out.is_empty(), "no prompt for a cached allow");
    }

    // WO-9@v1: prevent grants from authorizing a different remote session.
    #[test]
    fn grant_for_different_scope_does_not_authorize() {
        // A grant for a DIFFERENT session must not pass — scoping prevents
        // over-authorization across sessions/identities.
        let cache = RemoteCache::new();
        let uid = uid_of_pid(1);
        cache.allow(GrantKey::scoped(
            InodeKey { dev: 5, ino: 12 },
            uid,
            999, // different session
            EPOCH,
        ));
        let mut out = Vec::new();
        let (v, _) = {
            let mut p = provider(cache.clone(), &mut out);
            p.request(&req(12))
        };
        assert_eq!(
            v,
            Verdict::Deny,
            "a grant from another session must not apply"
        );
    }

    // WO-9@v1: pin lossless serialization of the full remote grant scope.
    #[test]
    fn grant_wire_round_trip() {
        let g = GrantKey {
            dev: 5,
            ino: 12,
            uid: 1000,
            session_id: 42,
            policy_epoch: 3,
        };
        assert_eq!(g.wire(), "5:12:1000:42:3");
        assert_eq!(GrantKey::parse_wire("5:12:1000:42:3"), Some(g));
        assert!(GrantKey::parse_wire("garbage").is_none());
    }

    // WO-9@v1: pin parsing of verdicts paired with scoped remote grants.
    #[test]
    fn verdict_reply_round_trip() {
        let (v, g) = parse_verdict_reply("allow-session 5:12:0:42:1").unwrap();
        assert_eq!(v, Verdict::AllowSession);
        assert_eq!(g.ino, 12);
        assert_eq!(g.session_id, 42);
        assert!(parse_verdict_reply("garbage").is_none());
    }

    // WO-9@v1: prove verdict intake caches allows and ignores deny replies.
    #[test]
    fn intake_applies_allow_session_to_cache() {
        let cache = RemoteCache::new();
        let input = "allow-session 5:13:0:42:1\ndeny 5:14:0:42:1\nallow-session 5:15:0:42:1\n";
        intake_verdicts(std::io::Cursor::new(input), cache.clone());
        assert!(cache.is_allowed(&GrantKey {
            dev: 5,
            ino: 13,
            uid: 0,
            session_id: 42,
            policy_epoch: 1
        }));
        assert!(cache.is_allowed(&GrantKey {
            dev: 5,
            ino: 15,
            uid: 0,
            session_id: 42,
            policy_epoch: 1
        }));
        assert!(!cache.is_allowed(&GrantKey {
            dev: 5,
            ino: 14,
            uid: 0,
            session_id: 42,
            policy_epoch: 1
        })); // deny ignored
    }

    // WO-9@v1: preserve structured prompt fields across the remote lane.
    #[test]
    fn prompt_parse_round_trip() {
        let cache = RemoteCache::new();
        let mut out = Vec::new();
        {
            let mut p = provider(cache, &mut out);
            p.request(&req(20));
        }
        let line = String::from_utf8(out).unwrap();
        let fields = parse_prompt(&line).unwrap();
        let get = |k: &str| {
            fields
                .iter()
                .find(|(fk, _)| fk == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("host"), Some("prod".into()));
        assert!(get("grant").unwrap().starts_with("5:20:"));
        assert_eq!(get("path"), Some("/etc/secret-20".into()));
    }

    // WO-18@v1: prove local prompt text carries host, path, and ancestry context.
    #[test]
    fn render_prompt_shows_host_path_ancestry() {
        let fields = vec![
            ("host".into(), "prod".into()),
            ("grant".into(), "5:10:0:42:1".into()),
            ("path".into(), "/etc/shadow".into()),
            ("ancestry".into(), "cat(9) <- bash(1)".into()),
        ];
        let s = render_prompt(&fields);
        assert!(s.contains("prod"));
        assert!(s.contains("/etc/shadow"));
        assert!(s.contains("cat(9) <- bash(1)"));
        // The scoped grant is control state, not shown to the operator.
        assert!(!s.contains("5:10:0:42:1"));
    }

    // WO-18@v1: prove the local operator returns the exact remote grant token.
    #[test]
    fn prompt_grant_extracts_verbatim() {
        let fields =
            parse_prompt("CONSENT\thost=prod\tgrant=5:10:0:42:1\tpath=/x\tancestry=a").unwrap();
        assert_eq!(prompt_grant(&fields), Some("5:10:0:42:1"));
    }

    // WO-18@v1: prove local verdict lines round-trip through remote parsing.
    #[test]
    fn verdict_line_round_trips_with_parse() {
        // The line built for the verdict lane parses back to the same verdict +
        // scoped grant, with the grant echoed verbatim (never reconstructed).
        let grant = "5:12:0:42:1";
        let line = verdict_line(Verdict::AllowSession, grant);
        assert_eq!(line, "allow-session 5:12:0:42:1");
        let (v, g) = parse_verdict_reply(&line).unwrap();
        assert_eq!(v, Verdict::AllowSession);
        assert_eq!(g.wire(), grant);

        let deny = verdict_line(Verdict::Deny, grant);
        let (v2, _) = parse_verdict_reply(&deny).unwrap();
        assert_eq!(v2, Verdict::Deny);
    }

    // WO-181@v1: a blocked prompt sink must not stall or hide queue overflow.
    struct BlockingPromptWriter {
        started: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    // WO-181@v1: hold the prompt writer after it takes one item from the queue.
    impl Write for BlockingPromptWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.started.try_send(());
            let _ = self.release.recv();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // WO-181@v1: prove a full prompt queue drops and counts without blocking.
    #[test]
    fn prompt_queue_drops_and_counts_when_full_without_blocking() {
        const CALLER_BOUND: std::time::Duration = std::time::Duration::from_secs(1);

        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let (mut prompt_out, stats) = PromptQueueWriter::spawn(BlockingPromptWriter {
            started: started_tx,
            release: release_rx,
        })
        .expect("spawn prompt writer");

        prompt_out.write_all(b"blocked\n").unwrap();
        started_rx
            .recv_timeout(CALLER_BOUND)
            .expect("writer must take the first prompt");

        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            for _ in 0..=PROMPT_QUEUE_BOUND {
                prompt_out.write_all(b"queued\n").unwrap();
            }
            done_tx.send(()).unwrap();
        });

        done_rx
            .recv_timeout(CALLER_BOUND)
            .expect("a full prompt queue must not block the caller");
        assert_eq!(stats.dropped(), 1, "the overflowed prompt must be counted");
        release_tx.send(()).unwrap();
    }
}
