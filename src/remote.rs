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

impl GrantKey {
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

    /// Wire form for the verdict lane: `<dev>:<ino>:<uid>:<session>:<epoch>`.
    pub fn wire(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.dev, self.ino, self.uid, self.session_id, self.policy_epoch
        )
    }

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

/// Scoped grants shared between the gate (reader) and the verdict-intake thread
/// (writer). The gate consults it on the prompt lane; the operator's replies,
/// arriving asynchronously on the verdict lane, populate it.
#[derive(Clone, Default)]
pub struct RemoteCache {
    allow_session: Arc<Mutex<HashSet<GrantKey>>>,
    /// Count of prompts emitted, for diagnostics/tests.
    prompts_emitted: Arc<AtomicU64>,
}

impl RemoteCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(&self, key: GrantKey) {
        self.allow_session.lock().unwrap().insert(key);
    }

    fn is_allowed(&self, key: &GrantKey) -> bool {
        self.allow_session.lock().unwrap().contains(key)
    }

    /// Number of prompts emitted this session (diagnostics + tests).
    #[allow(dead_code)] // used by tests and the future operator-UI status line
    pub fn prompts_emitted(&self) -> u64 {
        self.prompts_emitted.load(Ordering::SeqCst)
    }
}

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

impl<W: Write> AsyncRemoteProvider<W> {
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

impl<W: Write> ConsentProvider for AsyncRemoteProvider<W> {
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

/// The remote provider is itself the gate's decider — it does its own scoped
/// caching, so it does not need the generic `CachingProvider` wrapper.
impl<W: Write> crate::gate::ConsentDecider for AsyncRemoteProvider<W> {
    fn decide(&mut self, req: &ConsentRequest) -> (Verdict, Source) {
        self.request(req)
    }
}

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

/// Look up one field from a parsed prompt's key/value pairs.
fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

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

/// The verbatim scoped grant string from a parsed prompt, which the operator
/// echoes back unchanged on the verdict lane. Returns `None` if the prompt
/// carried no grant (a malformed line).
pub fn prompt_grant(fields: &[(String, String)]) -> Option<&str> {
    field(fields, "grant")
}

/// Build a verdict-lane line from a verdict and the verbatim scoped grant string
/// taken from the prompt. The grant is echoed unchanged so the authorization
/// stays bound to that identity/session/epoch — never reconstructed locally.
/// Round-trips with [`parse_verdict_reply`].
pub fn verdict_line(verdict: Verdict, grant: &str) -> String {
    format!("{} {}", verdict.as_str(), grant)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: u64 = 42;
    const EPOCH: u64 = 1;

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

    fn provider(cache: RemoteCache, out: &mut Vec<u8>) -> AsyncRemoteProvider<&mut Vec<u8>> {
        AsyncRemoteProvider::new(cache, out, "prod".into(), SESSION, EPOCH)
    }

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

    #[test]
    fn verdict_reply_round_trip() {
        let (v, g) = parse_verdict_reply("allow-session 5:12:0:42:1").unwrap();
        assert_eq!(v, Verdict::AllowSession);
        assert_eq!(g.ino, 12);
        assert_eq!(g.session_id, 42);
        assert!(parse_verdict_reply("garbage").is_none());
    }

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

    #[test]
    fn prompt_grant_extracts_verbatim() {
        let fields =
            parse_prompt("CONSENT\thost=prod\tgrant=5:10:0:42:1\tpath=/x\tancestry=a").unwrap();
        assert_eq!(prompt_grant(&fields), Some("5:10:0:42:1"));
    }

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
}
