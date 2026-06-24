//! Consent providers and the decision cache.
//!
//! When the gate sees a protected-inode open by the supervised tree, it asks a
//! [`ConsentProvider`] for a [`Verdict`] instead of denying unconditionally.
//! The provider is an interface — Bulwark ships a native one (a control socket
//! the operator answers, see [`crate::socket`]) and degrades to [`StaticDeny`]
//! when no interactive channel is configured. Optional fleet transports
//! (nr-pro / hivebus) can implement the same trait without the core depending
//! on them.
//!
//! The channel is operator ↔ tooling, never agent ↔ operator: a provider must
//! reach a human over a band the supervised process has no descriptor on, and
//! the agent only ever observes the syscall result.

use crate::protect::InodeKey;

/// The operator's (or a provider's) answer for one open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Allow just this open; ask again next time.
    AllowOnce,
    /// Allow this inode for the rest of the session (cached).
    AllowSession,
    /// Deny this open; ask again next time.
    Deny,
    /// Deny this inode permanently (cached + persisted by the caller).
    DenyForever,
}

impl Verdict {
    /// True if the open should be permitted.
    pub fn allows(self) -> bool {
        matches!(self, Verdict::AllowOnce | Verdict::AllowSession)
    }

    /// Wire string form (socket protocol + receipts).
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::AllowOnce => "allow-once",
            Verdict::AllowSession => "allow-session",
            Verdict::Deny => "deny",
            Verdict::DenyForever => "deny-forever",
        }
    }

    /// Parse the wire string form. Unknown strings parse to `None`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "allow-once" | "allow" | "o" => Some(Verdict::AllowOnce),
            "allow-session" | "session" | "s" => Some(Verdict::AllowSession),
            "deny" | "d" => Some(Verdict::Deny),
            "deny-forever" | "forever" | "f" => Some(Verdict::DenyForever),
            _ => None,
        }
    }
}

/// Context handed to a provider for one consent request. Never contains file
/// content — only identity and provenance.
#[derive(Debug, Clone)]
pub struct ConsentRequest {
    pub pid: i32,
    pub key: InodeKey,
    pub path: String,
    pub ancestry: String,
    pub reason: String,
}

/// How a verdict was reached, for the receipt log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A live operator answered.
    Operator,
    /// Served from the session cache (a prior allow-session / deny-forever).
    Cache,
    /// No answer within the deadline — denied.
    Timeout,
    /// No interactive provider configured — denied.
    Static,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Operator => "operator",
            Source::Cache => "cache",
            Source::Timeout => "timeout",
            Source::Static => "static",
        }
    }
}

/// A source of consent verdicts.
pub trait ConsentProvider {
    /// Request a verdict for one open. Implementations MUST be deadline-bounded
    /// and return `Verdict::Deny` (with [`Source::Timeout`]) rather than block
    /// indefinitely — the kernel is holding the open. Returns the verdict and
    /// how it was reached.
    fn request(&mut self, req: &ConsentRequest) -> (Verdict, Source);

    /// Receive the supervised tree's cgroup scope (relative path) so an off-band
    /// provider can reject in-tree answerers by membership. Default: no-op (the
    /// static-deny floor and providers without a peer channel ignore it).
    fn bind_scope(&mut self, _scope_rel: Option<&str>) {}
}

/// The default open-core provider: deny everything, immediately. This is the
/// graceful-degradation floor when no interactive channel is configured, and
/// reproduces the MVP behavior exactly.
pub struct StaticDeny;

impl ConsentProvider for StaticDeny {
    fn request(&mut self, _req: &ConsentRequest) -> (Verdict, Source) {
        (Verdict::Deny, Source::Static)
    }
}

/// Wraps a provider with the session decision cache. Inodes the operator
/// allowed for the session short-circuit to allow; inodes denied forever
/// short-circuit to deny. Everything else falls through to the inner provider.
pub struct CachingProvider<P: ConsentProvider> {
    inner: P,
    allow_session: std::collections::HashSet<InodeKey>,
    deny_forever: std::collections::HashSet<InodeKey>,
    /// Paths the operator denied forever this session, for persistence to the
    /// policy file by the caller. Path (not inode) is the durable form — inodes
    /// are reused across deletes.
    deny_forever_paths: Vec<String>,
    /// When set (integrity-tainted run, ), the allow-session cache is
    /// bypassed: every protected open is referred to the operator for a fresh
    /// decision, so no convenience grant survives the taint. Deny-forever still
    /// short-circuits (a standing deny is never weakened by taint).
    tainted: bool,
}

impl<P: ConsentProvider> CachingProvider<P> {
    pub fn new(inner: P) -> Self {
        CachingProvider {
            inner,
            allow_session: Default::default(),
            deny_forever: Default::default(),
            deny_forever_paths: Vec::new(),
            tainted: false,
        }
    }

    /// Mark this provider as operating in a tainted session: the allow-session
    /// cache is bypassed so every protected open re-prompts. Deny-forever is
    /// unaffected.
    pub fn tainted(mut self) -> Self {
        self.tainted = true;
        self
    }

    /// Paths that were denied forever this session (deduped), for the caller to
    /// persist as protected globs in the policy file.
    pub fn deny_forever_paths(&self) -> &[String] {
        &self.deny_forever_paths
    }

    /// Resolve a verdict for `req`, consulting and updating the cache.
    pub fn decide(&mut self, req: &ConsentRequest) -> (Verdict, Source) {
        if self.deny_forever.contains(&req.key) {
            return (Verdict::DenyForever, Source::Cache);
        }
        // Tainted runs never serve an allow from cache — the operator must
        // re-decide each protected open until taint is cleared with `bulwark
        // reset`. Deny-forever above is intentionally still honored.
        if !self.tainted && self.allow_session.contains(&req.key) {
            return (Verdict::AllowSession, Source::Cache);
        }
        let (verdict, source) = self.inner.request(req);
        if verdict == Verdict::AllowSession && !self.tainted {
            self.allow_session.insert(req.key);
        }
        if verdict == Verdict::DenyForever {
            let newly_denied = self.deny_forever.insert(req.key);
            // record the path once for persistence (path, not inode — durable)
            if newly_denied && !self.deny_forever_paths.contains(&req.path) {
                self.deny_forever_paths.push(req.path.clone());
            }
        }
        (verdict, source)
    }
}

impl<P: ConsentProvider> crate::gate::ConsentDecider for CachingProvider<P> {
    fn decide(&mut self, req: &ConsentRequest) -> (Verdict, Source) {
        CachingProvider::decide(self, req)
    }

    fn bind_scope(&mut self, scope_rel: Option<&str>) {
        // The cache holds no peer channel; forward to the wrapped provider.
        self.inner.bind_scope(scope_rel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(ino: u64) -> ConsentRequest {
        ConsentRequest {
            pid: 100,
            key: InodeKey { dev: 1, ino },
            path: format!("/x/{ino}"),
            ancestry: "cat(100) <- bash(9)".into(),
            reason: "protected".into(),
        }
    }

    /// A scripted provider that returns a fixed sequence of verdicts.
    struct Scripted(std::cell::RefCell<Vec<Verdict>>);
    impl ConsentProvider for Scripted {
        fn request(&mut self, _r: &ConsentRequest) -> (Verdict, Source) {
            let v = self.0.borrow_mut().remove(0);
            (v, Source::Operator)
        }
    }

    #[test]
    fn verdict_allows_only_allow_variants() {
        assert!(Verdict::AllowOnce.allows());
        assert!(Verdict::AllowSession.allows());
        assert!(!Verdict::Deny.allows());
        assert!(!Verdict::DenyForever.allows());
    }

    #[test]
    fn verdict_wire_round_trip() {
        for v in [
            Verdict::AllowOnce,
            Verdict::AllowSession,
            Verdict::Deny,
            Verdict::DenyForever,
        ] {
            assert_eq!(Verdict::parse(v.as_str()), Some(v));
        }
        assert_eq!(Verdict::parse("nonsense"), None);
    }

    #[test]
    fn static_deny_denies() {
        let mut p = StaticDeny;
        let (v, s) = p.request(&req(1));
        assert_eq!(v, Verdict::Deny);
        assert_eq!(s, Source::Static);
    }

    #[test]
    fn allow_session_is_cached_not_reasked() {
        // First call asks (allow-session); second call for same inode is cached.
        let scripted = Scripted(std::cell::RefCell::new(vec![Verdict::AllowSession]));
        let mut c = CachingProvider::new(scripted);
        let (v1, s1) = c.decide(&req(7));
        assert_eq!((v1, s1), (Verdict::AllowSession, Source::Operator));
        // No second scripted verdict available; if it asked again it would panic.
        let (v2, s2) = c.decide(&req(7));
        assert_eq!((v2, s2), (Verdict::AllowSession, Source::Cache));
    }

    #[test]
    fn deny_forever_is_cached_and_path_recorded() {
        let scripted = Scripted(std::cell::RefCell::new(vec![Verdict::DenyForever]));
        let mut c = CachingProvider::new(scripted);
        let (v1, _) = c.decide(&req(9));
        assert_eq!(v1, Verdict::DenyForever);
        // second time served from cache (scripted has no more verdicts)
        let (v2, s2) = c.decide(&req(9));
        assert_eq!((v2, s2), (Verdict::DenyForever, Source::Cache));
        // the path is recorded once for persistence
        assert_eq!(c.deny_forever_paths(), &["/x/9".to_string()]);
    }

    #[test]
    fn tainted_bypasses_allow_session_cache() {
        // In a tainted session every protected open re-asks: allow-session is
        // never served from cache. Two allow-sessions are scripted; both must be
        // consumed (Source::Operator), proving the second was not cached.
        let scripted = Scripted(std::cell::RefCell::new(vec![
            Verdict::AllowSession,
            Verdict::AllowSession,
        ]));
        let mut c = CachingProvider::new(scripted).tainted();
        assert_eq!(c.decide(&req(5)), (Verdict::AllowSession, Source::Operator));
        // Same inode again — a non-tainted provider would serve Source::Cache;
        // tainted re-asks the operator (consuming the second scripted verdict).
        assert_eq!(c.decide(&req(5)), (Verdict::AllowSession, Source::Operator));
    }

    #[test]
    fn tainted_still_honors_deny_forever() {
        // A standing deny-forever is never weakened by taint.
        let scripted = Scripted(std::cell::RefCell::new(vec![Verdict::DenyForever]));
        let mut c = CachingProvider::new(scripted).tainted();
        assert_eq!(c.decide(&req(8)).0, Verdict::DenyForever);
        // cached deny-forever short-circuits even when tainted
        assert_eq!(c.decide(&req(8)), (Verdict::DenyForever, Source::Cache));
    }

    #[test]
    fn allow_once_is_not_cached() {
        // allow-once must re-ask the next time for the same inode.
        let scripted = Scripted(std::cell::RefCell::new(vec![
            Verdict::AllowOnce,
            Verdict::Deny,
        ]));
        let mut c = CachingProvider::new(scripted);
        assert_eq!(c.decide(&req(3)).0, Verdict::AllowOnce);
        assert_eq!(c.decide(&req(3)).0, Verdict::Deny); // re-asked
    }
}
