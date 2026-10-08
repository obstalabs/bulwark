//! Integrity circuit-breaker (WO-13).
//!
//! Bulwark's fanotify gate fails *open* on hard supervisor death: a held
//! permission event is released by the kernel as allowed when the supervisor is
//! `SIGKILL`ed or crashes. That leak is inherent and cannot be retroactively
//! denied. This module does not try to fix it — it bounds the blast radius
//! *after* recovery.
//!
//! It records the integrity context of each run (a monotonic generation, a
//! clean-shutdown marker, a digest of the policy it loaded, and the identity of
//! every protected object) in a small persistent state file. On the next run it
//! detects two failure signals:
//!
//! 1. **Unclean restart** — the previous run never wrote its clean-shutdown
//!    marker (it was killed or crashed mid-flight, while events may have been
//!    outstanding).
//! 2. **Object-identity drift** — a protected path now resolves to a different
//!    `(dev, ino)`, or the policy loaded for the same project has a different
//!    digest (WO-117: an in-tree agent can rewrite `Bulwark.toml`; bulwark gates
//!    reads, not writes, so the rewrite is caught on the next launch instead).
//!
//! On either signal the run is **tainted**. The caller denies protected reads
//! by default (or, in socket mode, routes each open to a live operator for a
//! fresh decision — no pre-taint grant survives, because the in-memory consent
//! cache starts empty on every run). Taint **persists across restarts** until an
//! operator explicitly acknowledges it with `bulwark reset`; there is no silent
//! auto-clear. Safe by default, recoverable only by explicit acknowledgement.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default location of the persistent state file. Root-owned: the gate already
/// runs as root. Deliberately NOT under `$XDG_RUNTIME_DIR`, which is wiped on
/// reboot — that would silently erase taint across a power cycle.
pub const DEFAULT_STATE_PATH: &str = "/var/lib/bulwark/state.toml";

/// Identity of one protected object at decision time. The pair `(dev, ino)` is
/// the same identity the gate decides by; `path` is how the object was named so
/// drift can be reported meaningfully.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjId {
    pub path: String,
    pub dev: u64,
    pub ino: u64,
}

// WO-117: where a run's policy came from. The key decides which baseline the
// digest is compared against: an explicit file by its canonical path, an
// auto-discovered one by the directory searched (both file-name casings share
// it, so a Bulwark.toml appearing beside bulwark.toml is a change, not a new
// project), and a directory with no file still gets a record so a file created
// there later is a change too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// `--policy <FILE>`.
    Explicit(PathBuf),
    /// The cwd search over the known policy file names; `file` is what it found.
    Discovered { dir: PathBuf, file: Option<PathBuf> },
}

impl PolicySource {
    /// The history key. Canonical so symlinks and `./` spellings collapse.
    // WO-117 (R2): fail closed. A key that cannot be resolved would either
    // invent a fresh baseline or collide with another; refuse the run instead.
    pub fn key(&self) -> Result<String> {
        let target = match self {
            PolicySource::Explicit(path) => path.as_path(),
            PolicySource::Discovered { dir, .. } => dir.as_path(),
        };
        let canonical = std::fs::canonicalize(target).with_context(|| {
            format!(
                "cannot resolve the policy identity of {} for the integrity record",
                target.display()
            )
        })?;
        Ok(canonical.to_string_lossy().into_owned())
    }

    /// The file whose bytes the run enforces, if any.
    pub fn path(&self) -> Option<&Path> {
        match self {
            PolicySource::Explicit(path) => Some(path.as_path()),
            PolicySource::Discovered { file, .. } => file.as_deref(),
        }
    }

    /// Audit-safe description of what was digested.
    pub fn label(&self) -> String {
        match self.path() {
            Some(path) => format!("file:{}", path.display()),
            None => "builtin:default".to_string(),
        }
    }
}

// WO-117: one entry of the keyed policy history. Only `digest` is compared;
// `dev`/`ino` are recorded for the audit line because editors rename-replace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub key: String,
    pub source: String,
    pub digest: String,
    pub dev: u64,
    pub ino: u64,
}

// WO-117 (R3): the digest recorded for a discovery directory with no policy
// file. A fixed word rather than a hash of the built-in profile, so a bulwark
// upgrade that changes the default profile does not taint every such directory;
// a real file digest is 64 hex characters and can never equal it.
pub const BUILTIN_POLICY_DIGEST: &str = "builtin";

impl PolicyRecord {
    /// Record a file-backed policy from the handle it was read through: the
    /// identity comes from that handle's metadata and the digest from the bytes
    /// read from it, so the record describes exactly the bytes the run parsed.
    // WO-117 (R1): no second stat or read of the path, and no identity fallback.
    pub fn from_file(
        source: &PolicySource,
        meta: &std::fs::Metadata,
        bytes: &[u8],
    ) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        Ok(PolicyRecord {
            key: source.key()?,
            source: source.label(),
            digest: sha256_hex(bytes),
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }

    /// Record a discovery directory that holds no policy file. The built-in
    /// profile ships inside the binary and is not agent-writable, so there is
    /// nothing to digest; the marker only makes a later file a change.
    // WO-117 (R3): fixed marker; 0:0 identity is meaningful only here.
    pub fn builtin(source: &PolicySource) -> Result<Self> {
        Ok(PolicyRecord {
            key: source.key()?,
            source: source.label(),
            digest: BUILTIN_POLICY_DIGEST.to_string(),
            dev: 0,
            ino: 0,
        })
    }
}

// WO-117: lowercase hex sha256, the digest form stored in the state file.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The integrity context of the run being started: the policy this run loaded
/// (if any file-backed source was resolved) and the identity of every protected
/// object resolved at launch.
#[derive(Debug, Clone)]
pub struct RunContext {
    pub policy: Option<PolicyRecord>,
    pub objects: Vec<ObjId>,
}

/// Why a run is tainted. Carried into the audit receipt so the operator sees the
/// concrete reason, not just a flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintReason {
    /// The previous run did not record a clean shutdown.
    UncleanRestart,
    /// A protected object's identity changed since the last run.
    ObjectDrift {
        path: String,
        was: (u64, u64),
        now: (u64, u64),
    },
    // WO-117: the policy at this key has different bytes than last recorded.
    /// The policy loaded for this key changed since the last run that used it.
    PolicyChanged {
        key: String,
        prior_digest: String,
        now_digest: String,
    },
    /// A prior run was already tainted and never acknowledged with `reset`.
    Persisted,
}

impl TaintReason {
    /// One-line, audit-safe description (no file content, only identity).
    pub fn describe(&self) -> String {
        match self {
            TaintReason::UncleanRestart => "unclean restart (no clean-shutdown marker)".to_string(),
            TaintReason::ObjectDrift { path, was, now } => format!(
                "object-identity drift on {path}: dev/ino {}:{} -> {}:{}",
                was.0, was.1, now.0, now.1
            ),
            TaintReason::PolicyChanged {
                key,
                prior_digest,
                now_digest,
            } => format!("policy changed for {key}: sha256 {prior_digest} -> {now_digest}"),
            TaintReason::Persisted => {
                "prior taint not acknowledged (clear with `bulwark reset`)".to_string()
            }
        }
    }
}

/// Verdict of an integrity evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Integrity {
    Clean,
    Tainted(TaintReason),
}

impl Integrity {
    pub fn is_tainted(&self) -> bool {
        matches!(self, Integrity::Tainted(_))
    }
}

/// On-disk state. One run's recorded integrity context plus a sticky taint flag.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    /// Monotonic run counter. A grant minted in one generation never authorizes
    /// a read in another — restarts always start a new generation.
    pub generation: u64,
    /// Set only when the run shut down gracefully (child exit or trapped
    /// SIGTERM/SIGINT/SIGHUP). A hard kill or crash leaves this false.
    pub clean_shutdown: bool,
    // WO-117: keyed history, merged on every run and never replaced wholesale,
    // so a --protect-only run or a different project cannot erase a baseline.
    // Defaulted so pre-digest state files (which carried a fixed epoch field)
    // still load and keep their sticky taint instead of reading as a first run.
    #[serde(default)]
    pub policies: Vec<PolicyRecord>,
    pub objects: Vec<ObjId>,
    /// Sticky taint description. `Some` until an operator runs `bulwark reset`.
    pub tainted: Option<String>,
}

/// Pure evaluation: given the prior recorded state (if any) and the context of
/// the run being started, decide whether this run is tainted. No filesystem or
/// clock access, so it is fully unit-testable.
pub fn evaluate(prior: Option<&State>, current: &RunContext) -> Integrity {
    let prior = match prior {
        // First run on this host: nothing to compare against.
        None => return Integrity::Clean,
        Some(p) => p,
    };

    // A taint that was never acknowledged outranks everything: it persists across
    // any number of clean restarts until `bulwark reset`.
    if prior.tainted.is_some() {
        return Integrity::Tainted(TaintReason::Persisted);
    }

    // The previous run never recorded a clean shutdown — it was killed or crashed.
    if !prior.clean_shutdown {
        return Integrity::Tainted(TaintReason::UncleanRestart);
    }

    // WO-117: the policy loaded for this key has different bytes than the last
    // run that used the same key. A key seen for the first time has no baseline
    // and is clean (mirrors a brand-new protected path below); a run with no
    // file-backed policy compares nothing.
    if let Some(now) = &current.policy {
        if let Some(was) = prior.policies.iter().find(|p| p.key == now.key) {
            if was.digest != now.digest {
                return Integrity::Tainted(TaintReason::PolicyChanged {
                    key: now.key.clone(),
                    prior_digest: was.digest.clone(),
                    now_digest: now.digest.clone(),
                });
            }
        }
    }

    // A protected path present in both runs now resolves to a different inode.
    for now in &current.objects {
        if let Some(was) = prior.objects.iter().find(|o| o.path == now.path) {
            if was.dev != now.dev || was.ino != now.ino {
                return Integrity::Tainted(TaintReason::ObjectDrift {
                    path: now.path.clone(),
                    was: (was.dev, was.ino),
                    now: (now.dev, now.ino),
                });
            }
        }
    }

    Integrity::Clean
}

/// Owns the persistent state file and mediates reads/writes to it.
pub struct Store {
    path: PathBuf,
    /// The prior recorded state. `None` on the first run (no file yet), so it is
    /// never mistaken for an unclean restart.
    state: Option<State>,
}

impl Store {
    /// Load the state file, or start fresh if it does not exist. A
    /// corrupt/unreadable file is treated as absent but reported, so a damaged
    /// state never silently disables the circuit-breaker.
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let state = match std::fs::read_to_string(&path) {
            Ok(s) => match toml::from_str::<State>(&s) {
                Ok(st) => Some(st),
                Err(e) => {
                    eprintln!(
                        "[bulwark] warn: state file {} unreadable ({e}); treating as first run",
                        path.display()
                    );
                    None
                }
            },
            Err(_) => None,
        };
        Store { path, state }
    }

    /// The prior recorded state, for `evaluate`. `None` on the first run.
    pub fn prior(&self) -> Option<&State> {
        self.state.as_ref()
    }

    /// Begin a new run: bump the generation, clear the clean marker, and record
    /// this run's context. If the run is tainted, the reason is made sticky so it
    /// survives until `bulwark reset`.
    pub fn begin_run(&mut self, ctx: &RunContext, integrity: &Integrity) -> Result<u64> {
        let generation = self
            .state
            .as_ref()
            .map(|s| s.generation)
            .unwrap_or(0)
            .saturating_add(1);
        let tainted = match integrity {
            Integrity::Tainted(r) => Some(r.describe()),
            Integrity::Clean => None,
        };
        // WO-117: upsert this run's policy record and keep every other key, so
        // the baseline for one project survives runs of another (or none).
        let mut policies = self
            .state
            .as_ref()
            .map(|s| s.policies.clone())
            .unwrap_or_default();
        if let Some(now) = &ctx.policy {
            match policies.iter_mut().find(|p| p.key == now.key) {
                Some(slot) => *slot = now.clone(),
                None => policies.push(now.clone()),
            }
        }
        self.state = Some(State {
            generation,
            clean_shutdown: false,
            policies,
            objects: ctx.objects.clone(),
            tainted,
        });
        self.save()?;
        Ok(generation)
    }

    /// Record a clean shutdown. Called by the supervisor on any normal exit
    /// (child exited or a trapped termination signal). A hard kill skips this, so
    /// the next run sees an unclean restart.
    pub fn mark_clean_shutdown(&mut self) -> Result<()> {
        if let Some(s) = self.state.as_mut() {
            s.clean_shutdown = true;
        }
        self.save()
    }

    /// The sticky taint description, if any.
    pub fn taint_reason(&self) -> Option<&str> {
        self.state.as_ref().and_then(|s| s.tainted.as_deref())
    }

    /// Clear the taint marker only (what `bulwark reset` calls). Narrow by
    /// design: it does not reset the generation, the recorded objects, or the
    /// clean marker — only the operator acknowledgement.
    pub fn clear(&mut self) -> Result<()> {
        if let Some(s) = self.state.as_mut() {
            s.tainted = None;
        }
        self.save()
    }

    /// Persist the current state (no-op if there is nothing recorded yet),
    /// creating the parent directory if needed.
    fn save(&self) -> Result<()> {
        let state = match self.state.as_ref() {
            Some(s) => s,
            None => return Ok(()),
        };
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create state dir {}", dir.display()))?;
        }
        let body = toml::to_string(state).context("serialize integrity state")?;
        std::fs::write(&self.path, body)
            .with_context(|| format!("cannot write state file {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(path: &str, dev: u64, ino: u64) -> ObjId {
        ObjId {
            path: path.to_string(),
            dev,
            ino,
        }
    }

    // WO-117: the fixed key every tag-based helper records its policy under.
    const KEY: &str = "/proj";

    // WO-117: a policy record built directly; equal digests mean an unchanged policy.
    fn policy(key: &str, digest: &str) -> PolicyRecord {
        PolicyRecord {
            key: key.to_string(),
            source: format!("file:{key}/Bulwark.toml"),
            digest: digest.to_string(),
            dev: 1,
            ino: 5,
        }
    }

    // WO-117: `tag` selects the policy digest at KEY, replacing the former epoch;
    // the same tag on both sides means the policy did not change.
    fn ctx(tag: u64, objects: Vec<ObjId>) -> RunContext {
        RunContext {
            policy: Some(policy(KEY, &tag.to_string())),
            objects,
        }
    }

    fn clean_prior(tag: u64, objects: Vec<ObjId>) -> State {
        State {
            generation: 1,
            clean_shutdown: true,
            policies: vec![policy(KEY, &tag.to_string())],
            objects,
            tainted: None,
        }
    }

    // WO-117: a run context whose only variable is the policy record.
    fn policy_ctx(record: Option<PolicyRecord>) -> RunContext {
        RunContext {
            policy: record,
            objects: vec![obj("/s", 1, 10)],
        }
    }

    // WO-117: a fresh state file per test so the keyed history starts empty.
    fn scratch_state(tag: &str) -> (PathBuf, PathBuf) {
        // WO-132@v1: collision-free scratch dir instead of the tag+pid name.
        let dir = crate::test_scratch_dir(&format!("it-{tag}"));
        (dir.clone(), dir.join("state.toml"))
    }

    // WO-117 (R1): write `bytes` to the source's file and record it the way the
    // gate does: identity and bytes from one open handle.
    fn file_record(source: &PolicySource, bytes: &[u8]) -> PolicyRecord {
        use std::io::Read;
        let path = source.path().expect("file-backed source");
        std::fs::write(path, bytes).unwrap();
        let mut file = std::fs::File::open(path).unwrap();
        let meta = file.metadata().unwrap();
        let mut read = Vec::new();
        file.read_to_end(&mut read).unwrap();
        PolicyRecord::from_file(source, &meta, &read).unwrap()
    }

    // WO-117: one full clean run against the store: evaluate, record, shut down.
    fn cycle(path: &Path, c: &RunContext) -> Integrity {
        let mut store = Store::load(path);
        let verdict = evaluate(store.prior(), c);
        store.begin_run(c, &verdict).unwrap();
        store.mark_clean_shutdown().unwrap();
        verdict
    }

    #[test]
    fn first_run_is_clean() {
        let c = ctx(1, vec![obj("/s", 1, 10)]);
        assert_eq!(evaluate(None, &c), Integrity::Clean);
    }

    #[test]
    fn clean_shutdown_same_identity_is_clean() {
        let prior = clean_prior(1, vec![obj("/s", 1, 10)]);
        let c = ctx(1, vec![obj("/s", 1, 10)]);
        assert_eq!(evaluate(Some(&prior), &c), Integrity::Clean);
    }

    #[test]
    fn missing_clean_marker_is_unclean_restart() {
        let mut prior = clean_prior(1, vec![obj("/s", 1, 10)]);
        prior.clean_shutdown = false;
        let c = ctx(1, vec![obj("/s", 1, 10)]);
        assert_eq!(
            evaluate(Some(&prior), &c),
            Integrity::Tainted(TaintReason::UncleanRestart)
        );
    }

    #[test]
    fn changed_inode_is_object_drift() {
        let prior = clean_prior(1, vec![obj("/s", 1, 10)]);
        let c = ctx(1, vec![obj("/s", 1, 99)]);
        assert_eq!(
            evaluate(Some(&prior), &c),
            Integrity::Tainted(TaintReason::ObjectDrift {
                path: "/s".to_string(),
                was: (1, 10),
                now: (1, 99),
            })
        );
    }

    #[test]
    fn changed_device_is_object_drift() {
        let prior = clean_prior(1, vec![obj("/s", 1, 10)]);
        let c = ctx(1, vec![obj("/s", 2, 10)]);
        assert!(matches!(
            evaluate(Some(&prior), &c),
            Integrity::Tainted(TaintReason::ObjectDrift { .. })
        ));
    }

    // WO-117: replaces the former fixed-epoch test; the digest is what moves.
    #[test]
    fn changed_policy_digest_taints() {
        let prior = clean_prior(1, vec![obj("/s", 1, 10)]);
        let c = ctx(2, vec![obj("/s", 1, 10)]);
        assert_eq!(
            evaluate(Some(&prior), &c),
            Integrity::Tainted(TaintReason::PolicyChanged {
                key: KEY.to_string(),
                prior_digest: "1".to_string(),
                now_digest: "2".to_string(),
            })
        );
    }

    #[test]
    fn persisted_taint_survives_clean_restart() {
        let mut prior = clean_prior(1, vec![obj("/s", 1, 10)]);
        prior.tainted = Some("earlier drift".to_string());
        // Identical identity, clean shutdown — but the sticky taint outranks.
        let c = ctx(1, vec![obj("/s", 1, 10)]);
        assert_eq!(
            evaluate(Some(&prior), &c),
            Integrity::Tainted(TaintReason::Persisted)
        );
    }

    #[test]
    fn unclean_outranks_drift() {
        // An unclean restart is reported before drift is even checked.
        let mut prior = clean_prior(1, vec![obj("/s", 1, 10)]);
        prior.clean_shutdown = false;
        let c = ctx(9, vec![obj("/s", 9, 9)]);
        assert_eq!(
            evaluate(Some(&prior), &c),
            Integrity::Tainted(TaintReason::UncleanRestart)
        );
    }

    #[test]
    fn new_protected_path_alone_is_not_drift() {
        // Adding a brand-new protected path (not present last run) is a policy
        // change, not identity drift of an existing object — not tainted here.
        let prior = clean_prior(1, vec![obj("/s", 1, 10)]);
        let c = ctx(1, vec![obj("/s", 1, 10), obj("/new", 1, 20)]);
        assert_eq!(evaluate(Some(&prior), &c), Integrity::Clean);
    }

    #[test]
    fn store_round_trip_begin_then_clean_is_clean_next() {
        // WO-132@v1: collision-free scratch dir instead of the pid-only name.
        let dir = crate::test_scratch_dir("it");
        let path = dir.join("state.toml");

        let c = ctx(1, vec![obj("/s", 1, 10)]);

        // Run 1: begin clean, then mark clean shutdown.
        let mut s1 = Store::load(&path);
        let integ1 = evaluate(s1.prior(), &c); // default prior -> generation 0
        s1.begin_run(&c, &integ1).unwrap();
        s1.mark_clean_shutdown().unwrap();

        // Run 2: prior was clean, same identity -> clean.
        let s2 = Store::load(&path);
        assert!(s2.prior().unwrap().clean_shutdown);
        assert_eq!(evaluate(s2.prior(), &c), Integrity::Clean);
        assert_eq!(s2.prior().unwrap().generation, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_unclean_then_persist_then_clear() {
        // WO-132@v1: collision-free scratch dir instead of the pid-only name.
        let dir = crate::test_scratch_dir("it2");
        let path = dir.join("state.toml");

        let c = ctx(1, vec![obj("/s", 1, 10)]);

        // Run 1: begin but never mark clean (simulated crash).
        let mut s1 = Store::load(&path);
        let i1 = evaluate(s1.prior(), &c);
        s1.begin_run(&c, &i1).unwrap();
        // no mark_clean_shutdown

        // Run 2: detects unclean restart, persists the taint sticky.
        let mut s2 = Store::load(&path);
        let i2 = evaluate(s2.prior(), &c);
        assert_eq!(i2, Integrity::Tainted(TaintReason::UncleanRestart));
        s2.begin_run(&c, &i2).unwrap();
        s2.mark_clean_shutdown().unwrap(); // even a clean shutdown now...

        // Run 3: ...still tainted, because the marker is sticky (Persisted).
        let mut s3 = Store::load(&path);
        assert!(s3.taint_reason().is_some());
        assert_eq!(
            evaluate(s3.prior(), &c),
            Integrity::Tainted(TaintReason::Persisted)
        );

        // Operator acknowledges.
        s3.clear().unwrap();

        // Run 4: clean again.
        let s4 = Store::load(&path);
        assert!(s4.taint_reason().is_none());
        assert_eq!(evaluate(s4.prior(), &c), Integrity::Clean);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_then_redrift_retaints() {
        // WO-132@v1: collision-free scratch dir instead of the pid-only name.
        let dir = crate::test_scratch_dir("it3");
        let path = dir.join("state.toml");

        let c1 = ctx(1, vec![obj("/s", 1, 10)]);
        let mut s1 = Store::load(&path);
        let i1 = evaluate(s1.prior(), &c1);
        s1.begin_run(&c1, &i1).unwrap();
        s1.mark_clean_shutdown().unwrap();

        // Drift the inode; should taint.
        let c2 = ctx(1, vec![obj("/s", 1, 77)]);
        let mut s2 = Store::load(&path);
        let i2 = evaluate(s2.prior(), &c2);
        assert!(matches!(
            i2,
            Integrity::Tainted(TaintReason::ObjectDrift { .. })
        ));
        s2.begin_run(&c2, &i2).unwrap();
        s2.clear().unwrap(); // operator clears
        s2.mark_clean_shutdown().unwrap();

        // Re-drift again after clearing -> taints again.
        let c3 = ctx(1, vec![obj("/s", 1, 88)]);
        let s3 = Store::load(&path);
        assert!(matches!(
            evaluate(s3.prior(), &c3),
            Integrity::Tainted(TaintReason::ObjectDrift { .. })
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117 (a): a --protect-only run must not erase the baseline a later
    // policy run at the same key is compared against.
    #[test]
    fn protect_only_run_keeps_policy_baseline() {
        let (dir, path) = scratch_state("wo117a");
        assert_eq!(
            cycle(&path, &policy_ctx(Some(policy(KEY, "A")))),
            Integrity::Clean
        );
        assert_eq!(cycle(&path, &policy_ctx(None)), Integrity::Clean);
        assert_eq!(
            cycle(&path, &policy_ctx(Some(policy(KEY, "B")))),
            Integrity::Tainted(TaintReason::PolicyChanged {
                key: KEY.to_string(),
                prior_digest: "A".to_string(),
                now_digest: "B".to_string(),
            })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117 (b): the state file is host-global; two projects with unchanged
    // policies must be able to alternate without ever tainting.
    #[test]
    fn alternating_unchanged_projects_stay_clean() {
        let (dir, path) = scratch_state("wo117b");
        for (key, digest) in [
            ("/proj-a", "A"),
            ("/proj-b", "B"),
            ("/proj-a", "A"),
            ("/proj-b", "B"),
            ("/proj-a", "A"),
        ] {
            assert_eq!(
                cycle(&path, &policy_ctx(Some(policy(key, digest)))),
                Integrity::Clean,
                "{key} must stay clean"
            );
        }
        let prior = Store::load(&path);
        assert_eq!(prior.prior().unwrap().policies.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117 (c): discovery is keyed by the directory searched, so a
    // Bulwark.toml appearing beside bulwark.toml compares against one baseline.
    #[test]
    fn discovery_key_is_the_directory_not_the_file_name() {
        let (dir, _) = scratch_state("wo117c");
        let lower = PolicySource::Discovered {
            dir: dir.clone(),
            file: Some(dir.join("bulwark.toml")),
        };
        let upper = PolicySource::Discovered {
            dir: dir.clone(),
            file: Some(dir.join("Bulwark.toml")),
        };
        assert_eq!(lower.key().unwrap(), upper.key().unwrap());
        assert_eq!(
            lower.key().unwrap(),
            std::fs::canonicalize(&dir).unwrap().display().to_string()
        );
        let mut prior = clean_prior(1, vec![]);
        prior.policies = vec![file_record(&lower, b"protected = []\n")];
        let c = RunContext {
            policy: Some(file_record(&upper, b"protected = [\"/x\"]\n")),
            objects: vec![],
        };
        assert!(matches!(
            evaluate(Some(&prior), &c),
            Integrity::Tainted(TaintReason::PolicyChanged { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117 (d): a directory with no policy file records the built-in marker,
    // so a file created there later is a change, not a first sighting.
    #[test]
    fn file_appearing_after_builtin_baseline_taints() {
        let (dir, path) = scratch_state("wo117d");
        let builtin = PolicySource::Discovered {
            dir: dir.clone(),
            file: None,
        };
        let created = PolicySource::Discovered {
            dir: dir.clone(),
            file: Some(dir.join("Bulwark.toml")),
        };
        assert_eq!(builtin.key().unwrap(), created.key().unwrap());
        assert_ne!(builtin.label(), created.label());
        let baseline = PolicyRecord::builtin(&builtin).unwrap();
        assert_eq!(cycle(&path, &policy_ctx(Some(baseline))), Integrity::Clean);
        let now = file_record(&created, b"[protected]\nprompt = [\"/agent\"]\n");
        assert!(matches!(
            cycle(&path, &policy_ctx(Some(now))),
            Integrity::Tainted(TaintReason::PolicyChanged { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117 (R3): the no-file marker is a fixed word, never a hash, so a
    // bulwark upgrade that changes the default profile taints nothing.
    #[test]
    fn builtin_record_digest_is_marker() {
        let (dir, _) = scratch_state("wo117r3");
        let builtin = PolicySource::Discovered {
            dir: dir.clone(),
            file: None,
        };
        let record = PolicyRecord::builtin(&builtin).unwrap();
        assert_eq!(record.digest, BUILTIN_POLICY_DIGEST);
        assert_eq!(record.digest, "builtin");
        assert_eq!((record.dev, record.ino), (0, 0));
        assert_eq!(record.source, "builtin:default");
        assert_ne!(record.digest, sha256_hex(b"builtin"));
        assert_eq!(
            sha256_hex(b"").len(),
            64,
            "a file digest can never equal the marker"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117 (R2): a file-backed source whose identity cannot be resolved is an
    // error naming the path, never a record with a made-up key or 0:0 identity.
    #[test]
    fn unresolvable_policy_source_is_an_error() {
        let (dir, _) = scratch_state("wo117r2");
        let missing = dir.join("missing").join("Bulwark.toml");
        let explicit = PolicySource::Explicit(missing.clone());
        let err = explicit.key().unwrap_err().to_string();
        assert!(err.contains(&missing.display().to_string()), "{err}");
        let gone = dir.join("gone");
        let discovered = PolicySource::Discovered {
            dir: gone.clone(),
            file: None,
        };
        let err = PolicyRecord::builtin(&discovered).unwrap_err().to_string();
        assert!(err.contains(&gone.display().to_string()), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117 (R1): the record describes the bytes read from the open handle,
    // and the identity comes from that same handle.
    #[test]
    fn file_record_digest_matches_bytes_read() {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let (dir, _) = scratch_state("wo117r1");
        let file = dir.join("Bulwark.toml");
        let bytes = b"[protected]\nprompt = [\"/one\"]\n";
        std::fs::write(&file, bytes).unwrap();
        let source = PolicySource::Explicit(file.clone());
        let mut handle = std::fs::File::open(&file).unwrap();
        let meta = handle.metadata().unwrap();
        let mut read = Vec::new();
        handle.read_to_end(&mut read).unwrap();
        let record = PolicyRecord::from_file(&source, &meta, &read).unwrap();
        assert_eq!(record.digest, sha256_hex(bytes));
        assert_eq!((record.dev, record.ino), (meta.dev(), meta.ino()));
        assert_ne!(record.ino, 0);
        assert_eq!(record.key, source.key().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117 (e): editors rename-replace, so only the digest is compared; a
    // byte-identical rewrite with a new inode is clean.
    #[test]
    fn byte_identical_rewrite_is_clean() {
        let (dir, _) = scratch_state("wo117e");
        let file = dir.join("Bulwark.toml");
        let source = PolicySource::Explicit(file.clone());
        let before = file_record(&source, b"same bytes\n");
        std::fs::remove_file(&file).unwrap();
        let after = file_record(&source, b"same bytes\n");
        assert_eq!(before.digest, after.digest);
        let mut prior = clean_prior(1, vec![]);
        prior.policies = vec![before];
        let c = RunContext {
            policy: Some(PolicyRecord {
                ino: 999_999,
                ..after
            }),
            objects: vec![],
        };
        assert_eq!(evaluate(Some(&prior), &c), Integrity::Clean);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117 (f): a key never seen before has no baseline; it is recorded, not
    // tainted (mirrors new_protected_path_alone_is_not_drift).
    #[test]
    fn first_observation_of_a_key_is_clean() {
        let (dir, path) = scratch_state("wo117f");
        assert_eq!(
            cycle(&path, &policy_ctx(Some(policy("/proj-a", "A")))),
            Integrity::Clean
        );
        assert_eq!(
            cycle(&path, &policy_ctx(Some(policy("/proj-b", "Z")))),
            Integrity::Clean
        );
        let keys: Vec<String> = Store::load(&path)
            .prior()
            .unwrap()
            .policies
            .iter()
            .map(|p| p.key.clone())
            .collect();
        assert_eq!(keys, vec!["/proj-a".to_string(), "/proj-b".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117 (g): a pre-digest state file still loads (its stale policy_epoch
    // key is ignored) and its sticky taint still outranks everything.
    #[test]
    fn legacy_state_file_keeps_sticky_taint() {
        let (dir, path) = scratch_state("wo117g");
        std::fs::write(
            &path,
            "generation = 3\nclean_shutdown = true\npolicy_epoch = 1\n\
             tainted = \"object-identity drift on /s: dev/ino 1:10 -> 1:11\"\n\n\
             [[objects]]\npath = \"/s\"\ndev = 1\nino = 11\n",
        )
        .unwrap();
        let store = Store::load(&path);
        let prior = store.prior().expect("legacy state must load, not reset");
        assert_eq!(prior.generation, 3);
        assert!(prior.policies.is_empty());
        assert_eq!(
            evaluate(Some(prior), &policy_ctx(Some(policy(KEY, "A")))),
            Integrity::Tainted(TaintReason::Persisted)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-117: the digest is plain sha256 of the policy bytes.
    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // WO-117: an explicit --policy is keyed by its canonical path.
    #[test]
    fn explicit_policy_key_is_canonical_path() {
        let (dir, _) = scratch_state("wo117h");
        let file = dir.join("policy.toml");
        std::fs::write(&file, b"x\n").unwrap();
        let source = PolicySource::Explicit(file.clone());
        assert_eq!(
            source.key().unwrap(),
            std::fs::canonicalize(&file).unwrap().display().to_string()
        );
        let record = file_record(&source, b"x\n");
        assert_eq!(record.key, source.key().unwrap());
        assert_ne!(record.ino, 0, "inode of an existing file is recorded");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
