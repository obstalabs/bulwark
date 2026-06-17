//! Integrity circuit-breaker.
//!
//! Bulwark's fanotify gate fails *open* on hard supervisor death: a held
//! permission event is released by the kernel as allowed when the supervisor is
//! `SIGKILL`ed or crashes. That leak is inherent and cannot be retroactively
//! denied. This module does not try to fix it — it bounds the blast radius
//! *after* recovery.
//!
//! It records the integrity context of each run (a monotonic generation, a
//! clean-shutdown marker, the policy epoch, and the identity of every protected
//! object) in a small persistent state file. On the next run it detects two
//! failure signals:
//!
//! 1. **Unclean restart** — the previous run never wrote its clean-shutdown
//!    marker (it was killed or crashed mid-flight, while events may have been
//!    outstanding).
//! 2. **Object-identity drift** — a protected path now resolves to a different
//!    `(dev, ino)`, or the policy epoch changed, since the last recorded run.
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

/// The integrity context of the run being started: the policy epoch in force and
/// the identity of every protected object resolved at launch.
#[derive(Debug, Clone)]
pub struct RunContext {
    pub policy_epoch: u64,
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
    /// The policy epoch changed since the last run.
    PolicyEpochChanged { was: u64, now: u64 },
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
            TaintReason::PolicyEpochChanged { was, now } => {
                format!("policy epoch changed: {was} -> {now}")
            }
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
    pub policy_epoch: u64,
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

    // The policy epoch changed under us.
    if prior.policy_epoch != current.policy_epoch {
        return Integrity::Tainted(TaintReason::PolicyEpochChanged {
            was: prior.policy_epoch,
            now: current.policy_epoch,
        });
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
        self.state = Some(State {
            generation,
            clean_shutdown: false,
            policy_epoch: ctx.policy_epoch,
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

    fn ctx(epoch: u64, objects: Vec<ObjId>) -> RunContext {
        RunContext {
            policy_epoch: epoch,
            objects,
        }
    }

    fn clean_prior(epoch: u64, objects: Vec<ObjId>) -> State {
        State {
            generation: 1,
            clean_shutdown: true,
            policy_epoch: epoch,
            objects,
            tainted: None,
        }
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

    #[test]
    fn changed_policy_epoch_taints() {
        let prior = clean_prior(1, vec![obj("/s", 1, 10)]);
        let c = ctx(2, vec![obj("/s", 1, 10)]);
        assert_eq!(
            evaluate(Some(&prior), &c),
            Integrity::Tainted(TaintReason::PolicyEpochChanged { was: 1, now: 2 })
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
        let dir = std::env::temp_dir().join(format!("bulwark-it-{}", std::process::id()));
        let path = dir.join("state.toml");
        let _ = std::fs::remove_dir_all(&dir);

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
        let dir = std::env::temp_dir().join(format!("bulwark-it2-{}", std::process::id()));
        let path = dir.join("state.toml");
        let _ = std::fs::remove_dir_all(&dir);

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
        let dir = std::env::temp_dir().join(format!("bulwark-it3-{}", std::process::id()));
        let path = dir.join("state.toml");
        let _ = std::fs::remove_dir_all(&dir);

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
}
