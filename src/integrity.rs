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

use std::{
    ffi::{CString, OsString},
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default location of the persistent state file. Root-owned: the gate already
/// runs as root. Deliberately NOT under `$XDG_RUNTIME_DIR`, which is wiped on
/// reboot — that would silently erase taint across a power cycle.
pub const DEFAULT_STATE_PATH: &str = "/var/lib/bulwark/state.toml";

// WO-151@v1: produce numeric, process-monotonic suffixes for evidence and temp files.
static STATE_FILE_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// Identity of one protected object at decision time. The pair `(dev, ino)` is
/// the same identity the gate decides by; `path` is how the object was named so
/// drift can be reported meaningfully.
///
/// WO-130@v1: `(dev, ino)` alone cannot tell a delete-and-recreate apart: ext4
/// routinely hands the freed inode number straight back, so a swapped file
/// looked unchanged. `generation` is the kernel's per-inode version
/// (`FS_IOC_GETVERSION` on Linux, `st_gen` on macOS as root), bumped on reuse,
/// the same disambiguator the allow-list grant keys carry. `None` means the
/// filesystem or platform reports none, or the record predates this field:
/// such a record compares on `(dev, ino)` only, and is rewritten with the
/// generation on the run that reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjId {
    pub path: String,
    pub dev: u64,
    pub ino: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
}

/// WO-130@v1: the generation of the object at `path`, through the same
/// `FS_IOC_GETVERSION` read the allow-list snapshot uses. The path is opened
/// read-only and FOLLOWS a top-level symlink to its target, so it matches
/// `ProtectedSet::resolve` (which resolves via `fs::metadata`, i.e. follows).
/// A directory opens too. `None` when the open or the ioctl fails.
#[cfg(target_os = "linux")]
pub fn generation_of(path: &std::path::Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: c is a valid NUL-terminated path. No O_NOFOLLOW: the top-level
    // symlink is followed so the generation read is of the object actually
    // protected (its target), exactly as `fs::metadata` resolves it.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return None;
    }
    let g = crate::allowlist::fs_generation_fd(fd);
    // SAFETY: fd was opened just above and is not used after close.
    unsafe { libc::close(fd) };
    g
}

// WO-117: where a run's policy came from. The key decides which baseline the
// digest is compared against: an explicit file by its canonical path, an
// auto-discovered one by the directory searched (both file-name casings share
// it, so a Bulwark.toml appearing beside bulwark.toml is a change, not a new
// project), and a directory with no file still gets a record so a file created
// there later is a change too.
// WO-117@v1: key policy history by the file or discovery directory used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// `--policy <FILE>`.
    Explicit(PathBuf),
    /// The cwd search over the known policy file names; `file` is what it found.
    Discovered { dir: PathBuf, file: Option<PathBuf> },
}

// WO-117@v1: derive stable policy keys and audit labels from one source.
impl PolicySource {
    /// The history key. Canonical so symlinks and `./` spellings collapse.
    // WO-117 (R2): fail closed. A key that cannot be resolved would either
    // invent a fresh baseline or collide with another; refuse the run instead.
    // WO-117@v1: refuse policy identities that cannot be canonicalized.
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
    // WO-117@v1: identify the exact policy file backing this run.
    pub fn path(&self) -> Option<&Path> {
        match self {
            PolicySource::Explicit(path) => Some(path.as_path()),
            PolicySource::Discovered { file, .. } => file.as_deref(),
        }
    }

    /// Audit-safe description of what was digested.
    // WO-117@v1: label policy evidence without exposing policy contents.
    pub fn label(&self) -> String {
        match self.path() {
            Some(path) => format!("file:{}", path.display()),
            None => "builtin:default".to_string(),
        }
    }
}

// WO-117: one entry of the keyed policy history. Only `digest` is compared;
// `dev`/`ino` are recorded for the audit line because editors rename-replace.
// WO-117@v1: persist the keyed policy digest and audit identity.
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

// WO-117@v1: construct policy records from enforced bytes or the built-in marker.
impl PolicyRecord {
    /// Record a file-backed policy from the handle it was read through: the
    /// identity comes from that handle's metadata and the digest from the bytes
    /// read from it, so the record describes exactly the bytes the run parsed.
    // WO-117 (R1): no second stat or read of the path, and no identity fallback.
    // WO-117@v1: bind the policy digest and identity to one open handle.
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
    // WO-117@v1: baseline discovery directories that use the built-in policy.
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
// WO-117@v1: evaluate policy and protected-object state as one run context.
#[derive(Debug, Clone)]
pub struct RunContext {
    pub policy: Option<PolicyRecord>,
    pub objects: Vec<ObjId>,
}

// WO-13@v1: preserve the concrete reason an integrity check tainted a run.
/// Why a run is tainted. Carried into the audit receipt so the operator sees the
/// concrete reason, not just a flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintReason {
    // WO-151@v1: never mistake unreadable or malformed persisted state for first use.
    /// The integrity state could not be trusted and was preserved for inspection.
    UncleanState(String),
    /// The previous run did not record a clean shutdown.
    UncleanRestart,
    /// A protected object's identity changed since the last run.
    ObjectDrift {
        path: String,
        was: (u64, u64),
        now: (u64, u64),
        // WO-130@v1: the generations compared, so a same-inode swap is
        // readable in the receipt (dev/ino alone would print as unchanged).
        was_gen: Option<u64>,
        now_gen: Option<u64>,
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

// WO-13@v1: render integrity failures without exposing protected content.
impl TaintReason {
    /// One-line, audit-safe description (no file content, only identity).
    // WO-117@v1: describe policy digest drift without exposing policy bytes.
    // WO-130@v1: include inode generation when object identity changes.
    pub fn describe(&self) -> String {
        match self {
            TaintReason::UncleanState(reason) => reason.clone(),
            TaintReason::UncleanRestart => "unclean restart (no clean-shutdown marker)".to_string(),
            TaintReason::ObjectDrift {
                path,
                was,
                now,
                was_gen,
                now_gen,
            } => {
                let show = |g: &Option<u64>| g.map_or("?".to_string(), |g| g.to_string());
                format!(
                    "object-identity drift on {path}: dev/ino/gen {}:{}:{} -> {}:{}:{}",
                    was.0,
                    was.1,
                    show(was_gen),
                    now.0,
                    now.1,
                    show(now_gen)
                )
            }
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

// WO-13@v1: distinguish clean runs from runs requiring operator acknowledgement.
/// Verdict of an integrity evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Integrity {
    Clean,
    Tainted(TaintReason),
}

// WO-13@v1: expose whether an integrity evaluation activated tainted mode.
impl Integrity {
    // WO-13@v1: identify the tainted result used to tighten consent behavior.
    pub fn is_tainted(&self) -> bool {
        matches!(self, Integrity::Tainted(_))
    }
}

// WO-13@v1: persist run identity, shutdown state, and sticky integrity taint.
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

// WO-13@v1: detect unclean restarts and protected-object identity drift.
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
    if let Some(reason) = &prior.tainted {
        // WO-151@v1: retain the specific unclean-state reason across restarts.
        if reason.starts_with("unclean-state:") {
            return Integrity::Tainted(TaintReason::UncleanState(reason.clone()));
        }
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
    // WO-130@v1: or to the same inode number with a different generation, which
    // is a delete-and-recreate the number alone cannot show. A generation is
    // only compared when both runs have one; a record written before this
    // field, or a filesystem that reports none, compares on (dev, ino) alone.
    for now in &current.objects {
        if let Some(was) = prior.objects.iter().find(|o| o.path == now.path) {
            let gen_drift =
                matches!((was.generation, now.generation), (Some(a), Some(b)) if a != b);
            if was.dev != now.dev || was.ino != now.ino || gen_drift {
                return Integrity::Tainted(TaintReason::ObjectDrift {
                    path: now.path.clone(),
                    was: (was.dev, was.ino),
                    now: (now.dev, now.ino),
                    was_gen: was.generation,
                    now_gen: now.generation,
                });
            }
        }
    }

    Integrity::Clean
}

// WO-13@v1: mediate all reads and writes of persistent integrity state.
/// Owns the persistent state file and mediates reads/writes to it.
pub struct Store {
    path: PathBuf,
    /// The prior recorded state. `None` on the first run (no file yet), so it is
    /// never mistaken for an unclean restart.
    state: Option<State>,
    // WO-151@v1: prevent a failed evidence rename from being overwritten later.
    save_blocked: Option<String>,
}

// WO-151@v1: make each generated filename suffix a unique numeric timestamp.
fn next_state_file_timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64;
    let mut prior = STATE_FILE_TIMESTAMP.load(Ordering::Relaxed);
    loop {
        let next = now.max(prior.saturating_add(1));
        match STATE_FILE_TIMESTAMP.compare_exchange_weak(
            prior,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(actual) => prior = actual,
        }
    }
}

// WO-151@v1: pin state renames and replacements to the opened parent directory.
fn open_state_parent(path: &Path) -> Result<(File, PathBuf, OsString)> {
    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("state path {} has no file name", path.display()))?
        .to_os_string();
    let parent_c = CString::new(parent.as_os_str().as_bytes())
        .with_context(|| format!("state directory {} contains a NUL byte", parent.display()))?;
    // SAFETY: parent_c is NUL-terminated; the returned descriptor is immediately
    // owned by File and remains open while all relative operations run.
    let fd = unsafe {
        libc::open(
            parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot open state directory {}", parent.display()));
    }
    // SAFETY: fd is a newly opened descriptor owned by this File.
    Ok((unsafe { File::from_raw_fd(fd) }, parent, name))
}

// WO-151@v1: rename damaged evidence through a pinned directory descriptor.
fn preserve_damaged_state(path: &Path) -> Result<PathBuf> {
    let (dir, parent, name) = open_state_parent(path)?;
    let mut backup_bytes = name.as_bytes().to_vec();
    backup_bytes.extend_from_slice(format!(".corrupt-{}", next_state_file_timestamp()).as_bytes());
    let backup_name = OsString::from_vec(backup_bytes);
    let name_c = CString::new(name.as_bytes()).context("state file name contains a NUL byte")?;
    let backup_c =
        CString::new(backup_name.as_bytes()).context("state backup name contains a NUL byte")?;
    // SAFETY: both names are NUL-terminated and relative to the live directory fd.
    let rc = unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            name_c.as_ptr(),
            dir.as_raw_fd(),
            backup_c.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "cannot preserve damaged state {} as {}",
                path.display(),
                parent.join(&backup_name).display()
            )
        });
    }
    dir.sync_all().with_context(|| {
        format!(
            "cannot sync state directory {} after preserving damaged state",
            parent.display()
        )
    })?;
    Ok(parent.join(backup_name))
}

// WO-151@v1: replace state only after a durable same-directory temporary write.
fn atomic_write_state(path: &Path, body: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create state dir {}", parent.display()))?;
    }
    let (dir, parent, name) = open_state_parent(path)?;
    let mut temp_bytes = b".".to_vec();
    temp_bytes.extend_from_slice(name.as_bytes());
    temp_bytes.extend_from_slice(format!(".tmp-{}", next_state_file_timestamp()).as_bytes());
    let temp_name = OsString::from_vec(temp_bytes);
    let temp_c =
        CString::new(temp_name.as_bytes()).context("state temp name contains a NUL byte")?;
    let name_c = CString::new(name.as_bytes()).context("state file name contains a NUL byte")?;
    // SAFETY: temp_c is NUL-terminated and openat is pinned to the parent fd.
    let temp_fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            temp_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )
    };
    if temp_fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "cannot create temporary state file {}",
                parent.join(&temp_name).display()
            )
        });
    }
    // SAFETY: temp_fd is newly opened and ownership transfers to temp.
    let mut temp = unsafe { File::from_raw_fd(temp_fd) };
    let result = (|| -> Result<()> {
        temp.write_all(body)
            .context("cannot write temporary integrity state")?;
        temp.sync_all()
            .context("cannot sync temporary integrity state")?;
        drop(temp);
        // SAFETY: both names are NUL-terminated and relative to the same live fd.
        let rc = unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temp_c.as_ptr(),
                dir.as_raw_fd(),
                name_c.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("cannot replace state file {}", path.display()));
        }
        dir.sync_all().with_context(|| {
            format!(
                "cannot sync state directory {} after replacing state",
                parent.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        // SAFETY: temp_c is relative to dir; failure is best-effort cleanup only.
        unsafe { libc::unlinkat(dir.as_raw_fd(), temp_c.as_ptr(), 0) };
    }
    result
}

// WO-151@v1: synthesize sticky taint only after damaged evidence is set aside.
fn damaged_state(path: PathBuf, cause: &dyn std::fmt::Display) -> Store {
    let reason = format!(
        "unclean-state: integrity state {} was unreadable or invalid",
        path.display()
    );
    let (save_blocked, preserved) = match preserve_damaged_state(&path) {
        Ok(backup) => (None, Some(backup)),
        Err(error) => (
            Some(format!(
                "damaged integrity state {} was not replaced because its evidence could not be preserved: {error:#}",
                path.display()
            )),
            None,
        ),
    };
    match preserved {
        Some(backup) => eprintln!(
            "[bulwark] INTEGRITY TAINTED: state file {} is unreadable or invalid ({cause}); preserved as {}",
            path.display(),
            backup.display()
        ),
        None => eprintln!(
            "[bulwark] INTEGRITY TAINTED: state file {} is unreadable or invalid ({cause}); evidence preservation failed, refusing to replace it",
            path.display()
        ),
    }
    Store {
        path,
        state: Some(State {
            tainted: Some(reason),
            ..State::default()
        }),
        save_blocked,
    }
}

// WO-13@v1: manage the integrity state lifecycle around each supervised run.
impl Store {
    // WO-13@v1: load prior integrity state or establish a first-run baseline.
    /// Load the state file, or start fresh only if it does not exist. Any other
    /// read or parse failure starts tainted and preserves the original evidence.
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let state = match std::fs::read(&path) {
            Ok(bytes) => match std::str::from_utf8(&bytes) {
                Ok(text) => match toml::from_str::<State>(text) {
                    Ok(state) => Some(state),
                    Err(error) => return damaged_state(path, &error),
                },
                Err(error) => return damaged_state(path, &error),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::symlink_metadata(&path) {
                    Err(meta_error) if meta_error.kind() == std::io::ErrorKind::NotFound => None,
                    _ => return damaged_state(path, &error),
                }
            }
            Err(error) => return damaged_state(path, &error),
        };
        Store {
            path,
            state,
            save_blocked: None,
        }
    }

    // WO-13@v1: expose the prior state used by the pure integrity evaluation.
    /// The prior recorded state, for `evaluate`. `None` on the first run.
    pub fn prior(&self) -> Option<&State> {
        self.state.as_ref()
    }

    // WO-13@v1: persist a new run before the supervised process starts.
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

    // WO-13@v1: mark only normally completed supervision as clean shutdown.
    /// Record a clean shutdown. Called by the supervisor on any normal exit
    /// (child exited or a trapped termination signal). A hard kill skips this, so
    /// the next run sees an unclean restart.
    pub fn mark_clean_shutdown(&mut self) -> Result<()> {
        if let Some(s) = self.state.as_mut() {
            s.clean_shutdown = true;
        }
        self.save()
    }

    // WO-13@v1: expose sticky taint until the operator acknowledges it.
    /// The sticky taint description, if any.
    pub fn taint_reason(&self) -> Option<&str> {
        self.state.as_ref().and_then(|s| s.tainted.as_deref())
    }

    // WO-13@v1: clear only the acknowledged taint while retaining the baseline.
    /// Clear the taint marker only (what `bulwark reset` calls). Narrow by
    /// design: it does not reset the generation, the recorded objects, or the
    /// clean marker — only the operator acknowledgement.
    pub fn clear(&mut self) -> Result<()> {
        if let Some(s) = self.state.as_mut() {
            s.tainted = None;
        }
        self.save()
    }

    // WO-13@v1: persist the current integrity record before returning to callers.
    /// Persist the current state (no-op if there is nothing recorded yet),
    /// creating the parent directory if needed.
    fn save(&self) -> Result<()> {
        if let Some(reason) = &self.save_blocked {
            anyhow::bail!(reason.clone());
        }
        let state = match self.state.as_ref() {
            Some(s) => s,
            None => return Ok(()),
        };
        let body = toml::to_string(state).context("serialize integrity state")?;
        atomic_write_state(&self.path, body.as_bytes())
            .with_context(|| format!("cannot write state file {}", self.path.display()))
    }
}

// WO-13@v1: verify restart, drift, persistence, and taint precedence.
#[cfg(test)]
mod tests {
    use super::*;

    // WO-130@v1: build object identities without a reported inode generation.
    fn obj(path: &str, dev: u64, ino: u64) -> ObjId {
        ObjId {
            path: path.to_string(),
            dev,
            ino,
            generation: None,
        }
    }

    // WO-130@v1: an object with a known generation.
    fn obj_gen(path: &str, dev: u64, ino: u64, generation: u64) -> ObjId {
        ObjId {
            generation: Some(generation),
            ..obj(path, dev, ino)
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

    // WO-117@v1: build a clean keyed-policy baseline for integrity tests.
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
    // WO-117@v1: build test records from the same handle that supplies policy bytes.
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

    // WO-151@v1: locate evidence preserved beside a damaged state file.
    fn corrupt_backups(dir: &Path) -> Vec<PathBuf> {
        let mut paths = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("state.toml.corrupt-"))
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    // WO-151@v1: prove malformed state bytes taint and survive byte-for-byte.
    fn assert_corrupt_state_is_tainted_and_preserved(tag: &str, bytes: &[u8]) {
        let (dir, path) = scratch_state(tag);
        std::fs::write(&path, bytes).unwrap();
        let mut store = Store::load(&path);
        let current = ctx(1, vec![]);
        let verdict = evaluate(store.prior(), &current);
        assert!(
            matches!(&verdict, Integrity::Tainted(TaintReason::UncleanState(reason)) if reason.starts_with("unclean-state:")),
            "damaged state loaded as {verdict:?}"
        );
        let backups = corrupt_backups(&dir);
        assert_eq!(backups.len(), 1, "preserved evidence: {backups:?}");
        assert_eq!(std::fs::read(&backups[0]).unwrap(), bytes);
        assert!(!path.exists(), "damaged state was not renamed aside");
        store.begin_run(&current, &verdict).unwrap();
        assert_eq!(std::fs::read(&backups[0]).unwrap(), bytes);
        let replacement = Store::load(&path);
        assert!(matches!(
            evaluate(replacement.prior(), &current),
            Integrity::Tainted(TaintReason::UncleanState(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-151@v1: preserve a truncated TOML state and start tainted.
    #[test]
    fn corrupt_or_unreadable_state_truncated_toml() {
        assert_corrupt_state_is_tainted_and_preserved(
            "wo151-truncated",
            b"generation = 1\nclean_shutdown = ",
        );
    }

    // WO-151@v1: preserve non-UTF-8 state bytes and start tainted.
    #[test]
    fn corrupt_or_unreadable_state_garbage_bytes() {
        assert_corrupt_state_is_tainted_and_preserved("wo151-garbage", &[0xff, 0xfe, 0xfd, 0x00]);
    }

    // WO-151@v1: treat a root-resistant directory read error as unclean state.
    #[test]
    fn corrupt_or_unreadable_state_directory_path() {
        let (dir, path) = scratch_state("wo151-directory");
        std::fs::create_dir(&path).unwrap();
        let mut store = Store::load(&path);
        let current = ctx(1, vec![]);
        let verdict = evaluate(store.prior(), &current);
        assert!(
            matches!(&verdict, Integrity::Tainted(TaintReason::UncleanState(reason)) if reason.starts_with("unclean-state:")),
            "directory state loaded as {verdict:?}"
        );
        let backups = corrupt_backups(&dir);
        assert_eq!(backups.len(), 1, "preserved evidence: {backups:?}");
        assert!(backups[0].is_dir());
        assert!(!path.exists(), "unreadable state was not renamed aside");
        store.begin_run(&current, &verdict).unwrap();
        assert!(backups[0].is_dir());
        let replacement = Store::load(&path);
        assert!(matches!(
            evaluate(replacement.prior(), &current),
            Integrity::Tainted(TaintReason::UncleanState(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-151@v1: keep an absent state file as the only clean first-run case.
    #[test]
    fn absent_state_is_a_clean_first_run() {
        let (dir, path) = scratch_state("wo151-absent");
        let store = Store::load(&path);
        assert_eq!(evaluate(store.prior(), &ctx(1, vec![])), Integrity::Clean);
        assert!(corrupt_backups(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-151@v1: prove each save replaces the state atomically via a new inode.
    #[test]
    fn state_save_replaces_the_file_atomically() {
        use std::os::unix::fs::MetadataExt;

        let (dir, path) = scratch_state("wo151-atomic");
        let mut store = Store::load(&path);
        let current = ctx(1, vec![]);
        let verdict = evaluate(store.prior(), &current);
        store.begin_run(&current, &verdict).unwrap();
        let before = std::fs::metadata(&path).unwrap().ino();
        store.mark_clean_shutdown().unwrap();
        let after = std::fs::metadata(&path).unwrap().ino();
        assert_ne!(before, after, "state save rewrote the existing inode");
        assert!(
            std::fs::read_dir(&dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .all(|name| !name.to_string_lossy().contains(".tmp-")),
            "state save left a temporary file behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-151@v1: exercise EACCES only where chmod 000 makes the file unreadable.
    #[test]
    #[ignore = "requires a non-root uid; run explicitly"]
    fn eacces_state_file_starts_tainted_and_preserves_evidence() {
        use std::os::unix::fs::PermissionsExt;

        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "not exercised: root can read a mode-000 state file"
        );
        let bytes = b"unreadable-state-evidence";
        let (dir, path) = scratch_state("wo151-eacces");
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mut store = Store::load(&path);
        let current = ctx(1, vec![]);
        let verdict = evaluate(store.prior(), &current);
        assert!(
            matches!(&verdict, Integrity::Tainted(TaintReason::UncleanState(reason)) if reason.starts_with("unclean-state:")),
            "EACCES state loaded as {verdict:?}"
        );
        let backups = corrupt_backups(&dir);
        assert_eq!(backups.len(), 1, "preserved evidence: {backups:?}");
        std::fs::set_permissions(&backups[0], std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(&backups[0]).unwrap(), bytes);
        store.begin_run(&current, &verdict).unwrap();
        assert_eq!(std::fs::read(&backups[0]).unwrap(), bytes);
        let replacement = Store::load(&path);
        assert!(matches!(
            evaluate(replacement.prior(), &current),
            Integrity::Tainted(TaintReason::UncleanState(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WO-13@v1: establish a clean baseline when no prior state exists.
    #[test]
    fn first_run_is_clean() {
        let c = ctx(1, vec![obj("/s", 1, 10)]);
        assert_eq!(evaluate(None, &c), Integrity::Clean);
    }

    // WO-13@v1: keep an unchanged identity clean after graceful shutdown.
    #[test]
    fn clean_shutdown_same_identity_is_clean() {
        let prior = clean_prior(1, vec![obj("/s", 1, 10)]);
        let c = ctx(1, vec![obj("/s", 1, 10)]);
        assert_eq!(evaluate(Some(&prior), &c), Integrity::Clean);
    }

    // WO-13@v1: taint a run when the prior clean-shutdown marker is absent.
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

    // WO-130@v1: treat a changed inode number as protected-object drift.
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
                was_gen: None,
                now_gen: None,
            })
        );
    }

    // WO-130@v1: the inode number came back after a delete-and-recreate; only
    // the generation shows the swap.
    #[test]
    fn same_inode_with_new_generation_is_object_drift() {
        let prior = clean_prior(1, vec![obj_gen("/s", 1, 10, 7)]);
        let c = ctx(1, vec![obj_gen("/s", 1, 10, 8)]);
        let verdict = evaluate(Some(&prior), &c);
        assert_eq!(
            verdict,
            Integrity::Tainted(TaintReason::ObjectDrift {
                path: "/s".to_string(),
                was: (1, 10),
                now: (1, 10),
                was_gen: Some(7),
                now_gen: Some(8),
            })
        );
        if let Integrity::Tainted(reason) = verdict {
            assert_eq!(
                reason.describe(),
                "object-identity drift on /s: dev/ino/gen 1:10:7 -> 1:10:8"
            );
        }
    }

    // WO-130@v1: an unchanged object with the same generation stays clean, and
    // a generation known on only one side (a pre-generation state file, or a
    // filesystem without one) is not drift by itself.
    #[test]
    fn generation_is_compared_only_when_both_sides_have_one() {
        let same = clean_prior(1, vec![obj_gen("/s", 1, 10, 7)]);
        assert_eq!(
            evaluate(Some(&same), &ctx(1, vec![obj_gen("/s", 1, 10, 7)])),
            Integrity::Clean
        );
        let legacy = clean_prior(1, vec![obj("/s", 1, 10)]);
        assert_eq!(
            evaluate(Some(&legacy), &ctx(1, vec![obj_gen("/s", 1, 10, 7)])),
            Integrity::Clean
        );
        let now_unknown = clean_prior(1, vec![obj_gen("/s", 1, 10, 7)]);
        assert_eq!(
            evaluate(Some(&now_unknown), &ctx(1, vec![obj("/s", 1, 10)])),
            Integrity::Clean
        );
    }

    // WO-130@v1: a state file written before the generation field loads, and
    // a record with one round-trips.
    #[test]
    fn objid_generation_is_optional_in_the_state_file() {
        let legacy: ObjId = toml::from_str("path = \"/s\"\ndev = 1\nino = 10\n").unwrap();
        assert_eq!(legacy, obj("/s", 1, 10));
        let with_gen = obj_gen("/s", 1, 10, 7);
        let text = toml::to_string(&with_gen).unwrap();
        assert!(text.contains("generation = 7"), "{text}");
        assert_eq!(toml::from_str::<ObjId>(&text).unwrap(), with_gen);
        let text = toml::to_string(&obj("/s", 1, 10)).unwrap();
        assert!(!text.contains("generation"), "{text}");
    }

    // WO-13@v1: detect a protected object moving to another device.
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

    // WO-13@v1: keep taint sticky across otherwise clean restarts.
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

    // WO-13@v1: report an unclean restart before lower-priority drift.
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

    // WO-13@v1: avoid treating a newly protected path as identity drift.
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
    // WO-117@v1: retain keyed policy history across protect-only runs.
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
    // WO-117@v1: preserve independent policy baselines for alternating projects.
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
    // WO-117@v1: key discovered policy names by their shared directory.
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
    // WO-117@v1: detect a policy file appearing after a built-in baseline.
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
    // WO-117@v1: keep the built-in baseline stable across binary upgrades.
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
    // WO-117@v1: refuse policy sources whose stable identity cannot be resolved.
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
    // WO-117@v1: verify policy bytes and identity come from one handle.
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
    // WO-117@v1: compare policy content rather than rename-replaced inode identity.
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
    // WO-117@v1: record a new policy key without treating it as drift.
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
    // WO-117@v1: preserve sticky taint while loading legacy state.
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

    // WO-130@v1: generation_of must report the generation of the object ACTUALLY
    // protected. ProtectedSet resolves with fs::metadata, which follows a
    // top-level symlink to its target; generation_of must do the same, or a
    // symlinked protect entry records None and drift collapses to (dev, ino) —
    // the inode-reuse swap this WO exists to catch. On a filesystem that reports
    // generation (ext4) the link must equal the target's generation, not None.
    #[cfg(target_os = "linux")]
    #[test]
    fn generation_of_follows_a_top_level_symlink() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!(
            "bulwark-gen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        let link = dir.join("link");
        std::fs::write(&target, "x\n").unwrap();
        symlink(&target, &link).unwrap();

        let target_gen = generation_of(&target);
        let link_gen = generation_of(&link);
        // tmpfs never reports a generation (no FS_IOC_GETVERSION), so skip the
        // meaningful assertion there; on ext4 the target has one and the link
        // must resolve to the SAME one, not None.
        if let Some(tg) = target_gen {
            assert_eq!(
                link_gen,
                Some(tg),
                "a protected symlink must record its target's generation, not None"
            );
        } else {
            eprintln!(
                "generation_of_follows_a_top_level_symlink: filesystem under {} reports no \
                 generation; the follow behavior is not exercised here",
                std::env::temp_dir().display()
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
