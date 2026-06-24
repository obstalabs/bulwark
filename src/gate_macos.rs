//! macOS Endpoint Security `AUTH_OPEN` read gate.
//!
//! this is the macOS counterpart to the Linux fanotify gate. Rust keeps
//! policy resolution, child launch, and fail-closed supervision; a signed,
//! entitled Swift ES edge answers kernel `AUTH_OPEN` events by `(dev, ino)`.
//!
//! The child is forked in a stopped state. The ES edge must subscribe and write
//! its readiness marker before Rust sends `SIGCONT`, so the command is never run
//! before the kernel gate is live.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};

use crate::allowlist::AllowList;
use crate::consent::{ConsentRequest, Source, Verdict};
use crate::protect::{InodeKey, ProtectedSet};

const ES_EDGE_ENV: &str = "BULWARK_MACOS_ES_GATE";
const EDGE_READY_TIMEOUT: Duration = Duration::from_secs(10);
const EDGE_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Same public surface as the Linux gate.
pub enum GateMode<'a> {
    /// macOS currently supports the static deny-list path. Interactive
    /// consent is startup-seeded into the ES edge so AUTH_OPEN callbacks
    /// still answer from in-memory policy only.
    DenyList {
        protected: &'a ProtectedSet,
        consent: &'a mut dyn ConsentDecider,
    },
    AllowList {
        allow: &'a AllowList,
    },
}

/// Same public surface as the Linux gate. The ES edge reads pushed policy and
/// startup consent decisions from its config, then answers AUTH_OPEN from memory.
pub trait ConsentDecider {
    fn decide(&mut self, req: &ConsentRequest) -> (Verdict, Source);

    /// Receive the supervised tree's membership scope identifier, mirroring the
    /// Linux gate so the shared `CachingProvider` impl type-checks on every
    /// platform. macOS attributes the tree by the Endpoint Security PID set held
    /// in the supervisor (not a cgroup path), so the consent socket has no scope
    /// string to bind here yet and this is a no-op: socket membership stays the
    /// ancestry check. Wiring the ES PID set into the consent socket (the macOS
    /// analog of the cgroup fix) is tracked as a documented residual.
    fn bind_scope(&mut self, _scope_rel: Option<&str>) {}
}

pub(crate) fn shutdown_requested() -> bool {
    false
}

/// Credentials to drop the supervised child to before exec. The supervisor and
/// the Endpoint Security edge stay root; only the agent child becomes
/// unprivileged, so it cannot `SIGKILL` the edge and exploit the kernel's
/// allow-while-no-subscriber window on edge death. Attribution is by audit-token
/// PID ancestry, which the uid drop does not change.
#[derive(Clone, Copy)]
pub struct WorkerCreds {
    pub uid: u32,
    pub gid: u32,
}

/// Drop the calling process to `creds`, in the security-critical order:
/// supplementary groups, then gid, then uid. Returns `Err` on any failure — the
/// caller MUST NOT exec if this fails. Runs in the forked child before exec, so it
/// uses only raw libc calls (no allocation, no panics). Mirrors the Linux gate's
/// `drop_to`.
///
/// LIMITATION (honest): unlike Linux, macOS has no `PR_SET_NO_NEW_PRIVS`, so this
/// drop is NOT irreversible — a dropped agent that execs a setuid-root binary can
/// regain root, and a re-rooted agent could then `SIGKILL` the ES edge (re-opening
/// the edge-death fail-open window). The `setuid(0)`-must-fail check below proves
/// only that the *current* credentials cannot regain root. There is no macOS
/// primitive to ignore setuid bits on future execs; this residual is documented in
/// `docs/macos.md`. The mitigations that do hold: the agent runs unprivileged for
/// its own opens, and the ES membership set lives in the gate's memory (not an
/// agent-writable filesystem), so a re-rooted agent cannot rewrite tree membership
/// the way a Linux root agent can rewrite cgroup membership.
///
/// # Safety
/// Must be called in the child between `fork()` and `execvp()`.
unsafe fn drop_to(creds: WorkerCreds) -> std::result::Result<(), i32> {
    let groups = [creds.gid as libc::gid_t];
    if libc::setgroups(1, groups.as_ptr()) != 0 {
        return Err(libc::EPERM);
    }
    if libc::setgid(creds.gid as libc::gid_t) != 0 {
        return Err(libc::EPERM);
    }
    if libc::setuid(creds.uid as libc::uid_t) != 0 {
        return Err(libc::EPERM);
    }
    // The drop must be permanent for the *current* credentials: regaining root must
    // now fail. (macOS cannot also block setuid-bit exec — see the doc comment.)
    if libc::setuid(0) == 0 {
        return Err(libc::EPERM);
    }
    Ok(())
}

pub fn run(
    mode: GateMode,
    _mark_paths: &[PathBuf],
    receipts: Option<&Path>,
    command: &[String],
    worker: Option<WorkerCreds>,
) -> Result<i32> {
    if command.is_empty() {
        bail!("no command given");
    }
    if unsafe { libc::geteuid() } != 0 {
        bail!("macOS Endpoint Security gate must run as root");
    }
    if let Some(w) = worker {
        if w.uid == 0 {
            bail!("worker uid 0 is not a privilege drop");
        }
    }

    let policy = match mode {
        GateMode::DenyList { protected, consent } => {
            if protected.is_empty() {
                bail!("no protected inodes resolved — nothing to guard");
            }
            EdgePolicy::DenyList {
                protected,
                decisions: seed_denylist_decisions(protected, consent),
            }
        }
        GateMode::AllowList { allow } => {
            // replaces the former
            // "macOS allow-list/default-deny mode is not implemented yet"
            // fail-closed path with a pushed allow-list policy.
            EdgePolicy::AllowList { allow }
        }
    };

    let edge = edge_path()?;
    ensure_executable(&edge)?;

    let temp = GateTemp::new()?;
    let child = spawn_stopped(command, worker)?;
    let child_pid = child.pid;
    wait_until_stopped(child_pid).with_context(|| {
        let _ = kill_pid(child_pid, libc::SIGKILL);
        format!("child {child_pid} did not enter stopped launch state")
    })?;

    if let Err(err) = write_config(&temp.config, &policy, child_pid, receipts, &temp.ready) {
        let _ = kill_pid(child_pid, libc::SIGKILL);
        return Err(err);
    }

    let mut edge_child = match Command::new(&edge).arg(&temp.config).spawn() {
        Ok(child) => child,
        Err(err) => {
            let _ = kill_pid(child_pid, libc::SIGKILL);
            return Err(anyhow!(err)).with_context(|| format!("start ES edge {}", edge.display()));
        }
    };

    if let Err(err) = wait_for_ready(&temp.ready, &mut edge_child) {
        let _ = kill_pid(child_pid, libc::SIGKILL);
        let _ = terminate_edge(&mut edge_child);
        return Err(err);
    }

    match worker {
        Some(w) => eprintln!(
            "[bulwark] macOS ES gate live: supervising pid {child_pid} (uid={} gid={}): {}",
            w.uid,
            w.gid,
            command.join(" ")
        ),
        None => eprintln!(
            "[bulwark] macOS ES gate live: supervising pid {child_pid}: {}",
            command.join(" ")
        ),
    }
    kill_pid(child_pid, libc::SIGCONT).context("resume supervised child")?;
    let code = supervise(child_pid, &mut edge_child)?;
    terminate_edge(&mut edge_child)?;
    Ok(code)
}

/// Path inside the gate bundle to the edge executable, relative to a directory that
/// contains `bulwark_es_gate.app`.
const ES_EDGE_REL: &str = "bulwark_es_gate.app/Contents/MacOS/bulwark_es_gate";

/// Resolve the ES edge binary. Order:
///
/// 1. `BULWARK_MACOS_ES_GATE` if set (explicit override).
/// 2. Auto-discovery relative to the running CLI, so a packaged install (Homebrew,
///    release tarball) works with no environment setup. Tried in order:
///    `<bin>/../libexec/<rel>` (Homebrew: CLI in bin/, bundle in libexec/), then
///    `<bin>/../<rel>` (extracted tarball: bundle beside the binary), then
///    `<bin>/<rel>` (bundle in the same dir as the binary).
///
/// The first existing path wins; the env override always takes precedence.
/// Resolve the ES edge path (env override, then auto-discovery) without erroring —
/// for `doctor`, which reports presence rather than failing. `None` means neither the
/// env var nor discovery found an edge.
pub fn resolve_edge_path() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os(ES_EDGE_ENV) {
        return Some(PathBuf::from(value));
    }
    discover_edge()
}

fn edge_path() -> Result<PathBuf> {
    resolve_edge_path().ok_or_else(|| {
        anyhow!(
            "could not locate the Endpoint Security edge. It ships beside the CLI in a \
             packaged install; set {ES_EDGE_ENV} to override \
             (for example bulwark_es_gate.app/Contents/MacOS/bulwark_es_gate)"
        )
    })
}

/// Look for the gate bundle relative to the current executable. Returns the first
/// candidate that exists; `None` if discovery comes up empty (caller errors).
fn discover_edge() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // Canonicalize to resolve a Homebrew bin symlink to the real Cellar path.
    let exe = exe.canonicalize().unwrap_or(exe);
    let bin_dir = exe.parent()?;
    let candidates = [
        bin_dir.join("..").join("libexec").join(ES_EDGE_REL),
        bin_dir.join("..").join(ES_EDGE_REL),
        bin_dir.join(ES_EDGE_REL),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn ensure_executable(path: &Path) -> Result<()> {
    let meta = fs::metadata(path).with_context(|| format!("stat ES edge {}", path.display()))?;
    if !meta.is_file() {
        bail!("ES edge is not a file: {}", path.display());
    }
    if meta.permissions().mode() & 0o111 == 0 {
        bail!("ES edge is not executable: {}", path.display());
    }
    Ok(())
}

struct GateTemp {
    config: PathBuf,
    ready: PathBuf,
}

enum EdgePolicy<'a> {
    DenyList {
        protected: &'a ProtectedSet,
        decisions: EdgeDecisionSeeds,
    },
    // default-deny macOS gate policy pushed to the ES edge.
    AllowList {
        allow: &'a AllowList,
    },
}

#[derive(Default)]
struct EdgeDecisionSeeds {
    allow_once: Vec<InodeKey>,    // one-open operator grants
    allow_session: Vec<InodeKey>, // session-cache operator grants
}

impl GateTemp {
    fn new() -> Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base =
            std::env::temp_dir().join(format!("bulwark-macos-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&base)
            .with_context(|| format!("create macOS gate temp dir {}", base.display()))?;
        Ok(GateTemp {
            config: base.join("edge.conf"),
            ready: base.join("edge.ready"),
        })
    }
}

fn write_config(
    path: &Path,
    policy: &EdgePolicy<'_>,
    root_pid: libc::pid_t,
    receipts: Option<&Path>,
    ready: &Path,
) -> Result<()> {
    let mut body = String::new();
    push_config_line(&mut body, "root_pid", &root_pid.to_string())?;
    push_config_line(&mut body, "ready", &ready.display().to_string())?;
    if let Some(receipts) = receipts {
        push_config_line(&mut body, "receipts", &receipts.display().to_string())?;
    }
    match policy {
        EdgePolicy::DenyList {
            protected,
            decisions,
        } => {
            push_config_line(&mut body, "mode", "denylist")?;
            for key in protected.keys() {
                push_config_line(&mut body, "protected", &format!("{}:{}", key.dev, key.ino))?;
            }
            for key in &decisions.allow_once {
                push_config_line(&mut body, "allow_once", &format!("{}:{}", key.dev, key.ino))?;
            }
            for key in &decisions.allow_session {
                push_config_line(
                    &mut body,
                    "allow_session",
                    &format!("{}:{}", key.dev, key.ino),
                )?;
            }
        }
        EdgePolicy::AllowList { allow } => {
            push_config_line(&mut body, "mode", "allowlist")?;
            for glob in allow.base_globs() {
                push_config_line(&mut body, "allow_glob", glob)?;
            }
            // Grants are gated on inode identity, NOT a path-beneath grant root.
            // The prior `allow_root` rule allowed any object whose canonical path
            // sat under the grant directory, so a foreign secret hardlinked or
            // renamed into a granted path was allowed (B2 ported to macOS). The ES
            // edge already enforces an `allow_inode` membership set; we feed it the
            // launch snapshot of grant-glob-matching inodes so an inode that was
            // never genuinely under the grant is denied.
            for key in allow.grant_inode_keys() {
                push_config_line(
                    &mut body,
                    "allow_inode",
                    &format!("{}:{}", key.dev, key.ino),
                )?;
            }
        }
    }
    fs::write(path, body).with_context(|| format!("write ES edge config {}", path.display()))
}

fn push_config_line(body: &mut String, key: &str, value: &str) -> Result<()> {
    if value.contains('\n') || value.contains('\r') {
        bail!("ES edge config value for {key} contains a newline");
    }
    body.push_str(key);
    body.push('=');
    body.push_str(value);
    body.push('\n');
    Ok(())
}

// Superseded by inode-membership grants (`allow_inode`); retained for a possible
// recursive grant-root layer (the macOS analog of Linux move-in tracking).
#[allow(dead_code)]
struct AllowGrantRoot {
    dev: u64,        // root device identity
    ino: u64,        // root inode identity
    recursive: bool, // directory grants cover descendants
    path: PathBuf,   // canonical root path for the ES edge
}

#[allow(dead_code)]
fn resolve_allow_grant_roots(grants: &[String]) -> Result<Vec<AllowGrantRoot>> {
    let mut out = Vec::new();
    for grant in grants {
        let (root, recursive) = concrete_grant_root(grant)?;
        let root = root
            .canonicalize()
            .with_context(|| format!("resolve macOS allow grant {}", root.display()))?;
        let meta = fs::metadata(&root)
            .with_context(|| format!("metadata macOS allow grant {}", root.display()))?;
        out.push(AllowGrantRoot {
            dev: meta.dev(),
            ino: meta.ino(),
            recursive: recursive || meta.is_dir(),
            path: root,
        });
    }
    Ok(out)
}

#[allow(dead_code)]
fn concrete_grant_root(grant: &str) -> Result<(PathBuf, bool)> {
    let recursive = grant.ends_with("/**");
    let root = grant.strip_suffix("/**").unwrap_or(grant);
    if root.contains('*') || root.contains('?') || root.contains('[') {
        bail!("macOS allow grants must be concrete paths or trailing /** globs: {grant}");
    }
    if let Some(rest) = root.strip_prefix("~/") {
        let Some(home) = std::env::var_os("HOME") else {
            bail!("HOME is not set for macOS allow grant {grant}");
        };
        return Ok((PathBuf::from(home).join(rest), recursive));
    }
    Ok((PathBuf::from(root), recursive))
}

fn seed_denylist_decisions(
    protected: &ProtectedSet,
    consent: &mut dyn ConsentDecider,
) -> EdgeDecisionSeeds {
    let mut seeds = EdgeDecisionSeeds::default();
    for origin in protected.origins() {
        let req = ConsentRequest {
            pid: 0,
            key: origin.key,
            path: origin.path.clone(),
            ancestry: "bulwark macOS launch preflight".to_string(),
            reason: "protected inode requires a macOS edge startup verdict".to_string(),
        };
        let (verdict, _source) = consent.decide(&req);
        match verdict {
            Verdict::AllowOnce => seeds.allow_once.push(origin.key),
            Verdict::AllowSession => seeds.allow_session.push(origin.key),
            Verdict::Deny | Verdict::DenyForever => {}
        }
    }
    seeds
}

struct StoppedChild {
    pid: libc::pid_t,
}

fn spawn_stopped(command: &[String], worker: Option<WorkerCreds>) -> Result<StoppedChild> {
    let prog = CString::new(command[0].as_bytes())?;
    let argv: Vec<CString> = command
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<std::result::Result<_, _>>()?;
    let mut argv_ptr: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptr.push(std::ptr::null());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(anyhow!(std::io::Error::last_os_error())).context("fork");
    }
    if pid == 0 {
        unsafe {
            // Stop so the edge can subscribe by this PID before the command runs.
            libc::raise(libc::SIGSTOP);
            // Resumed (SIGCONT) only once the edge is live. Drop privileges now —
            // after the edge is attributing this PID, before exec — so the agent
            // runs unprivileged and cannot kill the root edge. A failed drop must
            // never exec the agent half-dropped.
            if let Some(creds) = worker {
                if drop_to(creds).is_err() {
                    libc::_exit(126);
                }
            }
            libc::execvp(prog.as_ptr(), argv_ptr.as_ptr());
            libc::_exit(127);
        }
    }
    Ok(StoppedChild { pid })
}

fn wait_until_stopped(pid: libc::pid_t) -> Result<()> {
    let mut status: libc::c_int = 0;
    let r = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
    if r < 0 {
        return Err(anyhow!(std::io::Error::last_os_error())).context("waitpid stopped child");
    }
    if libc::WIFSTOPPED(status) {
        return Ok(());
    }
    bail!("child exited before ES edge was ready")
}

fn wait_for_ready(ready: &Path, edge: &mut Child) -> Result<()> {
    let start = SystemTime::now();
    loop {
        if ready.exists() {
            return Ok(());
        }
        if let Some(status) = edge.try_wait().context("poll ES edge readiness")? {
            bail!("ES edge exited before readiness: {status}");
        }
        if start.elapsed().unwrap_or_default() > EDGE_READY_TIMEOUT {
            bail!(
                "timed out waiting for ES edge readiness marker {}",
                ready.display()
            );
        }
        thread::sleep(EDGE_POLL_INTERVAL);
    }
}

fn supervise(child_pid: libc::pid_t, edge: &mut Child) -> Result<i32> {
    // The foreground child exiting is NOT the end of the supervised tree: a
    // process that double-fork()s leaves an orphan (reparented to launchd) that
    // may still read after its parent is gone. The ES edge tracks the whole tree
    // and self-exits (status 0) only once it drains to empty — every member,
    // orphan included, has fired NOTIFY_EXIT. So we keep the edge running past
    // the foreground child's exit and tear down only when the edge itself exits;
    // otherwise the canonical double-fork attack wins by racing teardown.
    let mut foreground_code: Option<i32> = None;
    loop {
        if let Some(status) = edge.try_wait().context("poll ES edge")? {
            // Edge exited. Reap the child one last time first: with no orphan, the
            // child and the edge exit almost simultaneously (child exits -> ES
            // delivers its NOTIFY_EXIT -> edge drains -> edge exits), so the child
            // may be a zombie we have not yet collected this iteration. Only if
            // the child is genuinely still running did the edge die unexpectedly.
            if foreground_code.is_none() {
                foreground_code = try_wait(child_pid)?;
            }
            match foreground_code {
                Some(code) => return Ok(code),
                None => {
                    let _ = kill_pid(child_pid, libc::SIGKILL);
                    bail!("ES edge exited while child was running: {status}");
                }
            }
        }
        if foreground_code.is_none() {
            if let Some(code) = try_wait(child_pid)? {
                // Record the foreground exit code but keep the edge alive so it
                // can drain any orphaned descendants before we collect it.
                foreground_code = Some(code);
            }
        }
        thread::sleep(EDGE_POLL_INTERVAL);
    }
}

fn try_wait(pid: libc::pid_t) -> Result<Option<i32>> {
    let mut status: libc::c_int = 0;
    let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if r < 0 {
        return Err(anyhow!(std::io::Error::last_os_error())).context("waitpid child");
    }
    if r == 0 {
        return Ok(None);
    }
    if libc::WIFEXITED(status) {
        return Ok(Some(libc::WEXITSTATUS(status)));
    }
    if libc::WIFSIGNALED(status) {
        return Ok(Some(128 + libc::WTERMSIG(status)));
    }
    Ok(None)
}

fn terminate_edge(edge: &mut Child) -> Result<()> {
    if edge
        .try_wait()
        .context("poll ES edge before terminate")?
        .is_some()
    {
        return Ok(());
    }
    let pid = edge.id() as libc::pid_t;
    kill_pid(pid, libc::SIGTERM).context("terminate ES edge")?;
    for _ in 0..20 {
        if edge
            .try_wait()
            .context("wait ES edge after SIGTERM")?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(EDGE_POLL_INTERVAL);
    }
    kill_pid(pid, libc::SIGKILL).context("kill ES edge")?;
    let _ = edge.wait();
    Ok(())
}

fn kill_pid(pid: libc::pid_t, sig: libc::c_int) -> Result<()> {
    let rc = unsafe { libc::kill(pid, sig) };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(anyhow!(err))
}

#[cfg(test)]
mod allowlist_edge_tests {
    use super::*;
    use crate::allowlist::AllowList;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn scratch(tag: &str) -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("bulwark-es-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// B-B1 regression: macOS allow-list grants are emitted to the ES edge as
    /// inode-membership (`allow_inode`) entries, NOT as a path-beneath
    /// `allow_root`. The prior `allow_root` rule allowed any object whose
    /// canonical path was under the grant, so a hardlink/rename of a foreign
    /// secret into a granted path leaked. Reverting to `allow_root` makes this
    /// red on the `allow_inode`/no-`allow_root` assertions.
    #[test]
    fn allowlist_grants_emit_inode_not_root() {
        let dir = scratch("grants");
        let f = dir.join("app.log");
        fs::write(&f, b"x").unwrap();

        let mut al = AllowList::new(vec![format!("{}/**", dir.display())]).without_base();
        al.snapshot_grants();

        let cfg = scratch("cfg").join("edge.conf");
        let ready = scratch("ready").join("edge.ready");
        write_config(
            &cfg,
            &EdgePolicy::AllowList { allow: &al },
            1234,
            None,
            &ready,
        )
        .unwrap();
        let body = fs::read_to_string(&cfg).unwrap();

        let key = InodeKey::of(&fs::metadata(&f).unwrap());
        assert!(
            body.contains(&format!("allow_inode={}:{}", key.dev, key.ino)),
            "grant inode must be emitted as allow_inode; got:\n{body}"
        );
        assert!(
            !body.contains("allow_root="),
            "grants must not be emitted as path-beneath allow_root; got:\n{body}"
        );
    }
}
