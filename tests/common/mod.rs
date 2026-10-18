//! Shared helpers for the root (fanotify) integration tests.

use std::fs;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

// WO-158@v1: bound cleanup while the crash watcher empties a killed run's scope.
const SCOPE_CLEANUP_BOUND: Duration = Duration::from_secs(10);
// WO-158@v1: avoid a busy loop while waiting for the cgroup state to settle.
const SCOPE_CLEANUP_POLL: Duration = Duration::from_millis(10);

/// A test-owned tmpfs mount. Protected and allowed fixtures live here so
/// `FAN_MARK_FILESYSTEM` marks only this filesystem — never the root filesystem
/// — and the unmount leaves nothing behind. Root only (the `mount` call).
// WO-154@v1: isolate permission-loop tests from unrelated host filesystems.
// WO-155@v1: remove supervised-tree fixtures when each gate test ends.
pub struct TestFs {
    pub root: PathBuf,
}

// WO-154@v1: provide an isolated filesystem for permission-loop tests.
// WO-155@v1: own cleanup of supervised-tree fixtures as one resource.
impl TestFs {
    // WO-154@v1: mount only the filesystem exercised by each gate test.
    // WO-155@v1: give each supervised-tree test a distinct fixture root.
    pub fn new(tag: &str) -> Self {
        let root = PathBuf::from(format!(
            "/var/tmp/bulwark-testfs-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("create test fs dir");
        let st = Command::new("mount")
            .args([
                "-t",
                "tmpfs",
                "tmpfs",
                "-o",
                "size=16m",
                root.to_str().unwrap(),
            ])
            .status()
            .expect("run mount");
        assert!(st.success(), "tmpfs mount of {} failed", root.display());
        TestFs { root }
    }

    /// A fixture path on this test filesystem.
    // WO-154@v1: keep protected and allowed paths on the isolated mount.
    // WO-155@v1: keep supervised-tree artifacts under the owned fixture root.
    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

// WO-154@v1: release the isolated permission-loop filesystem after each test.
// WO-155@v1: tear down supervised-tree fixtures even on unwinding.
impl Drop for TestFs {
    // WO-154@v1: unmount before removing the permission-loop fixture root.
    // WO-155@v1: leave no mounted supervised-tree fixture behind.
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.root).status();
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Owns a gate that a test deliberately kills and removes its abandoned cgroup
/// scope only after the kernel reports that the scope is empty.
// WO-158@v1: clean hard-kill test resources on success and unwinding paths.
pub struct HardKillScopeGuard {
    gate: Child,
    scope: PathBuf,
}

// WO-158@v1: make existing gate assertions use the cleanup owner transparently.
impl Deref for HardKillScopeGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.gate
    }
}

// WO-158@v1: preserve mutable Child operations while the guard owns cleanup.
impl DerefMut for HardKillScopeGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.gate
    }
}

// WO-158@v1: bind each cleanup guard to the cgroup named for its gate pid.
impl HardKillScopeGuard {
    pub fn new(gate: Child) -> Self {
        let scope = PathBuf::from(format!("/sys/fs/cgroup/bulwark.run-{}", gate.id()));
        HardKillScopeGuard { gate, scope }
    }
}

// WO-158@v1: recognize only explicit cgroup-v2 emptiness proof.
fn scope_is_empty(events: &str) -> bool {
    events.lines().any(|line| line.trim() == "populated 0")
}

// WO-158@v1: finish all hard-kill cleanup before the enclosing TestFs unmounts.
impl Drop for HardKillScopeGuard {
    fn drop(&mut self) {
        let mut failures = Vec::new();

        match self.gate.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                if let Err(error) = self.gate.kill() {
                    failures.push(format!("cannot kill gate {}: {error}", self.gate.id()));
                }
                if let Err(error) = self.gate.wait() {
                    failures.push(format!("cannot reap gate {}: {error}", self.gate.id()));
                }
            }
        }

        if self.scope.exists() {
            let deadline = Instant::now() + SCOPE_CLEANUP_BOUND;
            let events_path = self.scope.join("cgroup.events");
            let mut empty = false;
            let mut gone = false;
            let mut last_observation = String::new();

            while Instant::now() < deadline {
                match fs::read_to_string(&events_path) {
                    Ok(events) => {
                        last_observation = events;
                        if scope_is_empty(&last_observation) {
                            empty = true;
                            break;
                        }
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::NotFound && !self.scope.exists() =>
                    {
                        gone = true;
                        break;
                    }
                    Err(error) => last_observation = format!("read failed: {error}"),
                }
                std::thread::sleep(SCOPE_CLEANUP_POLL);
            }

            if empty && !gone {
                let remove_deadline = Instant::now() + SCOPE_CLEANUP_BOUND;
                while Instant::now() < remove_deadline {
                    if fs::remove_dir(&self.scope).is_ok() || !self.scope.exists() {
                        break;
                    }
                    std::thread::sleep(SCOPE_CLEANUP_POLL);
                }
            }

            if !gone && self.scope.exists() {
                failures.push(format!(
                    "scope {} was not removed after empty proof; last cgroup.events: {:?}",
                    self.scope.display(),
                    last_observation
                ));
            }
        }

        if !failures.is_empty() {
            let message = failures.join("; ");
            if std::thread::panicking() {
                eprintln!("[bulwark] hard-kill cleanup failed: {message}");
            } else {
                panic!("hard-kill cleanup failed: {message}");
            }
        }
    }
}
