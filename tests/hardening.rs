//! hardening integration tests: bind-mount coverage and graceful-teardown
//! fail-closed. Require Linux + root (fanotify) and `mount`, so they are
//! `#[ignore]` and run under `sudo` like the other integration suites.
//!
//! NOTE: the SIGKILL-mid-decision leak is an inherent fanotify limitation
//! (the kernel releases held permission events as allowed on fd close) and is
//! NOT tested here as "fixed" — it is a documented residual, addressed by a
//! future kernel-enforced floor, not by this code.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bulwark"))
}

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "bulwark-harden-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
#[ignore = "requires Linux + root for fanotify + mount"]
fn bind_mount_alias_is_gated() {
    let dir = scratch("bind");
    let secret = dir.join("secret.env");
    let bindpoint = dir.join("bindpoint");
    fs::write(&secret, "SECRETVALUE=bindleak\n").unwrap();
    fs::write(&bindpoint, "").unwrap();

    // Bind-mount the protected file to an alias path (same inode, different mount).
    let mount = Command::new("mount")
        .args(["--bind"])
        .arg(&secret)
        .arg(&bindpoint)
        .status()
        .expect("mount --bind");
    assert!(mount.success(), "bind mount setup failed");

    let out = Command::new(bin())
        .args(["run", "--protect"])
        .arg(&secret)
        .arg("--")
        .arg("cat")
        .arg(&bindpoint)
        .output()
        .expect("spawn bulwark");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Tear down the mount before asserting, so a failure doesn't leak a mount.
    let _ = Command::new("umount").arg(&bindpoint).status();

    assert!(
        !stdout.contains("SECRETVALUE"),
        "a bind-mounted alias of a protected inode must be gated; got: {stdout:?}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn graceful_sigterm_denies_held_read() {
    let dir = scratch("term");
    let secret = dir.join("secret.env");
    let agent_read = dir.join("agent_read.txt");
    let sock = dir.join("consent.sock");
    fs::write(&secret, "SECRETVALUE=termleak\n").unwrap();

    // Consent mode so the protected open is held while waiting for an operator
    // that never comes; meanwhile we SIGTERM the supervisor. A graceful stop
    // must deny the held read, not let the kernel release it as allowed.
    let inner = format!(
        "sleep 2; cat {} > {} 2>&1; echo done",
        secret.display(),
        agent_read.display()
    );
    let mut child = Command::new(bin())
        .args(["run", "--consent", "socket", "--consent-socket"])
        .arg(&sock)
        .args(["--consent-timeout", "30", "--protect"])
        .arg(&secret)
        .arg("--")
        .args(["bash", "-c", &inner])
        .spawn()
        .expect("spawn gate");

    // Let the open get held in the consent wait, then SIGTERM the supervisor.
    thread::sleep(Duration::from_millis(3500));
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let _ = child.wait();
    thread::sleep(Duration::from_millis(500));

    let read = fs::read_to_string(&agent_read).unwrap_or_default();
    assert!(
        !read.contains("SECRETVALUE"),
        "graceful SIGTERM while a read is held must fail closed (deny); got: {read:?}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn defended_vectors_still_pass_after_filesystem_mark() {
    // The wider FAN_MARK_FILESYSTEM must not become over-broad: a non-protected
    // neighbour file must still be readable, and the protected one denied.
    let dir = scratch("regress");
    let secret = dir.join("secret.env");
    let public = dir.join("public.txt");
    fs::write(&secret, "SECRETVALUE=regress\n").unwrap();
    fs::write(&public, "public-ok\n").unwrap();

    let denied = Command::new(bin())
        .args(["run", "--protect"])
        .arg(&secret)
        .arg("--")
        .arg("cat")
        .arg(&secret)
        .output()
        .expect("spawn");
    assert!(
        !String::from_utf8_lossy(&denied.stdout).contains("SECRETVALUE"),
        "protected file must still be denied under filesystem mark"
    );

    let allowed = Command::new(bin())
        .args(["run", "--protect"])
        .arg(&secret)
        .arg("--")
        .arg("cat")
        .arg(&public)
        .output()
        .expect("spawn");
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("public-ok"),
        "a non-protected neighbour must still be readable (mark not over-broad)"
    );
}

/// `--worker-uid` drops the agent to an unprivileged uid while the
/// supervisor stays root, and the gate STILL enforces on the dropped child.
/// Uses `nobody` (65534), present on essentially every Linux host.
#[test]
#[ignore = "requires Linux + root for fanotify + a 'nobody' account"]
fn worker_uid_drops_agent_and_gate_still_denies() {
    const NOBODY: &str = "65534";
    let dir = scratch("workeruid");
    let secret = dir.join("secret.env");
    fs::write(&secret, "SECRETVALUE=workeruid\n").unwrap();

    // The agent prints its uid, then tries to read the protected file.
    let out = Command::new(bin())
        .args(["run", "--worker-uid", NOBODY, "--protect"])
        .arg(&secret)
        .arg("--")
        .arg("bash")
        .arg("-c")
        .arg(format!("id -u; cat {} 2>&1", secret.display()))
        .output()
        .expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The agent actually ran as nobody (the drop took).
    assert!(
        combined.lines().any(|l| l.trim() == NOBODY),
        "agent must run as uid {NOBODY} (the drop must take); got:\n{combined}"
    );
    // And the gate still denied the protected read for the unprivileged child.
    assert!(
        !combined.contains("SECRETVALUE"),
        "the gate must deny the protected read even for a dropped child; got:\n{combined}"
    );
}

/// headline: an unprivileged dropped agent CANNOT `SIGKILL` the root
/// supervisor, so it cannot force the fanotify fail-open. The agent reads its own
/// parent pid, tries `kill -9` on it (must fail with EPERM), then reads the
/// protected file (must still be denied). Contrast: without `--worker-uid`, a
/// root agent's kill would succeed — documenting the leak this closes.
#[test]
#[ignore = "requires Linux + root for fanotify + a 'nobody' account"]
fn worker_uid_agent_cannot_kill_the_root_supervisor() {
    const NOBODY: &str = "65534";
    let dir = scratch("nokill");
    let secret = dir.join("secret.env");
    fs::write(&secret, "SECRETVALUE=nokill\n").unwrap();

    // The agent's parent (PPID) is the root supervisor. Try to kill it; report
    // whether the kill was permitted; then attempt the protected read.
    let probe = format!(
        "sup=$PPID; \
         if kill -9 \"$sup\" 2>/dev/null; then echo KILL=ok; else echo KILL=denied; fi; \
         sleep 1; \
         cat {} 2>&1 || true",
        secret.display()
    );
    let out = Command::new(bin())
        .args(["run", "--worker-uid", NOBODY, "--protect"])
        .arg(&secret)
        .arg("--")
        .arg("bash")
        .arg("-c")
        .arg(probe)
        .output()
        .expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The unprivileged agent must NOT be able to kill the root supervisor.
    assert!(
        combined.contains("KILL=denied"),
        "unprivileged worker must not be able to SIGKILL the root supervisor; got:\n{combined}"
    );
    // The supervisor survived, so the protected read is still denied.
    assert!(
        !combined.contains("SECRETVALUE"),
        "gate must stay up (read denied) after the failed kill attempt; got:\n{combined}"
    );
}
