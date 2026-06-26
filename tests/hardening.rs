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
        .args(["run", "--allow-root", "--protect"])
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
        .args([
            "run",
            "--allow-root",
            "--consent",
            "socket",
            "--consent-socket",
        ])
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
        .args(["run", "--allow-root", "--protect"])
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
        .args(["run", "--allow-root", "--protect"])
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

/// Regression: a fanotify permission-event-queue OVERFLOW must FAIL CLOSED.
///
/// The default permission queue is bounded; when it overflows the kernel drops
/// the undeliverable event and lets the access proceed *as allowed* — a fail-open
/// an unprivileged supervised process can reach by flooding opens. `FAN_UNLIMITED_QUEUE`
/// removes the bound so the gate applies backpressure instead of leaking.
///
/// This test forces the failure mode by shrinking `fs.fanotify.max_queued_events`
/// to a tiny value, then floods opens while hammering the protected secret. With the
/// fix the secret is never read; without it, it leaks thousands of times.
#[test]
#[ignore = "requires Linux + root for fanotify + sysctl write"]
fn queue_overflow_fails_closed() {
    let dir = scratch("overflow");
    let secret = dir.join("secret.env");
    let pool = dir.join("pool");
    fs::write(&secret, "SECRETVALUE=overflow\n").unwrap();
    fs::create_dir_all(&pool).unwrap();
    for i in 0..3000 {
        fs::write(pool.join(format!("f{i}")), b"x").unwrap();
    }

    // Shrink the queue to force overflow under the flood; restore on the way out.
    let knob = "/proc/sys/fs/fanotify/max_queued_events";
    let original = fs::read_to_string(knob).unwrap_or_else(|_| "16384".into());
    fs::write(knob, "1").expect("write max_queued_events (need root)");

    // The supervised command: flood opens on the pool in the background while a tight
    // loop tries the protected secret. Echo a marker only if the secret content appears.
    // Flood opens on the pool (16 background loops) to overflow the tiny queue, while a
    // bounded attack loop tries the protected secret. The whole probe is wrapped in
    // `timeout` so it cannot hang the suite. The leak, when present, is massive
    // (~160k reads), so a few hundred attack iterations are more than enough to catch it.
    let probe = format!(
        "for i in $(seq 1 16); do ( while :; do cat {pool}/* >/dev/null 2>&1; done ) & done; \
         leaks=0; for i in $(seq 1 400); do \
           if cat {secret} 2>/dev/null | grep -q SECRETVALUE; then leaks=$((leaks+1)); fi; done; \
         echo LEAKS=$leaks",
        pool = pool.display(),
        secret = secret.display()
    );
    // Route receipts to a FILE, not stderr: under this flood the gate emits ~100k
    // allow-receipt lines, and on a slow/loaded CI runner that stderr volume can
    // delay the `LEAKS=` marker past a tight timeout — making the test flaky on
    // capture, not on the actual security property. A receipts file keeps stdout
    // clean so the marker is deterministic.
    let receipts = dir.join("receipts.jsonl");
    let out = Command::new("timeout")
        .arg("90")
        .arg(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&secret)
        .arg("--receipts")
        .arg(&receipts)
        .arg("--")
        .arg("bash")
        .arg("-c")
        .arg(&probe)
        .output()
        .expect("spawn");

    // Restore the sysctl before asserting so a failure doesn't leave the host shrunk.
    fs::write(knob, original.trim()).expect("restore max_queued_events");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The probe counts how many of its reads actually returned the secret content
    // and prints `LEAKS=<n>` (its own grep — note the supervisor also echoes the
    // command line, which literally contains the word SECRETVALUE, so asserting on
    // that substring would false-positive; the count is the real signal). The fix
    // requires zero. A MISSING marker means the run was cut short (e.g. the outer
    // timeout under load) — inconclusive, not a pass — so require it explicitly.
    let marker = combined
        .lines()
        .find_map(|l| l.trim().strip_prefix("LEAKS="))
        .map(str::trim);
    assert_eq!(
        marker,
        Some("0"),
        "queue overflow must fail closed with zero protected reads; LEAKS marker was {marker:?} \
         (None = probe did not finish in time, not a pass); output:\n{combined}"
    );
}

/// Regression: the privilege drop must be IRREVERSIBLE — a dropped agent cannot
/// regain root by exec'ing a setuid-root binary. Without `PR_SET_NO_NEW_PRIVS` in
/// `drop_to`, the kernel still honors the setuid bit on a later `execve`, so the
/// dropped agent re-roots and can then migrate out of the cgroup scope (A-1).
///
/// Plants a setuid-root helper on a suid-honoring filesystem (NOT /tmp, which is
/// usually `nosuid`), runs the agent under the default drop, and asserts the helper
/// runs as the dropped uid — i.e. the setuid bit was ignored.
#[test]
#[ignore = "requires Linux + root + a suid-honoring fs (/usr/local)"]
fn privilege_drop_is_irreversible_to_setuid_exec() {
    let dir = scratch("nnp");
    let control = dir.join("control.txt");
    fs::write(&control, "CTRL=ok\n").unwrap();
    let secret = dir.join("secret.env");
    fs::write(&secret, "SECRETVALUE=nnp\n").unwrap();

    // A setuid-root helper that prints its effective uid at entry. /tmp is commonly
    // mounted nosuid (which would mask the bug), so place it under /usr/local.
    let helper_src = dir.join("suid.c");
    fs::write(
        &helper_src,
        "#include <stdio.h>\n#include <unistd.h>\nint main(){printf(\"ENTER_EUID=%d\\n\",geteuid());return 0;}\n",
    )
    .unwrap();
    let helper = std::path::Path::new("/usr/local/bin/bulwark-nnp-test-helper");
    let cc = Command::new("cc")
        .arg(&helper_src)
        .arg("-o")
        .arg(helper)
        .status()
        .expect("cc");
    assert!(cc.success(), "compile setuid helper");
    // setuid-root bit
    let _ = Command::new("chown").arg("root:root").arg(helper).status();
    let _ = Command::new("chmod").arg("4755").arg(helper).status();

    let probe = format!(
        "id -u; cat {} >/dev/null 2>&1; {}",
        control.display(),
        helper.display()
    );
    let out = Command::new(bin())
        .args(["run", "--protect"])
        .arg(&secret)
        .arg("--")
        .arg("bash")
        .arg("-c")
        .arg(&probe)
        .output()
        .expect("spawn");

    // Clean up the host-level helper regardless of assertion outcome.
    let _ = fs::remove_file(helper);

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The helper must NOT have regained root: its entry euid is the dropped uid, not 0.
    assert!(
        combined.contains("ENTER_EUID=") && !combined.contains("ENTER_EUID=0"),
        "setuid-exec must NOT regain root after the drop (no_new_privs); got:\n{combined}"
    );
}
