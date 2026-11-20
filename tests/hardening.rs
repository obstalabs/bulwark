//! WO-12 hardening integration tests: bind-mount coverage and graceful-teardown
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

// WO-12@v1: drive the built binary so fail-closed shutdown is tested as shipped.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bulwark"))
}

// WO-12@v1: isolate each supervisor-kill and bind-mount scenario's files.
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

// WO-149@v1: give each root test its own integrity state, never the host default.
fn isolated_state(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "bulwark-state-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir.join("state.toml")
}

// WO-12@v1: a bind-mounted alias of a protected inode is gated like the original path.
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
        .args([
            "run",
            "--allow-user-writable-engine",
            "--allow-root",
            "--protect",
        ])
        .arg(&secret)
        // WO-149@v1: isolate this test's integrity state from the host default.
        .arg("--state")
        .arg(isolated_state("bind"))
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

// WO-12@v1: a graceful supervisor stop denies a held read instead of releasing it.
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
            "--allow-user-writable-engine",
            "--allow-root",
            "--consent",
            "socket",
            "--consent-socket",
        ])
        .arg(&sock)
        .args(["--consent-timeout", "30", "--protect"])
        .arg(&secret)
        // WO-149@v1: isolate this test's integrity state from the host default.
        .arg("--state")
        .arg(isolated_state("term"))
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

// WO-12@v1: the filesystem-wide mark still denies the protected file and allows its neighbour.
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

    // WO-149@v1: one integrity state for both runs of this test, never the host default.
    let state = isolated_state("regress");
    let denied = Command::new(bin())
        .args([
            "run",
            "--allow-user-writable-engine",
            "--allow-root",
            "--protect",
        ])
        .arg(&secret)
        // WO-149@v1: isolate this run's integrity state.
        .arg("--state")
        .arg(&state)
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
        .args([
            "run",
            "--allow-user-writable-engine",
            "--allow-root",
            "--protect",
        ])
        .arg(&secret)
        // WO-149@v1: isolate this run's integrity state.
        .arg("--state")
        .arg(&state)
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

/// WO-49: `--worker-uid` drops the agent to an unprivileged uid while the
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
        .args([
            "run",
            "--allow-user-writable-engine",
            "--worker-uid",
            NOBODY,
            "--protect",
        ])
        .arg(&secret)
        // WO-149@v1: isolate this test's integrity state from the host default.
        .arg("--state")
        .arg(isolated_state("workeruid"))
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

// WO-224@v1: check the environment seen by the worker after a real UID drop.
// WO-224: exercise passwd identity and session scrubbing through the shipped binary.
#[test]
#[ignore = "requires Linux + root for fanotify + a 'nobody' account"]
fn worker_uid_gets_its_passwd_environment() {
    // WO-224@v1: use the same unprivileged account as the other drop checks.
    // WO-224: read its account data from the test host instead of assuming its home.
    const NOBODY: &str = "65534";
    // WO-224@v1: obtain the host's expected passwd fields independently of Bulwark.
    // WO-224: allow distributions to supply different homes for the nobody account.
    let account = Command::new("getent")
        .args(["passwd", NOBODY])
        .output()
        .expect("getent passwd");
    assert!(
        account.status.success(),
        "uid {NOBODY} must have a passwd entry"
    );
    // WO-224@v1: retain the passwd fields until the worker's output is checked.
    // WO-224: parse the login name and home from the same account record.
    let passwd = std::str::from_utf8(&account.stdout).unwrap();
    // WO-224@v1: the passwd record has separate name and directory fields.
    // WO-224: assert both login variables and HOME against those fields.
    let fields: Vec<_> = passwd.trim_end().splitn(7, ':').collect();

    // WO-224@v1: keep the protected inode and integrity state within a test directory.
    // WO-224: provide a private fixture so the probe exercises the normal deny-list gate.
    let dir = scratch("worker-env");
    // WO-224@v1: supply a guard path that always exists for this run.
    // WO-224: avoid relying on host-specific default protected paths.
    let secret = dir.join("secret.env");
    fs::write(&secret, "secret\n").unwrap();

    // WO-224@v1: simulate sudo's root environment and verify the child's values after exec.
    // WO-224: seed all five variables so the probe detects accidental inheritance.
    let out = Command::new(bin())
        .args([
            "run",
            "--allow-user-writable-engine",
            "--worker-uid",
            NOBODY,
            "--protect",
        ])
        .arg(&secret)
        // WO-224@v1: use this test's state file instead of the host's integrity state.
        // WO-224: keep the test's state alongside the protected fixture.
        .arg("--state")
        .arg(dir.join("state.toml"))
        .args([
            "--",
            "sh",
            "-c",
            r#"echo "$HOME $USER"; printf '%s\n' "$LOGNAME" "${XDG_RUNTIME_DIR-unset}" "${DBUS_SESSION_BUS_ADDRESS-unset}""#,
        ])
        .env("HOME", "/root")
        .env("USER", "root")
        .env("LOGNAME", "root")
        .env("XDG_RUNTIME_DIR", "/run/user/0")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/0/bus")
        .output()
        .expect("spawn bulwark");
    fs::remove_dir_all(dir).unwrap();

    assert!(
        out.status.success(),
        "worker must run successfully: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{} {}\n{}\nunset\nunset\n", fields[5], fields[0], fields[0])
    );
}

// WO-281@v2: verify session overrides and duplicate-key precedence through a real worker exec.
#[test]
#[ignore = "requires Linux + root for fanotify + a 'nobody' account"]
fn worker_uid_gets_explicit_session_environment() {
    // WO-281@v2: check the two overrides both alone and after a conflicting runtime directory.
    for earlier_args in [&[][..], &["--worker-env", "XDG_RUNTIME_DIR=/run/user/1"]] {
        // WO-281@v2: isolate each launch's protected fixture and integrity state.
        let dir = scratch("worker-env-overrides");
        // WO-281@v2: use a known protected file to exercise the normal fanotify gate.
        let protected = dir.join("protected");
        fs::write(&protected, "protected\n").unwrap();

        // WO-281@v2: print the dropped UID and both session values exactly as the worker sees them.
        let out = Command::new(bin())
            .args([
                "run",
                "--allow-user-writable-engine",
                "--worker-uid",
                "65534",
                "--protect",
            ])
            .arg(&protected)
            .arg("--state")
            .arg(dir.join("state.toml"))
            .args(earlier_args)
            .args([
                "--worker-env",
                "XDG_RUNTIME_DIR=/run/user/65534",
                "--worker-env",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/65534/bus",
                "--",
                "/bin/sh",
                "-c",
                r#"id -u && printf '%s\n' "$XDG_RUNTIME_DIR" "$DBUS_SESSION_BUS_ADDRESS""#,
            ])
            .env("XDG_RUNTIME_DIR", "/run/user/0")
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/0/bus")
            .output()
            .expect("spawn bulwark");
        fs::remove_dir_all(dir).unwrap();

        assert!(
            out.status.success(),
            "worker must run with earlier arguments {earlier_args:?}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "65534\n/run/user/65534\nunix:path=/run/user/65534/bus\n",
            "unexpected worker environment with earlier arguments {earlier_args:?}"
        );
    }
}

// WO-49@v1: a dropped worker cannot kill the root supervisor to force a fail-open.
/// WO-49 headline: an unprivileged dropped agent CANNOT `SIGKILL` the root
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
        .args([
            "run",
            "--allow-user-writable-engine",
            "--worker-uid",
            NOBODY,
            "--protect",
        ])
        .arg(&secret)
        // WO-149@v1: isolate this test's integrity state from the host default.
        .arg("--state")
        .arg(isolated_state("nokill"))
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
// WO-66@v1: a permission-queue overflow must fail closed, never release the protected read.
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
        .args([
            "run",
            "--allow-user-writable-engine",
            "--allow-root",
            "--protect",
        ])
        .arg(&secret)
        .arg("--receipts")
        .arg(&receipts)
        // WO-149@v1: isolate this test's integrity state from the host default.
        .arg("--state")
        .arg(isolated_state("overflow"))
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
// WO-67@v1: the worker drop is irreversible; a setuid-root exec cannot regain root.
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
        .args(["run", "--allow-user-writable-engine", "--protect"])
        .arg(&secret)
        // WO-149@v1: isolate this test's integrity state from the host default.
        .arg("--state")
        .arg(isolated_state("nnp"))
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

// WO-258@v1: the root-from-user-writable-path refusal must be fail-closed, and
// the `--allow-user-writable-engine` waiver must be inert on a clean engine.
// (a) no flag refuses before any work; (b) the flag warns once and marks the
// summary `engine_unverified`; (c) a root-owned 0755 copy warns nothing.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn engine_writable_refusal_and_waiver_are_fail_closed() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("wo258");
    let secret = dir.join("secret");
    fs::write(&secret, b"secret\n").unwrap();

    // (a) no flag: refuse before any gate starts or config is read.
    let rcpt_a = dir.join("a.jsonl");
    let out = Command::new(bin())
        .args(["run", "--protect"])
        .arg(&secret)
        .arg("--receipts")
        .arg(&rcpt_a)
        .arg("--")
        .arg("/bin/true")
        .output()
        .expect("spawn run without waiver");
    assert!(!out.status.success(), "run without the waiver must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to run as root"),
        "refusal must name the cause: {stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "the agent must not run: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !rcpt_a.exists(),
        "no receipts file may be written on refusal"
    );

    // (b) waiver: warn exactly once and mark the summary.
    let rcpt_b = dir.join("b.jsonl");
    let out = Command::new(bin())
        .args(["run", "--allow-user-writable-engine", "--protect"])
        .arg(&secret)
        .arg("--receipts")
        .arg(&rcpt_b)
        .arg("--state")
        .arg(isolated_state("wo258b"))
        .arg("--")
        .arg("/bin/true")
        .output()
        .expect("spawn run with waiver");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "waived run must proceed: {stderr}");
    assert_eq!(
        stderr.matches("WARNING engine component").count(),
        1,
        "exactly one warning: {stderr}"
    );
    let body = fs::read_to_string(&rcpt_b).unwrap_or_default();
    assert!(
        body.contains(r#""engine_unverified":true"#),
        "summary must carry engine_unverified: {body}"
    );

    // (c) root-owned 0755 copy: the flag is inert — no warning, no unverified.
    let copy_dir = std::path::PathBuf::from(format!(
        "/bulwark-wo258-root-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&copy_dir).unwrap();
    let _ = Command::new("chmod").arg("0755").arg(&copy_dir).status();
    let copy = copy_dir.join("bulwark");
    fs::copy(bin(), &copy).unwrap();
    let mut perms = fs::metadata(&copy).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&copy, perms).unwrap();

    let rcpt_c = dir.join("c.jsonl");
    let out = Command::new(&copy)
        .args(["run", "--allow-user-writable-engine", "--protect"])
        .arg(&secret)
        .arg("--receipts")
        .arg(&rcpt_c)
        .arg("--state")
        .arg(isolated_state("wo258c"))
        .arg("--")
        .arg("/bin/true")
        .output()
        .expect("spawn root-owned copy");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "clean engine must run: {stderr}");
    assert!(
        !stderr.contains("WARNING engine"),
        "a clean engine must not warn: {stderr}"
    );
    let body = fs::read_to_string(&rcpt_c).unwrap_or_default();
    assert!(
        !body.contains("engine_unverified"),
        "a clean engine must not be marked unverified: {body}"
    );

    let _ = fs::remove_file(&copy);
    let _ = fs::remove_dir(&copy_dir);
    let _ = fs::remove_dir_all(&dir);
}

// WO-269@v1: count real warnings on a launch that reaches cmd_run as root.
// WO-269: also verify the unwaived launch refuses before opening its policy.
#[test]
#[ignore = "requires root for the engine path check"]
fn launch_warns_once_for_a_user_writable_engine() {
    use std::os::unix::fs::PermissionsExt;

    assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
    // WO-269: keep the group-writable engine copy inside a private directory.
    let dir = scratch("wo269");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    // WO-269: flag a writable component even when the build tree is root-owned.
    let engine = dir.join("bulwark");
    fs::copy(bin(), &engine).unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o775)).unwrap();

    // WO-269: use an explicit path that stays absent for the unwaived launch.
    let policy = dir.join("Bulwark.toml");
    // WO-268@v1: exercise launch's engine check with a trusted receipts directory.
    // WO-268: put the launch audit file at an absolute path inside the private scratch directory.
    let receipts = dir.canonicalize().unwrap().join("bulwark-audit.jsonl");
    // WO-269: share the same engine and policy path for both launch attempts.
    let launch = |waiver: Option<&str>| {
        Command::new(&engine)
            .current_dir(&dir)
            .args(["launch", "agent", "--policy"])
            .arg(&policy)
            // WO-268: supply the file sink explicitly for both launch attempts.
            .arg("--receipts")
            .arg(&receipts)
            .arg("--state")
            .arg(dir.join("state.toml"))
            .args(waiver)
            .output()
            .expect("spawn launch")
    };

    // WO-269: refusal must take precedence over reading the missing policy.
    let refused = launch(None);
    // WO-269: resolve the profile in launch, then stop in cmd_run before starting the gate.
    fs::write(
        &policy,
        "[agents.agent]\ncommand = [\"/bin/true\"]\nprotect = [\"relative\"]\ndecision = \"deny\"\n",
    )
    .unwrap();
    // WO-269: capture stderr after the waived launch delegates to cmd_run.
    let waived = launch(Some("--allow-user-writable-engine"));
    fs::remove_dir_all(&dir).unwrap();

    // WO-269: check that the engine refusal takes precedence over the missing policy.
    let refusal = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success());
    assert!(refusal.contains("refusing to run as root"), "{refusal}");
    // WO-269: relative path validation proves cmd_run received the waived launch.
    let stderr = String::from_utf8_lossy(&waived.stderr);
    assert!(!waived.status.success());
    assert!(stderr.contains("is relative: a protect entry"), "{stderr}");
    assert_eq!(
        stderr.matches("WARNING engine component").count(),
        1,
        "{stderr}"
    );
}

// WO-283@v1: a descriptor the launcher leaves open must not survive into the agent (WO-273).
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn launcher_held_descriptor_is_closed_before_the_agent_runs() {
    use std::os::fd::AsRawFd;

    let dir = scratch("wo283-held");
    let decoy = dir.join("decoy.env");
    fs::write(&decoy, "DECOYVALUE=heldleak\n").unwrap();

    // WO-283: opened by the test itself so bulwark inherits it, then made inheritable.
    let held = fs::File::open(&decoy).unwrap();
    let n = held.as_raw_fd();
    assert!(n > 2, "descriptor must be above stdio, got {n}");
    unsafe {
        let flags = libc::fcntl(n, libc::F_GETFD);
        assert!(flags >= 0, "F_GETFD failed");
        assert_eq!(
            libc::fcntl(n, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
            0,
            "clearing close-on-exec failed"
        );
    }

    // WO-283: bash, not sh, because dash cannot address a multi-digit descriptor.
    let inner = format!(
        "cat <&{n} 2>/dev/null; echo \"fd=$?\"; cat {} 2>&1; echo \"direct=$?\"",
        decoy.display()
    );
    let out = Command::new(bin())
        .args(["run", "--allow-user-writable-engine", "--allow-root"])
        .arg("--state")
        .arg(isolated_state("wo283-held"))
        .arg("--protect")
        .arg(&decoy)
        .arg("--")
        .args(["bash", "-c", &inner])
        .output()
        .expect("spawn bulwark");
    drop(held);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = fs::remove_dir_all(&dir);

    // WO-283: neither the inherited descriptor nor the direct path may yield content.
    assert!(
        !stdout.contains("DECOYVALUE"),
        "decoy content reached the agent: {stdout:?}"
    );
    assert!(
        stdout.contains("fd=") && !stdout.contains("fd=0"),
        "the inherited descriptor {n} must be unreadable in the agent: {stdout:?}"
    );
    assert!(
        stdout.contains("direct=") && !stdout.contains("direct=0"),
        "the direct read must be denied: {stdout:?}"
    );
}

// WO-283@v1: documents the known residual: a descriptor passed after launch by a process
// outside the supervised tree (SCM_RIGHTS) is readable by the agent. Not a defect to fix here.
#[test]
#[ignore = "requires Linux + root for fanotify + python3 (skips itself without it)"]
fn documented_residual_scm_rights_descriptor_from_outside_is_readable() {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    // WO-283: the receiver is python3; without it the residual cannot be built without new deps.
    let has_python = Command::new("python3")
        .args(["-c", "import socket; socket.recv_fds"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !has_python {
        eprintln!("skipping: python3 with socket.recv_fds is unavailable");
        return;
    }

    let dir = scratch("wo283-scm");
    let decoy = dir.join("decoy.env");
    let sock = dir.join("rx.sock");
    fs::write(&decoy, "DECOYVALUE=scmresidual\n").unwrap();
    // WO-283: close-on-exec (the Rust default) keeps this out of the launch-time inheritance.
    let outside = fs::File::open(&decoy).unwrap();

    let script = "import socket,os,sys\n\
s=socket.socket(socket.AF_UNIX)\n\
s.bind(sys.argv[1])\n\
s.listen(1)\n\
c,_=s.accept()\n\
m,fds,fl,a=socket.recv_fds(c,16,4)\n\
sys.stdout.write('RECV='+os.read(fds[0],4096).decode())\n\
sys.stdout.flush()\n";
    let mut child = Command::new(bin())
        .args(["run", "--allow-user-writable-engine", "--allow-root"])
        .arg("--state")
        .arg(isolated_state("wo283-scm"))
        .arg("--protect")
        .arg(&decoy)
        .arg("--")
        .args(["python3", "-c", script])
        .arg(&sock)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bulwark");

    // WO-283: wait for the agent's listener; kill the run rather than hang if it never appears.
    let mut waited = 0;
    while !sock.exists() {
        if waited >= 100 {
            let _ = child.kill();
            panic!("agent never created its receiving socket");
        }
        thread::sleep(Duration::from_millis(100));
        waited += 1;
    }
    let conn = UnixStream::connect(&sock).expect("connect to agent socket");
    unsafe {
        let payload = *b"x";
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let fd_size = std::mem::size_of::<libc::c_int>() as u32;
        let space = libc::CMSG_SPACE(fd_size) as usize;
        // u64 backing keeps the control buffer aligned for cmsghdr.
        let mut control = vec![0u64; space.div_ceil(8)];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_size) as _;
        std::ptr::write_unaligned(
            libc::CMSG_DATA(cmsg) as *mut libc::c_int,
            outside.as_raw_fd(),
        );
        assert!(
            libc::sendmsg(conn.as_raw_fd(), &msg, 0) >= 0,
            "sendmsg failed"
        );
    }

    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&dir);

    assert!(
        stdout.contains("RECV=DECOYVALUE=scmresidual"),
        "known residual: an fd passed from outside the tree should be readable; got {stdout:?}"
    );
}
