//! WO-14 hardened-mode (Landlock floor) integration tests. Require Linux with
//! Landlock and root, so `#[ignore]` + run under `sudo`.
//!
//! Hardened mode applies a kernel-enforced default-deny read floor and execs
//! the agent — crash-safe by construction (no supervisor). These tests verify
//! the floor allows the grant + base set and denies everything else. Crash-
//! safety is structural (the restriction is on the agent process in the kernel,
//! nothing to kill) and is exercised manually; it cannot widen at runtime.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bulwark"))
}

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("bulwark-hard-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_hardened(grant: &str, cmd: &[&str]) -> String {
    let mut c = Command::new(bin());
    c.args(["run", "--hardened", "--allow", grant, "--"]);
    for a in cmd {
        c.arg(a);
    }
    let out = c.output().expect("spawn bulwark");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore = "requires Linux + Landlock + root"]
fn hardened_floor_allows_grant_and_executes() {
    let dir = scratch("grant");
    let log = dir.join("app.log");
    fs::write(&log, "ERROR: needle\n").unwrap();
    let grant = format!("{}/**", dir.display());

    let out = run_hardened(&grant, &["grep", "needle", log.to_str().unwrap()]);
    assert!(
        out.contains("needle"),
        "hardened floor must allow the grant and let the agent execute; got: {out:?}"
    );
}

#[test]
#[ignore = "requires Linux + Landlock + root"]
fn hardened_floor_denies_credentials_outside_grant() {
    let dir = scratch("deny");
    let logs = dir.join("logs");
    let secrets = dir.join("secrets");
    fs::create_dir_all(&logs).unwrap();
    fs::create_dir_all(&secrets).unwrap();
    fs::write(logs.join("app.log"), "log\n").unwrap();
    let creds = secrets.join("credentials");
    fs::write(&creds, "AWS_SECRET=do-not-leak\n").unwrap();

    let grant = format!("{}/**", logs.display());
    let out = run_hardened(
        &grant,
        &["bash", "-c", &format!("cat {} 2>&1", creds.display())],
    );
    assert!(
        !out.contains("AWS_SECRET"),
        "credentials outside the grant must be denied by the kernel floor; got: {out:?}"
    );
}

#[test]
#[ignore = "requires Linux + Landlock + root"]
fn hardened_floor_denies_etc_shadow() {
    let dir = scratch("shadow");
    fs::write(dir.join("app.log"), "log\n").unwrap();
    let grant = format!("{}/**", dir.display());

    let out = run_hardened(&grant, &["bash", "-c", "cat /etc/shadow 2>&1"]);
    assert!(
        !out.contains("root:") && !out.contains(":$"),
        "/etc/shadow must be denied under the hardened floor; got: {out:?}"
    );
}

/// Regression: a `--hardened --allow` operator grant whose concrete prefix is
/// a SYMLINK to a broader directory must be REJECTED before any Landlock rule is
/// applied. Otherwise `open(O_PATH)` follows the symlink and floors the wider
/// target — a silent widening invisible in the grant string. The rejection is a
/// CLI-level bail (no Landlock/root needed), so this test checks stderr+status.
// WO-74@v1: a concrete grant that is a symlink to a broader directory is refused before any rule applies.
#[test]
#[ignore = "requires Linux (filesystem symlink + canonicalize)"]
fn hardened_rejects_symlink_widening_grant() {
    let dir = scratch("f4");
    let broad = dir.join("broad");
    fs::create_dir_all(broad.join("sub")).unwrap();
    fs::write(broad.join("sub/secret.env"), "BROADSECRET=widened\n").unwrap();
    // A concrete-looking grant that is actually a symlink to the broad dir.
    let glink = dir.join("glink");
    std::os::unix::fs::symlink(&broad, &glink).unwrap();

    let out = Command::new(bin())
        .args(["run", "--hardened", "--allow"])
        .arg(&glink)
        .args(["--", "cat"])
        .arg(broad.join("sub/secret.env"))
        .output()
        .expect("spawn bulwark");

    // Must fail (non-zero) and never print the secret.
    assert!(
        !out.status.success(),
        "a symlink-widening hardened grant must be rejected; status was success"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("BROADSECRET"),
        "the symlink target must not be readable; got: {combined:?}"
    );
    assert!(
        combined.contains("resolves through a symlink"),
        "rejection should name the symlink widening; got: {combined:?}"
    );
}

/// Regression: a RELATIVE `--hardened --allow` grant must be rejected. A relative
/// path is resolved against the working directory when the Landlock floor is
/// applied, so `tmp/**` launched from `/` would silently floor all of `/tmp` —
/// wider than the grant string names. The check is a CLI-level bail.
// WO-82@v1: a relative grant is refused because it would resolve against the working directory.
#[test]
#[ignore = "requires Linux"]
fn hardened_rejects_relative_grant() {
    let out = Command::new(bin())
        .args(["run", "--hardened", "--allow", "tmp/**", "--", "true"])
        .output()
        .expect("spawn bulwark");
    assert!(
        !out.status.success(),
        "a relative hardened grant must be rejected; status was success"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("must be an absolute path"),
        "rejection should name the absolute-path requirement; got: {combined:?}"
    );
}

/// Regression: a `--hardened --allow` grant with a symlink in an INTERMEDIATE
/// path component (e.g. `/base/slink/sub/**` where `slink` is a symlink to a
/// broader directory) must not widen the floor. The apply site resolves the
/// prefix with `openat2(RESOLVE_NO_SYMLINKS)`, which refuses a symlink in any
/// component — not just the final one — so the grant adds no rule and the
/// symlink target is not floored.
// WO-81@v1: a symlink in any grant component must not widen the floor at apply time.
#[test]
#[ignore = "requires Linux + Landlock + root + openat2"]
fn hardened_denies_intermediate_symlink_grant() {
    let dir = scratch("intermsym");
    let broad = dir.join("broad");
    fs::create_dir_all(broad.join("sub")).unwrap();
    fs::write(broad.join("sub/secret.env"), "INTERMSECRET=widened\n").unwrap();
    // slink is an intermediate component of the grant, pointing at the broad dir.
    let slink = dir.join("slink");
    std::os::unix::fs::symlink(&broad, &slink).unwrap();
    let grant = format!("{}/sub/**", slink.display());

    let out = run_hardened(
        &grant,
        &[
            "bash",
            "-c",
            &format!("cat {} 2>&1", broad.join("sub/secret.env").display()),
        ],
    );
    assert!(
        !out.contains("INTERMSECRET"),
        "a symlink in an intermediate grant component must not widen the floor; got: {out:?}"
    );
}

// WO-134@v1: regression for the dropped file-level rules. Landlock refuses a
// path_beneath rule that grants READ_DIR on a non-directory, so every regular
// file in the runtime base set (/dev/null among them) and every file-level
// operator grant used to be skipped with only a stderr line: the floor applied,
// the agent started, and could not read /dev/null or /etc/passwd. The floor must
// grant READ_FILE to files and READ_FILE|READ_DIR to directories. Landlock needs
// no root, so this test is not ignored. Where the kernel has no Landlock (a
// developer Mac, an old kernel) it prints why and returns, because cargo has no
// runtime skip; on the Linux CI runner Landlock is expected, so a failed probe
// there is a broken test and FAILS instead of passing while testing nothing.
#[test]
fn hardened_floor_grants_files_and_directories_alike() {
    let probe = Command::new(bin())
        .arg("landlock-check")
        .output()
        .expect("spawn landlock-check");
    if !probe.status.success() {
        let probe_stderr = String::from_utf8_lossy(&probe.stderr);
        if cfg!(target_os = "linux") && std::env::var_os("CI").is_some() {
            panic!(
                "Landlock expected on the Linux CI runner, but `bulwark landlock-check` failed \
                 (status {}); this test would otherwise pass without testing anything. stderr: {}",
                probe.status,
                probe_stderr.trim()
            );
        }
        eprintln!(
            "SKIP hardened_floor_grants_files_and_directories_alike: no Landlock on this kernel \
             (landlock-check status {}; {})",
            probe.status,
            probe_stderr.trim()
        );
        return;
    }

    // Canonical paths: the grant checks refuse a symlinked prefix.
    let dir = fs::canonicalize(scratch("files")).unwrap();
    let d = dir.join("d");
    fs::create_dir_all(&d).unwrap();
    let inner = d.join("inner.txt");
    fs::write(&inner, "INNER_OK\n").unwrap();
    let f = dir.join("f.txt");
    fs::write(&f, "FILE_OK\n").unwrap();
    let g = dir.join("g.txt");
    fs::write(&g, "G_MUST_NOT_LEAK\n").unwrap();

    // F is a file-level grant, D a directory grant, /dev/null comes from the
    // runtime base set, G is a sibling on no list.
    let script = format!(
        "cat {f}; cat {inner}; cat /dev/null && echo NULL_OK; cat {g} 2>&1; exit 0",
        f = f.display(),
        inner = inner.display(),
        g = g.display()
    );
    let out = Command::new(bin())
        .args(["run", "--hardened", "--allow"])
        .arg(format!("{}/**", d.display()))
        .arg("--allow")
        .arg(&f)
        .args(["--", "/bin/sh", "-c", &script])
        .output()
        .expect("spawn bulwark");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stderr.contains("kernel-enforced read floor applied"),
        "the floor must apply; stderr: {stderr}"
    );
    for dropped in [f.display().to_string(), "/dev/null".to_string()] {
        assert!(
            !stderr.contains(&format!("could not add allow rule for {dropped}")),
            "file-level rule for {dropped} must not be dropped; stderr: {stderr}"
        );
    }
    assert!(
        stdout.contains("FILE_OK"),
        "a file-level grant must be readable; stdout: {stdout:?} stderr: {stderr}"
    );
    assert!(
        stdout.contains("INNER_OK"),
        "a file under a directory grant must be readable; stdout: {stdout:?}"
    );
    assert!(
        stdout.contains("NULL_OK"),
        "/dev/null from the base set must open for read; stdout: {stdout:?}"
    );
    assert!(
        !stdout.contains("G_MUST_NOT_LEAK"),
        "a sibling file on no list must stay denied; stdout: {stdout:?}"
    );
    assert!(
        stdout.contains("Permission denied"),
        "the denied sibling must fail with EACCES; stdout: {stdout:?}"
    );
}

// WO-142@v1: regression for the /proc widening. The base set's `/proc/*/stat`
// and `/proc/*/status` reached the Landlock floor as path_beneath(/proc), so a
// hardened agent could read `status`, `stat` and `cmdline` (credentials on a
// command line) of every process on the host. `environ`, `maps`, `cwd` and
// `exe` were already denied, by Landlock's ptrace hook rather than by the
// floor; they are asserted here so that stays true. The red evidence on 0.9.2
// is `status` and `cmdline` of pid 1 and of a same-uid sibling. Same runtime
// policy as the WO-134 test above: not ignored, Landlock needs no root, a
// missing Landlock skips off-CI and fails on the Linux CI runner.
#[test]
fn hardened_floor_does_not_cover_other_processes_in_proc() {
    let probe = Command::new(bin())
        .arg("landlock-check")
        .output()
        .expect("spawn landlock-check");
    if !probe.status.success() {
        let probe_stderr = String::from_utf8_lossy(&probe.stderr);
        if cfg!(target_os = "linux") && std::env::var_os("CI").is_some() {
            panic!(
                "Landlock expected on the Linux CI runner, but `bulwark landlock-check` failed \
                 (status {}); this test would otherwise pass without testing anything. stderr: {}",
                probe.status,
                probe_stderr.trim()
            );
        }
        eprintln!(
            "SKIP hardened_floor_does_not_cover_other_processes_in_proc: no Landlock on this \
             kernel (landlock-check status {}; {})",
            probe.status,
            probe_stderr.trim()
        );
        return;
    }

    // A same-uid sibling outside the supervised tree, with a marker on its
    // command line. The trailing `true` keeps the shell from exec'ing sleep in
    // place, so the pid we hold is the shell whose cmdline carries the marker.
    let mut sibling = Command::new("/bin/sh")
        .args([
            "-c",
            "sleep 60; true",
            "sh",
            "--marker=SIBLING_CMDLINE_MARKER",
        ])
        .spawn()
        .expect("spawn sibling");
    let sib = sibling.id();
    std::thread::sleep(std::time::Duration::from_millis(200));

    let dir = fs::canonicalize(scratch("proc")).unwrap();
    // Each read is labelled so a denial can be told from a missing file, and
    // the script ends with a marker proving the agent ran to the end.
    let script = format!(
        "echo \"STATUS1: $(head -c 40 /proc/1/status 2>&1)\"; \
         echo \"CMDLINE1: $(cat /proc/1/cmdline 2>&1 | tr '\\0' ' ')\"; \
         echo \"ENVIRON1: $(head -c 40 /proc/1/environ 2>&1)\"; \
         echo \"STATUS_SIB: $(head -c 40 /proc/{sib}/status 2>&1)\"; \
         echo \"CMDLINE_SIB: $(cat /proc/{sib}/cmdline 2>&1 | tr '\\0' ' ')\"; \
         echo \"ENVIRON_SIB: $(head -c 40 /proc/{sib}/environ 2>&1)\"; \
         echo \"MAPS_SIB: $(head -c 40 /proc/{sib}/maps 2>&1)\"; \
         echo AGENT_RAN_TO_END; exit 0"
    );
    let out = Command::new(bin())
        .args(["run", "--hardened", "--allow"])
        .arg(format!("{}/**", dir.display()))
        .args(["--", "/bin/sh", "-c", &script])
        .output()
        .expect("spawn bulwark");
    let _ = sibling.kill();
    let _ = sibling.wait();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stderr.contains("kernel-enforced read floor applied"),
        "the floor must apply; stderr: {stderr}"
    );
    assert!(
        stdout.contains("AGENT_RAN_TO_END"),
        "the agent must run under the floor; stdout: {stdout:?} stderr: {stderr}"
    );
    assert!(
        !stdout.contains("Name:"),
        "/proc/<pid>/status of another process must not be readable; stdout: {stdout:?}"
    );
    assert!(
        !stdout.contains("SIBLING_CMDLINE_MARKER") && !stdout.contains("CMDLINE1: /"),
        "/proc/<pid>/cmdline of another process must not be readable; stdout: {stdout:?}"
    );
    for label in [
        "STATUS1",
        "CMDLINE1",
        "ENVIRON1",
        "STATUS_SIB",
        "CMDLINE_SIB",
        "ENVIRON_SIB",
        "MAPS_SIB",
    ] {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(&format!("{label}: ")))
            .unwrap_or_else(|| panic!("no {label} line; stdout: {stdout:?}"));
        assert!(
            line.contains("Permission denied"),
            "{label} must be EACCES, not readable or missing; got: {line:?}"
        );
    }
}

// WO-144@v1: hardened mode exec'd the agent at the launching uid and refused
// `--worker-uid`, so under sudo the agent held root behind the Landlock floor.
// The floor is now applied first and the process drops to the worker before
// the exec. These need a root launcher, so they run in the PR CI root step.
// `SUDO_UID` is set explicitly so the drop target does not depend on how the
// runner reached root (passwordless sudo keeps it, a root runner never had it).
fn run_hardened_as_root(
    grant: &str,
    sudo: Option<(&str, &str)>,
    extra: &[&str],
    cmd: &[&str],
) -> std::process::Output {
    let mut c = Command::new(bin());
    c.args(["run", "--hardened", "--allow", grant]);
    c.args(extra);
    c.arg("--");
    c.args(cmd);
    c.env_remove("SUDO_UID").env_remove("SUDO_GID");
    if let Some((uid, gid)) = sudo {
        c.env("SUDO_UID", uid).env("SUDO_GID", gid);
    }
    c.output().expect("spawn bulwark")
}

// WO-144@v1: under sudo the hardened agent runs as SUDO_UID, and the floor still holds after the drop.
#[test]
#[ignore = "requires Linux + Landlock + root"]
fn hardened_drops_root_agent_to_sudo_uid() {
    let dir = fs::canonicalize(scratch("drop")).unwrap();
    let granted = dir.join("granted");
    fs::create_dir_all(&granted).unwrap();
    fs::write(granted.join("in.txt"), "GRANT_OK\n").unwrap();
    // World-readable and outside the grant: only the floor can deny it.
    let outside = dir.join("outside.txt");
    fs::write(&outside, "OUTSIDE_MUST_NOT_LEAK\n").unwrap();
    let script = format!(
        "id -u; cat {g}/in.txt; echo \"OUTSIDE: $(cat {o} 2>&1)\"; \
         echo \"ENVIRON1: $(head -c 20 /proc/1/environ 2>&1)\"; echo END",
        g = granted.display(),
        o = outside.display()
    );
    let out = run_hardened_as_root(
        &format!("{}/**", granted.display()),
        Some(("65534", "65534")),
        &[],
        &["/bin/sh", "-c", &script],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("kernel-enforced read floor applied"),
        "the floor must apply; stderr: {stderr}"
    );
    assert_eq!(
        stdout.lines().next(),
        Some("65534"),
        "the agent must run as SUDO_UID, never root; stdout: {stdout:?} stderr: {stderr}"
    );
    assert!(
        stdout.contains("GRANT_OK") && stdout.contains("END"),
        "the dropped agent must still read its grant and run to the end; stdout: {stdout:?}"
    );
    assert!(
        !stdout.contains("OUTSIDE_MUST_NOT_LEAK") && stdout.contains("OUTSIDE: cat:"),
        "the floor must still hold after the drop; stdout: {stdout:?}"
    );
    for label in ["OUTSIDE", "ENVIRON1"] {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(&format!("{label}: ")))
            .unwrap_or_else(|| panic!("no {label} line; stdout: {stdout:?}"));
        assert!(
            line.contains("Permission denied"),
            "{label} must be EACCES after the drop; got: {line:?}"
        );
    }
}

// WO-144@v1: an explicit --worker-uid is accepted with --hardened and wins over SUDO_UID.
#[test]
#[ignore = "requires Linux + Landlock + root"]
fn hardened_honours_explicit_worker_uid_over_sudo_uid() {
    let dir = fs::canonicalize(scratch("wuid")).unwrap();
    let out = run_hardened_as_root(
        &format!("{}/**", dir.display()),
        Some(("65533", "65533")),
        &["--worker-uid", "65534", "--worker-gid", "65534"],
        &["id", "-u"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "--worker-uid must be accepted with --hardened; status {} stderr: {stderr}",
        out.status
    );
    assert_eq!(
        stdout.trim(),
        "65534",
        "an explicit --worker-uid must win over SUDO_UID; stdout: {stdout:?} stderr: {stderr}"
    );
}

// WO-144@v1: real root with no worker identity refuses before exec, so nothing runs as root.
#[test]
#[ignore = "requires Linux + Landlock + root"]
fn hardened_refuses_real_root_without_a_worker_uid() {
    let dir = fs::canonicalize(scratch("refuse")).unwrap();
    let marker = dir.join("agent-ran");
    let out = run_hardened_as_root(
        &format!("{}/**", dir.display()),
        None,
        &[],
        &["/bin/sh", "-c", &format!("echo RAN > {}", marker.display())],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "real root with no SUDO_UID and no --worker-uid must be refused; status was success"
    );
    assert!(
        stderr.contains("would run the agent as root") && stderr.contains("nothing was run"),
        "the refusal must say why and that nothing ran; stderr: {stderr}"
    );
    assert!(
        !marker.exists(),
        "the agent must not have been exec'd: marker {} exists",
        marker.display()
    );
}

// WO-144@v1: --allow-root keeps uid 0 only when the operator asks for it.
#[test]
#[ignore = "requires Linux + Landlock + root"]
fn hardened_allow_root_keeps_uid_zero_on_request() {
    let dir = fs::canonicalize(scratch("allowroot")).unwrap();
    let out = run_hardened_as_root(
        &format!("{}/**", dir.display()),
        None,
        &["--allow-root"],
        &["id", "-u"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stderr.contains("kernel-enforced read floor applied"),
        "--allow-root must run the agent under the floor; status {} stderr: {stderr}",
        out.status
    );
    assert_eq!(
        stdout.trim(),
        "0",
        "--allow-root keeps uid 0; stdout: {stdout:?}"
    );
}

// WO-142@v1: with the wildcard /proc entries skipped, the floor had
// no /proc at all, and tools that size themselves from the host went quiet
// rather than loud (node's os.cpus() returned 0). The base set now names the
// system-wide procfs files as exact paths, which the floor grants as file
// rules; per-process entries stay denied. Same runtime policy as the WO-134
// test: Landlock needs no root, a missing Landlock skips off-CI and fails on
// the Linux CI runner.
#[test]
fn hardened_floor_grants_system_wide_proc_files_only() {
    let probe = Command::new(bin())
        .arg("landlock-check")
        .output()
        .expect("spawn landlock-check");
    if !probe.status.success() {
        let probe_stderr = String::from_utf8_lossy(&probe.stderr);
        if cfg!(target_os = "linux") && std::env::var_os("CI").is_some() {
            panic!(
                "Landlock expected on the Linux CI runner, but `bulwark landlock-check` failed \
                 (status {}); this test would otherwise pass without testing anything. stderr: {}",
                probe.status,
                probe_stderr.trim()
            );
        }
        eprintln!(
            "SKIP hardened_floor_grants_system_wide_proc_files_only: no Landlock on this \
             kernel (landlock-check status {}; {})",
            probe.status,
            probe_stderr.trim()
        );
        return;
    }

    let dir = fs::canonicalize(scratch("procsys")).unwrap();
    // Each system-wide file is read and labelled; the two per-process reads
    // must still be denied, and a marker proves the agent ran to the end.
    let script = "for f in /proc/cpuinfo /proc/stat /proc/meminfo /proc/loadavg /proc/uptime; do \
                    if head -c 1 $f >/dev/null 2>&1; then echo \"OK $f\"; \
                    else echo \"FAIL $f: $(head -c 1 $f 2>&1)\"; fi; done; \
                  echo \"STATUS1: $(head -c 40 /proc/1/status 2>&1)\"; \
                  echo \"CMDLINE1: $(cat /proc/1/cmdline 2>&1 | tr '\\0' ' ')\"; \
                  echo AGENT_RAN_TO_END; exit 0";
    let out = Command::new(bin())
        .args(["run", "--hardened", "--allow"])
        .arg(format!("{}/**", dir.display()))
        .args(["--", "/bin/sh", "-c", script])
        .output()
        .expect("spawn bulwark");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stderr.contains("kernel-enforced read floor applied"),
        "the floor must apply; stderr: {stderr}"
    );
    assert!(
        stdout.contains("AGENT_RAN_TO_END"),
        "the agent must run under the floor; stdout: {stdout:?} stderr: {stderr}"
    );
    for f in [
        "/proc/cpuinfo",
        "/proc/stat",
        "/proc/meminfo",
        "/proc/loadavg",
        "/proc/uptime",
    ] {
        assert!(
            stdout.contains(&format!("OK {f}\n")),
            "{f} is a system-wide file the floor must grant; stdout: {stdout:?} stderr: {stderr}"
        );
    }
    for label in ["STATUS1", "CMDLINE1"] {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(&format!("{label}: ")))
            .unwrap_or_else(|| panic!("no {label} line; stdout: {stdout:?}"));
        assert!(
            line.contains("Permission denied"),
            "{label} must stay EACCES; got: {line:?}"
        );
    }
}
