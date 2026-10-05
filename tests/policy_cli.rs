//! CLI integration tests for the policy/audit surfaces (no root, no fanotify).
//!
//! Exercises `bulwark allow`, `bulwark deny`, `bulwark check`, and
//! `bulwark audit` against a temp Bulwark.toml and a temp receipts file.

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
        std::env::temp_dir().join(format!("bulwark-cli-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn deny_then_allow_writes_policy_file() {
    let dir = scratch("mutate");
    let policy = dir.join("Bulwark.toml");

    let out = Command::new(bin())
        .args(["deny", "~/vault/**", "--policy"])
        .arg(&policy)
        .output()
        .unwrap();
    assert!(out.status.success(), "deny should succeed");
    assert!(policy.exists(), "policy file should be created");

    let body = fs::read_to_string(&policy).unwrap();
    assert!(body.contains("vault"), "protected glob should be written");

    let out = Command::new(bin())
        .args(["allow", "~/dev/proj/**", "--policy"])
        .arg(&policy)
        .output()
        .unwrap();
    assert!(out.status.success(), "allow should succeed");
    let body = fs::read_to_string(&policy).unwrap();
    assert!(body.contains("dev/proj"), "allow glob should be written");
}

#[test]
fn deny_is_idempotent() {
    let dir = scratch("idem");
    let policy = dir.join("Bulwark.toml");
    for _ in 0..2 {
        let out = Command::new(bin())
            .args(["deny", "~/secrets", "--policy"])
            .arg(&policy)
            .output()
            .unwrap();
        assert!(out.status.success());
    }
    let body = fs::read_to_string(&policy).unwrap();
    let count = body.matches("~/secrets").count();
    assert_eq!(count, 1, "duplicate deny must not double-write");
}

#[test]
fn check_reports_protected_for_default_profile() {
    // ~/.ssh is protected in the default profile.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let target = format!("{home}/.ssh/id_ed25519");
    let out = Command::new(bin())
        .args(["check", &target, "--profile", "default"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("protected"),
        "default profile should protect ~/.ssh; got: {stdout}"
    );
    assert!(
        stdout.contains("DENIED"),
        "MVP effect for protected should be denied; got: {stdout}"
    );
}

#[test]
fn check_reports_outside_for_unprotected_path() {
    let out = Command::new(bin())
        .args(["check", "/var/log/syslog", "--profile", "default"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("outside"),
        "unprotected path should fall through to outside default; got: {stdout}"
    );
}

#[test]
fn audit_renders_and_counts_receipts() {
    let dir = scratch("audit");
    let receipts = dir.join("r.jsonl");
    let body = concat!(
        r#"{"ts_ms":1,"pid":10,"dev":1,"ino":2,"decision":"allow","path":"/a","ancestry":"x(10)","reason":"not protected"}"#,
        "\n",
        r#"{"ts_ms":2,"pid":11,"dev":1,"ino":3,"decision":"deny","path":"/b/secret","ancestry":"cat(11) <- bash(9)","reason":"protected inode"}"#,
        "\n",
    );
    fs::write(&receipts, body).unwrap();

    let out = Command::new(bin())
        .args(["audit"])
        .arg(&receipts)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("/b/secret"), "audit should list the path");
    assert!(
        stdout.contains("1 allow, 1 deny"),
        "audit should summarize counts; got: {stdout}"
    );
}

// WO-133@v3: run `bulwark run <args> -- /bin/sh -c 'echo SPAWNED > <marker>'`
// and return (output, marker). A marker that exists afterwards proves the
// agent was spawned; these refusals must happen before that and need no root.
fn run_with_spawn_marker(dir: &std::path::Path, args: &[&str]) -> (std::process::Output, PathBuf) {
    let marker = dir.join("spawned");
    let script = format!("echo SPAWNED > '{}'", marker.display());
    let out = Command::new(bin())
        .arg("run")
        .args(args)
        .args(["--", "/bin/sh", "-c", &script])
        .output()
        .unwrap();
    (out, marker)
}

// WO-133@v3: --allow means nothing on the default deny-list path; running
// anyway would give the operator a different gate than the one they named.
#[test]
fn allow_without_hardened_or_deny_all_refuses_before_spawn() {
    let dir = scratch("allow-alone");
    let glob = format!("{}/**", dir.display());
    let (out, marker) = run_with_spawn_marker(&dir, &["--allow", &glob]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must refuse; stderr: {stderr}");
    assert!(!marker.exists(), "agent was spawned despite the refusal");
    assert!(
        stderr.contains(
            "allow-lists apply only with --hardened (Linux) or --deny-all; nothing was run"
        ),
        "refusal must name the modes that take --allow; got: {stderr}"
    );
}

// WO-133@v3: where Landlock does not exist, --hardened must say that nothing
// ran, so a pasted multi-line demo cannot read as if the agent was supervised.
#[cfg(not(target_os = "linux"))]
#[test]
fn hardened_unsupported_refuses_before_spawn() {
    let dir = scratch("hardened-stub");
    // Canonical, so the symlink-widening check (/var -> /private/var on macOS)
    // does not refuse the grant before the platform stub is reached.
    let real = fs::canonicalize(&dir).unwrap();
    let glob = format!("{}/**", real.display());
    let (out, marker) = run_with_spawn_marker(&dir, &["--hardened", "--allow", &glob]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must refuse; stderr: {stderr}");
    assert!(!marker.exists(), "agent was spawned despite the refusal");
    assert!(
        stderr.contains("not available on this platform"),
        "refusal must say hardened mode is unavailable; got: {stderr}"
    );
    assert!(
        stderr.contains("run without --hardened to use the Endpoint Security gate"),
        "refusal must name the alternative; got: {stderr}"
    );
    assert!(
        stderr.trim_end().ends_with("; nothing was run"),
        "refusal must end with '; nothing was run'; got: {stderr}"
    );
}

// WO-133@v3: the refusal lives on the `run` surface only. `bulwark launch`
// with the starter profile (protect AND allow, a deny-list launch) must keep
// reaching its own path; the operator ruled its allow-list semantics a
// separate WO. This pins that the new check never fires for launch.
#[test]
fn launch_with_starter_profile_is_not_refused_by_the_allow_check() {
    let dir = scratch("launch-starter");
    let policy = dir.join("Bulwark.toml");
    let init = Command::new(bin())
        .args(["launch", "--init", "probe", "--policy"])
        .arg(&policy)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "launch --init must write the starter profile; stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let body = fs::read_to_string(&policy).unwrap();
    assert!(
        body.contains("[agents.probe]")
            && body.contains("allow = [")
            && body.contains("protect = ["),
        "the starter profile must carry both protect and allow; got: {body}"
    );
    let out = Command::new(bin())
        .args(["launch", "probe", "--policy"])
        .arg(&policy)
        .current_dir(&dir)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("allow-lists apply only with"),
        "launch must not be refused by the run-surface --allow check; got: {stderr}"
    );
}
