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
