//! allow-list (CI/CD default-deny) integration tests. Require Linux +
//! root (fanotify), so `#[ignore]` + run under `sudo` like the other suites.
//!
//! The scenario: a triage agent is dispatched with `--deny-all --allow <log>`.
//! It must be able to read the granted log and execute, while every other read
//! (the data directory, credentials, /etc/shadow) is denied — verifying real
//! least-privilege, no human in the loop.

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
    let dir = std::env::temp_dir().join(format!("bulwark-ci-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `bulwark run --deny-all --allow <grant> -- <cmd>` and return stdout.
fn run_allowlist(grant: &str, cmd: &[&str]) -> String {
    let mut c = Command::new(bin());
    c.args(["run", "--deny-all", "--allow", grant, "--"]);
    for a in cmd {
        c.arg(a);
    }
    let out = c.output().expect("spawn bulwark");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn triage_agent_reads_granted_log_and_executes() {
    let dir = scratch("granted");
    let log = dir.join("clickhouse.log");
    fs::write(&log, "2026-06-04 ERROR: query timeout on shard 3\n").unwrap();
    let grant = format!("{}/**", dir.display());

    // The agent runs grep (must load libc etc via the base set) over the log.
    let out = run_allowlist(&grant, &["grep", "ERROR", log.to_str().unwrap()]);
    assert!(
        out.contains("query timeout"),
        "agent must be able to read the granted log AND execute; got: {out:?}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn triage_agent_denied_credentials_and_data_outside_grant() {
    let dir = scratch("denied");
    let log_dir = dir.join("logs");
    let secrets = dir.join("secrets");
    fs::create_dir_all(&log_dir).unwrap();
    fs::create_dir_all(&secrets).unwrap();
    fs::write(log_dir.join("app.log"), "log line\n").unwrap();
    let creds = secrets.join("credentials");
    fs::write(&creds, "AWS_SECRET=AKIA-do-not-leak\n").unwrap();

    // Granted only the log dir; the credentials are elsewhere.
    let grant = format!("{}/**", log_dir.display());
    let out = run_allowlist(
        &grant,
        &["bash", "-c", &format!("cat {} 2>&1", creds.display())],
    );
    assert!(
        !out.contains("AWS_SECRET"),
        "credentials outside the grant must be denied; got: {out:?}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn triage_agent_denied_etc_shadow() {
    let dir = scratch("shadow");
    let log = dir.join("app.log");
    fs::write(&log, "log\n").unwrap();
    let grant = format!("{}/**", dir.display());

    // /etc/shadow is not in the runtime base set (only /etc/passwd is).
    let out = run_allowlist(&grant, &["bash", "-c", "cat /etc/shadow 2>&1"]);
    assert!(
        !out.contains("root:") && !out.contains(":$"),
        "/etc/shadow must be denied in allow-list mode; got: {out:?}"
    );
}
