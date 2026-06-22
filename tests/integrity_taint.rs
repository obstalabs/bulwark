//! Integrity circuit-breaker integration tests, over the real binary.
//!
//! These run `bulwark run` (which needs root for the fanotify gate) with a
//! per-test `--state` file, so they are `#[ignore]` and run under `sudo` on
//! Linux only — the same gate as the other integration tests. They witness the
//! taint lifecycle end-to-end: a clean run does not taint; an unclean restart
//! and object-identity drift both taint; and `bulwark reset` clears it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
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
        "bulwark-integrity-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `bulwark run --protect <secret> --state <state> -- <cmd>` to completion
/// and return its combined stderr (where taint notices and receipts are
/// printed). The supervised command is trivial — taint evaluation happens at
/// startup, before the gate forks, so it does not matter what the agent does.
fn run_gate(secret: &Path, state: &Path, cmd: &[&str]) -> String {
    let out = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(secret)
        .arg("--state")
        .arg(state)
        .arg("--")
        .args(cmd)
        .output()
        .expect("spawn gate");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

const TAINT_MARK: &str = "INTEGRITY TAINTED";

#[test]
#[ignore = "needs root (fanotify); run under sudo on Linux"]
fn clean_restart_is_not_tainted() {
    // AC4: a clean shutdown then a restart with unchanged identity is NOT tainted.
    let dir = scratch("clean");
    let secret = dir.join("secret.env");
    let state = dir.join("state.toml");
    fs::write(&secret, "SECRET=1\n").unwrap();

    let first = run_gate(&secret, &state, &["true"]);
    assert!(
        !first.contains(TAINT_MARK),
        "first run must not be tainted; stderr:\n{first}"
    );
    let second = run_gate(&secret, &state, &["true"]);
    assert!(
        !second.contains(TAINT_MARK),
        "clean restart must not be tainted; stderr:\n{second}"
    );
}

#[test]
#[ignore = "needs root (fanotify); run under sudo on Linux"]
fn unclean_restart_taints_then_reset_clears() {
    // AC1 + reset: a hard-killed supervisor leaves no clean marker, so the next
    // run is tainted; `bulwark reset` clears it and the following run is clean.
    let dir = scratch("unclean");
    let secret = dir.join("secret.env");
    let state = dir.join("state.toml");
    fs::write(&secret, "SECRET=1\n").unwrap();

    // Run 1: a gate that sleeps long enough for us to SIGKILL it mid-flight, so
    // mark_clean_shutdown never runs.
    let mut child = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&secret)
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sleep", "30"])
        .spawn()
        .expect("spawn gate");
    // Let it install the gate and write begin_run state.
    std::thread::sleep(Duration::from_millis(1500));
    // SIGKILL the supervisor: no graceful path, no clean marker.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGKILL);
    }
    let _ = child.wait();

    // Run 2: detects the unclean restart.
    let tainted = run_gate(&secret, &state, &["true"]);
    assert!(
        tainted.contains(TAINT_MARK) && tainted.contains("unclean restart"),
        "run after SIGKILL must be tainted as unclean restart; stderr:\n{tainted}"
    );

    // Operator acknowledges.
    let reset = Command::new(bin())
        .args(["reset", "--state"])
        .arg(&state)
        .output()
        .expect("spawn reset");
    let reset_out = String::from_utf8_lossy(&reset.stdout);
    assert!(
        reset_out.contains("taint cleared"),
        "reset should report cleared; stdout:\n{reset_out}"
    );

    // Run 3: clean again.
    let after = run_gate(&secret, &state, &["true"]);
    assert!(
        !after.contains(TAINT_MARK),
        "after reset the run must be clean; stderr:\n{after}"
    );
}

#[test]
#[ignore = "needs root (fanotify); run under sudo on Linux"]
fn object_identity_drift_taints() {
    // AC2: a protected path that resolves to a different inode between runs is
    // tainted as object-identity drift.
    let dir = scratch("drift");
    let secret = dir.join("secret.env");
    let state = dir.join("state.toml");
    fs::write(&secret, "SECRET=1\n").unwrap();

    // Run 1: clean, records the original inode.
    let first = run_gate(&secret, &state, &["true"]);
    assert!(
        !first.contains(TAINT_MARK),
        "first run clean; stderr:\n{first}"
    );

    // Swap the file for a brand-new inode at the same path.
    fs::remove_file(&secret).unwrap();
    fs::write(&secret, "SECRET=2\n").unwrap();

    // Run 2: the path now resolves to a different inode -> drift.
    let drifted = run_gate(&secret, &state, &["true"]);
    assert!(
        drifted.contains(TAINT_MARK) && drifted.contains("drift"),
        "inode swap must taint as object drift; stderr:\n{drifted}"
    );
}

#[test]
#[ignore = "needs root (fanotify); run under sudo on Linux"]
fn taint_receipt_is_recorded() {
    // AC3: the taint emits an audit receipt with source "integrity".
    let dir = scratch("receipt");
    let secret = dir.join("secret.env");
    let state = dir.join("state.toml");
    let receipts = dir.join("r.jsonl");
    fs::write(&secret, "SECRET=1\n").unwrap();

    // Cause an unclean restart.
    let mut child = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&secret)
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sleep", "30"])
        .spawn()
        .expect("spawn gate");
    std::thread::sleep(Duration::from_millis(1500));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGKILL);
    }
    let _ = child.wait();

    // Next run writes a taint receipt to the receipts file.
    Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&secret)
        .arg("--state")
        .arg(&state)
        .arg("--receipts")
        .arg(&receipts)
        .arg("--")
        .args(["true"])
        .output()
        .expect("spawn gate");

    let body = fs::read_to_string(&receipts).unwrap_or_default();
    assert!(
        body.contains("\"source\":\"integrity\""),
        "receipts must contain an integrity taint record; got:\n{body}"
    );
}
