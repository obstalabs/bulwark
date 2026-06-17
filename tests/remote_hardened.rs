//! integration: `bulwark ssh --hardened` applies a crash-safe Landlock read
//! floor on the remote agent (allow-list), over `ssh nullbot@localhost`.
//!
//! `#[ignore]` + VM only: needs passwordless `ssh localhost`, passwordless `sudo`,
//! a `bulwark` binary on the remote PATH, and a Landlock-capable kernel (5.13+).
//!
//! What they witness:
//!  - the remote agent may read INSIDE the `--allow` grant,
//!  - is DENIED outside it (e.g. `/etc/shadow`) — the floor enforces over ssh,
//!  - hardened is crash-safe by construction: the remote `bulwark run --hardened`
//!    installs the floor then execs the agent (no supervisor to kill).

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
        std::env::temp_dir().join(format!("bulwark-wo25-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

const TARGET: &str = "nullbot@localhost";

/// `bulwark ssh --hardened --allow <dir>/**`: the remote agent reads files inside
/// the grant, but a read of `/etc/shadow` (outside the floor) is denied by the
/// remote kernel. Proves the Landlock floor enforces over ssh.
#[test]
#[ignore = "needs ssh localhost + sudo + Landlock (5.13+); VM only"]
fn ssh_hardened_allows_grant_denies_outside() {
    let dir = scratch("hardened");
    let allowed = dir.join("allowed");
    fs::create_dir_all(&allowed).unwrap();
    let needle = allowed.join("app.log");
    fs::write(&needle, "ERROR: needle\n").unwrap();
    let grant = format!("{}/**", allowed.display());

    // The agent reads inside the grant (must succeed) and /etc/shadow (must be
    // denied by the Landlock floor).
    let inner = format!(
        "echo IN=[$(cat {} 2>&1)]; echo OUT=[$(cat /etc/shadow 2>&1)]",
        needle.display()
    );

    let out = Command::new(bin())
        .args(["ssh", TARGET, "--deploy", "never", "--hardened", "--allow"])
        .arg(&grant)
        .args(["--", "bash", "-c", &inner])
        .output()
        .expect("spawn bulwark ssh --hardened");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Inside the grant: the read succeeds.
    assert!(
        combined.contains("IN=[ERROR: needle"),
        "agent must read inside the --allow grant; got:\n{combined}"
    );
    // Outside the floor: /etc/shadow must NOT be readable.
    assert!(
        !combined.contains("root:") && combined.contains("OUT=["),
        "the Landlock floor must deny /etc/shadow over ssh; got:\n{combined}"
    );
}

/// `--hardened` + `--protect` are opposite modes — the launcher must reject the
/// mix locally, before any ssh, with a clear message.
#[test]
fn ssh_hardened_rejects_protect() {
    let out = Command::new(bin())
        .args([
            "ssh",
            TARGET,
            "--hardened",
            "--allow",
            "/tmp/x",
            "--protect",
            "/etc/shadow",
            "--",
            "true",
        ])
        .output()
        .expect("spawn");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && err.contains("--hardened uses --allow"),
        "must reject --hardened + --protect; got:\n{err}"
    );
}

/// `--hardened` with no `--allow` is rejected (no default floor).
#[test]
fn ssh_hardened_requires_allow() {
    let out = Command::new(bin())
        .args(["ssh", TARGET, "--hardened", "--", "true"])
        .output()
        .expect("spawn");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && err.contains("--hardened requires"),
        "must reject --hardened with no --allow; got:\n{err}"
    );
}
