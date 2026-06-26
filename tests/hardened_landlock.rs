//! hardened-mode (Landlock floor) integration tests. Require Linux with
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
