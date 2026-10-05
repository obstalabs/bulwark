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

/// Regression: a `--hardened --allow` grant with a symlink in an INTERMEDIATE
/// path component (e.g. `/base/slink/sub/**` where `slink` is a symlink to a
/// broader directory) must not widen the floor. The apply site resolves the
/// prefix with `openat2(RESOLVE_NO_SYMLINKS)`, which refuses a symlink in any
/// component — not just the final one — so the grant adds no rule and the
/// symlink target is not floored.
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
// no root, so this test is not ignored; where the kernel has no Landlock it
// says so and returns (cargo has no runtime skip).
#[test]
fn hardened_floor_grants_files_and_directories_alike() {
    let probe = Command::new(bin())
        .arg("landlock-check")
        .output()
        .expect("spawn landlock-check");
    if !probe.status.success() {
        eprintln!(
            "SKIP hardened_floor_grants_files_and_directories_alike: no Landlock on this kernel"
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
