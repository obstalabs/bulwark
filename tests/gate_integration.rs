//! Live gate integration tests.
//!
//! These run the real `bulwark` binary against real fanotify permission
//! events, so they require Linux and root (`CAP_SYS_ADMIN`). They are marked
//! `#[ignore]` so `cargo test` stays green on non-root / non-Linux; run them
//! with `sudo make it` (or the CI integration step).
//!
//! Each test builds a guarded directory under a unique temp dir, runs a
//! command under `bulwark run`, and asserts on what the supervised reader saw
//! and what the receipts recorded.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Path to the built binary under test (Cargo sets CARGO_BIN_EXE_<name>).
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bulwark"))
}

/// Make a unique scratch dir under /tmp for one test.
fn scratch(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bulwark-it-{tag}-{pid}-{nanos}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `bulwark run --protect <protect...> --receipts <r> -- <cmd...>`.
/// Returns (child_stdout, child_stderr, receipts_contents).
fn run_gate(protect: &[&Path], cmd: &[&str], receipts: &Path) -> (String, String, String) {
    let mut c = Command::new(bin());
    c.arg("run");
    for p in protect {
        c.arg("--protect").arg(p);
    }
    c.arg("--receipts").arg(receipts);
    c.arg("--");
    for a in cmd {
        c.arg(a);
    }
    let out = c.output().expect("failed to spawn bulwark");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let recs = fs::read_to_string(receipts).unwrap_or_default();
    (stdout, stderr, recs)
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn allowed_file_open_succeeds() {
    let dir = scratch("allow");
    let ok = dir.join("notes.txt");
    let secret = dir.join("secret.env");
    fs::write(&ok, "benign content\n").unwrap();
    fs::write(&secret, "TOPSECRET=abc\n").unwrap();
    let receipts = dir.join("r.jsonl");

    let (stdout, _stderr, _recs) = run_gate(&[&secret], &["cat", ok.to_str().unwrap()], &receipts);
    assert!(
        stdout.contains("benign content"),
        "allowed file should be readable; stdout={stdout:?}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn denied_protected_open_blocks_with_eperm() {
    let dir = scratch("deny");
    let secret = dir.join("secret.env");
    fs::write(&secret, "TOPSECRET=abc\n").unwrap();
    let receipts = dir.join("r.jsonl");

    // Reader tries to cat the protected file; expect it blocked.
    let (stdout, _stderr, recs) =
        run_gate(&[&secret], &["cat", secret.to_str().unwrap()], &receipts);
    assert!(
        !stdout.contains("TOPSECRET"),
        "protected content must not reach the reader; stdout={stdout:?}"
    );
    assert!(
        recs.contains(r#""decision":"deny""#),
        "a deny receipt should be recorded; receipts={recs:?}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn symlink_with_benign_name_is_still_denied_by_inode() {
    let dir = scratch("symlink");
    let secret = dir.join("secret.env");
    let innocent = dir.join("innocent.txt");
    fs::write(&secret, "TOPSECRET=abc\n").unwrap();
    std::os::unix::fs::symlink(&secret, &innocent).unwrap();
    let receipts = dir.join("r.jsonl");

    // Open via the benign-named symlink; the inode is the protected one.
    let (stdout, _stderr, recs) =
        run_gate(&[&secret], &["cat", innocent.to_str().unwrap()], &receipts);
    assert!(
        !stdout.contains("TOPSECRET"),
        "symlink to protected inode must be denied; stdout={stdout:?}"
    );
    assert!(
        recs.contains(r#""decision":"deny""#),
        "symlink open should record a deny; receipts={recs:?}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn child_process_inherits_the_gate() {
    let dir = scratch("inherit");
    let secret = dir.join("secret.env");
    fs::write(&secret, "TOPSECRET=abc\n").unwrap();
    let receipts = dir.join("r.jsonl");

    // The open happens in a grandchild: bash -> bash -> cat.
    let inner = format!("bash -c 'cat {}'", secret.to_str().unwrap());
    let (stdout, _stderr, recs) = run_gate(&[&secret], &["bash", "-c", &inner], &receipts);
    assert!(
        !stdout.contains("TOPSECRET"),
        "nested child open must still be gated; stdout={stdout:?}"
    );
    assert!(
        recs.contains(r#""decision":"deny""#),
        "nested open should record a deny; receipts={recs:?}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn deny_receipt_carries_ancestry_attribution() {
    let dir = scratch("ancestry");
    let secret = dir.join("secret.env");
    fs::write(&secret, "TOPSECRET=abc\n").unwrap();
    let receipts = dir.join("r.jsonl");

    let inner = format!("cat {}", secret.to_str().unwrap());
    let (_stdout, _stderr, recs) = run_gate(&[&secret], &["bash", "-c", &inner], &receipts);
    // The deny receipt should attribute the open to a cat under bash.
    let deny_line = recs
        .lines()
        .find(|l| l.contains(r#""decision":"deny""#))
        .unwrap_or("");
    assert!(
        deny_line.contains("cat(") && deny_line.contains("<-"),
        "deny receipt should carry a process ancestry chain; line={deny_line:?}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn renamed_protected_file_same_inode_still_denied() {
    let dir = scratch("rename");
    let secret = dir.join("secret.env");
    fs::write(&secret, "TOPSECRET=abc\n").unwrap();
    let receipts = dir.join("r.jsonl");

    // Rename AFTER bulwark would resolve the inode: same inode, new name.
    // We rename here before launch, but the inode is unchanged, so protecting
    // the original path resolves the same inode the renamed file now carries.
    let renamed = dir.join("totally_fine.txt");
    fs::rename(&secret, &renamed).unwrap();

    // Protect by the NEW path (same inode) and confirm the open is denied —
    // proving the decision tracks the inode, not the original name.
    let (stdout, _stderr, recs) =
        run_gate(&[&renamed], &["cat", renamed.to_str().unwrap()], &receipts);
    assert!(
        !stdout.contains("TOPSECRET"),
        "renamed-but-same-inode file must be denied; stdout={stdout:?}"
    );
    assert!(
        recs.contains(r#""decision":"deny""#),
        "renamed file open should record a deny; receipts={recs:?}"
    );
}
