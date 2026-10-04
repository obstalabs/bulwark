//! WO-120: `bulwark ssh --hardened` must reject the hivebus key-handoff flags
//! instead of silently ignoring them. Runs the real CLI with a fake `ssh` on
//! PATH that records every call, so the tests prove the rejection happens at
//! argument parsing, before any remote contact. No root, no network.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

// WO-120: each CLI run gets its own fake-ssh call log and key file.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(format!(
            "/tmp/bulwark-wo120-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        // WO-120: the fake transport only records that it was reached, then
        // fails, so a dispatch that passed argument parsing is observable.
        let ssh = root.join("bin").join("ssh");
        fs::write(
            &ssh,
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FIXTURE_ROOT/ssh.calls\"\nexit 255\n",
        )
        .unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("architect.pub"), "not-a-real-key\n").unwrap();
        Self { root }
    }

    fn architect_pub(&self) -> String {
        self.root.join("architect.pub").display().to_string()
    }

    // WO-120: invoke the actual built CLI with only the transport replaced.
    fn run(&self, args: &[&str]) -> Output {
        let mut paths = vec![self.root.join("bin")];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        Command::new(env!("CARGO_BIN_EXE_bulwark"))
            .arg("ssh")
            .arg("nobody@fixture.invalid")
            .args(args)
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("FIXTURE_ROOT", &self.root)
            .stdin(Stdio::null())
            .output()
            .expect("run real bulwark ssh")
    }

    fn ssh_attempted(&self) -> bool {
        self.root.join("ssh.calls").exists()
    }

    // WO-120: the rejection must come from argument parsing: clap's usage
    // error (exit 2) naming both flags, with the transport never reached.
    fn assert_parse_conflict(&self, out: &Output, hivebus_flag: &str) {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected a clap usage error, got {:?}: {stderr}",
            out.status.code()
        );
        assert!(
            stderr.contains("cannot be used with"),
            "not an argument conflict: {stderr}"
        );
        assert!(
            stderr.contains(hivebus_flag),
            "message lacks {hivebus_flag}: {stderr}"
        );
        assert!(
            stderr.contains("--hardened"),
            "message lacks --hardened: {stderr}"
        );
        assert!(
            !self.ssh_attempted(),
            "ssh was attempted despite the conflict: {stderr}"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// WO-120: a worker seed is never placed under --hardened; refuse rather than
// let the operator believe a fingerprint will be printed.
#[test]
fn hardened_rejects_worker_seed_generate_before_ssh() {
    let f = Fixture::new();
    let out = f.run(&[
        "--hardened",
        "--allow",
        "/usr/**",
        "--hivebus-worker-seed-generate",
        "--",
        "true",
    ]);
    f.assert_parse_conflict(&out, "--hivebus-worker-seed-generate");
}

// WO-120: an architect key is never relayed under --hardened; same refusal.
#[test]
fn hardened_rejects_architect_pub_before_ssh() {
    let f = Fixture::new();
    let pubkey = f.architect_pub();
    let out = f.run(&[
        "--hardened",
        "--allow",
        "/usr/**",
        "--hivebus-architect-pub",
        &pubkey,
        "--",
        "true",
    ]);
    f.assert_parse_conflict(&out, "--hivebus-architect-pub");
}

// WO-120: flag order must not matter to the conflict.
#[test]
fn hardened_after_hivebus_flag_is_still_rejected() {
    let f = Fixture::new();
    let out = f.run(&[
        "--hivebus-worker-seed-generate",
        "--allow",
        "/usr/**",
        "--hardened",
        "--",
        "true",
    ]);
    f.assert_parse_conflict(&out, "--hivebus-worker-seed-generate");
}

// WO-120: the consent (non-hardened) hivebus path must still parse and reach
// the transport; the fake ssh fails there, which is the expected outcome.
#[test]
fn consent_dispatch_with_hivebus_flags_still_reaches_ssh() {
    let f = Fixture::new();
    let pubkey = f.architect_pub();
    let out = f.run(&[
        "--deploy",
        "never",
        "--protect",
        "/fixture-guarded",
        "--auto",
        "deny",
        "--auto-worker-uid",
        "--hivebus-worker-seed-generate",
        "--hivebus-architect-pub",
        &pubkey,
        "--",
        "true",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(
        out.status.code(),
        Some(2),
        "unexpected usage error: {stderr}"
    );
    assert!(
        !stderr.contains("cannot be used with"),
        "consent dispatch must not report a flag conflict: {stderr}"
    );
    assert!(
        f.ssh_attempted(),
        "dispatch never reached the transport: {stderr}"
    );
    assert!(
        !out.status.success(),
        "fake ssh fails, so dispatch cannot succeed"
    );
}
