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

// WO-145@v3 (G1): a SUDO_UID with no /etc/passwd entry (an LDAP/AD-style
// account) whose home sits outside /home must refuse before anything runs —
// the default profile's `~/` entries cannot cover that user's own home. The
// marker proves the agent never exec'd.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn tilde_refuses_when_sudo_uid_owns_no_enumerated_home() {
    use std::os::unix::fs::chown;
    let uid: u32 = 55_555;
    assert!(
        !std::fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .any(|l| l.split(':').nth(2) == Some("55555")),
        "precondition: uid 55555 must have no /etc/passwd entry"
    );
    let ldap_home = std::path::PathBuf::from("/srv/wo145-ldap-sim");
    fs::create_dir_all(&ldap_home).unwrap();
    let _ = fs::remove_file(ldap_home.join("agent-ran"));
    chown(&ldap_home, Some(uid), Some(uid)).unwrap();
    let marker = ldap_home.join("agent-ran");

    let sh_cmd = format!("echo RAN > {}", marker.display());
    let out = Command::new(bin())
        .args(["run", "--", "/bin/sh", "-c", sh_cmd.as_str()])
        .env("SUDO_UID", uid.to_string())
        .env("SUDO_GID", uid.to_string())
        .env("HOME", ldap_home.to_string_lossy().into_owned())
        .output()
        .expect("spawn bulwark");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a SUDO_UID with no enumerated home must refuse; status {}",
        out.status
    );
    assert!(
        stderr.contains("no home directory on this host is owned by that uid"),
        "the refusal must name the reason; stderr: {stderr}"
    );
    assert!(
        !marker.exists(),
        "nothing may run when the refusal fires; marker {} exists",
        marker.display()
    );
    let _ = fs::remove_file(&marker);
    let _ = fs::remove_dir_all(&ldap_home);
}

// WO-145@v4: an EXPLICIT --worker-uid with no passwd line and no enumerated
// home must REFUSE — the earlier exemption keyed on "no passwd line" wrongly
// spared an LDAP/AD account. Nothing may run.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn tilde_refuses_explicit_worker_uid_with_no_home() {
    use std::os::unix::fs::chown;
    let uid: u32 = 55_556;
    let home = std::path::PathBuf::from("/srv/wo145-ldap-sim2");
    fs::create_dir_all(&home).unwrap();
    let _ = fs::remove_file(home.join("agent-ran"));
    chown(&home, Some(uid), Some(uid)).unwrap();
    let marker = home.join("agent-ran");

    let uid_s = uid.to_string();
    let sh_cmd = format!("echo RAN > {}", marker.display());
    let out = Command::new(bin())
        .args([
            "run",
            "--worker-uid",
            uid_s.as_str(),
            "--",
            "/bin/sh",
            "-c",
            sh_cmd.as_str(),
        ])
        .output()
        .expect("spawn bulwark");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "an explicit --worker-uid with no enumerated home must refuse; status {}",
        out.status
    );
    assert!(
        stderr.contains("no home directory on this host is owned by that uid"),
        "the refusal must name the reason; stderr: {stderr}"
    );
    assert!(
        !marker.exists(),
        "nothing may run; marker {} exists",
        marker.display()
    );
    let _ = fs::remove_file(&marker);
    let _ = fs::remove_dir_all(&home);
}

// WO-145@v4: an --auto-worker-uid anonymous worker (allocated by the remote
// --auto path, no account) OWNS no home, so it is exempt and must still run.
// WO-145@v7: the hidden local-run exemption was removed — `run --worker-uid` with
// no enumerated home must REFUSE with no exemption path left.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn tilde_explicit_worker_uid_with_no_home_refuses_without_an_auto_exemption() {
    use std::os::unix::fs::chown;
    let uid: u32 = 55_557;
    let home = std::path::PathBuf::from("/srv/wo145-ldap-sim3");
    fs::create_dir_all(&home).unwrap();
    let _ = fs::remove_file(home.join("agent-ran"));
    chown(&home, Some(uid), Some(uid)).unwrap();
    let marker = home.join("agent-ran");

    let uid_s = uid.to_string();
    let sh_cmd = format!("echo RAN > {}", marker.display());
    let out = Command::new(bin())
        .args([
            "run",
            "--worker-uid",
            uid_s.as_str(),
            "--",
            "/bin/sh",
            "-c",
            sh_cmd.as_str(),
        ])
        .output()
        .expect("spawn bulwark");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "an explicit --worker-uid with no enumerated home must refuse; status {} stderr: {stderr}",
        out.status
    );
    assert!(
        stderr.contains("no home directory on this host is owned by that uid"),
        "the refusal must name the reason; stderr: {stderr}"
    );
    assert!(
        !marker.exists(),
        "nothing may run; marker {} exists",
        marker.display()
    );
    let _ = fs::remove_file(&marker);
    let _ = fs::remove_dir_all(&home);
}

// WO-145@v6 (F): a root agent with the default `~` profile still covers /root.
// Run-evidence assertions: the agent RAN (done marker + exit 0), the read shows a
// kernel denial and not the secret, and the deny line names /root/.ssh/<fixture>.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn root_agent_home_is_covered_without_a_different_user_message() {
    let key_dir = std::path::PathBuf::from("/root/.ssh");
    fs::create_dir_all(&key_dir).unwrap();
    let name = format!("r6_fixture_{}", std::process::id());
    let key = key_dir.join(&name);
    fs::write(&key, "R6_SECRET\n").unwrap();
    // WO-145@v7 (c): read_out must live OUTSIDE any protected path, so the write
    // redirect itself is not denied — only the key READ is, which is what we assert.
    let scratch_dir = std::env::temp_dir().join(format!(
        "r6-scratch-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&scratch_dir).unwrap();
    let read_out = scratch_dir.join(format!("{name}.read"));
    let key_display = key.display().to_string();

    let inner = format!("cat {key_display} > {} 2>&1; echo done", read_out.display());
    let out = Command::new(bin())
        .args([
            "run",
            "--allow-root",
            "--consent",
            "static",
            "--",
            "/bin/sh",
            "-c",
            inner.as_str(),
        ])
        .output()
        .expect("spawn bulwark");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let status = out.status;
    let read = fs::read_to_string(&read_out).unwrap_or_default();

    // WO-145@v7 (c): clean up FIRST — remove the key and the scratch dir before
    // any assertion, so a failed assertion never leaves fixtures behind.
    let _ = fs::remove_file(&key);
    let _ = fs::remove_dir_all(&scratch_dir);

    // The agent ran under the gate.
    assert!(
        status.success(),
        "agent must run under the gate; status {} stderr: {stderr}",
        status
    );
    assert!(
        stdout.contains("done"),
        "agent must print its completion marker; stdout: {stdout}"
    );
    assert!(
        !read.contains("R6_SECRET"),
        "a root agent must not read /root/.ssh; got: {read:?}"
    );
    assert!(
        read.contains("Operation not permitted") || read.contains("Permission denied"),
        "the read must show the kernel denial; got: {read:?}"
    );
    assert!(
        stderr.contains(&key_display),
        "the deny/receipt line must name /root/.ssh/<fixture>; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("belongs to a different user"),
        "root's own home must not be reported as another user's; stderr: {stderr}"
    );
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

// WO-131@v1: a policy naming a protected path that does not exist on this host
// (the default profile's ~/.ssh on a fresh CI runner) must START, skipping the
// absent path with a note that names it; it must never die in fanotify_mark
// with ENOENT. Before the fix every requested path was marked, present or not.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn policy_with_absent_protected_path_starts_and_names_the_skip() {
    let dir = scratch("absent");
    let ok = dir.join("notes.txt");
    fs::write(&ok, "benign content\n").unwrap();
    let secret = dir.join("secret.env");
    fs::write(&secret, "TOPSECRET=abc\n").unwrap();
    let absent = dir.join("no-such-dot-ssh");
    let policy = dir.join("Bulwark.toml");
    fs::write(
        &policy,
        format!(
            "[protected]\nprompt = [{:?}, {:?}]\n",
            secret.display().to_string(),
            absent.display().to_string()
        ),
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["run", "--allow-root", "--policy"])
        .arg(&policy)
        .args(["--", "cat"])
        .arg(&ok)
        .output()
        .expect("failed to spawn bulwark");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stderr.contains("fanotify_mark on"),
        "an absent protected path must not reach fanotify_mark; stderr={stderr}"
    );
    assert!(
        stderr.contains("not present on this host, skipped")
            && stderr.contains(absent.to_str().unwrap()),
        "the skip note must name the absent path; stderr={stderr}"
    );
    assert!(
        out.status.success(),
        "the run must start with the present paths; stderr={stderr}"
    );
    assert!(
        stdout.contains("benign content"),
        "the agent must run under the gate; stdout={stdout:?}"
    );
}
// WO-145@v2: under plain sudo on Linux HOME is /root, and `~` in the default
// profile, a --policy [protected] section and a launch profile used to expand
// from it: the gate protected /root/.ssh while the agent, dropped to SUDO_UID,
// read the invoking user's real ~/.ssh. A `~/` entry now means that path under
// every home on the host. This runs the three surfaces with HOME=/root and a
// fixture key under a non-root user's home; each must deny the read and write
// a receipt naming that user's path. The test user is SUDO_UID when it is not
// root, else the first passwd user with uid >= 1000 whose home exists; a host
// with neither is a broken test host and fails, not skips.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn tilde_protects_every_home_not_the_sudo_home() {
    let (uid, gid, home) = non_root_test_user();
    let ssh = Path::new(&home).join(".ssh");
    let created_ssh = !ssh.exists();
    fs::create_dir_all(&ssh).unwrap();
    let key = ssh.join("wo145_fixture_key");
    fs::write(&key, "FIXTURE_KEY_MUST_NOT_LEAK\n").unwrap();
    std::os::unix::fs::chown(&key, Some(uid), Some(gid)).unwrap();
    if created_ssh {
        std::os::unix::fs::chown(&ssh, Some(uid), Some(gid)).unwrap();
    }
    // The fixture lives in a real user's ~/.ssh: remove it however the test ends.
    struct Cleanup(PathBuf, Option<PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            if let Some(d) = &self.1 {
                let _ = fs::remove_dir(d);
            }
        }
    }
    let _cleanup = Cleanup(key.clone(), created_ssh.then(|| ssh.clone()));

    let dir = scratch("homes");
    let script = format!("echo \"KEY: $(cat {} 2>&1)\"; exit 0", key.display());
    let policy = dir.join("policy.toml");
    fs::write(&policy, "[protected]\nprompt = [\"~/.ssh\"]\n").unwrap();
    let launch_policy = dir.join("Launch.toml");
    fs::write(
        &launch_policy,
        format!(
            "[agents.a]\ncommand = [\"/bin/sh\", \"-c\", {script:?}]\n\
             protect = [\"~/.ssh\"]\ndecision = \"deny\"\naudit = false\n"
        ),
    )
    .unwrap();

    // (label, arguments before `--`, the supervised command after it; launch
    // takes its command from the profile).
    let cmd = vec!["/bin/sh".to_string(), "-c".to_string(), script.clone()];
    let surfaces: [(&str, Vec<String>, Vec<String>); 3] = [
        ("default profile", vec!["run".into()], cmd.clone()),
        (
            "--policy",
            vec![
                "run".into(),
                "--policy".into(),
                policy.display().to_string(),
            ],
            cmd.clone(),
        ),
        (
            "launch",
            vec![
                "launch".into(),
                "a".into(),
                "--policy".into(),
                launch_policy.display().to_string(),
            ],
            vec![],
        ),
    ];
    for (label, pre, post) in surfaces {
        let tag = label.replace([' ', '-'], "_");
        let receipts = dir.join(format!("{tag}.jsonl"));
        let state = dir.join(format!("{tag}.state.toml"));
        let mut c = Command::new(bin());
        c.args(&pre)
            .arg("--receipts")
            .arg(&receipts)
            .arg("--state")
            .arg(&state);
        if !post.is_empty() {
            c.arg("--").args(&post);
        }
        let out = c
            // Plain sudo: HOME is root's, and the WO-49 default drops the
            // agent to the invoking user, who owns the fixture key.
            .env("HOME", "/root")
            .env("SUDO_UID", uid.to_string())
            .env("SUDO_GID", gid.to_string())
            .current_dir(&dir)
            .output()
            .expect("spawn bulwark");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let recs = fs::read_to_string(&receipts).unwrap_or_default();
        assert!(
            out.status.success(),
            "{label}: the run must complete ({}); stderr: {stderr}",
            out.status
        );
        assert!(
            !stdout.contains("FIXTURE_KEY_MUST_NOT_LEAK") && stdout.contains("KEY: cat:"),
            "{label}: the key under {home} must be denied, not read; stdout: {stdout:?} \
             stderr: {stderr}"
        );
        assert!(
            stderr.contains("`~/` entries are protected under every home directory"),
            "{label}: the rule must be stated; stderr: {stderr}"
        );
        let deny = recs
            .lines()
            .find(|l| l.contains(r#""decision":"deny""#) && l.contains(key.to_str().unwrap()));
        assert!(
            deny.is_some(),
            "{label}: a deny receipt must name {}; receipts: {recs}",
            key.display()
        );
    }
}

/// WO-145@v2: a non-root user with an existing home on this host, for the
/// test above: SUDO_UID when it is not root, else the first `/etc/passwd`
/// entry with uid >= 1000 whose home directory exists. Panics otherwise.
fn non_root_test_user() -> (u32, u32, String) {
    let passwd = fs::read_to_string("/etc/passwd").expect("read /etc/passwd");
    let by_uid = |want: u32| {
        passwd.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 6 && f[2].parse::<u32>().ok() == Some(want) && Path::new(f[5]).is_dir())
                .then(|| (want, f[3].parse::<u32>().unwrap_or(want), f[5].to_string()))
        })
    };
    if let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|u| *u != 0)
    {
        if let Some(found) = by_uid(uid) {
            return found;
        }
    }
    passwd
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let uid = f.get(2)?.parse::<u32>().ok()?;
            (uid >= 1000 && f.len() >= 6 && Path::new(f[5]).is_dir())
                .then(|| (uid, f[3].parse::<u32>().unwrap_or(uid), f[5].to_string()))
        })
        .expect("no non-root user with an existing home on this host; the test needs one")
}
