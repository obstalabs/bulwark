//! CLI integration tests for the policy/audit surfaces (no root, no fanotify).
//!
//! Exercises `bulwark allow`, `bulwark deny`, `bulwark check`, and
//! `bulwark audit` against a temp Bulwark.toml and a temp receipts file.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

// WO-5@v1: exercise policy mutation, checking, and receipt audit from the CLI.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bulwark"))
}

// WO-5@v1: exercise policy mutation, checking, and receipt audit from the CLI.
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

// WO-5@v1: exercise policy mutation, checking, and receipt audit from the CLI.
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

// WO-5@v1: exercise policy mutation, checking, and receipt audit from the CLI.
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

// WO-5@v1: exercise policy mutation, checking, and receipt audit from the CLI.
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

// WO-5@v1: exercise policy mutation, checking, and receipt audit from the CLI.
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

// WO-145@v2: make policy checks expand protected entries across host homes.
#[test]
fn check_uses_the_host_home_set_not_home() {
    // WO-145@v2: `check` expands `~/` over the host home set, so pointing
    // $HOME at a nonexistent directory still protects root's `.ssh` (always in
    // the set). Red before G2: a single-home expansion from $HOME missed it.
    let target = if cfg!(target_os = "macos") {
        // host_homes canonicalizes /var/root to /private/var/root on macOS.
        "/private/var/root/.ssh/id_key".to_string()
    } else {
        "/root/.ssh/id_key".to_string()
    };
    let out = Command::new(bin())
        .args(["check", &target, "--profile", "default"])
        .env("HOME", "/nonexistent-home-for-g2")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "check must succeed; stderr: {stderr}");
    assert!(
        stdout.contains("protected"),
        "check must protect {target} regardless of HOME; got: {stdout}"
    );
}

// WO-145@v2: expose the stable policy decision token in JSON output.
#[test]
fn check_json_decided_token_is_machine_readable() {
    // WO-145@v2: the JSON `decision` field carries the machine token, not the
    // human label.
    let protected = Command::new(bin())
        .args([
            "check",
            "--profile",
            "default",
            "--format",
            "json",
            "/home/u/dev/proj/.env",
        ])
        .output()
        .unwrap();
    let p = String::from_utf8_lossy(&protected.stdout);
    assert!(
        p.contains(r#""decision":"protected""#),
        "JSON decision must be the machine token `protected`; got: {p}"
    );

    let outside = Command::new(bin())
        .args([
            "check",
            "--profile",
            "default",
            "--format",
            "json",
            "/var/log/syslog",
        ])
        .output()
        .unwrap();
    let o = String::from_utf8_lossy(&outside.stdout);
    assert!(
        o.contains(r#""decision":"outside_prompt""#),
        "JSON decision must be the machine token `outside_prompt`; got: {o}"
    );
}

// WO-198@v1: `check` resolves symlinks like a real open: a link outside the
// protected directory pointing into it is protected, and says which entry decided.
#[test]
fn check_follows_a_symlink_to_its_protected_target() {
    let dir = std::fs::canonicalize(scratch("symlink")).unwrap();
    let vault = dir.join("vault");
    fs::create_dir_all(&vault).unwrap();
    fs::write(vault.join("key"), "x").unwrap();
    let link = dir.join("innocent.txt");
    std::os::unix::fs::symlink(vault.join("key"), &link).unwrap();
    let policy = dir.join("Bulwark.toml");
    fs::write(
        &policy,
        format!("[protected]\nprompt = [\"{}\"]\n", vault.display()),
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["check", "--format", "json", "--policy"])
        .arg(&policy)
        .arg(&link)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(r#""decision":"protected""#) && stdout.contains(r#""step":5"#),
        "a symlink into a protected directory must be protected by it; got: {stdout}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// WO-198@v1: R1 review R1-5: a relative query resolves from the working directory,
// as an open of the same spelling would.
#[test]
fn check_resolves_a_relative_path_from_the_working_directory() {
    let dir = std::fs::canonicalize(scratch("relative")).unwrap();
    fs::create_dir_all(dir.join("vault")).unwrap();
    fs::write(dir.join("vault/secret"), "x").unwrap();
    let policy = dir.join("Bulwark.toml");
    fs::write(
        &policy,
        format!(
            "[protected]\nprompt = [\"{}\"]\n",
            dir.join("vault/secret").display()
        ),
    )
    .unwrap();
    let out = Command::new(bin())
        .current_dir(&dir)
        .args(["check", "--format", "json", "--policy"])
        .arg(&policy)
        .arg("vault/secret")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(r#""decision":"protected""#),
        "a relative query must resolve from cwd; got: {stdout}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// WO-198@v1: an out-of-grammar protect entry is refused by name, not skipped.
#[test]
fn check_refuses_an_out_of_grammar_entry_by_name() {
    let dir = scratch("grammar");
    let policy = dir.join("Bulwark.toml");
    fs::write(&policy, "[protected]\nprompt = [\"/tmp/a*b*c*d\"]\n").unwrap();
    let out = Command::new(bin())
        .args(["check", "/tmp/x", "--policy"])
        .arg(&policy)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "an out-of-grammar entry must fail check"
    );
    assert!(
        stderr.contains(r#""/tmp/a*b*c*d""#) && stderr.contains("nothing was run"),
        "the refusal must name the entry; got: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// WO-5@v1: exercise policy mutation, checking, and receipt audit from the CLI.
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
        // WO-149@v1: keep each caller's integrity state in its own scratch dir.
        .arg("--state")
        .arg(dir.join("state.toml"))
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
//
// WO-141@v1: the positive evidence used to be the strict resolver's error
// line "cannot stat protected path ~/.ssh", which was the product failing:
// the profile's entries reached that resolver unexpanded, so the starter
// profile never launched. The evidence is now what the policy path prints
// for the same strings once it has expanded and split them. The run still
// stops at the gate (it needs root), but only after the plan resolved.
// WO-145@v2: `~/` no longer expands against HOME but under every home on the
// host, so the evidence is the rule line and the wildcard note, not a path
// under a HOME of the test's choosing.
#[test]
fn launch_with_starter_profile_resolves_protect_like_a_policy_run() {
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
    // HOME is pointed somewhere empty on purpose: the expansion must not
    // read it (WO-145@v2), so nothing about this run may depend on it.
    let out = Command::new(bin())
        .args(["launch", "probe", "--policy"])
        .arg(&policy)
        .arg("--state")
        .arg(dir.join("state.toml"))
        .arg("--consent-socket")
        .arg(dir.join("consent.sock"))
        .env("HOME", dir.join("not-a-home"))
        .current_dir(&dir)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("allow-lists apply only with"),
        "launch must not be refused by the run-surface --allow check; got: {stderr}"
    );
    // The literal `~` is what reached the strict resolver before WO-141. A
    // non-root run may still be refused later by the lenient resolver on a
    // home it cannot stat (root's, after WO-145), which is a different line.
    assert!(
        !stderr.contains("cannot stat protected path ~"),
        "the profile's entries must not reach the strict --protect resolver; got: {stderr}"
    );
    assert!(
        stderr.contains("`~/` entries are protected under every home directory on this host"),
        "the launch must state the home rule once; got: {stderr}"
    );
    assert!(
        stderr.contains("wildcard protected pattern(s)") && stderr.contains("**/.env"),
        "the profile's wildcard entries must be split off and named; got: {stderr}"
    );
    assert!(
        !stderr.contains("not-a-home"),
        "HOME must play no part in the expansion; got: {stderr}"
    );
    assert!(
        stderr.contains("[agents.probe] allow list (") && stderr.contains("bulwark/WO-136"),
        "the dropped allow list must be named at launch; got: {stderr}"
    );
}
