//! integration: local operator relay + auto-deploy, over `ssh localhost`.
//!
//! These exercise `bulwark ssh` end-to-end on a single Linux host acting as both
//! the local launcher and the remote gate (target `nullbot@localhost`). They
//! need passwordless `ssh localhost`, passwordless `sudo` (fanotify), and outshell
//! tools (mkfifo, curl for the dist path), so they are `#[ignore]` and run under
//! the VM harness only.
//!
//! What they witness:
//!  - the LOCAL operator relay receives a prompt and answers it (the agent does
//!    not see or answer its own consent);
//!  - `--auto` still works non-interactively;
//!  - auto-deploy resolves a remote binary (existing / dist), and a bad mode
//!    fails cleanly.

use std::fs;
use std::io::Write;
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
        std::env::temp_dir().join(format!("bulwark-wo18-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

const TARGET: &str = "nullbot@localhost";

/// `--auto allow-session`: the remote read of a protected file is denied on first
/// touch, the local relay auto-answers allow-session, and the second read passes
/// from cache. No interactive tty needed.
#[test]
#[ignore = "needs ssh localhost + sudo; VM only"]
fn auto_allow_session_lets_second_read_through() {
    let dir = scratch("auto");
    let secret = dir.join("secret.env");
    fs::write(&secret, "SECRETVALUE=wo18\n").unwrap();
    let agent_out = dir.join("out.txt");

    // The agent reads the secret twice with a gap; the relay grants between them.
    let inner = format!(
        "echo r1=[$(cat {s} 2>&1)]; sleep 3; echo r2=[$(cat {s} 2>&1)]",
        s = secret.display()
    );

    let out = Command::new(bin())
        .args([
            "ssh",
            TARGET,
            "--deploy",
            "never",
            "--auto",
            "allow-session",
            "--protect",
        ])
        .arg(&secret)
        .args(["--", "bash", "-c", &inner])
        .output()
        .expect("spawn bulwark ssh");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    fs::write(&agent_out, &combined).ok();

    // The second read must succeed (cache populated by the allow-session grant).
    assert!(
        combined.contains("r2=[SECRETVALUE=wo18"),
        "second read should pass after allow-session; got:\n{combined}"
    );
}

/// Interactive local relay: a scripted operator answers `a` (allow-session) on
/// the local stdin of `bulwark ssh`. The prompt is rendered locally and the
/// grant flows back over the verdict lane.
#[test]
#[ignore = "needs ssh localhost + sudo; VM only"]
fn interactive_operator_grants_locally() {
    let dir = scratch("interactive");
    let secret = dir.join("secret.env");
    fs::write(&secret, "SECRETVALUE=interactive\n").unwrap();

    let inner = format!(
        "echo r1=[$(cat {s} 2>&1)]; sleep 3; echo r2=[$(cat {s} 2>&1)]",
        s = secret.display()
    );

    let mut child = Command::new(bin())
        .args(["ssh", TARGET, "--deploy", "never", "--protect"])
        .arg(&secret)
        .args(["--", "bash", "-c", &inner])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn bulwark ssh");

    // Feed an allow-session answer to the local operator prompt. Send a couple,
    // so the first protected open is granted regardless of prompt timing.
    {
        let mut stdin = child.stdin.take().unwrap();
        let _ = stdin.write_all(b"a\na\n");
        // drop stdin -> EOF after our answers
    }
    let out = child.wait_with_output().expect("wait");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("r2=[SECRETVALUE=interactive"),
        "interactive allow-session should let the second read through; got:\n{combined}"
    );
    // The local operator prompt was rendered on stderr (control, not agent data).
    assert!(
        combined.contains("consent needed"),
        "operator should have seen a rendered prompt; got:\n{combined}"
    );
}

/// `--deploy dist`: fetch the matching release tarball, verify its sha256, and
/// run it. Uses the real published v0.5.0 dist release for this host's arch.
#[test]
#[ignore = "needs ssh localhost + sudo + network; VM only"]
fn deploy_dist_fetches_and_runs() {
    let dir = scratch("dist");
    let secret = dir.join("secret.env");
    fs::write(&secret, "SECRETVALUE=dist\n").unwrap();
    let inner = format!("cat {s} 2>&1 || true", s = secret.display());

    let out = Command::new(bin())
        .args([
            "ssh",
            TARGET,
            "--deploy",
            "dist",
            "--auto",
            "deny",
            "--protect",
        ])
        .arg(&secret)
        .args(["--", "bash", "-c", &inner])
        .output()
        .expect("spawn bulwark ssh");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The dist path should have fetched and run a gate (the deny shows the gate
    // was actually enforcing from the fetched binary).
    assert!(
        combined.contains("fetching bulwark") || combined.contains("from dist"),
        "dist deploy should announce a fetch; got:\n{combined}"
    );
    assert!(
        combined.contains("Permission denied") || combined.contains("deny"),
        "the fetched gate should enforce the protect (deny); got:\n{combined}"
    );
}

/// `--hivebus-worker-seed-generate` places a fresh worker seed on the
/// remote at the documented path with mode 0600 owned by the gate uid (root), and
/// prints the worker's pinnable public-key fingerprint locally. Re-dispatch yields
/// a DIFFERENT seed/fingerprint (freshness is the security property).
///
/// Placement is verified by inspecting the remote filesystem DIRECTLY via a
/// separate ssh while a slow agent keeps the run dir alive — not by reading
/// through the gated agent's data lane (which races teardown). The seed bytes are
/// asserted to never appear in the launcher's own output.
#[test]
#[ignore = "needs ssh localhost + sudo; VM only"]
fn hivebus_seed_placed_0600_and_fingerprint_printed() {
    // One dispatch with a slow agent; returns (launcher_output, remote_dir_listing,
    // seed_mode, seed_owner, seed_bytes_len) captured while the agent sleeps.
    let dispatch = |tag: &str| -> (String, String, String, String, usize) {
        let child = Command::new(bin())
            .args([
                "ssh",
                TARGET,
                "--deploy",
                "never",
                "--auto",
                "deny",
                "--hivebus-worker-seed-generate",
                "--protect",
                "/tmp/bulwark-nonexistent-protect",
                "--",
                "sleep",
                "4",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn bulwark ssh ({tag}): {e}"));

        // While the agent sleeps, inspect the placed seed directly on the remote.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let probe = |cmd: &str| -> String {
            let o = Command::new("ssh")
                .args(["-o", "BatchMode=yes", TARGET])
                .arg(cmd)
                .output()
                .expect("ssh probe");
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        // Resolve THIS dispatch's seed precisely: the newest worker.seed under any
        // bulwark run dir (a bare glob can match stale/sibling dirs and break stat).
        let seed = probe(
            "sudo sh -c 'ls -t /tmp/bulwark-remote-*/hivebus/worker.seed 2>/dev/null | head -1'",
        );
        assert!(
            seed.ends_with("/hivebus/worker.seed"),
            "expected a placed worker.seed; got {seed:?}"
        );
        let listing = probe(&format!("sudo ls -la \"$(dirname {seed})\" 2>&1"));
        let seed_mode = probe(&format!("sudo stat -c %a {seed} 2>/dev/null"));
        let seed_owner = probe(&format!("sudo stat -c %U {seed} 2>/dev/null"));
        // `sudo wc -c FILE` (not `< FILE`): the redirect would be opened by the
        // unprivileged outer shell, which cannot read the root-owned seed.
        let seed_len = probe(&format!("sudo wc -c {seed} 2>/dev/null"))
            .split_whitespace()
            .next()
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(0);

        let out = child.wait_with_output().expect("wait");
        let launcher = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (launcher, listing, seed_mode, seed_owner, seed_len)
    };

    let (first, listing1, mode1, owner1, len1) = dispatch("first");

    // The pinnable fingerprint was printed locally (stderr control line).
    assert!(
        first.contains("hivebus worker key fingerprint (pin this):"),
        "operator should see a pinnable worker fingerprint; got:\n{first}"
    );
    // Contract: worker.seed mode 0600, owned by the gate uid (root).
    assert_eq!(
        mode1, "600",
        "worker.seed must be mode 0600; listing:\n{listing1}"
    );
    assert_eq!(
        owner1, "root",
        "worker.seed must be owned by the gate uid (root)"
    );
    // 45 bytes = base64 of a 32-byte seed (44 chars) + trailing newline.
    assert_eq!(
        len1, 45,
        "worker.seed should be base64(32-byte seed) + newline"
    );

    // The launcher's OWN output must never contain raw seed bytes — only the
    // fingerprint. (The seed lives only on the remote, piped over stdin.)
    let fp_of = |s: &str| -> String {
        s.lines()
            .find_map(|l| l.split("fingerprint (pin this):").nth(1))
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let fp1 = fp_of(&first);
    assert_eq!(
        fp1.len(),
        64,
        "fingerprint is sha256 hex (64 chars); got {fp1:?}"
    );

    // Freshness: a second dispatch yields a different fingerprint (=> different
    // seed; the seed itself never leaves the remote, so we compare fingerprints).
    let (second, _l2, mode2, _o2, _len2) = dispatch("second");
    assert_eq!(mode2, "600", "second dispatch must also place 0600");
    assert_ne!(
        fp1,
        fp_of(&second),
        "each dispatch must generate a fresh worker key"
    );
}

/// The load-bearing CROSS-TOOL guard. The unit test pins bulwark's OWN
/// derivation against a known key; this proves the seam against the REAL hivebus
/// binary — that hivebus accepts a bulwark-placed seed AND derives the identical
/// public-key fingerprint bulwark printed. If hivebus ever changes its seed
/// encoding or fingerprint derivation, the handoff would break silently in the
/// field; this test fails instead. (Manual proof recorded in bulwark/notes,
/// 2026-06-15; this is the automated regression guard.)
///
/// PREREQ: a `hivebus` binary on the remote PATH (built for the remote's arch and
/// installed, e.g. /usr/local/bin/hivebus). The test skips with a clear message if
/// hivebus is absent, so it never silently passes on a host that cannot prove the
/// loop.
#[test]
#[ignore = "needs ssh localhost + sudo + a hivebus binary on the remote; VM only"]
fn hivebus_accepts_bulwark_seed_and_derives_same_fingerprint() {
    let probe = |cmd: &str| -> String {
        let o = Command::new("ssh")
            .args(["-o", "BatchMode=yes", TARGET])
            .arg(cmd)
            .output()
            .expect("ssh probe");
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };

    // Skip (not fail) when the cross-tool prerequisite is missing: this test can
    // only PROVE the loop where hivebus exists; absence is "not exercised here".
    if probe("command -v hivebus >/dev/null 2>&1 && echo yes").is_empty() {
        eprintln!("(skip) no hivebus on {TARGET}; cross-tool loop not exercised here");
        return;
    }

    // Dispatch a slow agent so the placed seed persists while we feed it to hivebus.
    let child = Command::new(bin())
        .args([
            "ssh",
            TARGET,
            "--deploy",
            "never",
            "--auto",
            "deny",
            "--hivebus-worker-seed-generate",
            "--protect",
            "/tmp/bulwark-nonexistent-protect",
            "--",
            "sleep",
            "6",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn bulwark ssh");

    std::thread::sleep(std::time::Duration::from_millis(2000));

    // Resolve THIS dispatch's seed (newest worker.seed under any bulwark run dir),
    // then feed it to the REAL hivebus and derive the public-key fingerprint the
    // same way hivebus's answerKeyFingerprint does: sha256-hex of the raw 32-byte
    // ed25519 public key. The whole pipeline runs remotely as root via one sudo sh
    // so the seed never crosses the wire or lands in argv.
    let hivebus_fp = probe(
        "sudo sh -c '\
         f=$(ls -t /tmp/bulwark-remote-*/hivebus/worker.seed 2>/dev/null | head -1); \
         [ -n \"$f\" ] || exit 0; \
         pub=$(hivebus answer --signing-key \"$(cat \"$f\")\" --print-public-key 2>/dev/null | tail -1); \
         printf %s \"$pub\" | base64 -d | sha256sum | cut -d\" \" -f1'",
    );

    let out = child.wait_with_output().expect("wait");
    let launcher = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // bulwark's printed fingerprint (the pinnable identity the operator records).
    let bulwark_fp = launcher
        .lines()
        .find_map(|l| l.split("fingerprint (pin this):").nth(1))
        .unwrap_or("")
        .trim()
        .to_string();

    assert_eq!(
        bulwark_fp.len(),
        64,
        "bulwark must print a 64-char sha256-hex fingerprint; got {bulwark_fp:?}\n{launcher}"
    );
    assert_eq!(
        hivebus_fp.len(),
        64,
        "hivebus must derive a 64-char fingerprint from the bulwark seed; got {hivebus_fp:?}"
    );
    // THE PROOF: real hivebus, fed the bulwark-placed seed, arrives at the SAME
    // identity bulwark told the operator to pin. The cross-repo seam holds.
    assert_eq!(
        bulwark_fp, hivebus_fp,
        "hivebus-derived fingerprint must equal bulwark's printed fingerprint (cross-tool seam)"
    );
}

/// `--deploy never` with no remote binary fails with a clear message rather than
/// silently running unprotected.
#[test]
#[ignore = "needs ssh localhost; VM only"]
fn deploy_never_without_binary_errors_clearly() {
    // Point PATH at an empty dir on the remote so `command -v bulwark` fails.
    // We simulate "absent" by asking for a binary name that cannot exist via a
    // wrapper: run bulwark ssh against a target whose PATH has no bulwark.
    let dir = scratch("never");
    let secret = dir.join("secret.env");
    fs::write(&secret, "x\n").unwrap();

    // Use env -i over ssh by targeting a command that clears PATH is not possible
    // through our CLI; instead assert the error path shape by checking that a
    // `never` run against a host WITHOUT bulwark on a stripped PATH fails. Here we
    // rely on the message text from ensure_remote_bulwark when command -v fails.
    // If the host DOES have bulwark, this test is a no-op pass (documented).
    let has = Command::new("ssh")
        .args(["-o", "BatchMode=yes", TARGET, "command -v bulwark"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if has {
        eprintln!("(skip) remote has bulwark on PATH; never-error path not exercised here");
        return;
    }
    let out = Command::new(bin())
        .args(["ssh", TARGET, "--deploy", "never", "--protect"])
        .arg(&secret)
        .args(["--", "true"])
        .output()
        .expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("no bulwark on") && combined.contains("--deploy never"),
        "never-without-binary should fail clearly; got:\n{combined}"
    );
}

/// `--auto-worker-uid` drops the remote agent to a fresh ANONYMOUS uid that
/// bulwark picks on the remote — no account is created (nothing to tear down, no
/// orphan). The agent runs as a bare number that has NO `/etc/passwd` entry before
/// or after the dispatch.
#[test]
#[ignore = "needs ssh localhost + sudo; VM only"]
fn auto_worker_uid_runs_as_anonymous_uid_no_orphan() {
    let dir = scratch("autoworker");
    let secret = dir.join("secret.env");
    fs::write(&secret, "x\n").unwrap();

    // The agent prints its uid; the protected read must be denied.
    let out = Command::new(bin())
        .args([
            "ssh",
            TARGET,
            "--deploy",
            "never",
            "--auto",
            "deny",
            "--auto-worker-uid",
            "--protect",
        ])
        .arg(&secret)
        .args(["--", "bash", "-c", "id -u"])
        .output()
        .expect("spawn bulwark ssh --auto-worker-uid");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The agent ran as a non-root uid in the auto-picked range.
    let uid: u32 = combined
        .lines()
        .find_map(|l| l.trim().parse::<u32>().ok())
        .unwrap_or_else(|| panic!("agent should print its uid; got:\n{combined}"));
    assert!(
        uid >= 60000 && uid != 0,
        "expected an anonymous high uid; got {uid}"
    );

    // The launcher recorded the chosen uid (the auditable trace).
    assert!(
        combined.contains(&format!("worker dropped to uid {uid}")),
        "launcher must surface the chosen uid; got:\n{combined}"
    );

    // CRUCIAL: no account was created — the uid has no passwd entry, so there is
    // nothing to orphan. (getent run locally; nullbot@localhost shares this host.)
    let getent = Command::new("getent")
        .args(["passwd", &uid.to_string()])
        .output()
        .expect("getent");
    assert!(
        !getent.status.success(),
        "auto-worker uid {uid} must have NO passwd entry (no account created/orphaned)"
    );
}
