//! Off-band consent integration tests over the real binary + socket.
//!
//! These spawn `bulwark run --consent socket` (which needs root for fanotify)
//! and a separate `bulwark consent` operator, so they are `#[ignore]` and run
//! under `sudo` on Linux only — same gate as the other integration tests.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
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
        "bulwark-consent-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run a consent scenario: launch the gate (sleeps then reads the secret) and an
/// operator that answers `verdict`. Returns (agent_read_contents, receipts).
fn scenario(tag: &str, verdict: &str) -> (String, String) {
    let dir = scratch(tag);
    let secret = dir.join("secret.env");
    let agent_read = dir.join("agent_read.txt");
    let receipts = dir.join("r.jsonl");
    let sock = dir.join("consent.sock");
    fs::write(&secret, "SECRETVALUE=xyzzy\n").unwrap();

    let inner = format!(
        "sleep 3; cat {} > {} 2>&1; echo done",
        secret.display(),
        agent_read.display()
    );
    let mut gate = Command::new(bin());
    gate.args([
        "run",
        "--allow-root",
        "--consent",
        "socket",
        "--consent-socket",
    ])
    .arg(&sock)
    .args(["--consent-timeout", "20", "--protect"])
    .arg(&secret)
    .arg("--receipts")
    .arg(&receipts)
    .arg("--")
    .args(["bash", "-c", &inner]);
    let mut gate_child = gate.spawn().expect("spawn gate");

    // Operator: wait for the socket, then answer.
    let sock_op = sock.clone();
    let verdict_owned = verdict.to_string();
    let op = thread::spawn(move || {
        for _ in 0..200 {
            if sock_op.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        thread::sleep(Duration::from_millis(300));
        let _ = Command::new(bin())
            .args(["consent", "--socket"])
            .arg(&sock_op)
            .args(["--verdict", &verdict_owned])
            .output();
    });

    let _ = gate_child.wait();
    op.join().unwrap();

    let read = fs::read_to_string(&agent_read).unwrap_or_default();
    let recs = fs::read_to_string(&receipts).unwrap_or_default();
    (read, recs)
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn operator_deny_blocks_read_with_operator_source() {
    let (read, recs) = scenario("deny", "deny");
    assert!(
        !read.contains("SECRETVALUE"),
        "denied read must not yield secret content; got: {read:?}"
    );
    assert!(
        recs.contains(r#""decision":"deny""#) && recs.contains(r#""source":"operator""#),
        "receipt should record an operator deny; got: {recs}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn operator_allow_once_lets_read_through_with_operator_source() {
    let (read, recs) = scenario("allow", "allow-once");
    assert!(
        read.contains("SECRETVALUE"),
        "operator-allowed read should yield content; got: {read:?}"
    );
    assert!(
        recs.contains(r#""decision":"allow""#) && recs.contains(r#""source":"operator""#),
        "receipt should record an operator allow; got: {recs}"
    );
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn agent_cannot_answer_its_own_consent() {
    // The supervised command tries to answer consent for itself; SO_PEERCRED
    // must refuse it, so the read times out to deny.
    let dir = scratch("self");
    let secret = dir.join("secret.env");
    let agent_read = dir.join("agent_read.txt");
    let receipts = dir.join("r.jsonl");
    let sock = dir.join("consent.sock");
    fs::write(&secret, "SECRETVALUE=selfapprove\n").unwrap();

    let inner = format!(
        "{bin} consent --socket {sock} --verdict allow-once >/dev/null 2>&1 & sleep 1; \
         cat {secret} > {out} 2>&1; echo done",
        bin = bin().display(),
        sock = sock.display(),
        secret = secret.display(),
        out = agent_read.display(),
    );
    let status = Command::new(bin())
        .args([
            "run",
            "--allow-root",
            "--consent",
            "socket",
            "--consent-socket",
        ])
        .arg(&sock)
        .args(["--consent-timeout", "6", "--protect"])
        .arg(&secret)
        .arg("--receipts")
        .arg(&receipts)
        .arg("--")
        .args(["bash", "-c", &inner])
        .status()
        .expect("spawn gate");
    assert!(status.success() || !status.success()); // gate exit code is the child's

    let read = fs::read_to_string(&agent_read).unwrap_or_default();
    let recs = fs::read_to_string(&receipts).unwrap_or_default();
    assert!(
        !read.contains("SECRETVALUE"),
        "agent self-approval must NOT yield the secret; got: {read:?}"
    );
    assert!(
        recs.contains(r#""decision":"deny""#),
        "self-approval attempt must be denied; got: {recs}"
    );
}
