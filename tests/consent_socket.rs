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

/// Dead-peer race: a supervised child connects to the consent socket, writes an
/// `allow-session` verdict, and exits IMMEDIATELY. `SO_PEERCRED` reports the pid
/// captured at connect(), which outlives the process, but by the time the
/// supervisor checks tree membership the child's `/proc` entry is gone — so a
/// "reject only if provably in-tree" rule would accept the dead in-tree peer and
/// let the agent answer its own consent. The gate must refuse a peer it can no
/// longer observe (fail closed), so the protected read stays denied.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn dead_peer_cannot_answer_its_own_consent() {
    let dir = scratch("deadpeer");
    let secret = dir.join("secret.env");
    let agent_read = dir.join("agent_read.txt");
    let receipts = dir.join("r.jsonl");
    let sock = dir.join("consent.sock");
    let client = dir.join("deadclient");
    fs::write(&secret, "SECRETVALUE=deadpeer\n").unwrap();

    // Minimal raw client: connect, write the verdict, _exit immediately (no wait,
    // no clean close) so it is dead before the supervisor's membership check.
    let csrc = dir.join("deadclient.c");
    fs::write(
        &csrc,
        r#"#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
int main(int c,char**v){int s=socket(AF_UNIX,SOCK_STREAM,0);
 struct sockaddr_un a;memset(&a,0,sizeof(a));a.sun_family=AF_UNIX;
 strncpy(a.sun_path,v[1],sizeof(a.sun_path)-1);
 if(connect(s,(struct sockaddr*)&a,sizeof(a))!=0)return 1;
 write(s,"allow-session\n",14);_exit(0);}
"#,
    )
    .unwrap();
    assert!(Command::new("cc")
        .arg(&csrc)
        .arg("-o")
        .arg(&client)
        .status()
        .expect("cc")
        .success());

    // The supervised command: fire the dead-peer client, wait so it is surely
    // reaped, THEN attempt the protected read.
    let inner = format!(
        "for i in $(seq 1 50); do [ -S {sock} ] && break; sleep 0.05; done; \
         {client} {sock}; sleep 1; cat {secret} > {out} 2>&1; echo done",
        sock = sock.display(),
        client = client.display(),
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
        .args(["--consent-timeout", "8", "--protect"])
        .arg(&secret)
        .arg("--receipts")
        .arg(&receipts)
        .arg("--")
        .args(["bash", "-c", &inner])
        .status()
        .expect("spawn gate");
    assert!(status.success() || !status.success());

    let read = fs::read_to_string(&agent_read).unwrap_or_default();
    assert!(
        !read.contains("SECRETVALUE"),
        "a dead supervised peer must NOT be able to answer its own consent; got: {read:?}"
    );
}
