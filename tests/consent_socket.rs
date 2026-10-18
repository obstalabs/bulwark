//! Off-band consent integration tests over the real binary + socket.
//!
//! These spawn `bulwark run --consent socket` (which needs root for fanotify)
//! and a separate `bulwark consent` operator, so they are `#[ignore]` and run
//! under `sudo` on Linux only — same gate as the other integration tests.

// WO-178@v1: reuse the hard-kill scope guard; this suite needs no other helper.
#[allow(dead_code)]
mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

// WO-8@v1: drive the built binary so the off-band consent socket is tested end to end.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bulwark"))
}

// WO-8@v1: each consent scenario gets a private scratch dir for its socket and fixtures.
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
    {
        // WO-147@v1: bind refuses a group/other-writable parent of <sock>.d;
        // force a safe mode here so a loose umask does not leak into the tests.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

// WO-149@v1: give each root test its own integrity state, never the host default.
fn isolated_state(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "bulwark-state-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir.join("state.toml")
}

/// WO-147@v1: the on-disk node for a requested socket path, the
/// same derivation the CLI and `answer_once` use (`<requested>.d/s`). A test
/// must point at THIS node, never at the requested path.
fn sock_node(sock: &std::path::Path) -> PathBuf {
    let mut d = sock.as_os_str().to_os_string();
    d.push(".d");
    PathBuf::from(d).join("s")
}

/// Run a consent scenario: launch the gate (sleeps then reads the secret) and an
/// operator that answers `verdict`. Returns (agent_read_contents, receipts).
// WO-8@v1: run the gate and an off-band operator together, as consent runs in practice.
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
    // WO-149@v1: each scenario call is one test; isolate its integrity state.
    .arg("--state")
    .arg(isolated_state(tag))
    .arg("--")
    .args(["bash", "-c", &inner]);
    let mut gate_child = gate.spawn().expect("spawn gate");

    // Operator: wait for the socket, then answer.
    let sock_op = sock.clone();
    let node = sock_node(&sock);
    let verdict_owned = verdict.to_string();
    let op = thread::spawn(move || {
        for _ in 0..200 {
            if node.exists() {
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

    // WO-103: a run that never produced its evidence must fail, not pass the
    // negative assertions vacuously on an empty string.
    let read = fs::read_to_string(&agent_read)
        .expect("agent_read.txt missing: the supervised command never ran");
    let recs = fs::read_to_string(&receipts).expect("r.jsonl missing: the gate wrote no receipts");
    (read, recs)
}

// WO-8@v1: an operator deny over the socket blocks the read and is receipted as operator.
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

// WO-8@v1: an operator allow-once lets exactly that read through, receipted as operator.
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

// WO-8@v1: the supervised command must not be able to answer its own consent prompt.
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
        // WO-149@v1: isolate this test's integrity state from the host default.
        .arg("--state")
        .arg(isolated_state("selfconsent"))
        .arg("--")
        .args(["bash", "-c", &inner])
        .status()
        .expect("spawn gate");
    // WO-103: the gate exits with the child's status and the supervised script
    // ends in `echo done`, so anything but 0 means the gate itself failed to run
    // (no root/fanotify, refused arguments, child killed), not a denied read.
    assert!(
        status.success(),
        "gate did not run the agent to completion: {status}"
    );

    // WO-103: missing evidence must fail the test, not satisfy the negative check.
    let read = fs::read_to_string(&agent_read)
        .expect("agent_read.txt missing: the supervised command never ran");
    let recs = fs::read_to_string(&receipts).expect("r.jsonl missing: the gate wrote no receipts");
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
// WO-80@v1: a peer that exited before the membership check is refused, so the read stays denied.
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
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
int main(int c,char**v){int s=socket(AF_UNIX,SOCK_STREAM,0);
 struct sockaddr_un a;memset(&a,0,sizeof(a));a.sun_family=AF_UNIX;
 strncpy(a.sun_path,v[1],sizeof(a.sun_path)-1);
 if(connect(s,(struct sockaddr*)&a,sizeof(a))!=0)return 1;
 if(write(s,"allow-session\n",14)!=14)return 2;
 /* prove this client reached the node and wrote its verdict */
 int m=open(v[2],O_WRONLY|O_CREAT|O_TRUNC,0600);
 if(m>=0){write(m,"ok",2);close(m);}
 _exit(0);}
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

    // The supervised command: fire the dead-peer client at the real node, wait so
    // it is surely reaped, THEN attempt the protected read.
    let node = sock_node(&sock);
    let proof = dir.join("deadclient.proof");
    let inner = format!(
        "for i in $(seq 1 50); do [ -S {node} ] && break; sleep 0.05; done; \
         {client} {node} {proof}; sleep 1; cat {secret} > {out} 2>&1; echo done",
        node = node.display(),
        client = client.display(),
        proof = proof.display(),
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
        // WO-149@v1: isolate this test's integrity state from the host default.
        .arg("--state")
        .arg(isolated_state("deadpeer"))
        .arg("--")
        .args(["bash", "-c", &inner])
        .status()
        .expect("spawn gate");
    // WO-103: same contract as above: the script ends in `echo done`, so a
    // non-zero status is a gate failure, which must not count as a denied read.
    assert!(
        status.success(),
        "gate did not run the agent to completion: {status}"
    );

    // WO-103: missing evidence must fail the test, not satisfy the negative check.
    let read = fs::read_to_string(&agent_read)
        .expect("agent_read.txt missing: the supervised command never ran");
    assert!(
        !read.contains("SECRETVALUE"),
        "a dead supervised peer must NOT be able to answer its own consent; got: {read:?}"
    );
    assert!(
        proof.exists(),
        "the dead-peer client must have connected to the node and written its verdict; proof missing"
    );
}

/// WO-147@v1: the socket directory for `sock`, which must match
/// `socket::bound_path`'s `<requested>.d` naming. External because tests cannot
/// import the crate's private derivation; if this drifts, the refusal tests
/// break loudly instead of silently testing the wrong path.
fn sock_dir(sock: &std::path::Path) -> PathBuf {
    PathBuf::from(format!("{}.d", sock.display()))
}

/// Run the gate just far enough to reach `bind`, which must refuse the planted
/// socket directory. Returns stderr.
// WO-147@v1: start the gate only far enough for bind to refuse the planted socket directory.
fn run_and_expect_refusal(sock: &std::path::Path) -> String {
    let out = Command::new(bin())
        .args([
            "run",
            "--allow-root",
            "--consent",
            "socket",
            "--consent-socket",
        ])
        .arg(sock)
        // WO-149@v1: each refusal call is one test; isolate its integrity state.
        .arg("--state")
        .arg(isolated_state("refusal"))
        .args(["--consent-timeout", "3", "--protect", "/etc/hostname", "--"])
        .args(["true"])
        .output()
        .expect("spawn bulwark");
    assert!(
        !out.status.success(),
        "the bind must refuse a foreign socket dir; got success"
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// WO-147@v1: a socket dir owned by another uid is refused and left in place.
#[test]
#[ignore = "requires Linux + root for fanotify + chown"]
fn foreign_owned_socket_dir_is_refused() {
    use std::os::unix::fs::chown;
    let dir = scratch("foreign");
    let sock = dir.join("consent.sock");
    let d = sock_dir(&sock);
    fs::create_dir(&d).unwrap();
    chown(&d, Some(65534), Some(65534)).unwrap();

    let stderr = run_and_expect_refusal(&sock);
    assert!(
        stderr.contains("refusing consent socket dir"),
        "must name the reason it refused; stderr: {stderr}"
    );
    assert!(
        std::path::Path::new(&d).is_dir(),
        "the foreign dir must be left in place (not deleted); stderr: {stderr}"
    );
}

// WO-147@v1: a symlink at the socket dir is refused and its target is untouched.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn symlink_at_socket_dir_is_refused_and_target_unchanged() {
    use std::os::unix::fs::{symlink, MetadataExt};
    let dir = scratch("symlink");
    let sock = dir.join("consent.sock");
    let d = sock_dir(&sock);
    let target = dir.join("target");
    fs::create_dir(&target).unwrap();
    let sentinel = target.join("sentinel.txt");
    fs::write(&sentinel, "sentinel-content").unwrap();
    let before = fs::metadata(&sentinel).unwrap();
    symlink(&target, &d).unwrap();

    let stderr = run_and_expect_refusal(&sock);
    assert!(
        stderr.contains("refusing consent socket dir"),
        "a symlink at the socket dir must be refused; stderr: {stderr}"
    );
    let after = fs::metadata(&sentinel).unwrap();
    assert_eq!(
        (before.mode(), before.uid(), before.gid()),
        (after.mode(), after.uid(), after.gid()),
        "the symlink target's sentinel must be unchanged"
    );
    assert_eq!(
        fs::read_to_string(&sentinel).unwrap(),
        "sentinel-content",
        "sentinel content must be unchanged"
    );
}

// WO-147@v1: a regular file at the socket dir is refused, never deleted.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn regular_file_at_socket_dir_is_not_deleted() {
    let dir = scratch("file");
    let sock = dir.join("consent.sock");
    let d = sock_dir(&sock);
    fs::write(&d, "not-a-dir").unwrap();

    let stderr = run_and_expect_refusal(&sock);
    assert!(
        stderr.contains("refusing consent socket dir"),
        "a regular file at the socket dir must be refused; stderr: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(&d).unwrap(),
        "not-a-dir",
        "the regular file must NOT be deleted"
    );
}

// WO-147@v1: the bound node is a 0600 socket owned by the invoking user.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn node_is_0600_socket_owned_by_invoking_user() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let dir = scratch("node");
    let sock = dir.join("consent.sock");
    let node = sock_node(&sock);
    // WO-178@v1: the killed gate never removes its own cgroup scope.
    let mut gate = common::HardKillScopeGuard::new(
        Command::new(bin())
            .args(["run", "--consent", "socket", "--consent-socket"])
            .arg(&sock)
            // WO-149@v1: isolate this test's integrity state from the host default.
            .arg("--state")
            .arg(isolated_state("node"))
            .args(["--consent-timeout", "4", "--protect", "/etc/hostname", "--"])
            .args(["sleep", "8"])
            .env("SUDO_UID", "65534")
            .env("SUDO_GID", "65534")
            .spawn()
            .expect("spawn gate"),
    );

    for _ in 0..200 {
        if node.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    let m = fs::symlink_metadata(&node).expect("node missing: the gate never bound it");
    assert!(m.file_type().is_socket(), "node must be a socket");
    assert_eq!(m.mode() & 0o777, 0o600, "node must be 0600");
    assert_eq!(m.uid(), 65534, "node must be owned by SUDO_UID");
    let _ = gate.kill();
    let _ = gate.wait();
    // WO-147@v1: leave no scratch behind once the assertions are done.
    let _ = fs::remove_dir_all(&dir);
}

/// WO-147@v1: as root, the default consent socket lives under the root-owned
/// runtime dir (`/run/bulwark` on Linux, `/var/run/bulwark` on macOS) REGARDLESS
/// of `$XDG_RUNTIME_DIR` — so `ensure_root_parent` actually governs the root
/// default, and an attacker's XDG_RUNTIME_DIR (which `sudo -E` preserves and the
/// invoking user owns) cannot steer root's consent socket into a user-owned dir.
#[test]
#[ignore = "requires Linux + root for fanotify"]
fn root_default_socket_ignores_xdg_runtime_dir() {
    use std::os::unix::fs::FileTypeExt;
    if root_default_in_use() {
        eprintln!("SKIP: a live bulwark run already holds the root consent socket");
        return;
    }
    let dir = scratch("rootdefault");
    let xdg = dir.join("xdg");
    fs::create_dir(&xdg).unwrap();
    let node = std::path::PathBuf::from("/run/bulwark/consent.sock.d/s");
    // WO-149@v1: isolate this test's integrity state from the host default.
    let state = isolated_state("rootdefault");

    // WO-178@v1: the killed gate never removes its own cgroup scope.
    let mut gate = common::HardKillScopeGuard::new(
        Command::new(bin())
            .args([
                "run",
                "--state",
                state.to_str().unwrap(),
                "--consent",
                "socket",
                "--consent-timeout",
                "4",
                "--protect",
                "/etc/hostname",
                "--",
            ])
            .args(["sleep", "8"])
            // sudo -E preserves a user-owned XDG_RUNTIME_DIR; as root the default
            // must ignore it and bind under /run/bulwark instead.
            .env("XDG_RUNTIME_DIR", &xdg)
            .spawn()
            .expect("spawn gate"),
    );

    for _ in 0..200 {
        if node.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    let m = fs::symlink_metadata(&node)
        .expect("root default socket must bind under /run/bulwark regardless of XDG_RUNTIME_DIR");
    assert!(m.file_type().is_socket(), "node must be a socket");

    // The answer client, run as root with no --socket, derives the SAME default
    // (the supervisor is still holding the node; a connect forms the request).
    let fired = Command::new("sudo")
        .arg("-E")
        .arg(bin())
        .args(["consent", "--verdict", "deny"])
        .env("XDG_RUNTIME_DIR", &xdg)
        .status()
        .expect("spawn bulwark consent");

    let _ = gate.kill();
    let _ = gate.wait();
    // The answer client is fire-and-forget; its exit status is not asserted here
    // (the node may answer a stale poll), but the socket binding above is the
    // evidence the default ignores XDG_RUNTIME_DIR. Leave the runtime node for
    // subsequent runs to reuse; remove only this test's scratch.
    let _ = fired;
    let _ = fs::remove_dir_all(&dir);
}

/// WO-147@v1: a consent socket under a directory owned by another uid must be
/// refused up front (the parent of `<sock>.d` is neither root's nor ours). Red
/// when the parent is not checked and the bind proceeds inside the foreign dir.
#[test]
#[ignore = "requires Linux + root for fanotify + chown"]
fn parent_owned_by_another_uid_is_refused() {
    use std::os::unix::fs::chown;
    let dir = scratch("parentuid");
    chown(&dir, Some(65534), Some(65534)).unwrap();
    let sock = dir.join("consent.sock");
    let stderr = run_and_expect_refusal(&sock);
    assert!(
        stderr.contains("refusing consent socket parent dir"),
        "must name the parent refusal; stderr: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// WO-147@v1: the tests below exercise the ROOT DEFAULT socket at `/run/bulwark`
/// (the client default and the runtime-dir hardening). They must never delete
/// `/run/bulwark` — so they probe the run lock and skip loudly if a live run
/// already holds it.
fn root_default_in_use() -> bool {
    use std::os::unix::io::AsRawFd;
    let lock = std::path::PathBuf::from("/run/bulwark/consent.sock.d/lock");
    if !lock.exists() {
        return false;
    }
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock)
    else {
        return false;
    };
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    rc != 0 // a non-blocking exclusive lock fails only when a live run holds it
}

/// WO-147@v1: a root gate binds the default `/run/bulwark/consent.sock`; a
/// non-root operator answering `bulwark consent` with NO `--socket` must still
/// reach it (the client default prefers the root runtime socket when its node
/// exists), and the verdict must reach the gate.
#[test]
#[ignore = "requires Linux + root for fanotify + sudo"]
fn non_root_client_connects_to_the_root_gate_default_without_socket() {
    if root_default_in_use() {
        eprintln!("SKIP: a live bulwark run already holds the root consent socket");
        return;
    }
    let dir = scratch("clientdefault");
    let secret = dir.join("secret.env");
    let agent_read = dir.join("agent_read.txt");
    let receipts = dir.join("r.jsonl");
    fs::write(&secret, "protected-payload\n").unwrap();
    let invoking =
        std::env::var("SUDO_USER").expect("run under sudo; SUDO_USER is the invoking user");

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
        "--consent-timeout",
        "20",
        "--protect",
    ])
    .arg(&secret)
    .arg("--receipts")
    .arg(&receipts)
    // WO-149@v1: isolate this test's integrity state from the host default.
    .arg("--state")
    .arg(isolated_state("clientdefault"))
    .arg("--")
    .args(["bash", "-c", &inner]);
    let mut gate_child = gate.spawn().expect("spawn gate");

    let node = std::path::PathBuf::from("/run/bulwark/consent.sock.d/s");
    for _ in 0..200 {
        if node.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_millis(300));
    let out = Command::new("sudo")
        .args(["-u", &invoking])
        .arg(bin())
        .args(["consent", "--verdict", "deny"])
        .output()
        .expect("spawn consent client");
    assert!(
        out.status.success(),
        "a non-root client with no --socket must reach the root default; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = gate_child.wait();
    let read = fs::read_to_string(&agent_read)
        .expect("agent_read.txt missing: the supervised command never ran");
    let recs = fs::read_to_string(&receipts).expect("r.jsonl missing: the gate wrote no receipts");
    assert!(
        !read.contains("protected-payload"),
        "the deny must block the read; got: {read:?}"
    );
    assert!(
        recs.contains(r#""decision":"deny""#) && recs.contains(r#""source":"operator""#),
        "the non-root client's deny must reach the gate and be recorded as operator; got: {recs}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// WO-147@v1: `ensure_root_parent` must leave `/run/bulwark` traversable (0711)
/// even under a restrictive umask (077), and the invoking user must be able to
/// answer. Red when a fresh mkdir under umask 077 leaves it 0700, blocking the
/// invoking user's traversal.
#[test]
#[ignore = "requires Linux + root for fanotify + sudo"]
fn root_parent_is_0711_under_umask_077_and_invoking_user_connects() {
    use std::os::unix::fs::PermissionsExt;
    // The fresh-mkdir umask path is only observable when /run/bulwark does not
    // already exist; never delete it — skip loudly instead.
    if root_default_in_use() || std::path::Path::new("/run/bulwark").exists() {
        eprintln!(
            "SKIP: /run/bulwark already present; the umask-077 fresh-create path is not observable"
        );
        return;
    }
    let invoking =
        std::env::var("SUDO_USER").expect("run under sudo; SUDO_USER is the invoking user");

    // WO-149@v1: isolate the integrity state; created before the umask changes.
    let state = isolated_state("rootparent");
    let old = unsafe { libc::umask(0o077) };
    // WO-178@v1: the killed gate never removes its own cgroup scope.
    let mut gate = common::HardKillScopeGuard::new(
        Command::new(bin())
            .args([
                "run",
                "--state",
                state.to_str().unwrap(),
                "--allow-root",
                "--consent",
                "socket",
                "--consent-timeout",
                "20",
                "--protect",
                "/etc/hostname",
                "--",
            ])
            .args([
                "bash",
                "-c",
                "sleep 3; cat /etc/hostname > /dev/null 2>&1; echo done",
            ])
            .spawn()
            .expect("spawn gate"),
    );
    unsafe { libc::umask(old) };

    let node = std::path::PathBuf::from("/run/bulwark/consent.sock.d/s");
    for _ in 0..200 {
        if node.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let m = fs::metadata("/run/bulwark").expect("/run/bulwark must exist after bind");
    assert_eq!(
        m.permissions().mode() & 0o777,
        0o711,
        "/run/bulwark must be 0711 even under umask 077"
    );

    // The invoking (non-root) user must be able to traverse it and answer.
    thread::sleep(Duration::from_millis(300));
    let out = Command::new("sudo")
        .args(["-u", &invoking])
        .arg(bin())
        .args(["consent", "--verdict", "deny"])
        .output()
        .expect("spawn consent client");
    assert!(
        out.status.success(),
        "the invoking user must connect through a 0711 parent; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = gate.kill();
    let _ = gate.wait();
    // Leave /run/bulwark in place (never delete host runtime state).
}
