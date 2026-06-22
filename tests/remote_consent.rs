//! remote-gate integration test. Exercises the remote consent mode's
//! decision/prompt split through the real binary + FIFO lanes (no SSH needed —
//! SSH is only transport; this tests the enforcement + lane logic that runs on
//! the remote host). Requires Linux + root for fanotify, so `#[ignore]` + sudo.

use std::fs;
use std::io::Write;
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
        "bulwark-remote-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Make a FIFO at `path` via `mkfifo`.
fn mkfifo(path: &std::path::Path) {
    let ok = Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(path)
        .status()
        .expect("mkfifo");
    assert!(ok.success(), "mkfifo failed for {}", path.display());
}

#[test]
#[ignore = "requires Linux + root for fanotify"]
fn remote_split_denies_then_caches_allow_session() {
    let dir = scratch("split");
    let secret = dir.join("secret.env");
    let agent_out = dir.join("agent.out");
    let prompts = dir.join("prompts");
    let verdicts = dir.join("verdicts");
    fs::write(&secret, "SECRETVALUE=remote\n").unwrap();
    mkfifo(&prompts);
    mkfifo(&verdicts);

    // Relay thread: read each prompt, echo back an allow-session for its scoped
    // grant on the verdict lane. This stands in for the local operator.
    let prompts_r = prompts.clone();
    let verdicts_w = verdicts.clone();
    let relay = thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let pf = std::fs::File::open(&prompts_r).expect("open prompts");
        // O_RDWR keeps the verdict FIFO writable without blocking.
        let mut vf = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&verdicts_w)
            .expect("open verdicts");
        for line in BufReader::new(pf).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if let Some(rest) = line.strip_prefix("CONSENT\t") {
                let grant = rest
                    .split('\t')
                    .find_map(|p| p.strip_prefix("grant="))
                    .unwrap_or("");
                let _ = writeln!(vf, "allow-session {grant}");
                break; // one grant is enough for this test
            }
        }
    });

    // The remote gate: first read denied, second read (after the relay's
    // allow-session lands) passes from cache.
    let inner = format!(
        "echo r1=[$(cat {s} 2>&1)]; sleep 3; echo r2=[$(cat {s} 2>&1)] > {out} 2>&1",
        s = secret.display(),
        out = agent_out.display(),
    );
    let status = Command::new(bin())
        .args([
            "run",
            "--allow-root",
            "--consent",
            "remote",
            "--host-label",
            "test",
        ])
        .arg("--prompt-out")
        .arg(&prompts)
        .arg("--verdict-in")
        .arg(&verdicts)
        .arg("--protect")
        .arg(&secret)
        .arg("--")
        .args(["bash", "-c", &inner])
        .status()
        .expect("spawn remote gate");
    assert!(status.success() || !status.success());
    let _ = relay.join();
    thread::sleep(Duration::from_millis(200));

    let second = fs::read_to_string(&agent_out).unwrap_or_default();
    assert!(
        second.contains("SECRETVALUE"),
        "the second read must pass from cache after allow-session; got: {second:?}"
    );
}
