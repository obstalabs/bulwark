//! WO-154 / WO-155: the permission loop never blocks on output, and a dead
//! supervisor never leaves a live unsupervised tree. Root-only (fanotify + a
//! test-owned tmpfs); run under `sudo`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// WO-188@v1: a rejected response must tear down promptly instead of holding
// the kernel permission event indefinitely.
#[cfg(feature = "fault-injection")]
const RESPONSE_FAILURE_EXIT_BOUND: Duration = Duration::from_secs(10);

// WO-154@v1: run the real gate binary for permission-loop tests.
// WO-155@v1: run the real supervisor for teardown and reaping tests.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bulwark"))
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

/// Time a single open of `path` from OUTSIDE the supervised tree (a fresh `sh`
/// process), bounded so a blocked open cannot hang the test thread — the
/// stalled gate is recovered by the harness, releasing the open. Returns the
/// elapsed milliseconds (capped at the budget).
// WO-154@v1: bound an unrelated open while the gate handles slow work.
fn probe_open_ms(path: &Path) -> u128 {
    let t = Instant::now();
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!("cat {} >/dev/null 2>&1", path.display()))
        .spawn()
        .expect("spawn probe");
    loop {
        if child.try_wait().expect("wait probe").is_some() {
            break;
        }
        if t.elapsed() > Duration::from_secs(3) {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    t.elapsed().as_millis()
}

/// WO-154: with the gate's log output going to a reader that never drains, the
/// permission loop must keep answering opens host-wide — an outside open of a
/// file on the marked filesystem stays fast throughout.
#[test]
#[ignore = "requires Linux + root"]
fn stalled_log_reader_does_not_block_outside_opens() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("stalled_log_reader_does_not_block_outside_opens");
    let fs = common::TestFs::new("wo154a");
    let protected = fs.path("secret");
    let allowed = fs.path("allowed.txt");
    fs::write(&protected, "secret\n").unwrap();
    fs::write(&allowed, "ok\n").unwrap();

    // stderr goes to a pipe we never drain.
    let inner = format!(
        "for i in $(seq 1 400); do cat {} >/dev/null; done",
        allowed.display()
    );
    let gate = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gate");
    // WO-158@v1: reap a deliberately killed gate before removing its empty scope.
    let mut gate = common::HardKillScopeGuard::new(gate);

    // Outside opens must complete fast throughout the flood.
    for _ in 0..40 {
        let ms = probe_open_ms(&allowed);
        assert!(
            ms < 500,
            "an outside open blocked for {ms}ms while the log reader was stalled"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = gate.kill();
    let _ = gate.wait();
}

/// WO-154: a consent prompt that is pending for its full timeout must not delay
/// an unrelated open on the same filesystem (the consent wait is off-loop).
#[test]
#[ignore = "requires Linux + root"]
fn pending_consent_does_not_delay_outside_opens() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("pending_consent_does_not_delay_outside_opens");
    let fs = common::TestFs::new("wo154b");
    let protected = fs.path("secret");
    let allowed = fs.path("allowed.txt");
    let sock = fs.path("consent.sock");
    fs::write(&protected, "secret\n").unwrap();
    fs::write(&allowed, "ok\n").unwrap();

    // The agent opens the PROTECTED file, which holds a consent prompt for the
    // full timeout (no operator answers).
    let inner = format!("cat {} >/dev/null 2>&1; echo done", protected.display());
    let gate = Command::new(bin())
        .args([
            "run",
            "--allow-root",
            "--consent",
            "socket",
            "--consent-socket",
        ])
        .arg(&sock)
        .args(["--consent-timeout", "30", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    // WO-158@v1: finish cgroup cleanup before the test filesystem unmounts.
    let mut gate = common::HardKillScopeGuard::new(gate);

    // Let the agent reach the protected open (the prompt is now pending).
    std::thread::sleep(Duration::from_millis(500));

    let ms = probe_open_ms(&allowed);
    assert!(
        ms < 500,
        "an outside open blocked for {ms}ms while a consent prompt was pending"
    );

    let _ = gate.kill();
    let _ = gate.wait();
}

/// WO-188@v1: two rejected fanotify response writes make the gate fatal; the
/// real CLI must reap the supervised tree and exit within a fixed bound.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn persistent_response_write_failure_tears_down_without_blocking() {
    let state = isolated_state("persistent_response_write_failure");
    let fs = common::TestFs::new("wo188");
    let protected = fs.path("secret");
    let stderr_path = fs.path("gate.stderr");
    // WO-188@v1: a child EACCES alone does not prove fatal response handling.
    let stdout_path = fs.path("agent.stdout");
    fs::write(&protected, "secret\n").unwrap();

    // WO-188@v1: cover both the inline responder and the deferred consent worker.
    for deny_all in [true, false] {
        let stderr = fs::File::create(&stderr_path).expect("create gate stderr");
        let stdout = fs::File::create(&stdout_path).expect("create agent stdout");
        let mut command = Command::new(bin());
        command.args(["run", "--allow-root"]);
        if deny_all {
            command.arg("--deny-all");
        } else {
            command.arg("--protect").arg(&protected);
        }
        // WO-188@v1: inject only DENY failures so the agent can reach its protected read.
        let gate = command
            .arg("--state")
            .arg(&state)
            .arg("--")
            .args(["sh", "-c", &format!("cat {}", protected.display())])
            .env("BULWARK_TEST_RESPONSE_WRITE_FAILURES", "2")
            .env("BULWARK_TEST_RESPONSE_DENY_ONLY", "1")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn gate");
        let mut gate = common::HardKillScopeGuard::new(gate);

        let deadline = Instant::now() + RESPONSE_FAILURE_EXIT_BOUND;
        let status = loop {
            if let Some(status) = gate.try_wait().expect("try wait gate") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the gate held a rejected permission response past {RESPONSE_FAILURE_EXIT_BOUND:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };

        assert!(
            !status.success(),
            "a persistent response failure must be fatal"
        );
        let stderr = fs::read_to_string(&stderr_path).expect("read gate stderr");
        assert!(
            stderr.contains("persistent fanotify response failure"),
            "the fatal response failure must be observable; stderr:\n{stderr}"
        );
        let stdout = fs::read_to_string(&stdout_path).expect("read agent stdout");
        assert!(
            // WO-188@v1: termination alone cannot hide bytes delivered before teardown.
            !stdout.contains("secret"),
            "protected content leaked: {stdout}"
        );
        // WO-188@v1: repeat the same outcome checks for both delivery paths.
    }
}

// WO-188@v1: keep unrelated opens active across enough consent timeouts to exercise reuse.
#[cfg(all(feature = "fault-injection", target_os = "linux"))]
const RESPONSE_REUSE_TRIALS: usize = 30;

// WO-188@v1: outside-open loops must be reaped even when a leak assertion fails.
#[cfg(all(feature = "fault-injection", target_os = "linux"))]
struct ResponseNoise(Vec<std::process::Child>);

// WO-188@v1: each loop owns its process group, including an in-flight head child.
#[cfg(all(feature = "fault-injection", target_os = "linux"))]
impl Drop for ResponseNoise {
    // WO-188@v1: kill every noise loop's process group so no writer outlives the test.
    fn drop(&mut self) {
        for child in &mut self.0 {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
        }
    }
}

// WO-188@v1: a failed deferred DENY must never be answered by an outside ALLOW
// that reuses its fd number while the kernel still holds the protected open.
#[test]
#[cfg(all(feature = "fault-injection", target_os = "linux"))]
#[ignore = "requires Linux + root"]
fn persistent_consent_response_failure_never_reuses_the_held_fd() {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;

    // WO-188@v1: /tmp may be tmpfs; the canary must share /etc/hostname's filesystem.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from(format!(
        "/var/tmp/bulwark-wo188-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir(&dir).unwrap();
    let protected = dir.join("secret");
    const CANARY: &str = "WO188_PROTECTED_CONTENT";
    fs::write(&protected, CANARY).unwrap();
    assert_eq!(
        fs::metadata(&protected).unwrap().dev(),
        fs::metadata("/etc/hostname").unwrap().dev(),
        "the outside opens must exercise the marked filesystem"
    );

    // WO-188@v1: unrelated ALLOW traffic exposes reuse of a failed event's fd number.
    let mut noise = ResponseNoise(Vec::new());
    for _ in 0..4 {
        noise.0.push(
            Command::new("sh")
                .args(["-c", "while :; do head -c 1 /etc/hostname >/dev/null; done"])
                .process_group(0)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn outside opens"),
        );
    }

    let mut leaks = Vec::new();
    for trial in 0..RESPONSE_REUSE_TRIALS {
        let stdout_path = dir.join(format!("agent-{trial}.stdout"));
        let stderr_path = dir.join(format!("gate-{trial}.stderr"));
        let gate = Command::new(bin())
            .args([
                "run",
                "--allow-root",
                "--consent",
                "socket",
                "--consent-timeout",
                "2",
            ])
            .arg("--consent-socket")
            .arg(dir.join(format!("c{trial}.sock")))
            .arg("--protect")
            .arg(&protected)
            .arg("--state")
            .arg(dir.join(format!("state-{trial}.toml")))
            .args(["--", "sh", "-c"])
            .arg(format!("cat {}; echo cat_rc=$?", protected.display()))
            .env("BULWARK_TEST_RESPONSE_WRITE_FAILURES", "2")
            .env("BULWARK_TEST_RESPONSE_DENY_ONLY", "1")
            .stdout(fs::File::create(&stdout_path).unwrap())
            .stderr(fs::File::create(&stderr_path).unwrap())
            .spawn()
            .expect("spawn gate");
        let mut gate = common::HardKillScopeGuard::new(gate);
        let deadline = Instant::now() + RESPONSE_FAILURE_EXIT_BOUND;
        let status = loop {
            if let Some(status) = gate.try_wait().expect("wait gate") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "trial {trial}: gate did not exit"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let stderr = fs::read_to_string(&stderr_path).unwrap();
        assert!(
            !status.success()
                && stderr.contains("persistent fanotify response failure in consent worker"),
            "trial {trial}: the deferred failure path did not run: {status}; {stderr}"
        );
        let stdout = fs::read_to_string(&stdout_path).unwrap();
        if stdout.contains(CANARY) {
            leaks.push((trial, stdout));
        }
    }
    drop(noise);
    assert!(
        // WO-188@v1: inspect every trial's real stdout, including reads before fatal exit.
        leaks.is_empty(),
        "protected content reached agent stdout in {}/{RESPONSE_REUSE_TRIALS} trials: {leaks:?}",
        leaks.len()
    );
    // WO-188@v1: discard fixtures only after the gate and outside-open loops are gone.
    fs::remove_dir_all(dir).expect("remove response test fixtures");
}

// WO-187@v1: the agent must lose the gate's OOM preference before dropping uid,
// including the kernel minimum that would otherwise let it restore that preference.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn agent_cannot_restore_the_gate_oom_score_after_the_uid_drop() {
    const OBSERVATION_BOUND: Duration = Duration::from_secs(10);
    const OBSERVATION_POLL: Duration = Duration::from_millis(20);
    const WORKER_UID: u32 = 65534;
    let fs = common::TestFs::new("wo187score");
    let secret = fs.path("secret");
    let output = fs.path("agent.stdout");
    let errors = fs.path("gate.stderr");
    let release = fs.path("release");
    fs::write(&secret, "protected\n").unwrap();
    let script = format!(
        "printf 'AGENT_PID=%s\\n' \"$$\"; \
         printf 'AGENT_UID=%s\\n' \"$(id -u)\"; \
         printf 'INITIAL_SCORE=%s\\n' \"$(cat /proc/$$/oom_score_adj)\"; \
         if (printf '%s\\n' -900 > /proc/$$/oom_score_adj) 2>/dev/null; \
         then echo SCORE_LOWERED; else echo SCORE_REFUSED; fi; \
         echo READY; while [ ! -e '{}' ]; do sleep 0.02; done; exit 7",
        release.display()
    );
    let gate = Command::new(bin())
        .args(["run", "--worker-uid", &WORKER_UID.to_string(), "--protect"])
        .arg(&secret)
        .arg("--state")
        .arg(fs.path("state.toml"))
        .args(["--", "sh", "-c", &script])
        .stdout(fs::File::create(&output).unwrap())
        .stderr(fs::File::create(&errors).unwrap())
        .spawn()
        .expect("spawn gate");
    let mut gate = common::HardKillScopeGuard::new(gate);
    let ready_deadline = Instant::now() + OBSERVATION_BOUND;
    let stdout = loop {
        let stdout = fs::read_to_string(&output).expect("read agent evidence");
        if stdout.lines().any(|line| line == "READY") {
            break stdout;
        }
        assert!(
            gate.try_wait().unwrap().is_none() && Instant::now() < ready_deadline,
            "agent did not reach the score probe: {stdout}; {}",
            fs::read_to_string(&errors).unwrap()
        );
        std::thread::sleep(OBSERVATION_POLL);
    };
    let agent_pid = stdout
        .lines()
        .find_map(|line| line.strip_prefix("AGENT_PID="))
        .expect("agent published its pid")
        .parse::<i32>()
        .expect("valid agent pid");
    assert!(
        stdout.lines().any(|line| line == "AGENT_UID=65534"),
        "{stdout}"
    );
    assert!(
        stdout.lines().any(|line| line == "INITIAL_SCORE=0"),
        "{stdout}"
    );
    assert!(
        stdout.lines().any(|line| line == "SCORE_REFUSED")
            && !stdout.lines().any(|line| line == "SCORE_LOWERED"),
        "the dropped agent must not be able to lower its score: {stdout}"
    );
    assert_eq!(
        fs::read_to_string(format!("/proc/{agent_pid}/oom_score_adj"))
            .unwrap()
            .trim(),
        "0",
        "the live agent must retain the default score after its attempt"
    );
    let gate_pid = gate.id() as i32;
    assert_eq!(
        fs::read_to_string(format!("/proc/{gate_pid}/oom_score_adj"))
            .unwrap()
            .trim(),
        "-900",
        "the gate must remain less attractive than the agent"
    );
    let watchers = watcher_pids_of(gate_pid);
    assert_eq!(watchers.len(), 1, "the run must have its crash watcher");
    for pid in watchers {
        assert_eq!(
            fs::read_to_string(format!("/proc/{pid}/oom_score_adj"))
                .unwrap()
                .trim(),
            "-900",
            "the watcher must inherit the gate's OOM preference"
        );
    }
    fs::write(release, "done\n").unwrap();
    let exit_deadline = Instant::now() + OBSERVATION_BOUND;
    loop {
        if let Some(status) = gate.try_wait().unwrap() {
            assert_eq!(status.code(), Some(7), "agent must finish its real command");
            break;
        }
        assert!(Instant::now() < exit_deadline, "gate did not finish");
        std::thread::sleep(OBSERVATION_POLL);
    }
}

/// WO-154@v1: the receipts FILE must never wait on stderr. Two bounded
/// queues/writers drain independently: with stderr stalled on a never-read pipe,
/// the file still receives every one of the 6000 receipts (its own queue never
/// drops), and the per-sink summary balances exactly — `submitted == written +
/// dropped` holds for each sink, so a lost line is never silent.
// WO-154@v1: prove terminal backpressure does not block gate decisions.
// WO-155@v1: prove a stalled terminal cannot starve file receipts.
#[test]
#[ignore = "requires Linux + root"]
fn a_stalled_stderr_never_costs_the_receipts_file_a_line() {
    let fs = common::TestFs::new("wo154c");
    let protected = fs.path("secret");
    let allowed = fs.path("allowed.txt");
    let receipts = fs.path("r.jsonl");
    fs::write(&protected, "secret\n").unwrap();
    fs::write(&allowed, "ok\n").unwrap();

    let inner = format!(
        "for i in $(seq 1 6000); do cat {} >/dev/null; done",
        allowed.display()
    );
    // Isolate the integrity state: a SIGKILL'd gate in a sibling test leaves the
    // shared state tainted, which writes a second (main-process) summary that
    // would corrupt this test's exact per-sink accounting.
    let state = fs.path("state.toml");
    let mut gate = Command::new(bin())
        .args(["run", "--state"])
        .arg(&state)
        .args(["--allow-root", "--protect"])
        .arg(&protected)
        .arg("--receipts")
        .arg(&receipts)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        // Stalled: the read end is held but never drained, so the stderr writer
        // blocks once the pipe buffer is full.
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gate");

    // Bound the wait: with the gate's loop blocked on output it would never finish,
    // so the failure is a clear assertion rather than a hang.
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(st) = gate.try_wait().expect("try wait gate") {
            break st;
        }
        assert!(
            Instant::now() < deadline,
            "the gate did not finish within 30s (blocked on output)"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        status.success(),
        "the gate must run the agent to completion: {status}"
    );

    let body = fs::read_to_string(&receipts).expect("receipts file");
    // The file sink wrote every receipt (its own queue never dropped).
    let receipt_lines = body
        .lines()
        .filter(|l| l.contains(r#""decision":"allow""#))
        .count();
    assert_eq!(
        receipt_lines, 6000,
        "the receipts file must contain every line not dropped from its own queue"
    );
    let summary = body
        .lines()
        .find(|l| l.contains(r#""kind":"summary""#))
        .expect("receipts summary line");
    // File section: the writer demonstrably drained, so it is `finished` and its
    // accounting balances exactly (zero drops).
    let file = summary.split(r#""stderr":"#).next().unwrap_or(summary);
    assert!(
        file.contains(r#""state":"finished""#),
        "the file writer must be reported finished"
    );
    assert_eq!(field_num(file, "submitted"), 6000);
    assert_eq!(field_num(file, "written"), 6000);
    assert_eq!(field_num(file, "dropped"), 0);
    // Stderr section: the stalled terminal abandoned its writer at the join
    // deadline, so it is `timed_out` and its counters are a snapshot — never
    // asserted to balance.
    let stderr = summary
        .split(r#""stderr":"#)
        .nth(1)
        .expect("stderr section");
    assert!(
        stderr.contains(r#""state":"timed_out""#),
        "the stalled stderr writer must be reported timed_out"
    );
}

/// WO-155: if the supervisor dies, the supervised tree is reaped so it cannot
/// outlive the gate and complete a later protected read.
#[test]
#[ignore = "requires Linux + root"]
fn the_supervised_tree_is_reaped_if_the_gate_is_killed() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("the_supervised_tree_is_reaped_if_the_gate_is_killed");
    let fs = common::TestFs::new("wo155");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    let inner = format!(
        "sleep 3; cat {} > {} 2>&1; echo done",
        protected.display(),
        leak.display()
    );
    let gate = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    // WO-158@v1: remove the hard-killed run's scope on success and panic paths.
    let mut gate = common::HardKillScopeGuard::new(gate);

    // Kill the gate after the agent is launched (1s), before its 3s read.
    std::thread::sleep(Duration::from_secs(1));
    unsafe {
        let _ = libc::kill(gate.id() as i32, libc::SIGKILL);
    }
    let _ = gate.wait();

    // The tree must be dead well before the read; the leak marker never appears.
    // Wait past the agent's would-be read (3s) so a surviving agent has time to
    // commit its read before we assert it never happened.
    std::thread::sleep(Duration::from_millis(2500));
    assert!(
        !leak.exists(),
        "the supervised tree must not outlive the gate"
    );
}

/// Wait until `path` exists (an agent wrote its ready marker), bounded.
// WO-155@v1: prove the supervised process reached the intended test phase.
fn wait_for_path(path: &Path, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while !path.exists() {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

// WO-177@v1: wait for the writer's newline before parsing a published pid.
fn read_complete_pid(path: &Path, budget: Duration) -> i32 {
    read_complete_pid_with(path, budget, |_| {})
}

// WO-177@v1: expose incomplete observations so the pure regression test can synchronize.
fn read_complete_pid_with<F>(path: &Path, budget: Duration, mut on_incomplete: F) -> i32
where
    F: FnMut(&[u8]),
{
    let deadline = Instant::now() + budget;
    let mut bytes = Vec::new();
    loop {
        match fs::read(path) {
            Ok(read) => bytes = read,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => bytes.clear(),
            Err(error) => panic!(
                "cannot read grandchild pid before {budget:?} deadline: {error}; bytes read: {bytes:?}"
            ),
        }
        if bytes.ends_with(b"\n") {
            let line = std::str::from_utf8(&bytes[..bytes.len() - 1]).unwrap_or_else(|error| {
                panic!("grandchild pid is not UTF-8: {error}; bytes read: {bytes:?}")
            });
            return line.parse().unwrap_or_else(|error| {
                panic!("cannot parse complete grandchild pid: {error}; bytes read: {bytes:?}")
            });
        }
        on_incomplete(&bytes);
        assert!(
            Instant::now() < deadline,
            "timed out after {budget:?} waiting for a complete grandchild pid line; bytes read: {bytes:?}"
        );
        std::thread::yield_now();
    }
}

// WO-177@v1: an empty first read waits for the writer's complete newline-terminated pid.
#[test]
fn complete_pid_reader_waits_for_newline_without_sleep() {
    let dir = std::env::temp_dir().join(format!(
        "bulwark-pid-reader-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("grandchild.pid");
    fs::write(&path, b"").unwrap();

    let (observed_tx, observed_rx) = std::sync::mpsc::sync_channel(0);
    let (continue_tx, continue_rx) = std::sync::mpsc::sync_channel(0);
    let reader_path = path.clone();
    let reader = std::thread::spawn(move || {
        let mut first = true;
        read_complete_pid_with(&reader_path, Duration::from_secs(1), |bytes| {
            if first {
                assert!(bytes.is_empty(), "first read must see the empty file");
                observed_tx.send(()).unwrap();
                continue_rx.recv().unwrap();
                first = false;
            }
        })
    });

    observed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("reader never observed the incomplete pid file");
    fs::write(&path, b"1234\n").unwrap();
    continue_tx.send(()).unwrap();
    assert_eq!(reader.join().expect("pid reader panicked"), 1234);
    fs::remove_dir_all(dir).unwrap();
}

/// The number of open file descriptors the gate process holds (its `/proc/N/fd`).
// WO-154@v1: bound descriptor retention while consent work is queued.
fn fd_count(pid: i32) -> usize {
    match std::fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(d) => d.count(),
        Err(_) => 0,
    }
}

/// Parse the integer value of the first `"key":N` pair in a JSON fragment.
// WO-154@v1: read per-sink accounting from the final receipt record.
// WO-155@v1: verify submitted output is written or counted as dropped.
fn field_num(s: &str, key: &str) -> u64 {
    let needle = format!("\"{key}\":");
    let at = s
        .find(&needle)
        .unwrap_or_else(|| panic!("{key} not found in {s}"));
    let rest = &s[at + needle.len()..];
    rest.chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap()
}

/// The pids of THIS test's supervisor's children whose comm is "bulwark" — the
/// crash watcher (a fork of the supervisor, so it keeps the inherited comm).
/// Scoped by `PPid == supervisor_pid` so a shared runner's unrelated gates are
/// never signaled. Recorded BEFORE the supervisor is killed (after that the
/// watcher is reparented to pid 1 and no longer enumerates this way).
// WO-155@v1: discover only the crash watcher owned by this supervisor.
#[cfg(feature = "fault-injection")]
fn watcher_pids_of(supervisor_pid: i32) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let is_watcher = proc_field(pid, "PPid:")
            .and_then(|v| v.parse::<i32>().ok())
            .map(|v| v == supervisor_pid)
            .unwrap_or(false)
            && proc_comm(pid).as_deref() == Some("bulwark");
        if is_watcher {
            out.push(pid);
        }
    }
    out
}

/// Read one whitespace-split field value from `/proc/<pid>/status`.
// WO-155@v1: identify a watcher by its original supervisor parent.
#[cfg(feature = "fault-injection")]
fn proc_field(pid: i32, field: &str) -> Option<String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with(field))?;
    let (_, v) = line.split_once(field)?;
    Some(v.trim().to_string())
}

/// The process name from `/proc/<pid>/comm`.
// WO-155@v1: distinguish the crash watcher from unrelated child processes.
#[cfg(feature = "fault-injection")]
fn proc_comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_string())
}

/// WO-155@v1: one guard owns the whole supervised run of a watcher test — the gate
/// `Child` (taken immediately after spawn, because `Child` does not kill on drop),
/// the run's cgroup scope path, and, once discovered, one pidfd per watcher (plus
/// its pid, so the terminal path can name it). Every watcher signal and the exit
/// wait go through `pidfd_send_signal` / `poll`, never a bare pid. `add_watchers`
/// fails closed: it panics on an empty pid list (before any destructive step) and
/// on any pidfd_open error. Drop runs its teardown to completion and never aborts
/// mid-sequence: (a) a gate that is not definitively reaped is SIGKILLed only (no
/// blocking `wait()`), then (b)–(e) signal/kill/prove the watchers and attempts
/// to remove the scope, and only then a final reap polls the gate's `try_wait()`
/// up to GATE_REAP_BOUND. Each failure — a nonzero gate kill, a watcher still
/// un-exited after WATCHER_KILL_BOUND, a remaining scope, a gate reap observation
/// error, or a gate not reaped within GATE_REAP_BOUND — is collected; after full
/// teardown Drop writes one line per failure to stderr and aborts the process, so
/// the suite never continues racing a possibly-held fanotify group. (Non-Linux:
/// these root tests are always ignored, so the guard is inert.)
// WO-155@v1: own every process and cgroup resource used by watcher tests.
// WO-158@v1: preserve teardown errors and require proof that the scope was removed.
#[cfg(feature = "fault-injection")]
struct RunGuard {
    gate: Option<std::process::Child>,
    scope: PathBuf,
    // (pidfd, pid) per watcher.
    watchers: Vec<(libc::c_int, i32)>,
}

/// How long Drop waits for the watchers to exit (pidfd poll) before SIGKILLing.
#[cfg(all(feature = "fault-injection", target_os = "linux"))]
const WATCHER_DRAIN_BOUND: Duration = Duration::from_secs(5);

/// How long Drop waits, after SIGKILLing every surviving watcher, for a pidfd to
/// report exit (POLLIN) before recording that watcher as un-exited; a SIGKILL exit
/// is fast, so this is only the bound for a watcher that should have died but has
/// not. An un-exited watcher is recorded and teardown finishes before Drop aborts.
#[cfg(all(feature = "fault-injection", target_os = "linux"))]
const WATCHER_KILL_BOUND: Duration = Duration::from_secs(2);

/// How long the final reap step polls a SIGKILLed gate's `try_wait()` (every 10 ms)
/// for `Ok(Some(..))` before recording it as not reaped; a SIGKILL is fast, so
/// this is only the bound for a gate that should have died but has not. A gate not
/// reaped within the bound is recorded and teardown finishes before Drop aborts.
#[cfg(feature = "fault-injection")]
const GATE_REAP_BOUND: Duration = Duration::from_secs(5);

// WO-155@v1: expose pidfd-based control of one supervised test run.
#[cfg(feature = "fault-injection")]
impl RunGuard {
    // WO-155@v1: take ownership before a panic can leak the gate or scope.
    fn new(gate: std::process::Child, scope: PathBuf) -> Self {
        RunGuard {
            gate: Some(gate),
            scope,
            watchers: Vec::new(),
        }
    }

    /// Mutable gate access, for tests that kill, panic or wait it on purpose.
    // WO-155@v1: keep destructive gate operations under guard ownership.
    fn gate(&mut self) -> Option<&mut std::process::Child> {
        self.gate.as_mut()
    }

    /// The run's cgroup scope path.
    // WO-155@v1: expose the exact scope owned by this guarded run.
    fn scope(&self) -> &Path {
        &self.scope
    }

    /// Pin one pidfd per watcher pid (fail closed). Panics on an empty list BEFORE
    /// any destructive step, and on any pidfd_open failure.
    // WO-155@v1: pin every watcher identity before sending any signal.
    fn add_watchers(&mut self, pids: &[i32]) {
        assert!(
            !pids.is_empty(),
            "a watcher must be found before any destructive step"
        );
        #[cfg(target_os = "linux")]
        {
            let mut fds = Vec::with_capacity(pids.len());
            for &pid in pids {
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                if fd < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    for &(opened, _) in &fds {
                        unsafe { libc::close(opened) };
                    }
                    panic!("pidfd_open({pid}) failed (errno {err})");
                }
                fds.push((fd as libc::c_int, pid));
            }
            self.watchers = fds;
        }
        #[cfg(not(target_os = "linux"))]
        let _ = pids;
    }

    /// Send `sig` to every watcher via pidfd_send_signal, asserting each succeeds.
    // WO-155@v1: signal watcher identities without pid-reuse races.
    fn signal_watchers(&self, sig: libc::c_int) {
        #[cfg(target_os = "linux")]
        for &(fd, _) in &self.watchers {
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd,
                    sig,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            assert_eq!(
                rc, 0,
                "pidfd_send_signal({sig}) on watcher pidfd {fd} must succeed"
            );
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (sig, &self.watchers);
    }

    /// Block until every watcher has exited (pidfd poll, `POLLIN` = exited), by
    /// `deadline` — never by busy-checking /proc/<pid>.
    // WO-155@v1: require bounded pidfd proof that every watcher exited.
    fn watchers_exited(&self, deadline: Instant) {
        #[cfg(target_os = "linux")]
        for &(fd, _) in &self.watchers {
            loop {
                assert!(
                    Instant::now() < deadline,
                    "the watcher (pidfd {fd}) must exit by the deadline"
                );
                let remaining_ms = deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as libc::c_long;
                let timeout_ms = remaining_ms.min(1000) as libc::c_int;
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
                if rc < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    if err == libc::EINTR {
                        continue;
                    }
                    panic!("poll on watcher pidfd {fd} failed (errno {err})");
                }
                if rc == 0 {
                    continue; // timeout — re-check the deadline
                }
                if pfd.revents & libc::POLLIN != 0 {
                    break; // exited
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (deadline, &self.watchers);
    }
}

// WO-155@v1: guarantee full teardown before a watcher test can continue.
#[cfg(feature = "fault-injection")]
impl Drop for RunGuard {
    // WO-155@v1: kill, drain, close, and remove every owned resource before return.
    fn drop(&mut self) {
        // Teardown never aborts mid-sequence: every step runs (b → … → scope
        // rmdir) and each failure is pushed onto `failures` as one stderr line
        // (pid + reason). Nothing is written to stderr until every kill has been
        // sent; the terminal abort below fires only after full teardown.
        let mut failures: Vec<String> = Vec::new();

        // (a) A gate that is not definitively reaped (the tests kill + wait it on
        // purpose, but a panic before they did must not leave a live gate) is
        // SIGKILLed only — no blocking `wait()` here, which could hang forever on
        // a gate that will not die. A nonzero kill_rc is recorded; the Child is
        // kept for the final reap step below, and the tree is still cgroup.killed
        // and the watchers still SIGKILLed before that step.
        let mut gate_to_reap: Option<std::process::Child> = None;
        if let Some(mut gate) = self.gate.take() {
            if !matches!(gate.try_wait(), Ok(Some(_))) {
                let kill_rc = unsafe { libc::kill(gate.id() as libc::pid_t, libc::SIGKILL) };
                if kill_rc != 0 {
                    failures.push(format!(
                        "[bulwark] gate pid {} kill failed (kill={kill_rc})",
                        gate.id()
                    ));
                }
                gate_to_reap = Some(gate);
            }
        }

        #[cfg(target_os = "linux")]
        {
            // (b) Resume every watcher: a SIGSTOPped watcher still holds the
            // fanotify group, so it must be resumed before it can be reaped.
            for &(fd, _) in &self.watchers {
                let _ = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd,
                        libc::SIGCONT,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
            }

            // (c) Kill the tree via cgroup.kill if the scope still exists (an
            // already-removed scope needs nothing).
            if self.scope.exists() {
                let _ = fs::write(self.scope.join("cgroup.kill"), b"1");
            }

            // (d) Wait for the watchers to exit, up to the named bound, retrying
            // on EINTR.
            let deadline = Instant::now() + WATCHER_DRAIN_BOUND;
            for &(fd, _) in &self.watchers {
                loop {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let remaining = deadline.saturating_duration_since(now).as_millis();
                    let timeout_ms = remaining.min(1000) as libc::c_int;
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
                    if rc < 0 {
                        let err = unsafe { *libc::__errno_location() };
                        if err == libc::EINTR {
                            continue; // retry on EINTR
                        }
                        break; // other errors: fall through to the SIGKILL
                    }
                    if rc == 0 {
                        continue; // timeout — re-check the deadline
                    }
                    if pfd.revents & libc::POLLIN != 0 {
                        break; // exited
                    }
                }
            }

            // (e) first pass: SIGKILL EVERY surviving watcher. All kills are sent
            // up front, so polling one watcher (next pass) can never delay the
            // kill signal another watcher needs.
            for &(fd, _) in &self.watchers {
                let _ = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd,
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
            }

            // (e) second pass: PROVE each exited (pidfd poll for POLLIN, up to
            // WATCHER_KILL_BOUND) before closing its pidfd — a SIGKILL is
            // asynchronous, and closing a pidfd of a live watcher would return
            // while it still holds the fanotify group. Record, don't abort, an
            // unexited watcher; teardown finishes and the terminal abort fires.
            for (fd, pid) in self.watchers.drain(..) {
                let kick_deadline = Instant::now() + WATCHER_KILL_BOUND;
                let mut exited = false;
                loop {
                    let now = Instant::now();
                    if now >= kick_deadline {
                        break;
                    }
                    let remaining = kick_deadline.saturating_duration_since(now).as_millis();
                    let timeout_ms = remaining.min(500) as libc::c_int;
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
                    if rc > 0 && (pfd.revents & libc::POLLIN != 0) {
                        exited = true;
                        break;
                    }
                    if rc < 0 && unsafe { *libc::__errno_location() } != libc::EINTR {
                        break; // real poll error: stop waiting, still close below
                    }
                    // rc == 0 (timeout) or EINTR: loop, re-check the deadline.
                }
                if !exited {
                    failures.push(format!(
                        "[bulwark] watcher pid {pid} did not exit within the kill bound; aborting after teardown"
                    ));
                }
                unsafe { libc::close(fd) };
            }

            // WO-158@v1: a remaining scope is a teardown failure, not silent residue.
            // The scope is now empty; remove it. The gate's own CgroupScope drop
            // never runs when the gate was SIGKILLed, so the guard owns this.
            for _ in 0..50 {
                if fs::remove_dir(&self.scope).is_ok() || !self.scope.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if self.scope.exists() {
                failures.push(format!(
                    "[bulwark] cgroup scope {} was not removed after teardown",
                    self.scope.display()
                ));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = &self.scope;

        // WO-158@v1: retain every reap observation error even if a later poll succeeds.
        // Final reap: only now that every other kill has been sent and scope
        // removal attempted, poll the (possibly SIGKILLed) gate's `try_wait()` up
        // to GATE_REAP_BOUND. No `Child::wait()` appears in Drop because it could
        // block on a gate that refused to die.
        if let Some(mut gate) = gate_to_reap.take() {
            let reap_deadline = Instant::now() + GATE_REAP_BOUND;
            let mut reaped = false;
            let mut reap_error = None;
            loop {
                match gate.try_wait() {
                    Ok(Some(_)) => {
                        reaped = true;
                        break;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if reap_error.is_none() {
                            reap_error = Some(error.to_string());
                        }
                    }
                }
                if Instant::now() >= reap_deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if let Some(error) = reap_error {
                failures.push(format!(
                    "[bulwark] gate pid {} reap observation failed: {error}",
                    gate.id()
                ));
            }
            if !reaped {
                failures.push(format!(
                    "[bulwark] gate pid {} not reaped within the bound",
                    gate.id()
                ));
            }
        }

        // Terminal: full teardown has now run — every kill sent, every pidfd
        // closed, the scope rmdir attempted, the gate reap polled. With any
        // failure recorded, write each line and abort so the suite never
        // continues racing a possibly-held fanotify group (or a possibly-live
        // gate).
        if !failures.is_empty() {
            for line in &failures {
                eprintln!("{line}");
            }
            std::process::abort();
        }
    }
}

/// WO-155@v1: PR_SET_PDEATHSIG must be set AFTER the credential drop (the kernel
/// clears it on euid/egid change). With the cgroup layer disabled, a DROPPED
/// direct child must still die when the gate is SIGKILLed.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root + sudo"]
fn pdeathsig_kills_a_dropped_direct_child_without_the_cgroup_layer() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("pdeathsig_kills_a_dropped_direct_child_without_the_cgroup_layer");
    let fs = common::TestFs::new("wo155pds");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let ready = fs.path("ready");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    // Default uid drop (no --allow-root): the agent runs as SUDO_USER.
    let inner = format!(
        "touch {}; sleep 3; cat {} > {} 2>&1; echo done",
        ready.display(),
        protected.display(),
        leak.display()
    );
    let gate = Command::new(bin())
        .env("BULWARK_TEST_NO_CGROUP", "1")
        .args(["run", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    // WO-158@v1: own hard-kill cleanup even when the cgroup layer is disabled.
    let mut gate = common::HardKillScopeGuard::new(gate);

    assert!(
        wait_for_path(&ready, Duration::from_secs(5)),
        "the agent never started"
    );
    std::thread::sleep(Duration::from_secs(1));
    unsafe {
        let _ = libc::kill(gate.id() as i32, libc::SIGKILL);
    }
    let _ = gate.wait();

    // Wait past the would-be read (3s); a dropped child that survived the gate
    // would have committed the read.
    std::thread::sleep(Duration::from_millis(2500));
    assert!(
        !leak.exists(),
        "the dropped direct child must die with the gate even with no cgroup layer"
    );
}

/// WO-154@v1: the gate must not set O_NONBLOCK on the inherited stderr — it is
/// shared with the operator's shell and the agent. The agent reports whether its
/// fd 2 is non-blocking.
#[test]
#[ignore = "requires Linux + root"]
fn a_run_does_not_make_the_agents_stderr_nonblocking() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("a_run_does_not_make_the_agents_stderr_nonblocking");
    let fs = common::TestFs::new("wo154nonb");
    let protected = fs.path("secret");
    let allowed = fs.path("allowed.txt");
    fs::write(&protected, "secret\n").unwrap();
    fs::write(&allowed, "ok\n").unwrap();

    let out = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["python3", "-c", "import fcntl,os,sys; sys.exit(1 if fcntl.fcntl(2, fcntl.F_GETFL) & os.O_NONBLOCK else 0)"])
        .output()
        .expect("spawn gate");
    assert!(
        out.status.success(),
        "the agent's stderr (fd 2) must not be O_NONBLOCK; gate stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// WO-154@v1: the consent queue is bounded; past its capacity a protected open
/// is denied immediately instead of holding an unbounded number of open event
/// fds. Proves it three ways: the fd count stays near the cap, the agent's
/// completion marker appears, and the receipts show the flood was denied (at
/// least one "consent queue full") AND every one of the 600 opens was answered.
#[test]
#[ignore = "requires Linux + root"]
fn bounded_consent_queue_denies_beyond_the_cap_without_fd_growth() {
    let fs = common::TestFs::new("wo154q");
    let protected = fs.path("secret");
    let done = fs.path("done");
    let receipts = fs.path("r.jsonl");
    fs::write(&protected, "secret\n").unwrap();

    // 600 concurrent opens of the protected inode, each deferred to a consent
    // worker that is blocked on the first (nobody answers).
    let inner = format!(
        "for i in $(seq 1 600); do cat {} >/dev/null 2>&1 & done; wait; echo done > {}",
        protected.display(),
        done.display()
    );
    let sock = fs.path("consent.sock");
    // Isolate the integrity state per test: a SIGKILL'd gate in a sibling test
    // leaves the shared state sticky-tainted ("prior taint not acknowledged"),
    // which would add a spurious +1 taint deny to this test's exact counts.
    let state = fs.path("state.toml");
    let mut gate = Command::new(bin())
        .args(["run", "--state"])
        .arg(&state)
        .args(["--allow-root", "--consent", "socket", "--consent-socket"])
        .arg(&sock)
        .args(["--consent-timeout", "30", "--protect"])
        .arg(&protected)
        .arg("--receipts")
        .arg(&receipts)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    let gate_pid = gate.id() as i32;

    std::thread::sleep(Duration::from_millis(400));
    let mut max_fds = 0usize;
    for _ in 0..6 {
        max_fds = max_fds.max(fd_count(gate_pid));
        std::thread::sleep(Duration::from_millis(200));
    }
    // Cap (256) plus the loop/worker/fanotify/log fds — nowhere near 600.
    assert!(
        max_fds <= 256 + 64,
        "the gate held {max_fds} open fds; the consent queue must be bounded"
    );

    let st = gate.wait().expect("reap gate");
    assert!(
        st.success(),
        "the gate must answer every open and exit: {st}"
    );

    // Evidence, not inference from fd counts alone:
    assert!(
        done.exists(),
        "the agent's completion marker must appear: every open was answered"
    );
    let body = fs::read_to_string(&receipts).expect("receipts file");
    let deny_count = body
        .lines()
        .filter(|l| l.contains(r#""decision":"deny""#))
        .count();
    assert_eq!(
        deny_count, 600,
        "all 600 protected opens must be answered with a deny receipt; got {deny_count}"
    );
    let full_count = body
        .lines()
        .filter(|l| l.contains(r#""reason":"consent queue full""#))
        .count();
    assert!(
        full_count >= 1,
        "the flood must deny at least one open via the bounded 'consent queue full' path"
    );
}

/// WO-155@v1: on graceful shutdown (SIGTERM) every already-read consent request
/// is answered DENY before the fanotify fd closes — none of the deferred
/// protected opens may succeed. Proved by the gate's exit status, the agent's
/// completion markers, and the deny receipts — not merely by missing leak files.
#[test]
#[ignore = "requires Linux + root"]
fn graceful_shutdown_denies_all_deferred_consents() {
    let fs = common::TestFs::new("wo155g");
    let protected = fs.path("secret");
    let l1 = fs.path("leak1");
    let l2 = fs.path("leak2");
    let l3 = fs.path("leak3");
    let d1 = fs.path("d1");
    let d2 = fs.path("d2");
    let d3 = fs.path("d3");
    let done = fs.path("ddone");
    let receipts = fs.path("r.jsonl");
    fs::write(&protected, "SECRET-BODY-MARKER-zz9\n").unwrap();

    // Each background reader marks its own completion after its (denied) read;
    // `wait` then the outer `done` proves all three were answered and finished.
    let inner = format!(
        "(cat {p} > {a} 2>&1; echo a > {da}) & (cat {p} > {b} 2>&1; echo b > {db}) & (cat {p} > {c} 2>&1; echo c > {dc}) & wait; echo done > {done}",
        p = protected.display(),
        a = l1.display(),
        b = l2.display(),
        c = l3.display(),
        da = d1.display(),
        db = d2.display(),
        dc = d3.display(),
        done = done.display(),
    );
    let sock = fs.path("consent.sock");
    // Isolate the integrity state per test: a SIGKILL'd gate in a sibling test
    // leaves the shared state sticky-tainted ("prior taint not acknowledged"),
    // which would add a spurious +1 taint deny to this test's exact counts.
    let state = fs.path("state.toml");
    let mut gate = Command::new(bin())
        .args(["run", "--state"])
        .arg(&state)
        .args(["--allow-root", "--consent", "socket", "--consent-socket"])
        .arg(&sock)
        .args(["--consent-timeout", "30", "--protect"])
        .arg(&protected)
        .arg("--receipts")
        .arg(&receipts)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");

    // Let the three opens reach the (blocked) consent worker, then SIGTERM.
    std::thread::sleep(Duration::from_millis(800));
    unsafe {
        let _ = libc::kill(gate.id() as i32, libc::SIGTERM);
    }
    let st = gate.wait().expect("reap gate");

    // The gate exits via the graceful-shutdown path (128 + SIGINT convention).
    assert_eq!(
        st.code(),
        Some(130),
        "the gate must exit 130 on graceful shutdown; got {st}"
    );

    // Every deferred open was answered (else its reader would still be blocked
    // and its completion marker never written) and every one was denied.
    assert!(
        d1.exists(),
        "reader 1's completion marker is missing: its open hung"
    );
    assert!(
        d2.exists(),
        "reader 2's completion marker is missing: its open hung"
    );
    assert!(
        d3.exists(),
        "reader 3's completion marker is missing: its open hung"
    );
    assert!(
        done.exists(),
        "the outer wait never finished: at least one deferred open was never answered"
    );

    let body = fs::read_to_string(&receipts).expect("receipts file");
    let deny_count = body
        .lines()
        .filter(|l| l.contains(r#""decision":"deny""#))
        .count();
    assert_eq!(
        deny_count, 3,
        "all three deferred opens must be denied in the receipts; got {deny_count}"
    );

    // And the deny is real: no read delivered the secret.
    for leak in [&l1, &l2, &l3] {
        if let Ok(b) = fs::read_to_string(leak) {
            assert!(
                !b.contains("SECRET-BODY-MARKER-zz9"),
                "a deferred open leaked the secret despite graceful shutdown: {b}"
            );
        }
    }
}

/// WO-155@v1: the cgroup layer alone reaps a REPARENTED grandchild (setsid +
/// double-fork, so the direct-child parent-death signal cannot reach it). The
/// PDEATHSIG layer is disabled via the fault-injection switch.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root + sudo"]
fn the_cgroup_layer_reaps_a_reparented_grandchild() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("the_cgroup_layer_reaps_a_reparented_grandchild");
    let fs = common::TestFs::new("wo155gc");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let gc_done = fs.path("gc-done");
    let ready = fs.path("ready");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    let inner = format!(
        "touch {ready}; setsid sh -c 'sleep 3; cat {p} > {leak} 2>&1; echo done > {done}' \
         </dev/null >/dev/null 2>&1 & exit 0",
        ready = ready.display(),
        p = protected.display(),
        leak = leak.display(),
        done = gc_done.display(),
    );
    let gate = Command::new(bin())
        .env("BULWARK_TEST_NO_PDEATHSIG", "1")
        .args(["run", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    // WO-158@v1: clean the cgroup scope after the parent-death proof completes.
    let mut gate = common::HardKillScopeGuard::new(gate);

    assert!(
        wait_for_path(&ready, Duration::from_secs(5)),
        "the agent never started"
    );
    std::thread::sleep(Duration::from_secs(1));
    unsafe {
        let _ = libc::kill(gate.id() as i32, libc::SIGKILL);
    }
    let _ = gate.wait();

    // The reparented grandchild (out of reach of PDEATHSIG) must still have been
    // reaped by the cgroup layer within ~1s, so the delayed read never happened.
    std::thread::sleep(Duration::from_millis(2500));
    assert!(
        !gc_done.exists(),
        "the reparented grandchild must be reaped by the cgroup layer, not survive to its read"
    );
    assert!(
        !leak.exists(),
        "the grandchild's protected read must never happen"
    );
}

/// WO-155@v1: fault-injection: in a DEFAULT build (feature OFF) the
/// test-only reaping switches are not compiled in, so setting BOTH
/// `BULWARK_TEST_NO_CGROUP` and `BULWARK_TEST_NO_PDEATHSIG` must be ignored and
/// the agent must still die with the gate. Compiled only when the feature is
/// absent, so it doubles as the "release build cannot be weakened by an env var"
/// check.
// WO-155@v1: prove production builds ignore test-only reaping switches.
#[test]
#[cfg(not(feature = "fault-injection"))]
#[ignore = "requires Linux + root"]
fn default_build_ignores_the_reaping_switches() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("default_build_ignores_the_reaping_switches");
    let fs = common::TestFs::new("wo155def");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let ready = fs.path("ready");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    let inner = format!(
        "touch {}; sleep 3; cat {} > {} 2>&1; echo done",
        ready.display(),
        protected.display(),
        leak.display()
    );
    let gate = Command::new(bin())
        .env("BULWARK_TEST_NO_CGROUP", "1")
        .env("BULWARK_TEST_NO_PDEATHSIG", "1")
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    // WO-158@v1: clean the default build's hard-killed run scope on every exit.
    let mut gate = common::HardKillScopeGuard::new(gate);

    assert!(
        wait_for_path(&ready, Duration::from_secs(5)),
        "the agent never started"
    );
    std::thread::sleep(Duration::from_secs(1));
    unsafe {
        let _ = libc::kill(gate.id() as i32, libc::SIGKILL);
    }
    let _ = gate.wait();

    // Both reaping switches were set, yet the default build ignores them: the
    // layers are intact and the agent must die with the gate (no leak).
    std::thread::sleep(Duration::from_millis(2500));
    assert!(
        !leak.exists(),
        "a default build must ignore the reaping switches and still reap the agent"
    );
}

/// WO-155@v1: real supervisor-death proof for the cgroup layer. The DIRECT child
/// stays alive (sleep 30) while its setsid + double-forked grandchild waits on a
/// marker; after the ready markers, SIGKILL the gate, then the grandchild must be
/// gone within 1s (reaped by cgroup.kill, reparent-proof) and its protected read
/// never happens. The PDEATHSIG layer is disabled via the fault-injection switch.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root + sudo"]
fn a_dead_gate_reaps_an_alive_direct_childs_reparented_grandchild() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("a_dead_gate_reaps_an_alive_direct_childs_reparented_grandchild");
    let fs = common::TestFs::new("wo155gc2");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let ready = fs.path("ready");
    let gcpid = fs.path("gc.pid");
    let go = fs.path("go");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    // The middle shell backgrounds the inner sh (the grandchild), records its pid
    // via $!, and exits — orphaning it — while the direct child touches READY and
    // then stays alive for 30 s.
    let inner = format!(
        "setsid sh -c '( sh -c \"while [ ! -f {go} ]; do sleep 1; done; cat {p} > {leak} 2>&1\" \
         </dev/null >/dev/null 2>&1 & echo $! > {pid} )' </dev/null >/dev/null 2>&1 & \
         touch {ready}; sleep 30",
        go = go.display(),
        p = protected.display(),
        leak = leak.display(),
        pid = gcpid.display(),
        ready = ready.display(),
    );
    let gate = Command::new(bin())
        .env("BULWARK_TEST_NO_PDEATHSIG", "1")
        .args(["run", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    // WO-158@v1: wait for cgroup emptiness and remove the killed run's scope.
    let mut gate = common::HardKillScopeGuard::new(gate);

    assert!(
        wait_for_path(&ready, Duration::from_secs(5)),
        "the agent never started"
    );
    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    // WO-177@v1: wait for the complete pid line, not merely the created path.
    let pid = read_complete_pid(&gcpid, Duration::from_secs(5));
    // Let the grandchild settle into its wait loop before the kill.
    std::thread::sleep(Duration::from_millis(300));

    unsafe {
        let rc = libc::kill(gate.id() as i32, libc::SIGKILL);
        assert_eq!(rc, 0, "SIGKILL of the gate must succeed");
    }
    let _ = gate.wait();

    // The reparented grandchild must be reaped by the cgroup layer within ~1s
    // (the direct child is still alive, so no parent-death signal is in play).
    let reap_deadline = Instant::now() + Duration::from_secs(1);
    let mut gone = !Path::new(&format!("/proc/{pid}")).exists();
    while !gone && Instant::now() < reap_deadline {
        std::thread::sleep(Duration::from_millis(20));
        gone = !Path::new(&format!("/proc/{pid}")).exists();
    }
    assert!(
        gone,
        "the grandchild must be reaped by the cgroup layer within 1s; pid {pid} still alive"
    );
    assert!(
        !leak.exists(),
        "the grandchild's protected read must never happen"
    );
}

/// WO-155@v1: on a NORMAL exit the gate reaps a daemonized (setsid + double-fork)
/// grandchild that outlives its direct child. The foreground exits while the
/// grandchild keeps running (sleep 30, then it would mark itself alive), and the
/// gate must kill it via cgroup.kill and exit promptly — never hang on the orphan
/// and never leave it unsupervised. RED when the gate instead waits out the
/// orphan's full sleep.
#[test]
#[ignore = "requires Linux + root"]
fn normal_exit_reaps_a_daemonized_grandchild() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("normal_exit_reaps_a_daemonized_grandchild");
    let fs = common::TestFs::new("wo155exit");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let alive = fs.path("alive");
    let gcpid = fs.path("gc.pid");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    // Daemonize a grandchild that would mark itself alive after a 30 s sleep,
    // then have the direct child wait for the grandchild's pid file and exit 0.
    let inner = format!(
        "setsid sh -c '( sh -c \"sleep 30; echo alive > {alive}\" \
         </dev/null >/dev/null 2>&1 & echo $! > {pid} )' </dev/null >/dev/null 2>&1 & \
         while [ ! -f {pid} ]; do sleep 0.1; done; exit 0",
        alive = alive.display(),
        pid = gcpid.display(),
    );
    let mut gate = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");

    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    // WO-177@v1: wait for the complete pid line, not merely the created path.
    let pid = read_complete_pid(&gcpid, Duration::from_secs(5));

    // The gate must exit promptly (it reaps the orphan, not waits out 30 s).
    let exit_deadline = Instant::now() + Duration::from_secs(8);
    let st = loop {
        if let Some(st) = gate.try_wait().expect("try wait gate") {
            break st;
        }
        assert!(
            Instant::now() < exit_deadline,
            "the gate must not hang on a daemonized grandchild (did not exit in 8s)"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        st.success(),
        "the gate must exit cleanly after reaping the orphan: {st}"
    );

    // The orphan is gone, and never lived to mark itself alive.
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "the daemonized grandchild must be reaped on normal exit; pid {pid} still alive"
    );
    assert!(
        !alive.exists(),
        "the grandchild survived long enough to mark itself alive (not reaped)"
    );
    assert!(
        !leak.exists(),
        "the daemonized grandchild must never complete a read"
    );
}

/// WO-155@v1: when `cgroup.kill` is made to fail, the freeze + per-pid SIGKILL
/// fallback must still reap a daemonized grandchild on a normal exit — the run
/// never returns on a timer with the tree still alive.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn normal_exit_reaps_via_the_freeze_fallback_when_cgroup_kill_fails() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("normal_exit_reaps_via_the_freeze_fallback_when_cgroup_kill_fails");
    let fs = common::TestFs::new("wo155freeze");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let alive = fs.path("alive");
    let gcpid = fs.path("gc.pid");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    let inner = format!(
        "setsid sh -c '( sh -c \"sleep 30; echo alive > {alive}; cat {p} > {leak} 2>&1\" \
         </dev/null >/dev/null 2>&1 & echo $! > {pid} )' </dev/null >/dev/null 2>&1 & \
         while [ ! -f {pid} ]; do sleep 0.1; done; exit 0",
        alive = alive.display(),
        p = protected.display(),
        leak = leak.display(),
        pid = gcpid.display(),
    );
    let mut gate = Command::new(bin())
        .env("BULWARK_TEST_NO_CGROUP_KILL", "1")
        .env("BULWARK_TEST_NO_CGROUP", "1")
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");

    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    // WO-177@v1: wait for the complete pid line, not merely the created path.
    let pid = read_complete_pid(&gcpid, Duration::from_secs(5));

    let exit_deadline = Instant::now() + Duration::from_secs(8);
    let st = loop {
        if let Some(st) = gate.try_wait().expect("try wait gate") {
            break st;
        }
        assert!(
            Instant::now() < exit_deadline,
            "the gate must not hang when cgroup.kill fails (did not exit in 8s)"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        st.success(),
        "the gate must exit cleanly after the freeze fallback: {st}"
    );
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "the grandchild must be reaped by the freeze fallback; pid {pid} alive"
    );
    assert!(
        !alive.exists(),
        "the grandchild survived long enough to mark itself alive"
    );
    assert!(
        !leak.exists(),
        "the grandchild's protected read must never succeed"
    );
}

/// WO-155@v1: on a graceful stop the loop keeps enforcing until the tree is dead.
/// A direct child whose first protected read is answered DENY then issues a
/// second protected read: the second must also be denied (or the child reaped
/// first) — never released as allowed when the fanotify fd closes.
#[test]
#[ignore = "requires Linux + root"]
fn a_second_protected_read_during_teardown_is_denied_not_released() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("a_second_protected_read_during_teardown_is_denied_not_released");
    let fs = common::TestFs::new("wo155twice");
    let protected = fs.path("secret");
    let leak1 = fs.path("leak1.txt");
    let leak2 = fs.path("leak2.txt");
    fs::write(&protected, "SECRET-BODY-MARKER-zz9\n").unwrap();

    let inner = format!(
        "cat {p} > {a} 2>&1; cat {p} > {b} 2>&1; echo done > {done}",
        p = protected.display(),
        a = leak1.display(),
        b = leak2.display(),
        done = fs.path("done").display(),
    );
    let sock = fs.path("consent.sock");
    let mut gate = Command::new(bin())
        .args([
            "run",
            "--allow-root",
            "--consent",
            "socket",
            "--consent-socket",
        ])
        .arg(&sock)
        .args(["--consent-timeout", "30", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");

    // Let the first read reach the deferred-consent state, then SIGTERM.
    std::thread::sleep(Duration::from_millis(800));
    unsafe {
        let _ = libc::kill(gate.id() as i32, libc::SIGTERM);
    }
    let st = gate.wait().expect("reap gate");
    assert_eq!(st.code(), Some(130), "the gate must exit 130: {st}");

    for leak in [&leak1, &leak2] {
        if let Ok(body) = fs::read_to_string(leak) {
            assert!(
                !body.contains("SECRET-BODY-MARKER-zz9"),
                "a protected read leaked the secret during teardown: {body}"
            );
        }
    }
}

/// WO-155@v1: default mode refuses to start when the host
/// cannot reap the whole supervised tree; no writable cgroup-v2 scope must name
/// the reason and the remedy (use --hardened). The `--hardened` launch — a
/// Landlock-only path with no supervisor — still runs.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn default_mode_refuses_without_a_reapable_scope_and_hardened_runs() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("default_mode_refuses_without_a_reapable_scope_and_hardened_runs");
    let fs = common::TestFs::new("wo155refuse");
    let protected = fs.path("secret");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    // Default (non-hardened) mode on a host with no scope: refuse before
    // running, naming the reason and --hardened.
    let out = Command::new(bin())
        .env("BULWARK_TEST_NO_SCOPE", "1")
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", "echo should-not-run"])
        .output()
        .expect("spawn gate");
    assert!(
        !out.status.success(),
        "default mode without a reapable scope must refuse"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot reap the supervised tree") && stderr.contains("--hardened"),
        "the refusal must name the reason and --hardened; got: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("should-not-run"),
        "the refused command must never have run (its output is absent)"
    );

    // --hardened (Landlock-only, no supervisor) still runs on the same host.
    let h = Command::new(bin())
        .env("BULWARK_TEST_NO_SCOPE", "1")
        .args([
            "run",
            // WO-149@v1: isolate the integrity state for this run.
            "--state",
            state.to_str().unwrap(),
            "--hardened",
            "--allow-root",
            "--allow",
            "/var/tmp",
            "--",
            "sh",
            "-c",
            "echo hardened-ran",
        ])
        .output()
        .expect("spawn hardened");
    assert!(
        h.status.success(),
        "--hardened must still run without a scope; stderr: {}",
        String::from_utf8_lossy(&h.stderr)
    );
}

/// WO-155@v1: default mode refuses to start when the cgroup status files
/// (cgroup.procs / cgroup.events) cannot be opened — the watcher could never
/// prove the tree reaped, so a dead gate would leave a live unsupervised tree.
/// Same refusal family as an unreapable host.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn default_mode_refuses_when_the_status_files_are_unreadable() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("default_mode_refuses_when_the_status_files_are_unreadable");
    let fs = common::TestFs::new("wo155refuse2");
    let protected = fs.path("secret");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    let out = Command::new(bin())
        .env("BULWARK_TEST_NO_PROCS_EVENTS", "1")
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", "echo should-not-run"])
        .output()
        .expect("spawn gate");
    assert!(
        !out.status.success(),
        "default mode without readable cgroup.procs/cgroup.events must refuse"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot reap the supervised tree") && stderr.contains("--hardened"),
        "the refusal must name the reason and --hardened; got: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("should-not-run"),
        "the refused command must never have run (its output is absent)"
    );
}

/// WO-155@v1: the crash WATCHER's freeze + SIGKILL fallback (its own cgroup.kill
/// is made unavailable by the fault-injection switch, which applies to the
/// watcher too). The direct child stays alive while a double-forked grandchild
/// loops on a protected read; SIGKILL the supervisor and the watcher must still
/// reap the grandchild within 2 s — the read never succeeds.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn the_crash_watcher_freeze_fallback_reaps_a_reparented_grandchild() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("the_crash_watcher_freeze_fallback_reaps_a_reparented_grandchild");
    let fs = common::TestFs::new("wo155wfall");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let gcpid = fs.path("gc.pid");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    let inner = format!(
        "setsid sh -c '( sh -c \"while :; do cat {p} > {leak} 2>/dev/null && break; sleep 0.05; done\" \
         </dev/null >/dev/null 2>&1 & echo $! > {pid} )' </dev/null >/dev/null 2>&1 & \
         while [ ! -f {pid} ]; do sleep 0.1; done; sleep 30",
        p = protected.display(),
        leak = leak.display(),
        pid = gcpid.display(),
    );
    let gate = Command::new(bin())
        .env("BULWARK_TEST_NO_CGROUP_KILL", "1")
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    // WO-158@v1: remove the freeze-fallback run's scope after positive emptiness proof.
    let mut gate = common::HardKillScopeGuard::new(gate);

    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    // WO-177@v1: wait for the complete pid line, not merely the created path.
    let pid = read_complete_pid(&gcpid, Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(300));

    unsafe {
        let rc = libc::kill(gate.id() as i32, libc::SIGKILL);
        assert_eq!(rc, 0, "SIGKILL of the supervisor must succeed");
    }
    let _ = gate.wait();

    // The watcher's freeze + SIGKILL sweep must reap the grandchild within ~2 s.
    let reap_deadline = Instant::now() + Duration::from_secs(2);
    let mut gone = !Path::new(&format!("/proc/{pid}")).exists();
    while !gone && Instant::now() < reap_deadline {
        std::thread::sleep(Duration::from_millis(20));
        gone = !Path::new(&format!("/proc/{pid}")).exists();
    }
    assert!(
        gone,
        "the crash watcher's freeze fallback must reap the grandchild within 2 s (pid {pid} alive)"
    );
    // The looping read never succeeds — the leak file, if it exists, is empty.
    if let Ok(body) = fs::read_to_string(&leak) {
        assert!(
            !body.contains("SECRET-LINE"),
            "the grandchild completed a protected read: {body}"
        );
    }
}

/// WO-155@v1: the crash watcher exits ONLY on positive proof the scope is empty.
/// With the cgroup.kill write failing AND the first several cgroup.events reads
/// failing (injected faults), a hard SIGKILL of the supervisor must still leave a
/// watcher that reaps a reparented grandchild over the freeze + SIGKILL sweep —
/// it must not exit on the failed kill write, and it must not treat the failed
/// status reads as "empty". Exercises the watcher's raw-libc fallback, not the
/// live-supervisor loop.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn the_watcher_fails_closed_when_the_kill_write_and_status_reads_fail() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state =
        isolated_state("the_watcher_fails_closed_when_the_kill_write_and_status_reads_fail");
    let fs = common::TestFs::new("wo155wfc");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let gcpid = fs.path("gc.pid");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    let inner = format!(
        "setsid sh -c '( sh -c \"while :; do cat {p} > {leak} 2>/dev/null && break; sleep 0.05; done\" \
         </dev/null >/dev/null 2>&1 & echo $! > {pid} )' </dev/null >/dev/null 2>&1 & \
         while [ ! -f {pid} ]; do sleep 0.1; done; sleep 30",
        p = protected.display(),
        leak = leak.display(),
        pid = gcpid.display(),
    );
    let gate = Command::new(bin())
        .env("BULWARK_TEST_KILL_WRITE_FAIL", "1")
        .env("BULWARK_TEST_EVENTS_READ_FAILS", "5")
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    // WO-158@v1: clean the fail-closed watcher's scope after it empties the tree.
    let mut gate = common::HardKillScopeGuard::new(gate);

    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    // WO-177@v1: wait for the complete pid line, not merely the created path.
    let pid = read_complete_pid(&gcpid, Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(300));

    unsafe {
        let rc = libc::kill(gate.id() as i32, libc::SIGKILL);
        assert_eq!(rc, 0, "SIGKILL of the supervisor must succeed");
    }
    let _ = gate.wait();

    // The watcher must not exit on the failed kill write or the failed status
    // reads: it keeps sweeping until an events read succeeds and shows the scope
    // empty, reaping the grandchild within ~2 s.
    let reap_deadline = Instant::now() + Duration::from_secs(2);
    let mut gone = !Path::new(&format!("/proc/{pid}")).exists();
    while !gone && Instant::now() < reap_deadline {
        std::thread::sleep(Duration::from_millis(20));
        gone = !Path::new(&format!("/proc/{pid}")).exists();
    }
    assert!(
        gone,
        "the watcher's fail-closed sweep must reap the grandchild within 2 s (pid {pid} alive)"
    );
    if let Ok(body) = fs::read_to_string(&leak) {
        assert!(
            !body.contains("SECRET-LINE"),
            "the grandchild completed a protected read: {body}"
        );
    }
}

/// WO-155@v1: `scope_removed()` — a real cgroup fd op failing ENODEV/ENOENT proves
/// the scope was removed underneath the watcher, and a cgroup-v2 scope is
/// removable only while empty, so the watcher EXITS instead of re-reading a
/// deleted scope's fds forever. Ordering, not overlapping clocks: the watcher is
/// SIGSTOPped before the supervisor is killed, so the test empties + rmdir's the
/// scope while the watcher is provably frozen; SIGCONT then resumes it and its
/// first action (the cgroup.kill write on the removed scope) fails ENODEV, so it
/// exits via scope_removed.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn the_watcher_exits_when_its_scope_is_removed() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("the_watcher_exits_when_its_scope_is_removed");
    let fs = common::TestFs::new("wo155scope");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let gcpid = fs.path("gc.pid");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    // A grandchild that keeps the scope populated while looping on a protected
    // read; the watcher's cgroup.kill races it, so the read never completes.
    let inner = format!(
        "setsid sh -c '( sh -c \"while :; do cat {p} > {leak} 2>/dev/null && break; sleep 0.05; done\" \
         </dev/null >/dev/null 2>&1 & echo $! > {pid} )' </dev/null >/dev/null 2>&1 & \
         while [ ! -f {pid} ]; do sleep 0.1; done; sleep 30",
        p = protected.display(),
        leak = leak.display(),
        pid = gcpid.display(),
    );
    let gate = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    let gate_pid = gate.id() as i32;
    let scope = PathBuf::from(format!("/sys/fs/cgroup/bulwark.run-{gate_pid}"));
    let mut guard = RunGuard::new(gate, scope);

    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    std::thread::sleep(Duration::from_millis(300));

    // Pin the watcher (a child of the supervisor) BEFORE stopping/killing;
    // add_watchers asserts one was found and fails closed on a pidfd error.
    let watchers = watcher_pids_of(gate_pid);
    guard.add_watchers(&watchers);

    // Freeze the watcher in place, THEN kill the supervisor: the watcher cannot
    // reap (and cannot exit normally) while the scope is emptied and rmdir'd.
    guard.signal_watchers(libc::SIGSTOP);
    unsafe {
        let rc = libc::kill(gate_pid, libc::SIGKILL);
        assert_eq!(rc, 0, "SIGKILL of the supervisor must succeed");
    }
    let _ = guard.gate().expect("gate owned").wait();

    // Empty the scope for real (cgroup.kill) and wait until it is removable,
    // then rmdir it — all while the watcher is SIGSTOPped, so there is no race.
    let scope = guard.scope();
    assert!(
        scope.exists(),
        "the run's cgroup scope must exist before the test removes it: {}",
        scope.display()
    );
    let _ = fs::write(scope.join("cgroup.kill"), b"1");
    let empty_deadline = Instant::now() + Duration::from_secs(5);
    let mut emptied = fs::read_to_string(scope.join("cgroup.procs"))
        .map(|s| s.trim().is_empty())
        .unwrap_or(false);
    while !emptied && Instant::now() < empty_deadline {
        std::thread::sleep(Duration::from_millis(10));
        emptied = fs::read_to_string(scope.join("cgroup.procs"))
            .map(|s| s.trim().is_empty())
            .unwrap_or(false);
    }
    assert!(emptied, "the scope must be empty before it can be removed");
    fs::remove_dir(scope).expect("rmdir the emptied cgroup scope");
    assert!(
        !scope.exists(),
        "the scope must be gone BEFORE the watcher is resumed"
    );

    // Resume the watcher: its read() now returns EOF, and its first action — the
    // cgroup.kill write on the removed scope — fails ENODEV/ENOENT, so it exits
    // via scope_removed. Its own deadline bounds the assertion, so a regression
    // to the old fail-closed read loop fails, never hangs forever.
    guard.signal_watchers(libc::SIGCONT);
    let watcher_deadline = Instant::now() + Duration::from_secs(15);
    guard.watchers_exited(watcher_deadline);

    // The fanotify group is now gone, so this open is not intercepted; the
    // grandchild never completed a read (cgroup.kill raced it).
    if let Ok(body) = fs::read_to_string(&leak) {
        assert!(
            !body.contains("SECRET-LINE"),
            "the grandchild completed a protected read before the removal: {body}"
        );
    }
}

/// WO-155@v1: SIGTERM with an uncooperative foreground child (it sleeps forever
/// and double-forks a sleeping grandchild) must still tear down — the gate exits
/// within SHUTDOWN_GRACE + SIGTERM_TO_KILL + 4 s, both processes are dead, and no
/// protected read succeeded. The forwarding SIGTERM and the later SIGKILL-reap
/// escalation, not a wait on the child.
#[test]
#[ignore = "requires Linux + root"]
fn uncooperative_child_is_escalated_after_the_shutdown_grace() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("uncooperative_child_is_escalated_after_the_shutdown_grace");
    let fs = common::TestFs::new("wo155stubborn");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let gcpid = fs.path("gc.pid");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    // Direct child ignores SIGTERM and sleeps forever; a double-forked grandchild
    // (sleeping too, in the same cgroup) outlives it regardless of the nudged
    // SIGTERM — only the grace escalation (a cgroup reap) can end the run.
    let inner = format!(
        "trap '' TERM; setsid sh -c '( sh -c \"sleep 1000\" </dev/null >/dev/null 2>&1 & echo $! > {pid} )' \
         </dev/null >/dev/null 2>&1 & while [ ! -f {pid} ]; do sleep 0.1; done; sleep 1000",
        pid = gcpid.display(),
    );
    let mut gate = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");

    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    // WO-177@v1: wait for the complete pid line, not merely the created path.
    let pid = read_complete_pid(&gcpid, Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(300));

    unsafe {
        let _ = libc::kill(gate.id() as i32, libc::SIGTERM);
    }

    // The gate exits within SHUTDOWN_GRACE + SIGTERM_TO_KILL + 4 s, having
    // escalated to a cgroup reap rather than waiting forever for the sleeping
    // child (SIGTERM at the grace, SIGKILL-reap after the kill delay).
    let exit_deadline = Instant::now() + Duration::from_secs(8);
    let st = loop {
        if let Some(st) = gate.try_wait().expect("try wait gate") {
            break st;
        }
        assert!(
            Instant::now() < exit_deadline,
            "the gate must not hang on an uncooperative child (did not exit in 8 s)"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        st.code(),
        Some(130),
        "the gate must exit 130 on SIGTERM: {st}"
    );

    // Both the direct child's tree and the double-forked grandchild are dead.
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "the double-forked grandchild must be reaped; pid {pid} alive"
    );
    assert!(!leak.exists(), "no protected read may have succeeded");
}

/// WO-155@v1: a SIGTERM-cooperative child (a TERM trap that writes a marker
/// and exits) must observe the forwarded SIGTERM and exit BEFORE the reap
/// escalates to SIGKILL — the marker proves the child got SIGTERM, not SIGKILL.
// WO-155@v1: give cooperative children a bounded graceful exit before reaping.
#[test]
#[ignore = "requires Linux + root"]
fn a_sigterm_cooperative_child_exits_before_the_reap_escalation() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("a_sigterm_cooperative_child_exits_before_the_reap_escalation");
    let fs = common::TestFs::new("wo155coop");
    let protected = fs.path("secret");
    let gcpid = fs.path("gc.pid");
    let marker = fs.path("exited");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    // The direct child traps TERM (writes a marker, exits 0) and double-forks a
    // sleeping grandchild in its OWN setsid session, which survives the child's
    // SIGTERM and is reaped by the cgroup afterwards. The trailing loop keeps the
    // shell alive in the trap (a trailing `sleep` would exec away the handler).
    let inner = format!(
        "trap 'echo gone > {marker}; exit 0' TERM; setsid sh -c '( sh -c \"sleep 1000\" </dev/null >/dev/null 2>&1 & echo $! > {pid} )' \
         </dev/null >/dev/null 2>&1 & while [ ! -f {pid} ]; do sleep 0.1; done; while :; do sleep 0.2; done",
        marker = marker.display(),
        pid = gcpid.display(),
    );
    let mut gate = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");

    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    // WO-177@v1: wait for the complete pid line, not merely the created path.
    let pid = read_complete_pid(&gcpid, Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(300));

    unsafe {
        let _ = libc::kill(gate.id() as i32, libc::SIGTERM);
    }

    // The gate exits 130 within SHUTDOWN_GRACE + SIGTERM_TO_KILL + 4 s.
    let exit_deadline = Instant::now() + Duration::from_secs(8);
    let st = loop {
        if let Some(st) = gate.try_wait().expect("try wait gate") {
            break st;
        }
        assert!(
            Instant::now() < exit_deadline,
            "the gate must not hang on a cooperative child"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        st.code(),
        Some(130),
        "the gate must exit 130 on SIGTERM: {st}"
    );

    // The trap wrote the marker only if the child processed SIGTERM (a SIGKILL
    // reap would skip the trap) — it exited before any reap.
    assert!(
        std::fs::metadata(&marker).is_ok(),
        "the SIGTERM-cooperative child must exit on SIGTERM before any reap"
    );

    // The double-forked grandchild is reaped by the cgroup.
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "the double-forked grandchild must be reaped; pid {pid} alive"
    );
}

/// WO-156@v2: a receipts file that already exists and is owned by ANOTHER uid
/// (planted in a sticky world-writable dir) is refused at startup — root must not
/// append its audit trail to a file the attacker chose — and left unchanged.
#[test]
#[ignore = "requires Linux + root"]
fn a_foreign_owned_receipts_file_is_refused_and_unchanged() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("a_foreign_owned_receipts_file_is_refused_and_unchanged");
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let fs = common::TestFs::new("wo156uid");
    let protected = fs.path("secret");
    fs::write(&protected, "secret\n").unwrap();

    // A sticky world-writable dir (like /tmp) holds a receipts file owned by
    // nobody (65534) — root can open it but must refuse to adopt it.
    let dir = std::env::temp_dir().join(format!(
        "bulwark-uid-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
    let receipts = dir.join("r.jsonl");
    std::fs::write(&receipts, "PLANTED\n").unwrap();
    let c = CString::new(receipts.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::chown(c.as_ptr(), 65534, 65534) };
    assert_eq!(
        rc, 0,
        "chown the receipts file to nobody failed (needs root)"
    );

    let out = Command::new(bin())
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        .args(["--receipts"])
        .arg(&receipts)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", "exit 0"])
        .output()
        .expect("spawn gate");

    assert!(
        !out.status.success(),
        "the gate must refuse a foreign-owned receipts file"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // On Linux the kernel's `fs.protected_regular` often refuses this open itself
    // (EACCES, "cannot open receipts file … Permission denied") before the
    // explicit ownership check runs; on macOS (no protected_regular) the check
    // fires with "… not the effective uid …". Either refusal names the path.
    assert!(
        stderr.contains("effective uid") || stderr.contains("cannot open receipts file"),
        "the refusal must name the ownership mismatch; stderr: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&receipts).unwrap(),
        "PLANTED\n",
        "the foreign-owned file must be unchanged"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// WO-155@v1: on a successful cgroup.kill the watcher must NOT exit until it
/// can positively confirm the scope is empty. With the cgroup.events reads failing
/// indefinitely (injected), a hard SIGKILL of the supervisor must leave the watcher
/// ALIVE after 2 s — it cannot prove empty, so it keeps holding the fanotify fd and
/// the grandchild's protected open never returns success. Exercises the
/// kill-success path's positive-proof rule (not the live-supervisor loop).
// WO-155@v1: keep the watcher alive until cgroup emptiness is proven.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn a_successful_kill_still_waits_for_positive_proof_of_empty() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("a_successful_kill_still_waits_for_positive_proof_of_empty");
    let fs = common::TestFs::new("wo155hold");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let gcpid = fs.path("gc.pid");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    let inner = format!(
        "setsid sh -c '( sh -c \"while :; do cat {p} > {leak} 2>/dev/null && break; sleep 0.05; done\" \
         </dev/null >/dev/null 2>&1 & echo $! > {pid} )' </dev/null >/dev/null 2>&1 & \
         while [ ! -f {pid} ]; do sleep 0.1; done; sleep 30",
        p = protected.display(),
        leak = leak.display(),
        pid = gcpid.display(),
    );
    let gate = Command::new(bin())
        .env("BULWARK_TEST_EVENTS_READ_FAILS", "999999999")
        .env("BULWARK_TEST_PROCS_READ_FAILS", "999999999")
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    let gate_pid = gate.id() as i32;
    let scope = PathBuf::from(format!("/sys/fs/cgroup/bulwark.run-{gate_pid}"));
    let mut guard = RunGuard::new(gate, scope);

    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    // WO-177@v1: wait for the complete pid line, not merely the created path.
    let pid = read_complete_pid(&gcpid, Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(300));

    // Pin the watcher (a child of the supervisor) BEFORE the kill; the guard
    // reaps it on drop (also on an assertion failure).
    let watchers = watcher_pids_of(gate_pid);
    guard.add_watchers(&watchers);

    unsafe {
        let rc = libc::kill(gate_pid, libc::SIGKILL);
        assert_eq!(rc, 0, "SIGKILL of the supervisor must succeed");
    }
    let _ = guard.gate().expect("gate owned").wait();

    // The injected read failure means the watcher can never positively confirm
    // empty, so it must STILL be alive after 2 s (cgroup.kill has reaped the
    // grandchild in the meantime, but the watcher has no proof and holds on).
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        !watchers.is_empty(),
        "the watcher must stay alive until it positively proves the scope empty"
    );
    for w in &watchers {
        assert!(
            Path::new(&format!("/proc/{w}")).exists(),
            "the watcher {w} must stay alive to hold the fanotify fd"
        );
    }
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "cgroup.kill must have reaped the grandchild; pid {pid} alive"
    );
    // Check the leak by SIZE, not by opening it: the watcher's fail-closed hold
    // keeps the fanotify fd open, and an open of leak.txt from the test would
    // hang (unanswered). A non-zero size means the protected read succeeded.
    if let Ok(m) = fs::metadata(&leak) {
        assert_eq!(
            m.len(),
            0,
            "the grandchild completed a protected read ({} bytes)",
            m.len()
        );
    }
    // The guard reaps the still-alive watcher on drop (also on an assertion failure).
}

/// WO-155@v1: on a successful cgroup.kill the watcher polls cgroup.events for
/// positive proof. With the events forced to report `populated 1` for N reads
/// (injected), the watcher must STAY ALIVE during those reads and exit only once a
/// later read reports `populated 0`. Exercises the kill-success polling rule.
// WO-155@v1: require positive empty-scope evidence before watcher exit.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn the_watcher_stays_alive_while_events_report_populated() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("the_watcher_stays_alive_while_events_report_populated");
    let fs = common::TestFs::new("wo155poll");
    let protected = fs.path("secret");
    let gcpid = fs.path("gc.pid");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    // A sleeping grandchild (no protected read needed): this test observes the
    // watcher's lifetime, not a read.
    let inner = format!(
        "setsid sh -c '( sh -c \"sleep 1000\" </dev/null >/dev/null 2>&1 & echo $! > {pid} )' \
         </dev/null >/dev/null 2>&1 & while [ ! -f {pid} ]; do sleep 0.1; done; sleep 30",
        pid = gcpid.display(),
    );
    let gate = Command::new(bin())
        .env("BULWARK_TEST_EVENTS_READ_POPULATED_FOR", "100")
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    let gate_pid = gate.id() as i32;
    let scope = PathBuf::from(format!("/sys/fs/cgroup/bulwark.run-{gate_pid}"));
    let mut guard = RunGuard::new(gate, scope);

    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    std::thread::sleep(Duration::from_millis(300));

    // Pin the watcher (a child of the supervisor) BEFORE the kill; the guard
    // reaps it on drop (also on an assertion failure).
    let watchers = watcher_pids_of(gate_pid);
    guard.add_watchers(&watchers);

    unsafe {
        let rc = libc::kill(gate_pid, libc::SIGKILL);
        assert_eq!(rc, 0, "SIGKILL of the supervisor must succeed");
    }
    let _ = guard.gate().expect("gate owned").wait();

    // 100 injected "populated 1" reads x 10 ms ≈ 1 s: the watcher must STILL be
    // alive at 300 ms (it is polling, not exiting immediately).
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !watchers.is_empty(),
        "the watcher must stay alive while cgroup.events still reports populated"
    );

    // After the injected window the real cgroup.events reads `populated 0` (the
    // cgroup.kill finished and the reparented zombies are reaped), so the watcher
    // exits. Poll those specific watcher pids rather than "no bulwark process",
    // so a leftover gate from a sibling test does not fool the check.
    let deadline = Instant::now() + Duration::from_secs(15);
    guard.watchers_exited(deadline);
}

/// WO-155@v1: a SUPERVISOR PANIC must not release the watcher — a
/// panic-unwind drop of the guard closes the pipe, so the watcher REAPS the tree
/// rather than exiting unwatched. The fault-injection switch arms a SIGUSR2
/// handler; the test signals the supervisor once the grandchild is live. The
/// grandchild must die within the watcher bound, no protected read may complete,
/// and the watcher must exit.
// WO-155@v1: retain crash reaping when supervisor control unwinds unexpectedly.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn a_panicking_supervisor_leaves_a_reaping_watcher() {
    // WO-149@v1: give this test its own integrity state, never the host default.
    let state = isolated_state("a_panicking_supervisor_leaves_a_reaping_watcher");
    let fs = common::TestFs::new("wo155panic");
    let protected = fs.path("secret");
    let leak = fs.path("leak.txt");
    let gcpid = fs.path("gc.pid");
    fs::write(&protected, "SECRET-LINE\n").unwrap();

    // The direct child double-forks a grandchild that loops on a protected read;
    // the gate answers non-protected opens normally (so `gc.pid` is observed) and
    // is then panicked by SIGUSR2 while the grandchild is still looping.
    let inner = format!(
        "setsid sh -c '( sh -c \"while :; do cat {p} > {leak} 2>/dev/null && break; sleep 0.05; done\" \
         </dev/null >/dev/null 2>&1 & echo $! > {pid} )' </dev/null >/dev/null 2>&1 & \
         while [ ! -f {pid} ]; do sleep 0.1; done; sleep 30",
        p = protected.display(),
        leak = leak.display(),
        pid = gcpid.display(),
    );
    let gate = Command::new(bin())
        .env("BULWARK_TEST_PANIC_AFTER_SPAWN", "1")
        .args(["run", "--allow-root", "--protect"])
        .arg(&protected)
        // WO-149@v1: isolate the integrity state for this run.
        .arg("--state")
        .arg(&state)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gate");
    let gate_pid = gate.id() as i32;
    let scope = PathBuf::from(format!("/sys/fs/cgroup/bulwark.run-{gate_pid}"));
    let mut guard = RunGuard::new(gate, scope);

    assert!(
        wait_for_path(&gcpid, Duration::from_secs(5)),
        "the grandchild never daemonized"
    );
    // WO-177@v1: wait for the complete pid line, not merely the created path.
    let pid = read_complete_pid(&gcpid, Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(300));

    // Pin the watcher (a child of the supervisor) BEFORE the panic; the guard
    // reaps it on drop (also on an assertion failure).
    let watchers = watcher_pids_of(gate_pid);
    guard.add_watchers(&watchers);

    // SIGUSR2 -> the supervisor panics on the main loop (exit 101).
    unsafe {
        let rc = libc::kill(gate_pid, libc::SIGUSR2);
        assert_eq!(rc, 0, "SIGUSR2 of the supervisor must succeed");
    }
    let st = guard
        .gate()
        .expect("gate owned")
        .wait()
        .expect("reap the panicked gate");
    assert_eq!(st.code(), Some(101), "the supervisor must panic: {st}");

    // The watcher must reap the grandchild within its bound (cgroup.kill, then
    // positive proof of empty) — the read never completes.
    let reap_deadline = Instant::now() + Duration::from_secs(2);
    let mut gone = !Path::new(&format!("/proc/{pid}")).exists();
    while !gone && Instant::now() < reap_deadline {
        std::thread::sleep(Duration::from_millis(20));
        gone = !Path::new(&format!("/proc/{pid}")).exists();
    }
    assert!(
        gone,
        "the crash watcher must reap the grandchild within 2 s (pid {pid} alive)"
    );
    if let Ok(body) = fs::read_to_string(&leak) {
        assert!(
            !body.contains("SECRET-LINE"),
            "the grandchild completed a protected read after the panic: {body}"
        );
    }

    // The watcher exits once it proves the scope empty (the panic path must not
    // leave a watcher hanging).
    let watcher_deadline = Instant::now() + Duration::from_secs(15);
    guard.watchers_exited(watcher_deadline);
}

/// WO-155@v1: a file writer blocked indefinitely (fault-injection) AND a
/// stderr pipe nobody drains must not delay the gate's exit — Drop enqueues the
/// summary, waits only a bounded time, and returns regardless, so the gate
/// finishes within the bound + 1 s and its integrity state is clean.
// WO-155@v1: bound gate exit when both receipt sinks are blocked.
// WO-160@v1: measure the exit bound only after supervised work completes.
#[test]
#[cfg(feature = "fault-injection")]
#[ignore = "requires Linux + root"]
fn a_blocked_receipts_sink_never_holds_the_gate_exit() {
    let fs = common::TestFs::new("wo155bk");
    let protected = fs.path("secret");
    let allowed = fs.path("allowed.txt");
    let receipts = fs.path("r.jsonl");
    let state = fs.path("state.toml");
    fs::write(&protected, "secret\n").unwrap();
    fs::write(&allowed, "ok\n").unwrap();

    // The file writer blocks forever (injected), and the stderr read end is held
    // but never drained, so the stderr writer blocks once its pipe fills.
    // WO-160@v1: the agent's last action is the marker, so the exit bound below
    // is measured from the end of its work, not from spawn (its 2000 opens take
    // a runner-dependent time).
    let marker = fs.path("agent-done");
    let inner = format!(
        "for i in $(seq 1 2000); do cat {} >/dev/null; done; : > {}",
        allowed.display(),
        marker.display()
    );
    let mut gate = Command::new(bin())
        .env("BULWARK_TEST_LOG_WRITER_BLOCK", "1")
        .args(["run", "--state"])
        .arg(&state)
        .args(["--allow-root", "--protect"])
        .arg(&protected)
        .arg("--receipts")
        .arg(&receipts)
        .arg("--")
        .args(["sh", "-c", &inner])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gate");

    // Wait (generously) for the agent to finish its work.
    let work_deadline = Instant::now() + Duration::from_secs(30);
    while !marker.exists() {
        assert!(
            Instant::now() < work_deadline,
            "the agent did not finish its opens within 30 s"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // From the end of the agent's work, the gate must exit within
    // WRITER_DRAIN_WAIT (2 s) + 1 s.
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(st) = gate.try_wait().expect("try wait gate") {
            break st;
        }
        assert!(
            Instant::now() < deadline,
            "the gate must not be held hostage by a blocked sink (still running 3 s after the agent finished)"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "the gate must exit cleanly: {status}");
    // A normal exit writes the clean-shutdown marker and no taint.
    let so = fs::read_to_string(&state).unwrap_or_default();
    assert!(
        so.contains("clean_shutdown = true") && !so.contains("taint"),
        "integrity state must be clean; got: {so}"
    );
}

// WO-240@v1: shadow mode must never deny, and must still name the protected open.
#[test]
#[ignore = "requires Linux + root"]
fn watch_allows_a_protected_read_and_flags_it_would_deny() {
    let fs = common::TestFs::new("wo240w");
    let protected = fs.path("guarded");
    let other = fs.path("plain.txt");
    // WO-240@v1: the tmpfs root is 1777, which watch refuses as a receipts parent.
    let evidence = fs.path("evidence");
    fs::create_dir(&evidence).unwrap();
    fs::set_permissions(
        &evidence,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let receipts = evidence.join("r.jsonl");
    fs::write(&protected, "WO240_GUARDED\n").unwrap();
    fs::write(&other, "WO240_PLAIN\n").unwrap();
    // WO-240@v1: a policy `~/` entry prints the home-expansion line, which must not
    // claim protection; a `--protect ~/…` flag is literal and would refuse the run.
    let policy = evidence.join("Bulwark.toml");
    fs::write(
        &policy,
        format!(
            "[protected]\nprompt = [\"~/.bulwark-wo240-absent\", \"{}\"]\n",
            protected.display()
        ),
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["watch", "--allow-root", "--policy"])
        .arg(&policy)
        .arg("--receipts")
        .arg(&receipts)
        .args(["--format", "json", "--", "sh", "-c"])
        .arg(format!("cat {} {}", protected.display(), other.display()))
        .output()
        .expect("spawn watch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "watch must pass the agent's exit through; stderr: {stderr}"
    );
    assert!(
        stdout.contains("WO240_GUARDED") && stdout.contains("WO240_PLAIN"),
        "watch must not deny any read; stdout: {stdout}"
    );
    assert!(
        stderr.contains("RECORDING ONLY"),
        "the banner must say nothing is enforced: {stderr}"
    );
    assert!(
        stderr.contains("[bulwark] watching: `~/` entries are flagged would_deny")
            && !stderr.contains("protecting:"),
        "watch must not claim protection: {stderr}"
    );
    // WO-240@v1: ordinary allows go to the receipts file only, never the agent's terminal.
    assert!(
        !stderr.contains(&format!("path={} ", other.display())),
        "an ordinary allow must not be echoed to stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!("path={} ", protected.display())),
        "a would-deny open must be echoed to stderr: {stderr}"
    );

    let raw = fs::read_to_string(&receipts).expect("read receipts");
    let guarded = format!("\"path\":\"{}\"", protected.display());
    let plain = format!("\"path\":\"{}\"", other.display());
    assert!(
        raw.lines().any(|l| l.contains(&guarded)
            && l.contains("\"decision\":\"allow\"")
            && l.contains("\"would_deny\":true")),
        "the protected open must be allowed and flagged would_deny: {raw}"
    );
    assert!(
        raw.lines().any(|l| l.contains(&plain)
            && l.contains("\"decision\":\"allow\"")
            && !l.contains("would_deny")),
        "an unprotected open must be recorded without the flag: {raw}"
    );
    assert!(
        !raw.contains("\"decision\":\"deny\""),
        "watch denied an open: {raw}"
    );
    assert!(
        stdout.contains(&format!(
            "\"would_deny_paths\":[\"{}\"]",
            protected.display()
        )),
        "the report must suggest exactly the protected path: {stdout}"
    );
}

// WO-240@v1: a receipts directory the watched uid can write lets the agent unlink the
// evidence before the report, so watch must refuse it before the agent starts.
#[test]
#[ignore = "requires Linux + root"]
fn watch_refuses_a_receipts_dir_the_agent_could_empty() {
    const WORKER_UID: u32 = 65534;
    let fs = common::TestFs::new("wo240rm");
    let protected = fs.path("guarded");
    let marker = fs.path("agent-ran");
    let agent_dir = fs.path("agent-owned");
    fs::write(&protected, "WO240_GUARDED\n").unwrap();
    fs::create_dir(&agent_dir).unwrap();
    fs::set_permissions(
        &agent_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let c = std::ffi::CString::new(agent_dir.to_str().unwrap()).unwrap();
    let rc = unsafe { libc::chown(c.as_ptr(), WORKER_UID, WORKER_UID) };
    assert_eq!(
        rc, 0,
        "chown the receipts dir to the worker failed (needs root)"
    );
    let receipts = agent_dir.join("r.jsonl");

    let out = Command::new(bin())
        .args([
            "watch",
            "--worker-uid",
            &WORKER_UID.to_string(),
            "--protect",
        ])
        .arg(&protected)
        .arg("--receipts")
        .arg(&receipts)
        .args(["--", "sh", "-c"])
        .arg(format!(
            "touch {}; rm -f {}",
            marker.display(),
            receipts.display()
        ))
        .output()
        .expect("spawn watch");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "watch must refuse an agent-writable receipts dir; stderr: {stderr}"
    );
    assert!(
        stderr.contains("must be a root-owned directory not writable by group or others")
            && stderr.contains("nothing was run"),
        "the refusal must name the rule: {stderr}"
    );
    assert!(!marker.exists(), "the agent ran despite the refusal");
    assert!(
        !receipts.exists(),
        "receipts were written despite the refusal"
    );
}
