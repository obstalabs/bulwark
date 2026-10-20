//! Linux root proofs for remote prompt and verdict lane safety.

#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

const STARTUP_BOUND: Duration = Duration::from_secs(15);
const OUTSIDE_OPEN_BOUND: Duration = Duration::from_secs(2);
const DECISION_BOUND: Duration = Duration::from_secs(20);
// WO-182@v1: bound each real gate case so a blocked FIFO open cannot hang the suite.
const GATE_CASE_BOUND: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
// WO-182@v1: give the launcher time to observe closed controls before releasing the gate.
const CONTROL_EXIT_OBSERVATION_BOUND: Duration = Duration::from_millis(250);
// WO-181@v1: exceed the product's 256 queued prompts after the FIFO is full.
const QUEUE_OVERFLOW_MARGIN: usize = 512;
// WO-192@v1: bound a launcher whose fake gate refuses before opening either lane.
const EARLY_FAILURE_BOUND: Duration = Duration::from_secs(15);
// WO-192@v1: bound proof that no process retains the removed remote run directory.
const LANE_PROCESS_EXIT_BOUND: Duration = Duration::from_secs(5);

// WO-181@v1: isolate the real remote CLI and its stopped prompt reader.
struct RemoteLaneFixture {
    root: PathBuf,
    worker_uid: u32,
}

// WO-181@v1: build executable transport fixtures around the real bulwark binary.
impl RemoteLaneFixture {
    fn new() -> Self {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run this root proof with sudo"
        );
        let worker_uid = std::env::var("SUDO_UID")
            .expect("SUDO_UID must name the non-root worker for this root proof")
            .parse::<u32>()
            .expect("SUDO_UID must be numeric");
        assert_ne!(worker_uid, 0, "the worker must be non-root");

        let root = PathBuf::from(format!(
            "/var/tmp/bulwark-wo181-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("set fixture root permissions");
        fs::create_dir(root.join("bin")).expect("create fixture bin");
        fs::create_dir(root.join("home")).expect("create fixture home");
        fs::create_dir(root.join("evidence")).expect("create evidence directory");
        fs::set_permissions(root.join("evidence"), fs::Permissions::from_mode(0o700))
            .expect("set evidence permissions");
        let evidence = std::ffi::CString::new(
            root.join("evidence")
                .as_os_str()
                .as_encoded_bytes()
                .to_vec(),
        )
        .expect("evidence path has no nul");
        assert_eq!(
            unsafe { libc::chown(evidence.as_ptr(), worker_uid, worker_uid) },
            0,
            "chown evidence directory"
        );

        fs::write(root.join("protected"), b"protected\n").expect("write protected fixture");
        fs::write(root.join("unrelated"), b"outside\n").expect("write unrelated fixture");
        std::os::unix::fs::symlink(
            env!("CARGO_BIN_EXE_bulwark"),
            root.join("bin").join("bulwark"),
        )
        .expect("link bulwark under fixture PATH");

        let fixture = Self { root, worker_uid };
        fixture.script(
            "ssh",
            r#"#!/bin/sh
set -eu
# WO-181@v1: execute the final ssh argument as the fake remote command.
for remote_command do :; done
case "$remote_command" in
  'id -u')
    printf '%s\n' 0
    exit 0
    ;;
esac
# WO-181@v1: preserve the real command and lane behavior behind fake transport.
exec /bin/sh -c "$remote_command"
"#,
        );
        fixture.script(
            "sudo",
            r#"#!/bin/sh
set -eu
[ "${1-}" != -n ] || shift
# WO-181@v1: retain root for the gate, which performs the real worker drop.
exec "$@"
"#,
        );
        fixture.script(
            "mkfifo",
            r#"#!/bin/sh
set -eu
/usr/bin/mkfifo "$@"
shift 2
# WO-181@v1: expose the two real FIFO paths to the bounded test driver.
printf '%s\n%s\n' "$1" "$2" > "$FIXTURE_ROOT/lanes"
"#,
        );
        fixture.script(
            "cat",
            r#"#!/bin/sh
set -eu
case "${1-}" in
  */prompts)
    # WO-181@v1: open the FIFO, publish the pid, then stop before draining it.
    exec 3<"$1"
    printf '%s\n' "$$" > "$FIXTURE_ROOT/prompt-reader.pid"
    kill -STOP "$$"
    # WO-181@v1: drain only if teardown resumes this stopped fixture process.
    exec /bin/cat <&3
    ;;
esac
# WO-181@v1: preserve ordinary cat calls made by the remote shell.
exec /bin/cat "$@"
"#,
        );
        fixture.script(
            "lane-agent",
            r#"#!/bin/sh
set -eu
# WO-181@v1: wait for the test to measure the live FIFO before opening files.
i=0
while [ ! -f "$FIXTURE_ROOT/start-agent" ]; do
  i=$((i + 1))
  [ "$i" -lt 1500 ] || exit 70
  sleep 0.01
done
# WO-181@v1: make more protected opens than the stopped FIFO can retain.
attempts=$(cat "$FIXTURE_ROOT/attempts")
fill_attempts=$(cat "$FIXTURE_ROOT/fill-attempts")
# WO-181@v1: retain real allow and deny outcomes for non-vacuous assertions.
i=0
denied=0
allowed=0
printf '%s\n' started > "$FIXTURE_ROOT/evidence/agent-started"
while [ "$i" -lt "$attempts" ]; do
  if ( : < "$FIXTURE_ROOT/protected" ) 2>/dev/null; then
    allowed=$((allowed + 1))
  else
    denied=$((denied + 1))
  fi
  i=$((i + 1))
  if [ "$i" -eq "$fill_attempts" ]; then
    printf '%s\n' loaded > "$FIXTURE_ROOT/evidence/pipe-loaded"
  fi
done
printf '%s\n' "$allowed" > "$FIXTURE_ROOT/evidence/allowed"
printf '%s\n' "$denied" > "$FIXTURE_ROOT/evidence/denied"
# WO-181@v1: completion proves every permission decision returned to the agent.
printf '%s\n' done > "$FIXTURE_ROOT/evidence/agent-done"
"#,
        );
        fixture
    }

    // WO-181@v1: install executable fixture programs without replacing policy code.
    fn script(&self, name: &str, contents: &str) {
        let path = self.root.join("bin").join(name);
        fs::write(&path, contents).expect("write fixture script");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("make fixture script executable");
    }

    // WO-181@v1: launch the actual ssh command in a group the test can always reap.
    fn spawn(&self) -> RunningCli {
        let stdout = File::create(self.root.join("stdout")).expect("create stdout capture");
        let stderr = File::create(self.root.join("stderr")).expect("create stderr capture");
        let mut paths = vec![self.root.join("bin")];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").expect("PATH is set"),
        ));
        let child = Command::new(env!("CARGO_BIN_EXE_bulwark"))
            .args(["ssh", "fixture.invalid", "--deploy", "never"])
            .args(["--worker-uid", &self.worker_uid.to_string()])
            .arg("--state")
            .arg(self.root.join("state.toml"))
            .arg("--protect")
            .arg(self.root.join("protected"))
            .args(["--auto", "deny", "--"])
            .arg(self.root.join("bin").join("lane-agent"))
            .env(
                "PATH",
                std::env::join_paths(paths).expect("join fixture PATH"),
            )
            .env("HOME", self.root.join("home"))
            .env("XDG_STATE_HOME", self.root.join("home"))
            .env("FIXTURE_ROOT", &self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .process_group(0)
            .spawn()
            .expect("spawn real bulwark ssh");
        RunningCli::new(child)
    }

    // WO-181@v1: read fixture evidence only after the producing process exits.
    fn contents(&self, relative: &str) -> String {
        fs::read_to_string(self.root.join(relative)).unwrap_or_default()
    }
}

// WO-181@v1: remove the isolated remote fixture after its process group is gone.
impl Drop for RemoteLaneFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// WO-181@v1: own cleanup for every timeout and assertion path in the root proof.
struct RunningCli {
    child: Option<Child>,
    process_group: i32,
}

// WO-181@v1: bound CLI completion while retaining a fail-safe process-group kill.
impl RunningCli {
    fn new(child: Child) -> Self {
        let process_group = child.id() as i32;
        Self {
            child: Some(child),
            process_group,
        }
    }

    fn wait(&mut self, bound: Duration) -> ExitStatus {
        let deadline = Instant::now() + bound;
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .expect("child exists while waiting")
                .try_wait()
                .expect("poll bulwark ssh")
            {
                self.child.take();
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "remote decisions did not finish within {bound:?}"
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    // WO-182@v1: observe a premature launcher exit without surrendering cleanup ownership.
    fn try_wait(&mut self) -> Option<ExitStatus> {
        let status = self
            .child
            .as_mut()
            .expect("child exists while polling")
            .try_wait()
            .expect("poll bulwark ssh");
        if status.is_some() {
            self.child.take();
        }
        status
    }
}

// WO-181@v1: resume and terminate every fake remote process before fixture removal.
impl Drop for RunningCli {
    fn drop(&mut self) {
        unsafe {
            libc::kill(-self.process_group, libc::SIGCONT);
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.wait();
        }
    }
}

// WO-181@v1: wait on an observable event with a named bound, never a proof sleep.
fn wait_for_file(path: &Path, bound: Duration, description: &str) {
    let deadline = Instant::now() + bound;
    while !path.is_file() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description}: {}",
            path.display()
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

// WO-181@v1: prove the fixture reader reached a kernel-stopped state before load.
fn wait_for_stopped(pid: i32, bound: Duration) {
    let status_path = PathBuf::from(format!("/proc/{pid}/status"));
    let deadline = Instant::now() + bound;
    loop {
        let status = fs::read_to_string(&status_path).unwrap_or_default();
        if status
            .lines()
            .any(|line| line.starts_with("State:") && line.contains("(stopped)"))
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "prompt reader {pid} did not stop"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

// WO-181@v1: derive load from the live FIFO capacity rather than a guessed count.
fn pipe_capacity(path: &Path) -> usize {
    let fifo = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .expect("open prompt FIFO for capacity query");
    let capacity = unsafe { libc::fcntl(fifo.as_raw_fd(), libc::F_GETPIPE_SZ) };
    assert!(capacity > 0, "F_GETPIPE_SZ failed");
    capacity as usize
}

// WO-181@v1: a stopped prompt reader must never hold remote permission decisions.
#[test]
#[ignore = "requires root and Linux fanotify"]
fn stopped_prompt_reader_never_blocks_remote_decisions() {
    let fixture = RemoteLaneFixture::new();
    let mut cli = fixture.spawn();

    wait_for_file(&fixture.root.join("lanes"), STARTUP_BOUND, "lane creation");
    wait_for_file(
        &fixture.root.join("prompt-reader.pid"),
        STARTUP_BOUND,
        "prompt reader",
    );
    let prompt_pid = fixture
        .contents("prompt-reader.pid")
        .trim()
        .parse::<i32>()
        .expect("prompt reader pid");
    wait_for_stopped(prompt_pid, STARTUP_BOUND);

    let prompt_lane = PathBuf::from(
        fixture
            .contents("lanes")
            .lines()
            .next()
            .expect("prompt lane path"),
    );
    let capacity = pipe_capacity(&prompt_lane);
    let minimum_line_bytes = "CONSENT\thost=fixture.invalid\tgrant=0:0:0:0:0\tpath=\tancestry=\n"
        .len()
        + fixture.root.join("protected").as_os_str().len();
    let fill_attempts = capacity / minimum_line_bytes + 2;
    let attempts = fill_attempts + QUEUE_OVERFLOW_MARGIN;
    assert!(
        fill_attempts * minimum_line_bytes > capacity,
        "attempts must exceed the FIFO's prompt capacity"
    );
    fs::write(fixture.root.join("attempts"), attempts.to_string()).expect("write attempt count");
    fs::write(
        fixture.root.join("fill-attempts"),
        fill_attempts.to_string(),
    )
    .expect("write FIFO fill count");
    fs::write(fixture.root.join("start-agent"), b"start\n").expect("start agent");
    wait_for_file(
        &fixture.root.join("evidence/agent-started"),
        STARTUP_BOUND,
        "agent start",
    );
    wait_for_file(
        &fixture.root.join("evidence/pipe-loaded"),
        DECISION_BOUND,
        "filled prompt FIFO",
    );

    let unrelated = fixture.root.join("unrelated");
    let (opened_tx, opened_rx) = std::sync::mpsc::sync_channel(1);
    let opener = std::thread::spawn(move || {
        opened_tx.send(fs::read_to_string(unrelated)).unwrap();
    });
    let outside = opened_rx
        .recv_timeout(OUTSIDE_OPEN_BOUND)
        .expect("an unrelated open on the marked filesystem must complete")
        .expect("read unrelated fixture");
    assert_eq!(outside, "outside\n");
    opener.join().expect("join unrelated opener");

    let status = cli.wait(DECISION_BOUND);
    let stderr = fixture.contents("stderr");
    assert!(status.success(), "remote CLI failed: {status}\n{stderr}");
    assert_eq!(
        fixture.contents("evidence/allowed").trim(),
        "0",
        "a protected open was unexpectedly allowed\n{stderr}"
    );
    assert_eq!(
        fixture.contents("evidence/denied").trim(),
        attempts.to_string(),
        "not every protected open returned a deny\n{stderr}"
    );
    assert_eq!(fixture.contents("evidence/agent-done").trim(), "done");
    assert!(
        stderr.contains("prompt line(s) dropped"),
        "queue overflow was not reported\n{stderr}"
    );
}

// WO-182@v1: enumerate the only lane shapes the gate-side root proof plants.
#[derive(Clone, Copy)]
enum LaneShape {
    Fifo,
    Regular,
    Symlink,
}

// WO-182@v1: isolate direct remote-gate invocations from launcher transport.
struct GateLaneFixture {
    root: PathBuf,
    worker_uid: u32,
}

// WO-182@v1: exercise the real CLI against attacker-controlled lane entries.
impl GateLaneFixture {
    fn new() -> Self {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run this root proof with sudo"
        );
        let worker_uid = std::env::var("SUDO_UID")
            .expect("SUDO_UID must name the non-root worker for this root proof")
            .parse::<u32>()
            .expect("SUDO_UID must be numeric");
        assert_ne!(worker_uid, 0, "the worker must be non-root");

        let root = PathBuf::from(format!(
            "/var/tmp/bulwark-wo182-gate-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create gate fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("set gate fixture permissions");
        fs::write(root.join("protected"), b"protected\n").expect("write protected fixture");
        Self { root, worker_uid }
    }

    // WO-182@v1: create a FIFO, regular file, or symlink without shared setup races.
    fn plant_lane(&self, path: &Path, shape: LaneShape) -> Option<PathBuf> {
        match shape {
            LaneShape::Fifo => {
                let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes().to_vec())
                    .expect("lane path has no nul");
                assert_eq!(
                    unsafe { libc::mkfifo(path.as_ptr(), 0o600) },
                    0,
                    "create lane FIFO"
                );
                None
            }
            LaneShape::Regular => {
                fs::write(path, b"sentinel\n").expect("write regular lane");
                Some(path.to_path_buf())
            }
            LaneShape::Symlink => {
                let target = path.with_extension("target");
                fs::write(&target, b"sentinel\n").expect("write symlink target");
                std::os::unix::fs::symlink(&target, path).expect("plant lane symlink");
                Some(target)
            }
        }
    }

    // WO-182@v1: run one lane pair through the actual remote-gate command path.
    fn run_case(
        &self,
        tag: &str,
        prompt_shape: LaneShape,
        verdict_shape: LaneShape,
    ) -> (std::process::Output, bool, Vec<(PathBuf, Vec<u8>)>) {
        let case = self.root.join(tag);
        let evidence = case.join("evidence");
        fs::create_dir(&case).expect("create lane case");
        fs::set_permissions(&case, fs::Permissions::from_mode(0o711))
            .expect("set lane case permissions");
        fs::create_dir(&evidence).expect("create lane evidence");
        fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700))
            .expect("make lane evidence writable by the worker");
        let evidence_path =
            std::ffi::CString::new(evidence.as_os_str().as_encoded_bytes().to_vec())
                .expect("evidence path has no nul");
        assert_eq!(
            unsafe { libc::chown(evidence_path.as_ptr(), self.worker_uid, self.worker_uid) },
            0,
            "chown lane evidence directory"
        );

        let prompt = case.join("prompts");
        let verdict = case.join("verdicts");
        let mut sentinels = Vec::new();
        if let Some(path) = self.plant_lane(&prompt, prompt_shape) {
            sentinels.push((path, b"sentinel\n".to_vec()));
        }
        if let Some(path) = self.plant_lane(&verdict, verdict_shape) {
            sentinels.push((path, b"sentinel\n".to_vec()));
        }

        let marker = evidence.join("agent-ran");
        let agent = format!("printf '%s\\n' ran > {}", marker.display());
        let stdout_path = case.join("stdout");
        let stderr_path = case.join("stderr");
        let stdout = File::create(&stdout_path).expect("create gate stdout capture");
        let stderr = File::create(&stderr_path).expect("create gate stderr capture");
        let child = Command::new(env!("CARGO_BIN_EXE_bulwark"))
            .args([
                "run",
                "--consent",
                "remote",
                "--host-label",
                "fixture.invalid",
            ])
            .arg("--prompt-out")
            .arg(&prompt)
            .arg("--verdict-in")
            .arg(&verdict)
            .arg("--state")
            .arg(case.join("state.toml"))
            .args(["--worker-uid", &self.worker_uid.to_string()])
            .arg("--protect")
            .arg(self.root.join("protected"))
            .args(["--", "/bin/sh", "-c", &agent])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .process_group(0)
            .spawn()
            .expect("spawn real remote gate");
        // WO-182@v1: the shared guard kills and reaps the whole gate process group on timeout.
        let mut gate = RunningCli::new(child);
        let status = gate.wait(GATE_CASE_BOUND);
        let output = std::process::Output {
            status,
            stdout: fs::read(stdout_path).expect("read gate stdout capture"),
            stderr: fs::read(stderr_path).expect("read gate stderr capture"),
        };
        (output, marker.is_file(), sentinels)
    }
}

// WO-182@v1: remove direct gate artifacts after every success and refusal.
impl Drop for GateLaneFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// WO-182@v1: refuse planted lane objects and preserve their target bytes.
#[test]
#[ignore = "requires root and Linux fanotify"]
fn remote_gate_refuses_symlink_and_regular_lanes() {
    let fixture = GateLaneFixture::new();
    let cases = [
        (
            "prompt-symlink",
            LaneShape::Symlink,
            LaneShape::Fifo,
            "cannot open existing prompt FIFO without following links",
        ),
        (
            "prompt-regular",
            LaneShape::Regular,
            LaneShape::Fifo,
            "prompt lane is not a FIFO",
        ),
        (
            "verdict-symlink",
            LaneShape::Fifo,
            LaneShape::Symlink,
            "cannot open existing verdict FIFO without following links",
        ),
        (
            "verdict-regular",
            LaneShape::Fifo,
            LaneShape::Regular,
            "verdict lane is not a FIFO",
        ),
    ];

    for (tag, prompt, verdict, expected_error) in cases {
        let (output, marker, sentinels) = fixture.run_case(tag, prompt, verdict);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{tag} was accepted:\n{stderr}");
        assert!(
            stderr.contains(expected_error),
            "{tag} did not report {expected_error:?}:\n{stderr}"
        );
        assert!(!marker, "{tag} launched the agent");
        for (path, expected) in sentinels {
            assert_eq!(
                fs::read(&path).expect("read planted target"),
                expected,
                "{tag} changed {}",
                path.display()
            );
        }
    }
}

// WO-182@v1: preserve the normal two-FIFO remote gate path after validation.
#[test]
#[ignore = "requires root and Linux fanotify"]
fn remote_gate_accepts_owned_fifo_lanes() {
    let fixture = GateLaneFixture::new();
    let (output, marker, sentinels) = fixture.run_case("normal", LaneShape::Fifo, LaneShape::Fifo);
    assert!(sentinels.is_empty());
    assert!(
        output.status.success(),
        "normal FIFO lanes failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(marker, "the normal FIFO path did not run the agent");
}

// WO-182@v1: isolate a launcher whose primary channel lives but lanes stay absent.
struct MissingLaneFixture {
    root: PathBuf,
    worker_uid: u32,
}

// WO-182@v1: drive the actual launcher through bounded missing-lane control sessions.
impl MissingLaneFixture {
    fn new() -> Self {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run this root proof with sudo"
        );
        let worker_uid = std::env::var("SUDO_UID")
            .expect("SUDO_UID must name the non-root worker for this root proof")
            .parse::<u32>()
            .expect("SUDO_UID must be numeric");
        assert_ne!(worker_uid, 0, "the worker must be non-root");

        let root = PathBuf::from(format!(
            "/var/tmp/bulwark-wo182-launcher-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create launcher fixture root");
        fs::create_dir(root.join("bin")).expect("create launcher fixture bin");
        fs::create_dir(root.join("home")).expect("create launcher fixture home");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("set launcher fixture permissions");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_bulwark"), root.join("bin/bulwark"))
            .expect("link bulwark under launcher PATH");
        let hold =
            std::ffi::CString::new(root.join("hold").as_os_str().as_encoded_bytes().to_vec())
                .expect("hold path has no nul");
        assert_eq!(
            unsafe { libc::mkfifo(hold.as_ptr(), 0o600) },
            0,
            "create hold FIFO"
        );

        let fixture = Self { root, worker_uid };
        fixture.script(
            "ssh",
            r#"#!/bin/sh
set -eu
# WO-182@v1: execute the final ssh argument as the fake remote command.
for remote_command do :; done
case "$remote_command" in
  'id -u')
    printf '%s\n' 0
    exit 0
    ;;
  'mkdir -m 700 '*)
    # WO-182@v1: retain the generated run path so teardown removes it.
    remote_dir=${remote_command#mkdir -m 700 }
    /bin/sh -c "$remote_command"
    printf '%s\n' "$remote_dir" > "$FIXTURE_ROOT/remote-dir"
    exit 0
    ;;
  *'run --consent remote'*)
    printf '%s\n' started > "$FIXTURE_ROOT/primary-started"
    # WO-182@v1: keep the primary channel live until the launcher kills it.
    exec /bin/cat "$FIXTURE_ROOT/hold"
    ;;
esac
# WO-182@v1: run identity, deployment and control commands unchanged.
exec /bin/sh -c "$remote_command"
"#,
        );
        fixture
    }

    // WO-182@v1: install the fake transport without replacing launcher logic.
    fn script(&self, name: &str, contents: &str) {
        let path = self.root.join("bin").join(name);
        fs::write(&path, contents).expect("write launcher fixture script");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("make launcher fixture script executable");
    }

    // WO-182@v1: launch the real ssh command with bounded process-group cleanup.
    fn spawn(&self) -> RunningCli {
        let stdout = File::create(self.root.join("stdout")).expect("create stdout capture");
        let stderr = File::create(self.root.join("stderr")).expect("create stderr capture");
        let mut paths = vec![self.root.join("bin")];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").expect("PATH is set"),
        ));
        let marker = self.root.join("agent-ran");
        let agent = format!("printf '%s\\n' ran > {}", marker.display());
        let child = Command::new(env!("CARGO_BIN_EXE_bulwark"))
            .args(["ssh", "fixture.invalid", "--deploy", "never"])
            .args(["--worker-uid", &self.worker_uid.to_string()])
            .arg("--state")
            .arg(self.root.join("state.toml"))
            .arg("--protect")
            .arg(self.root.join("guarded"))
            .args(["--auto", "deny", "--", "/bin/sh", "-c", &agent])
            .env(
                "PATH",
                std::env::join_paths(paths).expect("join launcher PATH"),
            )
            .env("HOME", self.root.join("home"))
            .env("XDG_STATE_HOME", self.root.join("home"))
            .env("FIXTURE_ROOT", &self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .process_group(0)
            .spawn()
            .expect("spawn missing-lane launcher");
        RunningCli::new(child)
    }

    // WO-182@v1: expose launcher evidence after the bounded failure.
    fn contents(&self, relative: &str) -> String {
        fs::read_to_string(self.root.join(relative)).unwrap_or_default()
    }
}

// WO-182@v1: remove the generated remote directory and local launcher fixture.
impl Drop for MissingLaneFixture {
    fn drop(&mut self) {
        let remote_dir = self.contents("remote-dir");
        let remote_dir = PathBuf::from(remote_dir.trim());
        if remote_dir.starts_with("/tmp")
            && remote_dir
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().starts_with(b"bulwark-remote-"))
        {
            let _ = fs::remove_dir_all(remote_dir);
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

// WO-182@v1: missing remote FIFOs must fail the launcher before any agent runs.
#[test]
#[ignore = "requires Linux root for the remote launcher fixture"]
fn missing_remote_fifos_fail_the_launcher_before_agent_start() {
    let fixture = MissingLaneFixture::new();
    let mut cli = fixture.spawn();
    wait_for_file(
        &fixture.root.join("primary-started"),
        STARTUP_BOUND,
        "primary remote channel",
    );
    let status = cli.wait(DECISION_BOUND);
    let stderr = fixture.contents("stderr");

    assert!(!status.success(), "missing lanes were accepted\n{stderr}");
    assert!(
        stderr.contains("remote FIFO did not appear"),
        "bounded lane error was not reported\n{stderr}"
    );
    assert!(
        stderr.contains("lane closed before the gate"),
        "the launcher did not propagate control-session failure\n{stderr}"
    );
    assert!(
        !fixture.root.join("agent-ran").exists(),
        "the agent ran without control FIFOs"
    );
}

// WO-182@v1: a completed gate owns the result when its control lanes close first.
#[test]
#[ignore = "requires Linux root for the remote launcher fixture"]
fn finished_remote_gate_is_not_reported_as_a_lane_failure() {
    let fixture = MissingLaneFixture::new();
    fixture.script(
        "ssh",
        r#"#!/bin/sh
set -eu
# WO-182@v1: execute the final ssh argument as the fake remote command.
for remote_command do :; done
case "$remote_command" in
  'id -u')
    printf '%s\n' 0
    exit 0
    ;;
  'mkdir -m 700 '*)
    # WO-182@v1: retain the generated run path so teardown removes it.
    remote_dir=${remote_command#mkdir -m 700 }
    /bin/sh -c "$remote_command"
    printf '%s\n' "$remote_dir" > "$FIXTURE_ROOT/remote-dir"
    exit 0
    ;;
  *'run --consent remote'*)
    printf '%s\n' started > "$FIXTURE_ROOT/primary-started"
    # WO-182@v1: let both controls close before the primary reports normal completion.
    i=0
    while [ ! -f "$FIXTURE_ROOT/release-gate" ]; do
      i=$((i + 1))
      [ "$i" -lt 1500 ] || exit 70
      sleep 0.01
    done
    exit 0
    ;;
  */prompts*)
    # WO-182@v1: model prompt EOF immediately before normal gate completion.
    printf '%s\n' closed > "$FIXTURE_ROOT/prompt-closed"
    exit 0
    ;;
  */verdicts*)
    # WO-182@v1: model the verdict writer's broken-pipe exit at normal teardown.
    printf '%s\n' closed > "$FIXTURE_ROOT/verdict-closed"
    exit 1
    ;;
esac
# WO-182@v1: preserve identity and deployment commands outside the control proof.
exec /bin/sh -c "$remote_command"
"#,
    );

    let mut cli = fixture.spawn();
    wait_for_file(
        &fixture.root.join("primary-started"),
        STARTUP_BOUND,
        "primary remote channel",
    );
    wait_for_file(
        &fixture.root.join("prompt-closed"),
        STARTUP_BOUND,
        "closed prompt control",
    );
    wait_for_file(
        &fixture.root.join("verdict-closed"),
        STARTUP_BOUND,
        "closed verdict control",
    );

    let observation_deadline = Instant::now() + CONTROL_EXIT_OBSERVATION_BOUND;
    let mut early_status = None;
    while Instant::now() < observation_deadline {
        if let Some(status) = cli.try_wait() {
            early_status = Some(status);
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    if early_status.is_none() {
        fs::write(fixture.root.join("release-gate"), b"release\n").expect("release gate");
    }
    let status = early_status.unwrap_or_else(|| cli.wait(DECISION_BOUND));
    let stderr = fixture.contents("stderr");

    assert!(
        status.success(),
        "normal gate completion failed: {status}\n{stderr}"
    );
    assert!(
        !stderr.contains("lane closed before the gate"),
        "normal gate completion was misreported as a lane failure\n{stderr}"
    );
}

// WO-192@v1: run every remote command locally while the fake gate refuses unopened FIFOs.
struct EarlyExitLaneFixture {
    root: PathBuf,
    worker_uid: u32,
}

// WO-192@v1: expose blocked control opens without intercepting generated SSH commands.
impl EarlyExitLaneFixture {
    fn new() -> Self {
        let login_uid = unsafe { libc::geteuid() };
        let worker_uid = login_uid
            .checked_add(1)
            .expect("fixture login uid must leave room for a distinct worker");
        let root = PathBuf::from(format!(
            "/var/tmp/bulwark-wo192-lanes-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create early-exit fixture root");
        fs::create_dir(root.join("bin")).expect("create early-exit fixture bin");
        fs::create_dir(root.join("home")).expect("create early-exit fixture home");
        fs::write(root.join("guarded"), b"guarded\n").expect("write protected fixture");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_bulwark"), root.join("bin/bulwark"))
            .expect("link bulwark under early-exit PATH");

        let fixture = Self { root, worker_uid };
        fixture.script(
            "ssh",
            r#"#!/bin/sh
set -eu
# WO-192@v1: execute every generated remote command instead of matching a prefix.
for remote_command do :; done
exec /bin/sh -c "$remote_command"
"#,
        );
        fixture.script(
            "sudo",
            r#"#!/bin/sh
set -eu
[ "${1-}" != -n ] || shift
case " $* " in
  *' --prompt-out '*)
    prompt=
    verdict=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --prompt-out)
          shift
          prompt=${1-}
          ;;
        --verdict-in)
          shift
          verdict=${1-}
          ;;
      esac
      shift
    done
    [ -n "$prompt" ] && [ -n "$verdict" ] || exit 72
    [ -p "$prompt" ] && [ -p "$verdict" ] || exit 73
    # WO-192@v1: prove both control sessions reached their blocking FIFO opens.
    control_block_attempts=200
    control_block_interval=0.05
    prompt_cmd=$(printf 'cat\n%s' "$prompt")
    verdict_cmd=$(printf 'dd\nbs=1\nof=%s\nconv=nocreat\nstatus=none' "$verdict")
    controls_blocked=
    attempt=0
    while [ "$attempt" -lt "$control_block_attempts" ]; do
      prompt_blocked=
      verdict_blocked=
      for proc_dir in /proc/[0-9]*; do
        [ -r "$proc_dir/cmdline" ] && [ -r "$proc_dir/wchan" ] || continue
        cmdline=$(/usr/bin/tr '\000' '\n' < "$proc_dir/cmdline" 2>/dev/null) || continue
        wchan=$(cat "$proc_dir/wchan" 2>/dev/null) || continue
        [ "$wchan" = wait_for_partner ] || continue
        if [ "$cmdline" = "$prompt_cmd" ]; then
          prompt_blocked=1
        fi
        if [ "$cmdline" = "$verdict_cmd" ]; then
          verdict_blocked=1
        fi
      done
      if [ -n "$prompt_blocked" ] && [ -n "$verdict_blocked" ]; then
        controls_blocked=1
        break
      fi
      attempt=$((attempt + 1))
      sleep "$control_block_interval"
    done
    if [ -z "$controls_blocked" ]; then
      printf '%s\n' controls-not-blocked > "$FIXTURE_ROOT/gate-checked"
      exit 75
    fi
    printf '%s\n' blocked > "$FIXTURE_ROOT/gate-checked"
    # WO-192@v1: refuse without opening a lane, reproducing early remote failure.
    exit 71
    ;;
esac
# WO-192@v1: preserve cleanup and deployment commands outside the fake gate.
exec "$@"
"#,
        );
        fixture.script(
            "mkfifo",
            r#"#!/bin/sh
set -eu
/usr/bin/mkfifo "$@"
shift 2
# WO-192@v1: publish the exact real FIFO paths for process-reference checks.
printf '%s\n%s\n' "$1" "$2" > "$FIXTURE_ROOT/lanes"
"#,
        );
        fixture
    }

    // WO-192@v1: install executable transport fixtures without replacing launcher logic.
    fn script(&self, name: &str, contents: &str) {
        let path = self.root.join("bin").join(name);
        fs::write(&path, contents).expect("write early-exit fixture script");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("make early-exit fixture script executable");
    }

    // WO-192@v1: keep the whole local transport tree in one killable process group.
    fn spawn(&self) -> RunningCli {
        let stdout = File::create(self.root.join("stdout")).expect("create stdout capture");
        let stderr = File::create(self.root.join("stderr")).expect("create stderr capture");
        let mut paths = vec![self.root.join("bin")];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").expect("PATH is set"),
        ));
        let child = Command::new(env!("CARGO_BIN_EXE_bulwark"))
            .args(["ssh", "fixture.invalid", "--deploy", "never"])
            .args(["--worker-uid", &self.worker_uid.to_string()])
            .arg("--state")
            .arg(self.root.join("state.toml"))
            .arg("--protect")
            .arg(self.root.join("guarded"))
            .args(["--auto", "deny", "--", "/bin/true"])
            .env(
                "PATH",
                std::env::join_paths(paths).expect("join early-exit fixture PATH"),
            )
            .env("HOME", self.root.join("home"))
            .env("XDG_STATE_HOME", self.root.join("home"))
            .env("FIXTURE_ROOT", &self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .process_group(0)
            .spawn()
            .expect("spawn early-exit launcher");
        RunningCli::new(child)
    }

    // WO-192@v1: read fixture evidence after the bounded launcher exit.
    fn contents(&self, relative: &str) -> String {
        fs::read_to_string(self.root.join(relative)).unwrap_or_default()
    }

    // WO-192@v1: recover the generated run directory without predicting its token.
    fn remote_dir(&self) -> Option<PathBuf> {
        let lane = self.contents("lanes").lines().next()?.to_string();
        PathBuf::from(lane).parent().map(Path::to_path_buf)
    }
}

// WO-192@v1: remove local evidence and any safely identified generated run directory.
impl Drop for EarlyExitLaneFixture {
    fn drop(&mut self) {
        if let Some(remote_dir) = self.remote_dir() {
            if remote_dir.starts_with("/tmp")
                && remote_dir
                    .file_name()
                    .is_some_and(|name| name.as_encoded_bytes().starts_with(b"bulwark-remote-"))
            {
                let _ = fs::remove_dir_all(remote_dir);
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

// WO-192@v1: find command lines or open descriptors retaining one generated run path.
fn remote_process_references(remote_dir: &Path) -> Vec<String> {
    let needle = remote_dir.as_os_str().as_encoded_bytes();
    assert!(!needle.is_empty(), "remote run directory must not be empty");
    let mut references = Vec::new();
    for entry in fs::read_dir("/proc").expect("read /proc") {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let pid = match entry.file_name().to_string_lossy().parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        let proc_path = entry.path();
        if fs::read(proc_path.join("cmdline"))
            .is_ok_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
        {
            references.push(format!("pid {pid} command line"));
        }
        let fds = match fs::read_dir(proc_path.join("fd")) {
            Ok(fds) => fds,
            Err(_) => continue,
        };
        for fd in fds.flatten() {
            let target = match fs::read_link(fd.path()) {
                Ok(target) => target,
                Err(_) => continue,
            };
            if target
                .as_os_str()
                .as_encoded_bytes()
                .windows(needle.len())
                .any(|window| window == needle)
            {
                references.push(format!("pid {pid} fd {}", fd.file_name().to_string_lossy()));
            }
        }
    }
    references
}

// WO-192@v1: poll to a named deadline without sleeping past process exit.
fn wait_for_remote_process_release(remote_dir: &Path, bound: Duration) {
    let deadline = Instant::now() + bound;
    loop {
        let references = remote_process_references(remote_dir);
        if references.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "remote lane processes outlived cleanup for {}: {references:?}",
            remote_dir.display()
        );
        std::thread::yield_now();
    }
}

// WO-192@v1: an early gate refusal must release both blocked control-lane opens.
#[test]
fn failed_remote_run_releases_blocked_lane_processes() {
    let fixture = EarlyExitLaneFixture::new();
    let mut cli = fixture.spawn();
    wait_for_file(
        &fixture.root.join("gate-checked"),
        STARTUP_BOUND,
        "fake gate lane checks",
    );
    let status = cli.wait(EARLY_FAILURE_BOUND);
    assert!(!status.success(), "the refusing fake gate was accepted");
    let gate_checked = fixture.contents("gate-checked");
    assert_eq!(
        gate_checked.trim(),
        "blocked",
        "fake gate did not observe both blocked lane opens: {:?}",
        gate_checked.trim()
    );

    let lanes = fixture.contents("lanes");
    let lane_paths = lanes.lines().map(PathBuf::from).collect::<Vec<_>>();
    assert_eq!(lane_paths.len(), 2, "fixture did not record both lanes");
    let remote_dir = lane_paths[0].parent().expect("prompt lane parent");
    assert_eq!(lane_paths[1].parent(), Some(remote_dir));
    assert!(
        !remote_dir.exists(),
        "remote run directory survived cleanup"
    );
    wait_for_remote_process_release(remote_dir, LANE_PROCESS_EXIT_BOUND);
}
