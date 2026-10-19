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
const POLL_INTERVAL: Duration = Duration::from_millis(10);
// WO-181@v1: exceed the product's 256 queued prompts after the FIFO is full.
const QUEUE_OVERFLOW_MARGIN: usize = 512;

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
