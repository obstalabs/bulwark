//! WO-110: exercise the real CLI's remote identity boundary without SSH or root.
//! The fixture runs the generated gate shell and creates real FIFOs, but replaces
//! the privileged gate and transport. It does not prove kernel EACCES behavior.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const WORKER_UID: &str = "42002";
const PICKED_UID: &str = "62002";
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

// WO-110: keep each CLI's transport, identity replies and side effects isolated.
struct RemoteFixture {
    root: PathBuf,
    login_uid: String,
}

impl RemoteFixture {
    // WO-110: only the fixture SSH executable may receive the CLI's remote calls.
    fn new() -> Self {
        let root = PathBuf::from(format!(
            "/tmp/bulwark-wo110-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        fs::create_dir(root.join("home")).unwrap();
        // WO-110: the remote owner deliberately differs from the local identity.
        let login_uid = if unsafe { libc::geteuid() } == 42001 {
            "42003"
        } else {
            "42001"
        };
        let fixture = Self {
            root,
            login_uid: login_uid.to_string(),
        };
        fixture.script(
            "ssh",
            r#"#!/bin/sh
set -eu
for remote_command do :; done
printf '%s\n' "$remote_command" >> "$FIXTURE_ROOT/ssh.calls"
case "$remote_command" in
  'id -u')
    printf '%s\n' identity >> "$FIXTURE_ROOT/queries"
    printf '%s' "$FIXTURE_LOGIN_UID"
    exit "$FIXTURE_ID_STATUS"
    ;;
  *'getent passwd'*)
    printf '%s\n' picker >> "$FIXTURE_ROOT/queries"
    printf '%s' "$FIXTURE_PICK_UID"
    exit "$FIXTURE_PICK_STATUS"
    ;;
  'for _ in '*)
    # No gate prompts in this fixture: both control streams terminate at EOF.
    exit 0
    ;;
  *'/hivebus'*)
    : > "$FIXTURE_ROOT/key-handoff"
    exit 43
    ;;
esac
exec /bin/sh -c "$remote_command"
"#,
        );
        fixture.script(
            "sudo",
            r#"#!/bin/sh
set -eu
if [ "${1-}" = -n ]; then shift; fi
exec "$@"
"#,
        );
        fixture.script(
            "mkfifo",
            r#"#!/bin/sh
set -eu
/usr/bin/mkfifo "$@"
shift 2
printf '%s\n' "$@" > "$FIXTURE_ROOT/lanes"
"#,
        );
        fixture.script(
            "bulwark",
            r#"#!/bin/sh
set -eu
if [ "${1-}" = landlock-check ]; then
  : > "$FIXTURE_ROOT/landlock-check"
  exit 0
fi
[ "${1-}" = run ] || exit 90
shift
worker=default
prompt=
verdict=
hardened=no
while [ "$#" -gt 0 ]; do
  case "$1" in
    --worker-uid) worker=$2; shift 2 ;;
    --prompt-out) prompt=$2; shift 2 ;;
    --verdict-in) verdict=$2; shift 2 ;;
    --hardened) hardened=yes; shift ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
if [ "$hardened" = no ]; then
  [ -p "$prompt" ] && [ -p "$verdict" ] || exit 91
fi
printf '%s\n' "$worker" > "$FIXTURE_ROOT/worker"
printf '%s\n' "$hardened" > "$FIXTURE_ROOT/hardened"
: > "$FIXTURE_ROOT/gate"
"$@"
exit "$FIXTURE_AGENT_STATUS"
"#,
        );
        fixture.script(
            "fixture-agent",
            r#"#!/bin/sh
set -eu
: > "$FIXTURE_ROOT/agent"
printf '%s\n' fixture-agent-executed
"#,
        );
        fixture
    }

    fn script(&self, name: &str, contents: &str) {
        let path = self.root.join("bin").join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    // WO-110: invoke the actual built CLI; fixtures replace transport, not policy.
    fn run(&self, args: &[&str], overrides: &[(&str, &str)]) -> Output {
        let mut paths = vec![self.root.join("bin")];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bulwark"));
        cmd.args(["ssh", "fixture.invalid", "--deploy", "never"])
            .args(args)
            .args(["--", "fixture-agent"])
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("HOME", self.root.join("home"))
            .env("XDG_STATE_HOME", self.root.join("home"))
            .env("FIXTURE_ROOT", &self.root)
            .env("FIXTURE_LOGIN_UID", format!("{}\n", self.login_uid))
            .env("FIXTURE_ID_STATUS", "0")
            .env("FIXTURE_PICK_UID", format!("{PICKED_UID}\n"))
            .env("FIXTURE_PICK_STATUS", "0")
            .env("FIXTURE_AGENT_STATUS", "0")
            .stdin(Stdio::null());
        for (key, value) in overrides {
            cmd.env(key, value);
        }
        cmd.output().expect("run real bulwark ssh")
    }

    fn contents(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(name)).unwrap_or_default()
    }

    // WO-110: refusal must prevent side effects, not merely print a warning.
    fn assert_refused(&self, out: &Output, diagnostic: &str) {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "unexpected success: {stderr}");
        assert!(stderr.contains(diagnostic), "diagnostic missing: {stderr}");
        for name in ["gate", "agent", "lanes", "key-handoff"] {
            assert!(
                !self.root.join(name).exists(),
                "refusal created {name}: {stderr}"
            );
        }
        assert!(out.stdout.is_empty(), "refusal leaked agent output");
    }

    // WO-110: accepted requests must reach the agent with the selected identity.
    fn assert_launched(&self, out: &Output, worker: &str, hardened: bool) {
        assert!(
            out.status.success(),
            "launch failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(self.root.join("gate").is_file());
        assert!(self.root.join("agent").is_file());
        assert_eq!(out.stdout, b"fixture-agent-executed\n");
        assert_eq!(self.contents("worker"), format!("{worker}\n"));
        if hardened {
            assert_eq!(self.contents("hardened"), "yes\n");
            assert!(!self.root.join("lanes").exists());
            assert!(self.root.join("landlock-check").exists());
        } else {
            assert_eq!(self.contents("hardened"), "no\n");
            let lanes = self.contents("lanes");
            assert_eq!(lanes.lines().count(), 2, "both FIFOs must be created");
            for lane in lanes.lines() {
                let path = PathBuf::from(lane);
                assert!(!path.exists(), "lane not cleaned up: {lane}");
                assert!(!path.parent().unwrap().exists(), "run dir not cleaned up");
            }
        }
    }
}

impl Drop for RemoteFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// WO-110: an implicit sudo-origin worker must never enter interactive consent.
#[test]
fn refuses_missing_worker_before_launch() {
    let f = RemoteFixture::new();
    let out = f.run(&["--protect", "/fixture-secret"], &[]);
    f.assert_refused(&out, "--auto-worker-uid");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--worker-uid"));
    assert!(!f.root.join("ssh.calls").exists());
}

// WO-110: explicit root remains able to answer every lane and must be refused.
#[test]
fn refuses_explicit_root() {
    let f = RemoteFixture::new();
    let out = f.run(&["--protect", "/fixture-secret", "--worker-uid", "0"], &[]);
    f.assert_refused(&out, "--worker-uid");
}

// WO-110: compare against the remote login, not the local launching user.
#[test]
fn refuses_remote_login_uid() {
    let f = RemoteFixture::new();
    assert_ne!(f.login_uid.parse::<u32>().unwrap(), unsafe {
        libc::geteuid()
    });
    let out = f.run(
        &["--protect", "/fixture-secret", "--worker-uid", &f.login_uid],
        &[],
    );
    f.assert_refused(&out, "SSH login uid");
    assert_eq!(f.contents("queries"), "identity\n");
}

// WO-110: a valid distinct identity must survive the full CLI dispatch unchanged.
#[test]
fn distinct_worker_launches_and_cleans_lanes() {
    let f = RemoteFixture::new();
    let out = f.run(
        &["--protect", "/fixture-secret", "--worker-uid", WORKER_UID],
        &[],
    );
    f.assert_launched(&out, WORKER_UID, false);
    assert_eq!(f.contents("queries"), "identity\n");
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains(&format!("worker dropped to uid {WORKER_UID}")));
}

// WO-110: a root SSH login may launch only a separately selected non-root worker.
#[test]
fn root_login_can_launch_distinct_worker() {
    let f = RemoteFixture::new();
    let out = f.run(
        &["--protect", "/fixture-secret", "--worker-uid", WORKER_UID],
        &[("FIXTURE_LOGIN_UID", "0\n")],
    );
    f.assert_launched(&out, WORKER_UID, false);
    assert_eq!(f.contents("queries"), "identity\n");
}

// WO-110: automatic selection is explicit opt-in, still checked against the owner.
#[test]
fn auto_selected_worker_launches_unchanged() {
    let f = RemoteFixture::new();
    let out = f.run(&["--protect", "/fixture-secret", "--auto-worker-uid"], &[]);
    f.assert_launched(&out, PICKED_UID, false);
    assert_eq!(f.contents("queries"), "identity\npicker\n");
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains(&format!("worker dropped to uid {PICKED_UID}")));
}

// WO-110: the picker is not authority to reuse the lane owner's uid.
#[test]
fn refuses_auto_selected_login_uid() {
    let f = RemoteFixture::new();
    let out = f.run(
        &["--protect", "/fixture-secret", "--auto-worker-uid"],
        &[("FIXTURE_PICK_UID", &f.login_uid)],
    );
    f.assert_refused(&out, "SSH login uid");
    assert_eq!(f.contents("queries"), "identity\npicker\n");
}

// WO-110: even an unexpected root result from the picker must fail closed.
#[test]
fn refuses_auto_selected_root() {
    let f = RemoteFixture::new();
    let out = f.run(
        &["--protect", "/fixture-secret", "--auto-worker-uid"],
        &[("FIXTURE_PICK_UID", "0\n")],
    );
    f.assert_refused(&out, "--worker-uid");
}

// WO-110: stdout from a failed identity query is not trustworthy evidence.
#[test]
fn failed_identity_query_refuses_even_with_numeric_stdout() {
    let f = RemoteFixture::new();
    let out = f.run(
        &["--protect", "/fixture-secret", "--worker-uid", WORKER_UID],
        &[("FIXTURE_ID_STATUS", "255")],
    );
    f.assert_refused(&out, "SSH login uid");
    assert_eq!(f.contents("queries"), "identity\n");
}

// WO-110: successful transport without an identity cannot authorize a launch.
#[test]
fn empty_identity_query_refuses() {
    let f = RemoteFixture::new();
    let out = f.run(
        &["--protect", "/fixture-secret", "--worker-uid", WORKER_UID],
        &[("FIXTURE_LOGIN_UID", "")],
    );
    f.assert_refused(&out, "SSH login uid");
}

// WO-110: reject ambiguous, signed, nonnumeric and overflowing identity replies.
#[test]
fn malformed_identity_queries_refuse() {
    for uid in ["unknown", "42001\n42003\n", "+42001", "-1", "4294967296"] {
        let f = RemoteFixture::new();
        let out = f.run(
            &["--protect", "/fixture-secret", "--worker-uid", WORKER_UID],
            &[("FIXTURE_LOGIN_UID", uid)],
        );
        f.assert_refused(&out, "SSH login uid");
        assert_eq!(f.contents("queries"), "identity\n");
    }
}

// WO-110: automatic selection must not bypass a failed owner check.
#[test]
fn auto_worker_refuses_failed_identity_query_before_picker() {
    let f = RemoteFixture::new();
    let out = f.run(
        &["--protect", "/fixture-secret", "--auto-worker-uid"],
        &[("FIXTURE_ID_STATUS", "255")],
    );
    f.assert_refused(&out, "SSH login uid");
    assert_eq!(f.contents("queries"), "identity\n");
}

// WO-110: an unresolved picker result must not fall back to root or the login.
#[test]
fn invalid_or_failed_auto_selection_refuses() {
    for (uid, status) in [("", "0"), ("unknown", "0"), (PICKED_UID, "73")] {
        let f = RemoteFixture::new();
        let out = f.run(
            &["--protect", "/fixture-secret", "--auto-worker-uid"],
            &[("FIXTURE_PICK_UID", uid), ("FIXTURE_PICK_STATUS", status)],
        );
        f.assert_refused(&out, "worker");
        assert_eq!(f.contents("queries"), "identity\npicker\n");
    }
}

// WO-110: rejected consent must not place optional key material first.
#[test]
fn unsafe_worker_refuses_before_key_handoff() {
    let f = RemoteFixture::new();
    let out = f.run(
        &[
            "--protect",
            "/fixture-secret",
            "--worker-uid",
            &f.login_uid,
            "--hivebus-worker-seed-generate",
        ],
        &[],
    );
    f.assert_refused(&out, "SSH login uid");
}

// WO-110: non-interactive verdicts keep the existing no-worker path and no query.
#[test]
fn auto_verdict_refuses_missing_worker_before_launch() {
    // WO-114: supersedes the WO-110 line above, which the scope check pins:
    // --auto no longer keeps the no-worker path. The lane owner could write its
    // own allow verdict, so dispatch refuses before any remote call.
    let f = RemoteFixture::new();
    let out = f.run(
        &["--protect", "/fixture-secret", "--auto", "deny"],
        &[("FIXTURE_ID_STATUS", "255")],
    );
    f.assert_refused(&out, "--auto-worker-uid");
    assert!(!f.root.join("ssh.calls").exists());
}

// WO-114: --auto with worker selection now checks the picked uid against the SSH
// login uid like interactive consent; a failed identity query refuses first.
#[test]
fn auto_verdict_auto_worker_requires_identity_check() {
    let f = RemoteFixture::new();
    let out = f.run(
        &[
            "--protect",
            "/fixture-secret",
            "--auto",
            "deny",
            "--auto-worker-uid",
        ],
        &[("FIXTURE_ID_STATUS", "255")],
    );
    f.assert_refused(&out, "SSH login uid");
    assert_eq!(f.contents("queries"), "identity\n");

    let f = RemoteFixture::new();
    let out = f.run(
        &[
            "--protect",
            "/fixture-secret",
            "--auto",
            "deny",
            "--auto-worker-uid",
        ],
        &[],
    );
    f.assert_launched(&out, PICKED_UID, false);
    assert_eq!(f.contents("queries"), "identity\npicker\n");
}

// WO-110: hardened dispatch stays consent-free and never queries the login uid.
#[test]
fn hardened_launch_remains_consent_free() {
    let f = RemoteFixture::new();
    let out = f.run(
        &["--hardened", "--allow", "/usr/**"],
        &[("FIXTURE_ID_STATUS", "255")],
    );
    f.assert_launched(&out, "default", true);
    assert!(!f.root.join("queries").exists());
}

// WO-110: safe consent dispatch must preserve agent failure and lane cleanup.
#[test]
fn distinct_worker_preserves_agent_exit_status_and_cleanup() {
    let f = RemoteFixture::new();
    let out = f.run(
        &["--protect", "/fixture-secret", "--worker-uid", WORKER_UID],
        &[("FIXTURE_AGENT_STATUS", "17")],
    );
    assert_eq!(out.status.code(), Some(17));
    assert!(f.root.join("agent").is_file());
    assert_eq!(f.contents("worker"), format!("{WORKER_UID}\n"));
    let lanes = f.contents("lanes");
    assert_eq!(lanes.lines().count(), 2);
    for lane in lanes.lines() {
        assert!(!PathBuf::from(lane).parent().unwrap().exists());
    }
}
