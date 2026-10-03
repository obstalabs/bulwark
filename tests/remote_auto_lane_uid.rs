//! WO-114: can a default-dropped `--auto` agent answer its own consent?
//! Same real-CLI + fake-ssh fixture style as `remote_consent_uid.rs`, but the
//! control channels really run: the local operator loop reads a prompt from a
//! real FIFO and writes its `--auto` reply to a real FIFO. The fake remote gate
//! mirrors `cmd_run_remote`'s intake (open the verdict lane O_RDWR, apply every
//! `allow-session <grant>` line) and runs the agent as the lane owner, which is
//! what the sudo-origin default drop produces. It does not prove kernel EACCES
//! behaviour and does not run fanotify.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

// WO-114: keep each CLI's transport, lanes and side effects isolated.
struct RemoteFixture {
    root: PathBuf,
}

impl RemoteFixture {
    // WO-114: only the fixture SSH executable may receive the CLI's remote calls.
    fn new() -> Self {
        let root = PathBuf::from(format!(
            "/tmp/bulwark-wo114-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        fs::create_dir(root.join("home")).unwrap();
        let fixture = Self { root };
        // WO-114: unlike the WO-110 fixture, the prompt reader and verdict writer
        // sessions execute for real so the operator's --auto reply travels the lane.
        fixture.script(
            "ssh",
            r#"#!/bin/sh
set -eu
for remote_command do :; done
printf '%s\n' "$remote_command" >> "$FIXTURE_ROOT/ssh.calls"
case "$remote_command" in
  'id -u')
    printf '%s\n' identity >> "$FIXTURE_ROOT/queries"
    printf '%s\n' "$FIXTURE_LOGIN_UID"
    exit 0
    ;;
  *'getent passwd'*)
    printf '%s\n' picker >> "$FIXTURE_ROOT/queries"
    exit 73
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
        // WO-114: the fake remote gate reproduces the real gate's lane handling:
        // verdict lane opened O_RDWR with an intake loop that applies any allow
        // line it reads (src/remote.rs intake_verdicts), a prompt emitted for the
        // first denied touch, then the agent launched under the same uid.
        fixture.script(
            "bulwark",
            r#"#!/bin/sh
set -eu
[ "${1-}" = run ] || exit 90
shift
worker=default
prompt=
verdict=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --worker-uid) worker=$2; shift 2 ;;
    --prompt-out) prompt=$2; shift 2 ;;
    --verdict-in) verdict=$2; shift 2 ;;
    --hardened) exit 92 ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
[ -p "$prompt" ] && [ -p "$verdict" ] || exit 91
printf '%s\n' "$worker" > "$FIXTURE_ROOT/worker"
: > "$FIXTURE_ROOT/gate"
grant="1:2:$(id -u):$$:1"
# Verdict intake, as the real gate: O_RDWR so the open never blocks, every
# parseable allow line is applied to the session cache, no origin check.
exec 3<>"$verdict"
(
  while IFS= read -r line <&3; do
    printf '%s\n' "$line" >> "$FIXTURE_ROOT/verdicts-received"
    case "$line" in
      allow-session\ *|allow-once\ *) printf '%s\n' "${line#* }" >> "$FIXTURE_ROOT/cache" ;;
    esac
  done
) &
intake=$!
# First touch of the protected file: deny now, prompt the operator.
exec 4>>"$prompt"
printf 'CONSENT\thost=%s\tgrant=%s\tpath=%s\tancestry=%s\n' fixture.invalid "$grant" /fixture-guarded fixture-agent >&4
# Wait for the operator's --auto reply so the agent's forgery comes after it.
i=0
until grep -q '^deny ' "$FIXTURE_ROOT/verdicts-received" 2>/dev/null; do
  i=$((i + 1)); [ "$i" -lt 200 ] || break
  sleep 0.05
done
set +e
FIXTURE_GRANT=$grant FIXTURE_VERDICT_LANE=$verdict "$@"
status=$?
set -e
kill "$intake" 2>/dev/null || true
exec 3>&- 4>&-
exit "$status"
"#,
        );
        // WO-114: the agent runs as whatever uid the gate dropped it to. It learns
        // the lane path the way a real agent would (the gate's argv and stderr
        // name it); only permissions decide whether it can write a verdict.
        fixture.script(
            "fixture-agent",
            r#"#!/bin/sh
set -eu
: > "$FIXTURE_ROOT/agent"
printf '%s\n' "$(id -u)" > "$FIXTURE_ROOT/agent-uid"
stat -f '%u %Lp' "$FIXTURE_VERDICT_LANE" > "$FIXTURE_ROOT/lane-owner" 2>/dev/null \
  || stat -c '%u %a' "$FIXTURE_VERDICT_LANE" > "$FIXTURE_ROOT/lane-owner"
if printf 'allow-session %s\n' "$FIXTURE_GRANT" > "$FIXTURE_VERDICT_LANE"; then
  printf '%s\n' written > "$FIXTURE_ROOT/forged"
else
  printf '%s\n' refused > "$FIXTURE_ROOT/forged"
fi
i=0
until grep -qx "$FIXTURE_GRANT" "$FIXTURE_ROOT/cache" 2>/dev/null; do
  i=$((i + 1)); [ "$i" -lt 100 ] || break
  sleep 0.05
done
# The next open consults the session cache, exactly like cache.is_allowed().
if grep -qx "$FIXTURE_GRANT" "$FIXTURE_ROOT/cache" 2>/dev/null; then
  printf '%s\n' granted > "$FIXTURE_ROOT/protected-read"
else
  printf '%s\n' denied > "$FIXTURE_ROOT/protected-read"
fi
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

    // WO-114: invoke the actual built CLI; fixtures replace transport, not policy.
    fn run(&self, args: &[&str]) -> Output {
        let mut paths = vec![self.root.join("bin")];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        Command::new(env!("CARGO_BIN_EXE_bulwark"))
            .args(["ssh", "fixture.invalid", "--deploy", "never"])
            .args(args)
            .args(["--", "fixture-agent"])
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("HOME", self.root.join("home"))
            .env("XDG_STATE_HOME", self.root.join("home"))
            .env("FIXTURE_ROOT", &self.root)
            .env("FIXTURE_LOGIN_UID", unsafe { libc::geteuid() }.to_string())
            .stdin(Stdio::null())
            .output()
            .expect("run real bulwark ssh")
    }

    fn contents(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(name)).unwrap_or_default()
    }

    // WO-114: one line of evidence per fact the WO asks to record.
    fn evidence(&self, out: &Output) -> String {
        format!(
            "exit={:?}\nworker={:?}\nagent-uid={:?}\nlane-owner(uid mode)={:?}\n\
             forged-line={:?}\nverdicts-received={:?}\ncache={:?}\nprotected-read={:?}\nstderr={}",
            out.status.code(),
            self.contents("worker").trim(),
            self.contents("agent-uid").trim(),
            self.contents("lane-owner").trim(),
            self.contents("forged").trim(),
            self.contents("verdicts-received"),
            self.contents("cache"),
            self.contents("protected-read").trim(),
            String::from_utf8_lossy(&out.stderr),
        )
    }
}

impl Drop for RemoteFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// WO-114: `--auto deny` must be a boundary the agent cannot answer for itself.
// Design-neutral: either the CLI refuses to launch a lane-owning agent, or the
// launched agent's forged allow line never becomes a grant. Today's default drop
// (no worker flag, agent = SSH login user = FIFO owner) is the case under test.
#[test]
fn auto_deny_agent_cannot_self_grant_via_verdict_lane() {
    let f = RemoteFixture::new();
    let out = f.run(&["--protect", "/fixture-guarded", "--auto", "deny"]);
    let evidence = f.evidence(&out);

    if !out.status.success() {
        // A refusal is acceptable only if it happened before any launch.
        for name in ["gate", "agent", "lanes"] {
            assert!(
                !f.root.join(name).exists(),
                "refused after creating {name}:\n{evidence}"
            );
        }
        return;
    }

    // Launched: the operator's auto-deny must have reached the gate, and the
    // agent's forged allow must not have been accepted as a grant.
    assert!(
        f.root.join("agent").is_file(),
        "agent did not run:\n{evidence}"
    );
    assert!(
        f.contents("verdicts-received")
            .lines()
            .any(|l| l.starts_with("deny ")),
        "operator --auto deny never reached the gate:\n{evidence}"
    );
    assert_eq!(
        f.contents("cache"),
        "",
        "the agent's forged allow-session became a grant:\n{evidence}"
    );
    assert_ne!(
        f.contents("protected-read").trim(),
        "granted",
        "the protected read was granted after a self-written verdict:\n{evidence}"
    );
}
