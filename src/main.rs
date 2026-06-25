//! Bulwark — kernel-boundary file-read gate for AI agent process trees.
//!
//! Linux fanotify MVP. `main` stays thin and delegates to the internal modules.

// The Linux gate exercises the full fanotify/Landlock/socket surface. Other
// platforms compile the portable support code progressively as their gate
// backends land, so scope the dead-code allowance away from Linux only.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod allowlist;
mod audit;
mod consent;
mod deploy;
mod glob;
mod hivebus_keys;
mod integrity;
mod policy;
mod proctree;
mod protect;
mod receipt;
mod remote;

// split the platform gate behind cfg-gated modules.
// Linux uses fanotify. macOS uses Endpoint Security. Other platforms keep a
// fail-closed stub with the same public surface so the portable core builds
// without ever running a command ungated.
#[cfg(target_os = "linux")]
#[path = "gate.rs"]
mod gate;
#[cfg(target_os = "macos")]
#[path = "gate_macos.rs"]
mod gate;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[path = "gate_stub.rs"]
mod gate;

#[cfg(target_os = "linux")]
#[path = "hardened.rs"]
mod hardened;
#[cfg(not(target_os = "linux"))]
#[path = "hardened_stub.rs"]
mod hardened;

// cgroup-v2 membership attribution is a Linux-only fanotify-gate support module.
#[cfg(target_os = "linux")]
mod cgroup;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "socket.rs"]
mod socket;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[path = "socket_stub.rs"]
mod socket;

use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use allowlist::AllowList;
use consent::{CachingProvider, StaticDeny, Verdict};
use gate::GateMode;
use policy::{AgentDecision, Policy};
use protect::ProtectedSet;
use receipt::{Decision, Receipt, ReceiptLog};
use socket::SocketProvider;

/// Canonical policy file name used when creating a new file.
const POLICY_FILE: &str = "Bulwark.toml";

/// Policy epoch for the integrity record. Bumping it taints existing
/// runs as a policy change. The MVP uses a fixed epoch — a future change that
/// edits live policy will thread the real epoch through here.
const POLICY_EPOCH: u64 = 1;

/// Accepted policy file names in the current directory, in precedence order.
/// We accept both casings so `bulwark.toml` and `Bulwark.toml` both work on
/// case-sensitive filesystems (Linux); on case-insensitive ones either resolves
/// to the same file anyway.
const POLICY_FILE_CANDIDATES: &[&str] = &["Bulwark.toml", "bulwark.toml"];

/// environment variable that points at the signed macOS ES edge binary.
#[cfg(target_os = "macos")]
const MACOS_ES_GATE_ENV: &str = "BULWARK_MACOS_ES_GATE";

/// the bundled ES gate is built for macOS 11.0 or newer.
#[cfg(target_os = "macos")]
const MACOS_MIN_MAJOR: u64 = 11;
#[cfg(target_os = "macos")]
const MACOS_MIN_VERSION: &str = "11.0";

/// Escape a string for a JSON double-quoted value (minimal rules, no
/// serde_json dependency — matches the receipt/audit writers).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Find an existing policy file in the current directory, trying both casings.
fn find_policy_file() -> Option<PathBuf> {
    POLICY_FILE_CANDIDATES
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(Path::to_path_buf)
}

/// Output format for commands that support machine-readable output. `human` is
/// the default table/text; `json` is the agent interface (one JSON object).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

/// Consent channel selection for `bulwark run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ConsentMode {
    /// Deny protected opens by default, no prompt (MVP behavior).
    Static,
    /// Ask the operator off-band over a Unix socket.
    Socket,
    /// Remote gate (used by `bulwark ssh`): a protected open is denied
    /// immediately and a prompt is emitted on the prompt lane to a local
    /// operator; the operator's allow-session reply on the verdict lane updates
    /// the cache so the next open passes. Never blocks the kernel.
    Remote,
}

#[derive(Parser)]
#[command(
    name = "bulwark",
    version,
    about = "Kernel-boundary file-read gate for AI agent process trees (Linux fanotify MVP)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command under the read gate. Opens of protected inodes by the
    /// supervised process tree are denied at the kernel (EPERM) before any
    /// bytes reach the reader.
    Run {
        /// Protect this path by inode (file or directory; directories are
        /// expanded to the inodes present at launch). Repeatable. Overrides
        /// any policy/profile selection.
        #[arg(long = "protect", value_name = "PATH")]
        protect: Vec<PathBuf>,

        /// Use a named built-in profile (`default`, `dev`).
        #[arg(long = "profile", value_name = "NAME")]
        profile: Option<String>,

        /// Load policy from a Bulwark.toml file.
        #[arg(long = "policy", value_name = "FILE")]
        policy: Option<PathBuf>,

        /// Append per-decision receipts to this file as JSON lines.
        #[arg(long = "receipts", value_name = "FILE")]
        receipts: Option<PathBuf>,

        /// Consent channel for protected opens: `static` (deny-by-default, no
        /// prompt — the MVP behavior) or `socket` (ask the operator off-band
        /// over a Unix socket; see `bulwark consent`).
        #[arg(long = "consent", value_name = "MODE", default_value = "static")]
        consent: ConsentMode,

        /// Path for the consent socket when `--consent socket` (default:
        /// `$XDG_RUNTIME_DIR/bulwark-consent.sock` or `/tmp/bulwark-consent.sock`).
        #[arg(long = "consent-socket", value_name = "FILE")]
        consent_socket: Option<PathBuf>,

        /// Seconds to wait for an operator decision before denying (kernel
        /// deadline safe; default 30).
        #[arg(long = "consent-timeout", value_name = "SECS", default_value = "30")]
        consent_timeout: u64,

        /// (`--consent remote`) Host label shown in prompts, so a local operator
        /// watching several remotes knows which one is asking.
        #[arg(long = "host-label", value_name = "NAME", default_value = "remote")]
        host_label: String,

        /// (`--consent remote`) Prompt lane: file the remote gate appends
        /// consent prompts to (the local side tails it).
        #[arg(long = "prompt-out", value_name = "FILE")]
        prompt_out: Option<PathBuf>,

        /// (`--consent remote`) Verdict lane: file the remote gate reads operator
        /// allow-session replies from (the local side appends to it).
        #[arg(long = "verdict-in", value_name = "FILE")]
        verdict_in: Option<PathBuf>,

        /// Default-deny allowlist mode (for CI/CD, non-interactive): the agent
        /// may read ONLY `--allow` paths plus the runtime base set; every other
        /// read is denied with no prompt. See `bulwark base-set` for what the
        /// base set permits. Mutually exclusive with `--protect`/policy modes.
        #[arg(long = "deny-all")]
        deny_all: bool,

        /// In `--deny-all` mode, a path glob the agent is permitted to read.
        /// Repeatable. e.g. `--allow '/var/log/clickhouse/**'`.
        #[arg(long = "allow", value_name = "GLOB")]
        allow: Vec<String>,

        /// In `--deny-all` mode, drop the runtime base set (only for a static
        /// binary that needs nothing but its grants — the agent will usually
        /// fail to start without the base set).
        #[arg(long = "no-base-set")]
        no_base_set: bool,

        /// Hardened mode: enforce the allowlist as a kernel-level Landlock floor
        /// instead of via the fanotify supervisor. Crash-safe — the restriction
        /// lives in the kernel on the agent itself, so there is no supervisor to
        /// kill and `SIGKILL`/crash cannot widen access. Non-interactive; uses
        /// the same `--allow` grants + runtime base set as `--deny-all`. Requires
        /// Landlock (Linux 5.13+).
        #[arg(long = "hardened")]
        hardened: bool,

        /// drop the supervised agent to this unprivileged uid before it
        /// runs. The supervisor (the gate) stays root and keeps the fanotify fd,
        /// so an unprivileged agent cannot `SIGKILL` it and force the kernel's
        /// fail-open-on-death residual. The account must already exist. Refused
        /// for uid 0 and when not run as root.
        #[arg(long = "worker-uid", value_name = "UID")]
        worker_uid: Option<u32>,

        /// primary gid for `--worker-uid` (defaults to the uid). Requires
        /// `--worker-uid`.
        #[arg(long = "worker-gid", value_name = "GID")]
        worker_gid: Option<u32>,

        /// Keep the supervised agent running as root (uid 0). A root agent with
        /// `CAP_SYS_ADMIN` can migrate out of the cgroup scope (remount cgroupfs)
        /// and evade the deny-list/allow-list read gate, so by default Bulwark
        /// auto-drops a would-be-root agent to the invoking user (`SUDO_UID`) when
        /// it can. Pass `--allow-root` to opt out and keep uid 0 — only safe for a
        /// trusted agent. `--hardened` does not need this (Landlock binds the
        /// process regardless of uid).
        #[arg(long = "allow-root")]
        allow_root: bool,

        /// Path to the integrity state file (circuit-breaker). Defaults to
        /// `/var/lib/bulwark/state.toml`. Hidden — primarily for tests.
        #[arg(long = "state", value_name = "FILE", hide = true)]
        state: Option<PathBuf>,

        /// Command (and arguments) to run, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Launch a named agent from Bulwark.toml. Refuses to guess policy: no
    /// config and unknown agents fail closed with an explicit init hint.
    Launch {
        /// Agent profile name from [agents.<name>].
        agent: String,

        /// Add a starter [agents.<agent>] profile and exit without launching.
        #[arg(long = "init")]
        init: bool,

        /// Load launch policy from a Bulwark.toml file.
        #[arg(long = "policy", value_name = "FILE")]
        policy: Option<PathBuf>,

        /// Append per-decision receipts to this file as JSON lines. If omitted
        /// and the agent profile has `audit = true`, writes bulwark-audit.jsonl.
        #[arg(long = "receipts", value_name = "FILE")]
        receipts: Option<PathBuf>,

        /// Path for the consent socket when the agent has `decision = "ask"`.
        #[arg(long = "consent-socket", value_name = "FILE")]
        consent_socket: Option<PathBuf>,

        /// Seconds to wait for an operator decision before denying.
        #[arg(long = "consent-timeout", value_name = "SECS", default_value = "30")]
        consent_timeout: u64,

        /// Path to the integrity state file. Hidden — primarily for tests.
        #[arg(long = "state", value_name = "FILE", hide = true)]
        state: Option<PathBuf>,
    },

    /// Clear the integrity taint marker after an unclean restart or object
    /// drift, once you have reviewed the audit event. This is the
    /// explicit operator acknowledgement: a tainted gate keeps re-prompting (or
    /// denying) until you run this. Narrow by design — it clears only the taint
    /// marker, nothing else.
    Reset {
        /// Path to the integrity state file. Defaults to
        /// `/var/lib/bulwark/state.toml`.
        #[arg(long = "state", value_name = "FILE")]
        state: Option<PathBuf>,
    },

    /// Print the runtime base set: the read paths allowed in `--deny-all` mode
    /// so a program can execute (linker, libc, locale, ...). These are allowed
    /// reads — inspect them to understand exactly what allowlist mode permits.
    BaseSet,

    /// Probe whether this kernel supports Landlock (needed for `--hardened`).
    /// Exits 0 if available, 1 if not. Used as a remote preflight by
    /// `bulwark ssh --hardened` so a host that cannot harden fails before launch.
    LandlockCheck,

    /// Run an agent on a REMOTE host under Bulwark enforcement, with consent
    /// routed back to the local operator. Enforcement runs on the remote
    /// kernel (SSH is only transport). A protected read is denied immediately
    /// (the remote kernel deadline is met); a prompt appears locally, and your
    /// allow-session reply lets the next read through. Requires the `bulwark`
    /// binary on the remote host.
    Ssh {
        /// Remote target, `user@host`.
        target: String,

        /// Protect this path on the REMOTE host by inode (deny-list mode).
        /// Repeatable. Required unless `--hardened` (which uses `--allow`).
        #[arg(long = "protect", value_name = "PATH")]
        protect: Vec<String>,

        /// crash-safe hardened mode — apply a kernel-level Landlock read
        /// floor on the REMOTE agent (allow-list). Survives gate death (no
        /// supervisor). Non-interactive; uses `--allow` grants, not `--protect`.
        /// Requires Landlock (Linux 5.13+) on the remote — checked before launch.
        #[arg(long = "hardened")]
        hardened: bool,

        /// in `--hardened` mode, a path glob the remote agent may read.
        /// Repeatable. e.g. `--allow '/var/log/**'`.
        #[arg(long = "allow", value_name = "GLOB")]
        allow: Vec<String>,

        /// in `--hardened` mode, drop the runtime base set (rarely needed —
        /// most programs need it to start). Mirrors `bulwark run --no-base-set`.
        #[arg(long = "no-base-set")]
        no_base_set: bool,

        /// Auto-answer prompts with this verdict instead of prompting
        /// interactively (for CI / tests). e.g. `--auto allow-session`.
        #[arg(long = "auto", value_name = "VERDICT")]
        auto: Option<String>,

        /// How to obtain the `bulwark` binary on the remote host:
        /// `auto` (default — use existing, else scp the local binary when
        /// arch-compatible, else fetch the matching release), `never` (require
        /// an existing remote binary), `scp` (force pushing the local binary),
        /// or `dist` (force fetching the release tarball).
        #[arg(long = "deploy", value_name = "MODE", default_value = "auto")]
        deploy: String,

        /// relay this hivebus architect PUBLIC key (base64 ed25519, the
        /// form hivebus `--print-public-key` emits) to the remote, so the worker
        /// there can verify architect-signed messages on first contact.
        #[arg(long = "hivebus-architect-pub", value_name = "FILE")]
        hivebus_architect_pub: Option<PathBuf>,

        /// generate a fresh per-dispatch worker ed25519 seed, place it on
        /// the remote (mode 0600), and print the worker's pinnable public-key
        /// fingerprint locally so you can pin it before first contact.
        #[arg(long = "hivebus-worker-seed-generate")]
        hivebus_worker_seed_generate: bool,

        /// drop the remote agent to this unprivileged uid. The remote gate
        /// stays root (it holds the fanotify fd), so the agent cannot `SIGKILL` it
        /// and force the kernel's fail-open-on-death residual. The account must
        /// already exist on the remote host.
        #[arg(long = "worker-uid", value_name = "UID")]
        worker_uid: Option<u32>,

        /// drop the remote agent to a fresh ANONYMOUS unprivileged uid that
        /// bulwark picks on the remote (no account is created — zero setup, nothing
        /// to tear down). Same protection as `--worker-uid` without a pre-existing
        /// account. Mutually exclusive with `--worker-uid`.
        #[arg(long = "auto-worker-uid", conflicts_with = "worker_uid")]
        auto_worker_uid: bool,

        /// Command (and arguments) to run on the remote host, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Answer one pending off-band consent request (operator side). Connects to
    /// the consent socket of a running `bulwark run --consent socket`.
    Consent {
        /// Consent socket to connect to.
        #[arg(long = "socket", value_name = "FILE")]
        socket: Option<PathBuf>,
        /// Non-interactive verdict (`allow-once|allow-session|deny|deny-forever`).
        /// If omitted, prompt on stdin.
        #[arg(long = "verdict", value_name = "VERDICT")]
        verdict: Option<String>,
    },

    /// Add a protected glob to the policy file (creates it from the default
    /// profile if absent).
    Deny {
        /// Glob to protect (e.g. `~/.config/**` or `**/*token*`).
        glob: String,
        /// Policy file to mutate (default: ./Bulwark.toml).
        #[arg(long = "policy", value_name = "FILE")]
        policy: Option<PathBuf>,
    },

    /// Add a workspace-allow glob to the policy file (creates it from the
    /// default profile if absent).
    Allow {
        /// Glob to allow (e.g. `~/dev/myproject/**`).
        glob: String,
        /// Policy file to mutate (default: ./Bulwark.toml).
        #[arg(long = "policy", value_name = "FILE")]
        policy: Option<PathBuf>,
    },

    /// Render the receipt log.
    Audit {
        /// Receipts file to read (JSON lines).
        #[arg(value_name = "FILE")]
        receipts: PathBuf,
        /// Output format: `human` (table) or `json` (one object: counts +
        /// per-decision records) for agent consumption.
        #[arg(long = "format", value_name = "FMT", default_value = "human")]
        format: OutputFormat,
    },

    /// Report what the active policy decides for a path, without running
    /// anything. Useful for testing a policy: does this file get allowed,
    /// protected, or fall through to the outside-workspace default?
    Check {
        /// Absolute path to classify.
        #[arg(value_name = "PATH")]
        path: String,
        /// Use a named built-in profile (`default`, `dev`).
        #[arg(long = "profile", value_name = "NAME")]
        profile: Option<String>,
        /// Load policy from a Bulwark.toml file.
        #[arg(long = "policy", value_name = "FILE")]
        policy: Option<PathBuf>,
        /// Output format: `human` or `json` (the classification as one object).
        #[arg(long = "format", value_name = "FMT", default_value = "human")]
        format: OutputFormat,
    },

    /// Write a default `Bulwark.toml` policy in the current directory so you can
    /// edit what is protected. Idempotent: refuses to overwrite an existing file
    /// unless `--force`.
    Init {
        /// Path to write (default: `Bulwark.toml` in the current directory).
        #[arg(long = "policy", value_name = "FILE")]
        policy: Option<PathBuf>,
        /// Start from a named built-in profile (`default`, `dev`).
        #[arg(long = "profile", value_name = "NAME")]
        profile: Option<String>,
        /// Overwrite an existing policy file.
        #[arg(long = "force")]
        force: bool,
    },

    /// Preflight: check that this host can actually enforce — kernel version,
    /// root/`CAP_SYS_ADMIN` for fanotify, and Landlock for `--hardened`. Run it
    /// before relying on the gate. Exit 0 if everything required is present.
    Doctor {
        /// Output format: `human` or `json` (per-check results as one object).
        #[arg(long = "format", value_name = "FMT", default_value = "human")]
        format: OutputFormat,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run {
            protect,
            profile,
            policy,
            receipts,
            consent,
            consent_socket,
            consent_timeout,
            host_label,
            prompt_out,
            verdict_in,
            deny_all,
            allow,
            no_base_set,
            hardened,
            worker_uid,
            worker_gid,
            allow_root,
            state,
            command,
        } => {
            let code = cmd_run(RunArgs {
                protect: &protect,
                profile: profile.as_deref(),
                policy_path: policy.as_deref(),
                receipts: receipts.as_deref(),
                consent,
                consent_socket,
                consent_timeout,
                host_label,
                prompt_out,
                verdict_in,
                deny_all,
                allow: &allow,
                no_base_set,
                hardened,
                worker_uid,
                worker_gid,
                allow_root,
                state: state.as_deref(),
                command: &command,
            })?;
            exit(code);
        }
        Cmd::Reset { state } => cmd_reset(state.as_deref()),
        Cmd::Launch {
            agent,
            init,
            policy,
            receipts,
            consent_socket,
            consent_timeout,
            state,
        } => {
            let code = cmd_launch(
                &agent,
                policy.as_deref(),
                init,
                receipts.as_deref(),
                consent_socket,
                consent_timeout,
                state.as_deref(),
            )?;
            exit(code);
        }
        Cmd::Deny { glob, policy } => cmd_mutate(&glob, policy.as_deref(), Mutate::Deny),
        Cmd::Allow { glob, policy } => cmd_mutate(&glob, policy.as_deref(), Mutate::Allow),
        Cmd::Audit { receipts, format } => {
            audit::render(&receipts, matches!(format, OutputFormat::Json))?;
            Ok(())
        }
        Cmd::Check {
            path,
            profile,
            policy,
            format,
        } => cmd_check(&path, profile.as_deref(), policy.as_deref(), format),
        Cmd::Init {
            policy,
            profile,
            force,
        } => cmd_init(policy.as_deref(), profile.as_deref(), force),
        Cmd::Doctor { format } => {
            let code = cmd_doctor(format);
            exit(code);
        }
        Cmd::Consent { socket, verdict } => cmd_consent(socket, verdict.as_deref()),
        Cmd::BaseSet => {
            println!("# Bulwark runtime base set — read paths allowed in --deny-all mode");
            println!("# so a program can execute. These are ALLOWED reads.");
            for g in allowlist::RUNTIME_BASE_SET {
                println!("{g}");
            }
            Ok(())
        }
        Cmd::LandlockCheck => match hardened::abi_version() {
            Some(v) => {
                println!("landlock available (ABI v{v})");
                exit(0);
            }
            None => {
                eprintln!("landlock not available — --hardened requires Linux 5.13+");
                exit(1);
            }
        },
        Cmd::Ssh {
            target,
            protect,
            hardened,
            allow,
            no_base_set,
            auto,
            deploy,
            hivebus_architect_pub,
            hivebus_worker_seed_generate,
            worker_uid,
            auto_worker_uid,
            command,
        } => {
            let mode = deploy::DeployMode::parse(&deploy)
                .ok_or_else(|| anyhow::anyhow!("invalid --deploy mode: {deploy}"))?;
            let hivebus = HivebusDispatch {
                architect_pub: hivebus_architect_pub.as_deref(),
                worker_seed_generate: hivebus_worker_seed_generate,
            };
            let ssh = SshArgs {
                target: &target,
                protect: &protect,
                hardened,
                allow: &allow,
                no_base_set,
                auto: auto.as_deref(),
                deploy_mode: mode,
                hivebus,
                worker_uid,
                auto_worker_uid,
                command: &command,
            };
            let code = cmd_ssh(ssh)?;
            exit(code);
        }
    }
}

/// Default consent socket path: `$XDG_RUNTIME_DIR/bulwark-consent.sock`, else
/// `/tmp/bulwark-consent.sock`.
fn default_consent_socket() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("bulwark-consent.sock");
        }
    }
    PathBuf::from("/tmp/bulwark-consent.sock")
}

/// `bulwark consent` — operator side: answer one pending request.
fn cmd_consent(socket: Option<PathBuf>, verdict: Option<&str>) -> Result<()> {
    let sock = socket.unwrap_or_else(default_consent_socket);
    let v = match verdict {
        Some(s) => Some(Verdict::parse(s).with_context(|| format!("unrecognized verdict '{s}'"))?),
        None => None,
    };
    let sent = socket::answer_once(&sock, v)?;
    println!("sent: {sent}");
    Ok(())
}

/// Resolve the user's home directory (for `~/` expansion in policy globs).
fn home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
}

/// `bulwark ssh user@host --protect <paths> -- <agent>` — the local launcher.
///
/// Enforcement runs on the REMOTE kernel: this bootstraps the remote gate over
/// SSH (it does not inspect the encrypted SSH stream, which would be theatre).
/// The remote gate uses two control lanes — a prompt lane (remote → here) and a
/// verdict lane (here → remote) — kept separate from the agent's own stdio.
///
/// A protected read on the remote host is denied immediately; the prompt
/// surfaces locally, and an `allow-session` reply lets the next read through.
/// This is a prototype-grade trust channel: SSH provides transport + auth, the
/// lanes carry structured control messages, and grants are scoped per
/// identity/session/epoch (see `remote.rs`). It is NOT yet mTLS-hardened and
/// assumes the `bulwark` binary is present on the remote host.
/// Build the remote gate orchestration script. Pure (no I/O) so the inert
/// behavior is regression-locked by a unit test: the hivebus handoff is placed by
/// a SEPARATE ssh session (see `place_hivebus_material`), never woven into this
/// script — so this output does not depend on the hivebus flags at all.
/// An unguessable hex token for the remote run-directory name, so an attacker on
/// the remote host cannot predict the path (in world-writable /tmp) and
/// pre-squat the consent lanes. Reads the OS CSPRNG; on the (very unlikely)
/// failure to read it, falls back to time+pid — degraded entropy, but the gate
/// script's fail-closed `mkdir`/`mkfifo` remain the structural backstop.
fn rand_token() -> String {
    let mut buf = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if std::io::Read::read_exact(&mut f, &mut buf).is_ok() {
            return buf.iter().map(|b| format!("{b:02x}")).collect();
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}{:x}", std::process::id())
}

#[allow(clippy::too_many_arguments)]
fn build_gate_script(
    remote_dir: &str,
    prompt_lane: &str,
    verdict_lane: &str,
    remote_bin: &str,
    target: &str,
    protect_args: &str,
    worker_uid: Option<u32>,
    agent: &str,
) -> String {
    // emit `--worker-uid <uid> ` on the remote sudo line when requested.
    // Empty otherwise, so the script is byte-identical to the pre-form when
    // no worker uid is set (the inert regression test depends on this).
    let worker = match worker_uid {
        Some(uid) => format!("--worker-uid {uid} "),
        None => String::new(),
    };
    // when the agent is dropped to a (possibly anonymous) uid, give it an
    // env identity so tools that call getpwuid()/expanduser prefer the env over a
    // passwd lookup that may have no entry. `sudo env VAR=...` survives sudo's env
    // reset; the vars survive the setuid drop into the agent. Empty when no worker
    // uid, so the no-worker path stays byte-identical.
    let env_prefix = match worker_uid {
        Some(_) => format!("env HOME={remote_dir} USER=bulwark-worker LOGNAME=bulwark-worker "),
        None => String::new(),
    };
    // `mkdir {dir}` (NOT `-p`) so a pre-existing directory at the run path is a
    // hard error under `set -e` — combined with the unguessable random suffix in
    // `{dir}`, an attacker cannot pre-create the run directory to squat the
    // lanes. `mkfifo` without `2>/dev/null || true` then fails closed if the
    // verdict/prompt FIFO already exists, so the gate never adopts a FIFO it did
    // not create (which an attacker could otherwise read prompts from or write
    // forged verdicts into to self-answer the off-band consent).
    format!(
        r#"set -e
mkdir {dir}
mkfifo -m 600 {pl} {vl}
sudo {env}{bw} run --consent remote --host-label {hl} \
  --prompt-out {pl} --verdict-in {vl} \
  {worker}{protect} -- {agent}
RC=$?
rm -rf {dir}
exit $RC
"#,
        dir = remote_dir,
        pl = prompt_lane,
        vl = verdict_lane,
        env = env_prefix,
        bw = remote_bin,
        hl = shell_quote(target),
        worker = worker,
        protect = protect_args,
        agent = agent,
    )
}

/// build the remote script for `bulwark ssh --hardened`. Unlike the
/// consent script, hardened mode is non-interactive and crash-safe: the remote
/// `bulwark run --hardened` applies a Landlock floor then *becomes* the agent (no
/// supervisor, no consent lanes). So there are no FIFOs, no `--consent remote`, no
/// prompt/verdict machinery — just the floor and the agent. Pure (no I/O) so the
/// exact bytes are pinned by a unit test.
fn build_hardened_gate_script(
    remote_dir: &str,
    remote_bin: &str,
    allow_args: &str,
    no_base_set: bool,
    agent: &str,
) -> String {
    let no_base = if no_base_set { "--no-base-set " } else { "" };
    format!(
        r#"set -e
mkdir -p {dir}
sudo {bw} run --hardened {no_base}{allow} -- {agent}
RC=$?
rm -rf {dir}
exit $RC
"#,
        dir = remote_dir,
        bw = remote_bin,
        no_base = no_base,
        allow = allow_args,
        agent = agent,
    )
}

/// optional hivebus key material to carry to the remote at dispatch.
/// Both fields default-off; when neither is set, `bulwark ssh` behaves exactly as
/// before (no key handoff, byte-identical remote script).
#[derive(Clone, Copy, Default)]
struct HivebusDispatch<'a> {
    /// Local file with the architect's base64 ed25519 PUBLIC key to relay.
    architect_pub: Option<&'a Path>,
    /// Generate + place a fresh per-dispatch worker seed, print its fingerprint.
    worker_seed_generate: bool,
}

impl HivebusDispatch<'_> {
    /// True when no hivebus handoff was requested — the feature stays fully inert.
    fn is_inert(&self) -> bool {
        self.architect_pub.is_none() && !self.worker_seed_generate
    }
}

/// Arguments for `bulwark ssh`. A struct (not a long positional list) because the
/// command grew several modes — deny-list consent, hivebus handoff, worker-uid
/// drop, and the hardened floor.
struct SshArgs<'a> {
    target: &'a str,
    protect: &'a [String],
    hardened: bool,
    allow: &'a [String],
    no_base_set: bool,
    auto: Option<&'a str>,
    deploy_mode: deploy::DeployMode,
    hivebus: HivebusDispatch<'a>,
    worker_uid: Option<u32>,
    auto_worker_uid: bool,
    command: &'a [String],
}

fn cmd_ssh(args: SshArgs) -> Result<i32> {
    use std::io::{BufRead, BufReader, Write};

    let SshArgs {
        target,
        protect,
        hardened,
        allow,
        no_base_set,
        auto,
        deploy_mode,
        hivebus,
        worker_uid,
        auto_worker_uid,
        command,
    } = args;

    if command.is_empty() {
        anyhow::bail!("no command given");
    }

    // hardened is allow-list (Landlock floor); the default path is deny-list
    // (fanotify + consent). The modes are opposite — reject mixing them, and route
    // hardened to its own (consent-free, crash-safe) dispatch.
    if hardened {
        if !protect.is_empty() {
            anyhow::bail!("--hardened uses --allow grants on the remote, not --protect");
        }
        if allow.is_empty() {
            anyhow::bail!("--hardened requires at least one --allow <glob>");
        }
        reject_widening_hardened_grants(allow)?;
        return cmd_ssh_hardened(target, allow, no_base_set, deploy_mode, command);
    }
    if protect.is_empty() {
        anyhow::bail!("--protect is required (or use --hardened with --allow)");
    }

    // Make sure a runnable bulwark exists on the remote host (use existing, scp
    // the local binary when arch-compatible, or fetch the matching release).
    let remote_bin = deploy::ensure_remote_bulwark(target, deploy_mode)?;

    // A unique run dir on the remote host holds the two lane FIFOs. The name
    // carries an UNGUESSABLE random token (not just the local pid): the dir lives
    // in world-writable /tmp on the remote, so a predictable name would let a
    // local attacker pre-create the verdict FIFO and self-answer the off-band
    // consent. With a random suffix the attacker cannot pre-create the path, and
    // the gate script's `mkdir` (no -p) + `mkfifo` (no `|| true`) fail closed if
    // the path is somehow occupied.
    let run_id = std::process::id();
    let remote_dir = format!("/tmp/bulwark-remote-{run_id}-{}", rand_token());
    let prompt_lane = format!("{remote_dir}/prompts");
    let verdict_lane = format!("{remote_dir}/verdicts");

    // `--auto-worker-uid` resolves a fresh anonymous uid ON THE REMOTE and
    // flows it into the SAME path `--worker-uid` uses. No account is created, so
    // there is nothing to tear down. The explicit `--worker-uid` is unchanged.
    let worker_uid = if auto_worker_uid {
        Some(pick_remote_worker_uid(target, &remote_bin, run_id)?)
    } else {
        worker_uid
    };

    let protect_args = protect
        .iter()
        .map(|p| format!("--protect {}", shell_quote(p)))
        .collect::<Vec<_>>()
        .join(" ");
    let agent = command
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ");

    // carry hivebus key material to the remote BEFORE the gate runs the
    // agent, so the worker there has a trustworthy first key introduction. The
    // material is placed by a separate, synchronous ssh session that pipes each
    // value over stdin to `cat >` — the secret seed never appears in argv on
    // either host (no remote `bash -c '<seed>'`, no local ssh arg), satisfying the
    // contract. Returns the fingerprints for the operator print + receipt.
    let hivebus_placed = if hivebus.is_inert() {
        None
    } else {
        Some(place_hivebus_material(
            target,
            &remote_dir,
            hivebus,
            worker_uid,
        )?)
    };

    // surface the worker's pinnable fingerprint to the operator (stderr,
    // off the agent's stdout) so it can be pinned on the hivebus side BEFORE the
    // worker's first contact, and record a dispatch receipt (fingerprints only,
    // never seed bytes).
    // surface the resolved worker uid (auto-picked or explicit) so the
    // operator sees which anonymous uid the agent runs as — the auditable trace.
    if let Some(uid) = worker_uid {
        eprintln!("[bulwark] worker dropped to uid {uid} on {target}");
    }
    if hivebus_placed.is_some() || worker_uid.is_some() {
        let placed = hivebus_placed.as_ref();
        if let Some(p) = placed {
            if let Some(fp) = &p.worker_fingerprint {
                eprintln!("[bulwark] hivebus worker key fingerprint (pin this): {fp}");
            }
            if let Some(fp) = &p.architect_fingerprint {
                eprintln!("[bulwark] hivebus architect key relayed, fingerprint: {fp}");
            }
        }
        let mut receipts = ReceiptLog::new(None)?;
        receipts.record_dispatch(&receipt::DispatchReceipt {
            target,
            worker_pub_fingerprint: placed.and_then(|p| p.worker_fingerprint.as_deref()),
            architect_pub_fingerprint: placed.and_then(|p| p.architect_fingerprint.as_deref()),
            worker_uid,
        });
    }

    // The remote orchestration script is now JUST the gate: create the FIFOs,
    // run the gate (it appends prompts to the prompt lane and reads verdicts
    // from the verdict lane), clean up. The operator loop runs LOCALLY (below),
    // so prompts cross the network to this machine and verdicts cross back —
    // SSH is transport, the operator UI is local, enforcement stays remote.
    let remote_script = build_gate_script(
        &remote_dir,
        &prompt_lane,
        &verdict_lane,
        &remote_bin,
        target,
        &protect_args,
        worker_uid,
        &agent,
    );

    eprintln!("[bulwark] ssh {target}: enforcement on the REMOTE kernel; consent routed locally");

    // Primary channel: run the gate + agent. The agent's stdout/stderr flow here.
    // Its LOCAL stdin is redirected from /dev/null: with `-tt`, ssh would forward
    // the local terminal's input to the remote, which would steal the operator's
    // keystrokes from the interactive consent prompt below. The remote PTY (`-tt`)
    // is kept so remote `sudo` still has a tty; the agent simply sees EOF on stdin.
    let mut gate = std::process::Command::new("ssh")
        .arg("-tt")
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .arg(target)
        .arg(&remote_script)
        .stdin(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("cannot ssh to {target}"))?;

    // Control channels (separate ssh sessions, structured lanes — never the
    // agent's stdio):
    //  - prompt reader: `cat <prompt_fifo>` streams CONSENT lines to us.
    //  - verdict writer: `cat > <verdict_fifo>` carries our replies back.
    //
    // Each waits for its FIFO to exist before opening it: the primary channel
    // creates the FIFOs via `mkfifo`, and these control sessions can connect
    // before that runs — without the wait, `cat` would fail on a missing path,
    // the reader would die, and the gate would block forever opening the prompt
    // FIFO with no reader. The bounded wait avoids that startup race.
    let wait_for =
        |fifo: &str| format!("for _ in $(seq 1 100); do [ -p {fifo} ] && break; sleep 0.1; done");
    let mut prompt_reader = std::process::Command::new("ssh")
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .arg(target)
        .arg(format!("{}; cat {prompt_lane}", wait_for(&prompt_lane)))
        .stdout(std::process::Stdio::piped())
        // Null its stdin: an inherited stdin would make this ssh consume the
        // operator's keystrokes (ssh forwards stdin to the remote), starving the
        // interactive consent prompt. It only needs to stream the prompt lane out.
        .stdin(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("cannot open prompt lane on {target}"))?;
    // The verdict sink is a shell read-loop, NOT `cat > fifo`: coreutils `cat`
    // block-buffers its output to the FIFO, so a verdict would not reach the gate
    // until EOF (after the agent already finished). Opening the FIFO once for the
    // whole loop and `printf`-ing each line gives an unbuffered write per verdict.
    let mut verdict_writer = std::process::Command::new("ssh")
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .arg(target)
        .arg(format!(
            "{}; while IFS= read -r l; do printf '%s\\n' \"$l\"; done > {verdict_lane}",
            wait_for(&verdict_lane)
        ))
        .stdin(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot open verdict lane on {target}"))?;

    let prompt_out = prompt_reader.stdout.take().expect("piped stdout");
    let mut verdict_in = verdict_writer.stdin.take().expect("piped stdin");
    let auto = auto.map(str::to_string);

    // The LOCAL operator loop: for each prompt, decide a verdict and write it on
    // the verdict lane, echoing the scoped grant verbatim. Runs on its own thread
    // so the agent's stdio is unblocked on the primary channel.
    let operator = std::thread::spawn(move || {
        for line in BufReader::new(prompt_out).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            let fields = match remote::parse_prompt(&line) {
                Some(f) => f,
                None => continue, // not a CONSENT line
            };
            let grant = match remote::prompt_grant(&fields) {
                Some(g) => g.to_string(),
                None => continue,
            };
            // Show the request to the operator on stderr (off the agent stdout).
            eprintln!("{}", remote::render_prompt(&fields));
            let verdict = match &auto {
                // CI / non-interactive: answer every prompt the same way.
                Some(v) => Verdict::parse(v).unwrap_or(Verdict::Deny),
                // Interactive: read one decision from the local tty.
                None => prompt_local_operator(),
            };
            let reply = remote::verdict_line(verdict, &grant);
            if writeln!(verdict_in, "{reply}").is_err() {
                break;
            }
            let _ = verdict_in.flush();
        }
    });

    let status = gate.wait().context("remote gate session failed")?;

    // The gate exited (agent done): tear down the control channels.
    let _ = prompt_reader.kill();
    let _ = verdict_writer.kill();
    let _ = operator.join();

    Ok(status.code().unwrap_or(1))
}

/// `bulwark ssh --hardened` — apply a crash-safe Landlock read floor on the
/// remote agent. Non-interactive (no consent lanes, no operator relay): the remote
/// `bulwark run --hardened` installs the floor then becomes the agent, so there is
/// no supervisor to kill and gate death cannot widen access.
fn cmd_ssh_hardened(
    target: &str,
    allow: &[String],
    no_base_set: bool,
    deploy_mode: deploy::DeployMode,
    command: &[String],
) -> Result<i32> {
    // Make a runnable bulwark available on the remote first (so the preflight can
    // call it), then PREFLIGHT: the remote kernel must support Landlock, or
    // `--hardened` would silently degrade. Fail BEFORE launching the agent.
    let remote_bin = deploy::ensure_remote_bulwark(target, deploy_mode)?;
    let check = std::process::Command::new("ssh")
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .arg(target)
        .arg(format!("{} landlock-check", shell_quote(&remote_bin)))
        .status()
        .with_context(|| format!("cannot ssh to {target} for the Landlock preflight"))?;
    if !check.success() {
        anyhow::bail!(
            "remote {target} does not support Landlock (needs Linux 5.13+); \
             cannot use --hardened"
        );
    }

    let run_id = std::process::id();
    let remote_dir = format!("/tmp/bulwark-remote-{run_id}");
    let allow_args = allow
        .iter()
        .map(|g| format!("--allow {}", shell_quote(g)))
        .collect::<Vec<_>>()
        .join(" ");
    let agent = command
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ");

    let remote_script =
        build_hardened_gate_script(&remote_dir, &remote_bin, &allow_args, no_base_set, &agent);

    eprintln!(
        "[bulwark] ssh {target}: HARDENED — kernel Landlock floor on the remote agent (crash-safe)"
    );

    // No consent lanes, no operator relay: just run the floored agent and wait.
    // The agent's stdout/stderr flow on this channel; stdin is null (no operator).
    let status = std::process::Command::new("ssh")
        .arg("-tt")
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .arg(target)
        .arg(&remote_script)
        .stdin(std::process::Stdio::null())
        .status()
        .with_context(|| format!("cannot ssh to {target}"))?;

    Ok(status.code().unwrap_or(1))
}

/// Fingerprints of the hivebus material placed on a remote, for the operator
/// print + dispatch receipt. Never carries seed bytes.
struct HivebusPlaced {
    worker_fingerprint: Option<String>,
    architect_fingerprint: Option<String>,
}

/// place hivebus key material on the remote under `{remote_dir}/hivebus/`,
/// per the ownership contract: `worker.seed` mode 0600 and `architect.pub`
/// mode 0644, both owned by the gate uid (root in the MVP — the placement runs
/// under `sudo`, matching the gate that later reads them).
///
/// Each value is streamed over the placement ssh session's STDIN to `cat >`, so
/// the secret seed never appears in argv on the local host (ssh args) or the
/// remote host (no `bash -c '<seed>'`). The fresh worker seed is generated here
/// and dropped as soon as it is written — only fingerprints are returned.
fn place_hivebus_material(
    target: &str,
    remote_dir: &str,
    hivebus: HivebusDispatch,
    worker_uid: Option<u32>,
) -> Result<HivebusPlaced> {
    let hb_dir = format!("{remote_dir}/hivebus");
    let seed_path = format!("{hb_dir}/worker.seed");
    let arch_path = format!("{hb_dir}/architect.pub");

    // Load + validate the architect public key locally first, so a bad key fails
    // the dispatch before we touch the remote.
    let architect = match hivebus.architect_pub {
        Some(p) => Some(hivebus_keys::ArchitectKey::load_base64_file(p)?),
        None => None,
    };
    let worker = if hivebus.worker_seed_generate {
        Some(hivebus_keys::WorkerKey::generate()?)
    } else {
        None
    };

    // One `tee` per value, each its own ssh session piping the value on stdin —
    // leak-free (no argv) and the simplest framing. The owner follows the gate:
    // root by default, or the dropped worker uid so the unprivileged agent
    // can read its OWN seed. The seed is the worker's own key — this is hygiene
    // (keep other remote users out), not secret-isolation.
    let mut worker_fingerprint = None;
    let mut architect_fingerprint = None;

    // create the hivebus dir (0700) before placing files in it. When the worker
    // is dropped to a uid, chown the dir to it so the unprivileged agent can
    // traverse in and read its seed; otherwise it stays root-owned as today.
    let chown_dir = match worker_uid {
        Some(uid) => format!(" && sudo chown {uid} {hb_dir}"),
        None => String::new(),
    };
    run_remote_quiet(
        target,
        &format!("sudo mkdir -p {hb_dir} && sudo chmod 0700 {hb_dir}{chown_dir}"),
        None,
    )
    .context("create remote hivebus dir")?;

    // architect public key (0644) — public, but still piped for a uniform path.
    if let Some(a) = &architect {
        run_remote_quiet(
            target,
            &format!("sudo tee {arch_path} >/dev/null && sudo chmod 0644 {arch_path}"),
            Some(&a.public_base64()),
        )
        .context("place architect pubkey on remote")?;
        architect_fingerprint = Some(a.fingerprint());
    }

    // worker seed (0600) — the secret. Piped over stdin, never argv. When a worker
    // uid is set, chown the seed to it (same 0600) so the dropped agent reads its
    // own key; otherwise root-owned as today (forward-compat: one chown).
    if let Some(w) = &worker {
        let chown_seed = match worker_uid {
            Some(uid) => format!(" && sudo chown {uid} {seed_path}"),
            None => String::new(),
        };
        run_remote_quiet(
            target,
            &format!("sudo tee {seed_path} >/dev/null && sudo chmod 0600 {seed_path}{chown_seed}"),
            Some(&w.seed_base64()),
        )
        .context("place worker seed on remote")?;
        worker_fingerprint = Some(w.fingerprint());
    }

    Ok(HivebusPlaced {
        worker_fingerprint,
        architect_fingerprint,
    })
}

/// Run a one-shot remote command over ssh, optionally piping `stdin_data` to it.
/// Used for hivebus placement: the data goes on STDIN so it never lands in argv.
///
/// No `-tt` here on purpose: a PTY would echo and line-process the piped base64,
/// corrupting the value written to `tee`. Placement assumes the same passwordless
/// `sudo` the gate session already requires, so no interactive tty is needed.
fn run_remote_quiet(target: &str, remote_cmd: &str, stdin_data: Option<&str>) -> Result<()> {
    use std::io::Write;
    let mut child = std::process::Command::new("ssh")
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .arg(target)
        .arg(remote_cmd)
        .stdin(if stdin_data.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("ssh {target} (hivebus placement)"))?;
    if let Some(data) = stdin_data {
        let mut stdin = child.stdin.take().expect("piped stdin");
        // Write the value + newline, then close stdin so `tee` sees EOF.
        stdin
            .write_all(data.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .context("write hivebus value to remote stdin")?;
        drop(stdin);
    }
    let status = child.wait().context("remote hivebus placement failed")?;
    if !status.success() {
        anyhow::bail!("remote hivebus placement exited {:?}", status.code());
    }
    Ok(())
}

/// Run a one-shot remote command over ssh and return its trimmed stdout. Like
/// `run_remote_quiet` but captures stdout (used to read a value back from the
/// remote, e.g. the picked uid). Errors on a non-zero remote exit.
fn run_remote_capture(target: &str, remote_cmd: &str) -> Result<String> {
    let out = std::process::Command::new("ssh")
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .arg(target)
        .arg(remote_cmd)
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("ssh {target}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "remote command on {target} exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// shell snippet that picks a free unprivileged uid on the remote. Seeds the
/// candidate from the dispatch's run id (so two concurrent dispatches start at
/// different candidates), then probes upward while the uid or gid is taken, and
/// fails (exit 73) if the 60000..64999 range is exhausted. Uses only `getent`
/// (universal) — no account is created. Pinned by a unit test.
fn remote_uid_pick_snippet(run_id: u32) -> String {
    let seed = 60000 + (run_id % 4000);
    format!(
        "n={seed}; \
         while getent passwd \"$n\" >/dev/null 2>&1 || getent group \"$n\" >/dev/null 2>&1; do \
         n=$((n+1)); \
         if [ \"$n\" -ge 65000 ]; then echo 'no free uid in 60000-64999' >&2; exit 73; fi; \
         done; \
         echo \"$n\""
    )
}

/// resolve a fresh anonymous worker uid on the remote host. Returns the
/// picked numeric uid; creates no account (nothing to tear down).
fn pick_remote_worker_uid(target: &str, _remote_bin: &str, run_id: u32) -> Result<u32> {
    let out = run_remote_capture(target, &remote_uid_pick_snippet(run_id))
        .context("pick a free worker uid on the remote")?;
    out.trim()
        .parse::<u32>()
        .map_err(|_| anyhow::anyhow!("remote returned an unexpected worker-uid value: {out:?}"))
}

/// Read one consent decision from the local controlling terminal. Defaults to
/// deny on EOF or an unrecognized key, so a closed terminal never auto-allows.
fn prompt_local_operator() -> Verdict {
    use std::io::Write;
    eprint!("[bulwark] allow this read? [a]llow-session / [d]eny (default deny): ");
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).unwrap_or(0) == 0 {
        return Verdict::Deny;
    }
    match input.trim() {
        "a" | "allow" | "allow-session" => Verdict::AllowSession,
        _ => Verdict::Deny,
    }
}

/// Single-quote a string for safe embedding in a remote shell command.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Hardened launch: apply the Landlock read floor for `allow_globs`, then exec
/// `command`. The Bulwark process is replaced by the agent, which now carries a
/// kernel-enforced restriction for its whole life — crash-safe, no supervisor.
/// Only returns on error (a successful `execvp` never returns).
fn run_hardened(allow_globs: &[String], command: &[String]) -> Result<i32> {
    if command.is_empty() {
        anyhow::bail!("no command given");
    }
    hardened::apply_read_floor(allow_globs)?;

    let prog = std::ffi::CString::new(command[0].as_bytes())?;
    let argv: Vec<std::ffi::CString> = command
        .iter()
        .map(|a| std::ffi::CString::new(a.as_bytes()))
        .collect::<std::result::Result<_, _>>()?;
    let mut argv_ptr: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptr.push(std::ptr::null());

    // SAFETY: standard execvp; on success the image is replaced and this never
    // returns. On failure we fall through to report the error.
    unsafe {
        libc::execvp(prog.as_ptr(), argv_ptr.as_ptr());
    }
    Err(anyhow::anyhow!(std::io::Error::last_os_error()))
        .with_context(|| format!("cannot exec {}", command[0]))
}

/// Enumerate the mount points of every real filesystem from `/proc/mounts`, so
/// allow-list mode can mark them all. Marking only `/` would miss separate
/// mounts (tmpfs, a data volume, network shares) and silently allow reads
/// there — fatal for a default-deny guarantee. We skip a few pseudo
/// filesystems that cannot hold a readable on-disk secret and would only add
/// event noise (`cgroup`, `devpts`, ...) but keep `proc`/`sysfs`/`tmpfs`/real
/// block and network filesystems. On any error we fall back to `/` and warn —
/// a noisy over-mark is safer than a silent gap.
fn real_mount_points() -> Vec<PathBuf> {
    const SKIP_FSTYPES: &[&str] = &[
        "cgroup",
        "cgroup2",
        "devpts",
        "mqueue",
        "hugetlbfs",
        "debugfs",
        "tracefs",
        "securityfs",
        "pstore",
        "bpf",
        "configfs",
        "fusectl",
        "binfmt_misc",
        "autofs",
    ];
    let raw = match std::fs::read_to_string("/proc/mounts") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[bulwark] WARN cannot read /proc/mounts ({e}); marking only / — other mounts will not be gated");
            return vec![PathBuf::from("/")];
        }
    };
    let mut seen = std::collections::HashSet::new();
    let mut mounts = Vec::new();
    for line in raw.lines() {
        let mut f = line.split_whitespace();
        let _dev = f.next();
        let mount_point = match f.next() {
            Some(m) => m,
            None => continue,
        };
        let fstype = f.next().unwrap_or("");
        if SKIP_FSTYPES.contains(&fstype) {
            continue;
        }
        // /proc/mounts escapes spaces as \040; un-escape for the path.
        let mount_point = mount_point.replace("\\040", " ");
        if seen.insert(mount_point.clone()) {
            mounts.push(PathBuf::from(mount_point));
        }
    }
    if mounts.is_empty() {
        mounts.push(PathBuf::from("/"));
    }
    eprintln!(
        "[bulwark] allow-list: marking {} mounted filesystem(s)",
        mounts.len()
    );
    mounts
}

/// Arguments for a `run` invocation.
struct RunArgs<'a> {
    protect: &'a [PathBuf],
    profile: Option<&'a str>,
    policy_path: Option<&'a Path>,
    receipts: Option<&'a Path>,
    consent: ConsentMode,
    consent_socket: Option<PathBuf>,
    consent_timeout: u64,
    host_label: String,
    prompt_out: Option<PathBuf>,
    verdict_in: Option<PathBuf>,
    deny_all: bool,
    allow: &'a [String],
    no_base_set: bool,
    hardened: bool,
    /// drop the supervised worker to this uid before exec (the supervisor
    /// stays root). `None` keeps the agent at the supervisor's uid (today's
    /// behavior). The paired gid, if not given explicitly, defaults to the uid.
    worker_uid: Option<u32>,
    worker_gid: Option<u32>,
    /// Keep a would-be-root agent at uid 0 instead of auto-dropping it to the
    /// invoking user. Opt-out of the safe default; only for a trusted agent.
    allow_root: bool,
    state: Option<&'a Path>,
    command: &'a [String],
}

/// owned launch plan derived from [agents.<name>] and then passed into
/// the existing run path.
#[derive(Debug)]
struct LaunchPlan {
    protect: Vec<PathBuf>, // protected paths for deny-list launches
    allow: Vec<String>,    // allow grants for default-deny launches
    consent: ConsentMode,  // configured static/socket decision channel
    deny_all: bool,        // route allow-only profiles into allow-list mode
    audit: bool,           // profile-controlled default receipt logging
    command: Vec<String>,  // resolved command vector
}

fn launch_policy_path(agent: &str, policy_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = policy_path {
        return Ok(path.to_path_buf());
    }
    find_policy_file().ok_or_else(|| {
        anyhow::anyhow!(
            "no Bulwark.toml found -- run: bulwark init\nwrites a starter policy here; then re-run: bulwark launch {agent}"
        )
    })
}

fn cmd_launch(
    agent: &str,
    policy_path: Option<&Path>,
    init: bool,
    receipts: Option<&Path>,
    consent_socket: Option<PathBuf>,
    consent_timeout: u64,
    state: Option<&Path>,
) -> Result<i32> {
    if init {
        let target = policy_path
            .map(Path::to_path_buf)
            .or_else(find_policy_file)
            .unwrap_or_else(|| PathBuf::from(POLICY_FILE));
        return cmd_launch_init(agent, &target).map(|()| 0);
    }

    let policy_path = launch_policy_path(agent, policy_path)?;
    let policy = Policy::load(&policy_path)?;
    let plan = resolve_launch_plan(agent, &policy)?;
    let default_receipts = if plan.audit && receipts.is_none() {
        Some(PathBuf::from("bulwark-audit.jsonl"))
    } else {
        None
    };
    cmd_run(RunArgs {
        protect: &plan.protect,
        profile: None,
        policy_path: None,
        receipts: receipts.or(default_receipts.as_deref()),
        consent: plan.consent,
        consent_socket,
        consent_timeout,
        host_label: "local".to_string(),
        prompt_out: None,
        verdict_in: None,
        deny_all: plan.deny_all,
        allow: &plan.allow,
        no_base_set: false,
        hardened: false,
        worker_uid: None,
        worker_gid: None,
        allow_root: false,
        state,
        command: &plan.command,
    })
}

fn cmd_launch_init(agent: &str, policy_path: &Path) -> Result<()> {
    let mut policy = if policy_path.exists() {
        Policy::load(policy_path)?
    } else {
        Policy::default_profile()
    };
    let added = policy.add_agent(agent);
    policy.save(policy_path)?;
    if added {
        println!(
            "added [agents.{agent}] to {} (review it, then run: bulwark launch {agent})",
            policy_path.display()
        );
    } else {
        println!(
            "[agents.{agent}] already exists in {}",
            policy_path.display()
        );
    }
    Ok(())
}

fn resolve_launch_plan(agent: &str, policy: &Policy) -> Result<LaunchPlan> {
    let profile = policy.agents.get(agent).ok_or_else(|| {
        anyhow::anyhow!("no agent configured for {agent}; run: bulwark launch --init {agent}")
    })?;
    if profile.command.is_empty() {
        anyhow::bail!("agent {agent} has no command configured");
    }
    if profile.protect.is_empty() && profile.allow.is_empty() {
        anyhow::bail!("agent {agent} has neither protect nor allow policy configured");
    }
    if matches!(profile.decision, AgentDecision::Allow) && !profile.protect.is_empty() {
        anyhow::bail!(
            "agent {agent} sets decision=allow with protected paths; refusing to launch unprotected"
        );
    }
    let deny_all = profile.protect.is_empty() && !profile.allow.is_empty();
    Ok(LaunchPlan {
        protect: profile.protect.iter().map(PathBuf::from).collect(),
        allow: profile.allow.clone(),
        consent: consent_mode_for_agent_decision(profile.decision),
        deny_all,
        audit: profile.audit,
        command: profile.command.clone(),
    })
}

fn consent_mode_for_agent_decision(decision: AgentDecision) -> ConsentMode {
    match decision {
        AgentDecision::Deny | AgentDecision::Allow => ConsentMode::Static,
        AgentDecision::Ask => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                ConsentMode::Socket
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                // unsupported platforms keep fail-closed launch behavior.
                ConsentMode::Static
            }
        }
    }
}

/// validate + resolve the optional `--worker-uid`/`--worker-gid` into the
/// credentials the gate drops the supervised child to. Returns `None` when no
/// worker uid was requested (the agent keeps the supervisor's uid, as before).
///
/// Refuses two foot-guns up front: dropping to uid 0 (a no-op that hides intent),
/// and requesting a drop when the supervisor is not root (it cannot drop
/// privileges it does not hold — fail loudly rather than exec un-dropped).
/// Safe default for an agent that would otherwise run as root. A uid-0 agent
/// with `CAP_SYS_ADMIN` can leave the cgroup scope by remounting cgroupfs, which
/// evades the deny-list/allow-list read gate (the reparent-proof attribution
/// only binds a process that cannot write the cgroup tree). So, when no explicit
/// `--worker-uid` was given and the operator did not pass `--allow-root`:
///
/// - if the supervisor itself is not root, there is nothing to drop — return
///   `None` (the agent already runs unprivileged);
/// - if we were invoked via `sudo` (`SUDO_UID` set to a non-root user), drop the
///   agent to that user — the common, least-surprising case: the agent runs as
///   *you*, not root, and cannot reach the platform's root-only evasion;
/// - otherwise (genuine root with no sudo origin) we have no safe uid to pick, so
///   warn loudly and proceed at uid 0 rather than break a legitimately-root host.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn root_default_worker() -> Result<Option<gate::WorkerCreds>> {
    // Platform-specific reason a root agent is unsafe (same fix: drop the uid).
    #[cfg(target_os = "linux")]
    let why_long = "a root agent with CAP_SYS_ADMIN can remount cgroupfs to leave the \
                    scope and evade the gate";
    #[cfg(target_os = "macos")]
    let why_long = "a root agent can SIGKILL the Endpoint Security edge, and the kernel \
                    allows opens in the brief window before the supervisor reaps it";

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Ok(None);
    }

    // Prefer the invoking user from sudo. Success is the safe, expected path, so
    // it is SILENT — the effective uid still appears in the gate's startup line
    // and in every receipt. Only the case where we CANNOT drop is worth a warning.
    let sudo_uid = std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok());
    let sudo_gid = std::env::var("SUDO_GID").ok().and_then(|s| s.parse().ok());
    if let Some(uid) = sudo_uid {
        if uid != 0 {
            let gid = sudo_gid.unwrap_or(uid);
            return Ok(Some(gate::WorkerCreds { uid, gid }));
        }
    }

    // Genuine root with no sudo origin: no safe uid to pick. THIS is the loud
    // case — the protection is not in effect, the operator needs to know.
    eprintln!(
        "[bulwark] WARNING: the supervised agent runs as root (uid 0) and {why_long}. \
         For an untrusted agent use --worker-uid <uid> (drop privilege) or --hardened. \
         Pass --allow-root to silence this and keep uid 0 deliberately."
    );
    Ok(None)
}

fn resolve_worker_creds(
    worker_uid: Option<u32>,
    worker_gid: Option<u32>,
) -> Result<Option<gate::WorkerCreds>> {
    let Some(uid) = worker_uid else {
        if worker_gid.is_some() {
            anyhow::bail!("--worker-gid requires --worker-uid");
        }
        return Ok(None);
    };
    if uid == 0 {
        anyhow::bail!("--worker-uid 0 is not a privilege drop; omit the flag to run as root");
    }
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            anyhow::bail!(
                "--worker-uid needs a root supervisor to drop from (euid={euid}); run under sudo"
            );
        }
    }
    // Default the gid to the uid when not given explicitly — the conventional
    // per-user primary group on a freshly provisioned account.
    let gid = worker_gid.unwrap_or(uid);
    Ok(Some(gate::WorkerCreds { uid, gid }))
}

/// Build the gate mode + mark paths for a `run` and dispatch.
/// Refuse operator `--hardened --allow` grants that Landlock cannot enforce
/// faithfully. Hardened mode maps each grant to a `path_beneath` rule keyed on
/// the glob's concrete directory prefix; a glob with a non-trailing or
/// single-segment wildcard silently widens to that whole subtree (a `*.log`
/// grant becomes the whole directory; `**/*.log` becomes `/`). Rather than grant
/// a broad read floor by surprise, require the operator to state it explicitly
/// as a concrete path or a trailing `/**` subtree. The runtime base set is
/// exempt — it is a documented, printable floor and is not operator input.
fn reject_widening_hardened_grants(grants: &[String]) -> Result<()> {
    for g in grants {
        if !glob::is_landlock_faithful(g) {
            let prefix = glob::landlock_prefix(g);
            anyhow::bail!(
                "--hardened --allow {g:?} cannot be enforced faithfully: Landlock is \
                 path-based and would grant the entire subtree {prefix:?} — broader than \
                 the pattern. Re-grant explicitly as a concrete path or a trailing '/**' \
                 subtree (e.g. '{prefix}/**' to accept the whole subtree, or name the exact \
                 file/dir)."
            );
        }
    }
    Ok(())
}

fn cmd_run(args: RunArgs) -> Result<i32> {
    // Hardened mode: enforce the allowlist as a kernel Landlock floor, then
    // exec the agent. Crash-safe — no supervisor, the restriction is in the
    // kernel on the agent process itself. This call does not return on success
    // (it execs into the command).
    if args.hardened {
        if !args.protect.is_empty() {
            anyhow::bail!("--hardened uses --allow grants, not --protect");
        }
        reject_widening_hardened_grants(args.allow)?;
        let mut al = AllowList::new(args.allow.to_vec());
        if args.no_base_set {
            al = al.without_base();
        }
        if args.worker_uid.is_some() {
            // Hardened mode execs in-process (no fork, no child to drop). The
            // Landlock floor is already crash-safe, so a uid drop adds nothing.
            anyhow::bail!("--worker-uid is not used with --hardened (no supervised child to drop)");
        }
        return run_hardened(&al.allowed_globs(), args.command);
    }

    // resolve the optional worker credentials once, up front, so every
    // forking gate path drops the child the same way. Validation fails the run
    // before any integrity state is written.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(unused_mut))]
    let mut worker = resolve_worker_creds(args.worker_uid, args.worker_gid)?;

    // Root-agent safety. A supervised agent left at uid 0 can evade the gate,
    // differently per platform but with the same fix (drop it to a non-root uid):
    //   - Linux: a root agent with CAP_SYS_ADMIN can remount cgroupfs and migrate
    //     out of the supervised cgroup scope.
    //   - macOS: a root agent can SIGKILL the Endpoint Security edge; the kernel
    //     then allows opens in the brief window before the supervisor reaps it
    //     (fail-open on edge death). An unprivileged agent cannot kill the root
    //     edge, so it cannot reach that window.
    // If no explicit worker drop was requested and the operator did not pass
    // --allow-root, drop a would-be-root agent to the invoking user where we can.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if worker.is_none() && !args.allow_root {
        worker = root_default_worker()?;
    }
    let _ = args.allow_root; // consumed only on unix; keep the field live elsewhere

    // Allow-list (CI) mode: default-deny, allow only the grants + runtime base.
    // Non-interactive — there is no consent provider. Mark every mounted
    // filesystem so each open the agent makes is seen and judged.
    if args.deny_all {
        if !args.protect.is_empty() {
            anyhow::bail!(
                "--deny-all (allowlist) and --protect (deny-list) are mutually exclusive"
            );
        }
        let mut al = AllowList::new(args.allow.to_vec());
        if args.no_base_set {
            al = al.without_base();
        }
        // Snapshot the inodes reachable under each grant NOW, before the agent
        // runs, so grant decisions can be gated on inode identity rather than the
        // mutable path — defeating a later hardlink/rename of a foreign file into
        // a granted path.
        al.snapshot_grants();
        // Default-deny only holds if EVERY filesystem the agent could read from
        // is marked. A single mark on `/` misses other mounts (tmpfs `/tmp`, a
        // separate `/var` or data volume, network mounts) — opens there would be
        // invisible to the gate and silently allowed. So mark every real mount.
        let mark_paths = real_mount_points();
        let mode = GateMode::AllowList { allow: &al };
        return gate::run(mode, &mark_paths, args.receipts, args.command, worker);
    }

    // non-Linux socket consent is a platform-not-implemented path, not a
    // supervised run. Refuse before the integrity state marks an unclean launch.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if matches!(args.consent, ConsentMode::Socket) {
        socket::ensure_available()?;
    }

    let home = home_dir();

    let (protected, mark_paths): (ProtectedSet, Vec<PathBuf>) = if !args.protect.is_empty() {
        // Explicit paths: strict resolution (a missing path is an error).
        let set = ProtectedSet::resolve(args.protect)?;
        (set, args.protect.to_vec())
    } else {
        // Policy-driven: explicit --policy, else --profile, else a Bulwark.toml
        // in the cwd, else the built-in default profile.
        let policy = load_policy(args.profile, args.policy_path)?;
        let concrete = policy.concrete_protected_paths(&home);
        if !policy.protected_globs(&home).is_empty() {
            eprintln!(
                "[bulwark] note: {} wildcard protected pattern(s) are not yet matched at \
                 decision time in the MVP (only concrete paths resolve to inodes)",
                policy.protected_globs(&home).len()
            );
        }
        let (set, skipped) = ProtectedSet::resolve_lenient(&concrete);
        if skipped > 0 {
            eprintln!(
                "[bulwark] note: {skipped} protected path(s) not present on this host, skipped"
            );
        }
        let marks: Vec<PathBuf> = concrete.iter().map(PathBuf::from).collect();
        (set, marks)
    };

    // Integrity circuit-breaker: evaluate whether this run is tainted by
    // an unclean prior restart or object-identity drift, record this run's
    // context, and (if tainted) bypass the allow-session cache so every protected
    // open is freshly decided until an operator runs `bulwark reset`.
    let state_path = args
        .state
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(integrity::DEFAULT_STATE_PATH));
    let objects = protected_object_ids(&mark_paths);
    let run_ctx = integrity::RunContext {
        policy_epoch: POLICY_EPOCH,
        objects,
    };
    let mut store = integrity::Store::load(&state_path);
    let verdict = integrity::evaluate(store.prior(), &run_ctx);
    if let integrity::Integrity::Tainted(reason) = &verdict {
        let desc = reason.describe();
        eprintln!("[bulwark] INTEGRITY TAINTED: {desc} — protected reads require fresh consent; clear with `bulwark reset`");
        // One audit receipt for the taint, so the decision is on the record.
        let mut log = ReceiptLog::new(args.receipts)?;
        log.record(&Receipt {
            pid: std::process::id() as i32,
            dev: 0,
            ino: 0,
            decision: Decision::Deny,
            path: "",
            ancestry: "",
            reason: &format!("integrity tainted: {desc}"),
            source: "integrity",
        });
    }
    let tainted = verdict.is_tainted();
    // Record this run's context (generation bump, clean marker cleared). A hard
    // kill from here on skips the post-run clean marker, so the next launch sees
    // an unclean restart — exactly the signal we want.
    store
        .begin_run(&run_ctx, &verdict)
        .with_context(|| format!("cannot write integrity state {}", state_path.display()))?;

    // Build the consent provider for protected opens. `static` denies by
    // default (no prompt); `socket` asks the operator off-band. The socket
    // provider is bound BEFORE the gate forks the agent, and its root pid is
    // the supervisor itself so the agent tree is refused as an answerer.
    let timeout = Duration::from_secs(args.consent_timeout);
    let supervisor_pid = std::process::id() as i32;
    let code = match args.consent {
        ConsentMode::Static => {
            let mut decider = CachingProvider::new(StaticDeny);
            if tainted {
                decider = decider.tainted();
            }
            let mode = GateMode::DenyList {
                protected: &protected,
                consent: &mut decider,
            };
            gate::run(mode, &mark_paths, args.receipts, args.command, worker)
        }
        ConsentMode::Socket => {
            let sock = args.consent_socket.unwrap_or_else(default_consent_socket);
            let provider = SocketProvider::bind(&sock, supervisor_pid, timeout)?;
            eprintln!(
                "[bulwark] consent socket ready at {} — answer with: bulwark consent --socket {}",
                sock.display(),
                sock.display()
            );
            let mut decider = CachingProvider::new(provider);
            if tainted {
                decider = decider.tainted();
            }
            let code = {
                let mode = GateMode::DenyList {
                    protected: &protected,
                    consent: &mut decider,
                };
                gate::run(mode, &mark_paths, args.receipts, args.command, worker)?
            };
            // Persist any deny-forever decisions as protected globs so they
            // hold across sessions (path, not inode — inodes are reused).
            persist_deny_forever(decider.deny_forever_paths(), args.policy_path);
            Ok(code)
        }
        ConsentMode::Remote => cmd_run_remote(&protected, &mark_paths, &args, worker),
    };

    // Reaching here means the supervisor exited normally (child exited or a
    // trapped termination signal drained-and-denied). Record the clean shutdown
    // so the NEXT launch does not see this run as an unclean restart. A hard kill
    // (SIGKILL/crash/OOM/power loss) never reaches this line — by design. Best
    // effort: a state-write failure must not change the run's exit code.
    if let Err(e) = store.mark_clean_shutdown() {
        eprintln!("[bulwark] warn: could not record clean shutdown: {e}");
    }
    code
}

/// Resolve each marked protected path to its current `(dev, ino)` for the
/// integrity record. Paths that cannot be stat'd (absent on this host) are
/// skipped — they contribute no identity to drift-check.
fn protected_object_ids(mark_paths: &[PathBuf]) -> Vec<integrity::ObjId> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    for p in mark_paths {
        if let Ok(m) = std::fs::metadata(p) {
            out.push(integrity::ObjId {
                path: p.to_string_lossy().into_owned(),
                dev: m.dev(),
                ino: m.ino(),
            });
        }
    }
    out
}

/// `bulwark reset`: clear the integrity taint marker after operator review.
fn cmd_reset(state: Option<&Path>) -> Result<()> {
    let state_path = state
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(integrity::DEFAULT_STATE_PATH));
    let mut store = integrity::Store::load(&state_path);
    match store.taint_reason() {
        Some(reason) => {
            let reason = reason.to_string();
            store
                .clear()
                .with_context(|| format!("cannot clear taint in {}", state_path.display()))?;
            println!("[bulwark] integrity taint cleared (was: {reason})");
        }
        None => {
            println!("[bulwark] no integrity taint set; nothing to clear");
        }
    }
    Ok(())
}

/// Remote gate side (driven by `bulwark ssh`): a protected open is denied
/// immediately and a prompt is appended to the prompt lane; a background thread
/// reads operator allow-session replies from the verdict lane and updates the
/// cache so the next open passes. The kernel deadline is always met.
fn cmd_run_remote(
    protected: &ProtectedSet,
    mark_paths: &[PathBuf],
    args: &RunArgs,
    worker: Option<gate::WorkerCreds>,
) -> Result<i32> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (protected, mark_paths, args, worker);
        anyhow::bail!(
            "remote consent is not implemented on this platform yet — \
             bulwark refuses to run a remote-gated agent without the Linux fanotify verdict lane"
        );
    }

    #[cfg(target_os = "linux")]
    {
        use std::io::BufReader;
        let prompt_path = args
            .prompt_out
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--consent remote requires --prompt-out <FILE>"))?;
        let verdict_path = args
            .verdict_in
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--consent remote requires --verdict-in <FILE>"))?;

        let cache = remote::RemoteCache::new();
        // Session id: this run is one session. Use the start time in millis so a new
        // run is a new session and old grants do not carry over.
        let session_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1);
        let policy_epoch: u64 = 1;

        // Verdict lane: a background thread reads operator allow-session replies and
        // populates the (shared) cache. Open O_RDWR so that, when the lane is a
        // FIFO, the open does NOT block waiting for a writer (a read-only FIFO open
        // blocks until a writer connects — which would deadlock startup) and the
        // reader never sees EOF when a transient writer disconnects.
        let verdict_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&verdict_path)
            .with_context(|| format!("cannot open verdict lane {}", verdict_path.display()))?;
        let intake_cache = cache.clone();
        std::thread::spawn(move || {
            remote::intake_verdicts(BufReader::new(verdict_file), intake_cache);
        });

        // Prompt lane: append-only file the local side tails.
        let prompt_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&prompt_path)
            .with_context(|| format!("cannot open prompt lane {}", prompt_path.display()))?;

        let mut decider = remote::AsyncRemoteProvider::new(
            cache,
            prompt_file,
            args.host_label.clone(),
            session_id,
            policy_epoch,
        );
        eprintln!(
            "[bulwark] remote gate: prompts -> {}, verdicts <- {}",
            prompt_path.display(),
            verdict_path.display()
        );
        let mode = GateMode::DenyList {
            protected,
            consent: &mut decider,
        };
        gate::run(mode, mark_paths, args.receipts, args.command, worker)
    }
}

/// Append deny-forever paths to the policy file as protected entries. Best
/// effort: a persistence failure must not change the exit code of the run.
fn persist_deny_forever(paths: &[String], policy_path: Option<&Path>) {
    if paths.is_empty() {
        return;
    }
    let target: PathBuf = match policy_path {
        Some(p) => p.to_path_buf(),
        None => find_policy_file().unwrap_or_else(|| PathBuf::from(POLICY_FILE)),
    };
    let mut policy = if target.exists() {
        match Policy::load(&target) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[bulwark] could not load policy to persist deny-forever: {e}");
                return;
            }
        }
    } else {
        Policy::default_profile()
    };
    let mut added = 0;
    for p in paths {
        if policy.add_protected(p) {
            added += 1;
        }
    }
    if added > 0 {
        if let Err(e) = policy.save(&target) {
            eprintln!(
                "[bulwark] could not persist deny-forever to {}: {e}",
                target.display()
            );
        } else {
            eprintln!(
                "[bulwark] persisted {added} deny-forever path(s) to {}",
                target.display()
            );
        }
    }
}

/// `bulwark check <path>` — print the policy decision for a path. In the Linux
/// MVP a `Protected` match and an `Outside(prompt)` both resolve to a denied
/// read at the gate (no interactive prompt yet); this is stated in the output.
fn cmd_check(
    path: &str,
    profile: Option<&str>,
    policy_path: Option<&Path>,
    format: OutputFormat,
) -> Result<()> {
    use policy::{OutsideWorkspace, PolicyDecision};
    let home = home_dir();
    let policy = load_policy(profile, policy_path)?;
    let decision = policy.decide(path, &home);
    // `decided` is a stable machine token; `label`/`effect` are human strings.
    let (decided, label, effect) = match decision {
        PolicyDecision::AllowWorkspace => ("allow_workspace", "allow (workspace)", "read allowed"),
        PolicyDecision::Protected => ("protected", "protected", "read DENIED"),
        PolicyDecision::Outside(OutsideWorkspace::Allow) => {
            ("outside_allow", "outside → allow", "read allowed")
        }
        PolicyDecision::Outside(OutsideWorkspace::Deny) => {
            ("outside_deny", "outside → deny", "read DENIED")
        }
        PolicyDecision::Outside(OutsideWorkspace::Prompt) => {
            ("outside_prompt", "outside → prompt", "read DENIED")
        }
    };
    match format {
        OutputFormat::Json => {
            println!(
                r#"{{"path":"{}","decision":"{}","effect":"{}"}}"#,
                json_escape(path),
                decided,
                effect
            );
        }
        OutputFormat::Human => {
            println!("{path}\n  policy:     {label}\n  effect:     {effect}");
        }
    }
    Ok(())
}

/// `bulwark init` — write a default policy file so the operator can edit what is
/// protected. Refuses to clobber an existing file without `--force`.
fn cmd_init(policy_path: Option<&Path>, profile: Option<&str>, force: bool) -> Result<()> {
    let target: PathBuf = match policy_path {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(POLICY_FILE),
    };
    if target.exists() && !force {
        anyhow::bail!(
            "{} already exists — use --force to overwrite",
            target.display()
        );
    }
    let policy = match profile {
        Some(name) => Policy::named(name)
            .with_context(|| format!("unknown profile '{name}' (try 'default' or 'dev')"))?,
        None => Policy::default_profile(),
    };
    policy.save(&target)?;
    println!(
        "wrote {} (edit it to choose what is protected)",
        target.display()
    );
    Ok(())
}

/// One preflight check result.
struct DoctorCheck {
    name: &'static str,
    ok: bool,
    /// `required` checks gate the exit code; advisory ones only inform.
    required: bool,
    detail: String,
}

/// `bulwark doctor` — report whether this host can enforce. Returns the process
/// exit code: 0 when every REQUIRED check passes, 1 otherwise.
fn cmd_doctor(format: OutputFormat) -> i32 {
    let checks = run_doctor_checks();
    let failed_required = checks.iter().any(|c| c.required && !c.ok);

    match format {
        OutputFormat::Json => {
            // Field shape follows the ANCC doctor convention so any orchestrator
            // can parse it uniformly: top-level `status` + `version`, and each
            // check carries a `status` (pass/fail/warn) alongside the booleans.
            let items: Vec<String> = checks
                .iter()
                .map(|c| {
                    let status = if c.ok {
                        "pass"
                    } else if c.required {
                        "fail"
                    } else {
                        "warn"
                    };
                    format!(
                        r#"{{"name":"{}","status":"{}","ok":{},"required":{},"detail":"{}"}}"#,
                        c.name,
                        status,
                        c.ok,
                        c.required,
                        json_escape(&c.detail)
                    )
                })
                .collect();
            println!(
                r#"{{"status":"{}","ok":{},"version":"{}","source":{{"repo":"obstalabs/bulwark"}},"checks":[{}]}}"#,
                if failed_required {
                    "unhealthy"
                } else {
                    "healthy"
                },
                !failed_required,
                env!("CARGO_PKG_VERSION"),
                items.join(",")
            );
        }
        OutputFormat::Human => {
            for c in &checks {
                let mark = if c.ok {
                    "ok  "
                } else if c.required {
                    "FAIL"
                } else {
                    "warn"
                };
                println!("[{mark}] {:<22} {}", c.name, c.detail);
            }
            println!(
                "\n{}",
                if failed_required {
                    "doctor: this host is MISSING a required capability (see FAIL above)"
                } else {
                    "doctor: this host can enforce"
                }
            );
        }
    }
    if failed_required {
        1
    } else {
        0
    }
}

/// Collect the preflight checks. Kept separate from rendering so it is testable.
fn run_doctor_checks() -> Vec<DoctorCheck> {
    #[cfg(target_os = "macos")]
    {
        let mut out = Vec::new();
        collect_macos_doctor_checks(&mut out);
        out
    }

    #[cfg(not(target_os = "macos"))]
    {
        let mut out = Vec::new();
        collect_linux_doctor_checks(&mut out);
        out
    }
}

fn collect_linux_doctor_checks(out: &mut Vec<DoctorCheck>) {
    // Linux is required — the gate is fanotify/Landlock.
    let is_linux = cfg!(target_os = "linux");
    out.push(DoctorCheck {
        name: "os-linux",
        ok: is_linux,
        required: true,
        detail: if is_linux {
            "Linux".to_string()
        } else {
            "not Linux — bulwark enforces via fanotify/Landlock (Linux only)".to_string()
        },
    });

    // Root / CAP_SYS_ADMIN — required for fanotify permission events.
    let uid = unsafe { libc::geteuid() };
    out.push(DoctorCheck {
        name: "root-or-cap",
        ok: uid == 0,
        required: true,
        detail: if uid == 0 {
            "running as root (CAP_SYS_ADMIN available)".to_string()
        } else {
            format!("euid={uid}, not root — fanotify needs CAP_SYS_ADMIN; run under sudo")
        },
    });

    // Kernel version — advisory: report what we can read.
    let kver = kernel_release();
    out.push(DoctorCheck {
        name: "kernel",
        ok: !kver.is_empty(),
        required: false,
        detail: if kver.is_empty() {
            "could not read kernel release".to_string()
        } else {
            kver
        },
    });

    // Landlock — advisory (only needed for --hardened). Probe the ABI.
    let landlock = landlock_available();
    out.push(DoctorCheck {
        name: "landlock",
        ok: landlock,
        required: false,
        detail: if landlock {
            "Landlock available (--hardened supported)".to_string()
        } else {
            "Landlock not available — --hardened will not work (needs Linux 5.13+)".to_string()
        },
    });
}

/// Read the kernel release string via uname(2). Empty on failure or non-Linux.
fn kernel_release() -> String {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) != 0 {
            return String::new();
        }
        // uts.release is c_char, which is u8 on some targets and i8 on others.
        // Reinterpret the array as bytes to read the NUL-terminated string
        // portably without a per-target cast.
        let raw = std::slice::from_raw_parts(uts.release.as_ptr().cast::<u8>(), uts.release.len());
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }
    #[cfg(not(target_os = "linux"))]
    String::new()
}

/// Probe Landlock support by asking the kernel for the current ABI version.
/// Returns true when ABI >= 1. Non-Linux always false.
fn landlock_available() -> bool {
    #[cfg(target_os = "linux")]
    unsafe {
        // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) returns
        // the ABI version (>=1) when supported, or -1/errno otherwise.
        const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
        const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1 << 0;
        let abi = libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        );
        abi >= 1
    }
    #[cfg(not(target_os = "linux"))]
    false
}

/// macOS preflight checks for the root-launched Endpoint Security edge.
#[cfg(target_os = "macos")]
fn collect_macos_doctor_checks(out: &mut Vec<DoctorCheck>) {
    let version = macos_product_version();
    let version_ok = macos_version_supported(&version);
    out.push(DoctorCheck {
        name: "os-macos",
        ok: version_ok,
        required: true,
        detail: if version_ok {
            format!("macOS {version}")
        } else {
            format!("macOS {version}; requires macOS {MACOS_MIN_VERSION}+")
        },
    });

    let uid = unsafe { libc::geteuid() };
    out.push(DoctorCheck {
        name: "root",
        ok: uid == 0,
        required: true,
        detail: if uid == 0 {
            "running as root (Endpoint Security clients must be privileged)".to_string()
        } else {
            format!("euid={uid}, not root — run the gate with sudo")
        },
    });

    // Resolve the edge the same way the gate does: env override, then auto-discovery
    // relative to the CLI (so a packaged install reports green with no env var set).
    let env_set = std::env::var_os(MACOS_ES_GATE_ENV).is_some();
    let edge = gate::resolve_edge_path();
    out.push(DoctorCheck {
        name: "es-edge",
        ok: edge.is_some(),
        required: true,
        detail: match (&edge, env_set) {
            (Some(path), true) => format!("{MACOS_ES_GATE_ENV}={}", path.display()),
            (Some(path), false) => format!("found beside CLI: {}", path.display()),
            (None, _) => format!(
                "no ES edge found (not beside the CLI; set {MACOS_ES_GATE_ENV} to override)"
            ),
        },
    });

    let executable_ok = edge.as_deref().is_some_and(is_executable_file);
    out.push(DoctorCheck {
        name: "es-edge-executable",
        ok: executable_ok,
        required: true,
        detail: match &edge {
            Some(path) if executable_ok => format!("{} is executable", path.display()),
            Some(path) => format!("{} is not an executable file", path.display()),
            None => "skipped: set BULWARK_MACOS_ES_GATE first".to_string(),
        },
    });

    let entitlement_ok = edge
        .as_deref()
        .and_then(codesign_entitlements)
        .is_some_and(|raw| raw.contains("com.apple.developer.endpoint-security.client"));
    out.push(DoctorCheck {
        name: "es-edge-entitlement",
        ok: entitlement_ok,
        required: true,
        detail: match &edge {
            Some(path) if entitlement_ok => {
                format!(
                    "{} carries the Endpoint Security client entitlement",
                    path.display()
                )
            }
            Some(path) => format!(
                "{} is missing com.apple.developer.endpoint-security.client or codesign failed",
                path.display()
            ),
            None => "skipped: set BULWARK_MACOS_ES_GATE first".to_string(),
        },
    });

    out.push(DoctorCheck {
        name: "full-disk-access",
        ok: true,
        required: false,
        detail: "advisory: if es_new_client reports ERR_NOT_PERMITTED, grant Full Disk Access to the launching terminal".to_string(),
    });
}

#[cfg(target_os = "macos")]
fn macos_product_version() -> String {
    command_output("/usr/bin/sw_vers", &["-productVersion"])
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(target_os = "macos")]
fn macos_version_supported(version: &str) -> bool {
    let Some(major) = version
        .split('.')
        .next()
        .and_then(|part| part.parse::<u64>().ok())
    else {
        return false;
    };
    major >= MACOS_MIN_MAJOR
}

#[cfg(target_os = "macos")]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(target_os = "macos")]
fn codesign_entitlements(path: &Path) -> Option<String> {
    let out = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(path)
        .output()
        .ok()?;
    let mut raw = String::from_utf8_lossy(&out.stdout).into_owned();
    raw.push_str(&String::from_utf8_lossy(&out.stderr));
    if raw.is_empty() {
        None
    } else {
        Some(raw)
    }
}

#[cfg(target_os = "macos")]
fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Load the policy for a `run`: `--policy` file wins, then a named `--profile`,
/// then `./Bulwark.toml` if present, else the built-in default profile.
fn load_policy(profile: Option<&str>, policy_path: Option<&Path>) -> Result<Policy> {
    if let Some(p) = policy_path {
        return Policy::load(p);
    }
    if let Some(name) = profile {
        return Policy::named(name)
            .with_context(|| format!("unknown profile '{name}' (try 'default' or 'dev')"));
    }
    if let Some(found) = find_policy_file() {
        return Policy::load(&found);
    }
    Ok(Policy::default_profile())
}

enum Mutate {
    Allow,
    Deny,
}

/// `bulwark allow|deny <glob>` — mutate the policy file, creating it from the
/// default profile if it does not exist.
fn cmd_mutate(glob: &str, policy_path: Option<&Path>, which: Mutate) -> Result<()> {
    // Explicit --policy wins; otherwise mutate an existing Bulwark.toml/
    // bulwark.toml in the cwd, or create the canonical Bulwark.toml.
    let path: PathBuf = match policy_path {
        Some(p) => p.to_path_buf(),
        None => find_policy_file().unwrap_or_else(|| PathBuf::from(POLICY_FILE)),
    };
    let mut policy = if path.exists() {
        Policy::load(&path)?
    } else {
        Policy::default_profile()
    };
    let (changed, verb) = match which {
        Mutate::Allow => (policy.add_allow(glob), "allowed"),
        Mutate::Deny => (policy.add_protected(glob), "protected"),
    };
    if changed {
        policy.save(&path)?;
        println!("{verb} {glob} (written to {})", path.display());
    } else {
        println!("{glob} already {verb} in {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_handles_quotes_and_controls() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(json_escape("line\nbreak"), "line\\nbreak");
        assert_eq!(json_escape("tab\tend"), "tab\\tend");
    }

    #[test]
    fn gate_script_is_byte_identical_to_pre_wo29_baseline() {
        // acceptance: with no hivebus flags, `bulwark ssh` must behave
        // exactly as before. The hivebus handoff is a SEPARATE ssh session, so the
        // gate script is independent of it — this pins the exact bytes so any
        // accidental weaving of key material into the gate script is caught.
        let script = build_gate_script(
            "/tmp/bulwark-remote-42",
            "/tmp/bulwark-remote-42/prompts",
            "/tmp/bulwark-remote-42/verdicts",
            "/usr/local/bin/bulwark",
            "nullbot@host",
            "--protect '/etc/shadow'",
            None,
            "'claude' '-p' 'fix it'",
        );
        let expected = "set -e\n\
mkdir /tmp/bulwark-remote-42\n\
mkfifo -m 600 /tmp/bulwark-remote-42/prompts /tmp/bulwark-remote-42/verdicts\n\
sudo /usr/local/bin/bulwark run --consent remote --host-label 'nullbot@host' \\\n  \
--prompt-out /tmp/bulwark-remote-42/prompts --verdict-in /tmp/bulwark-remote-42/verdicts \\\n  \
--protect '/etc/shadow' -- 'claude' '-p' 'fix it'\n\
RC=$?\n\
rm -rf /tmp/bulwark-remote-42\n\
exit $RC\n";
        assert_eq!(
            script, expected,
            "gate script must not drift from the baseline"
        );
        // The script must NEVER mention hivebus — the handoff is out-of-band.
        assert!(
            !script.contains("hivebus"),
            "gate script must not carry key material"
        );
    }

    #[test]
    fn hivebus_dispatch_default_is_inert() {
        let h = HivebusDispatch::default();
        assert!(h.is_inert(), "no flags set => fully inert, no key handoff");
    }

    #[test]
    fn hivebus_dispatch_not_inert_when_either_flag_set() {
        let p = std::path::Path::new("/x.pub");
        assert!(!HivebusDispatch {
            architect_pub: Some(p),
            worker_seed_generate: false,
        }
        .is_inert());
        assert!(!HivebusDispatch {
            architect_pub: None,
            worker_seed_generate: true,
        }
        .is_inert());
    }

    #[test]
    fn gate_script_emits_worker_uid_when_set() {
        // with --worker-uid, the remote sudo line carries it; absent, the
        // script is byte-identical to today (covered by the baseline test above).
        let with = build_gate_script(
            "/tmp/d",
            "/tmp/d/p",
            "/tmp/d/v",
            "/usr/local/bin/bulwark",
            "nullbot@host",
            "--protect '/etc/shadow'",
            Some(1000),
            "'claude'",
        );
        assert!(
            with.contains("--worker-uid 1000 --protect '/etc/shadow'"),
            "worker uid must precede the protect args on the sudo line:\n{with}"
        );
        // a worker uid also carries an env identity for getpwuid mitigation.
        assert!(
            with.contains("sudo env HOME=/tmp/d USER=bulwark-worker LOGNAME=bulwark-worker "),
            "worker uid must carry HOME/USER/LOGNAME env identity:\n{with}"
        );
        let without = build_gate_script(
            "/tmp/d",
            "/tmp/d/p",
            "/tmp/d/v",
            "/usr/local/bin/bulwark",
            "nullbot@host",
            "--protect '/etc/shadow'",
            None,
            "'claude'",
        );
        assert!(
            !without.contains("--worker-uid"),
            "no worker uid => no flag in the script"
        );
        // No worker uid => no env prefix (byte-identical to the pre-form).
        assert!(
            !without.contains("env HOME="),
            "no worker uid => no env identity prefix"
        );
    }

    #[test]
    fn remote_uid_pick_snippet_uses_getent_and_bounded_probe() {
        // the uid picker must seed from the run id, probe with getent only
        // (no useradd — nothing is created), and bound the range with a clear exit.
        let snip = remote_uid_pick_snippet(12345);
        assert!(
            snip.contains(&format!("n={}", 60000 + (12345 % 4000))),
            "candidate must seed from the run id:\n{snip}"
        );
        assert!(snip.contains("getent passwd"), "must probe with getent");
        assert!(!snip.contains("useradd"), "must NOT create an account");
        assert!(snip.contains("exit 73"), "must bail on range exhaustion");
    }

    #[test]
    fn hardened_gate_script_has_no_consent_machinery() {
        // the hardened remote script must NOT carry FIFOs, --consent remote,
        // or prompt/verdict lanes — hardened is non-interactive + crash-safe.
        let script = build_hardened_gate_script(
            "/tmp/bulwark-remote-7",
            "/usr/local/bin/bulwark",
            "--allow '/var/log/**'",
            false,
            "'claude'",
        );
        let expected = "set -e\n\
mkdir -p /tmp/bulwark-remote-7\n\
sudo /usr/local/bin/bulwark run --hardened --allow '/var/log/**' -- 'claude'\n\
RC=$?\n\
rm -rf /tmp/bulwark-remote-7\n\
exit $RC\n";
        assert_eq!(script, expected, "hardened script bytes must not drift");
        assert!(!script.contains("mkfifo"), "hardened: no FIFOs");
        assert!(!script.contains("--consent"), "hardened: no consent mode");
        assert!(!script.contains("--prompt-out"), "hardened: no prompt lane");
    }

    #[test]
    fn hardened_gate_script_no_base_set_toggles() {
        let with = build_hardened_gate_script("/tmp/d", "/b", "--allow '/x'", true, "'a'");
        assert!(
            with.contains("run --hardened --no-base-set --allow '/x'"),
            "no-base-set must precede --allow:\n{with}"
        );
        let without = build_hardened_gate_script("/tmp/d", "/b", "--allow '/x'", false, "'a'");
        assert!(!without.contains("--no-base-set"), "off => flag absent");
    }

    #[test]
    fn resolve_worker_creds_none_is_none() {
        assert!(resolve_worker_creds(None, None).unwrap().is_none());
    }

    #[test]
    fn resolve_worker_creds_rejects_uid_zero() {
        assert!(resolve_worker_creds(Some(0), None).is_err());
    }

    #[test]
    fn resolve_worker_creds_rejects_gid_without_uid() {
        assert!(resolve_worker_creds(None, Some(1000)).is_err());
    }

    #[test]
    fn doctor_always_reports_the_required_checks() {
        let checks = run_doctor_checks();
        let required: Vec<&str> = checks
            .iter()
            .filter(|c| c.required)
            .map(|c| c.name)
            .collect();
        if cfg!(target_os = "macos") {
            assert!(required.contains(&"os-macos"), "must check the OS");
            assert!(required.contains(&"root"), "must check privilege");
            assert!(required.contains(&"es-edge"), "must check the ES edge path");
            assert!(
                required.contains(&"es-edge-entitlement"),
                "must check the ES entitlement"
            );
            assert!(checks
                .iter()
                .any(|c| c.name == "full-disk-access" && !c.required));
        } else {
            assert!(required.contains(&"os-linux"), "must check the OS");
            assert!(required.contains(&"root-or-cap"), "must check privilege");
            assert!(checks.iter().any(|c| c.name == "kernel" && !c.required));
            assert!(checks.iter().any(|c| c.name == "landlock" && !c.required));
        }
    }

    #[test]
    fn launch_resolves_configured_agent_profile() {
        let policy = Policy::default_profile();
        let plan = resolve_launch_plan("claude", &policy).unwrap();
        assert_eq!(plan.command, vec!["claude".to_string()]);
        assert!(plan.protect.iter().any(|p| p == Path::new("~/.ssh")));
        assert!(plan.allow.iter().any(|p| p == "Cargo.toml"));
        assert!(plan.audit);
        assert!(!plan.deny_all);
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert_eq!(plan.consent, ConsentMode::Socket);
        } else {
            assert_eq!(plan.consent, ConsentMode::Static);
        }
    }

    #[test]
    fn launch_refuses_unknown_agent_with_init_hint() {
        let policy = Policy::default_profile();
        let err = resolve_launch_plan("random-agent", &policy).unwrap_err();
        assert!(err.to_string().contains(
            "no agent configured for random-agent; run: bulwark launch --init random-agent"
        ));
    }

    #[test]
    fn launch_refuses_profile_without_policy_boundary() {
        let mut policy = Policy::default_profile();
        let mut empty = policy.agents.get("claude").unwrap().clone();
        empty.protect.clear();
        empty.allow.clear();
        policy.agents.insert("empty".to_string(), empty);
        let err = resolve_launch_plan("empty", &policy).unwrap_err();
        assert!(err
            .to_string()
            .contains("agent empty has neither protect nor allow policy configured"));
    }
}
