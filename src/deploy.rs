//! Remote binary auto-deploy for `bulwark ssh`.
//!
//! The remote read gate must run on the remote kernel. This module resolves a
//! launch plan for that gate, preferring trace-minimal delivery before falling
//! back to legacy release-fetch behavior.

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The release version this binary was built from. The dist-fetch path pulls the
/// matching release so local and remote never skew.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Public dist repo that holds the release tarballs.
pub const DIST_REPO: &str = "obstalabs/bulwark-dist";

/// Local override for the static Linux gate payload streamed to memfd or shm.
pub const STREAMABLE_GATE_ENV: &str = "BULWARK_GATE_BINARY";

const DEPLOY_DIR_PREFIX: &str = "bulwark-deploy";
const REMOTE_TMP: &str = "/tmp";
const REMOTE_SHM: &str = "/dev/shm";

/// How `bulwark ssh` is allowed to obtain the remote binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployMode {
    /// Choose the most ephemeral viable delivery rung.
    Auto,
    /// Require an existing remote bulwark; never deploy.
    Never,
    /// Stream a static Linux gate into an anonymous memfd and fexecve it.
    Memfd,
    /// Stream a static Linux gate into `/dev/shm` as the RAM-backed fallback.
    Shm,
    /// Force the scp-the-local-binary path; fail if it is not possible.
    Scp,
    /// Force the remote dist-fetch path.
    Dist,
}

impl DeployMode {
    /// Parse the `--deploy` flag value. Unknown values return `None`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "auto" => Some(DeployMode::Auto),
            "never" => Some(DeployMode::Never),
            "memfd" => Some(DeployMode::Memfd),
            "shm" => Some(DeployMode::Shm),
            "scp" => Some(DeployMode::Scp),
            "dist" => Some(DeployMode::Dist),
            _ => None,
        }
    }
}

/// The remote host's OS and CPU arch, as reported by `uname -s -m`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePlatform {
    /// `uname -s`, e.g. `Linux`.
    pub os: String,
    /// `uname -m`, e.g. `x86_64` or `aarch64`.
    pub arch: String,
}

/// The resolved remote gate source and the shell fragments needed to execute it.
#[derive(Debug, Clone)]
pub struct RemoteBulwark {
    source: DeploySource,
    plain_invocation: String,
    gate_invocation: String,
    payload_path: Option<PathBuf>,
    prelude: Option<String>,
    cleanup_dir: Option<String>,
    run_dir_base: &'static str,
}

/// Which deploy rung was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploySource {
    Existing,
    Scp,
    Dist,
    Memfd,
    Shm,
}

impl RemoteBulwark {
    pub fn source(&self) -> DeploySource {
        self.source
    }

    /// Invocation for non-root preflight commands such as `landlock-check`.
    pub fn plain_invocation(&self) -> &str {
        &self.plain_invocation
    }

    /// Invocation for the actual remote gate run, including sudo where needed.
    pub fn gate_invocation(&self) -> &str {
        &self.gate_invocation
    }

    /// Local payload file streamed to the remote command's stdin, when needed.
    pub fn payload_path(&self) -> Option<&Path> {
        self.payload_path.as_deref()
    }

    /// Shell prelude that consumes the streamed payload before invoking the gate.
    pub fn prelude(&self) -> Option<&str> {
        self.prelude.as_deref()
    }

    /// Remote directory the caller must remove during teardown.
    pub fn cleanup_dir(&self) -> Option<&str> {
        self.cleanup_dir.as_deref()
    }

    /// Base directory for consent lanes. Memfd/shm avoid `/tmp`.
    pub fn run_dir_base(&self) -> &'static str {
        self.run_dir_base
    }

    pub fn needs_binary_stdin(&self) -> bool {
        matches!(self.source(), DeploySource::Memfd | DeploySource::Shm)
    }
}

impl RemotePlatform {
    /// Parse the output of `uname -s -m` (e.g. `"Linux x86_64"`).
    pub fn parse_uname(s: &str) -> Option<Self> {
        let mut parts = s.split_whitespace();
        let os = parts.next()?.to_string();
        let arch = parts.next()?.to_string();
        Some(RemotePlatform { os, arch })
    }
}

/// Map `uname -m` to the static musl target used for streamable gates.
pub fn target_triple(arch: &str) -> Result<&'static str> {
    match arch {
        "x86_64" | "amd64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" | "arm64" => Ok("aarch64-unknown-linux-musl"),
        other => Err(anyhow!(
            "no published bulwark release for arch '{other}' (supported: x86_64, aarch64)"
        )),
    }
}

/// The dist release tarball name for a version + arch, matching the asset names
/// published by `release.yml` (`bulwark-<version>-<target>.tar.gz`).
pub fn dist_asset(version: &str, arch: &str) -> Result<String> {
    Ok(format!("bulwark-{version}-{}.tar.gz", target_triple(arch)?))
}

/// The full download URL for a dist release asset.
pub fn dist_url(version: &str, asset: &str) -> String {
    format!("https://github.com/{DIST_REPO}/releases/download/v{version}/{asset}")
}

/// Whether the LOCAL binary can be scp'd to the remote and run there: true only
/// when this build is Linux and its arch matches the remote arch. On macOS this
/// is always false (a Mach-O binary will not run on Linux), forcing dist-fetch.
pub fn local_can_scp(remote: &RemotePlatform) -> bool {
    if std::env::consts::OS != "linux" || remote.os != "Linux" {
        return false;
    }
    let local_arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return false,
    };
    matches!(normalized_arch(&remote.arch), Ok(a) if a == local_arch)
}

// ---- I/O layer: probing and deploying over ssh/scp ------------------------

/// Common ssh options for the non-interactive control commands: accept a
/// first-seen host key and never block on a password prompt.
const SSH_OPTS: &[&str] = &[
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "BatchMode=yes",
];

/// Run `ssh <target> <remote_cmd>` and return trimmed stdout. Errors if ssh
/// itself fails to run; a non-zero remote exit yields an empty-ish result the
/// caller interprets.
fn ssh_capture(target: &str, remote_cmd: &str) -> Result<std::process::Output> {
    Command::new("ssh")
        .args(SSH_OPTS)
        .arg(target)
        .arg(remote_cmd)
        .output()
        .with_context(|| format!("cannot ssh to {target}"))
}

fn ssh_capture_with_payload(
    target: &str,
    remote_cmd: &str,
    payload_path: &Path,
) -> Result<std::process::Output> {
    let payload = File::open(payload_path)
        .with_context(|| format!("open streamable gate payload {}", payload_path.display()))?;
    Command::new("ssh")
        .args(SSH_OPTS)
        .arg(target)
        .arg(remote_cmd)
        .stdin(payload)
        .output()
        .with_context(|| format!("cannot ssh to {target}"))
}

/// Detect the remote OS + arch via `uname -s -m`.
pub fn detect_platform(target: &str) -> Result<RemotePlatform> {
    let out = ssh_capture(target, "uname -s -m")?;
    if !out.status.success() {
        return Err(anyhow!(
            "could not detect remote platform on {target}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    RemotePlatform::parse_uname(s.trim())
        .ok_or_else(|| anyhow!("unexpected `uname -s -m` output: {:?}", s.trim()))
}

/// Whether the remote already has a runnable `bulwark` on `PATH`. Returns the
/// resolved command name (`"bulwark"`) if so.
fn remote_has_bulwark(target: &str) -> bool {
    matches!(
        ssh_capture(target, "command -v bulwark"),
        Ok(o) if o.status.success() && !o.stdout.is_empty()
    )
}

fn normalized_arch(arch: &str) -> Result<&'static str> {
    match arch {
        "x86_64" | "amd64" => Ok("x86_64"),
        "aarch64" | "arm64" => Ok("aarch64"),
        other => Err(anyhow!(
            "no streamable bulwark gate for arch '{other}' (supported: x86_64, aarch64)"
        )),
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn output_reason(out: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !stdout.is_empty() {
        return stdout;
    }
    format!("remote exit {:?}", out.status.code())
}

fn cleanup_trap(cleanup_dir: &str) -> String {
    format!(
        r#"cleanup() {{
  rc=$?
  trap - EXIT INT TERM HUP
  sudo -n rm -rf {cleanup_dir} 2>/dev/null || rm -rf {cleanup_dir} 2>/dev/null || true
  exit "$rc"
}}
trap cleanup EXIT INT TERM HUP"#
    )
}

fn memfd_exec_invocation(remote_loader: &str) -> String {
    let script = r#"loader=$1; shift; exec "$loader" __memfd-exec bulwark "$@" < "$loader""#;
    format!("sh -c {} sh {remote_loader}", shell_quote(script))
}

// Probe memfd through the same sudo gate path used at launch.
fn memfd_probe_script(remote: &RemoteBulwark) -> String {
    let cleanup_dir = remote
        .cleanup_dir()
        .expect("memfd probe must have a loader cleanup dir");
    let prelude = remote
        .prelude()
        .expect("memfd probe must stage a dependency-free loader");
    format!(
        "set -e\n{}\n{}\n{} __memfd-probe\n",
        cleanup_trap(cleanup_dir),
        prelude,
        remote.gate_invocation()
    )
}

fn memfd_supported(target: &str, payload_path: &Path, deploy_id: &str) -> Result<(), String> {
    let remote = memfd_remote(payload_path.to_path_buf(), deploy_id);
    let script = memfd_probe_script(&remote);
    match ssh_capture_with_payload(target, &script, payload_path) {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "memfd/fexecve sudo probe failed; requires noninteractive sudo, Linux memfd_create/fexecve, and an executable {REMOTE_SHM} loader/control dir: {}",
            output_reason(&o)
        )),
        Err(e) => Err(e.to_string()),
    }
}

fn shm_probe_script() -> String {
    let probe_dir = format!("{REMOTE_SHM}/{DEPLOY_DIR_PREFIX}-probe-$$");
    format!(
        r#"set -e
d="{probe_dir}"
{cleanup}
mkdir "$d"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$d/probe"
chmod 700 "$d/probe"
sudo -n "$d/probe"
"#,
        cleanup = cleanup_trap("$d")
    )
}

fn shm_supported(target: &str) -> Result<(), String> {
    match ssh_capture(target, &shm_probe_script()) {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "{REMOTE_SHM} is not writable and executable for the shm deploy rung (possible noexec mount): {}",
            output_reason(&o)
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// scp the local `bulwark` executable to a fresh remote temp dir and return the
/// remote path. Caller must have already verified `local_can_scp`.
fn deploy_via_scp(target: &str, deploy_id: &str) -> Result<(String, String)> {
    let local = std::env::current_exe().context("cannot locate local bulwark binary")?;
    let remote_dir = format!("{REMOTE_TMP}/{DEPLOY_DIR_PREFIX}-{VERSION}-{deploy_id}");
    let remote_bin = format!("{remote_dir}/bulwark");
    let mkdir = ssh_capture(target, &format!("mkdir -p {remote_dir}"))?;
    if !mkdir.status.success() {
        return Err(anyhow!("could not create remote dir {remote_dir}"));
    }
    let status = Command::new("scp")
        .args(SSH_OPTS)
        .arg(&local)
        .arg(format!("{target}:{remote_bin}"))
        .status()
        .with_context(|| format!("cannot scp bulwark to {target}"))?;
    if !status.success() {
        return Err(anyhow!("scp of bulwark to {target} failed"));
    }
    let chmod = ssh_capture(target, &format!("chmod +x {remote_bin}"))?;
    if !chmod.status.success() {
        return Err(anyhow!("could not chmod the deployed bulwark on {target}"));
    }
    Ok((remote_bin, remote_dir))
}

/// Build the remote shell snippet that fetches the dist tarball for `arch`,
/// verifies its sha256, and unpacks it. Echoes the resolved binary path on
/// success. Pure string-builder (no I/O) so it is unit-testable.
pub fn dist_fetch_script(version: &str, arch: &str, deploy_id: &str) -> Result<String> {
    let asset = dist_asset(version, arch)?;
    let url = dist_url(version, &asset);
    let sha_url = format!("{url}.sha256");
    let dir = format!("{REMOTE_TMP}/{DEPLOY_DIR_PREFIX}-{version}-{deploy_id}");
    // The tarball unpacks to a dir named like the asset minus `.tar.gz`.
    let unpacked = asset.trim_end_matches(".tar.gz");
    Ok(format!(
        r#"set -e
mkdir -p {dir}
cd {dir}
curl -fsSL {url} -o bulwark.tar.gz
curl -fsSL {sha_url} -o bulwark.tar.gz.sha256
# The sha256 file names the asset; verify against our downloaded tarball.
echo "$(cut -d' ' -f1 bulwark.tar.gz.sha256)  bulwark.tar.gz" | sha256sum -c -
tar xzf bulwark.tar.gz
echo {dir}/{unpacked}/bulwark
"#
    ))
}

/// Run the dist-fetch on the remote host and return the resolved remote binary
/// path. A checksum failure (or any step) makes the remote script exit non-zero,
/// which surfaces here as an error.
fn deploy_via_dist(target: &str, arch: &str, deploy_id: &str) -> Result<(String, String)> {
    let script = dist_fetch_script(VERSION, arch, deploy_id)?;
    let out = ssh_capture(target, &script)?;
    if !out.status.success() {
        return Err(anyhow!(
            "dist-fetch of bulwark on {target} failed (checksum or download): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // The script echoes the resolved path on its last line.
    let path = String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap_or("")
        .trim()
        .to_string();
    if path.is_empty() {
        return Err(anyhow!("dist-fetch on {target} produced no binary path"));
    }
    let cleanup_dir = format!("{REMOTE_TMP}/{DEPLOY_DIR_PREFIX}-{VERSION}-{deploy_id}");
    Ok((path, cleanup_dir))
}

fn env_streamable_gate() -> Option<PathBuf> {
    std::env::var_os(STREAMABLE_GATE_ENV).map(PathBuf::from)
}

fn sibling_streamable_candidates(target: &str) -> Vec<PathBuf> {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    vec![
        dir.join(format!("bulwark-{target}")),
        dir.join(format!("bulwark-{VERSION}-{target}"))
            .join("bulwark"),
        dir.join("gates").join(format!("bulwark-{target}")),
    ]
}

fn current_exe_is_streamable_for(remote: &RemotePlatform) -> bool {
    if !(cfg!(target_os = "linux") && cfg!(target_env = "musl")) {
        return false;
    }
    matches!(
        normalized_arch(&remote.arch),
        Ok(remote_arch) if remote_arch == std::env::consts::ARCH
    )
}

fn sha256_hex(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn verify_sha256_file(tarball: &Path, sha_file: &Path) -> Result<()> {
    let expected = std::fs::read_to_string(sha_file)
        .with_context(|| format!("read {}", sha_file.display()))?
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("empty sha256 file {}", sha_file.display()))?
        .to_string();
    let actual = sha256_hex(tarball)?;
    if actual != expected {
        return Err(anyhow!(
            "checksum mismatch for {}: expected {expected}, got {actual}",
            tarball.display()
        ));
    }
    Ok(())
}

fn run_local(cmd: &mut Command, label: &str) -> Result<()> {
    let status = cmd.status().with_context(|| format!("run local {label}"))?;
    if !status.success() {
        return Err(anyhow!("local {label} exited {:?}", status.code()));
    }
    Ok(())
}

fn fetch_streamable_gate(version: &str, target: &str) -> Result<PathBuf> {
    let asset = format!("bulwark-{version}-{target}.tar.gz");
    let url = dist_url(version, &asset);
    let sha_url = format!("{url}.sha256");
    let cache = std::env::temp_dir().join(format!("{DEPLOY_DIR_PREFIX}-stream-{version}-{target}"));
    let tarball = cache.join(&asset);
    let sha_file = cache.join(format!("{asset}.sha256"));
    let unpacked = cache.join(asset.trim_end_matches(".tar.gz"));
    let binary = unpacked.join("bulwark");

    if binary.exists() {
        return Ok(binary);
    }

    std::fs::create_dir_all(&cache).with_context(|| format!("create {}", cache.display()))?;
    run_local(
        Command::new("curl")
            .args(["-fsSL", &url, "-o"])
            .arg(&tarball),
        "curl streamable gate",
    )?;
    run_local(
        Command::new("curl")
            .args(["-fsSL", &sha_url, "-o"])
            .arg(&sha_file),
        "curl streamable gate checksum",
    )?;
    verify_sha256_file(&tarball, &sha_file)?;
    run_local(
        Command::new("tar")
            .arg("xzf")
            .arg(&tarball)
            .arg("-C")
            .arg(&cache),
        "untar streamable gate",
    )?;
    if !binary.exists() {
        return Err(anyhow!(
            "dist asset {asset} did not contain expected binary {}",
            binary.display()
        ));
    }
    Ok(binary)
}

fn streamable_gate_path(platform: &RemotePlatform) -> Result<PathBuf> {
    if platform.os != "Linux" {
        return Err(anyhow!("memfd/shm deploy only supports Linux remotes"));
    }
    let target = target_triple(&platform.arch)?;

    if let Some(path) = env_streamable_gate() {
        if path.exists() {
            return Ok(path);
        }
        return Err(anyhow!(
            "{STREAMABLE_GATE_ENV} points to missing file {}",
            path.display()
        ));
    }

    for candidate in sibling_streamable_candidates(target) {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    if current_exe_is_streamable_for(platform) {
        return std::env::current_exe().context("locate current static bulwark executable");
    }

    fetch_streamable_gate(VERSION, target)
        .with_context(|| format!("prepare local static gate payload for {target}"))
}

fn memfd_remote(payload_path: PathBuf, deploy_id: &str) -> RemoteBulwark {
    let remote_dir = format!("{REMOTE_SHM}/{DEPLOY_DIR_PREFIX}-{VERSION}-{deploy_id}");
    let remote_loader = format!("{remote_dir}/bulwark-loader");
    let prelude =
        format!("mkdir -p {remote_dir}\ncat > {remote_loader}\nchmod 700 {remote_loader}");
    // No remote Python/runtime dependency; the streamed static gate
    // becomes the tiny loader that copies itself into memfd and fexecve's it.
    let plain_invocation = memfd_exec_invocation(&remote_loader);
    let gate_invocation = format!("sudo -n {plain_invocation}");
    RemoteBulwark {
        source: DeploySource::Memfd,
        plain_invocation,
        gate_invocation,
        payload_path: Some(payload_path),
        prelude: Some(prelude),
        cleanup_dir: Some(remote_dir),
        run_dir_base: REMOTE_SHM,
    }
}

fn shm_remote(payload_path: PathBuf, deploy_id: &str) -> RemoteBulwark {
    let remote_dir = format!("{REMOTE_SHM}/{DEPLOY_DIR_PREFIX}-{VERSION}-{deploy_id}");
    let remote_bin = format!("{remote_dir}/bulwark");
    let prelude = format!("mkdir -p {remote_dir}\ncat > {remote_bin}\nchmod 700 {remote_bin}");
    RemoteBulwark {
        source: DeploySource::Shm,
        plain_invocation: remote_bin.clone(),
        gate_invocation: format!("sudo -n {remote_bin}"),
        payload_path: Some(payload_path),
        prelude: Some(prelude),
        cleanup_dir: Some(remote_dir),
        run_dir_base: REMOTE_SHM,
    }
}

fn path_remote(source: DeploySource, path: String, cleanup_dir: Option<String>) -> RemoteBulwark {
    RemoteBulwark {
        source,
        plain_invocation: path.clone(),
        gate_invocation: format!("sudo {path}"),
        payload_path: None,
        prelude: None,
        cleanup_dir,
        run_dir_base: REMOTE_TMP,
    }
}

/// Resolve a runnable remote `bulwark`, honoring the deploy mode. Returns the
/// shell plan the launcher should invoke.
pub fn resolve_remote_bulwark(
    target: &str,
    mode: DeployMode,
    deploy_id: &str,
) -> Result<RemoteBulwark> {
    // `never`: require an existing remote binary, deploy nothing.
    if mode == DeployMode::Never {
        if remote_has_bulwark(target) {
            return Ok(path_remote(
                DeploySource::Existing,
                "bulwark".to_string(),
                None,
            ));
        }
        return Err(anyhow!(
            "no bulwark on {target} and --deploy never set; install it or use --deploy auto"
        ));
    }

    let platform = detect_platform(target)?;

    match mode {
        DeployMode::Memfd => {
            let payload = streamable_gate_path(&platform)?;
            if let Err(reason) = memfd_supported(target, &payload, deploy_id) {
                return Err(anyhow!(
                    "--deploy memfd requested but {target} cannot run the dependency-free memfd/fexecve loader: {reason}"
                ));
            }
            eprintln!("[bulwark] deploy rung: memfd on {target}");
            Ok(memfd_remote(payload, deploy_id))
        }
        DeployMode::Shm => {
            if let Err(reason) = shm_supported(target) {
                return Err(anyhow!(
                    "--deploy shm requested but {target} has no writable and executable {REMOTE_SHM} rung: {reason}"
                ));
            }
            let payload = streamable_gate_path(&platform)?;
            eprintln!("[bulwark] deploy rung: /dev/shm on {target}");
            Ok(shm_remote(payload, deploy_id))
        }
        DeployMode::Scp => {
            if !local_can_scp(&platform) {
                return Err(anyhow!(
                    "--deploy scp requested but local {}/{} cannot run on remote {}/{}",
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                    platform.os,
                    platform.arch
                ));
            }
            eprintln!("[bulwark] deploying local bulwark to {target} via scp");
            let (path, cleanup_dir) = deploy_via_scp(target, deploy_id)?;
            Ok(path_remote(DeploySource::Scp, path, Some(cleanup_dir)))
        }
        DeployMode::Dist => {
            eprintln!(
                "[bulwark] WARNING: --deploy dist is a last-resort fallback; it fetches on the remote and leaves traces until teardown"
            );
            eprintln!("[bulwark] fetching bulwark v{VERSION} on {target} from dist");
            let (path, cleanup_dir) = deploy_via_dist(target, &platform.arch, deploy_id)?;
            Ok(path_remote(DeploySource::Dist, path, Some(cleanup_dir)))
        }
        DeployMode::Auto => {
            match streamable_gate_path(&platform) {
                Ok(payload) => match memfd_supported(target, &payload, deploy_id) {
                    Ok(()) => {
                        eprintln!("[bulwark] deploy rung: memfd on {target}");
                        return Ok(memfd_remote(payload, deploy_id));
                    }
                    Err(reason) => {
                        eprintln!("[bulwark] WARN memfd rung unavailable: {reason}");
                    }
                },
                Err(e) => {
                    eprintln!("[bulwark] WARN streamable gate unavailable for memfd/shm: {e}");
                }
            }
            match shm_supported(target) {
                Ok(()) => match streamable_gate_path(&platform) {
                    Ok(payload) => {
                        eprintln!("[bulwark] deploy rung: /dev/shm on {target}");
                        return Ok(shm_remote(payload, deploy_id));
                    }
                    Err(e) => {
                        eprintln!("[bulwark] WARN /dev/shm rung unavailable: {e}");
                    }
                },
                Err(reason) => {
                    eprintln!("[bulwark] WARN /dev/shm rung unavailable: {reason}");
                }
            }
            if remote_has_bulwark(target) {
                eprintln!("[bulwark] deploy rung: existing remote bulwark on {target}");
                return Ok(path_remote(
                    DeploySource::Existing,
                    "bulwark".to_string(),
                    None,
                ));
            }
            eprintln!(
                "[bulwark] WARNING: dist is the last-resort deploy rung and leaves remote traces until teardown"
            );
            eprintln!("[bulwark] fetching bulwark v{VERSION} on {target} from dist");
            let (path, cleanup_dir) = deploy_via_dist(target, &platform.arch, deploy_id)?;
            Ok(path_remote(DeploySource::Dist, path, Some(cleanup_dir)))
        }
        DeployMode::Never => unreachable!("handled above"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_mode_parses_known_values() {
        assert_eq!(DeployMode::parse("auto"), Some(DeployMode::Auto));
        assert_eq!(DeployMode::parse("never"), Some(DeployMode::Never));
        assert_eq!(DeployMode::parse("memfd"), Some(DeployMode::Memfd));
        assert_eq!(DeployMode::parse("shm"), Some(DeployMode::Shm));
        assert_eq!(DeployMode::parse("scp"), Some(DeployMode::Scp));
        assert_eq!(DeployMode::parse("dist"), Some(DeployMode::Dist));
        assert_eq!(DeployMode::parse("nonsense"), None);
    }

    #[test]
    fn parse_uname_splits_os_and_arch() {
        let p = RemotePlatform::parse_uname("Linux x86_64").unwrap();
        assert_eq!(p.os, "Linux");
        assert_eq!(p.arch, "x86_64");
        assert!(RemotePlatform::parse_uname("").is_none());
    }

    #[test]
    fn target_triple_maps_known_arches() {
        assert_eq!(
            target_triple("x86_64").unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(target_triple("amd64").unwrap(), "x86_64-unknown-linux-musl");
        assert_eq!(
            target_triple("aarch64").unwrap(),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            target_triple("arm64").unwrap(),
            "aarch64-unknown-linux-musl"
        );
        assert!(target_triple("riscv64").is_err());
    }

    #[test]
    fn dist_asset_matches_release_naming() {
        assert_eq!(
            dist_asset("0.5.0", "x86_64").unwrap(),
            "bulwark-0.5.0-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            dist_asset("0.5.0", "aarch64").unwrap(),
            "bulwark-0.5.0-aarch64-unknown-linux-musl.tar.gz"
        );
        assert!(dist_asset("0.5.0", "mips").is_err());
    }

    #[test]
    fn dist_url_points_at_tagged_release() {
        let url = dist_url("0.5.0", "bulwark-0.5.0-x86_64-unknown-linux-musl.tar.gz");
        assert_eq!(
            url,
            "https://github.com/obstalabs/bulwark-dist/releases/download/v0.5.0/bulwark-0.5.0-x86_64-unknown-linux-musl.tar.gz"
        );
    }

    #[test]
    fn dist_fetch_script_verifies_checksum_and_echoes_path() {
        let s = dist_fetch_script("0.5.0", "x86_64", "abc123").unwrap();
        // Pulls both the tarball and its sha256, and verifies with sha256sum -c.
        assert!(s.contains("bulwark-0.5.0-x86_64-unknown-linux-musl.tar.gz"));
        assert!(s.contains("/tmp/bulwark-deploy-0.5.0-abc123"));
        assert!(s.contains("sha256sum -c -"));
        assert!(s.contains("set -e")); // any failed step aborts
                                       // Echoes the resolved binary path as the last line for the caller.
        assert!(s.contains("/bulwark"));
        assert!(dist_fetch_script("0.5.0", "sparc", "abc123").is_err());
    }

    #[test]
    fn memfd_invocation_uses_dependency_free_fexecve_loader() {
        let r = memfd_remote(PathBuf::from("/tmp/static-bulwark"), "run42");
        assert_eq!(r.source(), DeploySource::Memfd);
        assert!(r.needs_binary_stdin());
        assert!(!r.gate_invocation().contains("python3"));
        assert!(r.gate_invocation().contains("__memfd-exec"));
        assert!(r.gate_invocation().contains("bulwark-loader"));
        assert!(r
            .prelude()
            .unwrap()
            .contains("cat > /dev/shm/bulwark-deploy-"));
        let expected_cleanup = format!("/dev/shm/bulwark-deploy-{VERSION}-run42");
        assert_eq!(r.cleanup_dir(), Some(expected_cleanup.as_str()));
        assert_eq!(r.run_dir_base(), "/dev/shm");
    }

    #[test]
    fn memfd_probe_exercises_loader_and_removes_probe_dir() {
        let r = memfd_remote(PathBuf::from("/tmp/static-bulwark"), "probe42");
        let s = memfd_probe_script(&r);
        assert!(s.contains("trap cleanup EXIT INT TERM HUP"));
        assert!(s.contains(r.gate_invocation()));
        assert!(s.contains("sudo -n"));
        assert!(s.contains("__memfd-exec"));
        assert!(s.contains("__memfd-probe"));
        assert!(s.contains("rm -rf /dev/shm/bulwark-deploy-"));
        assert!(!s.contains("python3"));
    }

    #[test]
    fn shm_probe_executes_from_dev_shm_to_detect_noexec() {
        let s = shm_probe_script();
        assert!(s.contains("/dev/shm/bulwark-deploy-probe-$$"));
        assert!(s.contains("chmod 700 \"$d/probe\""));
        assert!(s.contains("sudo -n \"$d/probe\""));
        assert!(s.contains("rm -rf $d"));
    }

    #[test]
    fn shm_remote_writes_payload_before_exec() {
        let r = shm_remote(PathBuf::from("/tmp/static-bulwark"), "run42");
        assert_eq!(r.source(), DeploySource::Shm);
        assert!(r.needs_binary_stdin());
        let prelude = r.prelude().unwrap();
        assert!(prelude.contains("cat > /dev/shm/bulwark-deploy-"));
        assert!(prelude.contains("chmod 700"));
        let expected_cleanup = format!("/dev/shm/bulwark-deploy-{VERSION}-run42");
        assert_eq!(r.cleanup_dir(), Some(expected_cleanup.as_str()));
    }

    #[test]
    fn local_can_scp_rejects_cross_os() {
        // A macOS host can never scp-and-run on Linux, regardless of arch.
        let linux_x86 = RemotePlatform {
            os: "Linux".into(),
            arch: "x86_64".into(),
        };
        let expected =
            std::env::consts::OS == "linux" && matches!(std::env::consts::ARCH, "x86_64");
        assert_eq!(local_can_scp(&linux_x86), expected);

        // A non-Linux remote is never scp-compatible from any local OS.
        let darwin = RemotePlatform {
            os: "Darwin".into(),
            arch: "arm64".into(),
        };
        assert!(!local_can_scp(&darwin));
    }
}
