//! Remote binary auto-deploy for `bulwark ssh`.
//!
//! `bulwark ssh` enforces on the remote kernel, which means the `bulwark` binary
//! must be present on the remote host. The prototype assumed it was already
//! installed. This module bootstraps it when it is not, with two paths and a
//! strict order:
//!
//! 1. **Already present** — if the remote has a compatible `bulwark` on `PATH`,
//!    use it. No deploy.
//! 2. **scp the local binary** — only when the LOCAL executable is itself Linux
//!    and arch-matches the remote (air-gapped / private-network case). Never scp
//!    a macOS binary to Linux: a local binary is valid on the remote only when
//!    the OS and arch match.
//! 3. **Remote dist-fetch** — the remote downloads the pinned `bulwark-dist`
//!    release tarball for its arch, verifies the sha256, and unpacks it. This is
//!    the normal path for the common arm64-Mac → x86_64-Linux case.
//! 4. **Fail** — with a clear manual-install message.
//!
//! The deploy version is pinned to this binary's own version, so the remote gate
//! and the local launcher always speak the same wire protocol.

use anyhow::{anyhow, Result};

/// The release version this binary was built from. The dist-fetch path pulls the
/// matching release so local and remote never skew.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Public dist repo that holds the release tarballs.
pub const DIST_REPO: &str = "obstalabs/bulwark-dist";

/// How `bulwark ssh` is allowed to obtain the remote binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployMode {
    /// Default: use existing remote bulwark, else scp if possible, else dist.
    Auto,
    /// Require an existing remote bulwark; never deploy.
    Never,
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

impl RemotePlatform {
    /// Parse the output of `uname -s -m` (e.g. `"Linux x86_64"`).
    pub fn parse_uname(s: &str) -> Option<Self> {
        let mut parts = s.split_whitespace();
        let os = parts.next()?.to_string();
        let arch = parts.next()?.to_string();
        Some(RemotePlatform { os, arch })
    }
}

/// Map a `uname -m` arch to its Rust release target triple, matching the names
/// produced by `release.yml`. Returns an error for an arch we do not publish.
pub fn target_triple(arch: &str) -> Result<&'static str> {
    match arch {
        "x86_64" | "amd64" => Ok("x86_64-unknown-linux-gnu"),
        "aarch64" | "arm64" => Ok("aarch64-unknown-linux-gnu"),
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
    // Normalize both sides to a target triple so x86_64==amd64, aarch64==arm64.
    let local_triple = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        _ => return false,
    };
    matches!(target_triple(&remote.arch), Ok(t) if t == local_triple)
}

// ---- I/O layer: probing and deploying over ssh/scp ------------------------

use anyhow::Context;
use std::process::Command;

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

/// scp the local `bulwark` executable to a fresh remote temp dir and return the
/// remote path. Caller must have already verified `local_can_scp`.
fn deploy_via_scp(target: &str) -> Result<String> {
    let local = std::env::current_exe().context("cannot locate local bulwark binary")?;
    // A per-deploy remote dir, named by version to avoid clobbering.
    let remote_dir = format!("/tmp/bulwark-deploy-{VERSION}");
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
    Ok(remote_bin)
}

/// Build the remote shell snippet that fetches the dist tarball for `arch`,
/// verifies its sha256, and unpacks it. Echoes the resolved binary path on
/// success. Pure string-builder (no I/O) so it is unit-testable.
pub fn dist_fetch_script(version: &str, arch: &str) -> Result<String> {
    let asset = dist_asset(version, arch)?;
    let url = dist_url(version, &asset);
    let sha_url = format!("{url}.sha256");
    let dir = format!("/tmp/bulwark-deploy-{version}");
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
fn deploy_via_dist(target: &str, arch: &str) -> Result<String> {
    let script = dist_fetch_script(VERSION, arch)?;
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
    Ok(path)
}

/// Resolve a runnable remote `bulwark`, honoring the deploy mode. Returns the
/// remote command/path to invoke (`"bulwark"` when already present, or a
/// temp-dir path when deployed).
pub fn ensure_remote_bulwark(target: &str, mode: DeployMode) -> Result<String> {
    // `never`: require an existing remote binary, deploy nothing.
    if mode == DeployMode::Never {
        if remote_has_bulwark(target) {
            return Ok("bulwark".to_string());
        }
        return Err(anyhow!(
            "no bulwark on {target} and --deploy never set; install it or use --deploy auto"
        ));
    }

    // `auto`: an existing remote binary wins before any deploy.
    if mode == DeployMode::Auto && remote_has_bulwark(target) {
        eprintln!("[bulwark] remote {target} already has bulwark");
        return Ok("bulwark".to_string());
    }

    let platform = detect_platform(target)?;

    match mode {
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
            deploy_via_scp(target)
        }
        DeployMode::Dist => {
            eprintln!("[bulwark] fetching bulwark v{VERSION} on {target} from dist");
            deploy_via_dist(target, &platform.arch)
        }
        DeployMode::Auto => {
            if local_can_scp(&platform) {
                eprintln!("[bulwark] deploying local bulwark to {target} via scp");
                deploy_via_scp(target)
            } else {
                eprintln!(
                    "[bulwark] local {}/{} cannot run on remote {}/{}; fetching v{VERSION} from dist",
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                    platform.os,
                    platform.arch
                );
                deploy_via_dist(target, &platform.arch)
            }
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
        assert_eq!(target_triple("x86_64").unwrap(), "x86_64-unknown-linux-gnu");
        assert_eq!(target_triple("amd64").unwrap(), "x86_64-unknown-linux-gnu");
        assert_eq!(
            target_triple("aarch64").unwrap(),
            "aarch64-unknown-linux-gnu"
        );
        assert_eq!(target_triple("arm64").unwrap(), "aarch64-unknown-linux-gnu");
        assert!(target_triple("riscv64").is_err());
    }

    #[test]
    fn dist_asset_matches_release_naming() {
        assert_eq!(
            dist_asset("0.5.0", "x86_64").unwrap(),
            "bulwark-0.5.0-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            dist_asset("0.5.0", "aarch64").unwrap(),
            "bulwark-0.5.0-aarch64-unknown-linux-gnu.tar.gz"
        );
        assert!(dist_asset("0.5.0", "mips").is_err());
    }

    #[test]
    fn dist_url_points_at_tagged_release() {
        let url = dist_url("0.5.0", "bulwark-0.5.0-x86_64-unknown-linux-gnu.tar.gz");
        assert_eq!(
            url,
            "https://github.com/obstalabs/bulwark-dist/releases/download/v0.5.0/bulwark-0.5.0-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[test]
    fn dist_fetch_script_verifies_checksum_and_echoes_path() {
        let s = dist_fetch_script("0.5.0", "x86_64").unwrap();
        // Pulls both the tarball and its sha256, and verifies with sha256sum -c.
        assert!(s.contains("bulwark-0.5.0-x86_64-unknown-linux-gnu.tar.gz"));
        assert!(s.contains("sha256sum -c -"));
        assert!(s.contains("set -e")); // any failed step aborts
                                       // Echoes the resolved binary path as the last line for the caller.
        assert!(s.contains("/bulwark"));
        assert!(dist_fetch_script("0.5.0", "sparc").is_err());
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
