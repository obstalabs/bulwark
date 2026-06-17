//! Non-Linux stub of the Landlock hardened read-floor.
//!
//! fail-closed platform stub for the cfg-split hardened seam.
//!
//! `hardened.rs` applies a Landlock LSM ruleset (Linux 5.13+) as a crash-safe
//! kernel-enforced read floor. This stub mirrors its public surface so the
//! portable core compiles everywhere; `--hardened` is only available where
//! Landlock exists (Linux).
//!
//! Fail-closed: refuses rather than silently applying no restriction.

use anyhow::{bail, Result};

/// Mirror of `hardened::abi_version` for the cfg-split surface. No Landlock off
/// Linux, so the ABI is always absent.
pub fn abi_version() -> Option<i32> {
    None
}

/// Fail-closed stand-in for `hardened::apply_read_floor`. The real function
/// installs a Landlock ruleset; with no Landlock on this platform we refuse so
/// the caller never believes a floor was applied when none was.
pub fn apply_read_floor(_allow_paths: &[String]) -> Result<()> {
    bail!(
        "hardened mode (Landlock read floor) is not available on this platform — \
         it requires Linux 5.13+. The macOS enforcement floor is tracked in bulwark/."
    )
}
