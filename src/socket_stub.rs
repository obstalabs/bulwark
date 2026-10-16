//! Non-Linux stub of the consent socket.
//!
//! WO-28: fail-closed platform stub for the cfg-split consent socket seam.
//!
//! The real `socket.rs` binds a Unix socket and authenticates the operator via
//! `SO_PEERCRED` (Linux-specific). This stub mirrors its public surface so the
//! portable core compiles everywhere; the socket consent transport is only
//! available where the gate runs (Linux today).
//!
//! Fail-closed: `bind` refuses, and the stub `ConsentProvider` denies.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};

use crate::consent::{ConsentProvider, ConsentRequest, Source, Verdict};

const SOCKET_UNAVAILABLE: &str = "the consent socket is not available on this platform yet \
             (it is part of the Linux gate; see bulwark/WO-26 for the macOS gate)";

// WO-30@v1: return the same fail-closed error from every unsupported socket path.
fn unavailable<T>() -> Result<T> {
    bail!(SOCKET_UNAVAILABLE)
}

/// WO-30: let callers reject socket consent before recording a supervised run.
pub fn ensure_available() -> Result<()> {
    unavailable()
}

// WO-30@v1: preserve the provider type without starting an unsupported run.
/// Mirror of `socket::SocketProvider`. Constructing one is refused on platforms
/// without the gate; the type exists so `main` type-checks identically.
pub struct SocketProvider;

// WO-30@v1: expose the portable provider surface while refusing construction.
impl SocketProvider {
    // WO-30@v1: refuse socket consent before recording supervised-run state.
    /// Fail-closed stand-in for `SocketProvider::bind`.
    pub fn bind(_path: &Path, _supervised_root: i32, _timeout: Duration) -> Result<Self> {
        unavailable()
    }
}

// WO-30@v1: satisfy the consent interface without permitting unsupported opens.
impl ConsentProvider for SocketProvider {
    // WO-30@v1: deny if an unsupported provider is ever asked for a decision.
    /// Never reached (bind refuses), but required to match the Linux type. Deny.
    fn request(&mut self, _req: &ConsentRequest) -> (Verdict, Source) {
        (Verdict::Deny, Source::Static)
    }
}

// WO-30@v1: refuse operator answers where the consent socket is unavailable.
/// Fail-closed stand-in for `socket::answer_once`.
pub fn answer_once(_socket: &Path, _verdict: Option<Verdict>) -> Result<String> {
    bail!("the consent socket is not available on this platform yet (Linux gate only)")
}
