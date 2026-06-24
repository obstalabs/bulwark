//! Non-Linux stub of the fanotify gate.
//!
//! fail-closed platform stub for the cfg-split gate seam.
//!
//! Bulwark's enforcement gate is Linux-only (fanotify `FAN_OPEN_PERM`). This
//! stub mirrors the public surface of `gate.rs` so the portable core (CLI,
//! config, policy, audit, consent) compiles and runs on every platform, while
//! the actual gate is supplied per-OS.
//!
//! It is **fail-closed**: `run` does not execute the supervised command. It
//! refuses with a clear error pointing at the macOS gate work. A stub
//! that silently ran the command unprotected would be the "I thought it was
//! protected" trap one layer down — so it runs nothing at all.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::allowlist::AllowList;
use crate::consent::{ConsentRequest, Source, Verdict};
use crate::protect::ProtectedSet;

/// Mirror of `gate::GateMode`. Same shape so `main` builds the same value on
/// every platform; only the implementation behind `run` differs.
pub enum GateMode<'a> {
    DenyList {
        protected: &'a ProtectedSet,
        consent: &'a mut dyn ConsentDecider,
    },
    AllowList {
        allow: &'a AllowList,
    },
}

/// Mirror of `gate::ConsentDecider`. The portable `consent::CachingProvider`
/// implements this trait, so it must exist on every platform.
pub trait ConsentDecider {
    fn decide(&mut self, req: &ConsentRequest) -> (Verdict, Source);

    /// Mirror of the enforcing gates' trait so the shared `CachingProvider` impl
    /// type-checks on unsupported platforms. No-op (no enforcement here).
    fn bind_scope(&mut self, _scope_rel: Option<&str>) {}
}

/// Whether a graceful-termination signal has been received. On platforms
/// without the fanotify supervisor there is no event loop to fail closed, so
/// this is always false; it exists to match `gate::shutdown_requested`.
pub(crate) fn shutdown_requested() -> bool {
    false
}

/// Credentials to drop the supervised child to before exec. Present to match the
/// Linux/macOS gate surface; unused here (this stub never launches a child).
#[derive(Clone, Copy)]
pub struct WorkerCreds {
    pub uid: u32,
    pub gid: u32,
}

/// Fail-closed stand-in for `gate::run`. The real gate forks the command under
/// a kernel read-gate; with no gate available on this platform we refuse rather
/// than run the command unprotected.
pub fn run(
    _mode: GateMode,
    _mark_paths: &[PathBuf],
    _receipts: Option<&Path>,
    _command: &[String],
    _worker: Option<WorkerCreds>,
) -> Result<i32> {
    bail!(
        "the kernel read-gate is not implemented on this platform yet — \
         bulwark refuses to run an agent ungated (see bulwark/, macOS Endpoint Security gate). \
         The Linux fanotify gate is available on Linux."
    )
}
