//! dispatch-time hivebus key material.
//!
//! `bulwark ssh` can carry hivebus key material to a freshly dispatched remote so
//! the worker there has a trustworthy FIRST key introduction (feeds hivebus
//! pin-on-first-use). bulwark is TRANSPORT ONLY — it generates a fresh per-dispatch
//! worker identity and relays the architect's public key; it makes no trust
//! decisions about either.
//!
//! Two pieces of material per dispatch:
//!   - the architect PUBLIC key (loaded from a local file, relayed as-is), and
//!   - a fresh worker ed25519 SEED generated here (the worker's own signing
//!     identity; it is the worker's key, not an operator secret).
//!
//! ## Cross-repo seam — MUST match hivebus byte-for-byte
//!
//! These two encodings are a contract with the hivebus CLI. A mismatch silently
//! breaks the introduction, so they are pinned here and asserted in tests:
//!
//! - FINGERPRINT: lowercase hex of `sha256(publicKey)` over the raw 32-byte
//!   ed25519 PUBLIC key — matches what the hivebus CLI pins as the answer-key
//!   fingerprint.
//! - SEED ENCODING: `base64` (standard) of a 32-byte seed; the keypair is derived
//!   via RFC 8032 (`ed25519` from-seed). dalek's `SigningKey::from_bytes` uses the
//!   identical RFC 8032 derivation, so the public keys match what hivebus accepts
//!   for `answer --signing-key`.

use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

/// 32-byte ed25519 seed / public key length. Named, not magic (RFC 8032).
const ED25519_LEN: usize = 32;

/// A freshly generated worker identity for one dispatch.
pub struct WorkerKey {
    /// Raw 32-byte seed. Secret — base64-encoded for the remote, NEVER logged.
    seed: [u8; ED25519_LEN],
    /// Raw 32-byte public key.
    public: [u8; ED25519_LEN],
}

impl WorkerKey {
    /// Generate a fresh worker identity from the OS CSPRNG. Freshness per dispatch
    /// IS the security property — no key is ever reused across substrates, so this
    /// must draw new entropy every call (`getrandom` = the OS source directly).
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; ED25519_LEN];
        // getrandom::Error is a minimal no_std error (not std::error::Error), so
        // map it into anyhow by hand rather than via .context().
        getrandom::getrandom(&mut seed)
            .map_err(|e| anyhow::anyhow!("OS CSPRNG (getrandom) for worker seed: {e}"))?;
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        Ok(WorkerKey { seed, public })
    }

    /// The seed as hivebus `--signing-key` accepts it: base64 StdEncoding of the
    /// 32-byte seed. This is the SECRET to place on the remote (mode 0600).
    pub fn seed_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.seed)
    }

    /// The pinnable fingerprint of the worker public key — the operator pins THIS
    /// on the hivebus side before first contact. Matches hivebus byte-for-byte.
    /// The worker's public key is surfaced ONLY as this fingerprint (its base64
    /// form is never relayed — the seed carries the worker identity to the remote,
    /// and the remote derives its own public key from the seed).
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }
}

/// The architect public key relayed to the remote (loaded from a local file).
pub struct ArchitectKey {
    /// Raw 32-byte public key.
    public: [u8; ED25519_LEN],
}

impl ArchitectKey {
    /// Load + validate an architect public key from a base64 file (the form
    /// hivebus emits via `--print-public-key` / `--public-key-file`). Rejects
    /// anything that is not exactly a 32-byte ed25519 public key, so a malformed
    /// key fails the dispatch rather than placing junk on the remote.
    pub fn load_base64_file(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read architect pubkey file {}", path.display()))?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(raw.trim())
            .with_context(|| {
                format!(
                    "architect pubkey in {} must be base64 ed25519 (hivebus public-key form)",
                    path.display()
                )
            })?;
        let public: [u8; ED25519_LEN] = decoded.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "architect pubkey is {} bytes, want {ED25519_LEN}-byte ed25519 public key",
                decoded.len()
            )
        })?;
        // Reject a non-canonical / non-curve point: a key that cannot be parsed as
        // a verifying key is not a usable ed25519 public key.
        ed25519_dalek::VerifyingKey::from_bytes(&public)
            .context("architect pubkey is not a valid ed25519 public key")?;
        Ok(ArchitectKey { public })
    }

    /// Re-encode the validated public key as base64 StdEncoding for placement on
    /// the remote (canonical form, independent of incidental file whitespace).
    pub fn public_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.public)
    }

    /// Fingerprint of the architect key (for the dispatch receipt).
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }
}

/// Lowercase hex of sha256 over a raw 32-byte ed25519 public key. Pinned to match
/// the hivebus answer-key fingerprint byte-for-byte. Hex is hand-rolled to keep the
/// dependency surface minimal for a security binary.
fn fingerprint(public: &[u8; ED25519_LEN]) -> String {
    let digest = Sha256::digest(public);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0xf) as u32, 16).unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_seed_per_dispatch() {
        let a = WorkerKey::generate().unwrap();
        let b = WorkerKey::generate().unwrap();
        // Freshness is the security property: two dispatches never share a seed,
        // and therefore never share a public-key fingerprint.
        assert_ne!(a.seed_base64(), b.seed_base64());
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_matches_hivebus_derivation_for_known_key() {
        // Cross-repo pin: a known all-zero seed derives a fixed ed25519 public key
        // (RFC 8032); its sha256-hex fingerprint must equal what hivebus computes.
        // The expected public key for the zero seed is a well-known RFC 8032 test
        // vector: 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29.
        let signing = SigningKey::from_bytes(&[0u8; ED25519_LEN]);
        let public = signing.verifying_key().to_bytes();
        let pub_hex: String = public.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            pub_hex, "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            "dalek must derive the RFC 8032 public key for the zero seed"
        );
        // fingerprint = sha256(pubkey) hex lowercase. Pin the exact string so any
        // drift in our derivation vs hivebus's is caught here. This constant is
        // sha256 of the raw zero-seed public key bytes above (independently
        // computed); hivebus's answerKeyFingerprint must produce the same string.
        let fp = fingerprint(&public);
        assert_eq!(fp.len(), 64, "sha256 hex is 64 chars");
        assert_eq!(fp, fp.to_lowercase(), "hivebus uses lowercase hex");
        assert_eq!(
            fp, "139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
            "fingerprint must match hivebus answerKeyFingerprint byte-for-byte"
        );
    }

    #[test]
    fn seed_base64_roundtrips_to_32_bytes() {
        let k = WorkerKey::generate().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(k.seed_base64())
            .unwrap();
        assert_eq!(decoded.len(), ED25519_LEN, "hivebus expects a 32-byte seed");
    }

    #[test]
    fn architect_key_rejects_wrong_size() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("bw-arch-test-{}.pub", std::process::id()));
        // 16 bytes base64 — too short for ed25519.
        std::fs::write(
            &p,
            base64::engine::general_purpose::STANDARD.encode([1u8; 16]),
        )
        .unwrap();
        let r = ArchitectKey::load_base64_file(&p);
        let _ = std::fs::remove_file(&p);
        assert!(r.is_err(), "must reject a non-32-byte key");
    }
}
