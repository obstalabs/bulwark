//! Per-decision receipts.
//!
//! Every gate decision is logged: time, pid, ancestry, dev+inode, decision,
//! and the path observed at the moment of the open. Written as JSON lines so
//! the log is greppable and append-only. Receipts never contain file content.
//!
//! JSON is hand-rolled (one flat object, known fields) to keep the dependency
//! surface minimal for a security-layer binary.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        }
    }
}

/// One audit record for a single gated open().
pub struct Receipt<'a> {
    pub pid: i32,
    pub dev: u64,
    pub ino: u64,
    pub decision: Decision,
    pub path: &'a str,
    pub ancestry: &'a str,
    pub reason: &'a str,
    /// How the decision was reached (operator/cache/timeout/static), or "" when
    /// not applicable (e.g. a plain allow of an unprotected file).
    pub source: &'a str,
}

/// Escape a string for embedding in a JSON double-quoted value.
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

fn now_unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

impl Receipt<'_> {
    /// Serialize to a single JSON line (no trailing newline).
    pub fn to_json_line(&self) -> String {
        format!(
            r#"{{"ts_ms":{ts},"pid":{pid},"dev":{dev},"ino":{ino},"decision":"{dec}","source":"{src}","path":"{path}","ancestry":"{anc}","reason":"{reason}"}}"#,
            ts = now_unix_millis(),
            pid = self.pid,
            dev = self.dev,
            ino = self.ino,
            dec = self.decision.as_str(),
            src = json_escape(self.source),
            path = json_escape(self.path),
            anc = json_escape(self.ancestry),
            reason = json_escape(self.reason),
        )
    }
}

/// one record for a dispatch-time hivebus key handoff. A DIFFERENT shape
/// and lifecycle from the per-open `Receipt` above — it records WHAT key material
/// was placed on a remote at dispatch, by FINGERPRINT only. It MUST NEVER carry
/// seed bytes (the worker's private key); a test asserts this.
pub struct DispatchReceipt<'a> {
    pub target: &'a str,
    /// sha256-hex fingerprint of the worker public key placed on the remote.
    pub worker_pub_fingerprint: Option<&'a str>,
    /// sha256-hex fingerprint of the architect public key relayed to the remote.
    pub architect_pub_fingerprint: Option<&'a str>,
    /// the uid the remote agent was dropped to (auto-picked or explicit).
    /// Recorded here so the chosen uid is auditable independent of the remote run
    /// dir (which is removed on exit). `None` when the agent was not dropped.
    pub worker_uid: Option<u32>,
}

impl DispatchReceipt<'_> {
    /// Serialize to a single JSON line (no trailing newline). Fingerprints only.
    pub fn to_json_line(&self) -> String {
        let fp = |o: Option<&str>| match o {
            Some(s) => format!("\"{}\"", json_escape(s)),
            None => "null".to_string(),
        };
        let uid = match self.worker_uid {
            Some(u) => u.to_string(),
            None => "null".to_string(),
        };
        format!(
            r#"{{"ts_ms":{ts},"kind":"hivebus_dispatch","target":"{target}","worker_pub_fingerprint":{wfp},"architect_pub_fingerprint":{afp},"worker_uid":{uid}}}"#,
            ts = now_unix_millis(),
            target = json_escape(self.target),
            wfp = fp(self.worker_pub_fingerprint),
            afp = fp(self.architect_pub_fingerprint),
            uid = uid,
        )
    }
}

/// Sink for receipts: stderr always, plus an optional append-only file.
pub struct ReceiptLog {
    file: Option<std::fs::File>,
}

impl ReceiptLog {
    pub fn new(path: Option<&Path>) -> Result<Self> {
        let file = match path {
            Some(p) => Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .with_context(|| format!("cannot open receipts file {}", p.display()))?,
            ),
            None => None,
        };
        Ok(ReceiptLog { file })
    }

    /// Record one decision. Always emitted to stderr; also appended to the
    /// receipts file when configured.
    pub fn record(&mut self, r: &Receipt) {
        let line = r.to_json_line();
        eprintln!(
            "[bulwark] {} pid={} dev={} ino={} path={} ancestry={}",
            r.decision.as_str(),
            r.pid,
            r.dev,
            r.ino,
            r.path,
            r.ancestry
        );
        if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Record one dispatch-time hivebus key handoff. Emitted to stderr in the
    /// `[bulwark]` style and appended to the receipts file when configured.
    /// Fingerprints only — never seed bytes.
    pub fn record_dispatch(&mut self, r: &DispatchReceipt) {
        let line = r.to_json_line();
        eprintln!(
            "[bulwark] hivebus dispatch target={} worker_fp={} architect_fp={}",
            r.target,
            r.worker_pub_fingerprint.unwrap_or("-"),
            r.architect_pub_fingerprint.unwrap_or("-"),
        );
        if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_line_has_expected_fields() {
        let r = Receipt {
            pid: 42,
            dev: 7,
            ino: 99,
            decision: Decision::Deny,
            path: "/tmp/guard/secret.env",
            ancestry: "cat(42) <- bash(7)",
            reason: "protected inode",
            source: "operator",
        };
        let line = r.to_json_line();
        assert!(line.contains(r#""pid":42"#));
        assert!(line.contains(r#""dev":7"#));
        assert!(line.contains(r#""ino":99"#));
        assert!(line.contains(r#""decision":"deny""#));
        assert!(line.contains(r#""source":"operator""#));
        assert!(line.contains(r#""path":"/tmp/guard/secret.env""#));
        assert!(line.contains(r#""ancestry":"cat(42) <- bash(7)""#));
    }

    #[test]
    fn dispatch_receipt_has_fingerprints_never_seed() {
        // A plausible base64 seed value that MUST NOT leak into a receipt.
        let seed_b64 = "c2VjcmV0LXNlZWQtMzItYnl0ZXMtZG8tbm90LWxvZ2dlZA==";
        let r = DispatchReceipt {
            target: "nullbot@host",
            worker_pub_fingerprint: Some(
                "139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
            ),
            architect_pub_fingerprint: Some("abc123"),
            worker_uid: Some(63000),
        };
        let line = r.to_json_line();
        assert!(line.contains(r#""kind":"hivebus_dispatch""#));
        assert!(line.contains(r#""target":"nullbot@host""#));
        assert!(line.contains("139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070"));
        assert!(line.contains(r#""architect_pub_fingerprint":"abc123""#));
        // the chosen worker uid is recorded (the auditable trace).
        assert!(line.contains(r#""worker_uid":63000"#));
        // The seed must never appear anywhere in the serialized record.
        assert!(
            !line.contains(seed_b64),
            "seed bytes must never reach a receipt"
        );
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn dispatch_receipt_null_when_absent() {
        let r = DispatchReceipt {
            target: "h",
            worker_pub_fingerprint: None,
            architect_pub_fingerprint: None,
            worker_uid: None,
        };
        let line = r.to_json_line();
        assert!(line.contains(r#""worker_pub_fingerprint":null"#));
        assert!(line.contains(r#""architect_pub_fingerprint":null"#));
        assert!(line.contains(r#""worker_uid":null"#));
    }

    #[test]
    fn json_escapes_quotes_and_newlines() {
        let r = Receipt {
            pid: 1,
            dev: 0,
            ino: 0,
            decision: Decision::Allow,
            path: "/x/\"weird\"\npath",
            ancestry: "",
            reason: "",
            source: "",
        };
        let line = r.to_json_line();
        assert!(line.contains(r#"\"weird\""#));
        assert!(line.contains("\\n"));
        // The serialized line itself must be single-line.
        assert_eq!(line.lines().count(), 1);
    }
}
