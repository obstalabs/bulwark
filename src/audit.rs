//! `bulwark audit` — render the receipt log.
//!
//! Receipts are JSON lines written by the gate (see [`crate::receipt`]). Audit
//! reads them back and prints a human-readable table, plus a one-line summary
//! of allow/deny counts. The parser is tolerant: malformed lines are counted
//! and skipped, never fatal — an audit tool must never hide evidence behind a
//! parse error.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

/// Minimal flat view of one receipt line. We extract only the fields we render,
/// using the same hand-rolled approach as the writer (no serde_json dep).
struct Row {
    ts_ms: u128,
    pid: i64,
    decision: String,
    source: String,
    path: String,
    ancestry: String,
}

/// Extract a string value for `key` from a flat JSON object line.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        // string value: read until the next unescaped quote
        let bytes = stripped.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                return Some(&stripped[..i]);
            }
            i += 1;
        }
        None
    } else {
        // numeric/bare value: read until , or }
        let end = rest.find([',', '}']).unwrap_or(rest.len());
        Some(rest[..end].trim())
    }
}

fn parse_row(line: &str) -> Option<Row> {
    Some(Row {
        ts_ms: field(line, "ts_ms")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        pid: field(line, "pid")
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1),
        decision: field(line, "decision")?.to_string(),
        source: field(line, "source").unwrap_or("").to_string(),
        path: field(line, "path").unwrap_or("?").to_string(),
        ancestry: field(line, "ancestry").unwrap_or("").to_string(),
    })
}

/// Render the receipt log at `path` to stdout. When `json` is true, emit one
/// machine-readable object (counts + per-decision records) for agent
/// consumption; otherwise a human table. Returns (allow, deny, skipped).
pub fn render(path: &Path, json: bool) -> Result<(usize, usize, usize)> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("cannot read receipts {}", path.display()))?;

    let (mut allow, mut deny, mut skipped) = (0usize, 0usize, 0usize);
    let mut rows: Vec<Row> = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match parse_row(line) {
            Some(r) => {
                match r.decision.as_str() {
                    "allow" => allow += 1,
                    "deny" => deny += 1,
                    _ => {}
                }
                rows.push(r);
            }
            None => skipped += 1,
        }
    }

    if json {
        let items: Vec<String> = rows
            .iter()
            .map(|r| {
                format!(
                    r#"{{"ts_ms":{},"pid":{},"decision":"{}","source":"{}","path":"{}","ancestry":"{}"}}"#,
                    r.ts_ms,
                    r.pid,
                    json_escape(&r.decision),
                    json_escape(&r.source),
                    json_escape(&r.path),
                    json_escape(&r.ancestry),
                )
            })
            .collect();
        println!(
            r#"{{"allow":{allow},"deny":{deny},"unparsed":{skipped},"decisions":[{}]}}"#,
            items.join(",")
        );
    } else {
        println!(
            "{:<14}  {:<7}  {:<8}  {:<9}  {:<24}  ANCESTRY",
            "TS(ms)", "PID", "DECISION", "SOURCE", "PATH"
        );
        for r in &rows {
            println!(
                "{:<14}  {:<7}  {:<8}  {:<9}  {:<24}  {}",
                r.ts_ms, r.pid, r.decision, r.source, r.path, r.ancestry
            );
        }
        println!("\n{allow} allow, {deny} deny, {skipped} unparsed");
    }
    Ok((allow, deny, skipped))
}

/// Escape a string for a JSON double-quoted value (same minimal rules as the
/// receipt writer — no serde_json dependency).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_extracts_string_and_number() {
        let line = r#"{"ts_ms":123,"pid":42,"decision":"deny","path":"/x/secret.env","ancestry":"cat(42) <- bash(7)","reason":"protected inode"}"#;
        assert_eq!(field(line, "ts_ms"), Some("123"));
        assert_eq!(field(line, "pid"), Some("42"));
        assert_eq!(field(line, "decision"), Some("deny"));
        assert_eq!(field(line, "path"), Some("/x/secret.env"));
        assert_eq!(field(line, "ancestry"), Some("cat(42) <- bash(7)"));
    }

    #[test]
    fn field_handles_escaped_quote_in_value() {
        let line = r#"{"path":"/x/\"weird\".env","decision":"allow"}"#;
        assert_eq!(field(line, "path"), Some(r#"/x/\"weird\".env"#));
        assert_eq!(field(line, "decision"), Some("allow"));
    }

    #[test]
    fn parse_row_round_trips_a_written_receipt() {
        // Mirror what receipt::to_json_line produces.
        let line = r#"{"ts_ms":1717,"pid":959596,"dev":43,"ino":192214,"decision":"deny","path":"/tmp/guard/secret.env","ancestry":"cat(959596) <- bash(959591)","reason":"protected inode"}"#;
        let r = parse_row(line).unwrap();
        assert_eq!(r.pid, 959596);
        assert_eq!(r.decision, "deny");
        assert_eq!(r.path, "/tmp/guard/secret.env");
        assert!(r.ancestry.contains("cat(959596)"));
    }

    #[test]
    fn render_counts_allow_and_deny(/* via temp file */) {
        let dir = std::env::temp_dir().join(format!("bulwark-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("r.jsonl");
        let body = concat!(
            r#"{"ts_ms":1,"pid":1,"decision":"allow","path":"/a","ancestry":"x(1)"}"#,
            "\n",
            r#"{"ts_ms":2,"pid":2,"decision":"deny","path":"/b","ancestry":"y(2)"}"#,
            "\n",
            "garbage-not-json\n",
        );
        std::fs::write(&f, body).unwrap();
        let (allow, deny, skipped) = render(&f, false).unwrap();
        assert_eq!((allow, deny, skipped), (1, 1, 1));
        // JSON form returns the same counts.
        let (a2, d2, s2) = render(&f, true).unwrap();
        assert_eq!((a2, d2, s2), (1, 1, 1));
    }
}
