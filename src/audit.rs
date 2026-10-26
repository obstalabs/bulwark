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

// WO-5@v1: make policy matching and decision audit output deterministic.
/// Minimal flat view of one receipt line. We extract only the fields we render,
/// using the same hand-rolled approach as the writer (no serde_json dep).
struct Row {
    ts_ms: u128,
    pid: i64,
    decision: String,
    source: String,
    path: String,
    ancestry: String,
    // WO-240@v1: shadow-mode flag; absent on every non-watch receipt.
    would_deny: bool,
}

// WO-5@v1: make policy matching and decision audit output deterministic.
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

// WO-5@v1: make policy matching and decision audit output deterministic.
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
        // WO-240@v1: only the literal `true` written by the gate sets the flag.
        would_deny: field(line, "would_deny") == Some("true"),
    })
}

// WO-240@v1: name the credential store an opened path belongs to, deterministically.
/// Credential stores the report calls out, as (path suffix pattern, label). A
/// pattern ending in `/` matches any path inside that directory; any other
/// pattern must match the final components exactly. Matching is on the path as
/// recorded, so it covers every home, not only the invoking user's.
const CREDENTIAL_STORES: &[(&str, &str)] = &[
    ("/.ssh/", "ssh"),
    ("/.aws/", "aws"),
    ("/.config/gcloud/", "gcloud"),
    ("/.kube/", "kube"),
    ("/.gnupg/", "gnupg"),
    ("/.docker/config.json", "docker"),
    ("/.npmrc", "npm"),
    ("/.pypirc", "pypi"),
    ("/.netrc", "netrc"),
    ("/.git-credentials", "git-credentials"),
    ("/.config/gh/hosts.yml", "gh"),
];

// WO-240@v1: name the credential store an opened path belongs to, deterministically.
fn credential_store(path: &str) -> Option<&'static str> {
    CREDENTIAL_STORES.iter().find_map(|(pat, label)| {
        let hit = if pat.ends_with('/') {
            path.contains(pat)
        } else {
            path.ends_with(pat)
        };
        hit.then_some(*label)
    })
}

/// How many most-opened paths the report lists.
const REPORT_TOP_N: usize = 10;

// WO-240@v1: one summary shared by `bulwark watch` and `bulwark report`.
/// Aggregate view of a receipts file for the shadow-mode report.
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    /// Receipt lines with a decision (every gated open).
    pub opens: usize,
    /// Distinct paths among them (`?` excluded).
    pub distinct_paths: usize,
    /// Opens flagged `would_deny`.
    pub would_deny_opens: usize,
    /// Distinct would-deny paths, sorted: the suggested `--protect` set.
    pub would_deny_paths: Vec<String>,
    /// (store label, distinct paths opened in it, sorted), stores sorted by label.
    pub credential_paths: Vec<(String, Vec<String>)>,
    /// Up to [`REPORT_TOP_N`] (path, opens), most opened first, ties by path.
    pub top_paths: Vec<(String, usize)>,
    /// Lines that are neither a decision nor a known metadata record.
    pub unparsed: usize,
}

// WO-240@v1: one summary shared by `bulwark watch` and `bulwark report`.
/// Build the report from receipts text. Metadata records (`"kind":...`, e.g. the
/// gate's summary line) are not opens and are not counted as unparsed.
pub fn summarize(raw: &str) -> Report {
    use std::collections::{BTreeMap, BTreeSet};
    let mut rep = Report::default();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut would: BTreeSet<String> = BTreeSet::new();
    let mut creds: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Some(r) = parse_row(line) else {
            if field(line, "kind").is_none() {
                rep.unparsed += 1;
            }
            continue;
        };
        rep.opens += 1;
        if r.path != "?" {
            *counts.entry(r.path.clone()).or_insert(0) += 1;
            if let Some(store) = credential_store(&r.path) {
                creds.entry(store).or_default().insert(r.path.clone());
            }
        }
        if r.would_deny {
            rep.would_deny_opens += 1;
            would.insert(r.path.clone());
        }
    }
    rep.distinct_paths = counts.len();
    rep.would_deny_paths = would.into_iter().collect();
    rep.credential_paths = creds
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.into_iter().collect()))
        .collect();
    let mut top: Vec<(String, usize)> = counts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top.truncate(REPORT_TOP_N);
    rep.top_paths = top;
    rep
}

// WO-240@v1: render the shadow-mode report for a person or an agent.
/// Read `path`, summarise it, and print the report (human or JSON) to stdout.
pub fn report(path: &Path, json: bool) -> Result<Report> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("cannot read receipts {}", path.display()))?;
    let rep = summarize(&raw);
    if json {
        println!("{}", report_json(&rep));
    } else {
        print!("{}", report_human(&rep));
    }
    Ok(rep)
}

// WO-240@v1: machine-readable form of the same report.
fn report_json(rep: &Report) -> String {
    let strs = |v: &[String]| {
        v.iter()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .collect::<Vec<_>>()
            .join(",")
    };
    let creds = rep
        .credential_paths
        .iter()
        .map(|(k, v)| format!(r#"{{"store":"{}","paths":[{}]}}"#, json_escape(k), strs(v)))
        .collect::<Vec<_>>()
        .join(",");
    let top = rep
        .top_paths
        .iter()
        .map(|(p, n)| format!(r#"{{"path":"{}","opens":{n}}}"#, json_escape(p)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"opens":{},"distinct_paths":{},"would_deny_opens":{},"would_deny_paths":[{}],"credential_stores":[{}],"top_paths":[{}],"unparsed":{}}}"#,
        rep.opens,
        rep.distinct_paths,
        rep.would_deny_opens,
        strs(&rep.would_deny_paths),
        creds,
        top,
        rep.unparsed
    )
}

// WO-240@v1: human form; the suggested block is ready to paste after `bulwark run`.
fn report_human(rep: &Report) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{} opens, {} distinct files, {} would-deny opens",
        rep.opens, rep.distinct_paths, rep.would_deny_opens
    );
    if rep.credential_paths.is_empty() {
        let _ = writeln!(s, "credential stores: none opened");
    } else {
        let _ = writeln!(s, "credential stores opened:");
        for (store, paths) in &rep.credential_paths {
            let _ = writeln!(s, "  {store}:");
            for p in paths {
                let _ = writeln!(s, "    {p}");
            }
        }
    }
    if !rep.top_paths.is_empty() {
        let _ = writeln!(s, "most opened:");
        for (p, n) in &rep.top_paths {
            let _ = writeln!(s, "  {n:>6}  {p}");
        }
    }
    if rep.would_deny_paths.is_empty() {
        let _ = writeln!(
            s,
            "suggested --protect: none (no protected path was opened)"
        );
    } else {
        let _ = writeln!(
            s,
            "suggested --protect (opens the current policy would deny):"
        );
        for p in &rep.would_deny_paths {
            let _ = writeln!(s, "  --protect {p}");
        }
    }
    if rep.unparsed > 0 {
        let _ = writeln!(s, "{} unparsed line(s)", rep.unparsed);
    }
    s
}

// WO-5@v1: make policy matching and decision audit output deterministic.
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

// WO-20@v1: emit machine-readable audit fields without invalid JSON.
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

// WO-5@v1: make policy matching and decision audit output deterministic.
#[cfg(test)]
mod tests {
    use super::*;

    // WO-5@v1: make policy matching and decision audit output deterministic.
    #[test]
    fn field_extracts_string_and_number() {
        let line = r#"{"ts_ms":123,"pid":42,"decision":"deny","path":"/x/secret.env","ancestry":"cat(42) <- bash(7)","reason":"protected inode"}"#;
        assert_eq!(field(line, "ts_ms"), Some("123"));
        assert_eq!(field(line, "pid"), Some("42"));
        assert_eq!(field(line, "decision"), Some("deny"));
        assert_eq!(field(line, "path"), Some("/x/secret.env"));
        assert_eq!(field(line, "ancestry"), Some("cat(42) <- bash(7)"));
    }

    // WO-5@v1: make policy matching and decision audit output deterministic.
    #[test]
    fn field_handles_escaped_quote_in_value() {
        let line = r#"{"path":"/x/\"weird\".env","decision":"allow"}"#;
        assert_eq!(field(line, "path"), Some(r#"/x/\"weird\".env"#));
        assert_eq!(field(line, "decision"), Some("allow"));
    }

    // WO-5@v1: make policy matching and decision audit output deterministic.
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

    // WO-240@v1: credential stores are named by directory or exact file suffix.
    #[test]
    fn credential_store_matches_directories_and_exact_files() {
        assert_eq!(credential_store("/home/a/.ssh/id_ed25519"), Some("ssh"));
        assert_eq!(credential_store("/home/a/.ssh/known_hosts"), Some("ssh"));
        assert_eq!(credential_store("/Users/a/.aws/credentials"), Some("aws"));
        assert_eq!(credential_store("/home/a/.npmrc"), Some("npm"));
        assert_eq!(credential_store("/home/a/.config/gh/hosts.yml"), Some("gh"));
        // A suffix that is not a whole component is not the store.
        assert_eq!(credential_store("/home/a/project.npmrc"), None);
        assert_eq!(credential_store("/home/a/.ssh"), None);
        assert_eq!(credential_store("/repo/src/main.rs"), None);
    }

    // WO-240@v1: the report counts opens, flags, stores and ranks paths deterministically.
    #[test]
    fn summarize_builds_the_shadow_mode_report() {
        let raw = concat!(
            r#"{"ts_ms":1,"pid":1,"decision":"allow","source":"watch","path":"/h/.ssh/id_ed25519","ancestry":"cat(1)","reason":"watch: protected inode; run would deny","would_deny":true}"#,
            "\n",
            r#"{"ts_ms":2,"pid":1,"decision":"allow","source":"watch","path":"/h/.ssh/id_ed25519","ancestry":"cat(1)","reason":"watch: protected inode; run would deny","would_deny":true}"#,
            "\n",
            r#"{"ts_ms":3,"pid":1,"decision":"allow","source":"watch","path":"/h/.npmrc","ancestry":"npm(1)","reason":"watch: not protected"}"#,
            "\n",
            r#"{"ts_ms":4,"pid":1,"decision":"allow","source":"watch","path":"/repo/a.rs","ancestry":"x(1)","reason":"watch: not protected"}"#,
            "\n",
            r#"{"ts_ms":5,"pid":1,"decision":"allow","source":"watch","path":"/repo/a.rs","ancestry":"x(1)","reason":"watch: not protected"}"#,
            "\n",
            r#"{"ts_ms":6,"pid":1,"decision":"allow","source":"watch","path":"/repo/b.rs","ancestry":"x(1)","reason":"watch: not protected"}"#,
            "\n",
            r#"{"ts_ms":7,"kind":"summary","file":{"state":"finished"}}"#,
            "\n",
            "garbage-not-json\n",
        );
        let rep = summarize(raw);
        assert_eq!(rep.opens, 6);
        assert_eq!(rep.distinct_paths, 4);
        assert_eq!(rep.would_deny_opens, 2);
        assert_eq!(rep.would_deny_paths, vec!["/h/.ssh/id_ed25519".to_string()]);
        assert_eq!(
            rep.credential_paths,
            vec![
                ("npm".to_string(), vec!["/h/.npmrc".to_string()]),
                ("ssh".to_string(), vec!["/h/.ssh/id_ed25519".to_string()]),
            ]
        );
        // Most opened first; ties ordered by path.
        assert_eq!(
            rep.top_paths,
            vec![
                ("/h/.ssh/id_ed25519".to_string(), 2),
                ("/repo/a.rs".to_string(), 2),
                ("/h/.npmrc".to_string(), 1),
                ("/repo/b.rs".to_string(), 1),
            ]
        );
        // The summary record is metadata, not an unparsed line; garbage is.
        assert_eq!(rep.unparsed, 1);
        let json = report_json(&rep);
        assert!(json.starts_with(r#"{"opens":6,"distinct_paths":4,"would_deny_opens":2,"would_deny_paths":["/h/.ssh/id_ed25519"]"#), "{json}");
        let human = report_human(&rep);
        assert!(
            human.contains("  --protect /h/.ssh/id_ed25519\n"),
            "{human}"
        );
        assert!(human.contains("  npm:\n    /h/.npmrc\n"), "{human}");
    }

    // WO-240@v1: an empty run says so instead of suggesting nothing silently.
    #[test]
    fn summarize_of_no_opens_reports_no_suggestion() {
        let rep = summarize("");
        assert_eq!(rep, Report::default());
        let human = report_human(&rep);
        assert!(human.contains("credential stores: none opened"), "{human}");
        assert!(human.contains("suggested --protect: none"), "{human}");
    }

    #[test]
    fn render_counts_allow_and_deny(/* via temp file */) {
        // WO-132@v1: collision-free scratch dir instead of the pid-only name.
        let dir = crate::test_scratch_dir("audit");
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
