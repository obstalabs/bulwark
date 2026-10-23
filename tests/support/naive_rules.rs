//! A deliberately simple reference for the decision-rule contract.
//!
//! It shares no code with `src/rules`: whole-path string matching over canonical
//! paths, no anchors, no inode keys, no IR. On a tree that is not mutated after the
//! policy is read, both must reach the same verdict, step and rule for every path.

use std::collections::BTreeSet;

// WO-198@v1: the ladder outcome the reference reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Protected,
    Allowed,
    NotProtected,
}

// WO-198@v1: one entry for the reference (already home-expanded, absolute or `**...`).
#[derive(Debug, Clone)]
pub struct Entry {
    pub id: u16,
    pub protect: bool,
    pub pattern: String,
}

// WO-198@v1: the launch tree the reference consults for concrete entries.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    pub dirs: BTreeSet<String>,
    pub files: BTreeSet<String>,
}

// WO-198@v1: components of an absolute path or pattern.
fn comps(s: &str) -> Vec<String> {
    s.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .map(str::to_string)
        .collect()
}

// WO-198@v1: case policy as the contract states it (protect folds ASCII).
fn fold(s: &str, on: bool) -> String {
    if on {
        s.to_ascii_lowercase()
    } else {
        s.to_string()
    }
}

// WO-198@v1: recursive one-component wildcard match (a different algorithm from
// the evaluator's iterative one, on purpose).
fn wild(p: &[u8], n: &[u8]) -> bool {
    match p.first() {
        None => n.is_empty(),
        Some(b'*') => (0..=n.len()).any(|i| wild(&p[1..], &n[i..])),
        Some(b'?') => !n.is_empty() && wild(&p[1..], &n[1..]),
        Some(c) => n.first() == Some(c) && wild(&p[1..], &n[1..]),
    }
}

// WO-198@v1: whole-path glob over components; `**` is zero or more components.
fn glob(p: &[String], n: &[String]) -> bool {
    match p.first() {
        None => n.is_empty(),
        Some(s) if s == "**" => (0..=n.len()).any(|i| glob(&p[1..], &n[i..])),
        Some(s) => !n.is_empty() && wild(s.as_bytes(), n[0].as_bytes()) && glob(&p[1..], &n[1..]),
    }
}

// WO-198@v1: how one entry reaches a path: (names the file, covers it as subtree).
fn reach(e: &Entry, path: &[String]) -> (bool, bool) {
    let mut pat = comps(&e.pattern);
    let trailing = pat.last().map(|s| s == "**").unwrap_or(false);
    if trailing {
        pat.pop();
    }
    let concrete = !e.pattern.contains('*') && !e.pattern.contains('?');
    // A concrete protect entry covers its subtree; a concrete allow is exact.
    let subtree = trailing || (concrete && e.protect);
    let p: Vec<String> = pat.iter().map(|s| fold(s, e.protect)).collect();
    let n: Vec<String> = path.iter().map(|s| fold(s, e.protect)).collect();
    let names = glob(&p, &n);
    let below = subtree && (0..n.len()).any(|k| glob(&p, &n[..k]));
    (names, below)
}

// WO-198@v1: the entry ends in a literal component.
fn literal_last(e: &Entry) -> bool {
    let mut pat = comps(&e.pattern);
    if pat.last().map(|s| s == "**").unwrap_or(false) {
        pat.pop();
    }
    pat.last()
        .map(|s| !s.contains('*') && !s.contains('?') && s != "**")
        .unwrap_or(false)
}

/// WO-198@v1: the six-step ladder, computed from whole-path matches only.
pub fn decide(entries: &[Entry], tree: &Tree, path: &str) -> (Verdict, u8, Option<u16>) {
    let n = comps(path);
    let canon = format!("/{}", n.join("/"));
    let min = |it: &mut dyn Iterator<Item = u16>| it.min();

    // 1: a concrete protect entry that is an existing file, opened by that exact path.
    if let Some(id) = min(&mut entries.iter().filter_map(|e| {
        let ec = format!("/{}", comps(&e.pattern).join("/"));
        (e.protect
            && tree.files.contains(&ec)
            && ec == canon
            && !e.pattern.contains('*')
            && !e.pattern.contains('?'))
        .then_some(e.id)
    })) {
        return (Verdict::Protected, 1, Some(id));
    }
    let r: Vec<(&Entry, (bool, bool))> = entries.iter().map(|e| (e, reach(e, &n))).collect();
    let pick = |f: &dyn Fn(&Entry, (bool, bool)) -> bool| {
        r.iter().filter(|(e, x)| f(e, *x)).map(|(e, _)| e.id).min()
    };
    if let Some(id) = pick(&|e, (nf, _)| !e.protect && nf && literal_last(e)) {
        return (Verdict::Allowed, 2, Some(id));
    }
    if let Some(id) = pick(&|e, (nf, _)| e.protect && nf) {
        return (Verdict::Protected, 3, Some(id));
    }
    if let Some(id) = pick(&|e, (nf, sub)| !e.protect && ((nf && !literal_last(e)) || sub)) {
        return (Verdict::Allowed, 4, Some(id));
    }
    if let Some(id) = pick(&|e, (_, sub)| e.protect && sub) {
        return (Verdict::Protected, 5, Some(id));
    }
    (Verdict::NotProtected, 6, None)
}
