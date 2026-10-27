//! Conformance tests for the decision-rule contract (src/rules).
//!
//! 1. `tests/vectors/decision-rules.json`: hand-authored cases, each citing its
//!    source, run against a fixture tree that can be renamed, replaced and extended
//!    after the policy is compiled.
//! 2. A property test: generated policies and trees, `rules::decide` against the
//!    independent reference in `tests/support/naive_rules.rs`.

#[path = "../src/rules/mod.rs"]
#[allow(dead_code)]
mod rules;

#[path = "support/naive_rules.rs"]
mod naive;

use std::collections::{BTreeMap, BTreeSet};

use rules::{Chain, Component, Key, Kind, Lookup, Resolver, Spec, Verdict};
use serde::Deserialize;

// WO-198@v1: an in-memory tree with stable inode keys, mutable after compile.
#[derive(Debug, Clone, Default)]
struct Tree {
    nodes: BTreeMap<String, (Key, bool)>,
    unknown: BTreeSet<String>,
    next: u64,
}

impl Tree {
    // WO-198@v1: a fresh key for every created object.
    fn fresh(&mut self) -> Key {
        self.next += 1;
        Key {
            dev: 7,
            ino: self.next,
        }
    }
    // WO-198@v1: create a path and any missing parents as directories.
    fn add(&mut self, path: &str, dir: bool) {
        let comps = rules::split_path(path);
        for i in 0..comps.len() {
            let p = join(&comps[..=i]);
            let is_dir = i + 1 < comps.len() || dir;
            if !self.nodes.contains_key(&p) {
                let k = self.fresh();
                self.nodes.insert(p, (k, is_dir));
            }
        }
    }
    // WO-198@v1: move a path and everything under it, keeping keys.
    fn rename(&mut self, from: &str, to: &str) {
        let moved: Vec<(String, (Key, bool))> = self
            .nodes
            .iter()
            .filter(|(p, _)| *p == from || p.starts_with(&format!("{from}/")))
            .map(|(p, v)| (p.clone(), *v))
            .collect();
        for (p, _) in &moved {
            self.nodes.remove(p);
        }
        if let Some((parent, _)) = to.rsplit_once('/') {
            if !parent.is_empty() {
                self.add(parent, true);
            }
        }
        for (p, v) in moved {
            let np = format!("{to}{}", &p[from.len()..]);
            self.nodes.insert(np, v);
        }
    }
    // WO-198@v1: write-new-then-rename over a file: same path, new key.
    fn replace(&mut self, path: &str) {
        let k = self.fresh();
        self.nodes.insert(path.to_string(), (k, false));
    }
    // WO-198@v1: a hard link: a second name for the same key.
    fn link(&mut self, from: &str, to: &str) {
        if let Some((parent, _)) = to.rsplit_once('/') {
            if !parent.is_empty() {
                self.add(parent, true);
            }
        }
        if let Some(v) = self.nodes.get(from).copied() {
            self.nodes.insert(to.to_string(), v);
        }
    }
    // WO-198@v1: the chain an evaluator would build for an open of `path`.
    fn chain(&self, path: &str) -> Chain {
        let comps = rules::split_path(path);
        let mut chain = Chain {
            root: Some(Key { dev: 7, ino: 0 }),
            comps: Vec::new(),
        };
        let mut present = true;
        for i in 0..comps.len() {
            let p = join(&comps[..=i]);
            let key = if present {
                self.nodes.get(&p).map(|v| v.0)
            } else {
                None
            };
            present = key.is_some();
            chain.comps.push(Component {
                name: comps[i].clone(),
                key,
            });
        }
        chain
    }
}

// WO-198@v1: component list back to an absolute path string.
fn join(comps: &[Vec<u8>]) -> String {
    let parts: Vec<String> = comps
        .iter()
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    format!("/{}", parts.join("/"))
}

impl Resolver for Tree {
    // WO-198@v1: launch-time lookup against the fixture.
    fn lookup(&self, comps: &[Vec<u8>]) -> Lookup {
        if comps.is_empty() {
            return Lookup::Dir(Key { dev: 7, ino: 0 });
        }
        let p = join(comps);
        if self.unknown.contains(&p) {
            return Lookup::Unknown;
        }
        match self.nodes.get(&p) {
            Some((k, true)) => Lookup::Dir(*k),
            Some((k, false)) => Lookup::File(*k),
            None => Lookup::Absent,
        }
    }
    // WO-198@v1: launch snapshot of a protected directory.
    fn snapshot(&self, comps: &[Vec<u8>]) -> Option<(BTreeSet<Key>, BTreeSet<Key>)> {
        let base = join(comps);
        let (mut dirs, mut files) = (BTreeSet::new(), BTreeSet::new());
        for (p, (k, d)) in &self.nodes {
            if p.starts_with(&format!("{base}/")) {
                if *d {
                    dirs.insert(*k);
                } else {
                    files.insert(*k);
                }
            }
        }
        Some((dirs, files))
    }
}

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
    errors: Vec<ErrorCase>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    source: String,
    #[serde(default)]
    homes: Vec<String>,
    #[serde(default)]
    dirs: Vec<String>,
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    unknown: Vec<String>,
    #[serde(default)]
    protect: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    ops: Vec<Op>,
    queries: Vec<Query>,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Op {
    Rename { from: String, to: String },
    Replace { path: String },
    CreateFile { path: String },
    CreateDir { path: String },
    Link { from: String, to: String },
}

#[derive(Deserialize)]
struct Query {
    path: String,
    expect: String,
    step: u8,
    #[serde(default)]
    rule: Option<String>,
}

#[derive(Deserialize)]
struct ErrorCase {
    source: String,
    kind: String,
    entry: String,
    contains: String,
}

// WO-198@v1: protect entries fan out over homes (as policy.rs does); allow entries do not.
fn specs(protect: &[String], allow: &[String], homes: &[String]) -> Vec<Spec> {
    let mut out = Vec::new();
    let mut id = 0u16;
    for e in protect {
        let patterns: Vec<String> = if e == "~" || e.starts_with("~/") {
            homes.iter().map(|h| format!("{h}{}", &e[1..])).collect()
        } else {
            vec![e.clone()]
        };
        for p in patterns {
            out.push(Spec {
                id,
                kind: Kind::Protect,
                source: e.clone(),
                pattern: p,
            });
        }
        id += 1;
    }
    for e in allow {
        out.push(Spec {
            id,
            kind: Kind::Allow,
            source: e.clone(),
            pattern: e.clone(),
        });
        id += 1;
    }
    out
}

// WO-198@v1: the verdict token used in the vector file.
fn token(v: Verdict) -> &'static str {
    match v {
        Verdict::Protected => "protected",
        Verdict::Allowed => "allowed",
        Verdict::NotProtected => "not_protected",
    }
}

// WO-198@v1: load the shared vector file.
fn vectors() -> Vectors {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/decision-rules.json"
    ))
    .expect("read vectors");
    serde_json::from_str(&raw).expect("parse vectors")
}

// WO-198@v1: every hand-authored vector decides as the contract says.
#[test]
fn vectors_decide_as_written() {
    let v = vectors();
    let mut failures = Vec::new();
    for case in &v.cases {
        assert!(!case.source.is_empty(), "case {} has no source", case.name);
        let mut tree = Tree::default();
        for d in &case.dirs {
            tree.add(d, true);
        }
        for f in &case.files {
            tree.add(f, false);
        }
        tree.unknown = case.unknown.iter().cloned().collect();
        let compiled = rules::compile(&specs(&case.protect, &case.allow, &case.homes), &tree)
            .unwrap_or_else(|e| panic!("case {}: {e}", case.name));
        for op in &case.ops {
            match op {
                Op::Rename { from, to } => tree.rename(from, to),
                Op::Replace { path } => tree.replace(path),
                Op::CreateFile { path } => tree.add(path, false),
                Op::CreateDir { path } => tree.add(path, true),
                Op::Link { from, to } => tree.link(from, to),
            }
        }
        for q in &case.queries {
            let d = rules::decide(&tree.chain(&q.path), &compiled);
            let rule = d.rule.map(|id| compiled.sources[id as usize].clone());
            if token(d.verdict) != q.expect || d.step != q.step || rule != q.rule {
                failures.push(format!(
                    "{} / {}: want {} step {} rule {:?}, got {} step {} rule {:?}",
                    case.name,
                    q.path,
                    q.expect,
                    q.step,
                    q.rule,
                    token(d.verdict),
                    d.step,
                    rule
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} vector failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// WO-198@v1: every out-of-grammar class is a launch error that names the entry.
#[test]
fn grammar_errors_name_the_entry() {
    let v = vectors();
    let tree = {
        let mut t = Tree::default();
        t.add("/t", true);
        t
    };
    for e in &v.errors {
        assert!(!e.source.is_empty());
        let kind = if e.kind == "allow" {
            Kind::Allow
        } else {
            Kind::Protect
        };
        let spec = Spec {
            id: 0,
            kind,
            source: e.entry.clone(),
            pattern: e.entry.clone(),
        };
        let err =
            rules::compile(&[spec], &tree).expect_err(&format!("{} must be refused", e.entry));
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("{:?}", e.entry)),
            "error must name the entry: {msg}"
        );
        assert!(
            msg.contains(&e.contains),
            "{}: expected {:?} in {msg}",
            e.entry,
            e.contains
        );
        assert!(msg.contains("nothing was run"), "{msg}");
    }
}

// WO-198@v1: a non-ASCII name is refused even when it resolves to an
// existing anchor directory and so never reaches the chain.
#[test]
fn non_ascii_in_an_existing_anchor_is_refused() {
    let mut tree = Tree::default();
    tree.add("/t/café", true);
    let spec = Spec {
        id: 0,
        kind: Kind::Protect,
        source: "/t/café/x*".into(),
        pattern: "/t/café/x*".into(),
    };
    let err = rules::compile(&[spec], &tree).expect_err("non-ASCII anchor must be refused");
    assert!(err.to_string().contains("non-ASCII"), "{err}");
}

// WO-198@v1: a non-ASCII home directory from `~/` expansion is not in the written
// entry and stays allowed.
#[test]
fn non_ascii_home_from_expansion_is_allowed() {
    let mut tree = Tree::default();
    tree.add("/t/home/müller/.ssh", true);
    let spec = Spec {
        id: 0,
        kind: Kind::Protect,
        source: "~/.ssh".into(),
        pattern: "/t/home/müller/.ssh".into(),
    };
    rules::compile(&[spec], &tree).expect("a non-ASCII home from expansion compiles");
}

// WO-198@v1: per-home copies of one entry fold into one rule with an
// anchor set, so the compiled rule count does not grow with the number of homes.
#[test]
fn per_home_expansion_folds_into_one_rule() {
    let mut tree = Tree::default();
    let homes: Vec<String> = (0..=rules::R_MAX)
        .map(|i| format!("/t/home/u{i}"))
        .collect();
    for h in &homes {
        tree.add(h, true);
    }
    let compiled = rules::compile(&specs(&["~/.ssh".to_string()], &[], &homes), &tree).unwrap();
    assert_eq!(compiled.locations.len(), 1, "one rule for every home");
    let anchors = compiled.locations[0].anchors.as_ref().map(Vec::len);
    assert_eq!(anchors, Some(homes.len()));
    let d = rules::decide(&tree.chain("/t/home/u77/.ssh/id"), &compiled);
    assert_eq!((d.verdict, d.step), (Verdict::Protected, 5));
}

// WO-198@v1: the R_MAX cap counts written entries after `{}` expansion.
#[test]
fn entry_cap_refuses_past_r_max() {
    let tree = Tree::default();
    let mk = |n: usize| -> Vec<Spec> {
        (0..n)
            .map(|i| Spec {
                id: i as u16,
                kind: Kind::Protect,
                source: format!("/t/e{i}"),
                pattern: format!("/t/e{i}"),
            })
            .collect()
    };
    assert!(rules::compile(&mk(rules::R_MAX), &tree).is_ok());
    let err = rules::compile(&mk(rules::R_MAX + 1), &tree).expect_err("over the cap");
    assert!(err.to_string().contains("R_MAX"), "{err}");
}

// WO-198@v1: deterministic generator (xorshift64), fixed seed.
struct Rng(u64);
impl Rng {
    // WO-198@v1: next pseudo-random value.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    // WO-198@v1: uniform pick below `n`.
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// WO-198@v1: fixed seed so the generated comparison is the same on every run.
const PROPERTY_SEED: u64 = 0x005e_ed19_8dec_1de5;

const NAMES: &[&str] = &[
    "a",
    "b",
    "A",
    ".env",
    ".ENV",
    "secret",
    "my_secret.txt",
    "x.txt",
    "README.md",
    "dev",
];
const PATTERNS: &[&str] = &["*", "*secret*", "*.txt", ".*", "?", "README*", "*.md", "a*"];

// WO-198@v1: a random path under /t of depth 1..=4.
fn random_path(rng: &mut Rng) -> Vec<String> {
    let depth = 1 + rng.below(4);
    let mut p = vec!["t".to_string()];
    for _ in 0..depth {
        p.push(NAMES[rng.below(NAMES.len())].to_string());
    }
    p
}

// WO-198@v1: a random entry inside the grammar.
fn random_entry(rng: &mut Rng, tree_paths: &[Vec<String>]) -> String {
    match rng.below(4) {
        0 => {
            // a concrete path, existing or not
            let p = if !tree_paths.is_empty() && rng.below(2) == 0 {
                tree_paths[rng.below(tree_paths.len())].clone()
            } else {
                random_path(rng)
            };
            format!("/{}", p.join("/"))
        }
        1 => format!("**/{}", PATTERNS[rng.below(PATTERNS.len())]),
        2 => format!("**/{}", NAMES[rng.below(NAMES.len())]),
        _ => {
            let mut p = random_path(rng);
            let i = 1 + rng.below(p.len() - 1);
            p[i] = match rng.below(3) {
                0 => "**".into(),
                1 => PATTERNS[rng.below(PATTERNS.len())].into(),
                _ => p[i].clone(),
            };
            let mut s = format!("/{}", p.join("/"));
            if rng.below(3) == 0 {
                s.push_str("/**");
            }
            s
        }
    }
}

// WO-198@v1: rules::decide and the independent reference agree on generated policies.
#[test]
fn rules_agree_with_reference_on_generated_policies() {
    let mut rng = Rng(PROPERTY_SEED);
    let mut compared = 0usize;
    let mut disagreements = Vec::new();
    for case in 0..1200 {
        let mut tree = Tree::default();
        let mut ref_tree = naive::Tree::default();
        let mut paths: Vec<Vec<String>> = Vec::new();
        for _ in 0..(3 + rng.below(8)) {
            let p = random_path(&mut rng);
            // Files have no children: skip a path under an existing file.
            let blocked =
                (1..p.len()).any(|k| ref_tree.files.contains(&format!("/{}", p[..k].join("/"))));
            let s = format!("/{}", p.join("/"));
            if blocked || ref_tree.dirs.contains(&s) || ref_tree.files.contains(&s) {
                continue;
            }
            let is_dir = rng.below(3) == 0;
            tree.add(&s, is_dir);
            for k in 1..p.len() {
                ref_tree.dirs.insert(format!("/{}", p[..k].join("/")));
            }
            if is_dir {
                ref_tree.dirs.insert(s.clone());
            } else {
                ref_tree.files.insert(s.clone());
            }
            paths.push(p);
        }
        let protect: Vec<String> = (0..1 + rng.below(4))
            .map(|_| random_entry(&mut rng, &paths))
            .collect();
        let allow: Vec<String> = (0..rng.below(3))
            .map(|_| random_entry(&mut rng, &paths))
            .collect();
        let specs = specs(&protect, &allow, &[]);
        let Ok(compiled) = rules::compile(&specs, &tree) else {
            continue;
        };
        let entries: Vec<naive::Entry> = specs
            .iter()
            .map(|s| naive::Entry {
                id: s.id,
                protect: s.kind == Kind::Protect,
                pattern: s.pattern.clone(),
            })
            .collect();
        let mut queries: Vec<String> = paths.iter().map(|p| format!("/{}", p.join("/"))).collect();
        for _ in 0..6 {
            queries.push(format!("/{}", random_path(&mut rng).join("/")));
        }
        // A path below an existing file cannot be opened; it says nothing about the contract.
        queries.retain(|q| {
            let c: Vec<&str> = q.split('/').filter(|x| !x.is_empty()).collect();
            !(1..c.len()).any(|k| ref_tree.files.contains(&format!("/{}", c[..k].join("/"))))
        });
        for q in &queries {
            let d = rules::decide(&tree.chain(q), &compiled);
            let (rv, rs, rr) = naive::decide(&entries, &ref_tree, q);
            let rv = match rv {
                naive::Verdict::Protected => Verdict::Protected,
                naive::Verdict::Allowed => Verdict::Allowed,
                naive::Verdict::NotProtected => Verdict::NotProtected,
            };
            compared += 1;
            if (d.verdict, d.step, d.rule) != (rv, rs, rr) {
                disagreements.push(format!(
                    "case {case} path {q}\n  protect {protect:?} allow {allow:?}\n  rules {:?} step {} rule {:?} / reference {:?} step {} rule {:?}",
                    d.verdict, d.step, d.rule, rv, rs, rr
                ));
            }
        }
    }
    assert!(compared >= 10_000, "only {compared} comparisons");
    assert!(
        disagreements.is_empty(),
        "{} of {compared} disagree; first 5:\n{}",
        disagreements.len(),
        disagreements
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
