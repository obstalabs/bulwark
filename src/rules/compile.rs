//! Policy entries to object and location rules.

use std::collections::BTreeSet;
use std::fmt;

use super::{
    Anchor, Compiled, Key, Kind, LocationRule, ObjectRule, Seg, MAX_ALTERNATIVES, MAX_ANY_DEPTH,
    MAX_CHAIN, MAX_LITERAL, MAX_STARS, NAME_MAX, R_MAX,
};

/// WO-198@v1: one policy entry to compile, already expanded per home by the caller.
/// Entries that share `id` came from the same written entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub id: u16,
    pub kind: Kind,
    /// The entry as written, for receipts and errors.
    pub source: String,
    /// Absolute (`/...`) or any-ancestor (`**...`) pattern.
    pub pattern: String,
}

/// WO-198@v1: what a launch path resolved to when the policy was compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    Dir(Key),
    File(Key),
    /// Does not exist (ENOENT / ENOTDIR).
    Absent,
    /// Exists or not, cannot tell (EACCES, ...): treated as absent for location
    /// rules and yields no object rule.
    Unknown,
}

/// WO-198@v1: the caller's view of the filesystem at compile time.
pub trait Resolver {
    /// Resolve the path made of `comps` below `/` (empty = the root), following
    /// symlinks like `stat`.
    fn lookup(&self, comps: &[Vec<u8>]) -> Lookup;
    /// Launch snapshot under a protected directory: (directory keys, file keys).
    /// `None` when the caller does not snapshot (e.g. `check`).
    fn snapshot(&self, _comps: &[Vec<u8>]) -> Option<(BTreeSet<Key>, BTreeSet<Key>)> {
        None
    }
}

/// WO-198@v1: an out-of-grammar entry is a launch error naming it, never a silent skip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub kind: Kind,
    pub source: String,
    pub reason: String,
}

impl fmt::Display for CompileError {
    // WO-198@v1: name the entry and say nothing ran, like the other launch refusals.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            Kind::Protect => "protect",
            Kind::Allow => "allow",
        };
        write!(
            f,
            "{kind} entry {:?}: {}; nothing was run",
            self.source, self.reason
        )
    }
}

impl std::error::Error for CompileError {}

// WO-198@v1: shorthand for a refusal of one entry.
fn refuse(spec: &Spec, reason: impl Into<String>) -> CompileError {
    CompileError {
        kind: spec.kind,
        source: spec.source.clone(),
        reason: reason.into(),
    }
}

// WO-198@v1: `{a,b}` alternatives become separate patterns with the same rule id.
fn expand_braces(spec: &Spec) -> Result<Vec<String>, CompileError> {
    let mut out = vec![String::new()];
    let mut rest = spec.pattern.as_str();
    while let Some(open) = rest.find('{') {
        let close = rest[open..]
            .find('}')
            .map(|c| open + c)
            .ok_or_else(|| refuse(spec, "unclosed `{`"))?;
        let inner = &rest[open + 1..close];
        if inner.contains('{') {
            return Err(refuse(spec, "nested `{` is not supported"));
        }
        let head = &rest[..open];
        let alts: Vec<&str> = inner.split(',').collect();
        let mut next = Vec::new();
        for o in &out {
            for a in &alts {
                next.push(format!("{o}{head}{a}"));
            }
        }
        if next.len() > MAX_ALTERNATIVES {
            return Err(refuse(
                spec,
                format!("expands to more than {MAX_ALTERNATIVES} alternatives"),
            ));
        }
        out = next;
        rest = &rest[close + 1..];
    }
    if rest.contains('}') {
        return Err(refuse(spec, "unmatched `}`"));
    }
    Ok(out.into_iter().map(|o| format!("{o}{rest}")).collect())
}

// WO-198@v1: one written component to a segment, enforcing the bounded grammar.
fn parse_seg(spec: &Spec, raw: &[u8]) -> Result<Seg, CompileError> {
    if raw == b"**" {
        return Ok(Seg::AnyDepth);
    }
    if raw.len() > NAME_MAX {
        return Err(refuse(
            spec,
            format!("a component is longer than {NAME_MAX} bytes"),
        ));
    }
    if raw.windows(2).any(|w| w == b"**") {
        return Err(refuse(spec, "`**` must be a whole path component"));
    }
    let stars = raw.iter().filter(|b| **b == b'*').count();
    if stars == 0 && !raw.contains(&b'?') {
        return Ok(Seg::Name(raw.to_vec()));
    }
    if stars > MAX_STARS {
        return Err(refuse(
            spec,
            format!("a component has more than {MAX_STARS} `*`"),
        ));
    }
    if raw
        .split(|b| *b == b'*' || *b == b'?')
        .any(|lit| lit.len() > MAX_LITERAL)
    {
        return Err(refuse(
            spec,
            format!("a literal part is longer than {MAX_LITERAL} bytes"),
        ));
    }
    Ok(Seg::Pattern(raw.to_vec()))
}

// WO-198@v1: split a pattern into segments; `..` is refused, `.` and empty parts drop.
fn parse_segments(spec: &Spec, pattern: &str) -> Result<Vec<Seg>, CompileError> {
    let mut segs = Vec::new();
    for raw in pattern.as_bytes().split(|b| *b == b'/') {
        if raw.is_empty() || raw == b"." {
            continue;
        }
        if raw == b".." {
            return Err(refuse(spec, "`..` is not allowed in an entry"));
        }
        segs.push(parse_seg(spec, raw)?);
    }
    Ok(segs)
}

// WO-198@v1: a resolvable directory becomes an anchor; otherwise walk up to the
// nearest existing ancestor and carry the missing names into the chain.
fn nearest_anchor(prefix: &[Vec<u8>], r: &dyn Resolver) -> (Anchor, Vec<Seg>) {
    for j in (0..=prefix.len()).rev() {
        if let Lookup::Dir(k) = r.lookup(&prefix[..j]) {
            let missing = prefix[j..].iter().map(|n| Seg::Name(n.clone())).collect();
            return (
                Anchor {
                    key: Some(k),
                    path: prefix[..j].to_vec(),
                },
                missing,
            );
        }
    }
    (
        Anchor {
            key: None,
            path: Vec::new(),
        },
        prefix.iter().map(|n| Seg::Name(n.clone())).collect(),
    )
}

// WO-198@v1: enforce the chain bounds and the protect-side ASCII rule.
fn check_chain(spec: &Spec, chain: &[Seg]) -> Result<(), CompileError> {
    if chain.len() > MAX_CHAIN {
        return Err(refuse(
            spec,
            format!("more than {MAX_CHAIN} components below the anchor"),
        ));
    }
    if chain.iter().filter(|s| **s == Seg::AnyDepth).count() > MAX_ANY_DEPTH {
        return Err(refuse(
            spec,
            format!("more than {MAX_ANY_DEPTH} `**` components"),
        ));
    }
    if spec.kind == Kind::Protect {
        let non_ascii = chain.iter().any(|s| match s {
            Seg::Name(b) | Seg::Pattern(b) => b.iter().any(|c| *c >= 0x80),
            Seg::AnyDepth => false,
        });
        if non_ascii {
            return Err(refuse(
                spec,
                "a protect entry may not contain non-ASCII names (case and normalization \
                 equivalence beyond ASCII is not guaranteed)",
            ));
        }
    }
    Ok(())
}

// WO-198@v1: compile one alternative of one entry into its rules.
fn compile_one(
    spec: &Spec,
    pattern: &str,
    r: &dyn Resolver,
    out: &mut Compiled,
) -> Result<(), CompileError> {
    let any = pattern.starts_with("**");
    if !any && !pattern.starts_with('/') {
        return Err(refuse(
            spec,
            "a bare relative entry has no defined meaning; use an absolute path, `~/` or `**/`",
        ));
    }
    let mut segs = parse_segments(spec, pattern)?;
    let subtree_suffix = segs.last() == Some(&Seg::AnyDepth);
    if subtree_suffix {
        segs.pop();
    }
    if any {
        check_chain(spec, &segs)?;
        // A leading `**` stays in the chain so the match may start at any depth.
        if !segs.is_empty() && segs.first() != Some(&Seg::AnyDepth) {
            segs.insert(0, Seg::AnyDepth);
        }
        out.locations.push(LocationRule {
            id: spec.id,
            kind: spec.kind,
            anchors: None,
            chain: segs,
            subtree: subtree_suffix,
        });
        return Ok(());
    }

    if spec.kind == Kind::Allow {
        // Allow carve-outs are location-only and path-anchored at the root.
        check_chain(spec, &segs)?;
        out.locations.push(LocationRule {
            id: spec.id,
            kind: Kind::Allow,
            anchors: Some(vec![Anchor {
                key: None,
                path: Vec::new(),
            }]),
            chain: segs,
            subtree: subtree_suffix,
        });
        return Ok(());
    }

    let split = segs
        .iter()
        .position(|s| !matches!(s, Seg::Name(_)))
        .unwrap_or(segs.len());
    let prefix: Vec<Vec<u8>> = segs[..split]
        .iter()
        .filter_map(|s| match s {
            Seg::Name(n) => Some(n.clone()),
            _ => None,
        })
        .collect();
    let rest = segs[split..].to_vec();

    if rest.is_empty() && !subtree_suffix {
        // A concrete path: an object rule if it exists, plus a location rule.
        let looked = r.lookup(&prefix);
        match looked {
            Lookup::File(k) => out.objects.push(ObjectRule::File {
                id: spec.id,
                key: k,
            }),
            Lookup::Dir(k) => {
                let (dirs, contents) = r.snapshot(&prefix).unwrap_or_else(|| {
                    let mut d = BTreeSet::new();
                    d.insert(k);
                    (d, BTreeSet::new())
                });
                let mut dirs = dirs;
                dirs.insert(k);
                out.objects.push(ObjectRule::Dir {
                    id: spec.id,
                    dirs,
                    contents,
                });
            }
            Lookup::Absent | Lookup::Unknown => {}
        }
        if prefix.is_empty() {
            out.locations.push(LocationRule {
                id: spec.id,
                kind: Kind::Protect,
                anchors: Some(vec![Anchor {
                    key: None,
                    path: Vec::new(),
                }]),
                chain: Vec::new(),
                subtree: true,
            });
            return Ok(());
        }
        let parent = &prefix[..prefix.len() - 1];
        let (anchor, mut chain) = nearest_anchor(parent, r);
        chain.push(Seg::Name(prefix[prefix.len() - 1].clone()));
        check_chain(spec, &chain)?;
        out.locations.push(LocationRule {
            id: spec.id,
            kind: Kind::Protect,
            anchors: Some(vec![anchor]),
            chain,
            // Always a subtree: nothing lives below a real file, and the broader
            // rule also covers a case-variant directory at the location.
            subtree: true,
        });
        return Ok(());
    }

    let (anchor, mut chain) = nearest_anchor(&prefix, r);
    chain.extend(rest);
    check_chain(spec, &chain)?;
    out.locations.push(LocationRule {
        id: spec.id,
        kind: Kind::Protect,
        anchors: Some(vec![anchor]),
        chain,
        subtree: subtree_suffix,
    });
    Ok(())
}

/// WO-198@v1: compile a policy's entries. Ids must be dense from 0; every entry is
/// validated against the bounded grammar and refused by name if it falls outside.
pub fn compile(specs: &[Spec], r: &dyn Resolver) -> Result<Compiled, CompileError> {
    let mut out = Compiled::default();
    // Alternatives per written entry; per-home copies share an id and do not add.
    let mut alternatives: std::collections::BTreeMap<u16, usize> = Default::default();
    for spec in specs {
        let idx = spec.id as usize;
        if out.sources.len() <= idx {
            out.sources.resize(idx + 1, String::new());
        }
        out.sources[idx] = spec.source.clone();
        let patterns = expand_braces(spec)?;
        let n = alternatives.entry(spec.id).or_insert(0);
        *n = (*n).max(patterns.len());
        if alternatives.values().sum::<usize>() > R_MAX {
            return Err(refuse(
                spec,
                format!("the policy has more than R_MAX ({R_MAX}) entries after `{{}}` expansion"),
            ));
        }
        for pattern in patterns {
            compile_one(spec, &pattern, r, &mut out)?;
        }
    }
    Ok(out)
}
