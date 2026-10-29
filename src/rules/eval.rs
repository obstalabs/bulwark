//! The precedence ladder over an opened file's ancestor chain.

use super::{Anchor, Chain, Compiled, Decision, Kind, LocationRule, ObjectRule, Seg, Verdict};

/// WO-198@v1: how a location rule reached the opened file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Reach {
    /// The rule's last chain element matched the opened file itself.
    names_file: bool,
    /// The rule matched an ancestor and `subtree` covers the file below it.
    subtree: bool,
}

// WO-198@v1: protect compares fold ASCII case so a case-insensitive volume cannot dodge a rule;
// allow compares are byte-exact so a carve-out can never widen by case.
fn byte_eq(a: u8, b: u8, fold: bool) -> bool {
    if fold {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

// WO-198@v1: exact name comparison under the rule's case policy.
fn name_eq(a: &[u8], b: &[u8], fold: bool) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| byte_eq(*x, *y, fold))
}

// WO-198@v1: one-component wildcard match; `*` any bytes, `?` one byte; bounded by
// the compiler (<= MAX_STARS stars, <= NAME_MAX bytes), so the backtracking is small.
pub(crate) fn pattern_match(pat: &[u8], name: &[u8], fold: bool) -> bool {
    let (mut p, mut n) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pat.len() && pat[p] == b'*' {
            star = Some((p, n));
            p += 1;
        } else if p < pat.len() && (pat[p] == b'?' || byte_eq(pat[p], name[n], fold)) {
            p += 1;
            n += 1;
        } else if let Some((sp, sn)) = star {
            p = sp + 1;
            n = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

// WO-198@v1: match one segment against one component name.
fn seg_match(seg: &Seg, name: &[u8], fold: bool) -> bool {
    match seg {
        Seg::Name(n) => name_eq(n, name, fold),
        Seg::Pattern(p) => pattern_match(p, name, fold),
        Seg::AnyDepth => true,
    }
}

// WO-198@v1: match the chain against the names below an anchor; AnyDepth takes zero
// or more whole components. Recursion depth is bounded by MAX_CHAIN.
fn chain_reach(chain: &[Seg], names: &[&[u8]], subtree: bool, fold: bool) -> Reach {
    match chain.first() {
        None => Reach {
            names_file: names.is_empty(),
            subtree: subtree && !names.is_empty(),
        },
        Some(Seg::AnyDepth) => {
            let mut acc = Reach::default();
            for skip in 0..=names.len() {
                let r = chain_reach(&chain[1..], &names[skip..], subtree, fold);
                acc.names_file |= r.names_file;
                acc.subtree |= r.subtree;
            }
            // A chain ending in `**` reaches the file itself at any depth.
            acc
        }
        Some(seg) => match names.first() {
            Some(name) if seg_match(seg, name, fold) => {
                chain_reach(&chain[1..], &names[1..], subtree, fold)
            }
            _ => Reach::default(),
        },
    }
}

// WO-198@v1: positions in the chain (index of the anchor component, or None for the
// root) where an anchor matches.
fn anchor_positions(anchor: &Anchor, chain: &Chain, kind: Kind) -> Vec<Option<usize>> {
    let mut out = Vec::new();
    let by_path = kind == Kind::Protect || anchor.key.is_none();
    if anchor.path.is_empty() {
        let key_hit = anchor.key.is_some() && anchor.key == chain.root;
        if key_hit || by_path || kind == Kind::Allow {
            out.push(None);
        }
        return out;
    }
    for (i, comp) in chain.comps.iter().enumerate() {
        let key_hit = kind == Kind::Protect && anchor.key.is_some() && comp.key == anchor.key;
        let path_hit = by_path
            && anchor.path.len() == i + 1
            && anchor
                .path
                .iter()
                .zip(&chain.comps[..=i])
                .all(|(a, c)| name_eq(a, &c.name, kind == Kind::Protect));
        if key_hit || path_hit {
            out.push(Some(i));
        }
    }
    out
}

// WO-198@v1: everything a location rule reaches for this chain.
fn location_reach(rule: &LocationRule, chain: &Chain) -> Reach {
    let fold = rule.kind == Kind::Protect;
    let names: Vec<&[u8]> = chain.comps.iter().map(|c| c.name.as_slice()).collect();
    let starts: Vec<Option<usize>> = match &rule.anchors {
        None => vec![None],
        Some(anchors) => {
            let mut v = Vec::new();
            for a in anchors {
                v.extend(anchor_positions(a, chain, rule.kind));
            }
            v.sort();
            v.dedup();
            v
        }
    };
    let mut acc = Reach::default();
    for start in starts {
        let below = match start {
            None => &names[..],
            Some(i) => &names[i + 1..],
        };
        let r = chain_reach(&rule.chain, below, rule.subtree, fold);
        acc.names_file |= r.names_file;
        acc.subtree |= r.subtree;
    }
    acc
}

// WO-198@v1: a directory object covers the file when the file or any ancestor is one
// of its launch directories, or the file's inode was under it at launch.
fn dir_object_hit(
    dirs: &std::collections::BTreeSet<super::Key>,
    contents: &std::collections::BTreeSet<super::Key>,
    chain: &Chain,
) -> bool {
    if chain.root.is_some_and(|k| dirs.contains(&k)) {
        return true;
    }
    if let Some(leaf) = chain.comps.last().and_then(|c| c.key) {
        if contents.contains(&leaf) {
            return true;
        }
    }
    chain
        .comps
        .iter()
        .any(|c| c.key.is_some_and(|k| dirs.contains(&k)))
}

// WO-198@v1: lowest rule id among the candidates, so receipts are deterministic.
fn first(ids: impl Iterator<Item = u16>) -> Option<u16> {
    ids.min()
}

/// WO-198@v1: decide an open from its ancestor chain by the six-step ladder:
/// 1 protected file object; 2 allow naming the file by a literal name; 3 protect
/// naming the file; 4 allow by pattern or subtree; 5 protect subtree or directory
/// object; 6 not protected. A consent grant is applied by the caller afterwards.
pub fn decide(chain: &Chain, rules: &Compiled) -> Decision {
    let leaf = chain.comps.last().and_then(|c| c.key);
    if let Some(id) = first(rules.objects.iter().filter_map(|o| match o {
        ObjectRule::File { id, key } if Some(*key) == leaf => Some(*id),
        _ => None,
    })) {
        return Decision {
            verdict: Verdict::Protected,
            step: 1,
            rule: Some(id),
        };
    }

    let reaches: Vec<(&LocationRule, Reach)> = rules
        .locations
        .iter()
        .map(|r| (r, location_reach(r, chain)))
        .collect();
    let literal_last = |r: &LocationRule| matches!(r.chain.last(), Some(Seg::Name(_)));

    let step = |kind: Kind, pred: &dyn Fn(&LocationRule, Reach) -> bool| {
        first(
            reaches
                .iter()
                .filter(|(r, re)| r.kind == kind && pred(r, *re))
                .map(|(r, _)| r.id),
        )
    };

    if let Some(id) = step(Kind::Allow, &|r, re| re.names_file && literal_last(r)) {
        return Decision {
            verdict: Verdict::Allowed,
            step: 2,
            rule: Some(id),
        };
    }
    if let Some(id) = step(Kind::Protect, &|_, re| re.names_file) {
        return Decision {
            verdict: Verdict::Protected,
            step: 3,
            rule: Some(id),
        };
    }
    if let Some(id) = step(Kind::Allow, &|r, re| {
        (re.names_file && !literal_last(r)) || re.subtree
    }) {
        return Decision {
            verdict: Verdict::Allowed,
            step: 4,
            rule: Some(id),
        };
    }
    let subtree_loc = step(Kind::Protect, &|_, re| re.subtree);
    let dir_obj = first(rules.objects.iter().filter_map(|o| match o {
        ObjectRule::Dir { id, dirs, contents } if dir_object_hit(dirs, contents, chain) => {
            Some(*id)
        }
        _ => None,
    }));
    if let Some(id) = [subtree_loc, dir_obj].into_iter().flatten().min() {
        return Decision {
            verdict: Verdict::Protected,
            step: 5,
            rule: Some(id),
        };
    }
    Decision {
        verdict: Verdict::NotProtected,
        step: 6,
        rule: None,
    }
}

// WO-198@v1: pin the matcher and ladder behaviour independent of the compiler.
#[cfg(test)]
mod tests {
    use super::*;

    // WO-198@v1: wildcard semantics within one component.
    #[test]
    fn pattern_match_basics() {
        assert!(pattern_match(b"*secret*", b"db_secret_key", false));
        assert!(pattern_match(b".*", b".netrc", false));
        assert!(!pattern_match(b".*", b"netrc", false));
        assert!(pattern_match(b"a?c", b"abc", false));
        assert!(!pattern_match(b"a?c", b"ac", false));
        assert!(pattern_match(b"*SECRET*", b"my_secret", true));
        assert!(!pattern_match(b"*SECRET*", b"my_secret", false));
        assert!(pattern_match(b"*", b"", false));
    }

    // WO-198@v1: AnyDepth matches zero or more whole components.
    #[test]
    fn any_depth_spans_components() {
        let chain = [Seg::AnyDepth, Seg::Name(b".env".to_vec())];
        let names: Vec<&[u8]> = vec![b"a", b"b", b".env"];
        assert!(chain_reach(&chain, &names, false, true).names_file);
        let names: Vec<&[u8]> = vec![b".env"];
        assert!(chain_reach(&chain, &names, false, true).names_file);
        let names: Vec<&[u8]> = vec![b".env", b"x"];
        let r = chain_reach(&chain, &names, false, true);
        assert!(!r.names_file && !r.subtree);
    }
}
