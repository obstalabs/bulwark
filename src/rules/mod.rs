//! The decision-time rule contract every Bulwark evaluator shares.
//!
//! A policy entry compiles into two kinds of rule:
//!
//! - an **object** rule: the (dev, ino) of a file or directory that existed at
//!   launch. It follows the object through renames and hard links;
//! - a **location** rule: an anchor directory plus a bounded chain of names. It
//!   protects whatever sits at that location when an open happens, so a file that
//!   is replaced, created later, or renamed into the location is still covered.
//!
//! An open is decided from its ancestor chain only (names and inode keys of each
//! component from the root down to the opened file), by a fixed six-step ladder.
//! The module does no I/O and never panics on caller input: callers acquire the
//! chain and resolve launch paths, so the same code can back `check`, the Linux
//! gate and, linked as a static library, the macOS gate.

mod compile;
mod eval;

#[allow(unused_imports)]
pub use compile::{compile, CompileError, Lookup, Resolver, Spec};
#[allow(unused_imports)]
pub use eval::decide;

use std::collections::BTreeSet;

/// WO-198@v1: the bounds below keep every rule evaluable by a verifier-bounded
/// kernel program as well as by userspace, so all cores accept the same policies.
/// The most policy entries one compile accepts (after brace alternatives are
/// expanded; per-home expansion does not count: a rule's anchors are a set).
pub const R_MAX: usize = 128;
/// WO-198@v1: longest name chain below an anchor. 16 matches a u16 state mask.
pub const MAX_CHAIN: usize = 16;
/// WO-198@v1: `*` per pattern segment; the fixed prefix/mid/suffix lowering needs a constant shape.
pub const MAX_STARS: usize = 2;
/// WO-198@v1: `**` segments per rule (a trailing `/**` is the subtree flag, not counted).
pub const MAX_ANY_DEPTH: usize = 2;
/// WO-198@v1: longest literal run inside a pattern segment.
pub const MAX_LITERAL: usize = 64;
/// WO-198@v1: longest name a filesystem gives one component (NAME_MAX).
pub const NAME_MAX: usize = 255;
/// WO-198@v1: alternatives one `{a,b}` group may expand to.
pub const MAX_ALTERNATIVES: usize = 16;

/// WO-198@v1: identity of a filesystem object, as `stat` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    pub dev: u64,
    pub ino: u64,
}

/// WO-198@v1: protect entries deny, allow entries carve out of protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Protect,
    Allow,
}

/// WO-198@v1: one element of a location rule's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    /// An exact component name.
    Name(Vec<u8>),
    /// One component matched by `*` (any run of bytes) and `?` (one byte).
    Pattern(Vec<u8>),
    /// `**`: zero or more whole components.
    AnyDepth,
}

/// WO-198@v1: where a location rule starts. A protect anchor matches an ancestor
/// by its launch inode OR by the directory now at its launch path; an allow anchor
/// matches by path only, so recreating a path can never widen access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub key: Option<Key>,
    /// Components of the anchor's launch path below `/` (empty = the root).
    pub path: Vec<Vec<u8>>,
}

/// WO-198@v1: a rule that applies at a location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationRule {
    pub id: u16,
    pub kind: Kind,
    /// `None` = any ancestor (the entry started with `**`).
    pub anchors: Option<Vec<Anchor>>,
    pub chain: Vec<Seg>,
    /// Also protect (or allow) everything below a match.
    pub subtree: bool,
}

/// WO-198@v1: a rule that follows an object that existed at launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectRule {
    /// A concrete protected file: highest precedence, never carved out.
    File { id: u16, key: Key },
    /// A concrete protected directory: its own key and its launch descendants'
    /// directory keys (`dirs`), plus the launch inodes of files under it
    /// (`contents`, so a hard link elsewhere stays protected).
    Dir {
        id: u16,
        dirs: BTreeSet<Key>,
        contents: BTreeSet<Key>,
    },
}

/// WO-198@v1: everything a policy compiles to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Compiled {
    /// The entry text for each rule id, for receipts and errors.
    pub sources: Vec<String>,
    pub objects: Vec<ObjectRule>,
    pub locations: Vec<LocationRule>,
}

/// WO-198@v1: one component of the opened file's ancestor chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub name: Vec<u8>,
    /// `None` for a component that does not exist (a `check` of an absent path).
    pub key: Option<Key>,
}

/// WO-198@v1: the opened file's ancestry, root first; the last component is the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chain {
    pub root: Option<Key>,
    pub comps: Vec<Component>,
}

/// WO-198@v1: the outcome of the ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Protected,
    /// Carved out of protection by an allow entry.
    Allowed,
    NotProtected,
}

/// WO-198@v1: a verdict with the ladder step that decided it and the rule that matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    /// 1..=6, the step of the precedence ladder that decided.
    pub step: u8,
    pub rule: Option<u16>,
}

impl Chain {
    // WO-198@v1: build a key-less chain from an absolute path (tests and absent tails).
    /// A chain for `path` with no inode keys. `path` must be absolute.
    pub fn from_path_unkeyed(path: &str) -> Chain {
        Chain {
            root: None,
            comps: split_path(path)
                .into_iter()
                .map(|name| Component { name, key: None })
                .collect(),
        }
    }
}

// WO-198@v1: one normalisation of path text shared by the compiler and chain builders.
/// Split an absolute path into its components, dropping empty and `.` parts.
pub fn split_path(path: &str) -> Vec<Vec<u8>> {
    path.as_bytes()
        .split(|b| *b == b'/')
        .filter(|s| !s.is_empty() && *s != b".")
        .map(|s| s.to_vec())
        .collect()
}
