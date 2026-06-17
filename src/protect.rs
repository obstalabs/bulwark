//! Protected-inode set.
//!
//! The gate decides by `(dev, ino)`, never by path string — this is what
//! defeats symlink and rename bypass. Protected paths are resolved to their
//! underlying inodes once, at launch.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result};

/// A device+inode pair uniquely identifying a file on the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InodeKey {
    pub dev: u64,
    pub ino: u64,
}

impl InodeKey {
    fn of(meta: &fs::Metadata) -> Self {
        InodeKey {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

/// path evidence for a protected inode, used by macOS consent seeding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedOrigin {
    pub key: InodeKey,
    pub path: String,
}

/// The set of inodes whose open() is denied for the supervised tree.
#[derive(Debug, Default, Clone)]
pub struct ProtectedSet {
    inodes: HashSet<InodeKey>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    origins: Vec<ProtectedOrigin>, // first resolved path for each inode
}

impl ProtectedSet {
    /// Resolve each path to its inode. A directory contributes its own inode
    /// plus the inodes of its immediate entries (one level — the MVP does not
    /// recurse; deep trees are out of scope for the proof slice). Symlinks are
    /// followed to their target inode on purpose: protecting the target by
    /// inode is exactly the point.
    pub fn resolve(paths: &[std::path::PathBuf]) -> Result<Self> {
        let mut inodes = HashSet::new();
        let mut origins = Vec::new();
        for p in paths {
            let meta = fs::metadata(p)
                .with_context(|| format!("cannot stat protected path {}", p.display()))?;
            insert_origin(&mut inodes, &mut origins, p, &meta);
            if meta.is_dir() {
                for entry in fs::read_dir(p)
                    .with_context(|| format!("cannot read protected dir {}", p.display()))?
                {
                    let entry = entry?;
                    if let Ok(m) = entry.metadata() {
                        insert_origin(&mut inodes, &mut origins, &entry.path(), &m);
                    }
                }
            }
        }
        Ok(ProtectedSet { inodes, origins })
    }

    /// Resolve protected paths leniently: paths that do not exist are skipped
    /// rather than erroring. This suits a default profile that lists credential
    /// stores (`~/.aws`, `~/.kube`, ...) which may be absent on a given host.
    /// Returns the set plus the count of skipped (missing) paths.
    pub fn resolve_lenient<I, P>(paths: I) -> (Self, usize)
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut inodes = HashSet::new();
        let mut origins = Vec::new();
        let mut skipped = 0usize;
        for p in paths {
            let p = p.as_ref();
            let meta = match fs::metadata(p) {
                Ok(m) => m,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            insert_origin(&mut inodes, &mut origins, p, &meta);
            if meta.is_dir() {
                if let Ok(entries) = fs::read_dir(p) {
                    for entry in entries.flatten() {
                        if let Ok(m) = entry.metadata() {
                            insert_origin(&mut inodes, &mut origins, &entry.path(), &m);
                        }
                    }
                }
            }
        }
        (ProtectedSet { inodes, origins }, skipped)
    }

    /// True if this inode is protected (open should be denied).
    pub fn contains(&self, key: &InodeKey) -> bool {
        self.inodes.contains(key)
    }

    pub fn len(&self) -> usize {
        self.inodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inodes.is_empty()
    }

    /// expose resolved inode identities to the macOS Endpoint Security
    /// edge config without weakening the path-resolution invariant.
    #[cfg(target_os = "macos")]
    pub fn keys(&self) -> impl Iterator<Item = InodeKey> + '_ {
        self.inodes.iter().copied()
    }

    /// expose path evidence without changing inode authority.
    #[cfg(target_os = "macos")]
    pub fn origins(&self) -> impl Iterator<Item = &ProtectedOrigin> {
        self.origins.iter()
    }
}

fn insert_origin(
    inodes: &mut HashSet<InodeKey>,
    origins: &mut Vec<ProtectedOrigin>,
    path: &Path,
    meta: &fs::Metadata,
) {
    let key = InodeKey::of(meta);
    if inodes.insert(key) {
        origins.push(ProtectedOrigin {
            key,
            path: path.display().to_string(),
        });
    }
}
