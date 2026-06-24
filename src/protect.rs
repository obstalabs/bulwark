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

/// Recursion bound for protected-directory expansion. Credential stores
/// (`~/.ssh`, `~/.gnupg`, `~/.aws`) are shallow; this caps a pathological
/// `--protect /` from walking the whole filesystem at launch. Beyond the cap the
/// directory's inode is still in `dirs`, so the descendant check in `protects`
/// keeps every file under it protected — only the per-inode snapshot stops.
const MAX_RECURSION_DEPTH: usize = 64;
/// Total inodes to snapshot across all protected trees before stopping the walk
/// (the descendant check still covers the rest). Logged when hit.
const MAX_SNAPSHOT_ENTRIES: usize = 200_000;

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
///
/// Two layers, both keyed on inode identity (never on a mutable path string):
/// `inodes` is the snapshot of every protected file/dir inode known at launch
/// (recursed through protected directories); `dirs` is the subset that are
/// directories. The descendant check in [`ProtectedSet::protects`] uses `dirs`
/// to also protect files that were NOT in the launch snapshot — nested deeper
/// than the walk reached, or created under a protected directory *after* launch
/// — by matching the opened file's ancestor directory inodes against `dirs`.
/// This closes the directory-expansion gap where `--protect ~/.gnupg` left
/// `~/.gnupg/private-keys-v1.d/<key>` and post-launch keys readable.
#[derive(Debug, Default, Clone)]
pub struct ProtectedSet {
    inodes: HashSet<InodeKey>,
    dirs: HashSet<InodeKey>, // inodes of protected directories (for descendant matching)
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    origins: Vec<ProtectedOrigin>, // first resolved path for each inode
}

impl ProtectedSet {
    /// Resolve each path to its inode. A directory contributes its own inode and
    /// is recorded as a protected directory, then is walked recursively (bounded
    /// by [`MAX_RECURSION_DEPTH`]/[`MAX_SNAPSHOT_ENTRIES`]) so nested files and
    /// subdirectories are snapshotted too. Top-level symlinks are followed to
    /// their target inode on purpose: protecting the target by inode is exactly
    /// the point. Recursion does NOT descend through symlinked directories, so a
    /// symlink inside a protected tree cannot redirect the walk into an unrelated
    /// hierarchy.
    pub fn resolve(paths: &[std::path::PathBuf]) -> Result<Self> {
        let mut b = Build::default();
        for p in paths {
            let meta = fs::metadata(p)
                .with_context(|| format!("cannot stat protected path {}", p.display()))?;
            b.add(p, &meta, 0);
        }
        b.warn_if_capped();
        Ok(b.into_set())
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
        let mut b = Build::default();
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
            b.add(p, &meta, 0);
        }
        b.warn_if_capped();
        (b.into_set(), skipped)
    }

    /// True if this inode is in the launch snapshot (open should be denied).
    /// Prefer [`ProtectedSet::protects`], which also covers descendants of a
    /// protected directory; this exact-inode check is retained for callers that
    /// already hold the identity (e.g. macOS ES seeding) and as the snapshot
    /// probe in tests; the Linux gate now decides via `protects`.
    #[allow(dead_code)]
    pub fn contains(&self, key: &InodeKey) -> bool {
        self.inodes.contains(key)
    }

    /// True if an open of `key` at canonical `path` must be treated as protected.
    ///
    /// Protected when the inode is directly in the launch snapshot, OR when any
    /// ancestor directory of `path` is a protected directory. The ancestor walk
    /// stats each parent and matches its inode against `dirs`, so a file nested
    /// below the snapshot depth, or created under a protected directory after
    /// launch, is still denied — without trusting the path string itself as the
    /// authority (the authority is the ancestor *inodes*).
    ///
    /// Residual (documented, not silently ignored): a file hardlinked OUT of a
    /// protected directory and opened via the outside path has no protected
    /// ancestor; if it was present at launch its own inode is in the snapshot and
    /// it stays denied, but a post-launch file linked out escapes. Creating that
    /// link requires write access to the protected directory, which the dropped,
    /// unprivileged agent typically lacks for a mode-700 credential store.
    pub fn protects(&self, key: &InodeKey, path: &str) -> bool {
        if self.inodes.contains(key) {
            return true;
        }
        if self.dirs.is_empty() {
            return false;
        }
        let mut cur = Path::new(path);
        // Walk parents toward the root, matching ancestor directory inodes.
        while let Some(parent) = cur.parent() {
            if let Ok(m) = fs::metadata(parent) {
                let pkey = InodeKey::of(&m);
                if self.dirs.contains(&pkey) {
                    return true;
                }
            }
            if parent.parent().is_none() {
                break; // reached "/"
            }
            cur = parent;
        }
        false
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

/// Accumulator for resolving protected paths into the inode/dir snapshot,
/// with bounded recursion through protected directories.
#[derive(Default)]
struct Build {
    inodes: HashSet<InodeKey>,
    dirs: HashSet<InodeKey>,
    origins: Vec<ProtectedOrigin>,
    capped: bool,
}

impl Build {
    /// Record `path` (resolved metadata `meta`) and, if it is a directory,
    /// recurse into its real subdirectories. `depth` is the current recursion
    /// depth from the top-level protected path.
    fn add(&mut self, path: &Path, meta: &fs::Metadata, depth: usize) {
        let key = InodeKey::of(meta);
        if self.inodes.insert(key) {
            self.origins.push(ProtectedOrigin {
                key,
                path: path.display().to_string(),
            });
        }
        if !meta.is_dir() {
            return;
        }
        self.dirs.insert(key);
        if depth >= MAX_RECURSION_DEPTH {
            self.capped = true;
            return;
        }
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return, // unreadable dir: its inode is still in `dirs`
        };
        for entry in entries.flatten() {
            if self.inodes.len() >= MAX_SNAPSHOT_ENTRIES {
                self.capped = true;
                return;
            }
            // Decide recursion by the entry's own type (no symlink follow), so a
            // symlinked directory does not redirect the walk out of the tree.
            let is_real_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            // Record the inode by following symlinks (protect the link target),
            // matching the top-level resolve semantics.
            let child_meta = match fs::metadata(entry.path()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if is_real_dir {
                self.add(&entry.path(), &child_meta, depth + 1);
            } else {
                // A regular file, or a symlink (entry type is not a real dir).
                // Record the target inode so an open of it is denied, but do NOT
                // add it to `dirs`: a symlink to an external directory must not
                // pull that whole hierarchy into the descent set (it would
                // silently over-protect, e.g. a link to /usr/share). Protect a
                // symlinked directory's contents by listing its real path.
                let ck = InodeKey::of(&child_meta);
                if self.inodes.insert(ck) {
                    self.origins.push(ProtectedOrigin {
                        key: ck,
                        path: entry.path().display().to_string(),
                    });
                }
            }
        }
    }

    fn warn_if_capped(&self) {
        if self.capped {
            eprintln!(
                "[bulwark] protected-path snapshot hit the recursion/entry cap \
                 ({} inodes); deeper files stay protected by directory descent",
                self.inodes.len()
            );
        }
    }

    fn into_set(self) -> ProtectedSet {
        ProtectedSet {
            inodes: self.inodes,
            dirs: self.dirs,
            origins: self.origins,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A unique scratch directory under the system temp dir (no external dep).
    fn scratch(tag: &str) -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("bulwark-protect-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn key_of(p: &Path) -> InodeKey {
        InodeKey::of(&fs::metadata(p).unwrap())
    }

    fn s(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    /// A-3 negative control: a file created UNDER a protected directory AFTER
    /// resolve() ran is still protected, via the ancestor-directory descent —
    /// even though its inode was never in the launch snapshot. The pre-fix
    /// one-level `contains` snapshot missed exactly this (`--protect ~/.gnupg`
    /// then a key written to a subdir). Reverting `protects` to `contains` makes
    /// this red.
    #[test]
    fn post_launch_file_under_protected_dir_is_protected() {
        let root = scratch("postlaunch");
        let sub = root.join("private-keys-v1.d");
        fs::create_dir_all(&sub).unwrap();

        let set = ProtectedSet::resolve(std::slice::from_ref(&root)).unwrap();

        // Created only now — not present when the snapshot was taken.
        let key = sub.join("new.key");
        fs::write(&key, b"secret").unwrap();

        let k = key_of(&key);
        assert!(
            !set.contains(&k),
            "inode must NOT be in the launch snapshot (proves descent does the work)"
        );
        assert!(
            set.protects(&k, &s(&key)),
            "post-launch nested file must be protected by directory descent"
        );
    }

    /// Deeply nested files present at launch are snapshotted by recursion (so
    /// they are protected by inode even if hardlinked out later).
    #[test]
    fn nested_file_present_at_launch_is_snapshotted() {
        let root = scratch("nested");
        let deep = root.join("a/b/c");
        fs::create_dir_all(&deep).unwrap();
        let key = deep.join("id_ed25519");
        fs::write(&key, b"k").unwrap();

        let set = ProtectedSet::resolve(std::slice::from_ref(&root)).unwrap();
        let k = key_of(&key);
        assert!(
            set.contains(&k),
            "recursion must snapshot deep nested inode"
        );
        assert!(set.protects(&k, &s(&key)));
    }

    /// A sibling file outside the protected directory is not protected: descent
    /// only matches when an ancestor directory inode is protected.
    #[test]
    fn file_outside_protected_dir_is_not_protected() {
        let base = scratch("outside");
        let prot = base.join("protected");
        let other = base.join("other");
        fs::create_dir_all(&prot).unwrap();
        fs::create_dir_all(&other).unwrap();
        let secret = other.join("secret");
        fs::write(&secret, b"s").unwrap();

        let set = ProtectedSet::resolve(&[prot]).unwrap();
        let k = key_of(&secret);
        assert!(!set.contains(&k));
        assert!(
            !set.protects(&k, &s(&secret)),
            "a file outside the protected tree must stay allowed"
        );
    }

    /// Recursion does not follow a symlinked directory out of the tree: a file
    /// in the symlink's external target is not pulled into the protected dir set.
    #[cfg(unix)]
    #[test]
    fn recursion_does_not_descend_through_symlinked_dir() {
        let base = scratch("symlink");
        let prot = base.join("protected");
        let outside = base.join("outside");
        fs::create_dir_all(&prot).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let outside_secret = outside.join("secret");
        fs::write(&outside_secret, b"s").unwrap();
        // protected/link -> outside  (a symlinked directory inside the tree)
        std::os::unix::fs::symlink(&outside, prot.join("link")).unwrap();

        let set = ProtectedSet::resolve(&[prot]).unwrap();
        let k = key_of(&outside_secret);
        // The file reached only by walking THROUGH the symlink (its real path is
        // under `outside`, whose inode is not a protected dir) stays allowed.
        assert!(
            !set.protects(&k, &s(&outside_secret)),
            "walk must not adopt a symlinked dir's external tree as protected"
        );
    }
}
