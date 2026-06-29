//! Default-deny allowlist mode for non-interactive (CI/CD) use.
//!
//! The deny-list `Policy` answers "protect these, allow the rest." This module
//! answers the inverse, for least-privilege dispatch: **allow ONLY these paths,
//! deny everything else.** A triage agent can be handed exactly one path (a log
//! directory) and is denied reach to credentials, other databases, or a data
//! directory — without a human in the loop.
//!
//! ## The runtime base set is a real, stated limit — not a magic wand
//!
//! A process cannot execute while reading *only* the granted path: it must read
//! its interpreter, libc, locale data, terminfo, and a handful of system files
//! just to start. So allowlist mode allows a **base set** of standard runtime
//! paths in addition to the operator's grants. That base set is allowed reads.
//! It is the floor of what the supervised tree can see, and it is wide enough
//! to run a normal program — which means a secret deliberately placed under
//! `/usr/lib` or `/etc` is within it. The base set is therefore printable
//! (`bulwark base-set`) and documented, so the operator sees exactly what is
//! permitted and can reason about, or tighten, the trade-off. Bulwark is a
//! tool with limits; this is one of them, stated up front.
//!
//! Base-set decisions are by **path glob**: the base directories hold far too
//! many inodes to enumerate at launch, so we match the observed path of each
//! open against the allow globs. Platform gates can harden operator grants with
//! inode snapshots where their kernel surface supports it.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::glob;
use crate::protect::InodeKey;

/// Recursion bound for snapshotting grant inodes (mirrors protect.rs). Caps a
/// pathological `--allow /**` from walking the whole filesystem at launch.
const MAX_GRANT_DEPTH: usize = 64;
/// Total grant inodes to snapshot before stopping (logged when hit). Beyond it,
/// matching files fall through to deny — fail closed, never silently allowed.
const MAX_GRANT_ENTRIES: usize = 200_000;

/// The minimal set of read paths a typical dynamically-linked program needs to
/// execute on Linux, derived empirically (strace of `bash -c cat`). Globbed by
/// directory rather than by exact file so it is architecture-independent
/// (`/lib/**` covers `aarch64-linux-gnu`, `x86_64-linux-gnu`, etc.).
///
/// This is an ALLOW set. Everything in it is readable by the supervised tree.
#[cfg(target_os = "linux")]
pub const RUNTIME_BASE_SET: &[&str] = &[
    // Dynamic linker + shared libraries.
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d/**",
    "/lib/**",
    "/lib64/**",
    "/usr/lib/**",
    "/usr/lib64/**",
    // The executables themselves.
    "/bin/**",
    "/sbin/**",
    "/usr/bin/**",
    "/usr/sbin/**",
    // Locale / character conversion / terminal.
    "/usr/share/locale/**",
    "/usr/share/zoneinfo/**",
    "/etc/localtime",
    "/dev/tty",
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    // Process self-introspection (the supervised process and Bulwark's own
    // ancestry walk read these).
    "/proc/self/**",
    "/proc/*/stat",
    "/proc/*/status",
    // Name resolution basics (so an agent can do DNS / user lookups to work).
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/host.conf",
    "/etc/passwd",
    "/etc/group",
];

/// macOS runtime base set for default-deny mode.
///
/// This is intentionally distinct from the Linux set: macOS program startup is
/// driven by dyld, the dyld shared cache, framework bundles, cryptex paths on
/// modern releases, and Darwin user/group/locale data. It is an ALLOW set, and
/// `bulwark base-set` prints it for operator review.
#[cfg(target_os = "macos")]
pub const RUNTIME_BASE_SET: &[&str] = &[
    // dyld, shared cache, system libraries, and frameworks.
    "/usr/lib/dyld",
    "/usr/lib/**",
    "/System/Library/**",
    "/System/Cryptexes/**",
    "/System/Volumes/Preboot/Cryptexes/OS/usr/lib/**",
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/**",
    // Apple-provided command locations needed for simple launches.
    "/bin/**",
    "/sbin/**",
    "/usr/bin/**",
    "/usr/sbin/**",
    // Locale, timezone, and name-service basics.
    "/usr/share/locale/**",
    "/usr/share/icu/**",
    "/usr/share/zoneinfo/**",
    "/etc/localtime",
    "/private/etc/localtime",
    "/etc/passwd",
    "/private/etc/passwd",
    "/etc/group",
    "/private/etc/group",
    "/etc/nsswitch.conf",
    "/private/etc/nsswitch.conf",
    "/etc/hosts",
    "/private/etc/hosts",
    // Device nodes routinely touched by CLI startup/runtime paths.
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];

/// Conservative fallback for platforms that only compile the portable CLI and
/// fail closed for enforcement.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub const RUNTIME_BASE_SET: &[&str] = &[];

/// A default-deny allowlist: allow the base runtime set plus explicit grants,
/// deny every other read by the supervised tree.
#[derive(Debug, Clone)]
pub struct AllowList {
    /// Operator-granted globs (the paths the agent is dispatched to read).
    grants: Vec<String>,
    /// Whether the runtime base set is included (almost always yes; can be
    /// dropped for a fully static binary that needs nothing).
    include_base: bool,
    /// Inode identities reachable under the grants AND matching a grant glob at
    /// launch. Operator grants are gated on this set, not on the path alone, so a
    /// file aliased into a grant path after launch — hardlinked or renamed in from outside — presents a foreign inode and is denied. Empty
    /// until [`AllowList::snapshot_grants`] runs (the gate calls it at launch;
    /// the base set is deliberately NOT snapshotted — see `allows_open`).
    /// Each entry is `(inode, generation)`. The generation (from
    /// `FS_IOC_GETVERSION`) disambiguates inode-number REUSE: on filesystems that
    /// recycle inode numbers (ext4, xfs), a granted file deleted mid-run whose
    /// number is reused by a foreign file would otherwise match the snapshot by
    /// `(dev, ino)` alone. The kernel bumps the generation on reuse, so the foreign
    /// file's `(dev, ino, gen)` differs and is denied. `None` generation means the
    /// filesystem did not report one (see `fs_generation`) — such entries match
    /// only another `None`, and `allows_open` fails CLOSED when the opened file's
    /// generation is unreadable, so a missing generation never weakens the gate.
    grant_inodes: HashSet<(InodeKey, Option<u64>)>,
    /// Whether the snapshot hit its cap (some matching inodes were not recorded;
    /// they will be denied, never allowed).
    grant_capped: bool,
}

/// Read a file's generation number via `FS_IOC_GETVERSION`, the portable inode
/// "version" the kernel bumps when an inode number is reused after delete. Returns
/// `None` if the filesystem does not support it (some tmpfs/overlay/network fs) —
/// callers treat `None` as "cannot prove freshness" and fail closed for grant
/// matching. Linux-only (the ioctl does not exist elsewhere).
#[cfg(target_os = "linux")]
pub(crate) fn fs_generation_fd(fd: std::os::unix::io::RawFd) -> Option<u64> {
    // FS_IOC_GETVERSION writes a c_long (the generation) into the out param.
    let mut gen_val: libc::c_long = 0;
    // SAFETY: fd is a valid open descriptor; gen_val is a valid c_long out-param.
    // `ioctl`'s request arg is `c_ulong` on glibc but `c_int` on musl; cast to the
    // platform's expected type so the static musl gate compiles too.
    let rc = unsafe { libc::ioctl(fd, FS_IOC_GETVERSION as _, &mut gen_val) };
    if rc == 0 {
        Some(gen_val as u64)
    } else {
        None
    }
}

/// Open `path` read-only (no symlink follow on the final component) and read its
/// generation. Used at snapshot time, where we have a path, not an fd.
#[cfg(target_os = "linux")]
fn fs_generation_path(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: c is a valid NUL-terminated path.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return None;
    }
    let g = fs_generation_fd(fd);
    // SAFETY: fd was opened just above and is not used after close.
    unsafe { libc::close(fd) };
    g
}

// `FS_IOC_GETVERSION` is `_IOR('v', 1, long)`. libc does not expose it on all
// targets, so define it from the stable ioctl encoding. Linux uses the same value
// across architectures we support.
#[cfg(target_os = "linux")]
const FS_IOC_GETVERSION: libc::c_ulong = 0x8008_7601;

/// Generation of the file at `path` for the snapshot. Linux reads it via the
/// ioctl; other platforms have no equivalent and return `None` (decisions there
/// rely on the macOS ES gate's own inode model, not this snapshot).
#[cfg(target_os = "linux")]
fn grant_generation(path: &Path) -> Option<u64> {
    fs_generation_path(path)
}
#[cfg(not(target_os = "linux"))]
fn grant_generation(_path: &Path) -> Option<u64> {
    None
}

impl AllowList {
    /// Build from operator grants, including the runtime base set. The grant
    /// inode snapshot starts empty; call [`AllowList::snapshot_grants`] once the
    /// real grant paths exist on the host (the supervised gate does this at
    /// launch). Path-only checks (`allows`, `allowed_globs`) work without it.
    pub fn new(grants: Vec<String>) -> Self {
        AllowList {
            grants,
            include_base: true,
            grant_inodes: HashSet::new(),
            grant_capped: false,
        }
    }

    /// Snapshot the inode identities currently reachable under each grant glob.
    /// Only inodes whose path actually matches the grant glob are recorded — NOT
    /// every inode under the glob's directory prefix — so a non-granted file
    /// sharing the prefix (e.g. `secret.env` beside an `--allow '<dir>/*.log'`)
    /// is never snapshotted and therefore cannot be reached by hardlinking it to
    /// a granted name. Idempotent; call at launch before supervising.
    pub fn snapshot_grants(&mut self) {
        let grants = self.grants.clone();
        for g in &grants {
            let prefix = concrete_prefix(g);
            if prefix.is_empty() {
                continue;
            }
            self.snapshot_one(g, Path::new(prefix), 0);
        }
        if self.grant_capped {
            eprintln!(
                "[bulwark] grant inode snapshot hit the cap ({} inodes); files beyond \
                 it are denied (fail closed)",
                self.grant_inodes.len()
            );
        }
    }

    /// Walk `path` (a concrete grant prefix), recording the inode of every entry
    /// whose path matches grant glob `g`. Bounded by depth and total entries.
    fn snapshot_one(&mut self, g: &str, path: &Path, depth: usize) {
        if self.grant_inodes.len() >= MAX_GRANT_ENTRIES {
            self.grant_capped = true;
            return;
        }
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };
        let path_str = path.to_string_lossy();
        if glob::matches(g, &path_str) {
            let gen_val = grant_generation(path);
            self.grant_inodes.insert((InodeKey::of(&meta), gen_val));
        }
        if !meta.is_dir() || depth >= MAX_GRANT_DEPTH {
            return;
        }
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            // Recurse by the entry's own type (no symlink follow), so a symlinked
            // directory inside a grant cannot redirect the walk out of the tree.
            let is_real_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_real_dir {
                self.snapshot_one(g, &entry.path(), depth + 1);
            } else if let Ok(m) = fs::metadata(entry.path()) {
                if self.grant_inodes.len() >= MAX_GRANT_ENTRIES {
                    self.grant_capped = true;
                    return;
                }
                let ep = entry.path();
                if glob::matches(g, &ep.to_string_lossy()) {
                    let gen_val = grant_generation(&ep);
                    self.grant_inodes.insert((InodeKey::of(&m), gen_val));
                }
            }
        }
    }

    /// Drop the runtime base set (only safe for a static binary that opens
    /// nothing beyond its grants — rare; the agent will fail to start
    /// otherwise).
    pub fn without_base(mut self) -> Self {
        self.include_base = false;
        self
    }

    /// Every allow glob this list permits, base set first, in order.
    pub fn allowed_globs(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.include_base {
            out.extend(RUNTIME_BASE_SET.iter().map(|s| s.to_string()));
        }
        out.extend(self.grants.iter().cloned());
        out
    }

    /// operator grants only, excluding the platform runtime base set.
    #[cfg(target_os = "macos")]
    #[allow(dead_code)] // retained for diagnostics / a future recursive-witness layer
    pub fn grant_globs(&self) -> &[String] {
        &self.grants
    }

    /// Snapshotted grant inode identities for the macOS ES edge. The edge gates
    /// grants on inode membership (the same `allow_inode` set it already
    /// enforces), NOT a path-beneath grant root — so a hardlink/rename of a
    /// foreign file into a granted path presents an inode the snapshot never
    /// recorded and is denied (the macOS analog of the Linux grant inode gate).
    /// Requires [`AllowList::snapshot_grants`] to have run (the launch path does).
    #[cfg(target_os = "macos")]
    pub fn grant_inode_keys(&self) -> impl Iterator<Item = InodeKey> + '_ {
        // macOS keys on inode only (no FS_IOC_GETVERSION there); drop the
        // generation, which is always `None` on non-Linux.
        self.grant_inodes.iter().map(|(k, _gen)| *k)
    }

    /// runtime base globs included for this platform.
    #[cfg(target_os = "macos")]
    pub fn base_globs(&self) -> &'static [&'static str] {
        if self.include_base {
            RUNTIME_BASE_SET
        } else {
            &[]
        }
    }

    /// Path-only allow check: true if `path` matches the base set or a grant
    /// glob. Retained for grant/base-set listing and policy preview; the live
    /// gate decides with [`AllowList::allows_open`], which also gates grants on
    /// inode identity.
    #[allow(dead_code)]
    pub fn allows(&self, path: &str) -> bool {
        if self.include_base && RUNTIME_BASE_SET.iter().any(|g| glob::matches(g, path)) {
            return true;
        }
        self.grants.iter().any(|g| glob::matches(g, path))
    }

    /// Decide an open by both its observed `path` and the opened inode `key`.
    ///
    /// - The runtime **base set** is matched by path only: it spans far too many
    ///   inodes to snapshot (libc, locale, every `/proc/*/stat`), and it is a
    ///   stated, printable read floor — not a secret boundary. A file there is
    ///   readable, by design and by documentation.
    /// - Operator **grants** are gated on inode identity: the path must match a
    ///   grant glob AND the opened inode must be in the launch snapshot. This
    ///   defeats aliasing a foreign file into a granted path:
    ///     * hardlink-into-grant: the secret's inode was never under the
    ///       grant at launch, so it is not in the snapshot → denied;
    ///     * rename-into-grant: same — the renamed inode is foreign.
    ///
    /// A file created in a grant *after* launch is a foreign inode too, so it is
    /// currently denied (fail closed). Re-permitting genuinely-created files
    /// (so an agent can read logs rotated into a granted directory) is the job
    /// of the move-vs-create witness layer tracked separately; until it lands,
    /// the safe-but-strict behaviour here never leaks.
    ///
    /// `opened_gen` is the generation of the file actually being opened (read from
    /// the event fd by the caller). A grant match requires `(inode, generation)`
    /// to equal a snapshot entry — so a granted file deleted mid-run whose inode
    /// number is reused by a foreign file is denied (the kernel bumped the
    /// generation). If the snapshot entry has a generation but the opened file's
    /// is unreadable, the match fails CLOSED.
    pub fn allows_open(&self, path: &str, key: &InodeKey, opened_gen: Option<u64>) -> bool {
        if self.include_base && RUNTIME_BASE_SET.iter().any(|g| glob::matches(g, path)) {
            return true;
        }
        if self.grants.iter().any(|g| glob::matches(g, path)) {
            return self.grant_inodes.contains(&(*key, opened_gen));
        }
        false
    }

    /// Test-only: inject a snapshotted grant inode (with optional generation)
    /// without touching the filesystem, for decision-logic unit tests.
    #[cfg(test)]
    pub fn insert_grant_inode_for_test(&mut self, key: InodeKey, gen_val: Option<u64>) {
        self.grant_inodes.insert((key, gen_val));
    }
}

/// The fixed directory/file prefix of a grant glob — everything up to the first
/// path segment containing a wildcard. A concrete (wildcard-free) grant is its
/// own prefix, so `--allow /etc/foo.conf` snapshots exactly that file rather
/// than all of `/etc`. `/var/log/app/**` and `/var/log/app/*.log` both yield
/// `/var/log/app`.
fn concrete_prefix(g: &str) -> &str {
    match g.find(['*', '?']) {
        None => g,
        Some(w) => {
            let head = &g[..w];
            match head.rfind('/') {
                Some(0) => "/",
                Some(i) => &g[..i],
                None => head,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_is_allowed() {
        let a = AllowList::new(vec!["/var/log/clickhouse/**".into()]);
        assert!(a.allows("/var/log/clickhouse/clickhouse-server.log"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_base_lets_a_program_execute() {
        let a = AllowList::new(vec!["/var/log/app/**".into()]);
        // the things strace showed a real `bash -c cat` needs:
        assert!(a.allows("/etc/ld.so.cache"));
        assert!(a.allows("/lib/aarch64-linux-gnu/libc.so.6"));
        assert!(a.allows("/usr/lib/locale/locale-archive"));
        assert!(a.allows("/usr/bin/cat"));
        assert!(a.allows("/dev/tty"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_runtime_base_is_darwin_specific() {
        let a = AllowList::new(vec!["/Users/operator/project/**".into()]);
        assert!(a.allows("/usr/lib/dyld"));
        assert!(a.allows("/System/Library/Frameworks/Foundation.framework/Foundation"));
        assert!(a.allows("/System/Volumes/Preboot/Cryptexes/OS/usr/lib/libobjc.A.dylib"));
        assert!(!a.allows("/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(!a.allows("/etc/shadow"));
    }

    #[test]
    fn sensitive_paths_outside_grant_are_denied() {
        let a = AllowList::new(vec!["/var/log/clickhouse/**".into()]);
        // the whole point: triage agent cannot reach these.
        assert!(!a.allows("/etc/shadow"));
        assert!(!a.allows("/root/.ssh/id_ed25519"));
        assert!(!a.allows("/var/lib/clickhouse/data/secret_table/data.bin"));
        assert!(!a.allows("/var/lib/postgresql/15/main/base/1/2619"));
        assert!(!a.allows("/home/deploy/.aws/credentials"));
    }

    #[test]
    fn etc_shadow_is_denied_even_though_etc_passwd_is_allowed() {
        // /etc/passwd is in the base set (name lookups); /etc/shadow is NOT.
        let a = AllowList::new(vec![]);
        assert!(a.allows("/etc/passwd"));
        assert!(!a.allows("/etc/shadow"));
    }

    #[test]
    fn without_base_denies_runtime_paths() {
        let a = AllowList::new(vec!["/data/**".into()]).without_base();
        assert!(a.allows("/data/x"));
        assert!(!a.allows("/lib/aarch64-linux-gnu/libc.so.6"));
    }

    #[test]
    fn allowed_globs_lists_base_then_grants() {
        let a = AllowList::new(vec!["/g1".into(), "/g2".into()]);
        let globs = a.allowed_globs();
        assert!(globs.contains(&RUNTIME_BASE_SET[0].to_string()));
        assert_eq!(globs[globs.len() - 2], "/g1");
        assert_eq!(globs[globs.len() - 1], "/g2");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn exposes_base_and_grants_separately() {
        let a = AllowList::new(vec!["/g1".into(), "/g2".into()]);
        assert_eq!(a.base_globs(), RUNTIME_BASE_SET);
        assert_eq!(a.grant_globs(), &["/g1".to_string(), "/g2".to_string()]);
    }
}

#[cfg(test)]
mod inode_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn scratch(tag: &str) -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("bulwark-allow-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn key_of(p: &Path) -> InodeKey {
        InodeKey::of(&fs::metadata(p).unwrap())
    }

    /// The generation the decision path would read for `p` (mirrors the snapshot).
    fn gen_of(p: &Path) -> Option<u64> {
        grant_generation(p)
    }

    #[test]
    fn concrete_prefix_cases() {
        assert_eq!(concrete_prefix("/var/log/app/**"), "/var/log/app");
        assert_eq!(concrete_prefix("/var/log/app/*.log"), "/var/log/app");
        assert_eq!(concrete_prefix("/etc/foo.conf"), "/etc/foo.conf");
        assert_eq!(concrete_prefix("/data/**/*.log"), "/data");
        assert_eq!(concrete_prefix("/*"), "/");
    }

    /// A grant file present at launch is allowed by inode.
    #[test]
    fn snapshotted_grant_file_is_allowed() {
        let dir = scratch("present");
        let f = dir.join("app.log");
        fs::write(&f, b"x").unwrap();
        let glob = format!("{}/**", dir.display());
        let mut a = AllowList::new(vec![glob]).without_base();
        a.snapshot_grants();
        assert!(a.allows_open(&f.to_string_lossy(), &key_of(&f), gen_of(&f)));
    }

    /// Negative control: a path that matches a grant glob but whose inode
    /// was NOT under the grant at launch (a hardlinked or renamed-in foreign
    /// file) is DENIED. The pre-fix path-only `allows` returned true here.
    #[test]
    fn foreign_inode_on_granted_path_is_denied() {
        let dir = scratch("foreign");
        let outside = scratch("foreign-src");
        let secret = outside.join("secret");
        fs::write(&secret, b"s").unwrap();

        let glob = format!("{}/**", dir.display());
        let mut a = AllowList::new(vec![glob]).without_base();
        a.snapshot_grants(); // grant dir is empty at launch

        // The attacker presents the secret's inode under a granted path.
        let aliased_path = format!("{}/leak", dir.display());
        assert!(
            !a.allows_open(&aliased_path, &key_of(&secret), gen_of(&secret)),
            "foreign inode under a granted path must be denied (hardlink/rename-in)"
        );
    }

    /// The snapshot records only inodes whose path matches the grant glob, NOT
    /// every file under the prefix directory — so a non-granted sibling cannot
    /// be reached by hardlinking it to a granted name.
    #[test]
    fn non_matching_sibling_is_not_snapshotted() {
        let dir = scratch("sibling");
        let log = dir.join("a.log");
        let env = dir.join("secret.env");
        fs::write(&log, b"l").unwrap();
        fs::write(&env, b"e").unwrap();

        let glob = format!("{}/*.log", dir.display());
        let mut a = AllowList::new(vec![glob]).without_base();
        a.snapshot_grants();

        // The .log file is granted by path and snapshotted by inode.
        assert!(a.allows_open(&log.to_string_lossy(), &key_of(&log), gen_of(&log)));
        // secret.env's inode was never snapshotted (it doesn't match *.log), so
        // hardlinking it to a *.log name still fails the inode gate.
        let aliased = format!("{}/x.log", dir.display());
        assert!(!a.allows_open(&aliased, &key_of(&env), gen_of(&env)));
    }

    /// Base-set paths are allowed by path regardless of inode (documented read
    /// floor, not inode-snapshotted).
    #[test]
    fn base_set_path_allowed_regardless_of_inode() {
        let a = AllowList::new(vec![]);
        let any = InodeKey { dev: 1, ino: 2 };
        #[cfg(target_os = "linux")]
        assert!(a.allows_open("/etc/passwd", &any, None));
        #[cfg(target_os = "macos")]
        assert!(a.allows_open("/usr/lib/dyld", &any, None));
    }

    /// A path matching no rule is denied whatever its inode.
    #[test]
    fn ungranted_path_denied() {
        let mut a = AllowList::new(vec!["/data/**".into()]).without_base();
        let k = InodeKey { dev: 9, ino: 9 };
        a.insert_grant_inode_for_test(k, None);
        assert!(!a.allows_open("/etc/shadow", &k, None));
    }
}
