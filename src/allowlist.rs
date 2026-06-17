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

use crate::glob;

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
}

impl AllowList {
    /// Build from operator grants, including the runtime base set.
    pub fn new(grants: Vec<String>) -> Self {
        AllowList {
            grants,
            include_base: true,
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
    pub fn grant_globs(&self) -> &[String] {
        &self.grants
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

    /// True if `path` is allowed (matches the base set or a grant). Everything
    /// else is denied — this is the whole policy.
    pub fn allows(&self, path: &str) -> bool {
        if self.include_base && RUNTIME_BASE_SET.iter().any(|g| glob::matches(g, path)) {
            return true;
        }
        self.grants.iter().any(|g| glob::matches(g, path))
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
