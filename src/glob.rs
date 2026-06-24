//! Minimal deterministic glob matcher for protected-path patterns.
//!
//! Supports exactly what the policy needs, no regex dependency:
//! - `?`   matches one non-`/` character
//! - `*`   matches zero or more non-`/` characters (within a path segment)
//! - `**`  matches zero or more characters including `/` (spans segments)
//! - leading `~/` is expanded to the caller-provided home directory
//!
//! Matching is deterministic and case-sensitive — determinism over heuristic,
//! as the policy demands. A pattern with no wildcards is an exact-path match.

/// Expand a leading `~/` (or bare `~`) in `pat` using `home`.
pub fn expand_home(pat: &str, home: &str) -> String {
    if pat == "~" {
        return home.to_string();
    }
    if let Some(rest) = pat.strip_prefix("~/") {
        let home = home.trim_end_matches('/');
        return format!("{home}/{rest}");
    }
    pat.to_string()
}

/// True if `path` matches glob `pattern`. Both should be absolute, normalized
/// strings (the caller expands `~/` first via [`expand_home`]).
pub fn matches(pattern: &str, path: &str) -> bool {
    glob_match(pattern.as_bytes(), path.as_bytes())
}

/// Recursive glob matcher over bytes. Semantics:
///
/// - `**/` matches zero or more complete path segments (including the trailing
///   `/`), so `a/**/b` matches both `a/b` and `a/x/y/b`.
/// - `**` not followed by `/` matches any run of characters including `/`.
/// - `*` matches any run of non-`/` characters (stays within one segment).
/// - `?` matches exactly one non-`/` character.
///
/// Patterns are tiny (policy globs), so the recursion depth is bounded.
fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    // `**/` — match zero or more leading path segments.
    if pat.starts_with(b"**/") {
        let rest = &pat[3..];
        // zero directories: rest must match here
        if glob_match(rest, text) {
            return true;
        }
        // one or more: rest may match immediately after any `/` in text
        for i in 0..text.len() {
            if text[i] == b'/' && glob_match(rest, &text[i + 1..]) {
                return true;
            }
        }
        return false;
    }

    // `**` at end (or not followed by `/`) — match any chars including `/`.
    if pat.starts_with(b"**") {
        let rest = &pat[2..];
        for i in 0..=text.len() {
            if glob_match(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }

    match pat.first() {
        None => text.is_empty(),
        Some(b'*') => {
            let rest = &pat[1..];
            // try consuming 0..n non-`/` chars
            for i in 0..=text.len() {
                if glob_match(rest, &text[i..]) {
                    return true;
                }
                if i < text.len() && text[i] == b'/' {
                    break; // single `*` cannot cross a path separator
                }
            }
            false
        }
        Some(b'?') => {
            if !text.is_empty() && text[0] != b'/' {
                glob_match(&pat[1..], &text[1..])
            } else {
                false
            }
        }
        Some(&c) => {
            if !text.is_empty() && text[0] == c {
                glob_match(&pat[1..], &text[1..])
            } else {
                false
            }
        }
    }
}

/// The concrete directory prefix a glob reduces to for a path-based subtree
/// grant (Landlock `path_beneath`): segments are taken until the first one
/// containing a wildcard. `/var/log/app/**` -> `/var/log/app`; `/proc/*/stat`
/// -> `/proc`; `**/*.log` -> `/`. A wildcard-free glob is returned unchanged.
pub fn landlock_prefix(glob: &str) -> String {
    let mut prefix = String::new();
    for seg in glob.split('/') {
        if seg.contains('*') || seg.contains('?') {
            break;
        }
        if !seg.is_empty() {
            prefix.push('/');
            prefix.push_str(seg);
        }
    }
    if prefix.is_empty() {
        "/".to_string()
    } else {
        prefix
    }
}

/// True if `glob` maps to its [`landlock_prefix`] WITHOUT silently widening —
/// it is either wildcard-free (the prefix is the path itself) or a trailing
/// `/**` subtree (a `path_beneath` grant is exactly what `/**` means). Any other
/// wildcard — mid-path (`/a/*/b`), single-segment (`/a/*.log`), or a pattern
/// after `**` (`**/*.log`) — makes the path-based grant BROADER than the
/// pattern. Used to refuse `--hardened` operator grants that would silently
/// widen to a whole subtree the operator did not ask for.
pub fn is_landlock_faithful(glob: &str) -> bool {
    if !glob.contains('*') && !glob.contains('?') {
        return true;
    }
    if let Some(prefix) = glob.strip_suffix("/**") {
        return !prefix.is_empty() && !prefix.contains('*') && !prefix.contains('?');
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landlock_prefix_strips_wildcards() {
        assert_eq!(landlock_prefix("/lib/**"), "/lib");
        assert_eq!(landlock_prefix("/var/log/app/**"), "/var/log/app");
        assert_eq!(landlock_prefix("/etc/ld.so.cache"), "/etc/ld.so.cache");
        assert_eq!(landlock_prefix("/proc/*/stat"), "/proc");
        assert_eq!(landlock_prefix("**/*secret*"), "/");
    }

    #[test]
    fn faithful_grants_are_concrete_or_trailing_doublestar() {
        // Faithful: the Landlock prefix equals the pattern's intent.
        assert!(is_landlock_faithful("/var/log/app"));
        assert!(is_landlock_faithful("/var/log/app/file.log"));
        assert!(is_landlock_faithful("/var/log/app/**"));
        // Widening: prefix is broader than the pattern -> not faithful.
        assert!(!is_landlock_faithful("/var/log/app/*.log"));
        assert!(!is_landlock_faithful("/var/log/app/**/*.log"));
        assert!(!is_landlock_faithful("/var/log/*/current"));
        assert!(!is_landlock_faithful("**/*.log"));
        assert!(!is_landlock_faithful("/**")); // prefix empty -> whole fs
    }

    #[test]
    fn exact_match() {
        assert!(matches("/home/u/.ssh", "/home/u/.ssh"));
        assert!(!matches("/home/u/.ssh", "/home/u/.aws"));
    }

    #[test]
    fn single_star_within_segment() {
        assert!(matches("/x/*.env", "/x/prod.env"));
        assert!(matches("/x/*.env", "/x/.env"));
        // single star must not cross a slash
        assert!(!matches("/x/*.env", "/x/sub/prod.env"));
    }

    #[test]
    fn question_mark() {
        assert!(matches("/x/a?c", "/x/abc"));
        assert!(!matches("/x/a?c", "/x/a/c"));
        assert!(!matches("/x/a?c", "/x/ac"));
    }

    #[test]
    fn double_star_spans_segments() {
        assert!(matches("**/.env", "/a/b/c/.env"));
        assert!(matches("**/.env", "/.env"));
        assert!(matches("/root/**/secret", "/root/a/b/secret"));
        assert!(matches("/root/**/secret", "/root/secret"));
    }

    #[test]
    fn double_star_substring_patterns() {
        assert!(matches("**/*secret*", "/home/u/app/db_secret_key"));
        assert!(matches("**/*secret*", "/secret"));
        assert!(matches("**/*token*", "/var/run/api_token.txt"));
        assert!(!matches("**/*secret*", "/home/u/notes.txt"));
    }

    #[test]
    fn home_expansion() {
        assert_eq!(expand_home("~/.ssh", "/home/u"), "/home/u/.ssh");
        assert_eq!(expand_home("~", "/home/u"), "/home/u");
        assert_eq!(expand_home("/abs/path", "/home/u"), "/abs/path");
        // trailing slash on home is normalized
        assert_eq!(expand_home("~/.aws", "/home/u/"), "/home/u/.aws");
    }

    #[test]
    fn star_does_not_match_across_slash_but_double_does() {
        assert!(!matches("/a/*", "/a/b/c"));
        assert!(matches("/a/**", "/a/b/c"));
    }
}
