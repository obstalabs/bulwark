//! Compile expanded protect entries into a macOS Seatbelt profile.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// WO-291@v3: let the compiler resolve protect entries against real or fixture paths.
pub(crate) trait FsView {
    // WO-291@v3: resolve aliases to the spelling used for access checks.
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
    // WO-291@v3: distinguish missing paths from lookup failures while walking ancestors.
    fn exists(&self, path: &Path) -> io::Result<bool>;
    // WO-291@v3: select recursive coverage for an existing directory.
    fn is_dir(&self, path: &Path) -> io::Result<bool>;
    // WO-291@v3: look up case behavior at an existing canonical ancestor.
    fn volume_case_insensitive(&self, path: &Path) -> bool;
}

// WO-291@v3: supply the filesystem lookups used outside fixture tests.
pub(crate) struct RealFs;

// WO-291@v3: resolve aliases and path types through the standard filesystem API.
impl FsView for RealFs {
    // WO-291@v3: follow symlinks in the existing part of a protect entry.
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        fs::canonicalize(path)
    }

    // WO-291@v3: keep a failed stat from being mistaken for an uncreated file.
    fn exists(&self, path: &Path) -> io::Result<bool> {
        match fs::metadata(path) {
            Ok(_) => Ok(true),
            // WO-291@v3: a missing component or a parent that is a file proves absence.
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    // WO-291@v3: identify directories after canonicalization has resolved aliases.
    fn is_dir(&self, path: &Path) -> io::Result<bool> {
        fs::metadata(path).map(|meta| meta.is_dir())
    }

    // WO-291@v3: use case folding by default for profiles generated on macOS.
    fn volume_case_insensitive(&self, _path: &Path) -> bool {
        // The standard filesystem API exposes no case-sensitivity flag. Treat
        // macOS volumes as case-insensitive in the absence of contrary evidence.
        cfg!(target_os = "macos")
    }
}

// WO-291@v3: retain the failing input and its cause for launch diagnostics.
#[derive(Debug)]
pub(crate) struct FloorError {
    // WO-291@v3: preserve the spelling supplied by the caller.
    entry: PathBuf,
    // WO-291@v3: carry lookup failures and profile encoding errors.
    source: io::Error,
}

// WO-291@v3: show the rejected protect entry in error messages.
impl fmt::Display for FloorError {
    // WO-291@v3: escape control characters when printing the entry.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protect entry {:?}: {}", self.entry, self.source)
    }
}

// WO-291@v3: make the underlying error available to callers.
impl std::error::Error for FloorError {
    // WO-291@v3: keep the filesystem error in the error chain.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Compile the expanded concrete paths and globs from the protect list.
/// A `file-read-data` denial leaves stat metadata such as size and times visible.
// WO-291@v3: give each distinct filter one read-data denial in a stable order.
pub(crate) fn compile_floor_profile(
    protect: &[PathBuf],
    fs: &dyn FsView,
) -> Result<String, FloorError> {
    // WO-291@v3: sort and deduplicate after canonicalization and escaping.
    let mut filters = BTreeSet::new();
    for entry in protect {
        filters.insert(compile_filter(entry, fs).map_err(|source| FloorError {
            entry: entry.clone(),
            source,
        })?);
    }

    // WO-291@v3: leave every operation outside the listed read denials allowed.
    let mut profile = String::from("(version 1)\n(allow default)\n");
    for filter in filters {
        profile.push_str("(deny file-read-data ");
        profile.push_str(&filter);
        profile.push_str(")\n");
    }
    Ok(profile)
}

// WO-291@v3: select the filter for each expanded protect entry.
fn compile_filter(entry: &Path, fs: &dyn FsView) -> io::Result<String> {
    // WO-291@v3: catch unrepresentable input before resolution can change its spelling.
    let text = profile_text(entry)?;
    // WO-291@v3: an empty protect entry must never resolve to the working directory.
    if text.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty path"));
    }
    // WO-291@v3: the policy's wildcard entries need a path regex.
    if let Some(wildcard) = text.find(['*', '?']) {
        return glob_filter(text, wildcard, fs);
    }

    // WO-291@v3: keep absent leaves attached to the nearest resolved location.
    let (mut canonical, suffix) = canonical_ancestor(entry, fs)?;
    // WO-291@v3: only a directory present at compile time has a directory type.
    let filter = if suffix.as_os_str().is_empty() && fs.is_dir(&canonical)? {
        "subpath"
    } else {
        "literal"
    };
    canonical.extend(suffix);
    Ok(format!(
        "({filter} {})",
        quoted_string(profile_text(&canonical)?)
    ))
}

// WO-291@v3: split a path into a canonical existing prefix and the unresolved suffix.
fn canonical_ancestor<'a>(path: &'a Path, fs: &dyn FsView) -> io::Result<(PathBuf, &'a Path)> {
    for ancestor in path.ancestors() {
        // WO-291@v3: an empty relative prefix names the current working directory.
        let lookup = if ancestor.as_os_str().is_empty() {
            Path::new(".")
        } else {
            ancestor
        };
        // WO-291@v3: only a confirmed absence permits trying a shallower ancestor.
        if fs.exists(lookup)? {
            // WO-291@v3: retain the exact names below the canonical ancestor.
            let suffix = path
                .strip_prefix(ancestor)
                .expect("a path starts with its ancestor");
            return Ok((fs.canonicalize(lookup)?, suffix));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no existing ancestor",
    ))
}

// WO-291@v3: reject paths that cannot be written faithfully in a profile.
fn profile_text(path: &Path) -> io::Result<&str> {
    // WO-291@v3: lossy conversion could move the denial to a different path.
    let text = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not UTF-8"))?;
    // WO-291@v3: keep control characters out of both quoted filter forms.
    if text.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a control character",
        ));
    }
    Ok(text)
}

// WO-291@v3: quote a path or expression for the Seatbelt string reader.
fn quoted_string(text: &str) -> String {
    // WO-291@v3: put escaping and delimiters in the same string.
    let mut quoted = String::from("\"");
    for c in text.chars() {
        // WO-291@v3: stop a filename byte from closing the token or escaping its neighbor.
        if matches!(c, '\\' | '"') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

// WO-291@v3: translate the protect grammar into one anchored Seatbelt path regex.
fn glob_filter(text: &str, wildcard: usize, fs: &dyn FsView) -> io::Result<String> {
    // WO-291@v3: filesystem lookups stop before the first component with a wildcard.
    let pattern_start = text[..wildcard].rfind('/').map_or(0, |slash| slash + 1);
    // WO-291@v3: keep wildcard syntax separate from the prefix, which can resolve to any name.
    let (prefix, pattern) = text.split_at(pattern_start);
    // WO-291@v3: a leading double star can match at any depth from the root.
    let prefix = if prefix.is_empty() && pattern.starts_with("**") {
        "/"
    } else {
        prefix
    };
    // WO-291@v3: resolve the glob's concrete prefix the same way as a concrete entry.
    let (mut canonical, suffix) = canonical_ancestor(Path::new(prefix), fs)?;
    // WO-291@v3: ask about the volume while the prefix still names an existing path.
    let fold_case = fs.volume_case_insensitive(&canonical);
    canonical.extend(suffix);

    // WO-291@v3: anchor the expression and escape every character of the literal prefix.
    let mut regex = String::from("^");
    for c in profile_text(&canonical)?.trim_end_matches('/').chars() {
        push_regex_literal(&mut regex, c, fold_case);
    }
    regex.push('/');

    // WO-291@v3: look ahead to distinguish stars that can span a path separator.
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // WO-291@v3: only a paired star can span directory boundaries.
            '*' if chars.next_if_eq(&'*').is_some() => {
                // WO-291@v3: double-star slash also matches zero directory levels.
                if chars.next_if_eq(&'/').is_some() {
                    regex.push_str("(.*/)?");
                } else {
                    regex.push_str(".*");
                }
            }
            // WO-291@v3: a single star stays within its path component.
            '*' => regex.push_str("[^/]*"),
            // WO-291@v3: a question mark consumes one character inside its component.
            '?' => regex.push_str("[^/]"),
            c => push_regex_literal(&mut regex, c, fold_case),
        }
    }
    regex.push('$');

    // WO-291@v3: the raw regex reader ends at a quote even after a backslash.
    let expression = if regex.contains('"') {
        quoted_string(&regex)
    } else {
        format!("#\"{regex}\"")
    };
    Ok(format!("(regex {expression})"))
}

// WO-291@v3: keep path characters literal and express ASCII case pairs portably.
fn push_regex_literal(regex: &mut String, c: char, fold_case: bool) {
    // WO-291@v3: Seatbelt folds Unicode path names and supports ordinary ASCII character classes.
    if fold_case && c.is_ascii_alphabetic() {
        regex.push('[');
        regex.push(c.to_ascii_lowercase());
        regex.push(c.to_ascii_uppercase());
        regex.push(']');
    } else {
        // WO-291@v3: reserve operators for the compiler even if a canonical name contains them.
        if r".^$+()[]{}|*?\".contains(c) {
            regex.push('\\');
        }
        regex.push(c);
    }
}

// WO-291@v3: exercise profile generation without depending on the host filesystem.
#[cfg(test)]
mod tests {
    use super::*;

    // WO-291@v3: model symlink targets, existing directory types and volume case behavior.
    struct FakeFs {
        // WO-291@v3: map lookup names to canonical names and directory flags.
        entries: &'static [(&'static str, &'static str, bool)],
        // WO-291@v3: let tests select case folding independently of the host.
        case_insensitive: bool,
    }

    // WO-291@v3: share canonical alias fixtures across file, directory and glob tests.
    const FS: FakeFs = FakeFs {
        entries: &[
            ("/", "/", true),
            ("/tmp", "/private/tmp", true),
            ("/tmp/dir", "/private/tmp/dir", true),
            ("/tmp/x", "/private/tmp/x", false),
            ("/var", "/private/var", true),
        ],
        case_insensitive: false,
    };

    // WO-291@v3: use a single fixture lookup for all three filesystem queries.
    impl FakeFs {
        // WO-291@v3: recognize both aliases and their resolved path names.
        fn lookup(&self, path: &Path) -> Option<(&str, bool)> {
            self.entries
                .iter()
                .find(|(alias, canonical, _)| {
                    path == Path::new(alias) || path == Path::new(canonical)
                })
                .map(|&(_, canonical, dir)| (canonical, dir))
        }
    }

    // WO-291@v3: expose fixture entries through the production compiler's interface.
    impl FsView for FakeFs {
        // WO-291@v3: return the simulated target of each existing path.
        fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
            self.lookup(path)
                .map(|(canonical, _)| canonical.into())
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }

        // WO-291@v3: let unlisted paths exercise the missing-ancestor walk.
        fn exists(&self, path: &Path) -> io::Result<bool> {
            Ok(self.lookup(path).is_some())
        }

        // WO-291@v3: emulate directory detection for existing canonical paths.
        fn is_dir(&self, path: &Path) -> io::Result<bool> {
            self.lookup(path)
                .map(|(_, dir)| dir)
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }

        // WO-291@v3: inject the reported case behavior for glob tests.
        fn volume_case_insensitive(&self, _path: &Path) -> bool {
            self.case_insensitive
        }
    }

    // WO-291@v3: check that generated profiles contain no signal rule.
    fn profile(entries: &[&str], fs: &dyn FsView) -> String {
        // WO-291@v3: pass fixtures through the same path input as the caller.
        let paths: Vec<PathBuf> = entries.iter().map(PathBuf::from).collect();
        // WO-291@v3: check the operation restriction across all successful fixtures.
        let compiled = compile_floor_profile(&paths, fs).unwrap();
        assert!(!compiled.contains("signal"));
        compiled
    }

    // WO-291@v3: independently read a quoted token to catch escaping that changes the path.
    fn quoted_token(line: &str) -> String {
        // WO-291@v3: start reading immediately after the opening delimiter.
        let mut chars = line.split_once('"').unwrap().1.chars();
        // WO-291@v3: reconstruct the string that the profile reader should see.
        let mut token = String::new();
        while let Some(c) = chars.next() {
            match c {
                '"' => return token,
                '\\' => {
                    // WO-291@v3: the compiler should only escape these two token characters.
                    let escaped = chars.next().expect("trailing escape");
                    assert!(matches!(escaped, '\\' | '"'));
                    token.push(escaped);
                }
                c => token.push(c),
            }
        }
        panic!("unterminated quoted token")
    }

    // WO-291@v3: prove quote and backslash escaping preserves the literal path.
    #[test]
    fn literal_escaping_round_trips() {
        // WO-291@v3: compile a missing file whose name contains both escape characters.
        let compiled = profile(&[r#"/tmp/a"b\c"#], &FS);
        // WO-291@v3: compare both the encoded line and the path decoded from it.
        let deny = compiled.lines().nth(2).unwrap();
        assert_eq!(
            deny,
            r#"(deny file-read-data (literal "/private/tmp/a\"b\\c"))"#
        );
        assert_eq!(quoted_token(deny), r#"/private/tmp/a"b\c"#);
    }

    // WO-291@v3: prove control characters fail closed and identify the refused entry.
    #[test]
    fn refuses_control_characters() {
        for control in ['\n', '\r', '\0', '\t', '\u{7f}', '\u{85}'] {
            // WO-291@v3: place the control character in the protected leaf.
            let entry = PathBuf::from(format!("/tmp/bad{control}entry"));
            // WO-291@v3: require a diagnostic even for a path that does not exist.
            let error = compile_floor_profile(std::slice::from_ref(&entry), &FS).unwrap_err();
            assert!(error.to_string().contains(&format!("{entry:?}")));
            assert!(error.to_string().contains("control character"));
        }
    }

    // WO-291@v3: prove a file alias and a directory use canonical filters of different scope.
    #[test]
    fn existing_directories_use_subpath_and_files_use_literal() {
        assert_eq!(
            profile(&["/tmp/dir", "/tmp/x"], &FS),
            "(version 1)\n(allow default)\n\
             (deny file-read-data (literal \"/private/tmp/x\"))\n\
             (deny file-read-data (subpath \"/private/tmp/dir\"))\n"
        );
    }

    // WO-291@v3: prove absent components below an alias survive canonicalization.
    #[test]
    fn missing_leaves_keep_the_suffix_below_the_deepest_ancestor() {
        // WO-291@v3: give the deepest existing prefix a distinct target from its parent.
        let fs = FakeFs {
            entries: &[
                ("/var", "/private/var", true),
                ("/var/cache", "/secrets", true),
            ],
            case_insensitive: false,
        };
        assert_eq!(
            profile(&["/var/cache/new/leaf"], &fs),
            "(version 1)\n(allow default)\n(deny file-read-data (literal \"/secrets/new/leaf\"))\n"
        );
    }

    // WO-291@v3: pin the regex anchors, wildcard scope and escaped punctuation.
    #[test]
    fn glob_uses_an_anchored_regex() {
        // WO-291@v3: include metacharacters that are ordinary characters in the protect grammar.
        let compiled = profile(&["/tmp/a.(b)[c]+{d}^$|?/item*.key"], &FS);
        assert_eq!(
            compiled.lines().nth(2).unwrap(),
            r##"(deny file-read-data (regex #"^/private/tmp/a\.\(b\)\[c\]\+\{d\}\^\$\|[^/]/item[^/]*\.key$"))"##
        );
        assert_eq!(compiled.lines().count(), 3);
        assert!(!compiled.contains("(literal"));
    }

    // WO-291@v3: preserve both recursive glob forms used by protect policies.
    #[test]
    fn recursive_globs_span_directories() {
        // WO-291@v3: cover omitted directory levels and arbitrary descendants.
        let compiled = profile(&["**/.env", "/tmp/dir/**"], &FS);
        assert!(compiled.contains(r##"(regex #"^/(.*/)?\.env$")"##));
        assert!(compiled.contains(r##"(regex #"^/private/tmp/dir/.*$")"##));
    }

    // WO-291@v3: pin case folding in the canonical prefix and the wildcard component.
    #[test]
    fn glob_folds_case_on_a_case_insensitive_volume() {
        // WO-291@v3: change only the case behavior of the fixture volume.
        let fs = FakeFs {
            case_insensitive: true,
            ..FS
        };
        // WO-291@v3: expect both ASCII cases in literal portions of the expression.
        let compiled = profile(&["/tmp/Config?.Env"], &fs);
        assert!(compiled.contains(concat!(
            "^/[pP][rR][iI][vV][aA][tT][eE]/[tT][mM][pP]/",
            r"[cC][oO][nN][fF][iI][gG][^/]\.[eE][nN][vV]$"
        )));
    }

    // WO-291@v3: prove a quote inside a glob survives the Seatbelt string layer.
    #[test]
    fn glob_with_quotes_uses_an_escaped_string() {
        // WO-291@v3: combine a quote with both a literal backslash and an escaped regex dot.
        let compiled = profile(&[r#"/tmp/a"b\c.*"#], &FS);
        // WO-291@v3: the ordinary string carries the regex unchanged after decoding.
        let deny = compiled.lines().nth(2).unwrap();
        assert_eq!(
            deny,
            r#"(deny file-read-data (regex "^/private/tmp/a\"b\\\\c\\.[^/]*$"))"#
        );
        assert_eq!(quoted_token(deny), r#"^/private/tmp/a"b\\c\.[^/]*$"#);
    }

    // WO-291@v3: prove repeated inputs and canonical aliases do not change the profile.
    #[test]
    fn output_is_sorted_and_deduplicated() {
        // WO-291@v3: compile duplicates and two spellings of the same existing file.
        let entries = ["/tmp/y", "/tmp/x", "/private/tmp/x", "/tmp/y"];
        // WO-291@v3: pin the order of the distinct filters.
        let compiled = profile(&entries, &FS);
        assert_eq!(compiled, profile(&entries, &FS));
        assert_eq!(compiled, profile(&["/tmp/x", "/tmp/y"], &FS));
        assert_eq!(
            compiled,
            "(version 1)\n(allow default)\n\
             (deny file-read-data (literal \"/private/tmp/x\"))\n\
             (deny file-read-data (literal \"/private/tmp/y\"))\n"
        );
    }

    // WO-291@v3: pin the entire profile when no paths are protected.
    #[test]
    fn empty_input_has_only_the_preamble() {
        assert_eq!(profile(&[], &FS), "(version 1)\n(allow default)\n");
    }

    // WO-291@v3: verify actual macOS enforcement with a blocked read and an allowed control.
    #[cfg(target_os = "macos")]
    #[test]
    fn sandbox_exec_denies_decoy_allows_hosts() {
        use std::process::Command;

        // WO-291@v3: isolate the profile and decoy from other test runs.
        let dir = crate::test_scratch_dir("sandbox-floor");
        // WO-291@v3: use an existing file so the test exercises canonical file resolution.
        let decoy = dir.join("decoy.txt");
        fs::write(&decoy, b"decoy\n").unwrap();
        // WO-291@v3: pass the exact compiler output to both child processes.
        let profile_path = dir.join("floor.sb");
        fs::write(
            &profile_path,
            compile_floor_profile(std::slice::from_ref(&decoy), &RealFs).unwrap(),
        )
        .unwrap();

        // WO-291@v3: run both reads with the same executable and profile.
        let cat = |path: &Path| {
            Command::new("/usr/bin/sandbox-exec")
                .arg("-f")
                .arg(&profile_path)
                .arg("/bin/cat")
                .arg(path)
                .env("LC_ALL", "C")
                .output()
                .unwrap()
        };
        // WO-291@v3: attempt to read the protected file.
        let denied = cat(&decoy);
        // WO-291@v3: verify the same profile preserves an unrelated read.
        let allowed = cat(Path::new("/etc/hosts"));
        fs::remove_dir_all(dir).unwrap();

        // WO-291@v3: require the denial to come from opening the decoy.
        let stderr = String::from_utf8_lossy(&denied.stderr);
        assert!(
            !denied.status.success()
                && stderr.contains("decoy.txt")
                && stderr.contains("Operation not permitted"),
            "{stderr}"
        );
        assert!(
            allowed.status.success(),
            "{}",
            String::from_utf8_lossy(&allowed.stderr)
        );
    }
}
