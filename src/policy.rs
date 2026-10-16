//! Bulwark.toml policy schema and the default protected-path profile.
//!
//! One canonical policy format both platforms consume. The policy is an
//! allowlist boundary (workspace) plus a protected set, with deterministic
//! defaults: anything outside the workspace prompts, and a prompt that is not
//! answered denies. v1 is path-based only — no secret classification.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::glob;

/// What to do for an open that is neither explicitly allowed nor protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutsideWorkspace {
    /// Ask the operator (interactive). In the Linux MVP, with no prompt wired,
    /// this is treated as `Deny` (fail-safe) at decision time.
    Prompt,
    /// Allow silently.
    Allow,
    /// Deny.
    Deny,
}

/// What to do when an interactive prompt is not answered in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnTimeout {
    Deny,
    Allow,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Workspace {
    /// Globs the supervised tree may read freely.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Protected {
    /// Globs that are protected: an open is gated (prompt, or deny in the MVP).
    #[serde(default)]
    pub prompt: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Defaults {
    #[serde(default = "default_outside_workspace")]
    pub outside_workspace: OutsideWorkspace,
    #[serde(default = "default_on_timeout")]
    pub on_timeout: OnTimeout,
}

fn default_outside_workspace() -> OutsideWorkspace {
    OutsideWorkspace::Prompt
}
fn default_on_timeout() -> OnTimeout {
    OnTimeout::Deny
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            outside_workspace: default_outside_workspace(),
            on_timeout: default_on_timeout(),
        }
    }
}

/// Static decision policy for a configured agent launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentDecision {
    Ask,
    Deny,
    Allow,
}

fn default_agent_decision() -> AgentDecision {
    AgentDecision::Ask
}

fn default_agent_audit() -> bool {
    true
}

/// WO-27: named front-door configuration for `bulwark launch <agent>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentProfile {
    /// WO-27: command and arguments to execute for this agent.
    #[serde(default)]
    pub command: Vec<String>,
    /// WO-27: protected path globs used by the existing deny-list gate.
    #[serde(default)]
    pub protect: Vec<String>,
    /// WO-27: allow-list grants for default-deny launches.
    #[serde(default)]
    pub allow: Vec<String>,
    /// WO-27: default decision for protected opens in deny-list mode.
    #[serde(default = "default_agent_decision")]
    pub decision: AgentDecision,
    /// WO-27: whether launch should write the default audit receipts file.
    #[serde(default = "default_agent_audit")]
    pub audit: bool,
}

impl AgentProfile {
    /// Starter profile used by `bulwark init` and `bulwark launch --init`.
    pub fn starter(command: Vec<String>) -> Self {
        AgentProfile {
            command,
            protect: vec![
                "~/.ssh".into(),
                "~/.aws".into(),
                "~/.config/gcloud".into(),
                "**/.env".into(),
                "~/dev/**/secrets/**".into(),
            ],
            allow: vec![
                "~/dev/**/README*".into(),
                "package.json".into(),
                "go.mod".into(),
                "Cargo.toml".into(),
            ],
            decision: AgentDecision::Ask,
            audit: true,
        }
    }
}

/// The full Bulwark.toml document.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    #[serde(default)]
    pub workspace: Workspace,
    #[serde(default)]
    pub protected: Protected,
    #[serde(default)]
    pub default: Defaults,
    /// WO-27: default configured launch profile; `run` ignores this field.
    #[serde(default)]
    pub default_agent: Option<String>,
    /// WO-27: additive launch profiles keyed by agent name; `run` ignores them.
    #[serde(default)]
    pub agents: BTreeMap<String, AgentProfile>,
}

/// A gate decision a policy yields for a given path, before kernel/inode work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// In the workspace allowlist — allow.
    AllowWorkspace,
    /// Matched a protected glob — gate it (prompt; deny in the MVP).
    Protected,
    /// Outside the workspace and not protected — governed by
    /// `default.outside_workspace`.
    Outside(OutsideWorkspace),
}

// WO-145@v2: keep host-home protection expansion inside the shared policy path.
impl Policy {
    /// The shipped default profile. Protects the usual credential stores and
    /// secret-bearing filenames; the workspace allowlist is intentionally empty
    /// so the operator opts their project in explicitly.
    pub fn default_profile() -> Self {
        let mut agents = BTreeMap::new();
        agents.insert("agent".into(), AgentProfile::starter(vec!["agent".into()]));
        agents.insert(
            "claude".into(),
            AgentProfile::starter(vec!["claude".into()]),
        );
        Policy {
            workspace: Workspace { allow: vec![] },
            protected: Protected {
                prompt: vec![
                    "~/.ssh".into(),
                    "~/.aws".into(),
                    "~/.gnupg".into(),
                    "~/.kube".into(),
                    "~/.config/gcloud".into(),
                    "~/Documents".into(),
                    "~/Desktop".into(),
                    "~/Downloads".into(),
                    "~/.*".into(), // dotfiles in home
                    "**/.env".into(),
                    "**/*secret*".into(),
                    "**/*credential*".into(),
                    "**/*token*".into(),
                ],
            },
            default: Defaults::default(),
            default_agent: Some("agent".into()),
            agents,
        }
    }

    /// The built-in `dev` profile: same protections, but allows a typical
    /// project working directory so day-to-day reads are not gated.
    pub fn dev_profile() -> Self {
        let mut p = Self::default_profile();
        p.workspace.allow = vec!["~/dev/**".into(), "/tmp/**".into()];
        p
    }

    /// Select a named built-in profile.
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "default" => Some(Self::default_profile()),
            "dev" => Some(Self::dev_profile()),
            _ => None,
        }
    }

    /// Load a policy from a Bulwark.toml file.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("cannot read policy {}", path.display()))?;
        let policy: Policy =
            toml::from_str(&raw).with_context(|| format!("invalid policy {}", path.display()))?;
        Ok(policy)
    }

    /// Serialize to TOML.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serialize policy")
    }

    /// Save to a Bulwark.toml file.
    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, self.to_toml()?)
            .with_context(|| format!("cannot write policy {}", path.display()))
    }

    /// Add a protected glob (idempotent). Returns true if newly added.
    pub fn add_protected(&mut self, pattern: &str) -> bool {
        if self.protected.prompt.iter().any(|p| p == pattern) {
            false
        } else {
            self.protected.prompt.push(pattern.to_string());
            true
        }
    }

    /// Add a workspace allow glob (idempotent). Returns true if newly added.
    pub fn add_allow(&mut self, pattern: &str) -> bool {
        if self.workspace.allow.iter().any(|p| p == pattern) {
            false
        } else {
            self.workspace.allow.push(pattern.to_string());
            true
        }
    }

    /// Add a starter launch profile. Returns true if newly added.
    pub fn add_agent(&mut self, name: &str) -> bool {
        if self.agents.contains_key(name) {
            return false;
        }
        self.agents.insert(
            name.to_string(),
            AgentProfile::starter(vec![name.to_string()]),
        );
        if self.default_agent.is_none() {
            self.default_agent = Some(name.to_string());
        }
        true
    }

    /// Decide what the policy says about `path`. WO-145@v3 (G2): a `~/` entry is
    /// matched under every home in `homes` (the same rule `run` applies), so
    /// `check` and the live gate agree. Protected takes precedence over
    /// workspace-allow: a protected file inside an allowed workspace is still
    /// protected.
    // WO-145@v2: evaluate protected entries against the same host-home set as run.
    pub fn decide(&self, path: &str, homes: &[String]) -> PolicyDecision {
        // WO-145@v4 (C): protected entries expand through run's own
        // expand_protect_entry — same home set, same cap, same relative-refusal —
        // so `check` and `run` cannot diverge.
        let protected_hit = |pat: &String| match expand_protect_entry(pat, homes) {
            Ok(expanded) => expanded.iter().any(|p| decide_path_matches(path, p)),
            Err(_) => false,
        };
        if self.protected.prompt.iter().any(protected_hit) {
            return PolicyDecision::Protected;
        }
        // WO-145@v4 (D): a `~/` allow entry is NOT fanned out across homes (that
        // would widen a grant); it grants nothing and is reported by the caller.
        let allow_hit = |pat: &String| {
            if pat == "~" || pat.starts_with("~/") {
                false
            } else {
                glob::matches(pat, path)
            }
        };
        if self.workspace.allow.iter().any(allow_hit) {
            return PolicyDecision::AllowWorkspace;
        }
        PolicyDecision::Outside(self.default.outside_workspace)
    }

    /// Resolve every concrete (wildcard-free) protected pattern to absolute
    /// paths for inode resolution at launch. Patterns containing wildcards are
    /// returned separately by [`Self::protected_globs`] for decision-time
    /// matching (a gate follow-up).
    ///
    /// WO-145@v2: `homes` is the host's home set, not one user's home. An
    /// absolute entry is protected exactly as written; a `~/<rest>` entry
    /// means `<rest>` under every home in `homes`; any other relative entry
    /// is refused. See [`expand_protect_entry`].
    pub fn concrete_protected_paths(&self, homes: &[String]) -> Result<Vec<String>> {
        Ok(self
            .expand_protected(homes)?
            .into_iter()
            .filter(|p| !p.contains('*') && !p.contains('?'))
            .collect())
    }

    /// The protected patterns that contain wildcards (decision-time matching),
    /// expanded over `homes` the same way as the concrete ones (WO-145@v2).
    // WO-145@v2: expand wildcard protection across every enumerated host home.
    pub fn protected_globs(&self, homes: &[String]) -> Result<Vec<String>> {
        Ok(self
            .expand_protected(homes)?
            .into_iter()
            .filter(|p| p.contains('*') || p.contains('?'))
            .collect())
    }

    /// WO-145@v2: every protected entry expanded over the host home set, in
    /// entry order, each `~/` entry fanning out in home order. The one
    /// implementation behind both accessors above.
    fn expand_protected(&self, homes: &[String]) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in &self.protected.prompt {
            out.extend(expand_protect_entry(entry, homes)?);
        }
        Ok(out)
    }
}

/// WO-145@v3 (G2): true if `path` matches an already-expanded (or as-written)
/// pattern, either by glob or as a concrete directory ancestor of `path`.
// WO-145@v2: apply one matching rule to expanded protection paths.
fn decide_path_matches(path: &str, pattern: &str) -> bool {
    if glob::matches(pattern, path) {
        return true;
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        let dir = pattern.trim_end_matches('/');
        return path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'));
    }
    false
}

/// WO-145@v2: the most homes a host may present before the `~/` expansion
/// refuses rather than fan out further. Named so the refusal can cite it; far
/// above any real host, and a guard against a `/home` full of junk directories.
pub const MAX_PROTECT_HOMES: usize = 4096;

/// WO-145@v2: expand one protected entry over the host home set.
///
/// Until 0.9.2 `~` was expanded from `$HOME`, which under plain `sudo` on Linux
/// is root's home: the default profile protected `/root/.ssh` while the agent
/// ran as the invoking user and read that user's real `~/.ssh`. The operator
/// ruled that no single home is ever guessed. An absolute entry is exact; a
/// `~/<rest>` entry (or a bare `~`) means `<rest>` under EVERY home on the
/// host, which can only be broader than meant, never the wrong home; anything
/// else is an ambiguous relative path and is refused. A wildcard entry that
/// does not start with `~` (`**/.env`) is kept as written for decision-time
/// matching; one that does (`~/dev/**/secrets/**`) fans out per home too.
pub fn expand_protect_entry(entry: &str, homes: &[String]) -> Result<Vec<String>> {
    if homes.len() > MAX_PROTECT_HOMES {
        anyhow::bail!(
            "protect entry {entry:?}: this host presents {} home directories, more than \
             MAX_PROTECT_HOMES ({MAX_PROTECT_HOMES}); refusing to expand `~/` entries; \
             nothing was run",
            homes.len()
        );
    }
    if entry == "~" || entry.starts_with("~/") {
        return Ok(homes.iter().map(|h| glob::expand_home(entry, h)).collect());
    }
    if entry.starts_with('/') {
        return Ok(vec![entry.to_string()]);
    }
    if entry.contains('*') || entry.contains('?') {
        // A wildcard pattern such as `**/.env` matches by path at decision
        // time; it is not resolved against any directory, so it is kept.
        return Ok(vec![entry.to_string()]);
    }
    anyhow::bail!(
        "protect entry {entry:?} is relative: a protect entry must be an absolute path \
         (protected exactly as written) or start with `~/` (that path under every home \
         directory on this host); nothing was run"
    )
}

/// WO-145@v2: the host's home directories, with no NSS lookup beyond
/// `/etc/passwd`: the root home, every directory directly under the users
/// root (`/home`, or `/Users` without `Shared`), and the home of every passwd
/// entry with uid 0 or uid >= 1000 that exists. Each is canonicalized (a
/// symlinked `/home` still resolves), deduplicated and sorted.
pub fn host_homes() -> Vec<String> {
    #[cfg(target_os = "macos")]
    let (root_home, users_root, excluded): (&str, &str, &[&str]) =
        ("/var/root", "/Users", &["Shared"]);
    #[cfg(not(target_os = "macos"))]
    let (root_home, users_root, excluded): (&str, &str, &[&str]) = ("/root", "/home", &[]);
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    homes_from(
        Path::new(root_home),
        Path::new(users_root),
        excluded,
        &passwd,
    )
}

/// WO-145@v2: the home set from explicit roots and passwd text, so the shape
/// is unit-testable against a fixture tree. Only existing directories count.
pub fn homes_from(
    root_home: &Path,
    users_root: &Path,
    excluded: &[&str],
    passwd: &str,
) -> Vec<String> {
    let mut candidates: Vec<std::path::PathBuf> = vec![root_home.to_path_buf()];
    if let Ok(entries) = fs::read_dir(users_root) {
        for e in entries.flatten() {
            let name = e.file_name();
            if excluded.iter().any(|x| name == *x) {
                continue;
            }
            candidates.push(e.path());
        }
    }
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 6 {
            continue;
        }
        let Ok(uid) = f[2].parse::<u32>() else {
            continue;
        };
        if (uid == 0 || uid >= 1000) && f[5].starts_with('/') {
            candidates.push(std::path::PathBuf::from(f[5]));
        }
    }
    let mut homes: Vec<String> = candidates
        .into_iter()
        .filter_map(|c| fs::canonicalize(&c).ok())
        .filter(|c| c.is_dir())
        .map(|c| c.to_string_lossy().into_owned())
        .collect();
    homes.sort();
    homes.dedup();
    homes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_prompt_and_deny() {
        let d = Defaults::default();
        assert_eq!(d.outside_workspace, OutsideWorkspace::Prompt);
        assert_eq!(d.on_timeout, OnTimeout::Deny);
    }

    #[test]
    fn default_profile_protects_credentials() {
        let p = Policy::default_profile();
        assert!(p.protected.prompt.iter().any(|s| s == "~/.ssh"));
        assert!(p.protected.prompt.iter().any(|s| s == "**/*secret*"));
        // workspace allow is empty by default — opt-in boundary
        assert!(p.workspace.allow.is_empty());
    }

    #[test]
    fn default_profile_seeds_launch_agents() {
        let p = Policy::default_profile();
        assert_eq!(p.default_agent.as_deref(), Some("agent"));
        let claude = p.agents.get("claude").expect("claude starter agent");
        assert_eq!(claude.command, vec!["claude".to_string()]);
        assert!(claude.protect.iter().any(|s| s == "~/.ssh"));
        assert!(claude.allow.iter().any(|s| s == "Cargo.toml"));
        assert_eq!(claude.decision, AgentDecision::Ask);
        assert!(claude.audit);
    }

    #[test]
    fn toml_round_trip() {
        let p = Policy::dev_profile();
        let s = p.to_toml().unwrap();
        let back: Policy = toml::from_str(&s).unwrap();
        assert_eq!(back.protected.prompt, p.protected.prompt);
        assert_eq!(back.workspace.allow, p.workspace.allow);
        assert_eq!(back.default.outside_workspace, OutsideWorkspace::Prompt);
        assert_eq!(back.default.on_timeout, OnTimeout::Deny);
        assert_eq!(back.default_agent, p.default_agent);
        assert_eq!(back.agents.get("claude"), p.agents.get("claude"));
    }

    #[test]
    fn add_agent_is_idempotent() {
        let mut p = Policy::default_profile();
        assert!(p.add_agent("codex"));
        assert!(!p.add_agent("codex"));
        assert_eq!(
            p.agents.get("codex").map(|a| a.command.clone()),
            Some(vec!["codex".to_string()])
        );
    }

    // WO-145@v2: keep protected paths dominant over workspace grants.
    #[test]
    fn decide_protected_beats_workspace() {
        let mut p = Policy::default_profile();
        p.add_allow("~/dev/**");
        // a .env file inside the allowed workspace is still protected
        let d = p.decide("/home/u/dev/proj/.env", &["/home/u".to_string()]);
        assert_eq!(d, PolicyDecision::Protected);
    }

    // WO-145@v2: prevent home-relative allow entries from widening grants.
    #[test]
    fn decide_tilde_allow_grants_nothing() {
        // WO-145@v4 (D): a `~/` allow entry is not fanned out across homes (that
        // would widen a grant); it grants nothing.
        let mut p = Policy::default_profile();
        p.add_allow("~/dev/**");
        let d = p.decide("/home/u/dev/proj/main.rs", &["/home/u".to_string()]);
        assert_eq!(
            d,
            PolicyDecision::Outside(OutsideWorkspace::Prompt),
            "a `~/` allow entry must grant nothing"
        );
    }

    // WO-145@v2: preserve exact absolute workspace grants.
    #[test]
    fn decide_absolute_allow_is_granted() {
        // Control: a non-`~/` allow entry still grants.
        let mut p = Policy::default_profile();
        p.add_allow("/home/u/dev/**");
        let d = p.decide("/home/u/dev/proj/main.rs", &["/home/u".to_string()]);
        assert_eq!(d, PolicyDecision::AllowWorkspace);
    }

    // WO-145@v2: keep unmatched paths under the configured outside policy.
    #[test]
    fn decide_outside_is_prompt_by_default() {
        let p = Policy::default_profile();
        let d = p.decide("/var/log/syslog", &["/home/u".to_string()]);
        assert_eq!(d, PolicyDecision::Outside(OutsideWorkspace::Prompt));
    }

    // WO-145@v3 (G2): with HOME=/root, `~/.ssh` still matches a path under a
    // DIFFERENT user's home, because decide expands `~/` over every home.
    // WO-145@v2: cover each enumerated home without consulting HOME.
    #[test]
    fn decide_expands_tilde_over_every_home_not_sudo_home() {
        let p = Policy::default_profile();
        let homes = vec!["/root".to_string(), "/home/nullbot".to_string()];
        let d = p.decide("/home/nullbot/.ssh/id_key", &homes);
        assert_eq!(
            d,
            PolicyDecision::Protected,
            "~/.ssh must cover /home/nullbot too"
        );
    }

    #[test]
    fn add_protected_is_idempotent() {
        let mut p = Policy::default_profile();
        assert!(!p.add_protected("~/.ssh")); // already present
        assert!(p.add_protected("~/vault")); // new
        assert!(!p.add_protected("~/vault")); // now present
    }

    // WO-145@v2: keep concrete and wildcard protection paths distinct.
    #[test]
    fn concrete_vs_glob_split() {
        let p = Policy::default_profile();
        let homes = vec!["/home/u".to_string()];
        let concrete = p.concrete_protected_paths(&homes).unwrap();
        let globs = p.protected_globs(&homes).unwrap();
        assert!(concrete.contains(&"/home/u/.ssh".to_string()));
        assert!(globs.iter().any(|g| g == "**/.env"));
        // nothing should appear in both
        assert!(!concrete.iter().any(|c| c.contains('*')));
    }

    // WO-145@v2: the expansion over an injected home set, Linux and macOS
    // shapes alike (the shape only changes which homes are in the set).
    #[test]
    fn tilde_entry_expands_under_every_home() {
        let linux = vec![
            "/home/alice".to_string(),
            "/home/bob".to_string(),
            "/root".to_string(),
        ];
        assert_eq!(
            expand_protect_entry("~/.ssh", &linux).unwrap(),
            vec!["/home/alice/.ssh", "/home/bob/.ssh", "/root/.ssh"]
        );
        let mac = vec!["/Users/pat".to_string(), "/var/root".to_string()];
        assert_eq!(
            expand_protect_entry("~/.aws", &mac).unwrap(),
            vec!["/Users/pat/.aws", "/var/root/.aws"]
        );
        assert_eq!(
            expand_protect_entry("~", &mac).unwrap(),
            vec!["/Users/pat", "/var/root"]
        );
        // A wildcard entry under ~ fans out too; one elsewhere is kept as is.
        assert_eq!(
            expand_protect_entry("~/dev/**/secrets/**", &mac).unwrap(),
            vec![
                "/Users/pat/dev/**/secrets/**",
                "/var/root/dev/**/secrets/**"
            ]
        );
        assert_eq!(
            expand_protect_entry("**/.env", &mac).unwrap(),
            vec!["**/.env"]
        );
        // No homes at all: a ~ entry protects nothing, and says so by being empty.
        assert!(expand_protect_entry("~/.ssh", &[]).unwrap().is_empty());
    }

    // WO-145@v2: accept absolute protection and refuse ambiguous relative paths.
    #[test]
    fn absolute_entry_passes_through_and_relative_is_refused() {
        let homes = vec!["/home/alice".to_string()];
        assert_eq!(
            expand_protect_entry("/etc/hostname", &homes).unwrap(),
            vec!["/etc/hostname"]
        );
        let err = expand_protect_entry("notes/todo.txt", &homes)
            .expect_err("a bare relative entry must be refused")
            .to_string();
        assert!(
            err.contains("is relative") && err.contains("nothing was run"),
            "{err}"
        );
        assert!(expand_protect_entry("~alice/.ssh", &homes).is_err());
        assert!(expand_protect_entry(".ssh", &homes).is_err());
    }

    // WO-145@v2: refuse expansion beyond the bounded host-home set.
    #[test]
    fn home_set_past_the_cap_is_refused() {
        let homes: Vec<String> = (0..=MAX_PROTECT_HOMES)
            .map(|i| format!("/home/u{i}"))
            .collect();
        let err = expand_protect_entry("~/.ssh", &homes)
            .expect_err("more homes than the cap must refuse, not truncate")
            .to_string();
        assert!(err.contains("MAX_PROTECT_HOMES"), "{err}");
        // Exactly at the cap still expands.
        let at_cap: Vec<String> = homes[..MAX_PROTECT_HOMES].to_vec();
        assert_eq!(
            expand_protect_entry("~/.ssh", &at_cap).unwrap().len(),
            MAX_PROTECT_HOMES
        );
        // A host past the cap is not a host to guess on: the run as a whole
        // refuses, absolute entries included.
        assert!(expand_protect_entry("/etc/hostname", &homes).is_err());
    }

    // WO-145@v2: the home set from a fixture tree: the root home, every
    // directory under the users root except the excluded names, passwd homes
    // for uid 0 and uid >= 1000 that exist (a system account's home and a
    // missing home are dropped), a symlinked home canonicalized, duplicates
    // collapsed, sorted.
    #[test]
    fn host_home_set_from_fixture_tree() {
        let base = fs::canonicalize(crate::test_scratch_dir("homes")).unwrap();
        let users = base.join("Users");
        let root_home = base.join("var/root");
        fs::create_dir_all(users.join("alice")).unwrap();
        fs::create_dir_all(users.join("bob")).unwrap();
        fs::create_dir_all(users.join("Shared")).unwrap();
        fs::create_dir_all(&root_home).unwrap();
        fs::write(users.join("notes.txt"), "not a home\n").unwrap();
        // carol's home lives elsewhere and is reached through a symlink.
        let elsewhere = base.join("srv/carol");
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, users.join("carol")).unwrap();
        // dave's home is only known from passwd; eve's does not exist;
        // a system account's home (uid 33) is below the uid floor.
        let dave = base.join("opt/dave");
        fs::create_dir_all(&dave).unwrap();
        let passwd = format!(
            "root:x:0:0:root:{r}:/bin/sh\n\
             www-data:x:33:33::{u}/alice:/usr/sbin/nologin\n\
             alice:x:1000:1000::{u}/alice:/bin/sh\n\
             dave:x:1002:1002::{d}:/bin/sh\n\
             eve:x:1003:1003::{b}/missing/eve:/bin/sh\n\
             broken line without fields\n",
            r = root_home.display(),
            u = users.display(),
            d = dave.display(),
            b = base.display()
        );
        let homes = homes_from(&root_home, &users, &["Shared"], &passwd);
        let mut want: Vec<String> = [
            &users.join("alice"),
            &users.join("bob"),
            &dave,
            &elsewhere,
            &root_home,
        ]
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
        want.sort();
        assert_eq!(homes, want);
        let _ = fs::remove_dir_all(&base);
    }
}
