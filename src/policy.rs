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

/// named front-door configuration for `bulwark launch <agent>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentProfile {
    /// command and arguments to execute for this agent.
    #[serde(default)]
    pub command: Vec<String>,
    /// protected path globs used by the existing deny-list gate.
    #[serde(default)]
    pub protect: Vec<String>,
    /// allow-list grants for default-deny launches.
    #[serde(default)]
    pub allow: Vec<String>,
    /// default decision for protected opens in deny-list mode.
    #[serde(default = "default_agent_decision")]
    pub decision: AgentDecision,
    /// whether launch should write the default audit receipts file.
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
    /// default configured launch profile; `run` ignores this field.
    #[serde(default)]
    pub default_agent: Option<String>,
    /// additive launch profiles keyed by agent name; `run` ignores them.
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

    /// Decide what the policy says about `path`, expanding `~/` with `home`.
    /// Protected takes precedence over workspace-allow: a protected file inside
    /// an allowed workspace is still protected.
    ///
    /// A protected pattern matches if either (a) it glob-matches the path, or
    /// (b) it is a concrete (wildcard-free) path that is a parent directory of
    /// the path. Case (b) mirrors what the gate does at launch — protecting a
    /// directory like `~/.ssh` resolves the inodes of its entries — so `decide`
    /// and the live gate agree that `~/.ssh/id_ed25519` is protected.
    pub fn decide(&self, path: &str, home: &str) -> PolicyDecision {
        let protected_hit = |pat: &String| {
            let expanded = glob::expand_home(pat, home);
            if glob::matches(&expanded, path) {
                return true;
            }
            // concrete directory prefix: `~/.ssh` protects `~/.ssh/<entry>`
            if !expanded.contains('*') && !expanded.contains('?') {
                let dir = expanded.trim_end_matches('/');
                return path
                    .strip_prefix(dir)
                    .is_some_and(|rest| rest.starts_with('/'));
            }
            false
        };
        if self.protected.prompt.iter().any(protected_hit) {
            return PolicyDecision::Protected;
        }
        let allow_hit = |pat: &String| glob::matches(&glob::expand_home(pat, home), path);
        if self.workspace.allow.iter().any(allow_hit) {
            return PolicyDecision::AllowWorkspace;
        }
        PolicyDecision::Outside(self.default.outside_workspace)
    }

    /// Resolve every concrete (wildcard-free) protected pattern to an absolute
    /// path for inode resolution at launch. Patterns containing wildcards are
    /// returned separately by [`Self::protected_globs`] for decision-time
    /// matching (a gate follow-up).
    pub fn concrete_protected_paths(&self, home: &str) -> Vec<String> {
        self.protected
            .prompt
            .iter()
            .map(|p| glob::expand_home(p, home))
            .filter(|p| !p.contains('*') && !p.contains('?'))
            .collect()
    }

    /// The protected patterns that contain wildcards (decision-time matching).
    pub fn protected_globs(&self, home: &str) -> Vec<String> {
        self.protected
            .prompt
            .iter()
            .map(|p| glob::expand_home(p, home))
            .filter(|p| p.contains('*') || p.contains('?'))
            .collect()
    }
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

    #[test]
    fn decide_protected_beats_workspace() {
        let mut p = Policy::default_profile();
        p.add_allow("~/dev/**");
        // a secret file inside the allowed workspace is still protected
        let d = p.decide("/home/u/dev/proj/.env", "/home/u");
        assert_eq!(d, PolicyDecision::Protected);
    }

    #[test]
    fn decide_allows_workspace() {
        let mut p = Policy::default_profile();
        p.add_allow("~/dev/**");
        let d = p.decide("/home/u/dev/proj/main.rs", "/home/u");
        assert_eq!(d, PolicyDecision::AllowWorkspace);
    }

    #[test]
    fn decide_outside_is_prompt_by_default() {
        let p = Policy::default_profile();
        let d = p.decide("/var/log/syslog", "/home/u");
        assert_eq!(d, PolicyDecision::Outside(OutsideWorkspace::Prompt));
    }

    #[test]
    fn add_protected_is_idempotent() {
        let mut p = Policy::default_profile();
        assert!(!p.add_protected("~/.ssh")); // already present
        assert!(p.add_protected("~/vault")); // new
        assert!(!p.add_protected("~/vault")); // now present
    }

    #[test]
    fn concrete_vs_glob_split() {
        let p = Policy::default_profile();
        let concrete = p.concrete_protected_paths("/home/u");
        let globs = p.protected_globs("/home/u");
        assert!(concrete.contains(&"/home/u/.ssh".to_string()));
        assert!(globs.iter().any(|g| g == "**/.env"));
        // nothing should appear in both
        assert!(!concrete.iter().any(|c| c.contains('*')));
    }
}
