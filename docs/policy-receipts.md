# WO-5 — Policy + receipts: evidence

**Target:** Debian 13 arm64, kernel 6.12.74. **Date:** 2026-06-03.

## Verification gates

- `cargo fmt --check` — clean
- `cargo clippy --all-targets -- -D warnings` — clean
- `cargo test` — **25 unit + 5 CLI tests pass**
- `cargo test --test gate_integration -- --ignored` under sudo — **6/6 pass**
  (WO-3 gate regression check after the `gate::run` signature change)

## What shipped

- **`Bulwark.toml` schema** (`serde` + `toml`): `[workspace] allow`, `[protected]
  prompt`, `[default] outside_workspace`, `[default] on_timeout`.
- **Default profile**: `~/.ssh ~/.aws ~/.gnupg ~/.kube ~/.config/gcloud
  ~/Documents ~/Desktop ~/Downloads ~/.* **/.env **/*secret* **/*credential*
  **/*token*`; workspace allow empty (opt-in boundary). Built-in `dev` profile
  adds `~/dev/** /tmp/**`.
- **Deterministic glob matcher** (`*`, `?`, `**`, `**/`, `~/` expansion) — no
  regex dependency; `**/` correctly matches zero or more segments.
- **CLI**: `bulwark run --profile <name> | --policy <file>`; `bulwark allow
  <glob>` / `bulwark deny <glob>` mutate the policy; `bulwark audit <receipts>`
  renders the log; `bulwark check <path>` reports the policy decision.

## Live demo

```
$ bulwark check ~/.ssh/id_ed25519 --profile default
  policy:     protected
  MVP effect: read DENIED (prompt deferred to WO-8)

$ bulwark check ~/dev/proj/main.rs --profile dev
  policy:     allow (workspace)
  MVP effect: read allowed

$ bulwark deny '~/vault/**' --policy ./Bulwark.toml
protected ~/vault/** (written to ./Bulwark.toml)

$ bulwark audit r.jsonl
TS(ms)          PID      DECISION  PATH                  ANCESTRY
1780467195385   1034800  allow     /tmp/ademo/ok.txt     cat(1034800) <- bash <- bulwark <- ...
1780467195385   1034799  deny      /tmp/ademo/secret.env cat(1034799) <- bulwark <- ...

1 allow, 1 deny, 0 unparsed
```

## What `~` means in a protect entry

<!-- WO-145@v2: until 0.9.2, `~` came from $HOME, which under plain sudo on Linux is /root. -->
A protect entry in the default profile, a `[protected]` section or a launch
profile's `protect` list is one of two things. An **absolute** path is
protected exactly as written. An entry starting with **`~/`** means that path
under **every** home directory on the host: root's home, every directory under
`/home` (`/Users` on macOS, minus `Shared`), and the home of every `/etc/passwd`
account with uid 0 or uid 1000 and up that exists, canonicalized and
deduplicated. `~/.ssh` therefore protects every user's `.ssh` and root's, never
one guessed home. Anything else (a bare relative path such as `secrets/`) is
refused before the run starts. The run prints the rule once when a `~/` entry
is in play. The expansion refuses, rather than truncates, past
`MAX_PROTECT_HOMES` (4096) homes. `--protect` on the command line is not a
policy entry: your shell expands its `~` before Bulwark sees it.

<!-- WO-145@v3 (G1/G3): `~/` can still miss a non-enumerated home, or hit a broken one. -->
Two consequences follow when `~/` entries are in play. **G1** — when the run
will execute the agent as a known non-root uid (the `SUDO_UID` default drop,
an explicit `--worker-uid`, or an unprivileged launcher's own uid), Bulwark
requires at least one enumerated home to be *owned* by that uid (a uid owning
ANY listed home counts; its real home may be elsewhere, which without an
NSS/LDAP lookup Bulwark cannot know). If none is, the run refuses before
anything starts, naming the uid and pointing at absolute `--protect` paths —
this is what catches an account served by LDAP/AD/SSSD, or a home outside
`/home`/`/Users`, whose own `~/.ssh` the expansion would otherwise miss. The
check applies uniformly to every explicit non-root `--worker-uid`: there is no
anonymous-worker exemption. **G3** — a non-ENOENT stat failure on an expanded
protect path still refuses the run (fail closed, WO-131), and the refusal names
the home the path was expanded from and, when that home is owned by a
*different* uid, says so. **Allow** — a `~/` workspace allow entry is not
expanded across homes (that would widen a grant); it grants nothing and asks
for an absolute path. Bulwark stats only the expanded protect paths: it never
reads a directory listing *inside* a home, so it does not deliberately trigger
an automount.

## How `check` decides a protected path

<!-- WO-198@v1: check runs the decision-rule contract the gates are moving onto. -->
`bulwark check` decides protection with the same rule contract the gates are
moving onto. Each protect entry protects both the file or directory that exists
when the policy is read (it follows that object through renames) and the
**location** it names (whatever sits there later: a replaced file, a file
created afterwards, a file renamed into it). An entry that does not exist yet
is protected from its nearest existing parent, so it is covered the moment it
appears, including everything below it if it appears as a directory.

- Name matching in protect entries ignores ASCII case (`**/.env` also covers
  `.ENV`); a pattern that matches a directory name (`~/.*`) covers that name,
  not the directory's contents, unless the entry ends in `/**`.
- Entries must be absolute, start with `~/` or start with `**/`. A component may
  hold at most two `*`, an entry at most two `**` components and at most 16
  components below its anchor; `{a,b}` alternatives are allowed. An entry
  outside these limits, a bare relative entry, `..`, or a non-ASCII name in a
  protect entry is refused by name and nothing is checked.
- `check` resolves symlinks first, like a real open, and reports the entry that
  decided and its precedence step, for example
  `rule: **/.env (step 3)` (`"rule"` and `"step"` in `--format json`).

## MVP semantics (operator-narrowed)

`default.outside_workspace=prompt` and `default.on_timeout=deny` are stored
canonically, but the Linux MVP has no interactive prompt (deferred to WO-8), so
a `prompt` outcome resolves to **deny** (fail-safe) at the gate and `check`
states this explicitly. The running gate still resolves concrete protected
paths to inodes at launch and does not yet match wildcard entries at decision
time; moving the Linux and macOS gates onto the rule contract that `check`
uses is the next step.

## Acceptance mapping

| # | Requirement | Evidence |
|---|---|---|
| 1 | Bulwark.toml schema | `policy.rs`; round-trip test |
| 2 | Default profile ships | `Policy::default_profile`; demo above |
| 3 | Receipt schema (time, pid_tree, path, decision, reason) | `receipt.rs`; audit demo |
| 4 | `allow`/`deny` mutate policy | `policy_cli.rs`; demo |
| 5 | `audit` renders log | `audit.rs`; demo |
| 6 | `run --profile`/`--policy` select policy | `main.rs cmd_run`/`load_policy` |
| 7 | Tests: glob, default-deny outside, timeout=deny, receipt round-trip | 25 unit + 5 CLI tests |
