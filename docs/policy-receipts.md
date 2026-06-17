# — Policy + receipts: evidence

**Target:** Debian 13 arm64, kernel 6.12.74. **Date:** 2026-06-03.

## Verification gates (green on the VM)

- `cargo fmt --check` — clean
- `cargo clippy --all-targets -- -D warnings` — clean
- `cargo test` — **25 unit + 5 CLI tests pass**
- `cargo test --test gate_integration -- --ignored` under sudo — **6/6 pass**
  (gate regression check after the `gate::run` signature change)

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
  MVP effect: read DENIED (prompt deferred to )

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

## MVP semantics (operator-narrowed)

`default.outside_workspace=prompt` and `default.on_timeout=deny` are stored
canonically, but the Linux MVP has no interactive prompt (deferred to ), so
a `prompt` outcome resolves to **deny** (fail-safe) at the gate and `check`
states this explicitly. Concrete protected paths resolve to inodes at launch as
before; decision-time matching of wildcard protected patterns (`**/*secret*`) in
the running gate is a thin follow-up — the matcher and `decide()` logic are
implemented and unit-tested here, surfaced via `bulwark check`.

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
