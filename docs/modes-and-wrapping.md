# Choosing a mode, and wrapping an agent runner

Bulwark has two ways to bound what a supervised process tree can read. They suit
different situations, and picking the wrong one either breaks the agent or protects
nothing. This page explains which fits when, and how to wrap an agent launcher so
every run is confined.

## The two modes

### Deny-list — `--protect` (recommended for interactive / coding agents)

Protect specific paths; **everything else stays readable.**

```sh
bulwark run --protect ~/.ssh --protect ~/.aws --protect ~/other-project -- <agent>
```

The agent reads its working tree, the language toolchain, caches, and config exactly
as normal — and is denied, at the kernel, on the paths you named (by inode, so a
symlink or rename can't dodge it). `--protect` takes a file or a directory.

**Use this when the agent needs a broad, hard-to-enumerate read surface** — which is
almost always true for a real coding agent. `go build` reads the whole module cache
and `$GOROOT`; `npm`/`cargo`/`pip` read global caches; the agent greps the repo and
reads `.git` internals. You cannot list all of that up front, and you don't need to —
you only need to name the things it must *not* read (credentials, other repos,
secret stores). Deny-list does that without breaking the toolchain.

### Allow-list — `--deny-all --allow` (recommended for CI / unattended tasks)

Default-deny: the tree may read **only** the `--allow` globs plus a small runtime base
set (linker, libc, locale — the minimum to execute), and nothing else.

```sh
bulwark run --deny-all --allow '/srv/job/**' -- <agent>
```

**Use this for narrow, well-defined jobs** where you genuinely know the full read
surface — a single-purpose CI step, a log-triage task pointed at one directory, a
transform over one input tree. The agent gets a tightly bounded sandbox.

**Do not reach for allow-list to confine a general coding agent.** Its read surface is
not static — the toolchain alone reads far more than you can enumerate, so a tight
allow-list will `EPERM` the compiler/test runner and break the run. For that case use
deny-list and protect the dangerous paths instead.

## Which mode — quick guide

| Situation | Mode | Why |
|---|---|---|
| Coding agent on your machine / in a repo | `--protect <dangerous paths>` | Read surface is broad + non-static; deny only credentials & other repos |
| CI step with a known input directory | `--deny-all --allow '<dir>/**'` | Read surface is small and knowable; default-deny is tightest |
| "Let an agent work here but never touch my keys" | `--protect ~/.ssh ~/.aws ...` | The keys are what matters; everything else stays usable |
| One-shot transform over one tree | `--deny-all --allow '<tree>/**'` | Bounded job → bounded sandbox |

When unsure, start with **deny-list protecting the obvious secrets** (`~/.ssh`,
`~/.aws`, cloud config, other projects, password stores). It never breaks a run, and
it closes the leak path that matters most: an agent reading credentials it was never
meant to see.

## Wrapping an agent runner

If you dispatch agents from a launcher (a script, a CI runner, an orchestrator), make
every run go through Bulwark by wrapping the spawn at one chokepoint:

```sh
# before:
<agent> "$@"

# after:
bulwark run --protect "$HOME/.ssh" --protect "$HOME/.aws" \
            --protect "$HOME/.config/gcloud" --protect "$WORKSPACE_ROOT/../other-repos" \
            -- <agent> "$@"
```

Guidelines:

- **Deny-list is the safe default for a wrapper** — it confines without needing to
  predict each task's read surface, so the same wrapper works for any agent/task.
- **Protect by category, not by guessing the closure:** credentials, cloud config,
  SSH/GPG, sibling repositories, secret managers' local caches. These are stable and
  small; you don't have to track what the agent legitimately reads.
- **Never protect the agent's own config/home directory.** Many agents read their own
  directory to authenticate and run — an OpenAI-style CLI reads `~/.codex/auth.json`
  for its API key, a Claude CLI reads `~/.claude/` for settings and skills. `--protect`
  that directory and the agent can't start. The protect-set is therefore
  *agent-specific*: deny the secrets and the *other* tools' config dirs, but leave the
  wrapped agent's own dir readable. (Denying tool B's dir while running tool A is free
  confinement — A never needs it.)
- **Bulwark needs privilege** (root / `CAP_SYS_ADMIN` on Linux; root + Full Disk
  Access on macOS — see [docs/macos-permissions.md](macos-permissions.md)). A launcher
  that wraps with Bulwark must be able to elevate for the gate while the agent itself
  stays unprivileged. Scope that privilege deliberately.
- **It composes, it does not replace.** Bulwark gates *reads*. It does not gate writes,
  network egress, or secrets already inside the allowed area. Pair it with whatever you
  use for those — Bulwark adds the read boundary, cleanly and at the kernel.

For remote/dispatched agents, `bulwark ssh` carries the same model to another host;
see [docs/remote.md](remote.md).
