# CI/CD dispatch — default-deny allowlist mode

Run an agent in a pipeline so it can read **only** the path you grant it, and
nothing else. No human in the loop: the policy *is* the decision.

```
bulwark run --deny-all --allow '<glob>' [--allow '<glob>'...] -- <command>
```

`--deny-all` flips Bulwark from its normal deny-list (protect a few paths, allow
the rest) to a **default-deny allowlist**: every read by the supervised process
tree is denied unless its path matches `--allow` or the runtime base set.

## The runtime base set is allowed — and you should know exactly what it is

A program cannot execute while reading *only* your granted path: it must read
its interpreter, libc, locale data, and a handful of system files just to start.
So allow-list mode permits a **runtime base set** in addition to your grants.
These are allowed reads. Inspect them:

```
bulwark base-set
```

The base set covers `/lib`, `/usr/lib`, `/bin`, `/usr/bin`, the dynamic linker
cache, locale data, `/dev/tty`, `/proc/self`, and name-resolution basics like
`/etc/passwd` and `/etc/resolv.conf`. It does **not** include `/etc/shadow`,
SSH keys, cloud credentials, or any data directory. This is a deliberate
trade-off: wide enough to run a normal program, narrow enough that the
sensitive material is still out of reach. If your agent is statically linked and
needs nothing, `--no-base-set` drops it.

## Worked example: triage a production ClickHouse incident

Dispatch an agent to investigate a ClickHouse problem with read access to the
**logs only** — never the data directory, never credentials.

```sh
bulwark run --deny-all \
  --allow '/var/log/clickhouse-server/**' \
  --receipts /tmp/triage-receipts.jsonl \
  -- triage-agent --investigate "query timeouts on shard 3"
```

What the agent can do:

- ✅ read `/var/log/clickhouse-server/clickhouse-server.log` and `*.err.log`
- ✅ execute normally (the base set covers its runtime)

What the agent cannot do — denied, recorded in the receipts:

- ❌ read `/var/lib/clickhouse/**` (the data directory — customer rows)
- ❌ read `/etc/clickhouse-server/users.xml` or any credential file
- ❌ read `~/.ssh`, `~/.aws`, `/etc/shadow`, another database's files

Every decision is in the receipt log (`bulwark audit /tmp/triage-receipts.jsonl`)
with the process chain, the path, and allow/deny — so you have proof of exactly
what the agent reached.

## GitHub Actions

```yaml
- name: Triage under Bulwark
  run: |
    sudo bulwark run --deny-all \
      --allow '${{ github.workspace }}/logs/**' \
      --receipts "$RUNNER_TEMP/receipts.jsonl" \
      -- ./triage-agent
```

## Generic CI / shell

```sh
sudo bulwark run --deny-all \
  --allow "$PWD/logs/**" \
  -- ./agent
```

`sudo` is required: fanotify permission gating needs `CAP_SYS_ADMIN`.

## Honest limits

Allow-list mode is built on the same Linux fanotify gate as the rest of Bulwark,
so it shares the same boundary (see the project's security boundary notes):

- It gates **reads**, not consequences — it does not stop the agent acting on
  what it legitimately read, or sending it over the network. Pair it with an
  egress control.
- A **hard kill** of the supervisor (`SIGKILL`, crash, OOM, power loss) while a
  read is held releases that one read as allowed — an inherent fanotify
  property. A graceful stop (`SIGTERM`) fails closed. For an ephemeral CI job
  this window is small, but it is real; a crash-safe kernel floor is planned.
- All filesystems present at launch are marked. A filesystem **mounted after**
  the agent starts is not covered.
- A grant is a **launch-time snapshot of inodes**, not a live path rule. Files
  that exist and match a grant at launch are readable; a file **created, moved,
  or hardlinked into a granted directory after launch is denied** (fail closed).
  This is deliberate — it is what stops a foreign secret being hardlinked or
  renamed into a grant to read it. If a dispatched agent needs to read back its
  own output, write it to stdout or to a path you grant and pre-create, rather
  than relying on re-reading a file it made mid-run.
- Grant identity is the inode **plus its generation** (`FS_IOC_GETVERSION`), so a
  granted file deleted mid-run whose inode number is then reused by another file
  on the same filesystem is **denied** — the kernel bumps the generation on reuse,
  so the foreign file does not match the snapshot. This is verified on ext4. On a
  filesystem that reports no generation, the gate falls back to `(device, inode)`
  and fails closed if it cannot confirm freshness; in practice the filesystems that
  report no generation (tmpfs, overlayfs) also do not recycle inode numbers, so
  there is nothing to confuse. A networked grant filesystem such as NFS is
  untested — keep granted material on a local filesystem.

Bulwark is a tool with limits, stated up front — not a magic wand. Used with
its grain (one granted path, sensitive material kept off the host, paired with
egress control), it makes a dispatched agent genuinely least-privilege.
