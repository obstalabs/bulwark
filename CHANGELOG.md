# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
<!-- WO-140@v1: release and CI gates bind macOS seal evidence to exact artifacts. -->
- macOS hardware-seal receipts identify the tested binary, source commit and signed
  gate; release upload checks the extracted arm64 archive and gate identity, and CI
  requires acknowledgement when a boundary path changes, is renamed or is deleted.
<!-- WO-174@v1: ship the signed arm64 bytes that the hardware seals exercised. -->
- macOS release packaging signs before sealing and refuses upload unless both the
  arm64 tarball and installer payload match the hardware-seal receipts.

### Added
<!-- WO-95@v1: CI does not sign macOS; the manual packaging steps lived only in session notes. -->
- `macos-es-proof/package-release.sh`: the macOS release packaging steps for maintainers
  (bundle the signed gate app into the darwin tarballs, re-run both hardware seals on the
  exact pair that ships, build signed + notarized + stapled `.pkg` files, verify, upload),
  until CI signs macOS releases.

### Fixed
<!-- WO-179@v1: preserve the single-use scope of remote allow-once verdicts. -->
- Remote `allow-once` verdicts authorize exactly one matching open instead of the
  rest of the session; `allow-session` remains reusable and is shared by processes
  running as the requester uid in that session.
<!-- WO-182@v1: remote consent must reject substituted or absent control lanes. -->
- Remote consent opens existing FIFO lanes without following links or creating missing
  verdict paths, validates their ownership, and fails the launcher when a lane stays absent;
  control exits during normal gate teardown preserve the gate's status, and verdict delivery
  uses GNU `dd`'s `conv=nocreat` mode so unsupported hosts fail before consent starts.
<!-- WO-192@v1: failed remote cleanup must release processes blocked opening a lane. -->
- Failed remote runs no longer leave a consent-lane process and SSH session behind on
  the remote host.
<!-- WO-181@v1: remote prompt backpressure must never delay a permission decision. -->
- Remote consent prompts use a bounded writer queue, so a stalled prompt lane cannot delay protected-open denials.
<!-- WO-151@v1: damaged integrity state must not erase sticky taint or its evidence. -->
- Corrupt or unreadable integrity state now starts tainted and is preserved before an
  atomic replacement; only an absent state file starts clean; CI exercises EACCES before
  privileged tests.
<!-- WO-176@v1: failing non-root integrity checks must retain their Cargo diagnostics. -->
- CI prints Cargo output before failing the non-root integrity-state check.
<!-- WO-175@v1: pull requests must not supply the seal control that judges them. -->
- CI evaluates hardware-seal acknowledgement with the base branch's control files,
  every step of which carries its work-order citation.
<!-- WO-153@v1: reserve remote run paths before placing HiveBus material. -->
- Remote HiveBus dispatches create each run and key directory exactly once instead of
  colliding with the consent lane's anti-squatting guard; the remote integration tests
  stream the binary under test instead of using an installed copy.
<!-- WO-149@v1: isolate remote integration runs from shared integrity state. -->
- `bulwark ssh` accepts a hidden per-run integrity state path for isolated tests and
  forwards it safely to the remote gate; every root test suite uses its own state file and
  CI fails if one changes the host default.
<!-- WO-159@v1: macOS gates do not use Linux mount marks. -->
- macOS allow-list runs no longer warn that `/proc/mounts` could not be read; the mount
  enumerator documents its non-Linux fallback.

### Changed
<!-- WO-190@v1: public copy promised a paid tier that is not planned. -->
<!-- WO-193@v1: the site no longer offers an assessment, so the README does not either. -->
- README leads with why an independent layer matters and drops the Pro / Fleet tier,
  its roadmap items and any paid offer.
<!-- WO-177@v1: pid-based supervisor tests must wait for complete writer output. -->
- Supervisor reaping tests read newline-terminated pid records with a bounded deadline.
<!-- WO-182@v1: the verdict delivery test must not lose a line written just before the writer exits. -->
- The remote verdict delivery test drains the FIFO after the writer exits, so a line written just before exit is never missed.
<!-- WO-158@v1: hard-kill tests must release their cgroup and filesystem fixtures. -->
- Supervisor hard-kill tests prove their cgroup is empty, remove it and unmount their test filesystem on every exit path, retrying transiently busy unmounts to a bounded deadline.
<!-- WO-157@v1: verified lock identity makes consent socket directory removal race-safe. -->
- Consent socket teardown removes its verified node, lock and directory without allowing a racing binder to use an orphaned lock.
<!-- WO-83@v1: remote consent tests prove the worker cannot access either control FIFO. -->
- Remote consent documentation and tests make the worker-uid isolation requirement explicit for both control lanes.
<!-- WO-178@v1: other root suites that kill a gate must release its cgroup scope too. -->
- Consent socket and integrity tests that kill a gate prove its cgroup is empty and remove it on every exit path.
<!-- WO-173@v2: per-item platform gates expose unrelated dead code on non-Linux builds. -->
- Non-Linux builds scope dead-code allowances to the specific Linux-only items that need them;
  the crate comment names that per-item gate.
<!-- WO-123@v1 / WO-124@v1 / WO-125@v1 / WO-126@v1 / WO-161@v1 / WO-162@v1 / WO-163@v2 / WO-164@v2 / WO-166@v1 / WO-167@v1 / WO-168@v1 / WO-169@v1 / WO-170@v1 / WO-171@v1: source citations identify the current intent behind each attributed region. -->
- Source comments cite the work order behind each function and test, so every change traces to its stated intent.
  Code that shipped without a recorded work order was given a retroactive one that records its
  behaviour, instead of a guessed id.
<!-- WO-172@v1: helpers kept only for tests now compile only into tests. -->
- Helpers used only by unit tests are compiled only into test builds, instead of being
  kept in the shipped binary with dead-code warnings silenced.
<!-- WO-172@v1: the ES proof source checks existed but nothing ran them. -->
- CI runs the macOS ES proof source checks: the seal checks on every push, the proof
  client checks in the macOS job.

### Removed
<!-- WO-172@v1: no caller remained after inode-membership grants replaced path roots. -->
- The unused macOS path-root grant resolver, superseded by inode-membership grants, and an
  unused single-home lookup. Neither had a caller; behaviour is unchanged.

## [0.9.3] - 2026-10-15

### Security
<!-- WO-155@v1 / WO-156@v2: consolidated — tree reaped on any supervisor death with positive-proof empty-scope, freeze fallback and reapable-host refusal; receipts integrity and accounting; deadline-bounded consent; debug-only fault-injection. -->
- A dead supervisor never leaves a live unsupervised agent. The direct child
  carries a parent-death signal (set after its privilege drop), and an
  independent watcher reaps the run's cgroup, holding every unanswered
  permission event until it has positive proof the scope is empty. Release
  comes only after that proof, so a supervisor panic or other early exit reaps
  too; a successful `cgroup.kill` is confirmed by polling `cgroup.events` until
  empty, a kill that cannot be written falls back to freezing the scope and
  signalling each remaining process, and an unreadable status backs off and
  retries unless the scope has been removed, which the kernel allows only once
  it is empty. On kernels without
  `cgroup.kill` the watcher uses the freeze-and-sweep path, and default mode
  refuses to start on a host whose scope cannot be read or reaped, naming
  `--hardened` (its kernel-enforced floor keeps working there). A graceful stop
  forwards SIGTERM and escalates to a reaping kill only after a grace, and the
  fanotify group closes only after every deferred consent is answered and the
  tree is confirmed dead. Receipts are written to a file opened by a
  component-wise, no-follow walk from a pinned working directory, which refuses
  a symlinked ancestor (except a root-owned system link), a non-regular path
  such as a FIFO, and a final component that is not a regular, singly-linked
  file owned by the effective uid; the accounting summary is the writer's final
  message, and a lost or failed summary is warned and counted, never blocking
  the exit. Each consent request shares one absolute, poll-bounded deadline
  with a capped verdict line, so a trickling or late peer cannot hold an open.
  The fault-injection feature is compiled out of release builds.
<!-- WO-142@v1: the hardened Landlock floor took the base set unchecked; two wildcard entries floored all of /proc. -->
- `--hardened` no longer floors all of `/proc`. The runtime base set's
  `/proc/*/stat` and `/proc/*/status` reached the Landlock floor as a rule on
  `/proc` itself, so the agent could read `status`, `stat` and `cmdline` (and
  any credential on a command line) of every process on the host; `environ`
  and `maps` were already denied by Landlock's ptrace rule. Every glob is now
  checked where its rule is added and one that would widen is skipped with a
  stderr note, base set included. The floor grants the system-wide procfs
  files tools size themselves from (`/proc/cpuinfo`, `/proc/stat`,
  `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime`) as exact files and nothing
  per-process: `ps`, reads of `/proc/self/*` and Node's `process.memoryUsage()`
  fail with EACCES under `--hardened`; Node's `os.cpus()` works; bash, git,
  python3 and node themselves start and run subprocesses as before.
<!-- WO-144@v1: the hardened branch refused --worker-uid and exec'd at the launching uid. -->
- `--hardened` no longer runs the agent as root. Under `sudo` the agent kept
  uid 0 behind the Landlock floor, and the mode refused `--worker-uid`. The
  floor is now applied first and the process then drops to `SUDO_UID` (or the
  `--worker-uid`/`--worker-gid` given) before the exec, asserting that root
  cannot be regained. Launched as real root with no sudo origin and no
  `--worker-uid`, hardened mode refuses before anything runs unless
  `--allow-root` is passed.
<!-- WO-145@v2: protect entries expanded `~` from $HOME; under plain sudo on Linux that is /root. -->
- `~` in a protect entry no longer means one guessed home. In 0.9.0, 0.9.1 and
  0.9.2 the default profile, a `[protected]` section and (once launch worked)
  a launch profile expanded `~` from `$HOME`, which under plain `sudo` on
  Linux is root's home: the gate protected `/root/.ssh` while the agent,
  dropped to the invoking user, read that user's real `~/.ssh` and `~/.aws`
  unprotected. A `~/` entry now means that path under every home directory on
  the host (root's, every directory under `/home` or `/Users`, and every
  `/etc/passwd` home for uid 0 or uid 1000 and up that exists); an absolute
  entry is protected exactly as written; any other relative entry is refused
  before the run starts. The run states the rule once. `--protect` on the
  command line is unaffected, the shell expands it.
<!-- WO-145@v2: a known non-root agent uid with no enumerated home must refuse; check shares the home set; broken-home refusal names it. -->
- The every-home `~` rule refuses to launch when the agent would run as a
  known non-root uid that owns none of the enumerated homes. An account served
  by LDAP/AD/SSSD, or with a home outside `/home`/`/Users`, would otherwise
  still read its own keys unprotected; the run now fails first, naming the uid
  and pointing at absolute `--protect` paths. The check applies to every
  explicit non-root `--worker-uid`: there is no anonymous-worker exemption.
  `bulwark check` previews against the same home set as `run`, and a
  non-ENOENT stat failure on an expanded protect path names the home it came from.
<!-- WO-147@v1: the consent socket dir lived in /tmp and was reused + chmod'd by path. -->
- The consent socket directory is no longer a squattable, path-swappable target.
  As root the socket lives under a root-only runtime dir (`/run/bulwark`, or
  `/var/run/bulwark` on macOS) created 0711 regardless of `$XDG_RUNTIME_DIR`; the
  socket directory is created fresh with `mkdir` (or reused only if it is a real
  directory owned by the effective uid and not group/other-writable), opened
  `O_DIRECTORY|O_NOFOLLOW`, revalidated with `fstat` after the open (a fresh
  create must still name the very object it mkdir'd), and every chmod/chown goes
  through that fd — so a foreign node, symlink, regular file or a swapped-in
  directory squatting the name is refused, never deleted and never chmod'd, and
  root cannot be made to chmod an attacker-chosen directory. Only the socket
  node is chowned (0600) to the invoking user under sudo; the answer client
  derives the same default node.
<!-- WO-147@v1: the fixed socket path was not exclusive and a non-root client could not reach the root default. -->
- A consent socket path is now owned by exactly one run at a time. A second
  `bulwark run` on a path already in use is refused with a `--consent-socket
  <other path>` remedy rather than silently taking over the live node and its
  verdicts, and only that run may clear a stale node. Before the socket
  directory is created, its parent must be a directory owned by root or the
  effective uid with no group/other write, or sticky (like `/tmp`), so a
  directory the operator does not control cannot redirect the socket. `bulwark
  consent` run as the invoking non-root user now answers a root gate's default
  socket at `/run/bulwark/consent.sock` with no `--socket`, and the runtime dir
  is forced to 0711 even under a restrictive `umask` so that traversal works.
<!-- WO-154@v1: the permission loop wrote every decision to stderr synchronously. -->
- The permission loop no longer performs blocking output. Every gate decision is
  enqueued and drained by a separate writer thread, so a stalled log reader
  drops lines (counted and reported at shutdown) instead of stalling the loop;
  a protected-open consent decision is made on its own thread (a bounded queue,
  past which a protected open is denied outright), so a pending prompt cannot
  delay unrelated opens on the same filesystem. The log writer never changes the
  inherited stderr's mode (it is shared with the operator and the agent).
<!-- WO-147@v1: teardown could unlink a successor run's node; a relative socket path failed; the parent check covered only one ancestor. -->
- Consent socket handoff and path validation are tightened. Teardown unlinks the
  node while still holding the run lock (never the lock file), a relative
  `--consent-socket` resolves against the working directory, every ancestor of
  the socket directory (not just its immediate parent) must be a safe directory,
  and the answer client has a bounded read timeout with a clear error.
<!-- WO-130@v1: the integrity record keyed protected objects on (dev, ino) only. -->
- The integrity circuit breaker now records each protected object's inode
  generation next to its device and inode number, and reports object drift
  when the generation moves. Deleting a protected file and creating a new one
  at the same path routinely gets the same inode number back on ext4, so that
  swap went unreported. A protected path that is a top-level symlink records
  its target's generation, matching the reflected organization it actually
  guards. State files written before this field load unchanged and are rewritten
  with the generation on the next run.

### Fixed
<!-- WO-147@v1: socket::bind swapped the process umask to 0177 around the bind. -->
- `bulwark run` no longer changes the process-wide umask to create the consent
  socket. The socket is now bound inside a sibling directory created mode 0700
  and owned by the invoking user, so the socket's own mode no longer matters.
  The old `umask(0177)` swap raced any concurrent `mkdir` in the supervisor: a
  directory made in that window came out mode 0600 (no traverse bits), which
  flaked the multi-threaded policy snapshot tests with EACCES.
<!-- WO-147@v1: post-bind failure paths leaked the dir fd or left a half-set node; sun_path was a fixed constant. -->
- Consent-socket failure handling is tightened: the directory descriptor is no
  longer leaked when a bind fails, a `set_nonblocking` failure now unlinks the
  just-bound node through the directory fd, the node's chmod/chown are checked
  and verified (a 0600 socket owned by the invoking user), every error path after
  bind removes the just-bound node, teardown unlinks the node and removes the
  directory through a directory fd (never by path as root), and the sun_path
  limit is read from the platform (`sockaddr_un`) and refused up front when a
  `--consent-socket` node would exceed it.
<!-- WO-145@v2: a ~ allow entry must not widen a grant. -->
- A `~/` workspace allow entry is no longer expanded across every home — that
  would widen a grant; it grants nothing and asks for an absolute path instead.
  `bulwark check` now previews protected paths through the same expansion as
  `run`, so the two can no longer diverge.
<!-- WO-141@v1: launch handed the profile's protect strings to the strict --protect resolver. -->
- `bulwark launch <agent>` with the starter profile never started in 0.9.0,
  0.9.1 and 0.9.2: the profile's protect entries (`~/.ssh`, `**/.env`, ...)
  were stat'ed literally, so every launch failed with "cannot stat protected
  path ~/.ssh". A launch profile's protect list now goes through the same
  home expansion, concrete/wildcard split and lenient resolution as a policy
  file's `[protected]` section, with the same notes. A profile that sets both
  protect and allow still ignores its allow list (bulwark/WO-136 decides what
  it means) and now says so at launch.

## [0.9.2] - 2026-10-07

### Security
<!-- WO-137@v1: the allow-list grant snapshot followed symlinks; found by the macOS allow-list seal. -->
- Allow-list mode (`--deny-all --allow <glob>`) no longer follows symlinks when
  it snapshots a grant at launch. In 0.9.0 and 0.9.1 a symlink inside a granted
  folder recorded its target's inode, so a link to a file outside the grant made
  that file readable to the supervised tree, through the link and by its own
  path. Symlinks inside a grant are now skipped and a grant whose path ends in a
  symlink contributes nothing, however the path is spelled (a trailing `/` or
  `/.` does not get around the check, and a path ending in `..` grants nothing);
  a stderr note names the real path to grant instead, which matters on macOS
  where `/tmp`, `/var` and `/etc` are symlinks.
  Hardlinks keep their inode semantics: a hardlink of a granted file is that
  file, and a foreign file hardlinked into a grant after launch is denied.

### Fixed
<!-- WO-132@v1: the CI flake on the 0.9.1 merge; test-only, but user-visible as red CI. -->
- Tests no longer name their scratch directories or images by process id alone,
  so a leftover from another user or a root step cannot make them fail.
<!-- WO-134@v1: file-level Landlock rules were dropped; hardened mode could not read /dev/null. -->
- `--hardened` now grants read access to regular files and devices on the allow
  list, not only directories. Landlock rejected the directory right on a file, so
  `/dev/null`, `/etc/passwd`, `/etc/resolv.conf` and every other file in the
  runtime base set or a file-level `--allow` were silently left unreadable; the
  stderr line for a dropped rule now includes the OS error.
<!-- WO-131@v1: skipped-as-absent paths were still handed to fanotify_mark. -->
- A policy that names a protected path absent on this host (the default
  profile's `~/.ssh` on a fresh runner, for example) no longer aborts the run
  with `fanotify_mark ... No such file or directory`: only the paths that
  resolved are marked, and the skip note now names the absent paths. Only an
  absent path is skipped; a protected path that cannot be stat'ed for any other
  reason (permission denied through its parent, an I/O error) refuses the run
  before launch, naming the path and the OS error.
<!-- WO-133@v3: --allow was silently ignored on the deny-list path; the stub error did not say nothing ran. -->
- `bulwark run --allow <glob>` without `--hardened` or `--deny-all` now refuses
  before anything is spawned, naming the two modes that take an allow-list; it
  used to ignore the grant and run the default deny-list. On a platform without
  Landlock, `--hardened` now says to run without it to use the Endpoint
  Security gate and ends with "nothing was run".
<!-- WO-135@v2: the 0.9.1 x86_64 gnu binary required glibc 2.39. -->
- The static musl build is now the documented Linux install, and the glibc
  (`-gnu`) builds are cross-compiled against glibc 2.31 with a check in both
  the release and PR workflows that fails if either gnu binary needs anything
  newer, or needs a loader feature the floor cannot vouch for; the 0.9.1 x86_64 gnu
  archive required glibc 2.39 and did not load cleanly on Debian 12 or Ubuntu
  22.04.

### Changed
<!-- WO-128@v1: measurement instrument; the allow/deny decision is unchanged. -->
- macOS allow-list receipts now say when an open outside the supervised tree came
  from a process whose ancestry could not be established, instead of reporting it
  as an ordinary outside open. Decisions are unchanged.

## [0.9.1] - 2026-10-05

### Security
<!-- WO-127: the macOS 27 fail-open, in user language, no internal references. -->
- The macOS gate failed open on macOS 27 with 0.9.0. The Endpoint Security edge
  crashed on the first open every supervised process makes at startup (a devfs
  node whose device number is negative on that release), the kernel then allowed
  every later read including protected files, no receipt was written, and a run
  whose agent had already finished was reported as normal. The edge now converts
  device numbers without crashing and keys them exactly as the Rust side does,
  flushes the receipt log before it exits, and the supervisor exits non-zero with
  an audit record whenever the edge dies abnormally, even after the agent is
  done. A protected open by a process whose ancestry cannot be established is
  now denied and receipted as `edge-error` instead of being treated as outside
  the supervised tree, and a failed kernel response is receipted and ends the
  run instead of being logged and dropped. An edge that cannot finish writing
  its receipts before it exits now exits non-zero instead of reporting a clean
  run. The hardware seal gains direct-exec,
  `bash -c` and sleep-then-exec shapes against a user-owned `/private/tmp`
  file, repeated, and fails if the edge died, an integrity or `edge-error`
  record appears, the static deny receipt does not name the fixture inode, or
  any piece of evidence could not be read.
<!-- WO-117: the silent fail-open across launches, in user language. -->
- A policy file that changed between runs is no longer honored silently. Each
  run now records a digest of the `Bulwark.toml` it loaded, keyed by the policy
  path (or the directory searched), alongside the existing integrity state. If
  the file for the same project has different contents on the next launch, for
  example because an agent running under the gate rewrote it, that run starts
  tainted with a `policy changed` reason in the audit receipt, exactly like
  inode drift, until an operator reviews the change and runs `bulwark reset`.
  Byte-identical rewrites, first runs, and alternating between projects stay
  clean. `bulwark allow` and `bulwark deny` taint the next run once by design.

### Fixed
<!-- WO-120: the silent-ignore is the bug; name the refusal. -->
- `bulwark ssh --hardened` now refuses `--hivebus-architect-pub` and
  `--hivebus-worker-seed-generate` at argument parsing. Hardened dispatch never
  placed the key material, so the flags were accepted and silently ignored,
  leaving an operator expecting a worker fingerprint or a relayed architect key
  that did not exist.

## [0.9.0] - 2026-10-04

### Security
<!-- WO-114: name the shipped bypass and the fix plainly. -->
- In 0.8.0 and earlier, an agent run with `bulwark ssh --auto deny` and no worker
  flag was dropped to the SSH login user, who owns the consent FIFOs. The remote
  gate applies any well-formed `allow-session` line it reads from the verdict
  lane, so such an agent could grant itself the next protected read by writing to
  that lane. `--auto` runs now require `--auto-worker-uid` or a `--worker-uid`
  other than root and the SSH login user, checked on the remote host before
  anything is deployed or launched.
- `anyhow` bumped to 1.0.103 (RUSTSEC-2026-0190). bulwark never calls the
  affected downcast APIs, so it was not exploitable through bulwark; the bump
  clears the advisory for anyone scanning the binary.

### Changed
<!-- WO-110: make the new interactive refusal and its remedy explicit. -->
<!-- WO-114: --auto is covered by the same refusal. -->
- `bulwark ssh` consent dispatch now refuses to launch without a safe worker
  identity, with or without `--auto`. Use `--auto-worker-uid`, or `--worker-uid`
  with a uid other than root and the SSH login user. Failed or invalid remote
  identity checks also refuse launch. `--hardened` behavior is unchanged.
- CI now builds the static musl Linux gate and asserts its linkage on every pull
  request, not only at release time.

### Fixed
- Refusal messages in the macOS and non-Linux stub builds no longer print a
  truncated `bulwark/.` reference where the explanation belongs.

### Documentation
- Corrected the macOS privilege-drop guidance (`sudo` + `PATH` form), the remote
  consent description, and the platform and `--deploy` lists in the skill
  contract (`docs/SKILL.md`).
- The worker-uid requirement for remote consent is documented in the skill
  contract, `docs/remote.md` and `bulwark ssh --help`.
- The README leads with the enforcement mechanism; remote gate setup is
  described by outcome.

## [0.8.0] - 2026-06-29

### Added
- `bulwark ssh --deploy memfd|shm` streams the static Linux gate over SSH instead of
  requiring remote curl/tar or a writable `/tmp`; `auto` now prefers memfd, then
  `/dev/shm`, then an existing remote binary, then dist as the last resort.
- Release builds now include static musl Linux gates for x86_64 and aarch64, plus
  macOS artifacts for x86_64 and aarch64.

### Changed
- Releases now publish to this repository's own GitHub Releases instead of a
  separate distribution repo; the runtime gate-fetch path and install docs point
  here. The ANCC contract `docs/SKILL.md` now lives in this repo.
- The release workflow now fails if the published release is missing any expected
  target asset or checksum for the tagged CLI version.
- Legacy scp/dist remote deploy paths now tear down their deploy and run
  directories on normal exit and trapped termination.

## [0.7.2] - 2026-06-XX

Security-hardening release. The read gate was put through repeated adversarial review —
attacking the gate, fixing what was found, then attacking the fixes — until two
consecutive rounds found nothing a supervised agent could reach. Around a dozen-and-a-half
issues were closed, each with a regression test that fails on the pre-fix code and passes
on the fixed code, verified on real hardware (Linux kernel 6.12, macOS 26). No CLI behavior
changes for existing users; all changes tighten enforcement or correct fail-open paths.

### Fixed
- **Grants are gated by inode identity, not path.** Allow-list (`--deny-all`) grants are
  snapshotted by `(inode, generation)` at launch, so a foreign file hardlinked, renamed, or
  (via inode-number reuse) swapped into a granted location is denied. macOS grants are
  gated by inode as well, not by path-beneath the grant root.
- **`--protect <dir>` covers nested and post-launch files** under the directory, not only
  the entries present at launch.
- **`--hardened` grants can no longer silently widen.** A grant that would floor a broader
  subtree than its pattern names is rejected; grants must be absolute and may not resolve
  through a symlink in any path component (the prefix is opened with
  `openat2(RESOLVE_NO_SYMLINKS)`).
- **Off-band consent is reparent-proof and live-checked.** The consent channel refuses an
  answerer that is part of the supervised tree (by cgroup membership, not ancestry alone)
  and refuses a peer that has exited before its identity can be verified — so a supervised
  process cannot answer its own consent.
- **Fail-closed corrections.** The fanotify permission queue is unbounded
  (`FAN_UNLIMITED_QUEUE`) so a flood applies backpressure instead of overflowing and failing
  open; an in-tree open whose event-fd `fstat` fails is denied; the worker drop sets
  `PR_SET_NO_NEW_PRIVS` so a dropped process cannot regain root via a setuid binary; the
  remote consent run directory uses an unguessable name and fails closed on a pre-existing
  path or control FIFO.

## [0.7.1] - 2026-06-XX

macOS install becomes zero-setup: the gate ships with the CLI and the CLI finds it
automatically, so `brew install obstalabs/tap/bulwark` gives kernel enforcement, not
just the binary. No CLI behavior changes for existing users; Linux is unchanged.

### Added
- macOS CLI auto-discovers the signed Endpoint Security gate beside its own install
  location (`<bin>/../libexec/bulwark_es_gate.app`, then beside the binary), so no
  `BULWARK_MACOS_ES_GATE` environment variable is needed for a packaged install. The
  variable still works as an explicit override. `bulwark doctor` reports which path it
  resolved.

### Changed
- macOS release tarballs are now self-contained: each bundles the signed, notarized,
  stapled `bulwark_es_gate.app` alongside the CLI. The Homebrew formula installs both;
  the gate no longer has to be fetched or built separately.

### Docs
- New macOS guides: Full Disk Access (why it's required) and troubleshooting, running
  under sudo (and why not passwordless), choosing a mode and wrapping an agent runner,
  and a documentation index.

## [0.7.0] - 2026-06-06

Makes Bulwark agent-operable (ANCC-compliant): an orchestrator agent can read its
contract and apply a read-clamp to a sub-agent programmatically. Adds the
machine-facing surface that requires — and the ratchet that makes it safe.

### Added
- `bulwark init` — write a default `Bulwark.toml` policy in the current directory
  (refuses to overwrite without `--force`).
- `bulwark doctor` — preflight: report whether this host can enforce (OS,
  root/`CAP_SYS_ADMIN`, kernel version, Landlock for `--hardened`). Exit 0 when
  every required capability is present. `--format json`.
- `--format json` on `bulwark audit` (counts + per-decision records) and
  `bulwark check` (the classification as one object) — the agent interface.
- `docs/SKILL.md` (in bulwark-dist): the ANCC agent contract, documenting the
  clamp ratchet — an agent can tighten a clamp freely, but widening or removing
  one routes through off-band consent. An agent can clamp; it cannot un-clamp.

Makes `bulwark ssh` operationally complete: the consent prompt now runs on the
local operator's machine, and the gate binary auto-deploys to a remote host that
does not have it.

### Added
- `bulwark ssh` now runs the consent prompt **on the local operator's machine**
  instead of auto-answering on the remote host. The remote host runs only the
  gate; prompts (host, path, process ancestry) stream back over SSH to a local
  loop, and the operator's `allow-session`/`deny` reply travels back over a
  separate control channel — SSH is transport, the operator UI is local, the
  enforcement point stays remote, and the control lanes stay separate from the
  agent's own stdio. `--auto <verdict>` still answers non-interactively for CI.
- `bulwark ssh --deploy <auto|never|scp|dist>`: auto-deploy the `bulwark` binary
  to a remote host that does not have it. `auto` (default) uses an existing
  remote binary, else scp's the local one when it is arch-compatible, else
  fetches the matching `bulwark-dist` release tarball and verifies its sha256
  before running. `never` requires an existing remote binary; `scp`/`dist` force
  a path. A macOS binary is never scp'd to Linux (the dist path covers the common
  cross-OS case); a checksum mismatch is a hard failure.

## [0.5.0] - 2026-06-05

Adds an integrity circuit-breaker that bounds the blast radius after an unclean
recovery, plus `bulwark reset` to acknowledge and clear a taint.

### Added
- Integrity circuit-breaker: Bulwark records each run's integrity context (a
  generation counter, a clean-shutdown marker, the policy epoch, and the inode
  identity of every protected object) in a persistent state file. On the next
  run it enters **tainted mode** if the prior run ended uncleanly (no
  clean-shutdown marker, e.g. a `SIGKILL` or crash) or if a protected path now
  resolves to a different inode (object-identity drift). A tainted run denies
  protected reads by default and, in socket mode, bypasses the allow-session
  cache so every protected open is freshly decided — no pre-taint grant
  survives. The taint is sticky and persists across restarts until an operator
  acknowledges it; a taint audit receipt (`source: "integrity"`) records the
  reason. This bounds the blast radius after an unclean recovery; it does not
  change the documented fail-open behaviour of a held event at the moment of a
  hard kill.
- `bulwark reset` clears the integrity taint marker after operator review.

## [0.4.0] - 2026-06-05

Adds remote enforcement over SSH — run an agent on a remote host with the gate
on the remote kernel and consent routed to the local operator.

### Added
- Remote enforcement (`bulwark ssh user@host --protect <paths> -- <agent>`):
  run an agent on a remote host with enforcement on the *remote* kernel (SSH is
  only transport) and consent routed back to the local operator. Uses a
  decision/prompt split that respects the kernel deadline: a protected read is
  denied immediately, an async prompt surfaces locally, and an `allow-session`
  reply lets the next read of that inode through from cache. Grants are scoped
  per identity/session/policy-epoch, and prompt/verdict travel on control lanes
  separate from the agent's stdio. Prototype-grade: SSH provides transport/auth,
  not yet an mTLS-signed trust channel; assumes the `bulwark` binary is present
  on the remote host. See `docs/remote.md`.

## [0.3.0] - 2026-06-04

Adds hardened mode — a crash-safe, kernel-enforced read floor via Landlock.

### Added
- Hardened mode (`bulwark run --hardened --allow '<glob>' -- <cmd>`): enforces
  the allowlist as a kernel-level Landlock read floor instead of via the
  fanotify supervisor. Crash-safe — the restriction lives in the kernel on the
  agent process itself, so there is no supervisor to kill and `SIGKILL`/crash
  cannot widen access. Non-interactive; `no_new_privs` also blocks escalation
  around the floor. Requires Landlock (Linux 5.13+). See `docs/hardened-mode.md`.

## [0.2.0] - 2026-06-04

Adds default-deny allowlist mode for CI/CD dispatch, and hardens the gate to
fail closed on graceful shutdown and cover bind-mounted aliases.

### Added
- Default-deny allowlist mode for non-interactive (CI/CD) use:
  `bulwark run --deny-all --allow '<glob>' -- <cmd>` permits the supervised tree
  to read only the granted paths plus a runtime base set, denying every other
  read with no prompt. `bulwark base-set` prints exactly what the base set
  allows. See `docs/ci-allowlist.md` for a ClickHouse-triage worked example and
  CI snippets. Allow-list mode marks every mounted filesystem so default-deny
  holds across separate mounts (tmpfs, data volumes), not just the root.

### Changed
- Gate now marks the whole filesystem (`FAN_MARK_FILESYSTEM`) instead of a
  single mount, so a `mount --bind` alias of a protected inode is gated too.
- Graceful termination fails closed: on `SIGTERM`/`SIGINT`/`SIGHUP`, the
  supervisor denies any outstanding read before exiting. (Hard kills —
  `SIGKILL`, crash, OOM, power loss — remain an inherent fanotify limitation:
  the kernel releases held permission events as allowed on fd close. A
  kernel-enforced floor for that case is planned, not yet shipped.)
- Receipts gained a `shutdown` decision source for reads denied during teardown.

## [0.1.0] - 2026-06-03

First release — the Linux read-gate MVP. Gates file opens by a supervised
process tree at the kernel, by inode, with off-band operator consent. Linux
only; macOS (Endpoint Security) and remote consent are tracked for later.

### Added
- Linux fanotify `FAN_OPEN_PERM` read gate (MVP): `bulwark run --protect <path>
  -- <cmd>` supervises a process tree and denies opens of protected inodes,
  returning `EPERM` to the reader before any bytes are read.
- Inode-based protection (`dev + ino`) that defeats symlink and rename bypass.
- Process-tree attribution from `/proc/<pid>/stat`; only opens by the supervised
  tree are judged.
- Per-decision JSON-line receipts (pid, dev+ino, decision, path, ancestry,
  reason).
- `Bulwark.toml` policy schema (workspace allow globs, protected globs,
  `default.outside_workspace`, `default.on_timeout`) with a shipped default
  profile and a built-in `dev` profile.
- Deterministic glob matcher (`*`, `?`, `**`, `~/` expansion) — no regex
  dependency.
- `bulwark run --profile <name>` / `--policy <file>` to select policy;
  `bulwark allow <glob>` / `bulwark deny <glob>` to mutate it;
  `bulwark audit <receipts>` to render the decision log.
- Off-band interactive consent (`--consent socket`): a protected open is held at
  the kernel while the operator is asked over a Unix socket the agent has no
  descriptor on; `bulwark consent` answers it. Verdicts: allow-once,
  allow-session (inode-cached), deny, deny-forever (persisted to policy).
  Off-band is enforced structurally — `SO_PEERCRED` rejects any answerer inside
  the supervised tree, so an agent cannot approve its own access. Timeout denies
  (kernel-deadline safe). Receipts now record the decision source
  (operator/cache/timeout/static). Policy file name accepted case-insensitively
  (`Bulwark.toml` or `bulwark.toml`).
