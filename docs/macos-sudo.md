# macOS: running Bulwark under sudo (and why not passwordless)

Bulwark's macOS gate needs to run as **root** — Endpoint Security clients must be
privileged, so `bulwark run` is invoked with `sudo`. A natural next thought is "let me
make it passwordless so I stop typing my password." **Don't** — for this tool that
opens a root-shell hole. Here's the full picture so you can make an informed choice.

## Why root is required

macOS only lets a privileged process create an Endpoint Security client
(`es_new_client`) and subscribe to `AUTH_OPEN` — the event Bulwark answers to allow or
deny a file open. This is Apple's rule for the ES API, not a Bulwark design choice. So
you run `sudo bulwark run ...`. (You also need Full Disk Access for the launching
terminal — see [docs/macos-permissions.md](macos-permissions.md).)

## Why **not** passwordless sudo (`NOPASSWD`) — the important part

On macOS, `sudo bulwark run` drops a would-be-root agent to the invoking user
(`SUDO_UID`/`SUDO_GID`) by default, without a warning. `--worker-uid <uid>` selects an
explicit unprivileged uid; `--allow-root` deliberately keeps the agent at uid 0.
Genuine root with no sudo origin has no invoking user to drop to, so Bulwark prints
a loud `WARNING` and runs the agent at uid 0.

The default drop makes ordinary launches safer, but a blanket passwordless rule
still exposes a root shell:

```sh
sudo bulwark run --allow-root --protect /anything -- bash  # this bash is a ROOT shell
```

So a sudoers rule like `yourname ALL=(ALL) NOPASSWD: /usr/local/bin/bulwark` is
**equivalent to `NOPASSWD: ALL`** — anyone who can run Bulwark passwordless can get a
root shell by passing `--allow-root -- bash` (or `--allow-root -- /usr/bin/whatever`).
For a security tool, that is the worst possible footgun: the thing meant to *bound*
an agent becomes an unrestricted path to root.

Even without `--allow-root`, the macOS drop is not irreversible: a setuid-root
binary on the agent's path can regain root. See [docs/macos.md](macos.md#crash-posture-honest-limitation)
for this residual.

**Do not add a blanket `NOPASSWD` rule for `bulwark`.** Argument wildcards don't save
you either — the command after `--` is attacker-controlled, and permitting
`--allow-root` lets that command be a root shell. Omitting `--allow-root` still
leaves the macOS setuid-root residual above.

## What to do instead

### Just want to stop re-typing your password during a session?

Use sudo's normal timestamp — authenticate once, and subsequent `sudo` calls in the
same terminal are free for a few minutes. Optionally raise the window:

```sh
# /etc/sudoers.d/timestamp   (edit with `sudo visudo -f /etc/sudoers.d/timestamp`)
Defaults timestamp_timeout=30
```

This keeps the password requirement (so `-- bash` still needs auth) while removing the
repeat-typing friction. It does **not** create a passwordless path to root.

### Running Bulwark unattended (CI, a dispatcher, a scheduled job)?

Don't reach for passwordless sudo at all. Run the **launcher itself as root** from a
privileged context — a root-owned CI runner, or a `launchd` daemon (`LaunchDaemon`,
which starts as root with no interactive `sudo`). The privilege then lives in one
scoped, auditable place instead of a `NOPASSWD` rule any local user can exploit, and
Full Disk Access is granted once to that daemon's binary rather than fighting
`sudo`'s TCC attribution.

> Note: the `launchd` + Endpoint Security + TCC combination has its own setup details
> (FDA must attach to the daemon's executable), and you should prove it on your
> hardware before relying on it. The point here is only the *direction*: scoped root in
> a daemon, never a passwordless `sudo` rule for `bulwark`.

### Want `-- bash` to stop being a root shell?

That drop is now the default under sudo: the macOS gate runs the agent as the
invoking user. An explicit `--worker-uid <uid>` chooses another unprivileged uid;
`--allow-root` opts out of the default drop. The setuid-root residual above still
applies, so the macOS drop is not an irreversible privilege boundary.

## Summary

| You want | Do | Don't |
|---|---|---|
| Stop typing the password every command | Raise `timestamp_timeout` | `NOPASSWD: bulwark` (root hole via `--allow-root -- bash`) |
| Unattended runs | Root launcher / `launchd` daemon, scoped | Passwordless `sudo` |
| Safer `-- bash` | Keep the default sudo drop to `SUDO_UID`, or use `--worker-uid` | Treat the macOS drop as irreversible; setuid-root can regain root |
