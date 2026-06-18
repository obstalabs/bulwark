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

On macOS, the supervised command runs **as root**. Bulwark's privilege-drop (running
the agent as an unprivileged uid) is currently implemented only on the Linux gate; the
macOS gate execs the agent at the gate's own privilege. That means:

```sh
sudo bulwark run --protect /anything -- bash      # this bash is a ROOT shell
```

So a sudoers rule like `yourname ALL=(ALL) NOPASSWD: /usr/local/bin/bulwark` is
**equivalent to `NOPASSWD: ALL`** — anyone who can run Bulwark passwordless can get a
root shell by passing `-- bash` (or `-- /usr/bin/whatever`). For a security tool, that
is the worst possible footgun: the thing meant to *bound* an agent becomes an
unrestricted path to root.

**Do not add a blanket `NOPASSWD` rule for `bulwark`.** Argument wildcards don't save
you either — the command after `--` is attacker-controlled, so any rule that permits
`bulwark run ... -- <cmd>` permits `-- bash`.

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

That's the real structural fix: an unprivileged-drop for the macOS agent (as the Linux
gate already does with `--worker-uid`). It isn't implemented on macOS yet. Until it is,
treat `sudo bulwark run` as "this runs the child as root" and scope access accordingly.

## Summary

| You want | Do | Don't |
|---|---|---|
| Stop typing the password every command | Raise `timestamp_timeout` | `NOPASSWD: bulwark` (root hole via `-- bash`) |
| Unattended runs | Root launcher / `launchd` daemon, scoped | Passwordless `sudo` |
| Safer `-- bash` | (pending) macOS unprivileged-drop | Assume the child isn't root — on macOS it is |
