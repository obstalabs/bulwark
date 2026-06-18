# Bulwark documentation

A map of these docs. Start with the [main README](../README.md) for what Bulwark is
and a ten-second demo; come here for depth.

## Using Bulwark

- **[Choosing a mode + wrapping an agent runner](modes-and-wrapping.md)** — deny-list
  (`--protect`) vs allow-list (`--deny-all`), which fits when, and how to confine an
  agent launcher.
- **[CI allow-list mode](ci-allowlist.md)** — default-deny for unattended/CI jobs.
- **[Hardened mode](hardened-mode.md)** — the crash-safe Landlock floor (Linux).
- **[Off-band consent](offband-consent.md)** — answering protected opens over a socket.
- **[Policy & receipts](policy-receipts.md)** — the policy model and the decision log.

## macOS

- **[macOS quickstart](macos.md)** — the macOS entry point (build/run, crash posture).
- **[Permissions & troubleshooting](macos-permissions.md)** — Full Disk Access (why),
  gate wiring, and the common setup errors. Read this first if something doesn't work.
- **[Running under sudo](macos-sudo.md)** — why root, and why **not** passwordless.
- **[Behavior matrix](macos-behavior-matrix.md)** — macOS vs Linux support at a glance.

## Remote

- **[Remote enforcement](remote.md)** — `bulwark ssh`: gate on another host's kernel,
  with local operator consent.

## Background & evidence

- **[Adopt vs build](adopt-vs-build.md)** — why Bulwark exists rather than wrapping an
  existing tool.
- **[VM evidence](vm-evidence.md)** — the gate proven against a live kernel.
