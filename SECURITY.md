# Security Policy

Bulwark is a security tool — a kernel-level read gate that runs with privilege. We
take vulnerabilities in it seriously and appreciate reports.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately by one of:

- GitHub **Security Advisories** — "Report a vulnerability" on this repository
  (preferred; keeps the report private until a fix ships), or
- email **contact@obstalabs.dev** with `bulwark security` in the subject.

Include, as far as you can:

- the version (`bulwark --version`) and platform (Linux/macOS, kernel/OS version),
- a description of the issue and its impact (e.g. a protected read that is allowed, a
  way for a supervised process to bypass or disable the gate, a privilege issue),
- steps to reproduce, ideally a minimal proof of concept.

We aim to acknowledge a report within a few business days.

## Scope

Bulwark gates `open()` for protected files in a supervised process tree. The most
relevant classes of report:

- a **protected file is readable** by the supervised tree when it should be denied,
- a supervised process can **disable, kill, or escape** the gate to widen its own
  access,
- a **privilege or signature** issue in how the gate is launched or trusted.

Out of scope (documented limitations, see the README "What Bulwark is NOT"): Bulwark
is not redaction, not a network/exfiltration gate, and does not protect secrets
already inside the allowed workspace or processes not launched under it. Reports that
restate these documented boundaries are not vulnerabilities.

## Supported versions

Bulwark is pre-1.0; fixes land on the latest release line. Please reproduce against
the most recent release before reporting.
