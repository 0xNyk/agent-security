# Security policy

## What this project is

`agent-security` is a **defensive** skill/toolkit: shell scanners and a local
`gh` guard. It runs no network service and collects no data. It is meant to be
run by a repository owner on their own machine and repos.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older minors | Best effort |

## Reporting a vulnerability

If you find a security issue — a **detection bypass** (a real dropper/secret the
scanner should catch but misses), a **guard bypass** beyond the ones already
documented in `references/coverage-and-limits.md`, or a way this tool could
**leak** what it is meant to protect — report it **privately** to the maintainer
via GitHub (Security Advisories or direct message), not a public issue.

Acknowledgement and remediation are best effort; no response SLA is promised.
Do not open a public issue for an exploitable bypass until a fix is available.

## Known limitations (not vulnerabilities)

These are documented boundaries, not bugs — see `references/coverage-and-limits.md`:

- The scanner is **same-file only**; it cannot detect a cross-file dropper
  (payload split across `.env` + config). Use Semgrep/CodeQL taint analysis for that.
- The repo-guard **PATH shim** is bypassed by calling the real `gh` at an absolute
  path outside a Claude Code session; `curl` against the REST API is out of scope.
  It is a local per-machine brake, not organization policy.
- This is **not a replacement** for gitleaks, TruffleHog, Semgrep, CodeQL, GitHub
  push protection, or an organization's security controls. Use it alongside them.

## Scope

**In scope:** scanner detection logic, the guard scripts, the installer, and any
path in this repo that could execute code or leak data on a user's machine.

**Out of scope:** the user's own private marker file (never shipped), third-party
tools this composes with, and the inherent limits listed above.
