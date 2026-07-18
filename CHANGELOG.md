# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## 0.1.0

First public release. Five deterministic, defensive Tier-1 gates, each with a documented
boundary:

- **vet** (`vet-incoming.sh`) — inbound supply-chain gate: vets a third-party
  template / package / plugin / skill *before* adoption. Scan-only; never runs
  install/build/postinstall. Emits ADOPT / REVIEW / REJECT.
- **scan** (`scan-repo.sh`) — network-free leak + dropper gate over your own repo before
  publish/push: secrets, same-file decode-then-exec droppers, invisible/bidi unicode, and
  private-context leaks.
- **scan-content** (`scan-content.sh`) — same-file tripwire for untrusted fetched content
  (web/search/tool/MCP output, pasted text): known prompt-injection and social-engineering
  shapes. Paired with the behavioral contract in `references/untrusted-content.md`.
- **guard** (`repo-guard-install.sh`) — local `gh` PATH shim + optional Claude Code
  PreToolUse hook that blocks destructive repo-lifecycle ops (delete / rename / transfer /
  privatize / archive) unless a human names the exact repo. Includes `--status` and
  `--uninstall`.
- **harden** (`harden-check.sh`) — read-only audit of the real destructive-capability
  surface: token `delete_repo` scope, org deletion/transfer restrictions, branch
  protection. Reports a three-state token verdict — HIGH (has `delete_repo`), OK (does
  not), or DEGRADED/UNKNOWN when the scope cannot be verified in this context — and never
  reports an unverifiable check as a benign pass.

Ships with offline fixture test suites for every capability plus a self-scan, an offline
CI workflow (actions pinned to commit SHAs), and honest coverage/limits documentation.
