<p align="center">
  <img src="assets/brand/readme-banner-bg.png" alt="A diagnostic trace stopped at a repository boundary" width="100%">
</p>

# agent-security

Small, deterministic safety gates for repositories touched by coding agents and automation.

`agent-security` scans outbound repositories, vets inbound code without executing it, trips on known prompt-injection shapes, and adds a local brake to destructive GitHub operations. Every tool prints its boundary. A clean result means no known pattern matched, not that a repository is safe.

[Field notes](docs/field-notes.md) · [Blueprints](docs/blueprints.md) · [Coverage and limits](references/coverage-and-limits.md) · [Security policy](SECURITY.md)

## The five gates

| Gate | Command | Job |
|---|---|---|
| `scan` | `scripts/scan-repo.sh --all` | Finds credential shapes, private context, invisible Unicode, and same-file decode-to-exec patterns before publication. |
| `vet` | `scripts/vet-incoming.sh <path>` | Reads an incoming template, package, plugin, or skill without installing or building it. Returns ADOPT, REVIEW, or REJECT. |
| `scan-content` | `scripts/scan-content.sh <file>` | Flags known instruction-override, exfiltration, credential-solicitation, covert-action, and social-engineering patterns in fetched text. |
| `guard` | `scripts/repo-guard-install.sh --with-hook` | Blocks destructive `gh` repository operations until a human supplies repo-specific confirmation. |
| `harden` | `scripts/harden-check.sh` | Audits token deletion scope, local guard state, organization policy, and branch protection without changing GitHub. |

## Run it

No package install is required. The core scripts need Bash and Git. Python 3 handles Unicode checks, hook parsing, and installer JSON edits.

```sh
# Outbound: inspect every tracked file before publishing.
scripts/scan-repo.sh --all

# Inbound: inspect a clone before any install or build step.
scripts/vet-incoming.sh ./cloned-template

# Untrusted text: use as a tripwire before an agent reads fetched content.
scripts/scan-content.sh fetched-page.txt

# Destructive operations: install the local gh brake and inspect it.
scripts/repo-guard-install.sh --with-hook --setup-path
scripts/repo-guard-install.sh --status

# Capability audit: offline first, then the best-effort GitHub checks.
scripts/harden-check.sh --offline
scripts/harden-check.sh
```

Configuration, removal steps, and private-marker setup live in [the install reference](references/install.md).

## Trust boundary

These scripts are Tier 1 tripwires. They are cheap enough to run early and narrow enough to explain.

- Pattern matching does not prove a secret is live.
- The scanner cannot follow data across files. Use CodeQL or another taint-analysis tool for cross-file decode-to-exec flows.
- `scan-content` is easy to evade with new wording, encoding, translation, or split instructions. Treat fetched content as data and limit agent capabilities.
- The `gh` guard is local. An absolute-path binary or direct API client can bypass it. Removing destructive token permissions and applying server-side policy are the durable controls.
- `harden` reports UNKNOWN when it cannot inspect a capability. UNKNOWN is not a pass.

The complete detection matrix and bypass table are in [coverage and limits](references/coverage-and-limits.md).

## Why these controls exist

The project addresses two recurring failure modes:

1. A trusted-looking scaffold carries hidden execution through build or test configuration.
2. Automation holds enough GitHub authority to delete, transfer, archive, rename, or privatize repositories.

The threat model uses public incidents and primary sources. It does not include private incident data. See [the threat model](references/threat-model.md) and the implementation commentary in [field notes](docs/field-notes.md).

## Development

The test suite is offline and builds its dangerous-looking fixtures inside temporary repositories.

```sh
for test in test-scan test-vet test-harden test-scan-content test-guard self-scan; do
  bash "tests/$test.sh" || exit 1
done

shellcheck -S warning scripts/*.sh scripts/repo-guard/*.sh tests/*.sh
gitleaks git --no-banner --redact .
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a detector or bypass fixture. Security reports belong in a private GitHub advisory, as described in [SECURITY.md](SECURITY.md). General help belongs in [SUPPORT.md](SUPPORT.md).

## Project status

Experimental, maintained on a best-effort basis, and released under the [MIT License](LICENSE). The current release line is `0.1.x`; compatibility promises and release checks are recorded in [RELEASE.md](RELEASE.md).
