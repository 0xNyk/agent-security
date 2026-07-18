---
name: agent-security
description: >-
  Defensive agent supply-chain security for repositories that AI agents and
  automations touch. Use before making a repo public or pushing to one, when
  reviewing a cloned starter template or third-party skill/package, or when an
  agent has GitHub credentials that can delete/rename/transfer/archive repos.
  Ships two battle-tested defenses: (1) scan-repo — a deterministic, network-free
  leak + dropper gate that blocks secrets, obfuscated code-execution droppers,
  invisible-unicode, and private-context leaks from entering a public repo; and
  (2) repo-guard — a PATH shim + Claude Code hook that hard-blocks destructive
  GitHub repo-lifecycle operations unless a human confirms the exact repo. Verbs:
  scan, guard-install, guard-status. Defensive use only — not an attacker toolkit.
metadata:
  version: "0.1.0"
---

# agent-security

Two focused, honest defenses distilled from real 2026 incidents: a starter-template
**dropper** (obfuscated code-execution smuggled through a poisoned scaffold) and an
**automation that destroyed a project's repositories and their accumulated stars**.
This skill ships a Tier-1 answer to each. Neither is a complete security program —
every claim of protection states its boundary. Read `references/coverage-and-limits.md`
before you rely on either.

**Defensive framing only.** This skill detects and blocks; it does not generate,
obfuscate, or deliver payloads. The dropper fixtures are inert documentation examples.

## Progressive disclosure

| Level | Load |
|---|---|
| L1 | This file's YAML only (always) |
| L2 | This body when the skill triggers |
| L3 | `references/*`, `scripts/*` **on demand** |

- Before trusting a result: `references/coverage-and-limits.md` (what it does and does NOT catch).
- Threat background + cited public sources: `references/threat-model.md`.
- Install/uninstall detail: `references/install.md`.

## When this triggers

- Making a repository public, or pushing a changeset to a public repo.
- Reviewing a cloned starter template, third-party skill, plugin, MCP server, or package.
- An agent/automation holds GitHub credentials that can perform repo-lifecycle operations.
- Auditing build/test config, git hooks, CI YAML, or editor/agent config for hidden execution.

## Verbs

### `scan` — leak + dropper gate

Deterministic, network-free. Run from the target repo root. CRITICAL findings
(secrets, droppers, invisible-unicode) always fail; MAJOR (paths/infra/personal/marker)
can be downgraded with `--warn-only` or cleared per-line with `--allow`.

```sh
scripts/scan-repo.sh              # staged changeset (default)
scripts/scan-repo.sh --all        # every tracked file (pre-publish sweep)
scripts/scan-repo.sh --ref main..HEAD
scripts/scan-repo.sh --all --allow 'docs/example\.md:'   # named exception
```

Optional user-owned private markers (repo/venture/product names, private path
fragments) live in a **local** file that never ships: see
`private-markers.example.txt` and `references/install.md`.

### `guard-install` — repository-lifecycle guard

Blocks `gh repo delete|rename|transfer|archive` and privatize, plus the equivalent
`gh api`/graphql mutations, unless `REPO_LIFECYCLE_OK` names the exact repo. Normal
gh usage passes through unchanged.

```sh
scripts/repo-guard-install.sh                 # PATH shim (Layer 1)
scripts/repo-guard-install.sh --with-hook     # + Claude Code PreToolUse hook (Layer 3)
scripts/repo-guard-install.sh --with-hook --setup-path --dry-run   # preview
```

### `guard-status`

```sh
scripts/repo-guard-install.sh --status        # is gh resolving to the guard? is the hook registered?
scripts/repo-guard-install.sh --uninstall     # remove shim + hook
```

## Operating principles

1. **Honesty over coverage.** Overclaiming is a liability. Both tools are Tier-1: cheap,
   deterministic, first-line. They do not replace gitleaks/TruffleHog/Semgrep/CodeQL/GitHub
   push protection/org security. The scanner is **same-file only** and cannot see a
   cross-file dropper — this is documented, not hidden.
2. **Precision over recall.** A noisy gate gets disabled. Never flag a lone `eval`, a lone
   base64 blob, a lone config, or a lone hook. Require capability + indicator co-occurrence.
3. **Confirm the exact target.** Destructive repo ops require naming the specific
   `owner/repo` — a blanket "are you sure?" trains reflexive approval.
4. **Private markers stay local.** The scanner ships generic detection only. Your private
   names are a local-config concern (`private-markers.txt`), never shipped.

## Tests

```sh
bash tests/test-scan.sh    # scanner fixtures (dropper/secret/clean/allow/markers/unicode)
bash tests/test-guard.sh   # guard fixtures — offline, fake gh, no real GitHub call
```
