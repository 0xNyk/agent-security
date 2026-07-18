# agent-security

Deterministic, defensive gates for repositories that AI agents and automations touch —
with an honest boundary printed on every claim.

It ships five small, tested tools: a pre-publish leak/dropper scanner, an inbound
supply-chain vetter, an untrusted-content tripwire, a local guard against destructive
`gh` repo-lifecycle operations, and a read-only audit of the capability that actually
lets a token destroy repos. Each one is a **Tier-1 gate** — cheap, deterministic, run
first — not a security program, and none of them overclaims.

**Defensive use only.** These tools detect and block; they do not generate, obfuscate,
or deliver anything. The dropper "fixtures" are inert documentation examples.

## Capabilities

| Capability | Verb | What it does |
|---|---|---|
| **vet** | `vet` | Vets an **inbound** third-party template / package / plugin / skill *before* you adopt it — the poisoned-scaffold vector. Scan-only: it never runs install/build/postinstall. Emits ADOPT / REVIEW / REJECT. |
| **scan** | `scan` | Network-free leak + dropper gate over **your** repo before you publish or push. Blocks secrets, same-file decode-then-exec droppers, invisible/bidi unicode, and private-context leaks. |
| **scan-content** | `scan-content` | Same-file **tripwire** for **untrusted fetched content** (web-search results, fetched pages, tool/MCP output, pasted text). Flags known prompt-injection and social-engineering shapes. Detection only — see limits. |
| **guard** | `guard-install` · `--status` | Local `gh` PATH shim (+ optional Claude Code hook) that blocks destructive repo-lifecycle ops — delete / rename / transfer / privatize / archive — unless a human names the **exact** repo. Normal `gh` usage is untouched. |
| **harden** | `harden` | Read-only audit of the **real** destructive-capability surface: does the active token carry `delete_repo`, are org deletion/transfer restrictions on, is the default branch protected. Audits and guides — **you** apply the GitHub-side fixes. |

## Why it exists — two incidents (described generically)

1. **A poisoned starter template.** A cloned scaffold shipped an obfuscated
   code-execution dropper: an encoded payload committed in one file, decoded and
   executed by a separate build/test config — invisible to registry scanners because a
   git-cloned template has no registry provenance at all. `vet` gates that class *before*
   adoption; `scan` catches its same-file shape, and both are explicit about the
   cross-file split they cannot see.
2. **Repository destruction by automation.** An automation holding GitHub credentials
   ran destructive repo-lifecycle operations across public repositories and wiped out
   thousands of accumulated stars before a human could intervene. `guard` turns that
   one-command catastrophe into a deliberate, per-repo human act; `harden` audits the
   token scope and org policy that would have made it impossible in the first place.

The threat background cites **public** primary sources (xz-utils CVE-2024-3094,
Shai-Hulud, Nx/s1ngularity, GlassWorm, tj-actions CVE-2025-30066, OWASP LLM Top 10) —
see `references/threat-model.md`.

## Install / quickstart

```sh
# scan — pre-publish leak/dropper sweep (no install; run from your repo root)
scripts/scan-repo.sh --all

# vet — check an inbound template/package BEFORE you adopt it (never installs it)
scripts/vet-incoming.sh ./cloned-template
scripts/vet-incoming.sh --url https://github.com/owner/starter

# scan-content — tripwire on untrusted fetched content
scripts/scan-content.sh fetched.txt
fetch ... | scripts/scan-content.sh

# guard — install the gh shim (+ optional Claude hook), then check status
scripts/repo-guard-install.sh --with-hook --setup-path
scripts/repo-guard-install.sh --status

# harden — audit the destructive-capability surface (read-only)
scripts/harden-check.sh --offline        # token scope + local guard, no network
scripts/harden-check.sh                   # + org policy + branch protection
```

Requires `bash`, `git`, and `python3` (the invisible-unicode class, the Claude hook, and
the installer's JSON merge use python3). Full detail, private-marker setup, and removal:
`references/install.md`.

## What this does NOT do / when NOT to rely on it

Read this before you trust any result. A security tool that overclaims is worse than none.

- **Not a replacement** for gitleaks, TruffleHog, Socket, Snyk, Semgrep, CodeQL, GitHub
  secret scanning / push protection, or org-level security policy. Run these gates
  *alongside* those, as a fast first line — never instead of them.
- **The scanners are same-file tripwires.** `scan` and `vet` match *shapes* in a single
  file. They **cannot** see a cross-file dropper (decode in one file, exec sink in
  another) — the exact shape of the motivating incident — nor novel encoders, custom
  alphabets, minified/vendored/WASM payloads, steganographic carriers, remote second
  stages, or verified-live secrets (they match patterns; they never call the provider). A
  clean result means "no known pattern matched," **not** "safe." Cross-file dropper
  detection needs AST/dataflow taint (Semgrep Pro / CodeQL).
- **Prompt injection is unsolved, and `scan-content` does not solve it.** It catches a
  fixed set of **known** injection / social-engineering patterns and is **trivially
  evaded** by novel phrasing, encoding, translation, paraphrase, or splitting a payload
  across lines. It is a **tripwire, not a filter**: a hit means "a human should look"; a
  CLEAN result means "no known pattern matched," not "safe." The load-bearing defense is
  the behavioral contract in `references/untrusted-content.md` (treat fetched content as
  data; break the lethal trifecta; Rule of Two; human gate before acting on discovered
  instructions) plus architectural capability limits — which this skill **guides but
  cannot enforce**.
- **The guard is a local brake with known bypasses.** It stops interactive and
  PATH-resolved destruction. It is **bypassed** by calling the real `gh` at an absolute
  path outside a Claude session, and by `curl`/octokit against the REST API. It reduces
  *accidental / automated* destruction; it is **not** a determined-operator control and
  **not** server-side org policy.
- **`harden` audits — it does not fix.** It never changes your token or org settings.
  The durable prevention (mint an automation token **without** `delete_repo`, turn on
  org deletion/transfer restrictions, protect default branches) is a **GitHub-side action
  you must apply yourself**, some of it requiring org-admin. When `harden` cannot verify
  a check (e.g. the token scope is unreadable in a sandboxed/keyring-locked context) it
  reports **DEGRADED (exit 3)**, never a pass — do not read an unverifiable run as clear.
- **Don't** treat a clean scan, an installed guard, or a green harden run as permission
  to skip code review, least privilege, credential rotation, or org-level protections.

The full block lists, the same-file limitation, and the bypass matrix are in
`references/coverage-and-limits.md`.

## Defensive use only

This project exists to **detect and prevent** supply-chain compromise and accidental repo
destruction. The dropper patterns are detection signatures and the fixtures are inert
documentation examples. Do not repurpose any of it to build, obfuscate, or deliver a
payload. See `CONTRIBUTING.md` — offensive tooling and un-paired detection bypasses are
declined.

## Project

- **Security policy & reporting:** [`SECURITY.md`](SECURITY.md) — report bypasses privately.
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md) — defensive-only, no overclaiming, no real data.
- **Changelog:** [`CHANGELOG.md`](CHANGELOG.md).
- **Releasing:** [`RELEASE.md`](RELEASE.md).
- **Coverage & limits:** [`references/coverage-and-limits.md`](references/coverage-and-limits.md).

## License

MIT — see [`LICENSE`](LICENSE).
