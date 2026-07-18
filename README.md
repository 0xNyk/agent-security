# agent-security

Two focused, deterministic defenses for repositories that AI agents and automations
touch — with honest boundaries on every claim.

- **`scan-repo`** — a network-free leak + dropper gate. Blocks secrets, obfuscated
  code-execution droppers, invisible/obfuscating unicode, and private-context leaks
  from entering a repo you are about to publish or push.
- **`repo-guard`** — a `gh` PATH shim plus an optional Claude Code hook that hard-block
  destructive GitHub repo-lifecycle operations (delete / rename / transfer / privatize /
  archive) unless a human confirms the *exact* repository. Normal gh usage is untouched.

This is **v0.1**: focused, tested, and deliberately narrow. It is a set of Tier-1 gates,
not a security program. **Defensive use only** — it detects and blocks; it does not
generate, obfuscate, or deliver anything.

## Why it exists — two real incidents

1. **A starter-template dropper.** A poisoned scaffold shipped an obfuscated
   code-execution payload: a base64 string in a committed `.env`, decoded and executed by
   a separate build/test config, invisible to registry scanners because a git-cloned
   template has no registry provenance at all. `scan-repo` catches the same-file shapes of
   this class — and is explicit about the cross-file split it cannot see.
2. **Repository destruction by automation.** An automation with GitHub credentials
   performed destructive repo-lifecycle operations across public repositories and wiped out
   thousands of accumulated stars before a human could intervene. `repo-guard` turns that
   one-command catastrophe into a deliberate, per-repo human act.

Both incidents are described generically here. The threat background cites **public**
primary sources (xz-utils CVE-2024-3094, Shai-Hulud, Nx/s1ngularity, GlassWorm,
tj-actions CVE-2025-30066, OWASP LLM Top 10) — see `references/threat-model.md`.

## Install

```sh
# Scanner — no install; run from your repo root
scripts/scan-repo.sh --all

# Guard — PATH shim, optionally the Claude hook and PATH setup
scripts/repo-guard-install.sh --with-hook --setup-path
scripts/repo-guard-install.sh --status
```

Requires `bash`, `git`, and `python3` (the invisible-unicode class, the hook, and the
installer's JSON merge use python3). Full detail, private-marker setup, and removal:
`references/install.md`.

## Honest coverage summary

**`scan-repo` catches:** private-key blocks and known token shapes; secret assignments and
`*_SECRET/*_TOKEN=` env lines; connection strings, JWTs, cookies; same-file droppers
(decode encoder + exec sink co-occurring); base64 blobs under env keys in committed `.env`;
invisible/bidi/PUA/variation-selector unicode; personal home paths, private IPs, internal
hostnames, real emails/phones; and optional user-defined private markers.

**`repo-guard` blocks:** `gh repo delete|rename|transfer|archive`, `edit --visibility
private|internal`, and the equivalent `gh api`/graphql mutations — unless
`REPO_LIFECYCLE_OK` names the exact repo.

## When NOT to use this / what it does not cover

- **Not a replacement** for gitleaks, TruffleHog, Semgrep, CodeQL, GitHub secret scanning /
  push protection, org-level repo-deletion restrictions, or a real security program. Run it
  *alongside* those, as a fast first line.
- **`scan-repo` is same-file only.** It **cannot** detect a cross-file dropper (decode in
  one file, exec sink in another) — the exact shape of the motivating incident. That needs
  AST/dataflow taint (Semgrep Pro / CodeQL). It also will not catch novel encoders / custom
  alphabets, minified/vendored/WASM payloads, steganographic carriers, remote second stages,
  or verified-live secrets (it matches *shapes*, it does not call the provider).
- **`repo-guard` has a known bypass.** A tool calling the real `gh` by **absolute path**
  outside a Claude session skips the PATH shim; a plain terminal doing the same is not
  covered; `curl` against the REST API is out of scope. It targets *accidental / automated*
  destruction, not a determined operator, and it is a local per-machine brake — **not**
  server-side org policy.
- **Don't** treat a clean scan or an installed guard as permission to skip review, least
  privilege, credential rotation, or org-level protections.

The full block lists, the same-file limitation, and the bypass matrix are in
`references/coverage-and-limits.md`. Read it before you trust either tool.

## Defensive use only

This project exists to **detect and prevent** supply-chain compromise and accidental repo
destruction. The dropper patterns are detection signatures and the fixtures are inert
documentation examples. Do not repurpose any of it to build, obfuscate, or deliver a
payload.

## License

MIT — see `LICENSE`.
