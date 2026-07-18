# Vetting inbound code — the "never scaffold from / install unvetted code" contract

`scan-repo.sh` gates **outbound** content (yours, before you publish). This contract governs
**inbound** content: a third-party starter template, dependency, plugin, skill, or MCP server,
**before** you adopt it. Inbound is the vector behind one of the two real 2026 incidents this
skill exists for. Tool: `scripts/vet-incoming.sh` (**scan only — it never runs install/build/
postinstall**).

## Case study — the poisoned starter template

A project was scaffolded from a cloned starter template that carried an obfuscated RCE dropper:
`atob(process.env.…)` decoding a base64 URL, feeding `eval(await (await fetch(u)).text())` — an
**encoder + network fetcher + dynamic-exec sink** parked in the **vite/vitest build config**,
exactly where a scaffold gets skim-trusted. A git-cloned template has **no registry provenance**,
so registry scanners (`npm audit`, dependency-graph tools) never see it. It was caught on
**manual review of the template's always-read surfaces** before any install/build ran. The
lesson: treat every cloned template/skill/package as a supply-chain input and vet it *before* the
first `npm install` or `dev` command.

## The standing rule

> **Never scaffold from, or `npm/pnpm install` in, unvetted third-party code.** Run
> `scripts/vet-incoming.sh <path|--url>` first. At minimum, before scaffolding from any
> template, grep it for the dropper shape:
>
> ```sh
> grep -rnE 'atob\(process\.env|eval[[:space:]]*\(|new[[:space:]]+Function|child_process' \
>   --include='*.config.*' --include='vite*' --include='vitest*' --include='*.js' --include='*.ts' .
> ```
>
> Install with **`npm install --ignore-scripts`** and review lifecycle scripts by hand. Adopt
> the code only after the vet verdict is ADOPT (or REVIEW with the flagged items understood).

## Pre-adoption checklist (what `vet-incoming.sh` automates, plus the human parts)

1. **Never execute to inspect.** Clone/copy and *read*. `vet-incoming.sh --url` shallow-clones
   with hooks disabled and scans; it never runs the target.
2. **Install-time lifecycle scripts** (`preinstall`/`install`/`postinstall`/`prepare`/…) in
   every `package.json` — these run arbitrary code on `npm/pnpm install` (the postinstall
   attack, e.g. the Shai-Hulud worm class). If present: `--ignore-scripts` and read each one.
3. **Build/test/config files** (`vite`/`vitest`/`webpack`/`rollup`/`jest`/`*.config.*`, test
   setup) for exec+decode+fetch shapes — the starter-template vector. And any committed `.env*`
   for a base64 blob under an env key (the dropper URL carrier).
4. **Committed git hooks** (`.husky/*`, scripts that set `core.hooksPath` or write `.git/hooks`)
   — fire on git operations after adoption.
5. **CI workflows** (`.github/workflows`) for `curl|bash`, net→interpreter pipes, `eval`,
   **mutable/unpinned action refs** (`uses: x@main`), and secret-with-network exfil shapes.
6. **Editor autorun** (`.vscode/tasks.json` `runOn: folderOpen`, devcontainer
   `postCreate/postStart` commands) — code that runs just from opening the folder.
7. **Obfuscated / minified** code carrying `eval`/`Function` — review or reject; treat vendored
   `*.min.js` as opaque.
8. **Human diff of the always-read surfaces** even on ADOPT — the scanner catches KNOWN shapes
   only.

## Third-party skills / MCP servers (adjacent admission path)

A skill, plugin, or MCP server is inbound code with *more* privilege than a library — it can
shape the agent's behavior and hold tool/credential access. Vet the repo with `vet-incoming.sh`,
then apply a trust/scoping review: read every lifecycle hook, scope MCP tool access to least
privilege, and red-team the skill/MCP before granting it access. Treat third-party prompts,
skills, plugins, MCP servers, packages, install scripts, and lifecycle hooks as **supply-chain
inputs requiring review**; keep package lifecycle scripts restricted unless a reviewed dependency
specifically needs them.

## Honest limits (read before trusting a verdict)

- **KNOWN patterns only, trivially evadable.** Rename, encode, translate, split across files, or
  minify the payload and the regex sees nothing — same evasion story as `scan-repo.sh`. Cross-file
  droppers (decode in one file, exec in another) are out of a same-file gate's reach.
- **Not a replacement** for Socket / Snyk / `npm audit` (registry/dependency graph), Semgrep /
  CodeQL (dataflow taint), or sandbox detonation with egress observation. `vet-incoming.sh` is a
  Tier-1 pre-adoption tripwire that raises the cost of the common shapes.
- **A clean ADOPT is not proof of safety** — it means no known adoption red flag matched. Still
  read the code, still prefer `--ignore-scripts`, still detonate anything high-value in a sandbox.
- **Scan-only cannot catch a runtime-only payload** that reveals itself only when executed — which
  is exactly why the rule is *vet before install*, not *install then watch*.

See `coverage-and-limits.md` for the shared engine's detection classes and boundaries, and
`threat-model.md` for the dropper taxonomy this builds on.
