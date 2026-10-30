# Coverage and limits

This document is brutally honest on purpose. A security tool that overclaims is a
liability: it buys false confidence, which is worse than no tool. Read it before you
trust either component. Every protection here states its boundary.

**Neither component is a replacement for gitleaks, TruffleHog, Semgrep, CodeQL, GitHub
push protection, org-level branch/tag protection, or a real security program.** They are
cheap, deterministic, first-line gates that impose cost on the common cases and are honest
about the rest.

---

## `scan-repo.sh` — the leak + dropper gate

### What it catches

| Class | Severity | What it flags |
|---|---|---|
| `SECRET` | CRITICAL | Private-key blocks; known token shapes (`sk_live`, `ghp_`, `github_pat_`, `xox*`, `AKIA…`, `glpat-`, `AIza…`); `key/secret/token/password = "…"` assignments; `*_SECRET/*_TOKEN=` env lines; `scheme://user:pass@host` connection strings; JWTs; `Set-Cookie` values. Placeholder-shaped values are excluded. |
| `DROPPER` | CRITICAL | An exec **sink** (`eval` / `new Function` / `vm.*` / dynamic `import` / `child_process`; Python `exec`/`compile`/`__import__`; PowerShell `IEX`/`-EncodedCommand`) co-occurring **in the same file** with a decode **encoder** (base64/hex/charCode/`\x`·`\u` runs/reverse/XOR) or a network fetcher; fetch-then-exec shapes; decode-of-env/argv reaching a sink; a base64 blob under an env-var key in a committed `.env`. |
| `INVISIBLE_UNICODE` | CRITICAL | Zero-width, bidi, PUA, tag, and supplementary variation-selector codepoints that hide executable text (the GlassWorm class). BMP variation selectors (U+FE0F) are excluded — emoji use them. |
| `PATH` | MAJOR | Personal home paths (`/Users/<name>`, `/home/<name>`, Windows profile paths); `~/.ssh`, `~/.aws` references; hardcoded personal workspace roots (`$HOME/dev/…`, `~/projects/…`, `~/src/…`). Neutral placeholders (`example`, `you`, `runner`, …) and ordinary `$HOME` dot-directories (`$HOME/.config`, `$HOME/.cache`) are excluded. |
| `INFRA` | MAJOR | RFC-1918 private IPs; `*.internal`/`.intranet`/`.lan`/`.corp` hostnames; concrete `ssh user@host` destinations. |
| `PERSONAL` | MAJOR | Real-looking emails (excluding `example`/`test`/`noreply` and your own git-identity email) and phone numbers. |
| `MARKER` | MAJOR | Fixed strings you list in your **local** marker file (`[names]`, `[paths]`). Never shipped; see `private-markers.example.txt`. |

CRITICAL always fails and cannot be downgraded by `--warn-only`. MAJOR can be downgraded
with `--warn-only` (report without failing) or cleared per-line with `--allow '<ere>'`.

### What it does NOT catch — the honest boundaries

- **Cross-file droppers.** This is a **same-file regex gate by design.** The motivating
  incident split its payload across files — a base64 URL in a committed `.env`, decoded and
  executed by a *separate* build/test config. **A single-file pattern cannot bridge that
  split, and this gate does not fake it.** The `ENVB64` rule flags the `.env` carrier in
  isolation, and the config-side decode→exec is caught only when both stages share a file.
  Closing the config↔`.env` gap is a Tier-2 job: AST/dataflow taint that follows a decode
  source to an exec sink **across** files (Semgrep Pro / CodeQL). State the boundary; do not
  pretend the regex closed it.
- **Private context that does not look like a path.** The `PATH` class catches personal
  home and workspace roots by shape. It cannot know that a *name* is private — a sibling
  repository, an internal service, a codename — because that knowledge is local to you.
  That is the entire purpose of the marker file, and with no marker file configured the
  gate says so and runs the generic layer only. If your release process depends on
  catching private names, configure markers; do not rely on the shape rules.
- **Novel encoders / custom alphabets / heavy obfuscation.** Every regex family has a
  documented evasion (Lazarus HexEval vs regex; custom-alphabet base64 vs entropy; GlassWorm
  vs token scanners). This gate raises the cost of the common shapes; it is not a proof.
- **Compiled, minified, vendored, or WASM payloads.** Binary and skip-scanned paths are not
  inspected for dropper shapes.
- **Steganographic carriers** (image bytes / EXIF / LSB) and **remote second stages** that
  only reveal themselves at runtime — those need sandbox detonation, not static regex.
- **Verified-live secrets.** It matches credential *shapes*; it does not call the provider to
  confirm a secret is live (that is TruffleHog's job). Run it *alongside* a verifying scanner
  and GitHub push protection, not instead of them.
- **Semantic secrets** with no recognizable shape (a plain high-value string with no
  key/entropy signature) can slip the `SECRET` class.

### Deliberate design choices

- **Precision over recall.** A noisy gate gets disabled — the worst outcome. It never flags a
  lone `eval`, a lone base64 blob, a lone build config, or a lone git hook. It requires
  capability + indicator co-occurrence before a DROPPER finding counts.
- **`--allow` is a named, reviewable exception**, not a silent path skip. Use it for a
  specific defensive-example line (e.g. a documented inert dropper fixture) and record why.
- **The marker layer is optional and user-owned.** With no marker file, the generic layer
  still runs and warns once. Your private names never enter this repository.

### Scanning this repository itself

A security tool that ships attack signatures and inert fixtures will trip a naive
same-file scanner — that is expected, not a leak. `scan-repo.sh` self-skips its own
source and test file. The two **taxonomy docs** (`threat-model.md`, this file) list
encoder and exec-sink token names side by side, which a same-file gate cannot tell
apart from a payload, so it flags those specific documentation lines. We do **not**
hardcode these doc paths into the generic scanner (an adopter copying it would then
blind-spot files of the same name); instead `tests/self-scan.sh` allows those exact
lines, documented, and asserts a clean exit. Run it to prove the repo is clean under
its own tool:

```sh
bash tests/self-scan.sh   # CLEAN — no leak or dropper findings
```

The only allowances are three lines of documentation (the class table's sink row, the
threat-model Sink axis, and a `/Users/<name>` *example* in the PATH-class row). No
secret, no marker, no real personal data, and no invisible-unicode is ever allowed.

### Recommended layering

1. **Tier 1 — every commit (this tool):** deterministic, network-free regex. Pre-commit hook
   or `--staged`.
2. **Tier 2 — CI:** Semgrep/CodeQL taint for the cross-file gap + a verifying secret scanner
   (TruffleHog) + GitHub secret scanning & push protection.
3. **Admission — new dep/skill/template:** GuardDog / Socket / sandbox detonation with egress
   observation.

---

## `vet-incoming.sh` — the inbound supply-chain gate

`scan-repo.sh` gates content **leaving** for a public repo. `vet-incoming.sh` gates content
**arriving** — a third-party template, package, plugin, or skill you are about to adopt. It runs
the same dropper/secret/invisible-unicode engine over a temp copy of the target (**scan only —
it never runs install/build/postinstall**) plus adoption-specific checks, and emits an **ADOPT /
REVIEW / REJECT** verdict.

### What it flags (beyond the shared engine)

| Class | Tier | What it flags |
|---|---|---|
| Lifecycle scripts | HIGH | `preinstall`/`install`/`postinstall`/`prepare`/`prepublish` in any `package.json` — arbitrary code on `npm/pnpm install` (the postinstall attack). |
| Config-file dropper | CRITICAL | A dynamic-exec sink or base64/hex decoder co-occurring with a network fetcher or an environment-variable read, inside a build/test/config file (`vite`/`vitest`/`webpack`/`rollup`/`jest`/`*.config.*`, test setup) — the starter-template vector. Also a base64 blob under an env key in a committed `.env*`. |
| Committed git hooks | HIGH/MED | `.husky/*` hooks; scripts that set `core.hooksPath` or write `.git/hooks`. |
| CI workflow | HIGH/MED | `curl\|bash`, net→interpreter pipes, `eval`, `node -e`; secret-with-network exfil shapes; unpinned/mutable action refs (`uses: x@main`). |
| Editor autorun | HIGH/MED | `.vscode/tasks.json` `runOn: folderOpen`; devcontainer `postCreate/postStart` commands. |
| Obfuscated/minified | MED | Long/minified lines carrying an exec sink; vendored `*.min.js` flagged as opaque. |

Verdict: **REJECT** (any CRITICAL/HIGH, exit 1) · **REVIEW** (MEDIUM or a scan-repo MAJOR) ·
**ADOPT** (nothing matched, exit 0).

### What it does NOT catch — the honest boundaries

- **KNOWN patterns only, trivially evadable** — the same evasion story as `scan-repo.sh`
  (rename/encode/translate/split/minify), and the same **same-file** limitation for cross-file
  droppers.
- **Not a replacement** for Socket / Snyk / `npm audit` (registry & dependency graph), Semgrep /
  CodeQL (dataflow taint), or sandbox detonation with egress observation.
- **A clean ADOPT is not proof of safety** — it means no known adoption red flag matched. Read the
  code, prefer `npm install --ignore-scripts`, and detonate high-value inbound code in a sandbox.
- **Scan-only cannot see a runtime-only payload** — which is exactly why the rule is *vet before
  install*, not *install then watch*. Full contract + case study: `references/vetting-inbound.md`.

---

## `scan-content.sh` — the untrusted-content tripwire

**Prompt injection is an unsolved problem.** This tool does not solve it. It **reduces** risk
by detecting a fixed set of KNOWN injection / social-engineering patterns in a blob of
untrusted content (web-search result, fetched page, tool/MCP output, pasted text). It is a
**tripwire, not a filter**, and a CLEAN result means "no known pattern matched," never "safe."

### What it flags

| Class | Tier | What it flags |
|---|---|---|
| `EXFIL` | CRITICAL | An exfil verb (`send`/`post`/`email`/`upload`/`leak`…) co-occurring on one line with a secret noun (`api key`/`password`/`token`/`.env`/`cookie`/`private key`…) **and** a destination (URL/host/email). |
| `INJECT` | HIGH | Imperative override / role-switch: `ignore (all) previous instructions`, `disregard your rules`, `forget everything`, `new instructions:`, `you are now (a/an/unrestricted…)`, `act as DAN/unfiltered`, `override your instructions`, `enter developer mode`. |
| `CREDS` | HIGH | Solicits the system prompt / initial instructions / an API key / `.env` / credentials (`print your system prompt`, `repeat the words above`). |
| `COVERT` | HIGH | Asks the agent to act without informing the user (`do not tell the user`, `silently forward`, `keep this between us`). |
| `HIDDEN_UNICODE` | HIGH | Zero-width / bidi / PUA / tag codepoints hiding text from a human reviewer (same engine as `scan-repo.sh`). |
| `IMG_EXFIL` | HIGH | Markdown image/link whose URL **interpolates** a value (`${…}`/`{{…}}`/`%VAR%`) — a render-time exfil channel. |
| `URL_QUERY` | MEDIUM | Markdown image/link to an external host with a querystring (possible exfil carrier; benign CDN images also match — hence MEDIUM). |
| `ANSI` | MEDIUM | ANSI/terminal escape sequences embedded in text. |
| `SOCIAL` | MEDIUM | Urgency, authority/impersonation, fake prior approval, safety-bypass requests. |

Default exit: **1** if any CRITICAL or HIGH finding; MEDIUM-only reports and exits **0**
(advisory) unless `--strict`. MEDIUM is where the social-engineering false-positive risk lives,
so it never fails the tripwire by default.

### What it does NOT catch — the honest boundaries

- **Novel / obfuscated / paraphrased injection.** It matches fixed English shapes. Reword
  "ignore previous instructions" as "the earlier guidance no longer applies," translate it,
  base64 it, or split it across lines and this scanner sees nothing. Microsoft's own
  LLMail-Inject challenge (2025) shows even *trained classifiers* fall to adaptive attackers —
  a regex tripwire is far weaker than that.
- **Semantic injection within allowed tools/destinations** (the confused-deputy case) looks
  like legitimate work and has no pattern to match.
- **Multi-hop / delayed-trigger** payloads (land in memory/RAG now, fire later) defeat any
  single-blob scan.
- **It cannot enforce the response.** Detecting a pattern does nothing to stop the agent
  acting on it — that is the **behavioral contract** in `references/untrusted-content.md`, not
  a property of this script.

### What actually reduces the risk (this scanner only points at it)

The durable defense is **architectural**, and this skill *guides* but **cannot mechanically
enforce** it: treat all fetched content as data (`references/untrusted-content.md`), break the
**lethal trifecta** (private data + untrusted content + exfil sink — Willison 2025) so a
poisoned turn cannot both read secrets and exfiltrate, apply Meta's **Rule of Two**, allowlist
egress, and require a human gate at trust-boundary crossings. Use the scanner as a cheap
tripwire on top of that contract — never as a substitute for it.

---

## `check-url.sh` — pre-fetch research egress classifier

Classifies a URL **string** before the agent fetches, browses, or downloads it. Network-free
(no DNS, no HTTP). Exit: **0 ALLOW · 1 REVIEW · 2 BLOCK**.

### What it flags

| Verdict | Examples |
|---|---|
| **BLOCK** | `file:`/`data:`/`javascript:` schemes; credentials in URL; localhost; executables/installers (`.exe` `.dmg` `.pkg`…); archives (`.zip` `.tar.gz`…); install scripts (`.sh` `.ps1`…) |
| **REVIEW** | plain `http:`; `.pdf`/Office docs; IP-literal hosts; punycode (`xn--`); URL shorteners; free file hosts; download-path hints; very long URLs/queries |
| **ALLOW** | normal `https://` HTML/docs paths with no blocked/review extension |

### What it does NOT catch — the honest boundaries

- **No live reputation.** A compromised `docs.example.com` still ALLOW if the URL shape is
  clean. This is intentional: the tool does not pretend to know host safety.
- **No redirect following.** A shortener is REVIEW; the landing host is not resolved here.
- **Does not enforce agent behavior alone.** Pair with the PreToolUse hook
  (`scripts/research-egress-install.sh` → `block-research-egress`) which mechanically
  denies BLOCK (always) and REVIEW (unless `RESEARCH_URL_OK=<exact-url>`). SERP
  spray-click discipline remains in `references/safe-research.md`.
- **Allowlist never unblocks BLOCK** schemes/extensions — only host-reputation REVIEW items.

---

## `research-egress` PreToolUse hook

Installed via `scripts/research-egress-install.sh` to `~/.claude/hooks/block-research-egress.sh`
(+ `~/.grok/hooks/research-egress.json`). Watches `web_fetch` / `open_page` / `Bash` curl|wget.

| Verdict | Hook action |
|---|---|
| ALLOW | Pass |
| REVIEW | Deny unless `RESEARCH_URL_OK` matches the exact URL |
| BLOCK | Always deny (no env override) |

### Limits

- Matcher-bound: non-listed tools and most MCP servers are not covered.
- REVIEW override is env-based (same class as other human-in-the-loop tokens) — a fully
  jailbroken agent that can set env could spoof it; BLOCK cannot be spoofed this way.
- Still network-free classification (no live reputation).

---

## `runtime-audit.sh` — the host runtime audit

Every other control in this document watches a gate. This one watches the machine, and
it exists because a gate-only posture has a hole the size of anything that never touches
a gate: a node command-line implant ran for four and a half days on a host where every
other control here was installed and healthy. It was never in a repository and never in
an agent tool call, so nothing looked at it.

### What it flags

| Check | Shape |
|---|---|
| Inline-eval processes | `node -e` / `bun -e` / `deno eval` / `python -c` / `sh -c … curl … \| sh` |
| Dropper markers in a command line | exec sink (`eval(`, `new Function(`) co-occurring with an encoder, a network fetcher, a respawn call (`child_process`, `detached: true`), or a blockchain-C2 host |
| Orphaned interpreters | PPID 1, long-lived, inline-eval — the spawner exited, the child was left detached |
| Autostart drift | launchd plists, systemd user units, XDG autostart, `cron.d`, against a recorded baseline |
| Shell/agent config drift | rc, profile, and env dotfiles in `$HOME` and agent config directories |

A long-lived inline eval with no other markers is a `WARN`, not a finding: legitimate
inline eval exists, it is just normally short-lived. Blockchain RPC hosts never fire on
their own — plenty of people work on blockchains — they only add weight to a process
that is already an inline eval.

### What it does NOT catch — the honest boundaries

- **Command lines only.** An implant that execs from a file, rewrites its own `argv`, or
  hides its arguments does not appear here. This reads `ps`, not memory.
- **Point-in-time.** It reports what is running at the instant it runs. Unscheduled, that
  instant is "whenever someone remembers", which is exactly how four and a half days
  passed before anyone looked. `runtime-audit-install.sh` fixes the trigger — hourly by
  default — but a scheduled audit still only samples: an implant that starts and exits
  between two runs leaves no trace here, and one that sleeps through them is invisible
  regardless of frequency.
- **A baseline recorded after an infection blesses the infection.** The first run records
  whatever is currently installed as normal. When it matters, read autostart mtimes
  directly instead of trusting the diff.
- **Sleeping implants.** A beacon that wakes every six hours is a normal-looking idle
  process in between.
- **Not EDR.** No memory inspection, no binary signing checks, no syscall tracing, no
  network flow analysis. It is a tripwire for a known process shape.

### The failure mode it refuses to have

`BLIND` (exit 2) is a first-class verdict. An earlier version wrote its scratch snapshot
to `TMPDIR`; when that write failed it compared the baseline against an empty file and
reported every entry as removed and nothing as added — which on the axis that matters,
newly added persistence, is indistinguishable from a clean host. A check that cannot run
now says so as loudly as a finding, and exits non-zero.

### If it reports CRITICAL

Preserve, contain, hunt, then eradicate — in that order. Capture the full command line
and the `ps` table first. Contain with `kill -STOP` before `kill -9`: a stopped process
cannot execute a detached respawn, so containment is atomic even when several
generations are alive, and the volatile state a `-9` destroys survives for analysis.
Only then hunt persistence, verifying autostart and cron **mtimes** directly, and
eradicate.

---

## `ioc-sweep.sh` — the on-disk indicator sweep

`runtime-audit.sh` watches what is running. This watches what is installed and dormant,
which is where most 2026 supply-chain compromises sit between delivery and execution: a
compromised release in a lockfile, a worm loader in a package cache, a hijacked Action
reference in a workflow, a `SessionStart` hook committed into a repository's agent
config. None of those is a process until someone installs, opens the folder, or starts a
session.

### What it flags

| Finding | Shape |
|---|---|
| `DROP-PATH` / `PAYLOAD-FILE` / `REPO-PATH` / `TMP-STAGING` | a known drop directory under `$HOME`, an exact payload basename anywhere under the scanned roots (package caches included), a known path inside a working tree, a known staging name directly under a tmp directory |
| `LOOKALIKE-PKG` / `COMPROMISED-NPM-RELEASE` | a named package in any lockfile or `package.json`; an exact compromised version in a lockfile, an installed node_modules manifest, or a bun / npx / pnpm cache directory name |
| `PREINSTALL-HOOK` | a pre/postinstall whose command names a known worm loader |
| `MALICIOUS-PYPKG` / `COMPROMISED-PYPI-RELEASE` / `PYTHON-STARTUP-HOOK` | PEP 503-normalised name match in uv / poetry / requirements / pyproject locks and every `*.dist-info` under `$HOME`; the `*-setup.pth` + `_index.js` startup shape in any site-packages |
| `MALICIOUS-CRATE` / `HIJACKED-CRATE-RELEASE` | `Cargo.lock` name + version pairs and `~/.cargo/registry` directories |
| `ROGUE-WORKFLOW` / `ACTIONS-RUNNER` / `HIJACKED-ACTION-BY-TAG` / `UNPINNED-ACTION` | a known rogue workflow *filename* (basename match only, so a comment that names one does not fire) or a known marker token in a workflow's content; a self-hosted runner install; a `uses:` of a known-hijacked action that is not a 40-hex SHA pin; with `--strict-actions`, every third-party action used by tag or branch (a note with the file list otherwise) |
| `ENV-DECODE-DROPPER` | a base64 decode of an environment variable and an exec sink in the same source or config file, node_modules pruned, files over 2 MB skipped |
| `AUTORUN-TASK` / `REPO-AGENT-HOOK` / `SUSPICIOUS-MCP-CONFIG` | repository `.vscode/tasks.json` with `folderOpen`; the `hooks` object of repository `.claude` / `.cursor` / `.codex` settings with session-start hooks or fetch-and-exec shapes; repository MCP configs with fetch-and-exec shapes |
| `AGENT-CONFIG-NEW` / `AGENT-CONFIG-DRIFT` | a home agent config appeared or changed since the recorded hash baseline (for `~/.claude.json` only the MCP server maps are hashed, so ordinary UI state does not fire) |
| `HOME-AGENT-HOOK` / `HOME-MCP-CONFIG` | a fetch-and-exec shape in the `hooks` object of `~/.claude/settings.json` or `~/.codex/hooks.json`, in the MCP server maps of `~/.cursor/mcp.json` or `~/.claude.json`, in `~/.codex/config.toml`, or in `~/.hermes/config.yaml`; checked on every run, independent of the baseline |
| `AGENT-API-REDIRECT` / `NPMRC-TOKEN` | an API base-URL key (`ANTHROPIC_BASE_URL`, `chatgpt_base_url`, `base_url`) in the `env` of a repository `.claude` settings file or in a repository `.codex/config.toml` (the Downloads-folder `AGENTS.md` / `CLAUDE.md` lure writes one to capture the session token); at home the same key is a finding only for a plain-http or IP-literal target and a note otherwise; a `.npmrc` in a working tree whose `_authToken` is a literal rather than an environment reference (the fake-interview Tailwind lure's enabler). Both print the path, never the value. A home config that points at a named https host, or at a loopback address such as a local model server, is the `agent-api-url` note instead. `~/Downloads/AGENTS.md` and `~/Downloads/CLAUDE.md` are `DROP-PATH` findings even when you saved them yourself, because the lure is indistinguishable from notes until read; read it, then delete or move it. Upgrading adds `~/.codex/config.toml` to the baseline, so the first run reports it as `AGENT-CONFIG-NEW` once |
| `AGENT-CONFIG-UNPARSEABLE` / `AGENT-CONFIG-UNCHECKED` | an agent config that is not valid JSON; `python3` missing so no JSON config could be inspected |
| `SHELL-LURE` / `APPLE-NAMED-EXEC` / `TMP-MACHO` / `TMP-ELF` / `TMP-SCRIPT` / `INVISIBLE-UNICODE-EXT` / `INVISIBLE-UNICODE-SRC` | ClickFix lure shapes in recent history (pattern name and host only), executables named `com.apple.*` outside bundles, Mach-O executables (header filetype 2, or fat) and ELF files written to tmp within the window (a Mach-O bundle or dylib is the `tmp-macho-library` note: it needs a host process, and Electron apps unpack native addons there), executable scripts in tmp whose body carries a stager shape (curl/wget, base64 decode, `/dev/tcp`, quarantine strip, launchctl load; a script without one is a note), Variation Selectors Supplement bytes in IDE extensions and workspace source |

### What it does NOT catch — the honest boundaries

- **It is a list.** Every check is a name, path, version, or shape taken from public
  reporting. A renamed payload, a new package name, a version published after the list
  was last updated, or a loader split across two files walks past. The list is a
  snapshot; append to it.
- **Hijacked actions are detected by reference.** The sweep cannot tell whether a tag has
  already been repointed. It reports every action used by tag or branch (note by default,
  `--strict-actions` for findings) because a full-SHA pin is the only thing that closes
  this class, and the known-hijacked list is always one publication behind.
- **The baseline is only a diff.** It says a home config changed, not whether the change
  is bad. The shape check that runs on every pass is what catches a fetch-and-exec hook,
  including one present before the baseline was recorded. A hook that runs a local
  script by path is deliberately not flagged at home level.
- **Shell history is optional.** A lure pasted into a terminal with history off leaves
  nothing to read, and the check never prints the command itself.
- **Package stores are pruned for the dropper shape.** A dropper inside node_modules is
  caught by name and version rules, not by the decode-then-exec rule; walking every
  minified bundle for that shape produced only false positives (bundlers that decode an
  embedded archive next to an environment check).
- **Walks are bounded.** `--depth` (default 8 below the workspace root, package stores
  pruned) caps every workspace walk; a deeper monorepo needs a higher value and pays
  linearly for it. `--timing` shows where the seconds go.
- **Scripts in tmp are judged by body, not presence.** A stager that avoids every shape
  in the lure pattern is a note, not a finding.
- **Not an AV.** No hashes of binaries, no signing checks, no network reputation. A
  CLEAN result means no listed indicator matched.

### Precision, again

During development the sweep reported eight findings on a clean workspace, all false:
permission allowlists that merely *named* `curl` and `python3 -c`, and a real
`Math_Symbol.js` shipped by a Unicode data package. The next round repeated it: a
workflow that *mentioned* a rogue filename in a comment fired, and an executable shell
script in tmp fired. Filename tokens now match basenames only, and tmp scripts need a
stager shape; both have clean fixtures. A daily sweep that cries wolf is a daily sweep that
gets switched off, so the hooks check now reads only the `hooks` object, the filename
rule is exempt inside package stores, and both cases have clean fixtures.

---

## repo-guard — the repository-lifecycle guard

### What it blocks (repo-LEVEL destruction only), on a two-tier model

`gh repo delete` · `rename` · `transfer` · `archive` · `edit --visibility private|internal`;
`gh api` `DELETE`/`PATCH` on `/repos/OWNER/REPO` that changes `name`/`visibility`/`archived`/
`private`; `gh api …/repos/O/R/transfer`; and graphql `deleteRepository` /
`archiveRepository` / `updateRepository→private`.

These split into two confirmation tiers by recoverability:

- **TIER 2 (TRIPLE confirmation)** — the irreversible, star-destroying ops: **`delete` and
  `transfer`** (plus the `gh api` `DELETE /repos/O/R`, `…/transfer`, and graphql
  `deleteRepository` equivalents). A completed delete/transfer is not recoverable from this
  machine, so it requires **all three** independent factors below, each naming the same repo.
- **TIER 1 (single confirmation)** — the recoverable ops: **`rename`, `archive`,
  `edit --visibility private|internal`** (plus the `gh api` PATCH mutate and graphql
  archive/privatize equivalents). These need only the single `REPO_LIFECYCLE_OK` factor;
  they are not over-gated.

### What it deliberately does NOT block (passes through unchanged)

- All read/normal usage: `view`, `list`, `clone`, `create`, `fork`, `sync`, `pr`, `issue`,
  `workflow`, `api` GET, and `git push` (including **branch** deletes — out of scope,
  branch-level not repo-level).
- Making a repo **public** (`--visibility public`) and **unarchive** — both restorative.
- `gh api DELETE`/`PATCH` on **sub-resources** (`/git/refs/…`, labels, releases, comments):
  not repo-level destruction.
- A safe repo edit like `gh api -X PATCH /repos/O/R -f description=…`.

### The override (human-in-the-loop)

**TIER 1** — name the exact target repo in `REPO_LIFECYCLE_OK`:

```sh
REPO_LIFECYCLE_OK=owner/repo gh repo archive owner/repo
```

Accepted forms: `REPO_LIFECYCLE_OK=owner/repo`, or the token
`REPO_LIFECYCLE_OK=--yes-destroy-owner/repo` / `--yes-destroy-<repo-name>`. **The override
must match the repo actually being operated on**, or it still blocks — a mis-targeted
automation cannot satisfy the gate for the wrong repository.

**TIER 2** (delete / transfer) — all three factors, each naming the **same** `owner/repo`;
any missing factor blocks and the message names which:

```sh
printf '%s\n' 'owner/repo' >> ~/.local/state/repo-guard/CONFIRM-DESTROY   # single-use line
REPO_LIFECYCLE_OK=owner/repo REPO_DESTROY_CONFIRM=owner/repo gh repo delete owner/repo --yes
```

1. `REPO_LIFECYCLE_OK=<owner/repo>` (env) · 2. `REPO_DESTROY_CONFIRM=<owner/repo>` (env, a
second deliberate re-type under a different variable) · 3. a line == `<owner/repo>` in the
single-use file `~/.local/state/repo-guard/CONFIRM-DESTROY`, which the guard **removes on a
successful pass** (a second delete needs a fresh line). A graphql `deleteRepository` cannot
name a concrete repo and so can never satisfy the three factors — use the explicit
`gh repo delete <owner/repo>` form. **Triple-confirm is a stronger local brake, not an
absolute block:** absolute-path `gh` outside a Claude session and `curl`/octokit REST still
bypass it; the only categorical block on delete/transfer is a token without `delete_repo`
(see the honest line below).

### Honest coverage / bypass matrix

| Vector | PATH shim (L1) | Claude hook (L3) |
|---|---|---|
| `gh …` (bare, PATH-resolved) in any shell | blocks | blocks (Claude sessions) |
| `/abs/path/gh …` (absolute) in a Claude Bash tool call | **bypassed** | blocks |
| `/abs/path/gh …` (absolute) in a plain terminal / another tool | **bypassed** | **not covered** |
| gh via PATH from a script/CI on this machine | blocks | n/a |
| Direct REST call with `curl` (no gh) | **not covered** | **not covered** |

**The honest bypass.** A tool invoking the real `gh` by **absolute path** outside a Claude
session skips the PATH shim — we cannot intercept that without breaking Homebrew/symlink
resolution. The Claude hook (L3) closes this specifically for Claude Code sessions, the
primary automation threat. A determined human can always call the real binary directly; this
guard targets **accidental / automated** destruction, not a determined operator. `curl`
against the REST API is likewise out of scope (it never touches `gh`).

**What it is not — the load-bearing honest line.** It is not GitHub org-level protection, not a
branch/tag protection rule, not a permissions boundary on the token itself. It is a **local,
per-machine, per-invocation brake** — it REDUCES accidental/automated destruction risk; it does
**not** guarantee prevention (absolute-path `gh` and the REST API bypass it). **TRUE prevention
is capability removal at GitHub:** a token without `delete_repo` literally cannot delete/transfer
regardless of any bypass, plus org deletion/transfer restrictions and branch protection. Audit
that surface with `scripts/harden-check.sh` (verb `harden`) and read the full layered model — L1
guard, L2 token scope, L3 org policy, L4 branch protection, L5 recovery — with the minimal
automation-token recipe and exact Settings URLs in `references/destructive-ops-prevention.md`.
The GitHub-side fixes are the operator's to apply; the skill audits and guides, it never changes
your token or org settings.

### Logs

`~/.local/state/repo-guard/blocked.log` (dir `chmod 700`; override with `$REPO_GUARD_STATE`).
Records every BLOCK and every honored override (`ALLOWED-OVERRIDE`), tab-separated, with a
UTC timestamp, source (`SHIM`/`HOOK`), target repo, and argv.
