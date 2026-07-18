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
| `PATH` | MAJOR | Personal home paths (`/Users/<name>`, `/home/<name>`, Windows profile paths); `~/.ssh`, `~/.aws` references. Neutral placeholders (`example`, `you`, `runner`, …) are excluded. |
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

## repo-guard — the repository-lifecycle guard

### What it blocks (repo-LEVEL destruction only)

`gh repo delete` · `rename` · `transfer` · `archive` · `edit --visibility private|internal`;
`gh api` `DELETE`/`PATCH` on `/repos/OWNER/REPO` that changes `name`/`visibility`/`archived`/
`private`; `gh api …/repos/O/R/transfer`; and graphql `deleteRepository` /
`archiveRepository` / `updateRepository→private`.

### What it deliberately does NOT block (passes through unchanged)

- All read/normal usage: `view`, `list`, `clone`, `create`, `fork`, `sync`, `pr`, `issue`,
  `workflow`, `api` GET, and `git push` (including **branch** deletes — out of scope,
  branch-level not repo-level).
- Making a repo **public** (`--visibility public`) and **unarchive** — both restorative.
- `gh api DELETE`/`PATCH` on **sub-resources** (`/git/refs/…`, labels, releases, comments):
  not repo-level destruction.
- A safe repo edit like `gh api -X PATCH /repos/O/R -f description=…`.

### The override (human-in-the-loop)

Name the exact target repo in `REPO_LIFECYCLE_OK`:

```sh
REPO_LIFECYCLE_OK=owner/repo gh repo delete owner/repo --yes
```

Accepted forms: `REPO_LIFECYCLE_OK=owner/repo`, or the token
`REPO_LIFECYCLE_OK=--yes-destroy-owner/repo` / `--yes-destroy-<repo-name>`. **The override
must match the repo actually being operated on**, or it still blocks — a mis-targeted
automation cannot satisfy the gate for the wrong repository.

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

**What it is not.** It is not GitHub org-level protection, not a branch/tag protection rule,
not a permissions boundary on the token itself. For durable protection, also set
organization repository-deletion restrictions and least-privilege tokens. This guard is a
**local, per-machine, per-invocation** brake, not a server-side policy.

### Logs

`~/.local/state/repo-guard/blocked.log` (dir `chmod 700`; override with `$REPO_GUARD_STATE`).
Records every BLOCK and every honored override (`ALLOWED-OVERRIDE`), tab-separated, with a
UTC timestamp, source (`SHIM`/`HOOK`), target repo, and argv.
