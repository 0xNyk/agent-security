# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## 0.3.0 — 2026-10-30

- **No more `| grep -q` under `pipefail`, in detectors or tests.** Every script and test
  runs with `pipefail`, and 43 places piped `echo` / `printf` into `grep -q`. `grep -q` exits
  on its first match; when the producer still had bytes to write it died of `SIGPIPE`, the
  pipeline returned 141, and a match read as a miss. In the tests that was an intermittent
  failure under load. In `runtime-audit.sh` it was a silent false negative: a dropper whose
  command line was longer than one write buffer, which a padded base64 blob easily is, could
  pass the exec-sink and encoder checks. All of them now use here-strings, and a fixture
  runs the dropper shape on a 200 KB command line.
- **ioc: the three campaigns published since the list was last updated, and two checks for
  the mechanisms behind them.** Indicators for the fake job-interview Tailwind / Animate.css
  plugin set (29 packages plus the two private scoped payloads they require), MALFEX
  (`function-flag`, `function-color`, the Overlord and stealer loaders), the Downloads-folder
  `AGENTS.md` / `CLAUDE.md` lure that talks a coding agent into installing them, and the
  developer-tooling malware advisories of 27–30 October (`@atlisp/mcp`, `@zaip-ai/cli`,
  `dsh-*`, `itsa-*`, camelotlabs, `numprint`, `trajmetrics`, `log-utils-sdk`). Two new
  shapes: `AGENT-API-REDIRECT`, an API base-URL key in a repository `.claude` settings `env`
  or `.codex/config.toml` (at home a finding only for plain-http or IP targets, otherwise the
  `agent-api-url` note), because a redirected endpoint receives the session token and can
  answer with tool calls; and `NPMRC-TOKEN`, a working-tree `.npmrc` whose `_authToken` is a
  literal, which is what the Tailwind lure needs to resolve its private payload. Both print
  the path, never the value. `~/.codex/config.toml` joins the home shape checks and the hash
  baseline, so the first run after upgrading reports it as `AGENT-CONFIG-NEW` once. The npm
  lockfile walk now happens once and is shared by the lookalike and compromised-release
  checks instead of once per version indicator. Ten new fixture assertions, positive and
  negative, including that neither the token nor the URL is ever printed. Two precision
  fixes from the first live run: a Mach-O bundle or dylib in tmp (an Electron app's unpacked
  native addon) is the `tmp-macho-library` note rather than `TMP-MACHO`, which now requires
  an executable or fat header; and Codex `[projects."<path>"]` trust tables are dropped
  before the fetch-and-exec grep, so a trusted scratch project under `/tmp` does not fire.
  Every temporary list now lives in one private work directory that a trap removes on
  exit, Ctrl-C or kill, so an interrupted sweep no longer leaves files in tmp; a fixture
  sends `TERM` mid-run and checks.
- **ioc** (`ioc-sweep.sh` + `ioc-indicators.txt`) — read-only on-disk sweep against
  published indicators for the campaigns that targeted developer machines through
  October 2026. `runtime` sees processes; this sees what is installed and dormant.
  Families: Contagious Interview host artefacts and npm lookalikes; Shai-Hulud 2.0
  loaders anywhere including package caches; GlassWorm invisible-Unicode in IDE
  extensions; ClickFix lure shapes in recent shell history (pattern name and host only,
  never the command); the "auth error" config dropper (environment-variable decode
  feeding an exec sink in the same file); compromised npm releases by exact version
  (axios 1.14.1 / 0.30.4, tensorlake 0.5.144, @subql/common 5.8.3) and malicious
  packages (Apex / REF8801, agentenact, plain-crypto-js); ChainDrop / TeamPCP / Nx
  Console / CanisterWorm / Trivy loader paths and tmp staging; GitHub Actions whose tags
  were hijacked (actions-cool/*, codfish/semantic-release-action, aquasecurity/trivy-action)
  whenever a workflow uses them by anything other than a full commit SHA, plus
  GhostAction workflow names; PyPI (Hades, lightning 2.6.2 / 2.6.3, litellm 1.107.0, the
  `*-setup.pth` startup hook); crates.io (Rustbot crates, hijacked arrayref / internment /
  append-only-vec); and agent / IDE config injection — `folderOpen` tasks, `SessionStart`
  / `UserPromptSubmit` hooks or fetch-and-exec shapes in repository `.claude` / `.cursor`
  / `.codex` settings and MCP configs, and a hash baseline of the home agent configs
  with `--accept-config` to re-record after a deliberate change. Three-state exit like
  `runtime`: `0` clean, `1` findings, `2` BLIND. Indicator kinds are documented in the
  file header so a new campaign is a one-line append.

  Precision notes from development: permission allowlists that merely *name* `curl` or
  `python3 -c` are not hooks, so the hooks check inspects only the `hooks` object;
  `Math_*.js` is a real file in `regenerate-unicode-properties`, so the ChainDrop filename
  rule is exempt inside package stores; and per-indicator `$HOME` walks were collapsed
  into single walks, which cut a full run over a large workspace from well over an hour to
  minutes. Each fix has a neighbouring clean fixture. Runs under macOS `/bin/bash` 3.2 on
  an empty workspace (empty-array expansions are guarded; a crash would have exited `1`,
  which reads exactly like a finding), covered by a fixture that runs the system bash.
- **ioc: the engineering-side limits are fixed.** Rogue-workflow filename tokens match
  the basename only (a comment naming `security-audit.yml` no longer fires). Every
  third-party Action used by tag or branch is reported as a note with its file, or as
  `UNPINNED-ACTION` findings under `--strict-actions`, because the known-hijacked list is
  always one publication behind a full-SHA pin. Home agent configs are shape-checked on
  every run (`HOME-AGENT-HOOK`, `HOME-MCP-CONFIG`) so the hash baseline cannot bless a
  fetch-and-exec entry present on the first run. A config that does not parse is
  `AGENT-CONFIG-UNPARSEABLE`, and a machine without `python3` gets `AGENT-CONFIG-UNCHECKED`
  instead of a silent pass. tmp executables now cover ELF (`TMP-ELF`) and scripts whose
  body carries a stager shape (`TMP-SCRIPT`; a plain script is a note). Workspace walks
  share one `--depth` (default 8) instead of five different hardcoded depths, and
  `--timing` prints per-section seconds. Notes go to `ioc-sweep-notes.txt`. Seven new
  fixtures, positive and negative. The sweep no longer runs under macOS background QoS:
  `taskpolicy -b` throttles IO and pins to efficiency cores, which turned a ten-minute
  run into forty; it now runs at plain low CPU priority, and the hijacked-action check
  reads each workflow once instead of once per indicator.
- **The scheduler test no longer assumes launchd.** Its interval read-back check planted
  a LaunchAgent plist and expected `--status` to read it, which only holds on macOS; on
  Linux the installer reads a systemd timer or the user's real crontab, which a test must
  never write. The check now runs on Darwin only and says so, and the whole suite passes
  on Ubuntu 24.04 as a non-root user.

## 0.2.0

Adds the two surfaces the first release did not watch: what an agent fetches, and what
is already running.

- **runtime** (`runtime-audit.sh`) — read-only audit of the host. Flags inline-eval
  interpreter processes (`node -e`, `python -c`, `deno eval`, `bun -e`), dropper markers
  co-occurring in a single command line (exec sink + encoder + fetcher + respawn +
  blockchain C2), orphaned PPID-1 interpreters, and autostart + shell-profile drift
  against a recorded baseline — launchd plists, systemd user units, XDG autostart, and
  `cron.d`. Three-state exit: `0` clean or drift, `1` CRITICAL, `2` BLIND when a check
  could not run at all, because a drift checker that cannot read its baseline otherwise
  reports "nothing added" and looks exactly like a clean host. `--ps-file` audits a
  captured `ps` table for offline triage.

  This exists because a command-line implant ran for four and a half days on a machine
  where every other control in this project was installed and reporting healthy. Every
  one of those controls watches a gate — repository content, agent tool calls,
  destructive commands — and the implant passed through none of them. Limits are stated
  in the tool and the docs: command lines only, and point-in-time.

- **runtime scheduling** (`runtime-audit-install.sh`) — installs the audit as a
  LaunchAgent (macOS), a systemd user timer (Linux), or a crontab line, with `--status`,
  `--uninstall`, and a `--dry-run` that provably performs no work. Findings append to
  `~/.local/state/agent-security/runtime-audit.log`.

  A point-in-time check whose trigger is "someone remembers" has the same failure mode as
  the incident it was written for. Scheduling is what makes it a control rather than a
  habit. Intervals below 300s are refused as cost without detection benefit, and because
  installing a scheduler entry is itself autostart drift, the installer refreshes the
  audit's baseline once and announces that it did.

The egress side: the 0.1.0 gates all inspected content that had already reached the
machine, and nothing decided whether an agent should fetch it.

- **check-url** (`check-url.sh`) — network-free URL classifier returning `ALLOW` (0),
  `REVIEW` (1), or `BLOCK` (2) from URL shape alone: scheme, host form, extension,
  shorteners, file lockers, credentials in the URL, loopback and IP-literal hosts.
  Supports `--quiet`, `--json`, stdin, and an optional host allowlist that can upgrade a
  host-reputation `REVIEW` but can never unblock a blocked scheme or extension.
- **research-egress-install** (`research-egress-install.sh`) — installs `check-url` as a
  PreToolUse gate that runs *before* a fetch tool or a `curl`/`wget` shell command
  executes, across Claude Code, Grok, Codex, and Hermes. `BLOCK` is always denied;
  `REVIEW` is denied unless `RESEARCH_URL_OK` names the exact URL. Ships `--status` and
  `--uninstall`, plus the `RESEARCH_EGRESS_OFF=1` operator kill switch.
- **safe research contract** (`references/safe-research.md`) — the behavioural half the
  hook cannot enforce: prefer primary sources, cap fetches per question, never auto-open
  executables or archives, and keep treating whatever comes back as data.

Fixed:

- **The eval exec-sink pattern now carries a left word boundary.** The `exec` and
  `compile` sinks already had one; eval did not, so any identifier merely *ending* in
  those four letters matched — including a function named `is_inline_eval` in code that
  implements eval detection. A preceding dot is still allowed, so member-call forms such
  as the one on `window` keep matching.
- **Hardcoded personal workspace roots are now a `PATH` finding.** The rule only knew
  literal `/Users/<name>` and `/home/<name>`, so a home-relative workspace root followed
  by a repository name passed cleanly — leaking both a machine layout and the name of a
  private sibling repository. Ordinary home dot-directories such as `.config` and
  `.cache` are excluded, and covered by a negative fixture.
- **Interpreter flags are no longer confused with script flags.** `runtime-audit`
  matched one regex across the whole command line, so `node /path/to/pnpm start -p 3011`
  read pnpm's port flag as node's `-p` print-eval flag and reported a dev server as an
  implant. Detection now walks tokens and stops at the script path, because flags after
  it belong to the script. This is a security property rather than tidiness: an audit
  that reports dev servers every hour is an audit someone switches off. Covered by
  fixtures for both directions, including `python3 -W ignore -c CODE` still matching.
- **Nested-call decode is no longer a blind spot.** The dropper encoder pattern stopped
  at the first `)`, so `Buffer.from(decodeURIComponent(s), "base64")` feeding an `eval`
  was only caught when a network fetcher happened to appear alongside it. A payload that
  decoded from local state and executed, with no fetch stage, passed as `CLEAN`. The
  added alternative requires the quoted encoding name, so it does not fire on prose or on
  an unrelated `base64` elsewhere in a long or minified line. Covered by a positive and a
  negative fixture.
- **CI could not miss a suite again.** The workflow listed suites by hand and two shipped
  without being added. `tests/run-all.sh` now discovers every `tests/test-*.sh`, CI runs
  that single command, and shellcheck covers `scripts/research-egress/` as well.

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
