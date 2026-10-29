# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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
