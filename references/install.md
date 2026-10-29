# Install

Two independent components. Install either or both. Everything is path-agnostic:
paths are detected or use `$HOME`. macOS and Linux; requires `bash`, `git`, and
`python3` (python3 is used for the invisible-unicode class and the hook/installer
JSON handling — the scanner degrades to a warning without it, the hook fails closed).

## Requirements

- `bash` 3.2+ (works with macOS's system bash), `git`, `grep`, `sed`.
- `python3` — for the `INVISIBLE_UNICODE` scanner class, the Claude hook, and the
  installer's `settings.json` merge. Without it the scanner still runs every other
  class and warns; the hook and hook-registration require it.
- `gh` (GitHub CLI) — only for the repo-guard. The scanner does not need it.

## Component 1 — `scan-repo.sh` (leak + dropper gate)

No install step. Run it from the root of the repo you are about to publish:

```sh
# scan the staged changeset (default) — good as a pre-commit hook
scripts/scan-repo.sh

# scan every tracked file before flipping a repo public
scripts/scan-repo.sh --all

# scan a commit range
scripts/scan-repo.sh --ref main..HEAD
```

Optional pre-commit hook (`.git/hooks/pre-commit`, made executable):

```sh
#!/usr/bin/env bash
exec /absolute/path/to/scripts/scan-repo.sh --staged
```

### Your private markers (optional, local, never shipped)

Copy the template and fill in your own repo/venture/product names and private path
fragments. The file lives **outside** any repo you publish:

```sh
mkdir -p ~/.config/agent-security
cp private-markers.example.txt ~/.config/agent-security/private-markers.txt
chmod 600 ~/.config/agent-security/private-markers.txt
$EDITOR ~/.config/agent-security/private-markers.txt
```

The scanner auto-discovers it at `~/.config/agent-security/private-markers.txt`
(or `$AGENT_SECURITY_MARKERS`, or `--markers <file>`). With no marker file the
generic layer still runs and warns once. **Never commit this file** — `.gitignore`
already ignores `private-markers.txt`.

## Component 2 — repo-guard (repository-lifecycle guard)

```sh
# install the PATH shim (Layer 1)
scripts/repo-guard-install.sh

# also install + register the Claude Code hook (Layer 3)
scripts/repo-guard-install.sh --with-hook

# also prepend the shim's bin dir in your shell rc (~/.zshenv, ~/.bashrc)
scripts/repo-guard-install.sh --with-hook --setup-path

# custom shim location
scripts/repo-guard-install.sh --bin-dir ~/bin
```

Then verify and test (non-destructive):

```sh
scripts/repo-guard-install.sh --status   # shows whether gh resolves to the guard
gh repo view                             # should pass through normally
```

If `--status` says the PATH shim is INACTIVE, your `$PATH` resolves `gh` to the real
binary before the shim's bin dir. Re-run with `--setup-path`, or add the printed
`export PATH="…:$PATH"` line to your shell rc yourself, then open a new shell.

The Claude hook loads in **new** Claude Code sessions — restart Claude Code after
installing it.

### Removal

```sh
scripts/repo-guard-install.sh --uninstall   # removes shim + hook, de-registers from settings.json
```

`--uninstall` leaves your logs and any `--setup-path` rc lines (they are marked
`repo-guard:` — remove them by hand). Removing the shim alone disables the PATH guard
immediately; `gh` then resolves to the real binary again.

## Research-egress PreToolUse hook (optional, recommended)

Hard-blocks unsafe fetches before `web_fetch` / `open_page` / `curl|wget` run.
Uses `scripts/check-url.sh` under the hood. Installs on **Claude, Grok, Codex, and Hermes**.

```sh
scripts/research-egress-install.sh           # all hosts present on this machine
scripts/research-egress-install.sh --status
scripts/research-egress-install.sh --uninstall
```

| Host | What gets written |
|---|---|
| Claude | `~/.claude/hooks/block-research-egress.sh` + `settings.json` |
| Grok | `~/.grok/hooks/research-egress.json` |
| Codex | `~/.codex/hooks.json` + `features.hooks = true` |
| Hermes | `~/.hermes/config.yaml` `hooks.pre_tool_call` + shell-hooks allowlist |

Restart agent sessions after install. Policy: BLOCK always denied; REVIEW needs
`RESEARCH_URL_OK='https://…'` exact match; ALLOW passes. See `safe-research.md`.

## Scheduled runtime audit (optional, recommended)

`runtime-audit.sh` runs read-only and needs no installation to use. Scheduling it is the
part that matters: a point-in-time check whose trigger is "someone remembers to run it"
fails the same way the incident it was written for did.

```sh
scripts/runtime-audit.sh                       # audit now, no install
scripts/runtime-audit-install.sh               # schedule it, hourly by default
scripts/runtime-audit-install.sh --interval 1800
scripts/runtime-audit-install.sh --status      # exits 1 when not armed
scripts/runtime-audit-install.sh --uninstall
```

| Platform | What gets installed |
|---|---|
| macOS | `~/Library/LaunchAgents/com.agent-security.runtime-audit.plist` (`StartInterval`), loaded with `launchctl` |
| Linux with systemd | a user timer + service under `~/.config/systemd/user/` |
| Otherwise | a `crontab` line |

Findings append to `~/.local/state/agent-security/runtime-audit.log`. Intervals under
300s are refused. Because adding a scheduler entry is itself autostart drift, the
installer refreshes the audit's persistence baseline once and says so.

Removal restores nothing else: `--uninstall` takes out only the scheduler entry, leaves
the audit script alone, and reminds you to re-run `--update-baseline` so the removal is
not reported as drift on the next audit.

## Scheduled IOC sweep (optional, recommended)

`ioc-sweep.sh` is read-only and needs no installation. Daily is enough: the disk changes
slowly. Run time scales with the workspace: seconds on a small one, around ten minutes
across a large multi-repository tree with full package caches. There is no installer for
it yet; the lines below do the job. Pass `--no-notify` under cron.

```sh
scripts/ioc-sweep.sh                       # sweep now
scripts/ioc-sweep.sh --accept-config       # after you deliberately change a home agent config
scripts/ioc-sweep.sh --strict-actions      # once, to get every unpinned Action as a finding and pin them
```

macOS, `~/Library/LaunchAgents/com.agent-security.ioc-sweep.plist` (replace the path):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.agent-security.ioc-sweep</string>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string>
    <string>/path/to/agent-security/scripts/ioc-sweep.sh</string>
  </array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>12</integer><key>Minute</key><integer>5</integer></dict>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
```

Load it with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.agent-security.ioc-sweep.plist`.

Linux or anywhere with cron:

```
5 12 * * * /bin/bash /path/to/agent-security/scripts/ioc-sweep.sh --no-notify >/dev/null 2>&1
```

Findings land in `~/.local/state/agent-security/ioc-sweep-findings.txt` and a one-line
summary in `ioc-sweep.log`; on macOS a notification fires when there are findings. Adding
the scheduler entry is autostart drift for `runtime-audit.sh`, so re-run its
`--update-baseline` once afterwards.

## Dry-run everything first

```sh
scripts/repo-guard-install.sh --with-hook --dry-run   # print actions, change nothing
bash tests/test-scan.sh                                # scanner fixtures
bash tests/test-guard.sh                               # guard fixtures (offline, fake gh)
bash tests/test-research-egress-hook.sh                # fetch-gate fixtures
bash tests/test-ioc-sweep.sh                           # on-disk IOC sweep fixtures (throwaway HOME)
scripts/runtime-audit-install.sh --dry-run             # scheduler actions, change nothing
bash tests/run-all.sh                                  # every suite plus the self-scan
```
