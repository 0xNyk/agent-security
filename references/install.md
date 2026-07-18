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

## Dry-run everything first

```sh
scripts/repo-guard-install.sh --with-hook --dry-run   # print actions, change nothing
bash tests/test-scan.sh                                # scanner fixtures
bash tests/test-guard.sh                               # guard fixtures (offline, fake gh)
```
