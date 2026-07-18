#!/usr/bin/env bash
# repo-guard-install.sh — install / inspect / remove the repo-lifecycle guard.
#
# The guard makes DESTRUCTIVE GitHub repo operations require explicit per-repo human
# confirmation, on a TWO-TIER model:
#   TIER 1 (single confirm) — rename / archive / edit --visibility private|internal:
#     recoverable, so they need only REPO_LIFECYCLE_OK=<owner/repo>.
#   TIER 2 (TRIPLE confirm) — delete / transfer (the irreversible, star-destroying
#     ops): require ALL THREE of REPO_LIFECYCLE_OK=<owner/repo>,
#     REPO_DESTROY_CONFIRM=<owner/repo>, and a matching line in the single-use file
#     ~/.local/state/repo-guard/CONFIRM-DESTROY (consumed on success). Any missing
#     factor blocks. This is a strong LOCAL brake, not an absolute block — see the
#     coverage/limits doc; the categorical block on delete/transfer is a token without
#     the delete_repo scope.
# It has two path-agnostic layers:
#   L1  PATH shim   — a `gh` wrapper installed ahead of the real gh on PATH.
#   L3  Claude hook — a PreToolUse (Bash) hook that also catches gh called by
#                     ABSOLUTE path inside a Claude Code session (the shim's blind
#                     spot). Optional; enable with --with-hook.
#
# Usage:
#   repo-guard-install.sh                 # install the PATH shim
#   repo-guard-install.sh --with-hook     # also install + register the Claude hook
#   repo-guard-install.sh --setup-path    # also prepend the bin dir in shell rc files
#   repo-guard-install.sh --bin-dir DIR   # shim location (default ~/.local/bin)
#   repo-guard-install.sh --status        # show what is installed and whether it resolves
#   repo-guard-install.sh --uninstall     # remove shim + hook (leaves logs)
#   repo-guard-install.sh --dry-run       # print actions without making changes
#   repo-guard-install.sh -h|--help
#
# Nothing here is machine-specific: paths are detected or use $HOME. The real gh is
# located via PATH (excluding the shim), then common install locations.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SHIM_SRC="$HERE/repo-guard/gh-shim.sh"
HOOK_SRC="$HERE/repo-guard/pretool-hook.sh"

BIN_DIR="$HOME/.local/bin"
WITH_HOOK=0
SETUP_PATH=0
STATUS=0
UNINSTALL=0
DRY=0
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-hook) WITH_HOOK=1 ;;
    --setup-path) SETUP_PATH=1 ;;
    --bin-dir) [[ $# -ge 2 ]] || { echo "--bin-dir requires a path" >&2; exit 2; }; BIN_DIR="$2"; shift ;;
    --status) STATUS=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

SHIM_DST="$BIN_DIR/gh"
HOOK_DST="$CLAUDE_DIR/hooks/repo-guard-pretool.sh"
SETTINGS="$CLAUDE_DIR/settings.json"

run() { # echo + execute unless dry-run
  echo "  + $*"
  [[ "$DRY" -eq 1 ]] && return 0
  "$@"
}

# Locate the real gh (never the shim we install).
find_real_gh() {
  local d cand
  IFS=':' read -r -a _p <<< "${PATH:-}"
  for d in "${_p[@]}"; do
    [[ -z "$d" ]] && continue
    cand="$d/gh"
    [[ -x "$cand" && ! -d "$cand" ]] || continue
    [[ "$cand" == "$SHIM_DST" ]] && continue
    # skip anything that is our shim by content
    grep -q 'repo-guard: PATH shim for .gh.' "$cand" 2>/dev/null && continue
    echo "$cand"; return 0
  done
  for cand in /opt/homebrew/bin/gh /usr/local/bin/gh /usr/bin/gh; do
    [[ -x "$cand" ]] && { echo "$cand"; return 0; }
  done
  return 1
}

resolved_gh() { command -v gh 2>/dev/null || true; }

is_our_shim() { grep -q 'repo-guard: PATH shim for .gh.' "$1" 2>/dev/null; }

# ─── status ─────────────────────────────────────────────────────────────────
if [[ "$STATUS" -eq 1 ]]; then
  echo "repo-guard status"
  echo "  shim path      : $SHIM_DST $([[ -f "$SHIM_DST" ]] && is_our_shim "$SHIM_DST" && echo '(installed)' || echo '(absent)')"
  R="$(resolved_gh)"
  echo "  gh resolves to : ${R:-<none on PATH>}"
  if [[ -n "$R" ]] && is_our_shim "$R"; then
    echo "  L1 PATH shim   : ACTIVE (gh on PATH is the guard)"
  else
    echo "  L1 PATH shim   : INACTIVE (gh on PATH is not the guard — check PATH ordering)"
  fi
  echo "  real gh        : $(find_real_gh || echo '<not found>')"
  echo "  Claude hook    : $HOOK_DST $([[ -f "$HOOK_DST" ]] && echo '(installed)' || echo '(absent)')"
  if [[ -f "$SETTINGS" ]] && grep -q 'repo-guard-pretool.sh' "$SETTINGS" 2>/dev/null; then
    echo "  hook registered: yes (in $SETTINGS)"
  else
    echo "  hook registered: no"
  fi
  echo "  log dir        : ${REPO_GUARD_STATE:-$HOME/.local/state/repo-guard}"
  exit 0
fi

# ─── uninstall ──────────────────────────────────────────────────────────────
if [[ "$UNINSTALL" -eq 1 ]]; then
  echo "repo-guard uninstall"
  if [[ -f "$SHIM_DST" ]] && is_our_shim "$SHIM_DST"; then
    run rm -f "$SHIM_DST"
  else
    echo "  - shim not present (or not ours) at $SHIM_DST — leaving it"
  fi
  [[ -f "$HOOK_DST" ]] && run rm -f "$HOOK_DST" || echo "  - no hook at $HOOK_DST"
  if [[ -f "$SETTINGS" ]] && grep -q 'repo-guard-pretool.sh' "$SETTINGS" 2>/dev/null; then
    if [[ "$DRY" -eq 1 ]]; then
      echo "  + would de-register the hook from $SETTINGS"
    else
      python3 - "$SETTINGS" "$HOOK_DST" <<'PY'
import sys, json
settings, hook = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(settings))
except Exception:
    sys.exit(0)
h = d.get("hooks", {})
pt = h.get("PreToolUse", [])
for entry in list(pt):
    entry["hooks"] = [x for x in entry.get("hooks", []) if hook not in str(x.get("command",""))]
pt = [e for e in pt if e.get("hooks")]
if pt:
    h["PreToolUse"] = pt
else:
    h.pop("PreToolUse", None)
if h:
    d["hooks"] = h
else:
    d.pop("hooks", None)
json.dump(d, open(settings,"w"), indent=2)
open(settings,"a").write("\n")
print("  + de-registered repo-guard hook from settings.json")
PY
    fi
  fi
  echo "  NOTE: PATH-rc lines (if you ran --setup-path) are marked 'repo-guard:' — remove them by hand."
  echo "  NOTE: logs under ${REPO_GUARD_STATE:-$HOME/.local/state/repo-guard} are left in place."
  echo "Done. Removing the shim disables the PATH guard immediately."
  exit 0
fi

# ─── install ────────────────────────────────────────────────────────────────
[[ -f "$SHIM_SRC" ]] || { echo "missing shim source: $SHIM_SRC" >&2; exit 1; }
REAL_GH="$(find_real_gh || true)"
if [[ -z "$REAL_GH" ]]; then
  echo "WARN: no real gh found on this machine. The shim will refuse to run blind until gh is installed." >&2
else
  echo "Real gh detected at: $REAL_GH"
fi

echo "Installing PATH shim -> $SHIM_DST"
run mkdir -p "$BIN_DIR"
run cp "$SHIM_SRC" "$SHIM_DST"
run chmod 755 "$SHIM_DST"

# PATH ordering check.
R="$(resolved_gh)"
if [[ -n "$R" ]] && is_our_shim "$R"; then
  echo "PATH check: gh already resolves to the guard. Good."
elif [[ "$SETUP_PATH" -eq 1 ]]; then
  BLOCK="# repo-guard: put the shim ahead of the real gh
case \":\$PATH:\" in *\":$BIN_DIR:\"*) ;; *) export PATH=\"$BIN_DIR:\$PATH\";; esac"
  for rc in "$HOME/.zshenv" "$HOME/.bashrc"; do
    if [[ -f "$rc" ]] && grep -q 'repo-guard: put the shim ahead' "$rc" 2>/dev/null; then
      echo "  = PATH block already present in $rc"
      continue
    fi
    echo "  + appending PATH block to $rc"
    [[ "$DRY" -eq 1 ]] || printf '\n%s\n' "$BLOCK" >> "$rc"
  done
  echo "PATH: open a new shell (or 'source' the rc) for it to take effect."
else
  echo "PATH check: gh does NOT currently resolve to the guard."
  echo "  Add this to your shell rc (or re-run with --setup-path):"
  echo "    export PATH=\"$BIN_DIR:\$PATH\""
fi

# Optional Claude hook.
if [[ "$WITH_HOOK" -eq 1 ]]; then
  [[ -f "$HOOK_SRC" ]] || { echo "missing hook source: $HOOK_SRC" >&2; exit 1; }
  echo "Installing Claude Code hook -> $HOOK_DST"
  run mkdir -p "$CLAUDE_DIR/hooks"
  run cp "$HOOK_SRC" "$HOOK_DST"
  run chmod 755 "$HOOK_DST"
  if [[ "$DRY" -eq 1 ]]; then
    echo "  + would register the hook in $SETTINGS"
  else
    python3 - "$SETTINGS" "$HOOK_DST" <<'PY'
import sys, json, os
settings, hook = sys.argv[1], sys.argv[2]
os.makedirs(os.path.dirname(settings), exist_ok=True)
try:
    d = json.load(open(settings))
except Exception:
    d = {}
hooks = d.setdefault("hooks", {})
pt = hooks.setdefault("PreToolUse", [])
# find a Bash matcher entry
entry = None
for e in pt:
    if e.get("matcher") == "Bash":
        entry = e; break
if entry is None:
    entry = {"matcher": "Bash", "hooks": []}
    pt.append(entry)
cmds = entry.setdefault("hooks", [])
if not any(hook in str(x.get("command","")) for x in cmds):
    cmds.append({"type": "command", "command": hook})
    json.dump(d, open(settings,"w"), indent=2)
    open(settings,"a").write("\n")
    print("  + registered repo-guard hook in settings.json (PreToolUse/Bash)")
else:
    print("  = hook already registered in settings.json")
PY
  fi
  echo "  Claude hook active in NEW sessions (restart Claude Code to load it)."
fi

echo
echo "Verify with: $0 --status"
echo "Test (dry, non-destructive): gh repo view   # should pass through normally"
echo "TIER 1 (rename/archive/privatize): REPO_LIFECYCLE_OK=<owner/repo> gh repo archive <owner/repo>"
echo "TIER 2 (delete/transfer) needs ALL THREE:"
echo "  printf '%s\\n' '<owner/repo>' >> \"\${REPO_GUARD_STATE:-\$HOME/.local/state/repo-guard}/CONFIRM-DESTROY\""
echo "  REPO_LIFECYCLE_OK=<owner/repo> REPO_DESTROY_CONFIRM=<owner/repo> gh repo delete <owner/repo> --yes"
echo "Removal:     $0 --uninstall"
exit 0
