#!/usr/bin/env bash
# research-egress-install.sh — install / status / uninstall the research-egress
# PreToolUse / pre_tool_call hook across agent hosts.
#
# Usage:
#   research-egress-install.sh              # install on all present hosts
#   research-egress-install.sh --status
#   research-egress-install.sh --uninstall
#   research-egress-install.sh --dry-run
#   research-egress-install.sh -h|--help
#
# Hosts:
#   Claude Code  ~/.claude/hooks/block-research-egress.sh + settings.json
#   Grok         ~/.grok/hooks/research-egress.json (+ Claude settings scanned)
#   Codex        ~/.codex/hooks.json + features.hooks=true in config.toml
#   Hermes       ~/.hermes/config.yaml hooks.pre_tool_call + allowlist entry
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
HOOK_SRC="$HERE/research-egress/pretool-hook.sh"
CHECK_URL="$HERE/check-url.sh"

STATUS=0
UNINSTALL=0
DRY=0
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
GROK_DIR="${GROK_HOME:-$HOME/.grok}"
CODEX_DIR="${CODEX_HOME:-$HOME/.codex}"
HERMES_DIR="${HERMES_HOME:-$HOME/.hermes}"

# Broad matcher for Claude/Grok/Codex tool names
MATCHER='Bash|run_terminal_command|shell|terminal|WebFetch|web_fetch|open_page|open_page_with_find|web_extract|WebSearch|web_search|local_shell'
# Hermes tool-name matcher (pre_tool_call)
HERMES_MATCHER='terminal|web_extract|web_search|browser_.*|http_request|code_execution'

while [[ $# -gt 0 ]]; do
  case "$1" in
    --status) STATUS=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

HOOK_DST="$CLAUDE_DIR/hooks/block-research-egress.sh"
# Also copy into codex/hermes agent-hooks for host-local stability
CODEX_HOOK_DST="$CODEX_DIR/hooks/block-research-egress.sh"
HERMES_HOOK_DST="$HERMES_DIR/agent-hooks/block-research-egress.sh"
SETTINGS="$CLAUDE_DIR/settings.json"
GROK_HOOK_JSON="$GROK_DIR/hooks/research-egress.json"
CODEX_HOOKS_JSON="$CODEX_DIR/hooks.json"
CODEX_CONFIG="$CODEX_DIR/config.toml"
HERMES_CONFIG="$HERMES_DIR/config.yaml"
HERMES_ALLOWLIST="$HERMES_DIR/shell-hooks-allowlist.json"

run() {
  echo "  + $*"
  [[ "$DRY" -eq 1 ]] && return 0
  "$@"
}

registered_claude() {
  [[ -f "$SETTINGS" ]] && grep -q 'block-research-egress' "$SETTINGS" 2>/dev/null
}
registered_codex() {
  [[ -f "$CODEX_HOOKS_JSON" ]] && grep -q 'block-research-egress' "$CODEX_HOOKS_JSON" 2>/dev/null
}
registered_hermes() {
  [[ -f "$HERMES_CONFIG" ]] && grep -q 'block-research-egress' "$HERMES_CONFIG" 2>/dev/null
}

# ─── status ─────────────────────────────────────────────────────────────────
if [[ "$STATUS" -eq 1 ]]; then
  echo "research-egress status"
  echo "  hook source     : $HOOK_SRC $([[ -f "$HOOK_SRC" ]] && echo '(ok)' || echo '(MISSING)')"
  echo "  check-url       : $CHECK_URL $([[ -x "$CHECK_URL" ]] && echo '(executable)' || echo '(missing/not +x)')"
  echo "  --- Claude ---"
  echo "  hook            : $HOOK_DST $([[ -f "$HOOK_DST" ]] && echo '(installed)' || echo '(absent)')"
  echo "  settings        : $(registered_claude && echo registered || echo NOT registered)"
  echo "  --- Grok ---"
  echo "  hooks json      : $GROK_HOOK_JSON $([[ -f "$GROK_HOOK_JSON" ]] && echo '(installed)' || echo '(absent)')"
  echo "  --- Codex ---"
  echo "  hook copy       : $CODEX_HOOK_DST $([[ -f "$CODEX_HOOK_DST" ]] && echo '(installed)' || echo '(absent)')"
  echo "  hooks.json      : $(registered_codex && echo registered || echo NOT registered)"
  if [[ -f "$CODEX_CONFIG" ]] && grep -Eq '^\s*hooks\s*=\s*true' "$CODEX_CONFIG" 2>/dev/null; then
    echo "  features.hooks  : true"
  elif [[ -f "$CODEX_CONFIG" ]] && grep -Eq 'codex_hooks\s*=\s*true' "$CODEX_CONFIG" 2>/dev/null; then
    echo "  features.hooks  : codex_hooks=true"
  else
    echo "  features.hooks  : not set in config.toml (feature list may still default on)"
  fi
  echo "  --- Hermes ---"
  echo "  hook copy       : $HERMES_HOOK_DST $([[ -f "$HERMES_HOOK_DST" ]] && echo '(installed)' || echo '(absent)')"
  echo "  config.yaml     : $(registered_hermes && echo registered || echo NOT registered)"
  if [[ -f "$HERMES_ALLOWLIST" ]] && grep -q 'block-research-egress' "$HERMES_ALLOWLIST" 2>/dev/null; then
    echo "  allowlist       : approved"
  else
    echo "  allowlist       : not approved (first run may prompt; or use --accept-hooks)"
  fi
  armed=0
  [[ -f "$HOOK_DST" && -x "$CHECK_URL" ]] && registered_claude && armed=$((armed+1))
  [[ -f "$GROK_HOOK_JSON" ]] && armed=$((armed+1))
  registered_codex && armed=$((armed+1))
  registered_hermes && armed=$((armed+1))
  echo "  hosts armed     : $armed / 4 (claude settings + grok json + codex + hermes)"
  echo "  note            : restart each agent session after install"
  exit 0
fi

# ─── uninstall ──────────────────────────────────────────────────────────────
if [[ "$UNINSTALL" -eq 1 ]]; then
  echo "research-egress uninstall"
  [[ -f "$HOOK_DST" ]] && run rm -f "$HOOK_DST" || true
  [[ -f "$GROK_HOOK_JSON" ]] && run rm -f "$GROK_HOOK_JSON" || true
  [[ -f "$CODEX_HOOK_DST" ]] && run rm -f "$CODEX_HOOK_DST" || true
  [[ -f "$HERMES_HOOK_DST" ]] && run rm -f "$HERMES_HOOK_DST" || true

  if registered_claude && [[ "$DRY" -eq 0 ]]; then
    python3 - "$SETTINGS" "block-research-egress" <<'PY'
import sys, json
settings, needle = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(settings))
except Exception:
    sys.exit(0)
h = d.get("hooks", {})
pt = h.get("PreToolUse", [])
for entry in list(pt):
    entry["hooks"] = [x for x in entry.get("hooks", []) if needle not in str(x.get("command", ""))]
pt = [e for e in pt if e.get("hooks")]
if pt:
    h["PreToolUse"] = pt
else:
    h.pop("PreToolUse", None)
if h:
    d["hooks"] = h
else:
    d.pop("hooks", None)
json.dump(d, open(settings, "w"), indent=2)
open(settings, "a").write("\n")
print("  + de-registered from Claude settings.json")
PY
  fi

  if registered_codex && [[ "$DRY" -eq 0 ]]; then
    python3 - "$CODEX_HOOKS_JSON" "block-research-egress" <<'PY'
import sys, json, os
path, needle = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(path))
except Exception:
    sys.exit(0)
# support both {hooks:{PreToolUse:[...]}} and {PreToolUse:[...]}
root = d.get("hooks") if isinstance(d.get("hooks"), dict) else d
pt = root.get("PreToolUse", []) if isinstance(root, dict) else []
new_pt = []
for entry in pt:
    if not isinstance(entry, dict):
        continue
    hooks = entry.get("hooks")
    if isinstance(hooks, list):
        entry["hooks"] = [x for x in hooks if needle not in str(x.get("command", ""))]
        if entry["hooks"]:
            new_pt.append(entry)
    else:
        # flat form: {"command": "..."} entries
        if needle not in str(entry.get("command", "")):
            new_pt.append(entry)
if isinstance(d.get("hooks"), dict):
    if new_pt:
        d["hooks"]["PreToolUse"] = new_pt
    else:
        d["hooks"].pop("PreToolUse", None)
        if not d["hooks"]:
            d.pop("hooks", None)
else:
    if new_pt:
        d["PreToolUse"] = new_pt
    else:
        d.pop("PreToolUse", None)
json.dump(d, open(path, "w"), indent=2)
open(path, "a").write("\n")
print("  + de-registered from Codex hooks.json")
PY
  fi

  if registered_hermes && [[ "$DRY" -eq 0 ]]; then
    python3 - "$HERMES_CONFIG" "$HERMES_ALLOWLIST" "block-research-egress" <<'PY'
import sys, re
from pathlib import Path
cfg_path, allow_path, needle = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    import yaml
except ImportError:
    # strip lines containing needle as best-effort without PyYAML
    text = Path(cfg_path).read_text()
    lines = [ln for ln in text.splitlines() if needle not in ln]
    Path(cfg_path).write_text("\n".join(lines) + ("\n" if lines else ""))
    print("  + stripped hermes config lines containing block-research-egress (no PyYAML)")
    sys.exit(0)

data = yaml.safe_load(Path(cfg_path).read_text()) or {}
hooks = data.get("hooks") or {}
if isinstance(hooks, dict):
    for ev in list(hooks.keys()):
        entries = hooks.get(ev) or []
        if not isinstance(entries, list):
            continue
        hooks[ev] = [e for e in entries if not (isinstance(e, dict) and needle in str(e.get("command", "")))]
        if not hooks[ev]:
            del hooks[ev]
    if hooks:
        data["hooks"] = hooks
    else:
        data["hooks"] = {}
Path(cfg_path).write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
print("  + de-registered from Hermes config.yaml")
ap = Path(allow_path)
if ap.is_file():
    import json
    try:
        al = json.loads(ap.read_text())
    except Exception:
        al = {"approvals": []}
    al["approvals"] = [
        e for e in al.get("approvals", [])
        if not (isinstance(e, dict) and needle in str(e.get("command", "")))
    ]
    ap.write_text(json.dumps(al, indent=2) + "\n")
    print("  + removed Hermes allowlist entries")
PY
  fi

  echo "Done. Restart agent sessions so the hook is unloaded."
  exit 0
fi

# ─── install ────────────────────────────────────────────────────────────────
[[ -f "$HOOK_SRC" ]] || { echo "missing hook source: $HOOK_SRC" >&2; exit 1; }
[[ -x "$CHECK_URL" ]] || { echo "check-url.sh missing or not executable: $CHECK_URL" >&2; exit 1; }

echo "Installing research-egress fetch gate (Claude + Grok + Codex + Hermes)"

# Canonical script lives under Claude hooks (shared path)
run mkdir -p "$CLAUDE_DIR/hooks"
run cp "$HOOK_SRC" "$HOOK_DST"
run chmod 755 "$HOOK_DST"

if [[ "$DRY" -eq 1 ]]; then
  echo "  + would register Claude settings matcher=$MATCHER"
  echo "  + would write $GROK_HOOK_JSON"
  echo "  + would write $CODEX_HOOKS_JSON + enable features.hooks"
  echo "  + would register Hermes pre_tool_call + allowlist"
  exit 0
fi

# ── Claude settings.json ────────────────────────────────────────────────────
python3 - "$SETTINGS" "$HOOK_DST" "$MATCHER" <<'PY'
import sys, json, os
settings, hook, matcher = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(os.path.dirname(settings), exist_ok=True)
try:
    d = json.load(open(settings))
except Exception:
    d = {}
hooks = d.setdefault("hooks", {})
pt = hooks.setdefault("PreToolUse", [])
entry = None
for e in pt:
    if e.get("matcher") == matcher or "block-research-egress" in json.dumps(e):
        entry = e
        break
if entry is None:
    entry = {"matcher": matcher, "hooks": []}
    pt.append(entry)
else:
    entry["matcher"] = matcher
cmds = entry.setdefault("hooks", [])
if not any("block-research-egress" in str(x.get("command", "")) for x in cmds):
    cmds.append({"type": "command", "command": hook, "timeout": 15})
    print("  + Claude: registered PreToolUse")
else:
    # refresh path
    for x in cmds:
        if "block-research-egress" in str(x.get("command", "")):
            x["command"] = hook
            x["timeout"] = 15
    print("  = Claude: already registered (path refreshed)")
json.dump(d, open(settings, "w"), indent=2)
open(settings, "a").write("\n")
PY

# ── Grok ────────────────────────────────────────────────────────────────────
mkdir -p "$GROK_DIR/hooks"
cat >"$GROK_HOOK_JSON" <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "${MATCHER}",
        "hooks": [
          {
            "type": "command",
            "command": "${HOOK_DST}",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
EOF
echo "  + Grok: wrote $GROK_HOOK_JSON"

# ── Codex ───────────────────────────────────────────────────────────────────
mkdir -p "$CODEX_DIR/hooks"
cp "$HOOK_SRC" "$CODEX_HOOK_DST"
chmod 755 "$CODEX_HOOK_DST"
python3 - "$CODEX_HOOKS_JSON" "$CODEX_HOOK_DST" "$MATCHER" <<'PY'
import sys, json, os
path, hook, matcher = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
try:
    d = json.load(open(path))
except Exception:
    d = {}
# Prefer Claude-compatible wrapper
if "hooks" not in d or not isinstance(d.get("hooks"), dict):
    # migrate flat PreToolUse if present
    flat = {k: v for k, v in d.items() if k != "hooks"}
    d = {"hooks": flat} if flat else {"hooks": {}}
hooks = d["hooks"]
pt = hooks.setdefault("PreToolUse", [])
entry = None
for e in pt:
    if isinstance(e, dict) and (
        e.get("matcher") == matcher or "block-research-egress" in json.dumps(e)
    ):
        entry = e
        break
if entry is None:
    entry = {"matcher": matcher, "hooks": []}
    pt.append(entry)
else:
    entry["matcher"] = matcher
cmds = entry.setdefault("hooks", [])
if not isinstance(cmds, list):
    cmds = []
    entry["hooks"] = cmds
if not any("block-research-egress" in str(x.get("command", "")) for x in cmds if isinstance(x, dict)):
    cmds.append({
        "type": "command",
        "command": hook,
        "timeout": 15,
        "statusMessage": "research-egress URL check",
    })
    print("  + Codex: registered hooks.json PreToolUse")
else:
    for x in cmds:
        if isinstance(x, dict) and "block-research-egress" in str(x.get("command", "")):
            x["command"] = hook
            x["timeout"] = 15
    print("  = Codex: already registered (path refreshed)")
json.dump(d, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY

# Enable features.hooks in config.toml if missing
if [[ -f "$CODEX_CONFIG" ]]; then
  if ! grep -Eq '^\s*hooks\s*=\s*true' "$CODEX_CONFIG" 2>/dev/null \
     && ! grep -Eq 'codex_hooks\s*=\s*true' "$CODEX_CONFIG" 2>/dev/null; then
    if grep -q '^\[features\]' "$CODEX_CONFIG" 2>/dev/null; then
      # insert hooks = true after [features]
      python3 - "$CODEX_CONFIG" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
text = p.read_text()
if "[features]" in text and "hooks" not in text.split("[features]", 1)[1].split("[", 1)[0]:
    text = text.replace("[features]", "[features]\nhooks = true", 1)
    p.write_text(text)
    print("  + Codex: set features.hooks = true in config.toml")
else:
    print("  = Codex: features section already mentions hooks or missing [features]")
PY
    else
      printf '\n[features]\nhooks = true\n' >>"$CODEX_CONFIG"
      echo "  + Codex: appended [features] hooks = true to config.toml"
    fi
  else
    echo "  = Codex: features.hooks already enabled"
  fi
else
  mkdir -p "$CODEX_DIR"
  cat >"$CODEX_CONFIG" <<'EOF'
[features]
hooks = true
EOF
  echo "  + Codex: created config.toml with features.hooks = true"
fi

# ── Hermes ──────────────────────────────────────────────────────────────────
mkdir -p "$HERMES_DIR/agent-hooks"
cp "$HOOK_SRC" "$HERMES_HOOK_DST"
chmod 755 "$HERMES_HOOK_DST"

# Prefer a Python that has PyYAML — a system python3 often lacks it, while the host's
# own virtualenv usually has it. Set HERMES_PYTHON to point at a specific interpreter;
# the relative candidate covers a venv sitting alongside the config directory.
HERMES_PY=""
for cand in \
  "${HERMES_PYTHON:-}" \
  "$HERMES_DIR/.venv/bin/python" \
  "$HERMES_DIR/../hermes-agent/.venv/bin/python" \
  python3
do
  [[ -n "$cand" && -x "$cand" ]] || continue
  if "$cand" -c 'import yaml' 2>/dev/null; then
    HERMES_PY="$cand"
    break
  fi
done
[[ -n "$HERMES_PY" ]] || HERMES_PY=python3

"$HERMES_PY" - "$HERMES_CONFIG" "$HERMES_HOOK_DST" "$HERMES_MATCHER" "$HERMES_ALLOWLIST" <<'PY'
import sys, json
from pathlib import Path
from datetime import datetime, timezone

cfg_path, hook_cmd, matcher, allow_path = sys.argv[1:5]
Path(cfg_path).parent.mkdir(parents=True, exist_ok=True)

try:
    import yaml
except ImportError as e:
    print("  ! Hermes: PyYAML unavailable (%s) — cannot safely merge config.yaml" % e)
    print("    Install PyYAML or re-run with HERMES_PYTHON=/path/to/hermes/.venv/bin/python")
    sys.exit(1)

if Path(cfg_path).is_file():
    data = yaml.safe_load(Path(cfg_path).read_text()) or {}
else:
    data = {}
if not isinstance(data, dict):
    data = {}
hooks = data.get("hooks")
if not isinstance(hooks, dict):
    hooks = {}
entries = hooks.get("pre_tool_call")
if not isinstance(entries, list):
    entries = []
entries = [
    e for e in entries
    if not (isinstance(e, dict) and "block-research-egress" in str(e.get("command", "")))
]
entries.append({
    "matcher": matcher,
    "command": hook_cmd,
    "timeout": 15,
})
hooks["pre_tool_call"] = entries
data["hooks"] = hooks
Path(cfg_path).write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
print("  + Hermes: registered hooks.pre_tool_call in config.yaml")

al_path = Path(allow_path)
try:
    al = json.loads(al_path.read_text()) if al_path.is_file() else {"approvals": []}
except Exception:
    al = {"approvals": []}
if not isinstance(al, dict):
    al = {"approvals": []}
approvals = al.get("approvals")
if not isinstance(approvals, list):
    approvals = []
approvals = [
    e for e in approvals
    if not (isinstance(e, dict) and e.get("event") == "pre_tool_call" and e.get("command") == hook_cmd)
]
mtime = None
try:
    mtime = datetime.fromtimestamp(Path(hook_cmd).stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
except Exception:
    pass
approvals.append({
    "event": "pre_tool_call",
    "command": hook_cmd,
    "approved_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "script_mtime_at_approval": mtime,
})
al["approvals"] = approvals
al_path.write_text(json.dumps(al, indent=2) + "\n")
print("  + Hermes: allowlisted pre_tool_call (no first-use prompt)")
PY

echo
echo "research-egress installed on Claude + Grok + Codex + Hermes."
echo "  Canonical script : $HOOK_DST"
echo "  Restart each agent session to load hooks."
echo "  Verify: $0 --status"
echo "  Smoke:  printf '%s' '{\"tool_name\":\"web_fetch\",\"tool_input\":{\"url\":\"https://x.com/a.exe\"}}' | $HOOK_DST ; echo exit=\$?"
exit 0
