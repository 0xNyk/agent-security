#!/usr/bin/env bash
# research-egress PreToolUse hook — hard-block unsafe external fetches.
#
# Companion to scripts/check-url.sh + references/safe-research.md.
# Mechanically enforces BLOCK (and default-deny REVIEW) so agents cannot open
# random PDFs, archives, installers, file:/data: URLs, or shortener/IP-host
# shapes without an explicit operator override for REVIEW.
#
#   exit 2 BLOCKS the tool call (Claude Code + Grok).
#   Also emits Grok-compatible JSON: {"decision":"deny","reason":"..."}.
#   Non-fetch tools / no download URLs → allow (exit 0).
#
# Tools watched (matcher should include these):
#   Bash / run_terminal_command  — curl/wget/… URLs in the command
#   WebFetch / web_fetch
#   open_page / open_page_with_find
#
# Policy:
#   BLOCK  → always deny (no env override — do it outside the agent)
#   REVIEW → deny unless RESEARCH_URL_OK equals the exact URL
#   ALLOW  → pass
#
# Optional: RESEARCH_EGRESS_OFF=1 disables the hook (operator emergency only).

set -uo pipefail

input=$(cat)

if [[ "${RESEARCH_EGRESS_OFF:-}" == "1" ]]; then
  exit 0
fi

# Locate check-url.sh. Resolution order is deliberate: an explicit override first,
# then a configured checkout root, then paths relative to this hook — which is where
# it will be when the hook is installed from a clone. Set RESEARCH_EGRESS_CHECK_URL
# or AGENT_SECURITY_ROOT if your layout differs; no machine-specific path is baked in.
SKILL_CHECK_URL=""
for cand in \
  "${RESEARCH_EGRESS_CHECK_URL:-}" \
  "${AGENT_SECURITY_ROOT:+$AGENT_SECURITY_ROOT/scripts/check-url.sh}" \
  "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)/check-url.sh" \
  "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)/scripts/check-url.sh"
do
  [[ -n "${cand:-}" && -x "$cand" ]] && { SKILL_CHECK_URL="$cand"; break; }
done

# Python code as -c so stdin remains the hook JSON payload.
# shellcheck disable=SC2016
verdict=$(
  printf '%s' "$input" | CHECK_URL_BIN="$SKILL_CHECK_URL" \
    RESEARCH_URL_OK_ENV="${RESEARCH_URL_OK:-}" \
    python3 -c '
import sys, json, re, os, subprocess

def emit(kind, reason, urls=""):
    print("%s\t%s\t%s" % (kind, reason, urls))
    sys.exit(0)

raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception:
    emit("BLOCK", "unparseable hook input (failing closed)", "")

tool = str(d.get("tool_name") or d.get("toolName") or d.get("tool") or "").strip()
ti = d.get("tool_input") if isinstance(d.get("tool_input"), dict) else None
if ti is None:
    ti = d.get("toolInput") if isinstance(d.get("toolInput"), dict) else {}
if not isinstance(ti, dict):
    ti = {}

tlow = tool.lower().replace("-", "_")
FETCH_TOOLS = {
    "webfetch", "web_fetch", "open_page", "open_page_with_find",
    "browse_page", "browser_navigate", "web_extract", "webextract",
    "browser_navigate_to", "browser_open", "fetch_url", "http_request",
}
SHELL_TOOLS = {
    "bash", "run_terminal_command", "shell", "terminal",
    "local_shell", "shell_command", "exec_command", "unified_exec",
}

is_fetch = tlow in FETCH_TOOLS
is_shell = tlow in SHELL_TOOLS
# Hermes / some hosts put shell under terminal; treat any tool with a downloadish command
if not tool and ti.get("command"):
    is_shell = True

if not is_fetch and not is_shell:
    emit("OK", "not a watched fetch tool", "")

urls = []

def add_url(u):
    if u is None:
        return
    u = str(u).strip()
    if len(u) >= 2 and u[0] == u[-1] and u[0] in ("\x27", "\""):
        u = u[1:-1]
    u = u.rstrip(").,;]>\"\x27")
    if not u:
        return
    if re.match(r"^(https?|file|data|javascript|vbscript|blob|ftp|sftp):", u, re.I):
        if u not in urls:
            urls.append(u)

if is_fetch:
    for k in ("url", "uri", "href", "target_url", "page_url"):
        add_url(ti.get(k))
    raw_list = ti.get("urls") or ti.get("links")
    if isinstance(raw_list, list):
        for x in raw_list:
            add_url(x)

cmd = str(ti.get("command") or "")
if is_shell and cmd.strip():
    downloadish = re.search(
        r"(^|[\s;&|`(])(curl|wget|httpie|aria2c|"
        r"python3?\s+-m\s+urllib|"
        r"node\s+-e\b)",
        cmd,
        re.I,
    )
    httpie = re.search(r"(^|[\s;&|`(])http\s+(https?://|GET\s|POST\s)", cmd, re.I)
    pipe_install = re.search(
        r"(curl|wget)\b[^\n|]*\|\s*(bash|sh|zsh|python|node)",
        cmd,
        re.I,
    )
    if downloadish or httpie or pipe_install:
        for m in re.finditer(
            r"(?i)\b((?:https?|file|ftp|sftp|data|javascript|vbscript|blob):[^\s\"\x27<>\\\\]+)",
            cmd,
        ):
            add_url(m.group(1))

if not urls:
    emit("OK", "no fetch URL found", "")

check_bin = os.environ.get("CHECK_URL_BIN", "")
if not check_bin or not os.path.isfile(check_bin) or not os.access(check_bin, os.X_OK):
    emit("BLOCK", "check-url.sh not found — research-egress fail-closed", ",".join(urls))

override = os.environ.get("RESEARCH_URL_OK_ENV", "").strip()

def url_matches_override(u, ov):
    if not ov:
        return False
    if u == ov:
        return True
    def norm(x):
        x = x.split("#", 1)[0]
        if len(x) > 8 and x.endswith("/"):
            x = x[:-1]
        return x
    return norm(u) == norm(ov)

worst = "ALLOW"
worst_reason = "ok"
worst_url = ""

for u in urls:
    try:
        p = subprocess.run(
            [check_bin, "--quiet", u],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as e:
        emit("BLOCK", "check-url failed: %s" % e, u)

    code = p.returncode
    if code == 0:
        v = "ALLOW"
    elif code == 1:
        v = "REVIEW"
    else:
        v = "BLOCK"

    reason = v.lower()
    if v != "ALLOW":
        try:
            p2 = subprocess.run(
                [check_bin, u],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in (p2.stdout or "").splitlines():
                if "reasons:" in line:
                    reason = line.split("reasons:", 1)[1].strip()
                    break
        except Exception:
            pass

    if v == "BLOCK":
        worst, worst_reason, worst_url = "BLOCK", reason, u
        break
    if v == "REVIEW" and worst != "BLOCK":
        if url_matches_override(u, override):
            continue
        worst, worst_reason, worst_url = "REVIEW", reason, u

if worst == "ALLOW":
    emit("OK", "all URLs ALLOW", ",".join(urls))
elif worst == "REVIEW":
    emit("REVIEW", worst_reason, worst_url)
else:
    emit("BLOCK", worst_reason, worst_url)
'
)

kind="${verdict%%$'\t'*}"
rest="${verdict#*$'\t'}"
reason="${rest%%$'\t'*}"
url="${rest#*$'\t'}"

deny() {
  local msg="$1"
  # Multi-host JSON (single object — first valid parse wins on each host):
  #   Hermes shell hooks → decision:block | action:block
  #   Codex             → permissionDecision:deny (+ exit 2)
  #   Grok              → exit 2 (also accepts decision:deny; exit 2 is primary)
  #   Claude Code       → exit 2 + stderr
  python3 -c '
import json, sys
msg = sys.argv[1]
print(json.dumps({
    "decision": "block",
    "reason": msg,
    "action": "block",
    "message": msg,
    "permissionDecision": "deny",
    "permissionDecisionReason": msg,
}, ensure_ascii=False))
' "$msg"
  echo "BLOCKED by research-egress hook: $msg" >&2
  echo "Safe-research: primary sources only; no random PDFs/archives/installers." >&2
  echo "  classify:  scripts/check-url.sh '<url>'" >&2
  echo "  REVIEW OK: RESEARCH_URL_OK='<exact-url>' <command>" >&2
  echo "  BLOCK: no override — open outside the agent if you must." >&2
  echo "  contract: references/safe-research.md" >&2
  exit 2
}

case "$kind" in
  OK) exit 0 ;;
  REVIEW) deny "REVIEW URL needs operator approval (reason: ${reason}). url=${url}" ;;
  BLOCK) deny "BLOCK URL refused (reason: ${reason}). url=${url}" ;;
  *) deny "research-egress internal error (verdict='${verdict}')" ;;
esac
