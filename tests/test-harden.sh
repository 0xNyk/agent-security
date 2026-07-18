#!/usr/bin/env bash
# Offline fixture tests for harden-check.sh — the unit-testable core is the token
# scope parsing. We feed mocked `gh auth status` outputs via --auth-status-file and
# assert the tier + exit code. No network, no real gh call, no machine changes.
# Fixtures carry NO token-shaped literals (only the scopes line matters to parsing).
# Usage: bash tests/test-harden.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/harden-check.sh"
FAILURES=0

TMP="$(mktemp -d "${TMPDIR:-/tmp}/harden-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
export NO_COLOR=1

# Mock gh auth status outputs (synthetic — no real token; token line omitted on
# purpose so no credential-shaped literal is ever written to disk).
cat >"$TMP/with.txt" <<'EOF'
github.com
  Logged in to github.com account demo (keyring)
  - Active account: true
  - Token scopes: 'gist', 'read:org', 'repo', 'workflow', 'delete_repo'
EOF
cat >"$TMP/without.txt" <<'EOF'
github.com
  Logged in to github.com account demo (keyring)
  - Active account: true
  - Token scopes: 'read:org', 'repo', 'workflow'
EOF
cat >"$TMP/invalid.txt" <<'EOF'
github.com
  X Failed to log in to github.com account demo (keyring)
  - The token in keyring is invalid.
EOF
cat >"$TMP/finegrained.txt" <<'EOF'
github.com
  Logged in to github.com account demo (keyring)
  - Active account: true
EOF

run() { # label expected_exit needle authfile
  local label="$1" expect="$2" needle="$3" af="$4"
  local out code=0
  set +e
  out=$(bash "$CHECK" --offline --brief --auth-status-file "$af" 2>&1)
  code=$?
  set -e
  local ok=1
  [[ "$code" -eq "$expect" ]] || ok=0
  echo "$out" | grep -qF -- "$needle" || ok=0
  if [[ "$ok" -eq 1 ]]; then
    echo "  ok  $label (exit $code)"
  else
    echo "  XX  $label — expected exit $expect + '$needle', got exit $code"
    echo "$out" | grep -E 'HIGH|MED|OK|HARDEN' | head -4
    FAILURES=$((FAILURES + 1))
  fi
}

echo "agent-security test-harden — offline scope-parsing fixtures"
echo "---"
run "delete_repo scope -> HIGH, exit 1"   1 "token=HIGH"        "$TMP/with.txt"
run "no delete_repo    -> OK,   exit 0"   0 "token=OK"          "$TMP/without.txt"
run "invalid token     -> MED,  exit 0"   0 "token=INVALID"     "$TMP/invalid.txt"
run "fine-grained PAT  -> caveat, exit 0" 0 "token=FINE_GRAINED" "$TMP/finegrained.txt"

# The HIGH case must name the bypass thesis (the load-bearing framing).
OUT_HIGH="$(bash "$CHECK" --offline --auth-status-file "$TMP/with.txt" 2>&1 || true)"
if echo "$OUT_HIGH" | grep -qF "bypassable"; then
  echo "  ok  HIGH report states the guard is bypassable"
else
  echo "  XX  HIGH report missing the 'bypassable' residual-risk framing"; FAILURES=$((FAILURES + 1))
fi
if echo "$OUT_HIGH" | grep -qi "delete_repo on the automation path"; then
  echo "  ok  prevention mapping names the token-scope fix"
else
  echo "  XX  prevention mapping missing token-scope fix"; FAILURES=$((FAILURES + 1))
fi

echo "---"
if [[ "$FAILURES" -eq 0 ]]; then
  echo "OK — all harden-check fixtures passed"
  exit 0
fi
echo "FAILED — $FAILURES fixture check(s)"
exit 1
