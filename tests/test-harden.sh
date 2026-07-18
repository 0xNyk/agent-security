#!/usr/bin/env bash
# Offline fixture tests for harden-check.sh — the unit-testable core is the token
# scope parsing. We feed mocked `gh auth status` outputs via --auth-status-file and
# assert the tier + exit code. No network, no real gh call, no machine changes.
# Fixtures carry NO token-shaped literals (only the scopes line matters to parsing).
# Usage: bash tests/test-harden.sh
#
# Three token states are the whole point (see harden-check.sh):
#   (a) readable + delete_repo    -> HIGH,    exit 1
#   (b) readable + no delete_repo -> OK,      exit 0
#   (c) COULD-NOT-VERIFY          -> UNKNOWN, exit 3  (DEGRADED, never benign)
# State (c) is the false-comfort fix: a token we could not READ (keyring/permission
# blocked, gh not logged in here, command failed, fine-grained scopes not printed)
# must NOT be reported as a benign pass.
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
# State (c) fixture 1: keyring/credential error — gh CANNOT read the token here.
cat >"$TMP/error.txt" <<'EOF'
github.com
  X Failed to log in to github.com account demo (keyring)
  - The token in keyring is invalid.
EOF
# State (c) fixture 2: not logged in at all in this context.
cat >"$TMP/notloggedin.txt" <<'EOF'
You are not logged into any GitHub hosts. To log in, run: gh auth login
EOF
# State (c) fixture 3: authenticated, but fine-grained PAT — no classic scopes line,
# so delete capability cannot be confirmed from here.
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
    echo "$out" | grep -E 'HIGH|MED|OK|WARN|HARDEN' | head -4
    FAILURES=$((FAILURES + 1))
  fi
}

echo "agent-security test-harden — offline scope-parsing fixtures"
echo "---"
run "delete_repo scope   -> HIGH,    exit 1" 1 "token=HIGH"               "$TMP/with.txt"
run "no delete_repo      -> OK,      exit 0" 0 "token=OK"                 "$TMP/without.txt"
run "keyring error       -> UNKNOWN, exit 3" 3 "token=UNKNOWN"            "$TMP/error.txt"
run "not logged in       -> UNKNOWN, exit 3" 3 "token=UNKNOWN"            "$TMP/notloggedin.txt"
run "fine-grained PAT    -> UNKNOWN, exit 3" 3 "token=UNKNOWN_FINEGRAINED" "$TMP/finegrained.txt"

# The could-not-verify states MUST carry the honest "do NOT treat this as safe" line
# and must NOT be counted as a pass. Assert both, in brief and full output.
for f in error notloggedin finegrained; do
  OUT="$(bash "$CHECK" --offline --brief --auth-status-file "$TMP/$f.txt" 2>&1 || true)"
  if echo "$OUT" | grep -qF "do NOT treat this as safe"; then
    echo "  ok  $f states 'do NOT treat this as safe'"
  else
    echo "  XX  $f missing 'do NOT treat this as safe' warning"; FAILURES=$((FAILURES + 1))
  fi
done

# Non-brief: a could-not-verify run must render the DEGRADED verdict and must NEVER
# print the clear 'no confirmed HIGH exposure' pass line (the false-comfort bug).
set +e
OUT_UNK="$(bash "$CHECK" --offline --auth-status-file "$TMP/error.txt" 2>&1)"
CODE_UNK=$?
set -e
if [[ "$CODE_UNK" -eq 3 ]] && echo "$OUT_UNK" | grep -qF "VERDICT: DEGRADED"; then
  echo "  ok  could-not-verify renders DEGRADED verdict (exit 3)"
else
  echo "  XX  could-not-verify did not render DEGRADED verdict / exit 3 (got exit $CODE_UNK)"; FAILURES=$((FAILURES + 1))
fi
if echo "$OUT_UNK" | grep -qF "VERDICT: no confirmed HIGH exposure"; then
  echo "  XX  FALSE COMFORT: could-not-verify run printed the clear-pass verdict"; FAILURES=$((FAILURES + 1))
else
  echo "  ok  could-not-verify does NOT print the clear-pass verdict"
fi

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
