#!/usr/bin/env bash
# Dry-run tests for the repo-lifecycle guard (PATH shim + Claude hook).
# No real GitHub call is ever made: a fake `gh` on PATH stands in for the real
# binary, so passthrough and block behavior are both exercised offline.
# Usage: bash tests/test-guard.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHIM="$ROOT/scripts/repo-guard/gh-shim.sh"
HOOK="$ROOT/scripts/repo-guard/pretool-hook.sh"
FAILURES=0

TMP="$(mktemp -d "${TMPDIR:-/tmp}/repo-guard-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Fake real gh: prints a marker + its args, exits 0. The shim finds it on PATH.
FAKE="$TMP/bin"; mkdir -p "$FAKE"
cat >"$FAKE/gh" <<'SH'
#!/usr/bin/env bash
echo "REAL_GH_CALLED: $*"
exit 0
SH
chmod 755 "$FAKE/gh"

export PATH="$FAKE:$PATH"
export REPO_GUARD_STATE="$TMP/state"   # keep logs out of the real home

check() { # label, expected_exit, expected_needle, cmd...
  local label="$1" expect="$2" needle="$3"; shift 3
  local out code=0
  set +e
  out=$("$@" 2>&1)
  code=$?
  set -e
  local ok=1
  [[ "$code" -eq "$expect" ]] || ok=0
  if [[ -n "$needle" ]] && ! echo "$out" | grep -qF -- "$needle"; then ok=0; fi
  if [[ "$ok" -eq 1 ]]; then
    echo "  ok  $label (exit $code)"
  else
    echo "  XX  $label — expected exit $expect + '$needle', got exit $code"
    echo "$out" | tail -6
    FAILURES=$((FAILURES + 1))
  fi
}

echo "agent-security test-guard — offline fixtures (fake gh)"
echo "---"

# PATH shim (L1)
check "repo view passes through"         0 "REAL_GH_CALLED: repo view"   bash "$SHIM" repo view
check "repo list passes through"         0 "REAL_GH_CALLED"              bash "$SHIM" repo list
check "repo delete is BLOCKED"           1 "BLOCKED a destructive"       bash "$SHIM" repo delete acme/widget --yes
check "repo rename is BLOCKED"           1 "repo rename"                 bash "$SHIM" repo rename newname -R acme/widget
check "repo archive is BLOCKED"          1 "repo archive"               bash "$SHIM" repo archive acme/widget
check "repo transfer is BLOCKED"         1 "repo transfer"              bash "$SHIM" repo transfer acme/widget neworg
check "edit --visibility private BLOCK"  1 "visibility private"         bash "$SHIM" repo edit acme/widget --visibility private
check "edit --visibility public passes"  0 "REAL_GH_CALLED"             bash "$SHIM" repo edit acme/widget --visibility public
check "api DELETE repo root BLOCKED"     1 "repo delete via gh api"     bash "$SHIM" api -X DELETE /repos/acme/widget
check "api DELETE sub-resource passes"   0 "REAL_GH_CALLED"             bash "$SHIM" api -X DELETE /repos/acme/widget/labels/bug
check "api transfer BLOCKED"             1 "repo transfer via gh api"   bash "$SHIM" api -X POST /repos/acme/widget/transfer -f new_owner=neworg

# Override (human-in-the-loop) is honored for the exact repo.
check "override honors exact repo" 0 "REAL_GH_CALLED: repo delete" \
  env REPO_LIFECYCLE_OK=acme/widget bash "$SHIM" repo delete acme/widget --yes
# Wrong-repo override still blocks.
check "mismatched override still blocks" 1 "BLOCKED" \
  env REPO_LIFECYCLE_OK=acme/other bash "$SHIM" repo delete acme/widget --yes

# Claude PreToolUse hook (L3): absolute-path gh the shim cannot see.
hook_call() { printf '%s' "$1" | bash "$HOOK"; }
check "hook blocks absolute-path gh delete" 2 "BLOCKED by repo-guard hook" \
  hook_call '{"tool_input":{"command":"/opt/homebrew/bin/gh repo delete acme/widget --yes"}}'
check "hook passes normal gh view" 0 "" \
  hook_call '{"tool_input":{"command":"gh repo view acme/widget"}}'
check "hook fails closed on garbage input" 2 "" \
  hook_call 'not json at all'
check "hook honors override" 0 "" \
  hook_call '{"tool_input":{"command":"REPO_LIFECYCLE_OK=acme/widget gh repo delete acme/widget --yes"}}'

echo "---"
if [[ "$FAILURES" -eq 0 ]]; then
  echo "OK — all repo-guard fixtures passed"
  exit 0
fi
echo "FAILED — $FAILURES fixture check(s)"
exit 1
