#!/usr/bin/env bash
# Dry-run tests for the repo-lifecycle guard (PATH shim + Claude hook), two-tier model.
# No real GitHub call is ever made: a fake `gh` on PATH stands in for the real
# binary, so passthrough and block behavior are both exercised offline.
#
# Two tiers:
#   TIER 1 (single REPO_LIFECYCLE_OK): rename, archive, edit --visibility private/internal.
#   TIER 2 (triple confirmation):      delete, transfer (+ api/graphql equivalents).
#     needs (1) REPO_LIFECYCLE_OK=<owner/repo> (2) REPO_DESTROY_CONFIRM=<owner/repo>
#     (3) a line == <owner/repo> in $REPO_GUARD_STATE/CONFIRM-DESTROY (consumed on use).
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
export REPO_GUARD_STATE="$TMP/state"   # keep logs + CONFIRM-DESTROY out of the real home
CF="$REPO_GUARD_STATE/CONFIRM-DESTROY"
mkdir -p "$REPO_GUARD_STATE"
R="acme/widget"                        # fake repo used throughout
GHP="/opt/homebrew/bin/gh"             # absolute-path gh (shim blind spot; hook covers it)

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
    echo "$out" | tail -8
    FAILURES=$((FAILURES + 1))
  fi
}

assert_cf() { # label, expected_content
  local label="$1" want="$2" got
  got="$(cat "$CF" 2>/dev/null || true)"
  if [[ "$got" == "$want" ]]; then
    echo "  ok  $label"
  else
    echo "  XX  $label — CONFIRM-DESTROY=[$got] expected [$want]"
    FAILURES=$((FAILURES + 1))
  fi
}

seed_cf() { printf '%s\n' "$1" > "$CF"; }
clear_cf() { rm -f "$CF"; }

echo "agent-security test-guard — offline fixtures (fake gh), two-tier model"
echo "--- PATH shim (L1): passthrough + TIER 1 (single confirm) ---"
check "repo view passes through"         0 "REAL_GH_CALLED: repo view"   bash "$SHIM" repo view
check "repo list passes through"         0 "REAL_GH_CALLED"              bash "$SHIM" repo list
check "T1 repo rename BLOCKED"           1 "BLOCKED a destructive"       bash "$SHIM" repo rename newname -R "$R"
check "T1 rename +LIFECYCLE passes"      0 "REAL_GH_CALLED: repo rename" env REPO_LIFECYCLE_OK="$R" bash "$SHIM" repo rename newname -R "$R"
check "T1 repo archive BLOCKED"          1 "repo archive"               bash "$SHIM" repo archive "$R"
check "T1 archive +LIFECYCLE passes"     0 "REAL_GH_CALLED: repo archive" env REPO_LIFECYCLE_OK="$R" bash "$SHIM" repo archive "$R"
check "T1 edit --visibility private BLK" 1 "visibility private"         bash "$SHIM" repo edit "$R" --visibility private
check "T1 privatize +LIFECYCLE passes"   0 "REAL_GH_CALLED"             env REPO_LIFECYCLE_OK="$R" bash "$SHIM" repo edit "$R" --visibility private
check "edit --visibility public passes"  0 "REAL_GH_CALLED"             bash "$SHIM" repo edit "$R" --visibility public
check "T1 api PATCH name BLOCKED"        1 "repo mutate via gh api"     bash "$SHIM" api -X PATCH /repos/"$R" -f name=renamed
check "api DELETE sub-resource passes"   0 "REAL_GH_CALLED"             bash "$SHIM" api -X DELETE /repos/"$R"/labels/bug
check "api GET repo-root passes"         0 "REAL_GH_CALLED"             bash "$SHIM" api /repos/"$R"

echo "--- PATH shim (L1): TIER 2 (triple confirmation) delete ---"
clear_cf
check "T2 delete NONE -> BLOCK"          1 "BLOCKED a TIER-2"           bash "$SHIM" repo delete "$R" --yes
check "T2 delete NONE lists all 3"       1 "3. a line '$R'"             bash "$SHIM" repo delete "$R" --yes
check "T2 delete +LIFECYCLE only BLOCK"  1 "2. REPO_DESTROY_CONFIRM=$R" env REPO_LIFECYCLE_OK="$R" bash "$SHIM" repo delete "$R" --yes
check "T2 delete +2 (no file) BLOCK"     1 "3. a line '$R'"             env REPO_LIFECYCLE_OK="$R" REPO_DESTROY_CONFIRM="$R" bash "$SHIM" repo delete "$R" --yes
# ALL THREE -> passes the guard, and consumes the single-use line
seed_cf "$R"
check "T2 delete ALL THREE -> PASS"      0 "REAL_GH_CALLED: repo delete" env REPO_LIFECYCLE_OK="$R" REPO_DESTROY_CONFIRM="$R" bash "$SHIM" repo delete "$R" --yes
assert_cf "T2 delete consumed the file line (single-use)" ""
# Second attempt, same env, line now gone -> BLOCK
check "T2 delete replay (line gone) BLK" 1 "3. a line '$R'"            env REPO_LIFECYCLE_OK="$R" REPO_DESTROY_CONFIRM="$R" bash "$SHIM" repo delete "$R" --yes
# Mismatch: all three name a DIFFERENT repo than the delete target -> BLOCK, other line kept
seed_cf "acme/other"
check "T2 delete MISMATCH -> BLOCK"      1 "BLOCKED a TIER-2"          env REPO_LIFECYCLE_OK="acme/other" REPO_DESTROY_CONFIRM="acme/other" bash "$SHIM" repo delete "$R" --yes
assert_cf "T2 mismatch did NOT consume the other repo's line" "acme/other"
clear_cf

echo "--- PATH shim (L1): TIER 2 transfer + api/graphql routing ---"
check "T2 transfer NONE -> BLOCK"        1 "BLOCKED a TIER-2"          bash "$SHIM" repo transfer "$R" neworg
seed_cf "$R"
check "T2 transfer ALL THREE -> PASS"    0 "REAL_GH_CALLED: repo transfer" env REPO_LIFECYCLE_OK="$R" REPO_DESTROY_CONFIRM="$R" bash "$SHIM" repo transfer "$R" neworg
assert_cf "T2 transfer consumed the file line" ""
clear_cf
check "T2 api DELETE repo-root BLOCK"    1 "BLOCKED a TIER-2"          bash "$SHIM" api -X DELETE /repos/"$R"
seed_cf "$R"
check "T2 api DELETE ALL THREE PASS"     0 "REAL_GH_CALLED"            env REPO_LIFECYCLE_OK="$R" REPO_DESTROY_CONFIRM="$R" bash "$SHIM" api -X DELETE /repos/"$R"
assert_cf "T2 api DELETE consumed the file line" ""
clear_cf
check "T2 api transfer BLOCK"            1 "BLOCKED a TIER-2"          bash "$SHIM" api -X POST /repos/"$R"/transfer -f new_owner=neworg
check "T2 graphql deleteRepository BLK"  1 "BLOCKED a TIER-2"          bash "$SHIM" api graphql -f query='mutation{deleteRepository(input:{repositoryId:"x"}){clientMutationId}}'
check "T1 graphql archiveRepository BLK" 1 "BLOCKED a destructive"     bash "$SHIM" api graphql -f query='mutation{archiveRepository(input:{repositoryId:"x"}){clientMutationId}}'

echo "--- Claude PreToolUse hook (L3): absolute-path gh the shim cannot see ---"
hook_call() { printf '%s' "$1" | bash "$HOOK"; }
clear_cf
check "hook T2 abs-path delete NONE BLK" 2 "BLOCKED by repo-guard hook: TIER-2" \
  hook_call "{\"tool_input\":{\"command\":\"$GHP repo delete $R --yes\"}}"
check "hook passes normal gh view"       0 "" \
  hook_call "{\"tool_input\":{\"command\":\"gh repo view $R\"}}"
check "hook fails closed on garbage"     2 "" \
  hook_call 'not json at all'
check "hook T1 rename +LIFECYCLE OK"     0 "" \
  hook_call "{\"tool_input\":{\"command\":\"REPO_LIFECYCLE_OK=$R gh repo rename newname -R $R\"}}"
check "hook T1 archive no-factor BLOCK"  2 "BLOCKED by repo-guard hook: repo archive" \
  hook_call "{\"tool_input\":{\"command\":\"gh repo archive $R\"}}"
# TIER 2 abs-path with all three -> allowed (0) AND consumes the file (shim won't run)
seed_cf "$R"
check "hook T2 abs-path ALL THREE -> OK" 0 "" \
  hook_call "{\"tool_input\":{\"command\":\"REPO_LIFECYCLE_OK=$R REPO_DESTROY_CONFIRM=$R $GHP repo delete $R --yes\"}}"
assert_cf "hook abs-path delete CONSUMED file line" ""
# TIER 2 BARE gh with all three -> allowed (0) but does NOT consume (the shim will)
seed_cf "$R"
check "hook T2 bare gh ALL THREE -> OK"  0 "" \
  hook_call "{\"tool_input\":{\"command\":\"REPO_LIFECYCLE_OK=$R REPO_DESTROY_CONFIRM=$R gh repo delete $R --yes\"}}"
assert_cf "hook bare gh did NOT consume (shim consumes)" "$R"
clear_cf
check "hook T2 abs-path transfer NONE BLK" 2 "TIER-2" \
  hook_call "{\"tool_input\":{\"command\":\"$GHP repo transfer $R neworg\"}}"
check "hook T2 graphql delete BLOCK"     2 "TIER-2" \
  hook_call "{\"tool_input\":{\"command\":\"$GHP api graphql -f query=mutation{deleteRepository(input:{repositoryId:x}){z}}\"}}"

echo "---"
if [[ "$FAILURES" -eq 0 ]]; then
  echo "OK — all repo-guard fixtures passed"
  exit 0
fi
echo "FAILED — $FAILURES fixture check(s)"
exit 1
