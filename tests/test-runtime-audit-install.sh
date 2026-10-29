#!/usr/bin/env bash
# Fixture tests for runtime-audit-install.sh (scheduling the host audit).
#
# Offline and side-effect free: every run uses a throwaway HOME, and the paths that
# would touch a real scheduler are exercised through --dry-run. Nothing is loaded into
# launchd, systemd, or crontab, and the real user's LaunchAgents are never written.
#
# Usage: bash tests/test-runtime-audit-install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="$ROOT/scripts/runtime-audit-install.sh"
AUDIT="$ROOT/scripts/runtime-audit.sh"
FAILURES=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/runtime-install-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
LAST_OUT=""

mkdir -p "$TMP/sandbox-home"

run_install() { # label, expected_exit, [args...]
  local label="$1" expect="$2"; shift 2
  local out code=0
  set +e
  out=$(HOME="$TMP/sandbox-home" bash "$INSTALL" --audit "$AUDIT" "$@" 2>&1)
  code=$?
  set -e
  LAST_OUT="$out"
  if [[ "$code" -eq "$expect" ]]; then
    echo "  ok  $label (exit $code)"
  else
    echo "  XX  $label — expected exit $expect got $code"
    echo "$out" | tail -10
    FAILURES=$((FAILURES+1))
  fi
}
expect_in() {
  if echo "$LAST_OUT" | grep -qF -- "$2"; then echo "  ok  $1"
  else echo "  XX  $1 — output lacks: $2"; FAILURES=$((FAILURES+1)); fi
}

echo "agent-security test-runtime-audit-install — offline fixtures"
echo "---"

# An interval that would hammer the process table is refused rather than accepted
# quietly: a scheduler running constantly is cost without detection benefit.
run_install "sub-300s interval refused" 2 --interval 60
expect_in "explains the refusal" "no detection benefit"

run_install "non-numeric interval refused" 2 --interval soon
expect_in "names the expected type" "whole number of seconds"

run_install "unknown argument refused" 2 --nonsense

# A missing audit script must fail loudly rather than schedule a no-op.
run_install "missing audit script refused" 2 --audit "$TMP/absent.sh"
expect_in "names the missing script" "missing or not executable"

# --status before install reports NOT armed, and says so in the exit code too.
run_install "status before install is not armed" 1 --status
expect_in "status says no" "ARMED           : no"
expect_in "explains what not-armed means" "only runs when you remember"
expect_in "status states the limit" "not WHAT it can see"

# --dry-run must change nothing at all.
run_install "dry-run install succeeds" 0 --dry-run --interval 3600
expect_in "announces dry-run actions" "[dry-run]"
expect_in "announces baseline refresh" "refreshing the audit's persistence baseline"
# A dry run must never claim work it did not do: `run` returns 0 without acting, so a
# success line gated on its exit status would lie about loading the scheduler.
if echo "$LAST_OUT" | grep -qE '^  (loaded into launchd|timer enabled|added crontab entry)$'; then
  echo "  XX  dry-run claimed it performed a real action"; FAILURES=$((FAILURES+1))
else
  echo "  ok  dry-run claims no work it did not do"
fi
if [[ -e "$TMP/sandbox-home/Library/LaunchAgents/com.agent-security.runtime-audit.plist" ]]; then
  echo "  XX  dry-run wrote a LaunchAgent"; FAILURES=$((FAILURES+1))
else
  echo "  ok  dry-run left the scheduler untouched"
fi
run_install "status after dry-run still not armed" 1 --status

# The installer must be honest that scheduling does not widen coverage.
run_install "dry-run states the boundary" 0 --dry-run
expect_in "does not widen what it sees" "does NOT widen what it can see"
expect_in "clean is still qualified" "no known pattern matched"

# --status must read the interval back from the installed entry, not restate what was
# typed at install time: an install at 1800s that someone later forgets should not look
# identical to one at 3600s.
mkdir -p "$TMP/sandbox-home/Library/LaunchAgents"
cat >"$TMP/sandbox-home/Library/LaunchAgents/com.agent-security.runtime-audit.plist" <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>com.agent-security.runtime-audit</string>
  <key>StartInterval</key><integer>1800</integer>
</dict></plist>
PL
run_install "status reads the real interval back" 0 --status
expect_in "reports 1800s" "every 1800s"
expect_in "reports it in minutes too" "about 30 min"
expect_in "armed" "ARMED           : yes"
rm -f "$TMP/sandbox-home/Library/LaunchAgents/com.agent-security.runtime-audit.plist"

# --uninstall is safe to run when nothing is installed.
run_install "uninstall with nothing installed" 0 --uninstall --dry-run
expect_in "reminds about the baseline" "--update-baseline"

# --help works without touching anything.
run_install "help exits clean" 0 --help
expect_in "help mentions scheduling" "schedule"

echo "---"
if [[ "$FAILURES" -eq 0 ]]; then
  echo "ALL PASS"
  exit 0
else
  echo "FAILURES: $FAILURES"
  exit 1
fi
