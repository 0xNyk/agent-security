#!/usr/bin/env bash
# run-all.sh — run every test suite in this repo and report a single verdict.
# Offline: no network, no real GitHub call, no changes outside a temp directory.
#
# Suites are DISCOVERED, not listed: every tests/test-*.sh runs automatically, so a
# new suite cannot be written and then silently left out of the run. self-scan.sh is
# included explicitly — it is a repo gate rather than a fixture suite.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

shopt -s nullglob
SUITES=("$HERE"/test-*.sh)
shopt -u nullglob
[[ -f "$HERE/self-scan.sh" ]] && SUITES+=("$HERE/self-scan.sh")

if [[ ${#SUITES[@]} -eq 0 ]]; then
  echo "run-all: no suites found in $HERE — that is itself a failure"
  exit 1
fi

fail=0
passed=()
failed=()
for suite in "${SUITES[@]}"; do
  name="$(basename "$suite")"
  echo "=== $name ==="
  if bash "$suite"; then
    passed+=("$name")
  else
    failed+=("$name")
    fail=1
  fi
  echo
done

echo "==================================================================="
printf 'suites: %d passed, %d failed\n' "${#passed[@]}" "${#failed[@]}"
if [[ "$fail" -eq 0 ]]; then
  echo "ALL TESTS PASSED"
  exit 0
fi
for name in "${failed[@]}"; do printf '  FAILED  %s\n' "$name"; done
echo "SOME TESTS FAILED"
exit 1
