#!/usr/bin/env bash
# self-scan.sh — prove THIS repository is clean under its own scanner.
#
# scan-repo.sh self-skips its own source and test file, but the two security
# TAXONOMY docs (references/threat-model.md, references/coverage-and-limits.md)
# legitimately list encoder + exec-sink token names side by side. A same-file gate
# cannot tell a taxonomy table from a payload, so it flags those specific lines.
# We do NOT hardcode this repo's doc paths into the generic scanner (an adopter
# copying scan-repo.sh into their project would then blind-spot files named the
# same). Instead we allow the exact defensive-example lines here, documented.
#
# Each --allow below is a specific line of DOCUMENTATION, not a payload:
#   'An exec \*\*sink\*\*'  → coverage-and-limits.md class table (names the sink tokens)
#   '\*\*Sink\*\*'          → threat-model.md axis table (the Sink row)
#   'Personal home paths'   → coverage-and-limits.md PATH-class row (a /Users/<name> EXAMPLE)
#
# The inbound-vetting layer adds a few more inert defensive-EXAMPLE lines: the
# starter-template decode-then-exec dropper shape appears verbatim in the vet tool's
# header comment, the vetting-inbound case study, and the vet test's synthetic poisoned
# fixture. Each is documentation / an inert test fixture, never a runnable payload, so
# each is allowed here by an exact substring:
#   'starter template carrying an atob'          → vet-incoming.sh header comment
#   'decoding a base64 URL, feeding'             → vetting-inbound.md case study
#   'POISONED template: install-time postinstall'→ test-vet.sh fixture banner
#   'const u = atob\(process\.env\.CFG_URL'      → test-vet.sh synthetic vite-config fixture
#   'eval\(await \(await fetch\(u\)\)\.text'     → test-vet.sh synthetic vite-config fixture
#   '_0x1a2b3c=1;'                               → test-vet.sh synthetic committed-config-worm fixture
#
# The runtime audit adds four. Its detector patterns live in scripts/runtime-audit.sh,
# which is written to avoid literal sink syntax, so only these need allowing:
#   'Dropper markers in a command line'          → coverage-and-limits.md taxonomy row
#   'node -e const\{spawn\}='                    → test-runtime-audit.sh inert ps fixture
#   'python3 -c import urllib\.request'          → test-runtime-audit.sh inert ps fixture
#   'node --experimental-vm-modules -e'          → test-runtime-audit.sh inert ps fixture
#   'python3 -W ignore -c'                       → test-runtime-audit.sh inert ps fixture
# Every one is a STRING INSIDE A HEREDOC written to a temp file and fed to the audit via
# --ps-file. Nothing executes them; they exist so the detector has something to detect.
#
# The on-disk IOC sweep adds five, all in tests/test-ioc-sweep.sh: the "auth error"
# config-dropper fixture (decode an env var, fetch, exec behind a fake auth error) and
# the clean-side negatives (decode without a sink, a sink without a decode, and a
# dropper placed inside node_modules to prove the sweep prunes package stores). Every
# one is a printf STRING written into a throwaway fixture tree; nothing runs them.
#   'const src = atob\(process'                → the config-dropper fixture (decode line)
#   'eval\(proxyInfo\)'                        → the config-dropper fixture (sink line)
#   'APP_CONFIG_B64'                            → clean negative: decode, no sink
#   'devtools REPL helper'                      → clean negative: sink, no decode
#   'var a=atob\(process'                       → pruned node_modules negative
#
# If any OTHER finding appears, this exits non-zero — the allow-list is intentionally tight.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

exec bash "$ROOT/scripts/scan-repo.sh" --all --markers /dev/null \
  --allow 'An exec \*\*sink\*\*' \
  --allow '\*\*Sink\*\*' \
  --allow 'Personal home paths' \
  --allow 'starter template carrying an atob' \
  --allow 'decoding a base64 URL, feeding' \
  --allow 'POISONED template: install-time postinstall' \
  --allow 'const u = atob\(process\.env\.CFG_URL' \
  --allow 'eval\(await \(await fetch\(u\)\)\.text' \
  --allow '_0x1a2b3c=1;' \
  --allow 'Dropper markers in a command line' \
  --allow 'node -e const\{spawn\}=' \
  --allow 'python3 -c import urllib\.request' \
  --allow 'node --experimental-vm-modules -e' \
  --allow 'python3 -W ignore -c' \
  --allow 'const src = atob\(process' \
  --allow 'eval\(proxyInfo\)' \
  --allow 'APP_CONFIG_B64' \
  --allow 'devtools REPL helper' \
  --allow 'var a=atob\(process'
