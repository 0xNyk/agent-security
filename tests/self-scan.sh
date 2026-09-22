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
  --allow '_0x1a2b3c=1;'
