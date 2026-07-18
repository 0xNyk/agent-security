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
# If any OTHER finding appears, this exits non-zero — the allow-list is intentionally tight.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec bash "$ROOT/scripts/scan-repo.sh" --all --markers /dev/null \
  --allow 'An exec \*\*sink\*\*' \
  --allow '\*\*Sink\*\*' \
  --allow 'Personal home paths'
