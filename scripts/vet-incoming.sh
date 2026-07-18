#!/usr/bin/env bash
# vet-incoming.sh — vet a THIRD-PARTY repo / template / package / skill BEFORE use.
#
# scan-repo.sh gates YOUR content before you publish. This gates INCOMING content
# before you adopt it — the exact starter-template vector behind a real 2026 incident: a scaffolded
# starter template carrying an atob(process.env…)→eval(fetch())
# dropper in its vite/vitest config. See references/vetting-inbound.md.
#
# SCAN ONLY — this NEVER runs install/build/postinstall. It materializes the target
# in a temp working tree and reads it; nothing from the target is executed.
#
# Usage:
#   vet-incoming.sh <path>              # a local dir, template, or extracted package
#   vet-incoming.sh --url <git-url>     # shallow-clone (depth 1), scan, clean up
#   vet-incoming.sh <path> --json       # machine-readable verdict line too
#
# Runs the shared dropper/secret/invisible-unicode engine (scan-repo.sh) PLUS
# adoption-specific checks:
#   • package.json lifecycle scripts (preinstall/install/postinstall/prepare/…)  HIGH
#   • dropper shapes in build/test/config files (vite/vitest/webpack/rollup/jest) CRIT
#   • base64 blob in a committed .env* (the dropper URL carrier)                  HIGH
#   • committed git hooks (.husky/*, .git/hooks/* non-sample, hook installers)    HIGH
#   • CI workflows: curl|bash, net→interpreter pipes, eval, unpinned action refs,
#     secret exfil                                                                HIGH/MED
#   • editor autorun (.vscode/tasks.json runOn, devcontainer postCreate/Start)    HIGH
#   • obfuscated / minified code containing eval / Function                       MED
#
# Verdict: REJECT (any CRITICAL/HIGH) · REVIEW (MEDIUM or scan-repo MAJOR) · ADOPT.
#
# HONEST HEADER: KNOWN patterns only, trivially evadable. NOT a replacement for
# Socket / Snyk / `npm audit` / Semgrep / sandbox detonation. A clean result is NOT
# proof of safety — it means "no known adoption red flag matched." Read the code you
# adopt; run `npm install --ignore-scripts` and review lifecycle scripts by hand.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_REPO="$HERE/scan-repo.sh"

TARGET=""
URL=""
JSON=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) [[ $# -ge 2 ]] || { echo "--url needs a value" >&2; exit 2; }; URL="$2"; shift ;;
    --json) JSON=1 ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "Unknown argument: $1" >&2; exit 2 ;;
    *) TARGET="$1" ;;
  esac
  shift
done

CRIT=0; HIGH=0; MED=0
CTMP="$(mktemp -d "${TMPDIR:-/tmp}/vet-incoming.XXXXXX")"
CLONE=""
cleanup() { [[ -n "$CLONE" ]] && rm -rf "$CLONE" 2>/dev/null; rm -rf "$CTMP" 2>/dev/null; }
trap cleanup EXIT

crit() { printf '  [CRIT] %s\n' "$1"; CRIT=$((CRIT+1)); }
high() { printf '  [HIGH] %s\n' "$1"; HIGH=$((HIGH+1)); }
med()  { printf '  [MED ] %s\n' "$1"; MED=$((MED+1)); }
note() { printf '         %s\n' "$1"; }

# ── Resolve the target into a readable directory (SCAN ONLY, never execute) ──
if [[ -n "$URL" ]]; then
  command -v git >/dev/null 2>&1 || { echo "git required for --url" >&2; exit 2; }
  CLONE="$(mktemp -d "${TMPDIR:-/tmp}/vet-clone.XXXXXX")"
  echo "vet-incoming — shallow-cloning (depth 1, no submodules, no hooks run): $URL"
  # core.hooksPath=/dev/null: even clone-time hook config from the remote can't fire.
  if ! GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null clone --depth 1 --no-tags "$URL" "$CLONE" >/dev/null 2>&1; then
    echo "FAILED to clone $URL — cannot vet." >&2; exit 2
  fi
  DIR="$CLONE"
elif [[ -n "$TARGET" && -d "$TARGET" ]]; then
  DIR="$TARGET"
else
  echo "Usage: vet-incoming.sh <path> | --url <git-url>" >&2; exit 2
fi

echo "==================================================================="
echo "vet-incoming: $([[ -n "$URL" ]] && echo "$URL" || echo "$DIR")"
echo "SCAN ONLY — no install/build/postinstall was or will be run."
echo "KNOWN patterns only; evadable; not a replacement for Socket/Snyk/npm audit/Semgrep."
echo "==================================================================="

# ── 1. Shared engine: run scan-repo.sh over a temp git tree of the target ────
# scan-repo needs a git repo; copy the target in and init one (no signing/hooks).
echo "[engine] dropper / secret / invisible-unicode scan (scan-repo.sh)"
WORK="$CTMP/work"
mkdir -p "$WORK"
# Copy contents (portable; excludes an existing .git so we control the tree).
( cd "$DIR" && tar --exclude='./.git' -cf - . 2>/dev/null ) | ( cd "$WORK" && tar -xf - 2>/dev/null ) || \
  cp -R "$DIR/." "$WORK/" 2>/dev/null
rm -rf "$WORK/.git" 2>/dev/null
(
  cd "$WORK"
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q 2>/dev/null
  git config user.email vet@example.com; git config user.name vet; git config commit.gpgsign false
  git add -A 2>/dev/null
)
ENGINE_OUT="$(cd "$WORK" && AGENT_SECURITY_MARKERS=/dev/null bash "$SCAN_REPO" --all --markers /dev/null 2>&1)"
ENGINE_CODE=$?
ENGINE_CRIT="$(printf '%s\n' "$ENGINE_OUT" | grep -oE 'CRITICAL [0-9]+' | tail -1 | awk '{print $2}')"
ENGINE_MAJOR="$(printf '%s\n' "$ENGINE_OUT" | grep -oE 'MAJOR [0-9]+' | tail -1 | awk '{print $2}')"
ENGINE_CRIT="${ENGINE_CRIT:-0}"; ENGINE_MAJOR="${ENGINE_MAJOR:-0}"
if [[ "$ENGINE_CRIT" -gt 0 ]]; then
  crit "scan-repo engine: $ENGINE_CRIT CRITICAL (dropper/secret/invisible-unicode) — see detail:"
  printf '%s\n' "$ENGINE_OUT" | grep -E '\[(SECRET|DROPPER|INVISIBLE_UNICODE)' | sed 's/^/         /'
elif [[ "$ENGINE_MAJOR" -gt 0 ]]; then
  med "scan-repo engine: $ENGINE_MAJOR MAJOR (paths/infra/personal) — usually benign in third-party code, review"
else
  note "scan-repo engine: clean (no dropper/secret/unicode shapes)"
fi

# Helper: list files, skipping heavy/binary dirs.
files() { find "$DIR" -type f \
  -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/dist/*' \
  -not -path '*/build/*' -not -path '*/.next/*' -not -path '*/coverage/*' 2>/dev/null; }

# ── 2. package.json lifecycle scripts (execute on npm/pnpm install) ─────────
echo "[adopt] package.json install-time lifecycle scripts"
LC_HIT=0
while IFS= read -r pj; do
  [[ -z "$pj" ]] && continue
  hits="$(grep -nE '"(preinstall|install|postinstall|preuninstall|postuninstall|prepare|prepublish|prepublishOnly)"[[:space:]]*:' "$pj" 2>/dev/null || true)"
  if [[ -n "$hits" ]]; then
    LC_HIT=1
    high "lifecycle script(s) in ${pj#"$DIR"/} — run arbitrary code on \`npm/pnpm install\`:"
    printf '%s\n' "$hits" | sed 's/^/         /'
  fi
done < <(files | grep -E '/package\.json$' || true)
[[ "$LC_HIT" -eq 0 ]] && note "no install-time lifecycle scripts found" || \
  note "→ adopt with \`npm install --ignore-scripts\` and review each script by hand."

# ── 3. Dropper shapes specifically in build/test/config files ───────────────
echo "[adopt] dropper shapes in build/test/config files (the starter-template vector)"
CFG_HIT=0
while IFS= read -r cf; do
  [[ -z "$cf" ]] && continue
  if grep -lqE 'eval[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\(|atob[[:space:]]*\(|Buffer\.from[[:space:]]*\([^)]*base64|child_process|execSync' "$cf" 2>/dev/null; then
    if grep -qE 'fetch[[:space:]]*\(|https?://|process\.env|atob|Buffer\.from|child_process' "$cf" 2>/dev/null; then
      CFG_HIT=1
      crit "exec/decode + fetch/env in config file ${cf#"$DIR"/}:"
      grep -nE 'eval[[:space:]]*\(|new[[:space:]]+Function|atob[[:space:]]*\(|child_process|execSync|fetch[[:space:]]*\(' "$cf" 2>/dev/null | head -6 | sed 's/^/         /'
    fi
  fi
done < <(files | grep -E '\.(config|conf)\.(js|ts|mjs|cjs)$|(vite|vitest|webpack|rollup|jest|babel|next|svelte|astro|tsup|esbuild)\.[cm]?[jt]s$|(setup|test-setup|jest\.setup|vitest\.setup)\.[cm]?[jt]s$' || true)
[[ "$CFG_HIT" -eq 0 ]] && note "no exec+fetch/decode shapes in config/build/test files"

# base64 blob in a committed .env* (the dropper URL carrier)
while IFS= read -r ef; do
  [[ -z "$ef" ]] && continue
  base="$(basename "$ef")"
  [[ "$base" == ".env.example" || "$base" == ".env.sample" ]] && continue
  if grep -qE '^[A-Za-z_][A-Za-z0-9_]*=["'"'"']?[A-Za-z0-9+/_-]{24,}={0,2}["'"'"']?[[:space:]]*$' "$ef" 2>/dev/null; then
    high "base64-shaped blob under an env key in committed ${ef#"$DIR"/} — classic dropper URL carrier"
  fi
done < <(files | grep -E '/\.env(\.|$)' || true)

# ── 4. Committed git hooks ──────────────────────────────────────────────────
echo "[adopt] committed git hooks (fire on git operations after adoption)"
HK_HIT=0
if [[ -d "$DIR/.husky" ]]; then
  while IFS= read -r hk; do
    [[ -z "$hk" ]] && continue
    HK_HIT=1; high "husky hook committed: ${hk#"$DIR"/}"
    grep -nE 'curl|wget|eval|atob|node -e|bash -c|\|[[:space:]]*(sh|bash)' "$hk" 2>/dev/null | head -4 | sed 's/^/         /'
  done < <(find "$DIR/.husky" -type f -not -name '*.md' 2>/dev/null)
fi
while IFS= read -r sh; do
  [[ -z "$sh" ]] && continue
  if grep -qE 'core\.hooksPath|husky install|\.git/hooks/|ln -s .*hooks' "$sh" 2>/dev/null; then
    HK_HIT=1; med "script installs git hooks: ${sh#"$DIR"/} (review what it registers)"
  fi
done < <(files | grep -E '\.(sh|js|cjs|mjs)$' || true)
[[ "$HK_HIT" -eq 0 ]] && note "no committed git hooks / hook installers found"

# ── 5. CI workflows ─────────────────────────────────────────────────────────
echo "[adopt] CI workflows (.github/workflows)"
CI_HIT=0
while IFS= read -r wf; do
  [[ -z "$wf" ]] && continue
  if grep -qE '(curl|wget)[^|]*\|[[:space:]]*(sh|bash)|(sh|bash)[[:space:]]*<\(|eval[[:space:]]*\(|node[[:space:]]+-e|python[[:space:]]+-c' "$wf" 2>/dev/null; then
    CI_HIT=1; high "network→interpreter pipe / eval in workflow ${wf#"$DIR"/}:"
    grep -nE '(curl|wget).*\|[[:space:]]*(sh|bash)|eval[[:space:]]*\(|node[[:space:]]+-e' "$wf" 2>/dev/null | head -4 | sed 's/^/         /'
  fi
  # Unpinned/mutable action refs (uses: x@main / @master / @v1) — supply-chain drift.
  if grep -qE 'uses:[[:space:]]*[^@[:space:]]+@(main|master|v[0-9]+)[[:space:]]*$' "$wf" 2>/dev/null; then
    CI_HIT=1; med "mutable action ref (not pinned to a SHA) in ${wf#"$DIR"/} — a moved tag can inject code"
  fi
  if grep -qiE '(secrets\.|GITHUB_TOKEN).*(curl|wget|nc |http)' "$wf" 2>/dev/null; then
    CI_HIT=1; high "possible secret exfil shape in ${wf#"$DIR"/} (secret used with a network tool)"
  fi
done < <(files | grep -E '\.github/workflows/.*\.ya?ml$' || true)
[[ "$CI_HIT" -eq 0 ]] && note "no risky CI workflow shapes found"

# ── 6. Editor / devcontainer autorun ────────────────────────────────────────
echo "[adopt] editor / devcontainer autorun configs"
ED_HIT=0
while IFS= read -r vt; do
  [[ -z "$vt" ]] && continue
  if grep -qE '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$vt" 2>/dev/null; then
    ED_HIT=1; high "VS Code task auto-runs on folder open: ${vt#"$DIR"/}"
  fi
done < <(files | grep -E '\.vscode/tasks\.json$' || true)
while IFS= read -r dc; do
  [[ -z "$dc" ]] && continue
  if grep -qE '"(postCreateCommand|postStartCommand|onCreateCommand|updateContentCommand)"' "$dc" 2>/dev/null; then
    ED_HIT=1; med "devcontainer lifecycle command in ${dc#"$DIR"/} (runs on container create/start)"
  fi
done < <(files | grep -E 'devcontainer\.json$' || true)
[[ "$ED_HIT" -eq 0 ]] && note "no autorun editor/devcontainer configs found"

# ── 7. Obfuscated / minified code with eval / Function ──────────────────────
echo "[adopt] obfuscated / minified code containing eval / Function"
OB_HIT=0
while IFS= read -r js; do
  [[ -z "$js" ]] && continue
  # Heuristic: very long single lines (minified) that also carry an exec sink.
  if awk 'length>500{print;exit}' "$js" 2>/dev/null | grep -qE 'eval[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\(|atob[[:space:]]*\('; then
    OB_HIT=1; med "minified/long-line code with an exec sink: ${js#"$DIR"/} (review or reject; can hide payloads)"
  fi
done < <(files | grep -E '\.(js|mjs|cjs|ts)$' | grep -vE '\.min\.js$|node_modules' | head -400 || true)
while IFS= read -r mj; do
  [[ -z "$mj" ]] && continue
  OB_HIT=1; note "vendored *.min.js present (${mj#"$DIR"/}) — not inspected; treat as opaque"
done < <(files | grep -E '\.min\.js$' | head -5 || true)
[[ "$OB_HIT" -eq 0 ]] && note "no obfuscated/minified exec-sink code flagged"

# ── Verdict ─────────────────────────────────────────────────────────────────
echo "==================================================================="
echo "findings: CRITICAL $CRIT · HIGH $HIGH · MEDIUM $MED"
VERDICT="ADOPT"
if [[ "$CRIT" -gt 0 || "$HIGH" -gt 0 ]]; then
  VERDICT="REJECT"
elif [[ "$MED" -gt 0 || "${ENGINE_MAJOR:-0}" -gt 0 ]]; then
  VERDICT="REVIEW"
fi
case "$VERDICT" in
  REJECT) echo "VERDICT: REJECT — do NOT scaffold from or install this without removing the flagged vectors first." ;;
  REVIEW) echo "VERDICT: REVIEW — no hard red flag, but read the flagged items before adopting. Install with --ignore-scripts." ;;
  ADOPT)  echo "VERDICT: ADOPT (no KNOWN adoption red flag matched) — still not proof of safety; read the code, prefer --ignore-scripts." ;;
esac
[[ "$JSON" -eq 1 ]] && echo "{\"verdict\":\"$VERDICT\",\"critical\":$CRIT,\"high\":$HIGH,\"medium\":$MED}"
[[ "$VERDICT" == "REJECT" ]] && exit 1
exit 0
