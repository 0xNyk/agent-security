#!/usr/bin/env bash
# ioc-sweep.sh — daily on-disk indicator sweep for the malware families that target
# developer Macs in 2026: Contagious Interview (BeaverTail/InvisibleFerret/OtterCookie),
# Shai-Hulud 2.0 (npm worm), GlassWorm (invisible-Unicode IDE extensions) and the
# ClickFix stealer lures, plus the 2026 campaigns against npm, PyPI, crates.io, GitHub
# Actions and agent/IDE configs.
# runtime-audit looks at what is RUNNING. This looks at what is INSTALLED on disk.
#
# Read-only. Reports, fixes nothing. Indicators live in ioc-indicators.txt next to
# this script (override with --indicators) so a new IOC is a one-line append.
#
# Usage:
#   ioc-sweep.sh                     sweep the real machine
#   ioc-sweep.sh --home DIR --dev DIR --state DIR --history FILE --ext-dir DIR ...
#                                    offline/fixture mode (tests)
#   ioc-sweep.sh --days N            shell-history window (default 7)
#   ioc-sweep.sh --accept-config     re-record the home agent-config baseline ([12])
# Exit: 0 clean, 1 findings, 2 could not run (BLIND).
set -uo pipefail
PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOME_DIR="$HOME"
DEV_DIR="$HOME/dev"
STATE="$HOME/.local/state/agent-security"
INDICATORS="$HERE/ioc-indicators.txt"
HISTORY_FILES=()
EXT_DIRS=()
TMP_DIRS=()
DAYS=7
NOTIFY=1
ACCEPT_CONFIG=0
EXPLICIT_HIST=0; EXPLICIT_EXT=0; EXPLICIT_TMP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --home) HOME_DIR="$2"; shift 2 ;;
    --dev) DEV_DIR="$2"; shift 2 ;;
    --state) STATE="$2"; shift 2 ;;
    --indicators) INDICATORS="$2"; shift 2 ;;
    --history) HISTORY_FILES+=("$2"); EXPLICIT_HIST=1; shift 2 ;;
    --ext-dir) EXT_DIRS+=("$2"); EXPLICIT_EXT=1; shift 2 ;;
    --tmp-dir) TMP_DIRS+=("$2"); EXPLICIT_TMP=1; shift 2 ;;
    --days) DAYS="$2"; shift 2 ;;
    --no-notify) NOTIFY=0; shift ;;
    --accept-config) ACCEPT_CONFIG=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

(( EXPLICIT_HIST )) || HISTORY_FILES=("$HOME_DIR/.zsh_history" "$HOME_DIR/.bash_history")
(( EXPLICIT_EXT ))  || EXT_DIRS=("$HOME_DIR/.cursor/extensions" "$HOME_DIR/.vscode/extensions" "$HOME_DIR/.vscode-oss/extensions")
(( EXPLICIT_TMP ))  || TMP_DIRS=("/tmp" "/private/tmp" "${TMPDIR:-}")

[[ -r "$INDICATORS" ]] || { echo "BLIND: indicators file unreadable: $INDICATORS" >&2; exit 2; }
mkdir -p "$STATE" 2>/dev/null || { echo "BLIND: cannot create $STATE" >&2; exit 2; }
OUT="$STATE/ioc-sweep-findings.txt"
LOG="$STATE/ioc-sweep.log"
: > "$OUT" || { echo "BLIND: cannot write $OUT" >&2; exit 2; }

# Background QoS: efficiency cores, throttled IO (macOS taskpolicy, else renice).
taskpolicy -b -p $$ 2>/dev/null || renice -n 15 -p $$ >/dev/null 2>&1

find_hit() { printf '%s\n' "$*" >> "$OUT"; }

# Parse indicator file into per-kind arrays.
IOC_PATHS=(); IOC_FILENAMES=(); IOC_PKGS=(); IOC_WORKFLOW=(); IOC_SHELL_RE=(); IOC_SHELL_NAME=()
IOC_ABSPATHS=(); IOC_REPOPATHS=(); IOC_TMPGLOBS=(); IOC_NPMVER=(); IOC_PYPKG=(); IOC_PYVER=()
IOC_CRATE=(); IOC_CRATEVER=(); IOC_ACTIONREF=()
while IFS=$'\t' read -r kind value note; do
  [[ -z "${kind:-}" || "$kind" == \#* ]] && continue
  case "$kind" in
    PATH) IOC_PATHS+=("$value") ;;
    FILENAME) IOC_FILENAMES+=("$value") ;;
    NPMPKG) IOC_PKGS+=("$value") ;;
    WORKFLOW) IOC_WORKFLOW+=("$value") ;;
    SHELLCMD) IOC_SHELL_RE+=("$value"); IOC_SHELL_NAME+=("${note:-shellcmd}") ;;
    ABSPATH) IOC_ABSPATHS+=("$value") ;;
    REPOPATH) IOC_REPOPATHS+=("$value") ;;
    TMPGLOB) IOC_TMPGLOBS+=("$value") ;;
    NPMVER) IOC_NPMVER+=("$value	$note") ;;      # name<TAB>version (note column holds the version)
    PYPKG) IOC_PYPKG+=("$value") ;;
    PYVER) IOC_PYVER+=("$value	$note") ;;
    CRATE) IOC_CRATE+=("$value") ;;
    CRATEVER) IOC_CRATEVER+=("$value	$note") ;;
    ACTIONREF) IOC_ACTIONREF+=("$value") ;;
  esac
done < "$INDICATORS"
re_escape() { printf '%s' "$1" | sed -e 's/[][\.|$(){}?+*^]/\\&/g'; }

PRUNE=( -name node_modules -o -name .git -o -name .next -o -name .turbo -o -name dist -o -name .venv -o -name target )

# [1] Known drop paths under $HOME.
for p in ${IOC_ABSPATHS[@]+"${IOC_ABSPATHS[@]}"}; do
  [[ -e "$p" ]] && find_hit "DROP-PATH $p"
done
if (( ${#IOC_REPOPATHS[@]} )) && [[ -d "$DEV_DIR" ]]; then
  for rp in ${IOC_REPOPATHS[@]+"${IOC_REPOPATHS[@]}"}; do
    find "$DEV_DIR" -maxdepth 7 -path "*/$rp" -not -path '*/node_modules/*' -not -path '*/tests/fixtures/*' 2>/dev/null |
      while read -r f; do find_hit "REPO-PATH $f"; done
  done
fi
for p in ${IOC_PATHS[@]+"${IOC_PATHS[@]}"}; do
  [[ -e "$HOME_DIR/$p" ]] && find_hit "DROP-PATH $HOME_DIR/$p"
done

# [2] Known payload filenames: dev tree (INCLUDING node_modules — that is where Shai-Hulud
#     lands), package caches, and $HOME top-level dot dirs. parser.js is only an IOC
#     outside node_modules, where real parsers legitimately live.
NAME_EXPR=()
for f in ${IOC_FILENAMES[@]+"${IOC_FILENAMES[@]}"}; do NAME_EXPR+=( -o -name "$f" ); done
if (( ${#NAME_EXPR[@]} )); then
  NAME_EXPR=( "${NAME_EXPR[@]:1}" )
  for root in "$DEV_DIR" "$HOME_DIR/.npm/_npx" "$HOME_DIR/.bun/install/cache" \
              "$HOME_DIR/Library/pnpm" "$HOME_DIR/.local/share/pnpm" "$HOME_DIR/.cache"; do
    [[ -d "$root" ]] || continue
    find "$root" -maxdepth 9 -type f \( "${NAME_EXPR[@]}" \) 2>/dev/null |
      while read -r f; do
        case "$f" in
          # parser.js is only an IOC where no package lives: any package store has dozens
          */node_modules/*parser.js|*/.bun/install/cache/*parser.js|*/.npm/_npx/*parser.js|*/pnpm/*parser.js|*/.cache/*parser.js) continue ;;
          # Math_Symbol.js is a real Unicode-property table in regenerate-unicode-properties
          */node_modules/*Math_*.js|*/.bun/install/cache/*Math_*.js|*/pnpm/*Math_*.js|*/.cache/*Math_*.js) continue ;;
          */tests/fixtures/*) continue ;;
        esac
        find_hit "PAYLOAD-FILE $f"
      done
  done
  # dot dirs directly under $HOME (not the whole home — too slow and too noisy)
  find "$HOME_DIR" -mindepth 2 -maxdepth 4 -path "$HOME_DIR/.*" -type f \( "${NAME_EXPR[@]}" \) 2>/dev/null |
    grep -vE '/(\.cursor|\.vscode|\.vscode-oss)/extensions/|/node_modules/' |
    while read -r f; do find_hit "PAYLOAD-FILE $f"; done
fi

# [3] Shai-Hulud preinstall hooks in installed package manifests.
if [[ -d "$DEV_DIR" ]]; then
  find "$DEV_DIR" -maxdepth 8 -name package.json -type f -print0 2>/dev/null |
    xargs -0 -n 200 grep -lE '"(pre|post)install"[[:space:]]*:[[:space:]]*"[^"]*(setup_bun|bun_environment|setup\.m?js|bw_setup|router_init|tanstack_runner)' 2>/dev/null |
    while read -r f; do find_hit "PREINSTALL-HOOK $f"; done
fi

# [4] npm lookalike packages in lockfiles.
if (( ${#IOC_PKGS[@]} )) && [[ -d "$DEV_DIR" ]]; then
  PKG_RE="$(printf '%s|' "${IOC_PKGS[@]}")"; PKG_RE="${PKG_RE%|}"
  find "$DEV_DIR" -maxdepth 5 -type d \( "${PRUNE[@]}" \) -prune -o -type f \
       \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name bun.lock -o -name bun.lockb -o -name package.json \) -print 2>/dev/null |
    while read -r f; do
      grep -qE "(^|[\"'/ ])(${PKG_RE})[@\"':/ ]" "$f" 2>/dev/null && find_hit "LOOKALIKE-PKG $f"
    done
fi

# [4b] Specific compromised npm releases: lockfiles + manifests, installed node_modules
#      manifests, and the bun/npx caches (dir names carry name@version).
if (( ${#IOC_NPMVER[@]} )); then
  NM_MANIFESTS="$(mktemp "${TMPDIR:-/tmp}/ioc-nm.XXXXXX")"
  if [[ -d "$DEV_DIR" ]]; then
    NM_EXPR=(); for nv in ${IOC_NPMVER[@]+"${IOC_NPMVER[@]}"}; do NM_EXPR+=( -o -path "*/node_modules/${nv%%	*}/package.json" ); done
    find "$DEV_DIR" -maxdepth 9 -type f \( "${NM_EXPR[@]:1}" \) 2>/dev/null > "$NM_MANIFESTS"
  fi
  for nv in ${IOC_NPMVER[@]+"${IOC_NPMVER[@]}"}; do
    name="${nv%%	*}"; ver="${nv#*	}"; ename="$(re_escape "$name")"; ever="$(re_escape "$ver")"
    base="${name##*/}"
    if [[ -d "$DEV_DIR" ]]; then
      find "$DEV_DIR" -maxdepth 5 -type d \( "${PRUNE[@]}" \) -prune -o -type f \
           \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name bun.lock -o -name package.json \) -print 2>/dev/null |
        while read -r f; do
          grep -qE "(${ename}@${ever}([^0-9.]|$)|\"${ename}\"[[:space:]]*:[[:space:]]*\"${ever}\"|/${ename}/-/${base}-${ever}\.tgz|/${ename}@${ever}[:/])" "$f" 2>/dev/null &&
            find_hit "COMPROMISED-NPM-RELEASE $name@$ver $f"
        done
    fi
    grep -F "/node_modules/$name/package.json" "$NM_MANIFESTS" | while read -r f; do
      grep -qE "\"version\"[[:space:]]*:[[:space:]]*\"${ever}\"" "$f" 2>/dev/null && find_hit "COMPROMISED-NPM-RELEASE $name@$ver $f"
    done
    for root in "$HOME_DIR/.bun/install/cache" "$HOME_DIR/.npm/_npx" "$HOME_DIR/Library/pnpm" "$HOME_DIR/.local/share/pnpm"; do
      [[ -d "$root" ]] || continue
      find "$root" -maxdepth 4 \( -name "${base}@${ver}" -o -name "${base}@${ver}@*" -o -name "${base}@${ver}_*" \) 2>/dev/null |
        while read -r f; do find_hit "COMPROMISED-NPM-RELEASE $name@$ver $f"; done
    done
  done
  rm -f "$NM_MANIFESTS"
fi

# [5] Rogue GitHub Actions workflows and self-hosted runner installs.
if (( ${#IOC_WORKFLOW[@]} )) && [[ -d "$DEV_DIR" ]]; then
  WF_RE="$(printf '%s|' "${IOC_WORKFLOW[@]}")"; WF_RE="${WF_RE%|}"
  find "$DEV_DIR" -maxdepth 4 -path '*/.github/workflows/*' -type f 2>/dev/null |
    while read -r f; do
      if [[ "$(basename "$f")" =~ ^(${WF_RE})$ ]] || grep -qiE "${WF_RE}" "$f" 2>/dev/null; then
        find_hit "ROGUE-WORKFLOW $f"
      fi
    done
fi
# [5b] Actions whose tags were hijacked: any use that is not a 40-hex commit pin.
if (( ${#IOC_ACTIONREF[@]} )) && [[ -d "$DEV_DIR" ]]; then
  for a in ${IOC_ACTIONREF[@]+"${IOC_ACTIONREF[@]}"}; do
    ea="$(re_escape "$a")"
    find "$DEV_DIR" -maxdepth 4 -path '*/.github/workflows/*' -type f 2>/dev/null |
      while read -r f; do
        grep -E "uses:[[:space:]]*['\"]?${ea}(/[^@[:space:]]*)?@" "$f" 2>/dev/null |
          grep -vqE "@[0-9a-f]{40}([[:space:]'\"#]|$)" && find_hit "HIJACKED-ACTION-BY-TAG $a $f"
      done
  done
fi
for r in "$HOME_DIR"/actions-runner "$HOME_DIR"/.runner "$HOME_DIR"/*/.runner; do
  [[ -e "$r" ]] && find_hit "ACTIONS-RUNNER $r"
done

# [6] GlassWorm: invisible Unicode in IDE extensions and dev source.
#     Only the Variation Selectors Supplement (U+E0100–U+E01EF, UTF-8 F3 A0 84..87 xx) is
#     matched. FE00–FE0F are left alone because emoji use VS-16 legitimately.
VS_BYTES=$'\xF3\xA0[\x84-\x87][\x80-\xBF]'
scan_invisible() {
  local root="$1" tag="$2"
  [[ -d "$root" ]] || return 0
  LC_ALL=C grep -rlIE --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' \
    --include='*.json' --include='*.vsix' \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=dist \
    --exclude-dir=.turbo --exclude-dir=fixtures \
    -- "$VS_BYTES" "$root" 2>/dev/null | sed "s/^/$tag /" >> "$OUT"
}
for d in ${EXT_DIRS[@]+"${EXT_DIRS[@]}"}; do scan_invisible "$d" "INVISIBLE-UNICODE-EXT"; done
scan_invisible "$DEV_DIR" "INVISIBLE-UNICODE-SRC"

# [7] ClickFix lure shapes in recent shell history. Prints ONLY the pattern name and
#     the host (if any) — never the command, which may carry a token.
now=$(date +%s); cutoff=$(( now - DAYS*86400 ))
for h in ${HISTORY_FILES[@]+"${HISTORY_FILES[@]}"}; do
  [[ -r "$h" ]] || continue
  i=0
  while (( i < ${#IOC_SHELL_RE[@]} )); do
    re="${IOC_SHELL_RE[$i]}"; name="${IOC_SHELL_NAME[$i]}"; i=$((i+1))
    LC_ALL=C grep -aE -- "$re" "$h" 2>/dev/null |
      while IFS= read -r line; do
        ts=""; cmd="$line"
        if [[ "$line" =~ ^:[[:space:]]*([0-9]+):[0-9]+\;(.*)$ ]]; then ts="${BASH_REMATCH[1]}"; cmd="${BASH_REMATCH[2]}"; fi
        [[ -n "$ts" && "$ts" -lt "$cutoff" ]] && continue
        host="$(printf '%s' "$cmd" | grep -oE 'https?://[^/[:space:]"'"'"']+' | head -1 | sed -E 's#https?://##')"
        when="unknown-date"; [[ -n "$ts" ]] && when="$(date -r "$ts" +%F 2>/dev/null || date -d "@$ts" +%F 2>/dev/null || echo "$ts")"
        find_hit "SHELL-LURE $name host=${host:-none} date=$when file=$(basename "$h")"
      done
  done
done

# [8] Quarantine-stripped or Apple-named executables outside app bundles.
#     Stealers copy themselves to names like com.apple.verified and strip the xattr.
find "$HOME_DIR" -maxdepth 6 -type d \( -name node_modules -o -name .git -o -name '*.app' -o -name Containers -o -name 'Group Containers' \) -prune -o \
     -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) -name 'com.apple.*' -print 2>/dev/null |
  while read -r f; do find_hit "APPLE-NAMED-EXEC $f"; done
for t in ${TMP_DIRS[@]+"${TMP_DIRS[@]}"}; do
  [[ -n "$t" && -d "$t" ]] || continue
  for g in ${IOC_TMPGLOBS[@]+"${IOC_TMPGLOBS[@]}"}; do
    find "$t" -mindepth 1 -maxdepth 1 -name "$g" 2>/dev/null | while read -r f; do find_hit "TMP-STAGING $f"; done
  done
  find "$t" -maxdepth 2 -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) -mtime "-$DAYS" 2>/dev/null |
    while read -r f; do
      magic="$(head -c 4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
      case "$magic" in
        cffaedfe|cefaedfe|cafebabe|feedfacf|feedface) find_hit "TMP-MACHO $f" ;;
      esac
    done
done

# [9] The "auth error" config dropper (Contagious Interview; reported in 2026 inside a
#     Capacitor config file): a base64 env var is decoded, fetched, and the body eval'd inside
#     a try/catch that logs "Auth Error". Same-file co-occurrence of an ENV-DECODE and a
#     dynamic-exec SINK in source/config files of every working tree (node_modules
#     pruned: install-time payloads are [3]'s job and minified bundles are all noise)
#     plus the package caches, where a lookalike package would land.
ENVDEC_RE='(atob|Buffer\.from|b64decode|base64[_-]?decode)[^;]{0,160}(process\.env|import\.meta\.env|os\.environ)'
SINK_RE='(^|[^[:alnum:]_.])eval[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\(|vm\.(runInContext|Script|compileFunction)[[:space:]]*\('
SRC_EXT=( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name '*.mts' -o -name '*.cts' -o -name '*.vue' -o -name '*.svelte' )
for root in "$DEV_DIR" "$HOME_DIR/.npm/_npx" "$HOME_DIR/.bun/install/cache" \
            "$HOME_DIR/Library/pnpm" "$HOME_DIR/.local/share/pnpm"; do
  [[ -d "$root" ]] || continue
  find "$root" -maxdepth 9 \( "${PRUNE[@]}" \) -prune -o -type f \( "${SRC_EXT[@]}" \) -size -2M -print0 2>/dev/null |
    xargs -0 grep -lIE "$ENVDEC_RE" 2>/dev/null |
    grep -v '/tests/fixtures/' |
    while read -r f; do
      LC_ALL=C grep -qE "$SINK_RE" "$f" 2>/dev/null && find_hit "ENV-DECODE-DROPPER $f"
    done
done

# [10] PyPI: Hades / lightning / LiteLLM. Three surfaces: lock/requirements files in the
#      dev tree, installed dist-info dirs anywhere under $HOME (uv tools, venvs, uv python
#      installs), and the Hades startup hook shape (*-setup.pth + _index.js in site-packages).
py_norm() { printf '%s' "$1" | sed -e 's/[-_.]/[-_.]/g'; }   # PEP 503: - _ . are interchangeable
PY_LOCKS=()
[[ -d "$DEV_DIR" ]] && while IFS= read -r f; do PY_LOCKS+=("$f"); done < <(
  find "$DEV_DIR" -maxdepth 5 -type d \( "${PRUNE[@]}" \) -prune -o -type f \
       \( -name uv.lock -o -name poetry.lock -o -name 'requirements*.txt' -o -name Pipfile.lock -o -name pyproject.toml \) -print 2>/dev/null)
# one walk of $HOME for every site-packages artefact we care about (dist-info dirs,
# .pth startup hooks, Hades _index.js); per-indicator greps run against this list
PY_INSTALLED="$(mktemp "${TMPDIR:-/tmp}/ioc-py.XXXXXX")"
find "$HOME_DIR" -maxdepth 10 \( -name Library -o -name node_modules -o -name .git -o -name .Trash \) -prune -o \
     \( -type d -name '*.dist-info' -o -type f -name '*-setup.pth' -o -type f -name '_index.js' \) -print 2>/dev/null |
  grep -v '/tests/fixtures/' > "$PY_INSTALLED"
for pk in ${IOC_PYPKG[@]+"${IOC_PYPKG[@]}"}; do
  n_re="$(py_norm "$pk")"
  for f in ${PY_LOCKS[@]+"${PY_LOCKS[@]}"}; do
    grep -qiE "(^|[\"' =])${n_re}([\"' =<>!~;[]|$)" "$f" 2>/dev/null && find_hit "MALICIOUS-PYPKG $pk $f"
  done
  grep -iE "/${n_re}-[0-9][^/]*\.dist-info$" "$PY_INSTALLED" | while read -r d; do find_hit "MALICIOUS-PYPKG $pk $d"; done
done
for pv in ${IOC_PYVER[@]+"${IOC_PYVER[@]}"}; do
  name="${pv%%	*}"; ver="${pv#*	}"; n_re="$(py_norm "$name")"; ever="$(re_escape "$ver")"
  for f in ${PY_LOCKS[@]+"${PY_LOCKS[@]}"}; do
    if grep -qiE "${n_re}==${ever}([^0-9.]|$)" "$f" 2>/dev/null ||
       grep -iA1 -E "^name = \"${n_re}\"" "$f" 2>/dev/null | grep -qE "^version = \"${ever}\""; then
      find_hit "COMPROMISED-PYPI-RELEASE $name==$ver $f"
    fi
  done
  grep -iE "/${n_re}-${ever}\.dist-info$" "$PY_INSTALLED" | while read -r d; do find_hit "COMPROMISED-PYPI-RELEASE $name==$ver $d"; done
done
grep -E 'site-packages/.*(-setup\.pth|/_index\.js)$' "$PY_INSTALLED" | while read -r f; do find_hit "PYTHON-STARTUP-HOOK $f"; done
rm -f "$PY_INSTALLED"

# [11] crates.io: Rustbot loaders and hijacked releases, in Cargo.lock files and the
#      local cargo registry (src and cache).
CARGO_LOCKS=()
[[ -d "$DEV_DIR" ]] && while IFS= read -r f; do CARGO_LOCKS+=("$f"); done < <(
  find "$DEV_DIR" -maxdepth 5 -type d \( "${PRUNE[@]}" \) -prune -o -type f -name Cargo.lock -print 2>/dev/null)
for c in ${IOC_CRATE[@]+"${IOC_CRATE[@]}"}; do
  ec="$(re_escape "$c")"
  for f in ${CARGO_LOCKS[@]+"${CARGO_LOCKS[@]}"}; do grep -qE "^name = \"${ec}\"$" "$f" 2>/dev/null && find_hit "MALICIOUS-CRATE $c $f"; done
  find "$HOME_DIR/.cargo/registry" -maxdepth 3 \( -name "${c}-[0-9]*" \) 2>/dev/null | while read -r d; do find_hit "MALICIOUS-CRATE $c $d"; done
done
for cv in ${IOC_CRATEVER[@]+"${IOC_CRATEVER[@]}"}; do
  name="${cv%%	*}"; ver="${cv#*	}"; en="$(re_escape "$name")"; ev="$(re_escape "$ver")"
  for f in ${CARGO_LOCKS[@]+"${CARGO_LOCKS[@]}"}; do
    grep -A1 -E "^name = \"${en}\"$" "$f" 2>/dev/null | grep -qE "^version = \"${ev}\"$" && find_hit "HIJACKED-CRATE-RELEASE $name@$ver $f"
  done
  find "$HOME_DIR/.cargo/registry" -maxdepth 3 \( -name "${name}-${ver}" -o -name "${name}-${ver}.crate" \) 2>/dev/null |
    while read -r d; do find_hit "HIJACKED-CRATE-RELEASE $name@$ver $d"; done
done

# [12] Agent/IDE config injection (ChainDrop, TeamPCP, Hades, Apex): the 2026 campaigns
#      persist by editing what the IDE or coding agent auto-runs — .vscode/tasks.json
#      runOn folderOpen, SessionStart hooks in .claude/.cursor settings, and MCP server
#      entries that fetch or eval. Repo-level files are matched on shape; home-level
#      agent configs are hashed against a baseline (first run records it silently;
#      --accept-config re-records after a deliberate change).
FETCH_EXEC_RE='curl |wget |base64|node -e|bun -e|python3? -c|sh -c|bash -c|/tmp/|/private/tmp/|https?://[0-9]{1,3}(\.[0-9]{1,3}){3}|atob\(|eval\('
if [[ -d "$DEV_DIR" ]]; then
  find "$DEV_DIR" -maxdepth 6 -path '*/.vscode/tasks.json' -type f -not -path '*/node_modules/*' -not -path '*/tests/fixtures/*' 2>/dev/null |
    while read -r f; do grep -q 'folderOpen' "$f" 2>/dev/null && find_hit "AUTORUN-TASK $f"; done
  find "$DEV_DIR" -maxdepth 6 \( -path '*/.claude/settings.json' -o -path '*/.claude/settings.local.json' -o -path '*/.cursor/settings.json' -o -path '*/.codex/hooks.json' \) \
       -type f -not -path '*/node_modules/*' -not -path '*/tests/fixtures/*' 2>/dev/null |
    while read -r f; do
      # only the hooks object counts: permission allowlists legitimately name curl/python -c
      hooks="$(python3 -I -c 'import json,sys
d=json.load(open(sys.argv[1])); h=d.get("hooks") or {}
print(json.dumps(h) if h else "")' "$f" 2>/dev/null)"
      [[ -z "$hooks" ]] && { command -v python3 >/dev/null 2>&1 || hooks="$(cat "$f")"; }
      [[ -z "$hooks" ]] && continue
      if grep -qE '"SessionStart"|"UserPromptSubmit"' <<<"$hooks" || grep -qE "$FETCH_EXEC_RE" <<<"$hooks"; then
        find_hit "REPO-AGENT-HOOK $f"
      fi
    done
  find "$DEV_DIR" -maxdepth 6 \( -name '.mcp.json' -o -path '*/.cursor/mcp.json' -o -path '*/.vscode/mcp.json' -o -path '*/.codex/config.toml' \) \
       -type f -not -path '*/node_modules/*' -not -path '*/tests/fixtures/*' 2>/dev/null |
    while read -r f; do grep -qE "$FETCH_EXEC_RE" "$f" 2>/dev/null && find_hit "SUSPICIOUS-MCP-CONFIG $f"; done
fi
[[ -f "$HOME_DIR/.vscode/tasks.json" ]] && grep -q folderOpen "$HOME_DIR/.vscode/tasks.json" 2>/dev/null && find_hit "AUTORUN-TASK $HOME_DIR/.vscode/tasks.json"
AGENT_CFG=( "$HOME_DIR/.cursor/mcp.json" "$HOME_DIR/.hermes/config.yaml" "$HOME_DIR/.vscode/tasks.json" "$HOME_DIR/.codex/hooks.json" "$HOME_DIR/.claude/settings.json" "$HOME_DIR/.claude.json" )
BASELINE="$STATE/agent-config.baseline"
cfg_digest() {   # ~/.claude.json churns constantly; only its MCP server maps matter
  local f="$1"
  if [[ "$(basename "$f")" == ".claude.json" ]] && command -v python3 >/dev/null 2>&1; then
    python3 -I -c 'import json,sys
d=json.load(open(sys.argv[1]))
out={"mcpServers":d.get("mcpServers",{}),"projects":{k:v.get("mcpServers") for k,v in (d.get("projects") or {}).items() if v.get("mcpServers")}}
print(json.dumps(out,sort_keys=True))' "$f" 2>/dev/null | shasum -a 256 | cut -c1-16
  else
    shasum -a 256 "$f" 2>/dev/null | cut -c1-16
  fi
}
NEWBASE="$(mktemp "${TMPDIR:-/tmp}/ioc-cfg.XXXXXX")"
for f in ${AGENT_CFG[@]+"${AGENT_CFG[@]}"}; do [[ -f "$f" ]] && printf '%s\t%s\n' "$f" "$(cfg_digest "$f")" >> "$NEWBASE"; done
if [[ ! -s "$BASELINE" || "$ACCEPT_CONFIG" == 1 ]]; then
  cp "$NEWBASE" "$BASELINE" 2>/dev/null && echo "$(date -u +%FT%TZ) agent-config baseline recorded" >> "$LOG"
else
  while IFS=$'\t' read -r f h; do
    old="$(awk -F'\t' -v f="$f" '$1==f{print $2}' "$BASELINE")"
    if [[ -z "$old" ]]; then find_hit "AGENT-CONFIG-NEW $f"
    elif [[ "$old" != "$h" ]]; then find_hit "AGENT-CONFIG-DRIFT $f (run with --accept-config after review)"
    fi
  done < "$NEWBASE"
fi
rm -f "$NEWBASE"

n=$(grep -c . "$OUT" 2>/dev/null); n=${n:-0}
echo "$(date -u +%FT%TZ) ioc sweep complete — findings: $n" >> "$LOG"
if (( n > 0 )); then
  head -30 "$OUT" >> "$LOG"
  (( NOTIFY )) && osascript -e "display notification \"$n IOC finding(s) — see ioc-sweep-findings.txt\" with title \"agent-security: ioc sweep\"" 2>/dev/null
  echo "IOC SWEEP: $n finding(s)"; cat "$OUT"
  exit 1
fi
echo "IOC SWEEP: CLEAN"
exit 0
