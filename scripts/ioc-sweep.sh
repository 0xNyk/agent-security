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
#   ioc-sweep.sh --strict-actions    every GitHub Action used by tag/branch is a finding
#   ioc-sweep.sh --depth N           workspace walk depth (default 8)
#   ioc-sweep.sh --timing            per-section seconds on stderr
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
STRICT_ACTIONS=0
DEV_DEPTH=8
TIMING=0
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
    --strict-actions) STRICT_ACTIONS=1; shift ;;
    --depth) DEV_DEPTH="$2"; shift 2 ;;
    --timing) TIMING=1; shift ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
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
# Every temporary list lives in one private directory that a trap removes on any exit,
# including Ctrl-C and kill, so an interrupted sweep leaves nothing behind in tmp.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ioc-sweep.XXXXXX")" || { echo "BLIND: cannot create a work directory" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Plain nice, not background QoS: taskpolicy -b throttles IO and pins to efficiency cores,
# which made a 10-minute sweep take 40. A shorter run at low CPU priority disturbs the
# machine less than a long one at throttled IO.
renice -n 10 -p $$ >/dev/null 2>&1

find_hit() { printf '%s\n' "$*" >> "$OUT"; }
note() { printf '%s\n' "$*" >> "$NOTES"; }
NOTES="$STATE/ioc-sweep-notes.txt"; : > "$NOTES"
T_LAST=$SECONDS
mark() { (( TIMING )) || return 0; printf '  %-28s %4ds\n' "$1" $((SECONDS - T_LAST)) >&2; T_LAST=$SECONDS; }

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
  RP_EXPR=(); for rp in "${IOC_REPOPATHS[@]}"; do RP_EXPR+=( -o -path "*/$rp" ); done
  find "$DEV_DIR" -maxdepth "$DEV_DEPTH" -type d \( "${PRUNE[@]}" \) -prune -o \( "${RP_EXPR[@]:1}" \) -print 2>/dev/null |
    grep -v '/tests/fixtures/' |
    while read -r f; do find_hit "REPO-PATH $f"; done
fi
for p in ${IOC_PATHS[@]+"${IOC_PATHS[@]}"}; do
  [[ -e "$HOME_DIR/$p" ]] && find_hit "DROP-PATH $HOME_DIR/$p"
done
mark '[1] drop paths'

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
mark '[2] payload filenames'

# [3] Shai-Hulud preinstall hooks in installed package manifests.
if [[ -d "$DEV_DIR" ]]; then
  find "$DEV_DIR" -maxdepth 8 -name package.json -type f -print0 2>/dev/null |
    xargs -0 -n 200 grep -lE '"(pre|post)install"[[:space:]]*:[[:space:]]*"[^"]*(setup_bun|bun_environment|setup\.m?js|bw_setup|router_init|tanstack_runner)' 2>/dev/null |
    while read -r f; do find_hit "PREINSTALL-HOOK $f"; done
fi

# [4] npm lookalike packages in lockfiles. One walk collects every npm manifest and
#     lockfile in the workspace; [4] and every [4b] version check read that list instead
#     of walking once per indicator.
LOCK_LIST="$(mktemp "$WORK/ioc-locks.XXXXXX")"
[[ -d "$DEV_DIR" ]] && find "$DEV_DIR" -maxdepth 5 -type d \( "${PRUNE[@]}" \) -prune -o -type f \
     \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name bun.lock -o -name bun.lockb -o -name package.json \) -print 2>/dev/null > "$LOCK_LIST"
if (( ${#IOC_PKGS[@]} )) && [[ -s "$LOCK_LIST" ]]; then
  PKG_RE="$(printf '%s|' "${IOC_PKGS[@]}")"; PKG_RE="${PKG_RE%|}"
  while read -r f; do   # -a: bun.lockb is binary, and grep without it reports no match
    grep -aqE "(^|[\"'/ ])(${PKG_RE})[@\"':/ ]" "$f" 2>/dev/null && find_hit "LOOKALIKE-PKG $f"
  done < "$LOCK_LIST"
fi

# [4b] Specific compromised npm releases: lockfiles + manifests, installed node_modules
#      manifests, and the bun/npx caches (dir names carry name@version).
if (( ${#IOC_NPMVER[@]} )); then
  NM_MANIFESTS="$(mktemp "$WORK/ioc-nm.XXXXXX")"
  if [[ -d "$DEV_DIR" ]]; then
    NM_EXPR=(); for nv in ${IOC_NPMVER[@]+"${IOC_NPMVER[@]}"}; do NM_EXPR+=( -o -path "*/node_modules/${nv%%	*}/package.json" ); done
    find "$DEV_DIR" -maxdepth 9 -type f \( "${NM_EXPR[@]:1}" \) 2>/dev/null > "$NM_MANIFESTS"
  fi
  for nv in ${IOC_NPMVER[@]+"${IOC_NPMVER[@]}"}; do
    name="${nv%%	*}"; ver="${nv#*	}"; ename="$(re_escape "$name")"; ever="$(re_escape "$ver")"
    base="${name##*/}"
    if [[ -s "$LOCK_LIST" ]]; then
      while read -r f; do
        grep -aqE "(${ename}@${ever}([^0-9.]|$)|\"${ename}\"[[:space:]]*:[[:space:]]*\"${ever}\"|/${ename}/-/${base}-${ever}\.tgz|/${ename}@${ever}[:/])" "$f" 2>/dev/null &&
          find_hit "COMPROMISED-NPM-RELEASE $name@$ver $f"
      done < "$LOCK_LIST"
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
rm -f "$LOCK_LIST"

# [5] Rogue GitHub Actions workflows and self-hosted runner installs. One walk of the
#     workspace collects every workflow file; [5], [5b] and [5c] read that list.
WF_LIST="$(mktemp "$WORK/ioc-wf.XXXXXX")"
[[ -d "$DEV_DIR" ]] && find "$DEV_DIR" -maxdepth "$DEV_DEPTH" -type d \( "${PRUNE[@]}" \) -prune -o -path '*/.github/workflows/*' -type f -print 2>/dev/null > "$WF_LIST"
if (( ${#IOC_WORKFLOW[@]} )) && [[ -s "$WF_LIST" ]]; then
  # A token that is a workflow FILENAME only matches the basename: a workflow that merely
  # mentions security-audit.yml in a comment is not a rogue workflow. Marker tokens
  # (commit-search strings, exfil hosts) still match anywhere in the content.
  WF_NAME_RE=''; WF_BODY_RE=''
  for w in "${IOC_WORKFLOW[@]}"; do
    ew="$(re_escape "$w")"
    case "$w" in *.yml|*.yaml) WF_NAME_RE+="${ew}|" ;; *) WF_BODY_RE+="${ew}|" ;; esac
  done
  WF_NAME_RE="${WF_NAME_RE%|}"; WF_BODY_RE="${WF_BODY_RE%|}"
  while read -r f; do
      if [[ -n "$WF_NAME_RE" && "$(basename "$f")" =~ ^(${WF_NAME_RE})$ ]]; then
        find_hit "ROGUE-WORKFLOW $f (filename)"
      elif [[ -n "$WF_BODY_RE" ]] && grep -qiE "${WF_BODY_RE}" "$f" 2>/dev/null; then
        find_hit "ROGUE-WORKFLOW $f"
      fi
  done < "$WF_LIST"
fi
# [5b] Actions whose tags were hijacked: any use that is not a 40-hex commit pin.
if (( ${#IOC_ACTIONREF[@]} )) && [[ -s "$WF_LIST" ]]; then
  AR_RE=''; for a in "${IOC_ACTIONREF[@]}"; do AR_RE+="$(re_escape "$a")|"; done; AR_RE="${AR_RE%|}"
  while read -r f; do
    # one pass per file: every use of a listed action that is not a 40-hex pin
    grep -oE "uses:[[:space:]]*['\"]?(${AR_RE})(/[^@[:space:]]*)?@[^[:space:]'\"#]+" "$f" 2>/dev/null |
      grep -vE '@[0-9a-f]{40}$' | sed -E "s/^uses:[[:space:]]*['\"]?//; s#^([^/]+/[^/@]+).*#\1#" | sort -u |
      while read -r a; do find_hit "HIJACKED-ACTION-BY-TAG $a $f"; done
  done < "$WF_LIST"
fi
# [5c] Every third-party action used by tag or branch. The known-hijacked list above is
#      always one publication behind; the only durable protection is a full-SHA pin, so
#      the sweep reports the exposure. A note by default (count + file list in
#      ioc-sweep-notes.txt), a finding per use with --strict-actions.
if [[ -s "$WF_LIST" ]]; then
  UNPINNED="$(mktemp "$WORK/ioc-unpin.XXXXXX")"
  grep -v '/tests/fixtures/' "$WF_LIST" |
    while read -r f; do
      grep -oE "uses:[[:space:]]*['\"]?[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[^[:space:]'\"#]+" "$f" 2>/dev/null |
        grep -vE '@[0-9a-f]{40}$' | sed -E "s/^uses:[[:space:]]*['\"]?//" |
        while read -r u; do printf '%s\t%s\n' "$u" "$f"; done
    done > "$UNPINNED"
  if [[ -s "$UNPINNED" ]]; then
    if (( STRICT_ACTIONS )); then
      while IFS=$'\t' read -r u f; do find_hit "UNPINNED-ACTION $u $f"; done < "$UNPINNED"
    else
      note "unpinned-actions: $(wc -l < "$UNPINNED" | tr -d ' ') use(s) by tag or branch in $(cut -f2 "$UNPINNED" | sort -u | wc -l | tr -d ' ') workflow file(s); pin to full commit SHAs or run with --strict-actions"
      sort -u "$UNPINNED" | sed 's/^/  /' >> "$NOTES"
    fi
  fi
  rm -f "$UNPINNED"
fi
rm -f "$WF_LIST"
for r in "$HOME_DIR"/actions-runner "$HOME_DIR"/.runner "$HOME_DIR"/*/.runner; do
  [[ -e "$r" ]] && find_hit "ACTIONS-RUNNER $r"
done
mark '[5] workflows + actions'

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
# Mach-O header filetype: 2 executable, 6 dylib, 8 bundle. A bundle or dylib cannot run on
# its own; Electron apps unpack their native addons (*.node) into tmp under names like
# .com.electron.<app>.XXXXXX, so those are a note. Fat binaries stay findings.
mach_filetype() {
  local m="$1" f="$2" b
  b="$(od -An -tx1 -j12 -N4 "$f" 2>/dev/null | tr -d ' \n')"; [[ ${#b} -eq 8 ]] || return 0
  case "$m" in
    cffaedfe|cefaedfe) printf '%d' "0x${b:6:2}${b:4:2}${b:2:2}${b:0:2}" ;;   # little-endian
    *)                 printf '%d' "0x$b" ;;
  esac
}
SCRIPT_LURE_RE='curl |wget |base64 (-d|-D|--decode)|\beval |/dev/tcp/|osascript|xattr -[dc] |nohup |launchctl (load|bootstrap)|python3? -c|node -e|chmod \+x /tmp|/private/tmp/\.|\$\(curl'
for t in ${TMP_DIRS[@]+"${TMP_DIRS[@]}"}; do
  [[ -n "$t" && -d "$t" ]] || continue
  for g in ${IOC_TMPGLOBS[@]+"${IOC_TMPGLOBS[@]}"}; do
    find "$t" -mindepth 1 -maxdepth 1 -name "$g" 2>/dev/null | while read -r f; do find_hit "TMP-STAGING $f"; done
  done
  find "$t" -maxdepth 2 -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) -mtime "-$DAYS" 2>/dev/null |
    while read -r f; do
      magic="$(head -c 4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
      case "$magic" in
        cffaedfe|cefaedfe|feedfacf|feedface)
          ft="$(mach_filetype "$magic" "$f")"
          if [[ "$ft" == 6 || "$ft" == 8 ]]; then note "tmp-macho-library: $f (Mach-O bundle/dylib, needs a host process; Electron apps unpack native addons here)"
          else find_hit "TMP-MACHO $f"; fi ;;
        cafebabe) find_hit "TMP-MACHO $f" ;;
        7f454c46) find_hit "TMP-ELF $f" ;;
        2321*)   # '#!' — an executable script in tmp is common (installers, editors); it is a
                 # finding only when its body carries a stager shape, otherwise a note
          if LC_ALL=C grep -qE "$SCRIPT_LURE_RE" "$f" 2>/dev/null; then find_hit "TMP-SCRIPT $f"
          else note "tmp-script: $f (executable script in tmp, no stager shape)"; fi ;;
      esac
    done
done
mark '[8] tmp + apple-named'

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
  find "$root" -maxdepth "$((DEV_DEPTH + 1))" \( "${PRUNE[@]}" \) -prune -o -type f \( "${SRC_EXT[@]}" \) -size -2M -print0 2>/dev/null |
    xargs -0 grep -lIE "$ENVDEC_RE" 2>/dev/null |
    grep -v '/tests/fixtures/' |
    while read -r f; do
      LC_ALL=C grep -qE "$SINK_RE" "$f" 2>/dev/null && find_hit "ENV-DECODE-DROPPER $f"
    done
done
mark '[9] env-decode dropper'

# [10] PyPI: Hades / lightning / LiteLLM. Three surfaces: lock/requirements files in the
#      dev tree, installed dist-info dirs anywhere under $HOME (uv tools, venvs, uv python
#      installs), and the Hades startup hook shape (*-setup.pth + _index.js in site-packages).
py_norm() { printf '%s' "$1" | sed -e 's/[-_.]/[-_.]/g'; }   # PEP 503: - _ . are interchangeable
PY_LOCKS=()
[[ -d "$DEV_DIR" ]] && while IFS= read -r f; do PY_LOCKS+=("$f"); done < <(
  find "$DEV_DIR" -maxdepth "$DEV_DEPTH" -type d \( "${PRUNE[@]}" \) -prune -o -type f \
       \( -name uv.lock -o -name poetry.lock -o -name 'requirements*.txt' -o -name Pipfile.lock -o -name pyproject.toml \) -print 2>/dev/null)
# one walk of $HOME for every site-packages artefact we care about (dist-info dirs,
# .pth startup hooks, Hades _index.js); per-indicator greps run against this list
PY_INSTALLED="$(mktemp "$WORK/ioc-py.XXXXXX")"
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
  find "$DEV_DIR" -maxdepth "$DEV_DEPTH" -type d \( "${PRUNE[@]}" \) -prune -o -type f -name Cargo.lock -print 2>/dev/null)
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
# Codex [projects."<path>"] trust tables name directories, not commands; they are dropped
# before the fetch/exec grep so a trusted scratch project under /tmp does not fire.
TOML_NOPROJ='^[[:space:]]*\[projects\.'
FETCH_EXEC_RE='curl |wget |base64|node -e|bun -e|python3? -c|sh -c|bash -c|/tmp/|/private/tmp/|https?://[0-9]{1,3}(\.[0-9]{1,3}){3}|atob\(|eval\('
HAVE_PY=1; command -v python3 >/dev/null 2>&1 || { HAVE_PY=0; find_hit "AGENT-CONFIG-UNCHECKED python3 missing: agent config JSON could not be inspected"; }
# Prints the hooks object of a settings file; prints nothing when there is none; returns
# 1 when the file is not valid JSON (a broken config is a finding, not an empty one).
hooks_object() {
  (( HAVE_PY )) || { cat "$1" 2>/dev/null; return 0; }
  python3 -I -c 'import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(1)
h=d.get("hooks") if isinstance(d,dict) else None
print(json.dumps(h) if h else "")' "$1" 2>/dev/null
}
# The MCP server maps of a JSON config (mcp.json, .claude.json incl. per-project maps).
mcp_maps() {
  (( HAVE_PY )) || { cat "$1" 2>/dev/null; return 0; }
  python3 -I -c 'import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(1)
if not isinstance(d,dict): sys.exit(1)
out={"mcpServers":d.get("mcpServers",{}),"projects":{k:v.get("mcpServers") for k,v in (d.get("projects") or {}).items() if isinstance(v,dict) and v.get("mcpServers")}}
print(json.dumps(out,sort_keys=True))' "$1" 2>/dev/null
}
# The env map of a JSON agent config (Claude settings): where a base-URL redirect lands.
API_KEYS="$(mktemp "$WORK/ioc-apikeys.XXXXXX")"
env_object() {
  (( HAVE_PY )) || { cat "$1" 2>/dev/null; return 0; }
  python3 -I -c 'import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(1)
e=d.get("env") if isinstance(d,dict) else None
if isinstance(e,dict):
    for k,v in e.items(): print(k, "=", json.dumps(v))' "$1" 2>/dev/null
}
# API base-URL redirect (the Downloads-folder AGENTS.md / CLAUDE.md lure, October 2026): a
# redirected ANTHROPIC_BASE_URL / chatgpt_base_url hands the session token to whoever runs
# the endpoint and lets them answer with tool calls. Repository scope is a finding; home
# scope is a finding when the target is plain http or an IP literal and a note otherwise,
# because a deliberate proxy lives there. Prints the file, never the URL.
API_URL_RE='^[[:space:]]*((ANTHROPIC|OPENAI|CLAUDE|CODEX)[A-Z_]*(BASE_URL|API_BASE)|chatgpt_base_url|base_url)[[:space:]]*='
api_redirect() {
  local f="$1" scope="$2"
  case "$f" in
    *.json) env_object "$f" ;;   # unparseable: prints nothing here, the hooks check reports it
    *)      cat "$f" ;;
  esac 2>/dev/null | grep -E "$API_URL_RE" > "$API_KEYS"   # one matched key per line; only their values are tested
  [[ -s "$API_KEYS" ]] || return 0
  # a local model server (Ollama, LM Studio) is a plain-http loopback URL and a note, not a finding
  if [[ "$scope" == repo ]] ||
     grep -viE '//(localhost|127\.[0-9.]+|0\.0\.0\.0|\[::1\])([:/"]|$)' "$API_KEYS" | grep -qiE 'http://|https?://([^@/]*@)?[0-9]{1,3}(\.[0-9]{1,3}){3}'; then
    find_hit "AGENT-API-REDIRECT $f"
  else
    note "agent-api-url: $f sets a custom API base URL (review it once; a redirect leaks the session token)"
  fi
}
if [[ -d "$DEV_DIR" ]]; then
  CFG_LIST="$(mktemp "$WORK/ioc-cfg-list.XXXXXX")"
  find "$DEV_DIR" -maxdepth "$DEV_DEPTH" -type d \( "${PRUNE[@]}" \) -prune -o -type f \
       \( -path '*/.vscode/tasks.json' -o -path '*/.claude/settings.json' -o -path '*/.claude/settings.local.json' \
          -o -path '*/.cursor/settings.json' -o -path '*/.codex/hooks.json' -o -name '.mcp.json' \
          -o -path '*/.cursor/mcp.json' -o -path '*/.vscode/mcp.json' -o -path '*/.codex/config.toml' -o -name '.npmrc' \) -print 2>/dev/null |
    grep -v '/tests/fixtures/' > "$CFG_LIST"
  grep '/\.vscode/tasks\.json$' "$CFG_LIST" |
    while read -r f; do grep -q 'folderOpen' "$f" 2>/dev/null && find_hit "AUTORUN-TASK $f"; done
  grep -E '/\.(claude/settings(\.local)?|cursor/settings|codex/hooks)\.json$' "$CFG_LIST" |
    while read -r f; do
      # only the hooks object counts: permission allowlists legitimately name curl/python -c
      hooks="$(hooks_object "$f")" || { find_hit "AGENT-CONFIG-UNPARSEABLE $f"; continue; }
      [[ -z "$hooks" ]] && continue
      if grep -qE '"SessionStart"|"UserPromptSubmit"' <<<"$hooks" || grep -qE "$FETCH_EXEC_RE" <<<"$hooks"; then
        find_hit "REPO-AGENT-HOOK $f"
      fi
    done
  grep -E '/\.claude/settings(\.local)?\.json$|/\.codex/config\.toml$' "$CFG_LIST" |
    while read -r f; do api_redirect "$f" repo; done
  # a committed .npmrc carrying a literal registry token: the fake-interview Tailwind lure
  # (October 2026) needs it so its private scoped payload resolves. Path only, never the value.
  grep '/\.npmrc$' "$CFG_LIST" |
    while read -r f; do grep -qE '_authToken[[:space:]]*=[[:space:]]*["'"'"']?[^$"'"'"'[:space:]]' "$f" 2>/dev/null && find_hit "NPMRC-TOKEN $f"; done
  grep -E '(/\.mcp\.json|/\.cursor/mcp\.json|/\.vscode/mcp\.json|/\.codex/config\.toml)$' "$CFG_LIST" |
    while read -r f; do grep -vE "$TOML_NOPROJ" "$f" 2>/dev/null | grep -qE "$FETCH_EXEC_RE" && find_hit "SUSPICIOUS-MCP-CONFIG $f"; done
  rm -f "$CFG_LIST"
fi
[[ -f "$HOME_DIR/.vscode/tasks.json" ]] && grep -q folderOpen "$HOME_DIR/.vscode/tasks.json" 2>/dev/null && find_hit "AUTORUN-TASK $HOME_DIR/.vscode/tasks.json"
# Home agent configs are shape-checked on EVERY run, so the hash baseline below never
# blesses a fetch-and-exec hook or MCP entry that was already there on the first run.
# Session-start hooks are not flagged at home level: operators install their own.
for f in "$HOME_DIR/.claude/settings.json" "$HOME_DIR/.codex/hooks.json"; do
  [[ -f "$f" ]] || continue
  hooks="$(hooks_object "$f")" || { find_hit "AGENT-CONFIG-UNPARSEABLE $f"; continue; }
  [[ -n "$hooks" ]] && grep -qE "$FETCH_EXEC_RE" <<<"$hooks" && find_hit "HOME-AGENT-HOOK $f (fetch/exec shape in hooks)"
done
for f in "$HOME_DIR/.cursor/mcp.json" "$HOME_DIR/.claude.json"; do
  [[ -f "$f" ]] || continue
  maps="$(mcp_maps "$f")" || { find_hit "AGENT-CONFIG-UNPARSEABLE $f"; continue; }
  [[ -n "$maps" ]] && grep -qE "$FETCH_EXEC_RE" <<<"$maps" && find_hit "HOME-MCP-CONFIG $f (fetch/exec shape in MCP servers)"
done
[[ -f "$HOME_DIR/.hermes/config.yaml" ]] && grep -qE "$FETCH_EXEC_RE" "$HOME_DIR/.hermes/config.yaml" 2>/dev/null && find_hit "HOME-AGENT-HOOK $HOME_DIR/.hermes/config.yaml (fetch/exec shape)"
[[ -f "$HOME_DIR/.codex/config.toml" ]] && grep -vE "$TOML_NOPROJ" "$HOME_DIR/.codex/config.toml" 2>/dev/null | grep -qE "$FETCH_EXEC_RE" && find_hit "HOME-MCP-CONFIG $HOME_DIR/.codex/config.toml (fetch/exec shape)"
for f in "$HOME_DIR/.claude/settings.json" "$HOME_DIR/.codex/config.toml"; do [[ -f "$f" ]] && api_redirect "$f" home; done
AGENT_CFG=( "$HOME_DIR/.cursor/mcp.json" "$HOME_DIR/.hermes/config.yaml" "$HOME_DIR/.vscode/tasks.json" "$HOME_DIR/.codex/hooks.json" "$HOME_DIR/.codex/config.toml" "$HOME_DIR/.claude/settings.json" "$HOME_DIR/.claude.json" )
BASELINE="$STATE/agent-config.baseline"
cfg_digest() {   # ~/.claude.json churns constantly; only its MCP server maps matter
  local f="$1"
  if [[ "$(basename "$f")" == ".claude.json" ]] && (( HAVE_PY )); then
    # an unparseable file hashes as its raw bytes, never as a constant empty digest
    { mcp_maps "$f" || cat "$f"; } | shasum -a 256 | cut -c1-16
  else
    shasum -a 256 "$f" 2>/dev/null | cut -c1-16
  fi
}
NEWBASE="$(mktemp "$WORK/ioc-cfg.XXXXXX")"
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
rm -f "$NEWBASE" "$API_KEYS"
mark '[12] agent configs'

n=$(grep -c . "$OUT" 2>/dev/null); n=${n:-0}
if [[ -s "$NOTES" ]]; then echo "NOTES ($(grep -c '^[a-z]' "$NOTES") item(s), not findings): $NOTES"; grep '^[a-z]' "$NOTES" | sed 's/^/  /'; fi
echo "$(date -u +%FT%TZ) ioc sweep complete — findings: $n" >> "$LOG"
if (( n > 0 )); then
  head -30 "$OUT" >> "$LOG"
  (( NOTIFY )) && osascript -e "display notification \"$n IOC finding(s) — see ioc-sweep-findings.txt\" with title \"agent-security: ioc sweep\"" 2>/dev/null
  echo "IOC SWEEP: $n finding(s)"; cat "$OUT"
  exit 1
fi
echo "IOC SWEEP: CLEAN"
exit 0
