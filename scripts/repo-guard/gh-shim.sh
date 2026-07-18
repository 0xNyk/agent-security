#!/usr/bin/env bash
# repo-guard: PATH shim for `gh` that hard-blocks DESTRUCTIVE GitHub repository
# lifecycle operations unless a human explicitly confirms the exact repo.
#
# Why this exists: an automation that deletes/renames/privatizes/archives repos
# can wipe out a project's history and its accumulated stars in a single keystroke.
# This shim sits in front of the real gh on PATH and refuses repo-level destruction
# unless REPO_LIFECYCLE_OK names the exact target repo — turning a one-command
# catastrophe into a deliberate, per-repo human act.
#
# CONTRACT
#   - stdout is a PURE passthrough of the real gh. Guard messages go to stderr.
#   - Normal usage (view/list/clone/pr/issue/api GET/push/workflow/edit-desc)
#     execs the real gh transparently, with identical args and exit codes.
#   - Destructive repo ops are blocked (exit 1) and logged UNLESS overridden.
#
# OVERRIDE (human-in-the-loop)
#   REPO_LIFECYCLE_OK=owner/repo gh repo delete owner/repo --yes
#   Also accepts REPO_LIFECYCLE_OK=--yes-destroy-<repo>  (name or owner/repo).
#
# Blocked repo-level ops:
#   gh repo delete | rename | archive | transfer
#   gh repo edit ... --visibility private|internal
#   gh api  -X DELETE /repos/OWNER/REPO
#   gh api  -X PATCH  /repos/OWNER/REPO  (name/visibility/archived/private)
#   gh api  ...       /repos/OWNER/REPO/transfer
#   gh api  graphql   (deleteRepository / archiveRepository / updateRepository->visibility)
#
# NOT in scope (intentionally passes through): git push branch deletes,
# file/branch/label/release DELETEs on sub-resources, making a repo PUBLIC,
# unarchive, repo create/clone/fork/sync.
#
# HONEST LIMIT: a tool invoking the real gh by ABSOLUTE path (e.g. /opt/homebrew/
# bin/gh) bypasses this PATH shim. The companion Claude Code hook (pretool-hook.sh)
# closes that gap for agent sessions; a plain terminal calling the absolute path,
# or curl against the REST API, is out of scope. See references/coverage-and-limits.md.

set -uo pipefail

# ----------------------------------------------------------------------------
# 1. Locate the REAL gh (never ourselves).
# ----------------------------------------------------------------------------
self="${BASH_SOURCE[0]}"
case "$self" in
  /*) : ;;
  *)  self="$(cd "$(dirname "$self")" >/dev/null 2>&1 && pwd)/$(basename "$self")" ;;
esac
self_dir="$(cd "$(dirname "$self")" >/dev/null 2>&1 && pwd -P)"
self_real="$self_dir/$(basename "$self")"

real_gh=""
IFS=':' read -r -a _paths <<< "${PATH:-}"
for d in "${_paths[@]}"; do
  [ -z "$d" ] && continue
  cand="$d/gh"
  [ -x "$cand" ] || continue
  [ -d "$cand" ] && continue
  crdir="$(cd "$(dirname "$cand")" >/dev/null 2>&1 && pwd -P)" || continue
  creal="$crdir/$(basename "$cand")"
  # Skip if this candidate is us (by literal path or resolved dir path).
  if [ "$cand" = "$self" ] || [ "$creal" = "$self_real" ]; then
    continue
  fi
  real_gh="$cand"
  break
done
if [ -z "$real_gh" ]; then
  for cand in /opt/homebrew/bin/gh /usr/local/bin/gh /usr/bin/gh; do
    if [ -x "$cand" ] && [ "$cand" != "$self" ] && [ "$cand" != "$self_real" ]; then
      real_gh="$cand"; break
    fi
  done
fi
if [ -z "$real_gh" ]; then
  echo "repo-guard: could not locate the real gh binary; refusing to run blind." >&2
  exit 127
fi

# ----------------------------------------------------------------------------
# 2. Fast paths that are never destructive.
# ----------------------------------------------------------------------------
ALL=("$@")
n=${#ALL[@]}

# Nothing / help / version -> straight through.
if [ "$n" -eq 0 ]; then exec "$real_gh"; fi
for a in "$@"; do
  case "$a" in
    -h|--help|--version) exec "$real_gh" "$@" ;;
  esac
done

sub1="${ALL[0]:-}"
sub2="${ALL[1]:-}"

# Only `repo` and `api` subcommands can be destructive at the repo level.
case "$sub1" in
  repo|api) : ;;
  *) exec "$real_gh" "$@" ;;
esac

# ----------------------------------------------------------------------------
# 3. Small arg-scanning helpers.
# ----------------------------------------------------------------------------
# Value of --repo/-R (space or =-joined).
repo_flag=""
for ((i=0;i<n;i++)); do
  a="${ALL[$i]}"
  case "$a" in
    --repo=*) repo_flag="${a#*=}" ;;
    -R=*)     repo_flag="${a#*=}" ;;
    --repo|-R) j=$((i+1)); [ "$j" -lt "$n" ] && repo_flag="${ALL[$j]}" ;;
  esac
done

# Value of --visibility (space or =-joined).
vis=""
for ((i=0;i<n;i++)); do
  a="${ALL[$i]}"
  case "$a" in
    --visibility=*) vis="${a#*=}" ;;
    --visibility)   j=$((i+1)); [ "$j" -lt "$n" ] && vis="${ALL[$j]}" ;;
  esac
done

# First positional after the subcommand (repo target for delete/archive/edit).
pos2="${ALL[2]:-}"
case "$pos2" in -*) pos2="" ;; esac

# Resolve owner/repo target: -R flag, else provided positional, else git remote.
resolve_target() {
  local provided="${1:-}" url rest owner repo
  if [ -n "$repo_flag" ]; then printf '%s' "${repo_flag%/}"; return; fi
  if [ -n "$provided" ]; then printf '%s' "${provided%/}"; return; fi
  url="$(git -C "$PWD" config --get remote.origin.url 2>/dev/null)"
  if [ -n "$url" ]; then
    url="${url%.git}"
    repo="${url##*/}"
    rest="${url%/*}"
    owner="${rest##*[:/]}"
    if [ -n "$owner" ] && [ -n "$repo" ]; then printf '%s/%s' "$owner" "$repo"; return; fi
  fi
  printf 'UNKNOWN'
}

# Is the destructive op explicitly authorized for this exact target?
overridden() {
  local target="$1" base="${1##*/}"
  [ -n "${REPO_LIFECYCLE_OK:-}" ] || return 1
  case "$REPO_LIFECYCLE_OK" in
    "$target"|"--yes-destroy-$target"|"--yes-destroy-$base") return 0 ;;
  esac
  return 1
}

logdir="${REPO_GUARD_STATE:-$HOME/.local/state/repo-guard}"

block() {
  local what="$1" target="$2"
  mkdir -p "$logdir" 2>/dev/null && chmod 700 "$logdir" 2>/dev/null
  {
    printf '%s\tSHIM\tBLOCKED\twhat=%s\ttarget=%s\tREPO_LIFECYCLE_OK=%s\tpwd=%s\targv=' \
      "$(date -u +%FT%TZ)" "$what" "$target" "${REPO_LIFECYCLE_OK:-<unset>}" "$PWD"
    printf '%q ' "${ALL[@]}"
    printf '\n'
  } >> "$logdir/blocked.log" 2>/dev/null
  {
    echo "==================================================================="
    echo "repo-guard: BLOCKED a destructive repository operation."
    echo "  what   : $what"
    echo "  repo   : $target"
    echo "  via    : gh ${ALL[*]}"
    echo
    echo "No API call was made. This is intentional (defensive guard)."
    echo
    echo "If YOU (a human) truly intend this, re-run with the exact repo named:"
    if [ "$target" = "UNKNOWN" ]; then
      echo "  REPO_LIFECYCLE_OK=<owner/repo> gh ${ALL[*]}"
    else
      echo "  REPO_LIFECYCLE_OK=$target gh ${ALL[*]}"
    fi
    echo
    echo "Logged to: $logdir/blocked.log"
    echo "==================================================================="
  } >&2
  exit 1
}

allow_note() {
  # Record honored overrides too, for audit. Never touches stdout.
  local what="$1" target="$2"
  mkdir -p "$logdir" 2>/dev/null && chmod 700 "$logdir" 2>/dev/null
  {
    printf '%s\tSHIM\tALLOWED-OVERRIDE\twhat=%s\ttarget=%s\tpwd=%s\targv=' \
      "$(date -u +%FT%TZ)" "$what" "$target" "$PWD"
    printf '%q ' "${ALL[@]}"
    printf '\n'
  } >> "$logdir/blocked.log" 2>/dev/null
  echo "repo-guard: override honored for $what on $target (proceeding)." >&2
}

# ----------------------------------------------------------------------------
# 3b. TIER-2 triple-confirmation gate (for the IRREVERSIBLE ops: delete/transfer).
#     ALL THREE independent factors must name the SAME owner/repo, or we block:
#       (1) REPO_LIFECYCLE_OK=<owner/repo>     env  (names the exact repo)
#       (2) REPO_DESTROY_CONFIRM=<owner/repo>  env  (a 2nd deliberate re-type)
#       (3) a line == <owner/repo> in the single-use CONFIRM-DESTROY file
#     On a successful pass the matching file line is REMOVED (single-use: a
#     second delete needs a fresh confirmation). TIER-1 ops are left untouched.
# ----------------------------------------------------------------------------
confirm_file="$logdir/CONFIRM-DESTROY"

confirm_file_has_line() {  # target -> 0 if a line == target exists
  [ -f "$confirm_file" ] || return 1
  grep -qxF -- "$1" "$confirm_file" 2>/dev/null
}

confirm_file_consume() {   # target -> remove the FIRST matching line (single-use)
  local want="$1" tmp
  [ -f "$confirm_file" ] || return 0
  tmp="$(mktemp "${confirm_file}.XXXXXX" 2>/dev/null)" || return 1
  awk -v w="$want" 'BEGIN{c=0}{ if(c==0 && $0==w){c=1; next} print }' "$confirm_file" >"$tmp" 2>/dev/null \
    && mv "$tmp" "$confirm_file" 2>/dev/null
  chmod 600 "$confirm_file" 2>/dev/null || true
  rm -f "$tmp" 2>/dev/null || true
}

# Sets MISSING to the space-separated factors that are absent (empty => all present).
MISSING=""
tier2_check() {  # target -> 0 only if all three factors name this exact repo
  local target="$1"
  MISSING=""
  overridden "$target"                          || MISSING="${MISSING}LIFECYCLE "
  [ "${REPO_DESTROY_CONFIRM:-}" = "$target" ]   || MISSING="${MISSING}DESTROY "
  confirm_file_has_line "$target"               || MISSING="${MISSING}FILE "
  [ -z "$MISSING" ]
}

block2() {  # what target -- TIER-2 block: lists exactly which factors are missing
  local what="$1" target="$2"
  tier2_check "$target" || true
  mkdir -p "$logdir" 2>/dev/null && chmod 700 "$logdir" 2>/dev/null
  {
    printf '%s\tSHIM\tBLOCKED-TIER2\twhat=%s\ttarget=%s\tmissing=%s\tpwd=%s\targv=' \
      "$(date -u +%FT%TZ)" "$what" "$target" "${MISSING:-none}" "$PWD"
    printf '%q ' "${ALL[@]}"
    printf '\n'
  } >> "$logdir/blocked.log" 2>/dev/null
  {
    echo "==================================================================="
    echo "repo-guard: BLOCKED a TIER-2 (IRREVERSIBLE) repository operation."
    echo "  what   : $what"
    echo "  repo   : $target"
    echo "  via    : gh ${ALL[*]}"
    echo
    echo "delete/transfer is IRREVERSIBLE -- it destroys stars, forks, issues and"
    echo "history. It requires TRIPLE, independent confirmation; ALL THREE must"
    echo "name the SAME repo. Missing factor(s):"
    echo
    case " $MISSING " in *" LIFECYCLE "*)
      echo "  [ ] 1. REPO_LIFECYCLE_OK=$target        (env -- names the exact repo)" ;;
    esac
    case " $MISSING " in *" DESTROY "*)
      echo "  [ ] 2. REPO_DESTROY_CONFIRM=$target     (env -- re-type the exact repo)" ;;
    esac
    case " $MISSING " in *" FILE "*)
      echo "  [ ] 3. a line '$target' in $confirm_file"
      echo "         add it: printf '%s\\n' '$target' >> $confirm_file" ;;
    esac
    echo
    if [ "$target" = "UNKNOWN" ]; then
      echo "NOTE: the target repo could not be determined (e.g. via graphql). Re-run"
      echo "      the explicit form  gh repo delete <owner/repo>  so the guard can"
      echo "      name the repo and you can supply the three factors."
    else
      echo "Full recipe (all three name the same repo; file line consumed on success):"
      echo "  printf '%s\\n' '$target' >> $confirm_file"
      echo "  REPO_LIFECYCLE_OK=$target REPO_DESTROY_CONFIRM=$target gh ${ALL[*]}"
    fi
    echo
    echo "No API call was made. Logged to: $logdir/blocked.log"
    echo
    echo "HONEST LIMIT: this is a strong LOCAL brake, not an absolute block. An"
    echo "absolute-path gh outside a Claude session and curl/octokit against the REST"
    echo "API still bypass it. The only CATEGORICAL block on delete/transfer is an"
    echo "auth token WITHOUT the delete_repo scope. Triple-confirm != unbypassable."
    echo "==================================================================="
  } >&2
  exit 1
}

# ----------------------------------------------------------------------------
# 4. gh repo <delete|rename|archive|transfer|edit>
#    TIER 2 (triple-confirm): delete, transfer.  TIER 1 (single REPO_LIFECYCLE_OK):
#    rename, archive, edit --visibility private|internal.
# ----------------------------------------------------------------------------
if [ "$sub1" = "repo" ]; then
  what=""; target=""; tier=1
  case "$sub2" in
    delete)   what="repo delete";   target="$(resolve_target "$pos2")"; tier=2 ;;
    transfer) what="repo transfer"; target="$(resolve_target "$pos2")"; tier=2 ;;
    archive)  what="repo archive";  target="$(resolve_target "$pos2")" ;;
    rename)   what="repo rename";   target="$(resolve_target "")"     ;;  # pos2 is the NEW name
    edit)
      case "$vis" in
        private|internal) what="repo edit --visibility $vis"; target="$(resolve_target "$pos2")" ;;
        *) exec "$real_gh" "$@" ;;   # description/topics/default-branch/public = safe
      esac
      ;;
    *) exec "$real_gh" "$@" ;;       # create/list/clone/view/fork/sync/unarchive...
  esac
  if [ "$tier" = 2 ]; then
    if tier2_check "$target"; then
      confirm_file_consume "$target"; allow_note "TIER2 $what" "$target"; exec "$real_gh" "$@"
    fi
    block2 "$what" "$target"
  fi
  if overridden "$target"; then allow_note "$what" "$target"; exec "$real_gh" "$@"; fi
  block "$what" "$target"
fi

# ----------------------------------------------------------------------------
# 5. gh api ...   (REST + a light graphql check)
# ----------------------------------------------------------------------------
if [ "$sub1" = "api" ]; then
  method=""
  has_fields=0
  has_input=0
  ep=""
  graphql=0

  for ((i=1;i<n;i++)); do
    a="${ALL[$i]}"
    case "$a" in
      -X|--method) j=$((i+1)); [ "$j" -lt "$n" ] && method="${ALL[$j]}" ;;
      -X=*|--method=*) method="${a#*=}" ;;
      -X[A-Za-z]*) method="${a#-X}" ;;                      # curl-style -XDELETE
      -f|-F|--field|--raw-field) has_fields=1 ;;
      -f=*|-F=*|--field=*|--raw-field=*) has_fields=1 ;;
      --input|--input=*) has_input=1 ;;
      graphql) graphql=1 ;;
      -*) : ;;                                              # other flag: ignore
      *repos/*) [ -z "$ep" ] && ep="$a" ;;                  # endpoint (path or URL)
    esac
  done
  method="$(printf '%s' "${method:-GET}" | tr '[:lower:]' '[:upper:]')"

  # Light graphql guard: block obvious repo-destroying mutations.
  if [ "$graphql" -eq 1 ]; then
    for ((i=1;i<n;i++)); do
      case "${ALL[$i]}" in
        *deleteRepository*)
          block2 "repo delete via graphql" "UNKNOWN" ;;   # TIER 2 (unknown target -> cannot satisfy)
        *archiveRepository*)
          block "repo archive via graphql" "UNKNOWN" ;;    # TIER 1
        *updateRepository*)
          case "${ALL[$i]}" in
            *[Vv]isibility*PRIVATE*|*[Vv]isibility*INTERNAL*|*private*true*)
              block "repo privatize via graphql" "UNKNOWN" ;;  # TIER 1
          esac ;;
      esac
    done
    exec "$real_gh" "$@"
  fi

  # Normalize endpoint down to  repos/OWNER/REPO[/...]
  p="$ep"
  case "$p" in
    */repos/*) p="repos/${p#*/repos/}" ;;
    repos/*)   : ;;
    */repos)   p="repos" ;;
    repos)     : ;;
    *) p="" ;;
  esac
  p="${p%%\?*}"        # strip query string
  p="${p%/}"           # strip trailing slash
  p="${p#/}"           # strip leading slash

  if [ -n "$p" ]; then
    # Transfer: any method on /repos/OWNER/REPO/transfer  -- TIER 2 (triple-confirm).
    if [[ "$p" =~ ^repos/[^/]+/[^/]+/transfer$ ]]; then
      target="$(printf '%s' "$p" | sed -E 's#^repos/([^/]+/[^/]+)/transfer$#\1#')"
      if tier2_check "$target"; then
        confirm_file_consume "$target"; allow_note "TIER2 api repo transfer" "$target"; exec "$real_gh" "$@"
      fi
      block2 "repo transfer via gh api" "$target"
    fi
    # Repo root: /repos/OWNER/REPO  (delete / rename / privatize / archive)
    if [[ "$p" =~ ^repos/[^/]+/[^/]+$ ]]; then
      target="${p#repos/}"
      # TIER 2: DELETE /repos/OWNER/REPO is an irreversible repo delete.
      if [ "$method" = "DELETE" ]; then
        if tier2_check "$target"; then
          confirm_file_consume "$target"; allow_note "TIER2 repo delete via gh api" "$target"; exec "$real_gh" "$@"
        fi
        block2 "repo delete via gh api" "$target"
      fi
      # TIER 1: PATCH/PUT (or fields) that rename / privatize / archive the repo.
      danger=""
      if [ "$method" = "PATCH" ] || [ "$method" = "PUT" ] || \
           { [ "$has_fields" -eq 1 ] && { [ "$method" = "POST" ] || [ "$method" = "GET" ]; }; }; then
        # PATCH/PUT to repo root, or fields present (gh defaults to POST):
        # dangerous only if it changes name/visibility/archived/private.
        if [ "$has_input" -eq 1 ]; then
          danger="repo mutate via gh api (--input to repo root)"
        else
          for ((i=1;i<n;i++)); do
            case "${ALL[$i]}" in
              name=*|visibility=*|archived=*|private=*)
                danger="repo mutate via gh api (${ALL[$i]%%=*})" ; break ;;
            esac
          done
        fi
      fi
      if [ -n "$danger" ]; then
        if overridden "$target"; then allow_note "$danger" "$target"; exec "$real_gh" "$@"; fi
        block "$danger" "$target"
      fi
    fi
  fi

  exec "$real_gh" "$@"
fi

# ----------------------------------------------------------------------------
# 6. Anything else: transparent passthrough.
# ----------------------------------------------------------------------------
exec "$real_gh" "$@"
