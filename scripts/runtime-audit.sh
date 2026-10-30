#!/usr/bin/env bash
# runtime-audit.sh — read-only audit of the HOST RUNTIME surface.
#
# Why this exists: every other control in this project watches a gate. scan-repo and
# vet-incoming watch repository content, scan-content and check-url watch what an
# agent reads and fetches, repo-guard watches destructive commands. None of them
# watches what is ALREADY RUNNING.
#
# That gap is not theoretical. A node command-line implant ran for four and a half
# days on a machine where every other control in this project was installed and
# reporting healthy. It never appeared in a repository and never passed through an
# agent tool call, so nothing looked at it. This script looks at it.
#
# Checks:
#   1. Inline-eval interpreter processes (node -e, python -c, deno eval, bun -e).
#      Legitimate inline eval is short-lived; a long-lived one is the dropper shape.
#   2. Dropper shapes inside process command lines — an eval sink co-occurring with
#      an encoder, a network fetcher, a respawn call, or a blockchain-C2 host,
#      mirroring the same-file co-occurrence rule in scan-repo.sh.
#   3. Orphaned interpreters (PPID 1) — a parent that exited after spawning a
#      detached child is the classic persistence stager.
#   4. Autostart persistence drift against a recorded baseline (launchd plists on
#      macOS, systemd user units / XDG autostart / cron.d on Linux).
#   5. Shell-profile and agent-config drift against a recorded baseline.
#
# Exit: 0 clean or drift, 1 when any CRITICAL is found (usable as a cron gate),
# 2 when a check could not run at all (unreadable baseline, bad arguments). The 2
# exists because the failure mode that matters here is a broken check that looks
# like a clean one: BLIND is reported as loudly as a finding, never as a pass.
#
# Read-only: it reads process metadata and file paths. It kills nothing and changes
# nothing except writing its own baseline under --update-baseline.
#
# LIMITS, up front. This reads COMMAND LINES. An implant that execs from a file,
# rewrites its own argv, or sleeps between beacons is invisible to it. It is also
# POINT-IN-TIME: it finds what is running at the moment you run it. Schedule it, or
# it will only ever tell you about the implant you already suspected. It is a
# tripwire for a known shape, not endpoint detection and response.
set -uo pipefail

BASELINE_DIR="${AGENT_SECURITY_BASELINE:-${XDG_CONFIG_HOME:-$HOME/.config}/agent-security/runtime-baseline}"
UPDATE_BASELINE=0
QUIET=0
# Triage/test input: raw `ps -eo pid=,ppid=,etime=,command=` output captured
# elsewhere, analysed instead of this host's live process table.
PS_FILE="${RUNTIME_AUDIT_PS_FILE:-}"
# An inline-eval interpreter alive longer than this is treated as anomalous.
MAX_INLINE_EVAL_SECONDS="${MAX_INLINE_EVAL_SECONDS:-3600}"

usage() {
  cat <<'USAGE'
runtime-audit.sh — read-only audit of running processes and autostart persistence.

  scripts/runtime-audit.sh                      audit this host
  scripts/runtime-audit.sh --update-baseline    accept current persistence state
  scripts/runtime-audit.sh --ps-file FILE       audit a captured `ps` table instead
  scripts/runtime-audit.sh --baseline-dir DIR   use an alternate baseline location
  scripts/runtime-audit.sh --quiet              print findings and the verdict only

Exit 0 clean or drift · 1 CRITICAL findings · 2 a check could not run (BLIND).

Capture a process table for --ps-file with:
  ps -eo pid=,ppid=,etime=,command= > capture.txt
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --update-baseline) UPDATE_BASELINE=1 ;;
    --baseline-dir) BASELINE_DIR="${2:-}"; shift ;;
    --ps-file) PS_FILE="${2:-}"; shift ;;
    --quiet) QUIET=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'runtime-audit: unknown argument %s (try --help)\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

PASS=0; WARN=0; CRIT=0; BLIND=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; WARN=$((WARN+1)); }
bad()  { printf '  \033[31mCRIT\033[0m  %s\n' "$1"; CRIT=$((CRIT+1)); }
if [[ ! -t 1 || -n "${NO_COLOR:-}" ]]; then
  ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)); }
  warn() { printf '  WARN  %s\n' "$1"; WARN=$((WARN+1)); }
  bad()  { printf '  CRIT  %s\n' "$1"; CRIT=$((CRIT+1)); }
fi
# --quiet suppresses PASS lines and section headers; findings and the verdict always
# print. A quiet mode that can hide a CRIT would be worse than no quiet mode.
if [[ "$QUIET" -eq 1 ]]; then
  ok() { PASS=$((PASS+1)); }
  say() { :; }
else
  say() { printf '%s\n' "$*"; }
fi

mkdir -p "$BASELINE_DIR" 2>/dev/null || true

# Portable SHA-256: coreutils on Linux, Perl-backed shasum on macOS.
if command -v sha256sum >/dev/null 2>&1; then
  hash_cmd() { sha256sum "$@" 2>/dev/null; }
elif command -v shasum >/dev/null 2>&1; then
  hash_cmd() { shasum -a 256 "$@" 2>/dev/null; }
else
  hash_cmd() { return 1; }
fi

say "agent-security — runtime audit ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
say "baseline: $BASELINE_DIR"
[[ -n "$PS_FILE" ]] && say "process table: $PS_FILE (captured input, NOT this host live)"
say "==================================================================="

# ---------------------------------------------------------------------------
# Snapshot the process table once. Format: PID<TAB>PPID<TAB>ELAPSED<TAB>COMMAND
# ---------------------------------------------------------------------------
if [[ -n "$PS_FILE" ]]; then
  if [[ ! -r "$PS_FILE" ]]; then
    printf 'runtime-audit: --ps-file not readable: %s\n' "$PS_FILE" >&2
    exit 2
  fi
  PS_RAW="$(cat "$PS_FILE")"
else
  PS_RAW="$(ps -eo pid=,ppid=,etime=,command= 2>/dev/null)"
fi
PS_SNAPSHOT="$(printf '%s\n' "$PS_RAW" \
  | sed -E 's/^[[:space:]]*//' \
  | awk '{pid=$1; ppid=$2; et=$3; $1=$2=$3=""; sub(/^[[:space:]]+/,""); print pid"\t"ppid"\t"et"\t"$0}')"

# Convert ps ELAPSED ([[dd-]hh:]mm:ss) to seconds.
etime_seconds() {
  local et="${1:-}"
  local days=0 h=0 m=0 s=0
  local rest="$et"
  [[ -z "$rest" ]] && { echo 0; return; }
  if [[ "$rest" == *-* ]]; then days="${rest%%-*}"; rest="${rest#*-}"; fi
  local IFS=:; read -ra parts <<< "$rest"
  case "${#parts[@]}" in
    3) h="${parts[0]}"; m="${parts[1]}"; s="${parts[2]}" ;;
    2) m="${parts[0]}"; s="${parts[1]}" ;;
    1) s="${parts[0]}" ;;
  esac
  echo $(( 10#${days:-0}*86400 + 10#${h:-0}*3600 + 10#${m:-0}*60 + 10#${s:-0} ))
}

# An inline-eval invocation: code passed on the command line rather than a file.
#
# This walks tokens instead of matching one regex across the whole line, because a
# regex cannot tell WHOSE flag it found. `node /path/to/pnpm start -p 3011` matched a
# naive `node .* -p` pattern and reported a dev server as an implant. The -p belongs to
# pnpm, not to node. An audit that cries wolf about a dev server every hour is an audit
# someone switches off, so precision here is a security property, not tidiness.
#
# Rule: interpreter flags only count before the script. Scanning stops at the first
# token that looks like a path or script file; a bare non-option token (a flag's value,
# as in `python3 -W ignore -c CODE`) is skipped rather than ending the scan.
is_inline_eval() {
  local cmd="$1" base tok i
  local -a tok_list
  read -ra tok_list <<< "$cmd"
  [[ ${#tok_list[@]} -gt 0 ]] || return 1
  base="${tok_list[0]##*/}"

  case "$base" in
    node|nodejs|bun|deno|python|python[0-9]*) ;;
    sh|bash|zsh)
      # A shell is only interesting here when it pipes a download into another shell.
      grep -qE ' -c .*(curl|wget).*\| *(sh|bash)' <<<"$cmd" && return 0
      return 1 ;;
    *) return 1 ;;
  esac

  # `deno eval` is a subcommand rather than a flag.
  [[ "$base" == deno && "${tok_list[1]:-}" == "eval" ]] && return 0

  for (( i=1; i<${#tok_list[@]}; i++ )); do
    tok="${tok_list[$i]}"
    if [[ "$tok" != -* ]]; then
      # A path or script name means every later flag belongs to that script.
      case "$tok" in
        */*|*.js|*.mjs|*.cjs|*.ts|*.py) return 1 ;;
        *) continue ;;
      esac
    fi
    case "$base" in
      node|nodejs|bun|deno)
        [[ "$tok" == "-e" || "$tok" == "--eval" || "$tok" == "-p" || "$tok" == "--print" ]] && return 0 ;;
      python|python[0-9]*)
        [[ "$tok" == "-c" ]] && return 0 ;;
    esac
  done
  return 1
}

# Dropper shape: a dynamic-execution sink co-occurring with an encoder, a fetcher,
# a respawn call, or a blockchain-C2 host. Mirrors scan-repo.sh's same-file rule.
dropper_markers() {
  local cmd="$1" found=()
  grep -qE 'eval\(|new +Function\(|Function\(' <<<"$cmd" && found+=("exec-sink:eval")
  # `[^;]` rather than `[^)]`: the decoded argument is routinely a nested call —
  # Buffer.from(fetch(u),'base64') — so a pattern that stops at the first ')'
  # misses the real shape. Bounded so it cannot run past the statement.
  grep -qE "atob[[:space:]]*\(|from[[:space:]]*\([^;]{0,160}['\"](base64|hex)|b64decode|base64[_-]?decode|fromhex[[:space:]]*\(" <<<"$cmd" && found+=("encoder")
  grep -qE 'fetch\(|https?\.get\(|https?\.request\(|XMLHttpRequest|urllib|requests\.get' <<<"$cmd" && found+=("network-fetch")
  grep -qE 'child_process|spawn\(|execSync|detached: *true' <<<"$cmd" && found+=("respawn")
  # Public blockchain RPC endpoints are a known C2 retrieval channel. On their own
  # they are ordinary traffic for anyone doing blockchain work, so they never fire
  # alone — they only add weight to a process that is ALREADY an inline eval.
  grep -qE 'trongrid|aptoslabs|bsc-dataseed|publicnode|etherscan|blockchain\.info' <<<"$cmd" && found+=("blockchain-c2")
  # Join without a subshell: the $(IFS=,; echo ...) idiom reads as a useless echo to
  # linters, and this is the same result.
  if [[ ${#found[@]} -gt 0 ]]; then
    local IFS=,
    printf '%s' "${found[*]}"
  fi
}

say "[1] inline-eval interpreter processes (dropper delivery shape)"
INLINE_FOUND=0
while IFS=$'\t' read -r pid ppid etime cmd; do
  [[ -z "${pid:-}" ]] && continue
  [[ "$pid" == "$$" ]] && continue
  is_inline_eval "$cmd" || continue
  INLINE_FOUND=$((INLINE_FOUND+1))
  secs="$(etime_seconds "$etime")"
  markers="$(dropper_markers "$cmd")"
  short="$(printf '%.110s' "$cmd")"
  if [[ -n "$markers" ]]; then
    bad "pid $pid (ppid $ppid, up $etime) inline-eval with dropper markers [$markers]"
    printf '        %s…\n' "$short"
    printf '        triage: ps -o pid,ppid,lstart,command -p %s · lsof -nP -p %s\n' "$pid" "$pid"
  elif (( secs > MAX_INLINE_EVAL_SECONDS )); then
    warn "pid $pid (ppid $ppid, up $etime) long-lived inline-eval — legitimate inline eval is short-lived"
    printf '        %s…\n' "$short"
  else
    ok "pid $pid inline-eval, short-lived ($etime) — normal tooling"
  fi
done <<< "$PS_SNAPSHOT"
(( INLINE_FOUND == 0 )) && ok "no inline-eval interpreter processes running"

say "[2] orphaned long-running interpreters (detached-stager shape)"
ORPHAN_FOUND=0
while IFS=$'\t' read -r pid ppid etime cmd; do
  [[ -z "${pid:-}" ]] && continue
  [[ "$ppid" == "1" ]] || continue
  [[ "$cmd" =~ (^|/)(node|bun|deno|python[0-9.]*)([[:space:]]|$) ]] || continue
  secs="$(etime_seconds "$etime")"
  (( secs > MAX_INLINE_EVAL_SECONDS )) || continue
  # A service manager legitimately owns PPID-1 processes; an inline-eval one is not
  # a service, it is a child whose spawner exited.
  if is_inline_eval "$cmd"; then
    ORPHAN_FOUND=$((ORPHAN_FOUND+1))
    bad "pid $pid orphaned inline-eval interpreter, up $etime — reparented after its spawner exited"
    printf '        %.110s…\n' "$cmd"
  fi
done <<< "$PS_SNAPSHOT"
(( ORPHAN_FOUND == 0 )) && ok "no orphaned inline-eval interpreters"

# ---------------------------------------------------------------------------
# Persistence drift. First run records a baseline; later runs diff against it.
#
# A baseline recorded AFTER an infection blesses whatever the implant installed.
# When it matters, read autostart mtimes directly instead of trusting this diff.
# ---------------------------------------------------------------------------
# snapshot_dir MODE LABEL DIR...
#   MODE=all       hash every file in the directory. Correct for dedicated autostart
#                  directories, where every entry IS a persistence mechanism —
#                  including extensionless ones like /etc/cron.d/*.
#   MODE=dotfiles  hash only rc/profile/env-shaped dotfiles. Correct for $HOME and
#                  agent config directories, where hashing everything would produce
#                  constant churn from ordinary work.
snapshot_dir() {
  local mode="$1"; shift
  local label="$1"; shift
  local out="$BASELINE_DIR/$label.txt"
  # The scratch file lives beside the baseline, not in TMPDIR: this function is
  # useless without a writable BASELINE_DIR anyway, and a sandboxed or full TMPDIR
  # must never be able to degrade the diff. Every failure below returns an explicit
  # error token — an unreadable baseline reports BLIND, never "no drift".
  local tmp="$out.new"
  # Braces matter: the redirection is what fails, so 2>/dev/null has to wrap it.
  if ! { : > "$tmp"; } 2>/dev/null; then
    printf 'baseline-error:cannot write %s' "$tmp"
    return
  fi
  # Collect paths first, then hash — hash_cmd is a shell function, so it cannot be
  # invoked from find -exec.
  {
    for d in "$@"; do
      [[ -d "$d" ]] || continue
      if [[ "$mode" == "all" ]]; then
        find "$d" -maxdepth 1 -type f 2>/dev/null
      else
        find "$d" -maxdepth 1 -type f \
          \( -name '.*rc' -o -name '.*profile' -o -name '.*env' \
             -o -name '*.plist' -o -name '*.service' -o -name '*.desktop' \) 2>/dev/null
      fi
    done
  } | sort -u | while IFS= read -r f; do hash_cmd "$f"; done | sort > "$tmp"
  if [[ ! -f "$out" || "$UPDATE_BASELINE" == "1" ]]; then
    if mv "$tmp" "$out" 2>/dev/null; then
      printf 'baseline-recorded'
    else
      rm -f "$tmp"
      printf 'baseline-error:cannot record baseline at %s' "$out"
    fi
    return
  fi
  if [[ ! -r "$out" ]]; then
    rm -f "$tmp"
    printf 'baseline-error:cannot read baseline at %s' "$out"
    return
  fi
  local added removed
  added="$(comm -13 <(cut -d' ' -f3- "$out" | sort) <(cut -d' ' -f3- "$tmp" | sort) 2>/dev/null)"
  removed="$(comm -23 <(cut -d' ' -f3- "$out" | sort) <(cut -d' ' -f3- "$tmp" | sort) 2>/dev/null)"
  local changed
  changed="$(comm -13 <(sort "$out") <(sort "$tmp") 2>/dev/null | cut -d' ' -f3- \
    | grep -Fxv -f <(echo "$added") 2>/dev/null)"
  rm -f "$tmp"
  printf '%s' "ADDED:${added//$'\n'/;} REMOVED:${removed//$'\n'/;} CHANGED:${changed//$'\n'/;}"
}

# Report one drift result. Keeps the BLIND case distinct from the clean case so a
# baseline the audit cannot read is never mistaken for a host that has not drifted.
report_drift() {
  local what="$1" result="$2" why="$3"
  if [[ "$result" == baseline-error:* ]]; then
    BLIND=$((BLIND+1))
    warn "$what drift detection is BLIND — ${result#baseline-error:}"
    printf '        this is an operational failure, not a clean result: nothing was compared\n'
  elif [[ "$result" == "baseline-recorded" ]]; then
    ok "baseline recorded — drift detection active from the next run"
  elif [[ "$result" =~ ADDED:[[:space:]]*REMOVED:[[:space:]]*CHANGED:[[:space:]]*$ ]]; then
    ok "no $what drift"
  else
    warn "$what drift: $result"
    printf '        %s\n' "$why"
  fi
}

say "[3] autostart persistence drift"
report_drift "autostart" \
  "$(snapshot_dir all autostart \
      "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons \
      "$HOME/.config/systemd/user" /etc/systemd/system /etc/systemd/user \
      "$HOME/.config/autostart" /etc/cron.d)" \
  "a new or changed autostart entry is how an implant survives reboot — confirm each one is yours"

say "[4] shell profile / agent config drift"
report_drift "shell profile / agent config" \
  "$(snapshot_dir dotfiles shell-profiles "$HOME" "$HOME/.claude" "$HOME/.codex")" \
  "a modified rc file is the second most common persistence hook after autostart entries"

printf '===================================================================\n'
printf 'PASS %d · WARN %d · CRIT %d · BLIND %d\n' "$PASS" "$WARN" "$CRIT" "$BLIND"
if (( CRIT > 0 )); then
  printf 'RUNTIME: COMPROMISE INDICATORS PRESENT.\n'
  printf '  Preserve first (capture the full command line and `ps` table), contain with\n'
  printf '  `kill -STOP` before `kill -9` so a detached respawn cannot fire, then hunt\n'
  printf '  persistence before eradicating. See references/coverage-and-limits.md.\n'
  exit 1
fi
if (( BLIND > 0 )); then
  printf 'RUNTIME: BLIND — %d check(s) could not run. Fix the baseline directory\n' "$BLIND"
  printf '  (%s) and re-run; until then this audit proves nothing about persistence.\n' "$BASELINE_DIR"
  exit 2
fi
if (( WARN > 0 )); then
  printf 'RUNTIME: DRIFT — review each WARN; none is proof of compromise on its own.\n'
  exit 0
fi
printf 'RUNTIME: CLEAN (known command-line shapes only — a novel or sleeping implant evades this).\n'
