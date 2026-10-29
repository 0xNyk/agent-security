#!/usr/bin/env bash
# runtime-audit-install.sh — schedule runtime-audit.sh so it runs without you.
#
# Why this exists: runtime-audit.sh is point-in-time. Run by hand, it reports what is
# running at that instant and nothing else. The incident that motivated the audit went
# four and a half days unnoticed, and a manual check would not have shortened that by
# itself — someone still has to decide to look. Scheduling is what converts the tool
# from "a thing you remember" into a control.
#
# Installs a periodic run:
#   macOS  — a LaunchAgent (StartInterval), loaded for the current user
#   Linux  — a systemd user timer when systemctl --user works, otherwise a crontab line
#
# The audit stays read-only. This installer writes a scheduler entry, a log directory,
# and (because adding a LaunchAgent is itself autostart drift) refreshes the audit's
# persistence baseline once, so the next run does not flag the scheduler it just
# installed. That refresh is announced, never silent.
#
# Usage:
#   scripts/runtime-audit-install.sh                 # install with the default interval
#   scripts/runtime-audit-install.sh --interval 1800 # every 30 minutes
#   scripts/runtime-audit-install.sh --status
#   scripts/runtime-audit-install.sh --uninstall
#   scripts/runtime-audit-install.sh --dry-run       # print actions, change nothing
#
# Exit: 0 success (or --status when armed), 1 --status when not armed, 2 usage error.
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
AUDIT="$SKILL_DIR/scripts/runtime-audit.sh"
LABEL="com.agent-security.runtime-audit"
INTERVAL=3600
ACTION=install
DRY=0

LAUNCH_AGENT_DIR="$HOME/Library/LaunchAgents"
PLIST="$LAUNCH_AGENT_DIR/$LABEL.plist"
SYSTEMD_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE="$SYSTEMD_DIR/agent-security-runtime-audit.service"
TIMER="$SYSTEMD_DIR/agent-security-runtime-audit.timer"
LOG_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/agent-security"
LOG="$LOG_DIR/runtime-audit.log"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interval)
      [[ $# -ge 2 ]] || { echo "--interval requires seconds" >&2; exit 2; }
      INTERVAL="$2"; shift ;;
    --status) ACTION=status ;;
    --uninstall) ACTION=uninstall ;;
    --dry-run) DRY=1 ;;
    --audit) [[ $# -ge 2 ]] || { echo "--audit requires a path" >&2; exit 2; }
             AUDIT="$2"; shift ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "runtime-audit-install: unknown argument $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

[[ "$INTERVAL" =~ ^[0-9]+$ ]] || { echo "--interval must be a whole number of seconds" >&2; exit 2; }
if (( INTERVAL < 300 )); then
  echo "--interval below 300s is refused: the audit walks the process table, and a" >&2
  echo "  scheduler that runs it constantly is a cost with no detection benefit." >&2
  exit 2
fi

run() { if [[ "$DRY" -eq 1 ]]; then echo "  [dry-run] $*"; else "$@"; fi; }

have_systemd() { command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; }

platform() {
  if [[ "$(uname -s)" == "Darwin" ]]; then echo launchd
  elif have_systemd; then echo systemd
  else echo cron; fi
}

cron_line() { printf '*/%d * * * * %s --quiet >>%s 2>&1\n' "$(( INTERVAL / 60 ))" "$AUDIT" "$LOG"; }

armed_launchd() { [[ -f "$PLIST" ]]; }
armed_systemd() { [[ -f "$TIMER" && -f "$SERVICE" ]]; }
armed_cron()    { crontab -l 2>/dev/null | grep -q 'runtime-audit'; }

# Read the interval back from whatever is actually installed. "configured at install
# time" is not a status: an install at 1800s that someone later forgets looks identical
# to one at 3600s, and the whole point of --status is answering how often this runs.
installed_interval() {
  case "$(platform)" in
    launchd)
      [[ -f "$PLIST" ]] || return 1
      grep -A1 'StartInterval' "$PLIST" 2>/dev/null \
        | grep -oE '<integer>[0-9]+</integer>' | grep -oE '[0-9]+' | head -1 ;;
    systemd)
      [[ -f "$TIMER" ]] || return 1
      grep -oE '^OnUnitActiveSec=[0-9]+' "$TIMER" 2>/dev/null | grep -oE '[0-9]+' | head -1 ;;
    cron)
      crontab -l 2>/dev/null | grep 'runtime-audit' | grep -oE '^\*/[0-9]+' \
        | grep -oE '[0-9]+' | head -1 | awk '{print $1*60}' ;;
  esac
}

# ─── status ─────────────────────────────────────────────────────────────────
if [[ "$ACTION" == "status" ]]; then
  p="$(platform)"
  echo "runtime-audit schedule status"
  echo "  platform        : $p"
  echo "  audit script    : $AUDIT $([[ -x "$AUDIT" ]] && echo '(executable)' || echo '(MISSING/not executable)')"
  echo "  log             : $LOG $([[ -f "$LOG" ]] && echo "($(wc -l <"$LOG" | tr -d ' ') lines)" || echo '(none yet)')"
  armed=1
  case "$p" in
    launchd) echo "  LaunchAgent     : $PLIST $(armed_launchd && echo '(installed)' || echo '(absent)')"
             armed_launchd || armed=0 ;;
    systemd) echo "  systemd timer   : $TIMER $(armed_systemd && echo '(installed)' || echo '(absent)')"
             armed_systemd || armed=0 ;;
    cron)    echo "  crontab entry   : $(armed_cron && echo present || echo absent)"
             armed_cron || armed=0 ;;
  esac
  if [[ "$armed" -eq 1 ]]; then
    iv="$(installed_interval 2>/dev/null)"
    if [[ -n "${iv:-}" ]]; then
      echo "  interval        : every ${iv}s (about $(( iv / 60 )) min)"
    else
      echo "  interval        : installed, but could not be read back from the scheduler entry"
    fi
    echo "  ARMED           : yes"
  else
    echo "  ARMED           : no — the audit only runs when you remember to run it"
  fi
  # Printed in both states on purpose: someone reading an armed report needs the limit
  # just as much as someone reading an unarmed one, arguably more.
  echo "  reminder        : scheduling fixes WHEN the audit runs, not WHAT it can see."
  echo "                    Command-line shapes only; a file-exec or sleeping implant still evades it."
  [[ "$armed" -eq 1 ]] || exit 1
  exit 0
fi

# ─── uninstall ──────────────────────────────────────────────────────────────
if [[ "$ACTION" == "uninstall" ]]; then
  echo "runtime-audit schedule uninstall"
  case "$(platform)" in
    launchd)
      if [[ -f "$PLIST" ]]; then
        run launchctl unload "$PLIST" 2>/dev/null || true
        run rm -f "$PLIST"
        echo "  removed $PLIST"
      else echo "  no LaunchAgent to remove"; fi ;;
    systemd)
      run systemctl --user disable --now agent-security-runtime-audit.timer 2>/dev/null || true
      run rm -f "$TIMER" "$SERVICE"
      echo "  removed systemd timer + service" ;;
    cron)
      if crontab -l 2>/dev/null | grep -q 'runtime-audit'; then
        if [[ "$DRY" -eq 1 ]]; then echo "  [dry-run] strip runtime-audit lines from crontab"
        else crontab -l 2>/dev/null | grep -v 'runtime-audit' | crontab -; fi
        echo "  removed crontab entry"
      else echo "  no crontab entry to remove"; fi ;;
  esac
  echo "  the audit itself is untouched — run it by hand any time: $AUDIT"
  echo "  NOTE: removing the scheduler changes the persistence baseline. Re-run"
  echo "        '$AUDIT --update-baseline' once so the next audit does not report it as drift."
  exit 0
fi

# ─── install ────────────────────────────────────────────────────────────────
if [[ ! -x "$AUDIT" ]]; then
  echo "runtime-audit-install: $AUDIT is missing or not executable" >&2
  exit 2
fi

PLATFORM="$(platform)"
echo "runtime-audit schedule install ($PLATFORM, every ${INTERVAL}s)"
run mkdir -p "$LOG_DIR"

case "$PLATFORM" in
  launchd)
    run mkdir -p "$LAUNCH_AGENT_DIR"
    if [[ "$DRY" -eq 1 ]]; then
      echo "  [dry-run] write $PLIST"
    else
      cat >"$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$AUDIT</string>
    <string>--quiet</string>
  </array>
  <key>StartInterval</key><integer>$INTERVAL</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
PLISTEOF
      echo "  wrote $PLIST"
    fi
    run launchctl unload "$PLIST" 2>/dev/null || true
    # `run` returns 0 in dry-run without doing anything, so its exit status must not be
    # read as "the load succeeded" — that would print a success line for work not done.
    if [[ "$DRY" -eq 1 ]]; then
      echo "  [dry-run] launchctl load $PLIST"
    elif launchctl load "$PLIST" 2>/dev/null; then
      echo "  loaded into launchd"
    else
      echo "  WARN could not load into launchd — the plist is written; load it manually:"
      echo "       launchctl load $PLIST"
    fi ;;

  systemd)
    run mkdir -p "$SYSTEMD_DIR"
    if [[ "$DRY" -eq 1 ]]; then
      echo "  [dry-run] write $SERVICE and $TIMER"
    else
      cat >"$SERVICE" <<SVCEOF
[Unit]
Description=agent-security runtime audit

[Service]
Type=oneshot
ExecStart=/bin/bash $AUDIT --quiet
StandardOutput=append:$LOG
StandardError=append:$LOG
SVCEOF
      cat >"$TIMER" <<TIMEREOF
[Unit]
Description=agent-security runtime audit (every ${INTERVAL}s)

[Timer]
OnBootSec=120
OnUnitActiveSec=${INTERVAL}
Persistent=true

[Install]
WantedBy=timers.target
TIMEREOF
      echo "  wrote $SERVICE and $TIMER"
    fi
    run systemctl --user daemon-reload 2>/dev/null || true
    if [[ "$DRY" -eq 1 ]]; then
      echo "  [dry-run] systemctl --user enable --now agent-security-runtime-audit.timer"
    elif systemctl --user enable --now agent-security-runtime-audit.timer 2>/dev/null; then
      echo "  timer enabled"
    else
      echo "  WARN could not enable the timer — enable it manually:"
      echo "       systemctl --user enable --now agent-security-runtime-audit.timer"
    fi ;;

  cron)
    if crontab -l 2>/dev/null | grep -q 'runtime-audit'; then
      echo "  crontab already has a runtime-audit entry — leaving it alone"
    elif [[ "$DRY" -eq 1 ]]; then
      echo "  [dry-run] add crontab line: $(cron_line)"
    else
      { crontab -l 2>/dev/null; cron_line; } | crontab - \
        && echo "  added crontab entry" \
        || echo "  WARN could not write crontab — add this line manually: $(cron_line)"
    fi ;;
esac

# Installing a scheduler entry IS autostart drift. Refresh the baseline once, out loud,
# so the first scheduled run reports the host rather than this installer's own footprint.
echo "  refreshing the audit's persistence baseline (this installer just added an autostart entry)"
if [[ "$DRY" -eq 1 ]]; then
  echo "  [dry-run] $AUDIT --update-baseline --quiet"
else
  bash "$AUDIT" --update-baseline --quiet >/dev/null 2>&1 || true
fi

echo
echo "Installed. Findings go to: $LOG"
echo "  tail -f $LOG"
echo
echo "What this does and does not change:"
echo "  · fixes WHEN the audit runs — it no longer depends on you remembering"
echo "  · does NOT widen what it can see: command-line shapes only, no memory inspection"
echo "  · a scheduled CLEAN result still means 'no known pattern matched at that moment'"
