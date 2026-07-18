#!/usr/bin/env bash
# harden-check.sh — READ-ONLY audit of the REAL destructive-capability surface.
#
# THE HONEST THESIS (this is the whole point, stated plainly):
#   The repo-guard this skill installs is DEFENSE-IN-DEPTH — a LOCAL BRAKE that
#   catches interactive / PATH-resolved destruction. It is BYPASSED by absolute-path
#   `gh` outside a Claude session and by the REST API (curl / octokit). It REDUCES
#   accidental/automated destruction risk; it does NOT guarantee prevention.
#   TRUE prevention of the repo-destruction incident this skill exists for (repo
#   delete/transfer/rename/privatize that wiped thousands of accumulated stars) is
#   CAPABILITY REMOVAL AT GITHUB: a token WITHOUT `delete_repo` scope literally cannot
#   delete/transfer regardless of any bypass, plus org-level deletion/transfer
#   restrictions and branch protection. This script AUDITS and GUIDES those controls.
#   It NEVER changes your token or org settings — applying the GitHub-side fixes is
#   YOUR action (some need org-admin).
#
# What it audits (each item: exposure + fix + honest residual-risk line):
#   1. Token scopes        — does the active gh token carry `delete_repo`? (HIGH)
#   2. Local repo-guard     — installed? (a BRAKE, bypassable — not prevention)
#   3. Org restrictions     — deletion/transfer allowed? (best-effort; usually
#                             needs the Settings UI — points you to the exact URL)
#   4. Branch protection    — default branch protected against force-push/deletion
#                             on star-bearing repos (best-effort via gh api)
#   5. Star-loss recovery   — informational: repos still showing lost stars
#
# Exit: 0 = no confirmed HIGH exposure · 1 = OPEN HIGH exposure · 3 = DEGRADED, a
# check could NOT be verified in this context (e.g. token scope unreadable) — NOT a
# pass, do not treat as safe. Usable as a gate. The REPORT is the value — read it,
# don't just check the code.
#
# Flags:
#   --auth-status-file F  read `gh auth status` output from F instead of calling gh
#                         (offline / unit-testable scope parsing)
#   --offline             skip every network check (org read, branch protection)
#   --org ORG             org to reference for restriction guidance (default: your-org)
#   --repos a/b,c/d       comma-separated owner/repo to check branch protection on
#   --brief               compact output (final tier lines only; for embedding)
#   -h | --help           this header
set -uo pipefail

# ── Configure these for your fleet (placeholders by default) ────────────────
DEFAULT_ORG="your-org"
# Star-bearing repos to protect — set via --repos, or edit this default.
STAR_REPOS_DEFAULT="owner/repo-a,owner/repo-b"

AUTH_FILE=""
OFFLINE=0
ORG="$DEFAULT_ORG"
REPOS=""
BRIEF=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auth-status-file) [[ $# -ge 2 ]] || { echo "--auth-status-file needs a path" >&2; exit 2; }; AUTH_FILE="$2"; shift ;;
    --offline) OFFLINE=1 ;;
    --org) [[ $# -ge 2 ]] || { echo "--org needs a value" >&2; exit 2; }; ORG="$2"; shift ;;
    --repos) [[ $# -ge 2 ]] || { echo "--repos needs a value" >&2; exit 2; }; REPOS="$2"; shift ;;
    --brief) BRIEF=1 ;;
    -h|--help) sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

HIGH=0; MED=0; INFO=0; OK=0; UNKNOWN=0
hi()   { printf '  \033[31mHIGH\033[0m  %s\n' "$1"; HIGH=$((HIGH+1)); }
med()  { printf '  \033[33mMED \033[0m  %s\n' "$1"; MED=$((MED+1)); }
good() { printf '  \033[32mOK  \033[0m  %s\n' "$1"; OK=$((OK+1)); }
info() { printf '  INFO  %s\n' "$1"; INFO=$((INFO+1)); }
# WARN = DEGRADED / could-not-verify. NOT benign: a check that could not run must
# never be counted as a pass. UNKNOWN>0 blocks the "no confirmed HIGH exposure" verdict.
warn() { printf '  \033[35mWARN\033[0m  %s\n' "$1"; UNKNOWN=$((UNKNOWN+1)); }
risk() { printf '        \033[2mresidual:\033[0m %s\n' "$1"; }
fix()  { printf '        fix: %s\n' "$1"; }
if [[ ! -t 1 || -n "${NO_COLOR:-}" ]]; then
  hi()   { printf '  HIGH  %s\n' "$1"; HIGH=$((HIGH+1)); }
  med()  { printf '  MED   %s\n' "$1"; MED=$((MED+1)); }
  good() { printf '  OK    %s\n' "$1"; OK=$((OK+1)); }
  warn() { printf '  WARN  %s\n' "$1"; UNKNOWN=$((UNKNOWN+1)); }
  risk() { printf '        residual: %s\n' "$1"; }
fi

[[ "$BRIEF" -eq 0 ]] && {
  echo "agent-security — destructive-capability harden check ($(date -u +%FT%TZ))"
  echo "==================================================================="
}

# ── 1. Token scopes — the real backstop for delete/transfer ─────────────────
# HONEST: the local guard is bypassable, so a token that CAN delete IS the
# residual risk. A token without delete_repo cannot delete/transfer, bypass or not.
[[ "$BRIEF" -eq 0 ]] && echo "[1] GitHub token scope — can the active token delete/transfer a repo?"
AUTH_TXT=""
AUTH_SRC=""
if [[ -n "$AUTH_FILE" ]]; then
  if [[ -f "$AUTH_FILE" ]]; then AUTH_TXT="$(cat "$AUTH_FILE")"; AUTH_SRC="file:$AUTH_FILE"; fi
elif command -v gh >/dev/null 2>&1; then
  AUTH_TXT="$(gh auth status 2>&1 || true)"; AUTH_SRC="gh auth status"
fi

SCOPE_LINE="$(printf '%s\n' "$AUTH_TXT" | grep -i 'Token scopes:' | head -1 || true)"
TOKEN_TIER="UNKNOWN"
# HONEST FAILURE MODE: three states only —
#   (a) readable + delete_repo   -> HIGH   (it CAN destroy)
#   (b) readable + no delete_repo -> OK    (it cannot delete/transfer)
#   (c) COULD-NOT-VERIFY          -> WARN/UNKNOWN (DEGRADED, never benign)
# The old code reported "INVALID -> benign MED, exit 0". A token we could not READ
# (keyring/permission blocked, gh not logged in here, command failed) is NOT proof of
# safety — reporting it green is FALSE COMFORT. Any could-not-verify state is UNKNOWN,
# blocks the clear verdict, and exits nonzero.
CANT_VERIFY="could not verify token scope in this context — re-run in an interactive terminal with keyring access; do NOT treat this as safe"
if [[ -z "$AUTH_TXT" ]]; then
  warn "$CANT_VERIFY (gh not installed or no auth status available — $AUTH_SRC)"
  risk "scope is UNVERIFIED, not clear. UNKNOWN != safe: authenticate in a context where 'gh auth status' succeeds, then confirm the token carries NO delete_repo."
  TOKEN_TIER="UNKNOWN"
elif printf '%s\n' "$AUTH_TXT" | grep -qiE 'invalid|failed to log in|not logged'; then
  warn "$CANT_VERIFY (gh could not read the token — not-logged-in / invalid / keyring error, $AUTH_SRC)"
  risk "gh could not read the token HERE — keyring/permission/session, not a proof of safety. DEGRADED, not benign. Do NOT record this run as a pass; the token's real scope is still unknown."
  fix "re-run in an interactive terminal where 'gh auth status' succeeds (keyring unlocked), then confirm the token carries NO delete_repo (mint a MINIMAL-scope automation token: repo,read:org,workflow — delete_repo ONLY for rare manual human deletes)."
  TOKEN_TIER="UNKNOWN"
elif [[ -z "$SCOPE_LINE" ]]; then
  warn "$CANT_VERIFY (authenticated, but no classic 'Token scopes:' line — likely a fine-grained PAT)"
  risk "fine-grained PATs express repo administration as PERMISSIONS, not classic scopes — gh does not print them, so delete capability cannot be confirmed from here. Treat as UNVERIFIED, not safe."
  fix "open the token's page and confirm it lacks 'Administration: read+write' (which permits delete) on any repo it can reach."
  TOKEN_TIER="UNKNOWN_FINEGRAINED"
elif printf '%s\n' "$SCOPE_LINE" | grep -q 'delete_repo'; then
  hi "token carries delete_repo → it CAN delete/transfer any repo it can access"
  echo "        scopes: ${SCOPE_LINE#*Token scopes: }"
  risk "the local guard is bypassable (absolute-path gh / curl / octokit), so a token with delete_repo IS the residual risk. This is the single most important item to fix."
  fix "mint a MINIMAL automation token WITHOUT delete_repo for all agents/automations; keep the delete-capable token for rare, manual, human-only use. Tradeoff: removing delete_repo also blocks legitimate deletes — that is deliberate."
  TOKEN_TIER="HIGH"
else
  good "token authenticated and does NOT carry delete_repo (cannot delete/transfer)"
  echo "        scopes: ${SCOPE_LINE#*Token scopes: }"
  risk "delete_repo absence is the durable backstop. Note: 'repo' still allows privatize (visibility) and archive via API — org policy + branch protection cover those."
  TOKEN_TIER="OK"
fi

# ── 2. Local repo-guard — a BRAKE, bypassable (NOT prevention) ──────────────
[[ "$BRIEF" -eq 0 ]] && echo "[2] Local repo-guard (defense-in-depth BRAKE — not a capability boundary)"
BIN_DIR="${REPO_GUARD_BIN:-$HOME/.local/bin}"
SHIM="$BIN_DIR/gh"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
SETTINGS="$CLAUDE_DIR/settings.json"
GUARD_OK=1
if [[ -f "$SHIM" ]] && grep -q 'repo-guard: PATH shim for .gh.' "$SHIM" 2>/dev/null; then
  RES="$(command -v gh 2>/dev/null || true)"
  if [[ -n "$RES" ]] && grep -q 'repo-guard: PATH shim for .gh.' "$RES" 2>/dev/null; then
    good "L1 PATH shim installed and gh resolves to it ($RES)"
  else
    med "L1 shim present but gh resolves to '${RES:-<none>}' — PATH ordering broken"; GUARD_OK=0
  fi
else
  med "L1 PATH shim absent/not ours at $SHIM — install: scripts/repo-guard-install.sh"; GUARD_OK=0
fi
if [[ -f "$SETTINGS" ]] && grep -qE 'block-repo-lifecycle\.sh|repo-guard-pretool\.sh' "$SETTINGS" 2>/dev/null; then
  good "L3 Claude PreToolUse hook registered (catches absolute-path gh in Claude)"
else
  med "L3 Claude hook not registered in $SETTINGS — absolute-path gap open in Claude (install --with-hook)"; GUARD_OK=0
fi
risk "BRAKE, BYPASSABLE. Absolute-path gh outside a Claude session, or curl/octokit against the REST API, skips both layers. This reduces accidental/automated destruction; it is NOT true prevention. Durable prevention = token scope (item 1) + org policy (item 3)."

# ── 3. Org deletion/transfer restrictions (best-effort; usually UI-only) ────
[[ "$BRIEF" -eq 0 ]] && echo "[3] Org policy — member repo deletion/transfer restrictions ($ORG)"
if [[ "$OFFLINE" -eq 1 ]]; then
  info "skipped (--offline). Org member-privilege settings are not reliably API-readable anyway."
elif command -v gh >/dev/null 2>&1; then
  ORG_JSON="$(gh api "orgs/$ORG" 2>/dev/null || true)"
  if [[ -n "$ORG_JSON" ]] && printf '%s' "$ORG_JSON" | grep -q 'members_can_delete_repositories'; then
    VAL="$(printf '%s' "$ORG_JSON" | grep -o '"members_can_delete_repositories"[^,]*' | head -1)"
    if printf '%s' "$VAL" | grep -q 'false'; then
      good "members_can_delete_repositories = false (deletion restricted)"
    else
      hi "members_can_delete_repositories = true — org members CAN delete repos"
      fix "turn OFF at: https://github.com/organizations/$ORG/settings/member_privileges"
    fi
  else
    info "org deletion/transfer policy NOT readable via API (needs org-admin/UI, as expected)"
    risk "cannot be confirmed from here — verify by hand."
    fix "Settings → Member privileges: set 'Allow members to delete or transfer repositories' OFF at https://github.com/organizations/$ORG/settings/member_privileges"
  fi
else
  info "gh not installed — cannot attempt org read"
  fix "verify at https://github.com/organizations/$ORG/settings/member_privileges"
fi

# ── 4. Branch protection on star-bearing / important public repos ───────────
[[ "$BRIEF" -eq 0 ]] && echo "[4] Branch protection on star-bearing repos (force-push / deletion)"
CHECK_REPOS="${REPOS:-$STAR_REPOS_DEFAULT}"
if [[ "$OFFLINE" -eq 1 ]]; then
  info "skipped (--offline). Repos to protect: $CHECK_REPOS"
elif command -v gh >/dev/null 2>&1; then
  IFS=',' read -r -a _repos <<< "$CHECK_REPOS"
  for r in "${_repos[@]}"; do
    [[ -z "$r" ]] && continue
    DEF="$(gh api "repos/$r" --jq .default_branch 2>/dev/null || true)"
    if [[ -z "$DEF" ]]; then
      info "$r — cannot read (404/403/no access); skipping"
      continue
    fi
    if gh api "repos/$r/branches/$DEF/protection" >/dev/null 2>&1; then
      good "$r ($DEF) — branch protection present"
    else
      med "$r ($DEF) — no branch protection (or no admin access to read it)"
      fix "protect $DEF against force-push + deletion: https://github.com/$r/settings/branches"
    fi
  done
else
  info "gh not installed — cannot check; repos to protect: $CHECK_REPOS"
fi
risk "branch protection stops force-push/history rewrite + branch deletion; it does NOT stop repo DELETE/transfer (item 1 + 3 cover those)."

# ── 5. Star-loss recovery state (informational) ─────────────────────────────
[[ "$BRIEF" -eq 0 ]] && {
  echo "[5] Star-loss recovery state (informational)"
  info "any public repo that historically had many stars but now shows 0-1 is a candidate for a still-open GitHub Support restoration item."
  info "deleted repos: only GitHub Support can restore (within their window) — keep independent evidence (e.g. Wayback/archive.org snapshots of the star count)."
  info "privatized repos: stars survive a visibility flip — re-publishing restores the count."
  echo "        see references/destructive-ops-prevention.md and references/coverage-and-limits.md."
}

# ── Summary + prevention mapping ────────────────────────────────────────────
if [[ "$BRIEF" -eq 0 ]]; then
  echo "==================================================================="
  echo "What would have PREVENTED the repo-destruction / star loss:"
  echo "  • A token WITHOUT delete_repo on the automation path  → delete/transfer impossible"
  echo "  • Org 'members can delete/transfer repositories' = OFF → server-side backstop"
  echo "  • Branch protection                                    → history/force-push (not delete)"
  echo "  The local repo-guard would have caught the PATH-resolved case only — a brake, not a guarantee."
  echo "-------------------------------------------------------------------"
fi
echo "HARDEN: HIGH $HIGH · MED $MED · OK $OK · INFO $INFO · UNKNOWN $UNKNOWN · token=$TOKEN_TIER · guard=$([[ $GUARD_OK -eq 1 ]] && echo armed || echo degraded)"
if [[ "$HIGH" -gt 0 ]]; then
  [[ "$BRIEF" -eq 0 ]] && echo "VERDICT: OPEN HIGH EXPOSURE — a token/policy CAN still destroy repos. Fix item(s) above (user action at GitHub)."
  exit 1
fi
if [[ "$UNKNOWN" -gt 0 ]]; then
  [[ "$BRIEF" -eq 0 ]] && echo "VERDICT: DEGRADED — one or more capability checks could NOT be verified in this context (e.g. token scope unreadable: keyring/permission blocked or gh not logged in). This is NOT a pass and NOT 'no confirmed HIGH exposure' — do not treat it as safe. Re-run unsandboxed / in an interactive terminal with keyring access."
  exit 3
fi
[[ "$BRIEF" -eq 0 ]] && echo "VERDICT: no confirmed HIGH exposure (review MED/INFO — capability removal at GitHub is the durable control)."
exit 0
