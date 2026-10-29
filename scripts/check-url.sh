#!/usr/bin/env bash
# check-url.sh — pre-fetch URL classifier for safe external research.
#
# Classifies a URL string BEFORE the agent fetches, browses, or downloads it.
# Network-free: no DNS, no HTTP. Verdict is about shape risk (scheme, host form,
# path extension, credentials-in-URL), not about whether the remote host is
# "actually safe." A high-reputation domain that is compromised will still ALLOW.
#
# Usage:
#   check-url.sh <url>
#   check-url.sh --json <url>
#   check-url.sh --quiet <url>          # verdict word only on stdout
#   check-url.sh --allowlist <file> <url>
#   echo <url> | check-url.sh
#
# Exit codes:
#   0  ALLOW   — safe enough to fetch as HTML/text under the safe-research contract
#   1  REVIEW  — human must approve this exact URL (PDF, shortener, IP host, etc.)
#   2  BLOCK   — do not fetch
#   3  usage / parse error
#
# Optional allowlist file: one hostname or *.suffix per line (# comments ok).
# Allowlist can only upgrade REVIEW→ALLOW for host-reputation reasons; it never
# overrides BLOCK (dangerous scheme/extension/credentials).
#
# Contract: references/safe-research.md
set -euo pipefail

JSON=0
QUIET=0
ALLOWLIST=""
URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) JSON=1 ;;
    --quiet) QUIET=1 ;;
    --allowlist)
      shift
      [[ $# -gt 0 ]] || { echo "check-url: --allowlist needs a file" >&2; exit 3; }
      ALLOWLIST="$1"
      ;;
    -h|--help)
      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    --) shift; URL="${1:-}"; break ;;
    -*)
      echo "Unknown argument: $1" >&2
      exit 3
      ;;
    *)
      URL="$1"
      ;;
  esac
  shift
done

if [[ -z "$URL" ]]; then
  if [[ ! -t 0 ]]; then
    URL="$(cat | head -n 1 | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  fi
fi

if [[ -z "$URL" ]]; then
  echo "usage: check-url.sh [--json] [--quiet] [--allowlist file] <url>" >&2
  exit 3
fi

# Strip surrounding quotes if the agent passed them literally.
URL="${URL#\'}"; URL="${URL%\'}"
URL="${URL#\"}"; URL="${URL%\"}"

REASONS=()   # human-readable reason codes
VERDICT="ALLOW"
# severity rank: ALLOW=0 REVIEW=1 BLOCK=2
rank_of() { case "$1" in ALLOW) echo 0;; REVIEW) echo 1;; BLOCK) echo 2;; *) echo 0;; esac; }
raise() {
  local new="$1" reason="$2"
  REASONS+=("$reason")
  if [[ "$(rank_of "$new")" -gt "$(rank_of "$VERDICT")" ]]; then
    VERDICT="$new"
  fi
}

# ── Parse with python3 when available (robust); else bash-ish fallback ──────
parse_py() {
  python3 - "$URL" <<'PY'
import sys, re
from urllib.parse import urlsplit, unquote

raw = sys.argv[1].strip()
# Reject whitespace / control chars in the URL string
if re.search(r"[\x00-\x1f\x7f]", raw):
    print("CTRL_CHARS")
    sys.exit(0)

parts = urlsplit(raw)
scheme = (parts.scheme or "").lower()
netloc = parts.netloc or ""
path = unquote(parts.path or "")
query = parts.query or ""
fragment = parts.fragment or ""

# userinfo
userinfo = ""
hostport = netloc
if "@" in netloc:
    userinfo, hostport = netloc.rsplit("@", 1)

host = hostport
port = ""
if hostport.startswith("["):
    # IPv6 [addr]:port
    m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostport)
    if m:
        host, port = m.group(1), m.group(2) or ""
    else:
        host = hostport
else:
    if hostport.count(":") == 1:
        host, port = hostport.split(":", 1)

print("SCHEME=" + scheme)
print("USERINFO=" + ("1" if userinfo else "0"))
print("HOST=" + host.lower())
print("URL_PATH=" + path)
print("QUERY_LEN=" + str(len(query)))
print("RAW_LEN=" + str(len(raw)))
PY
}

# Port and fragment are deliberately not carried: no rule reads them today, and an
# unread variable in a classifier invites someone to assume it is checked.
SCHEME=""; USERINFO="0"; HOST=""; URL_PATH=""; QUERY_LEN="0"; RAW_LEN="0"
PARSE_ERR=""

if command -v python3 >/dev/null 2>&1; then
  if ! PARSE_OUT="$(parse_py 2>/dev/null)"; then
    PARSE_ERR="1"
  else
    if [[ "$PARSE_OUT" == "CTRL_CHARS" ]]; then
      raise BLOCK "control_chars_in_url"
    else
      while IFS= read -r line; do
        case "$line" in
          SCHEME=*) SCHEME="${line#SCHEME=}" ;;
          USERINFO=*) USERINFO="${line#USERINFO=}" ;;
          HOST=*) HOST="${line#HOST=}" ;;
          URL_PATH=*) URL_PATH="${line#URL_PATH=}" ;;
          QUERY_LEN=*) QUERY_LEN="${line#QUERY_LEN=}" ;;
          RAW_LEN=*) RAW_LEN="${line#RAW_LEN=}" ;;
        esac
      done <<<"$PARSE_OUT"
    fi
  fi
else
  # Minimal fallback: scheme://host/path
  if [[ "$URL" =~ ^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]+)([^\?]*)(\?[^#]*)?(#.*)?$ ]]; then
    SCHEME="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
    netloc="${BASH_REMATCH[2]}"
    URL_PATH="${BASH_REMATCH[3]}"
    [[ -n "${BASH_REMATCH[4]:-}" ]] && QUERY_LEN="${#BASH_REMATCH[4]}"
    if [[ "$netloc" == *"@"* ]]; then
      USERINFO="1"
      netloc="${netloc##*@}"
    fi
    HOST="$(printf '%s' "$netloc" | tr '[:upper:]' '[:lower:]')"
    if [[ "$HOST" == *:* && "$HOST" != \[* ]]; then
      HOST="${HOST%%:*}"
    fi
  else
    PARSE_ERR="1"
  fi
fi

if [[ -n "$PARSE_ERR" ]]; then
  raise BLOCK "unparseable_url"
fi

# ── Scheme policy ───────────────────────────────────────────────────────────
case "$SCHEME" in
  https) : ;;
  http) raise REVIEW "insecure_http" ;;
  "") raise BLOCK "missing_scheme" ;;
  file|data|javascript|vbscript|blob|about|ftp|sftp|ssh|telnet|ws|wss)
    raise BLOCK "blocked_scheme:${SCHEME}"
    ;;
  *) raise BLOCK "unknown_scheme:${SCHEME}" ;;
esac

# ── Credentials in URL ──────────────────────────────────────────────────────
if [[ "$USERINFO" == "1" ]]; then
  raise BLOCK "credentials_in_url"
fi

# ── Host shape ──────────────────────────────────────────────────────────────
if [[ -z "$HOST" ]]; then
  raise BLOCK "missing_host"
fi

# IPv4
if [[ "$HOST" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  raise REVIEW "ip_literal_host"
fi
# IPv6 bare or from brackets (python already stripped brackets)
if [[ "$HOST" == *:* ]]; then
  raise REVIEW "ip_literal_host"
fi

# Punycode / IDN homograph risk
if [[ "$HOST" == *xn--* ]]; then
  raise REVIEW "punycode_host"
fi

# Local / link-local / metadata-ish hosts (research should not need these)
case "$HOST" in
  localhost|localhost.*|*.localhost)
    raise BLOCK "local_host"
    ;;
  127.*|0.0.0.0|::1)
    raise BLOCK "local_host"
    ;;
  metadata|metadata.*|*.internal|*.local)
    raise REVIEW "internal_looking_host"
    ;;
esac

# ── Extension / path policy ─────────────────────────────────────────────────
# Take last path segment after final slash; strip trailing slash first.
PATH_TRIM="${URL_PATH%/}"
BASE="${PATH_TRIM##*/}"
# Ignore empty and query-ish
EXT=""
if [[ "$BASE" == *.* && "$BASE" != .* ]]; then
  EXT="$(printf '%s' "${BASE##*.}" | tr '[:upper:]' '[:lower:]')"
  # Only treat as extension if reasonably short and alnum
  if [[ ! "$EXT" =~ ^[a-z0-9]{1,10}$ ]]; then
    EXT=""
  fi
fi

BLOCK_EXTS='exe|dmg|pkg|msi|apk|deb|rpm|appimage|bat|cmd|ps1|scr|com|dll|sys|vbs|vbe|wsf|wsh|jar|war|ear|hta|msp|msu|iso|img|vmdk|vdi|ova|ovf|bin|run|sh|bash|zsh|fish|py|pyc|rb|pl|php|cgi|action|command|ipa|xpi|crx|gadget|torrent|lnk|reg|inf|cab|msix|appx|zip|rar|7z|tar|gz|tgz|bz2|xz|zst|lz|lzma|tbz|txz'
REVIEW_EXTS='pdf|doc|docx|xls|xlsx|ppt|pptx|rtf|odt|ods|odp|pages|numbers|key|epub|mobi|csv|tsv|sqlite|db|parquet|feather|arrow|wasm'

if [[ -n "$EXT" ]]; then
  if echo "|$BLOCK_EXTS|" | grep -q "|${EXT}|"; then
    raise BLOCK "blocked_extension:.${EXT}"
  elif echo "|$REVIEW_EXTS|" | grep -q "|${EXT}|"; then
    raise REVIEW "review_extension:.${EXT}"
  fi
fi

# Path keywords that often mean "download this binary"
PATH_LC="$(printf '%s' "$URL_PATH" | tr '[:upper:]' '[:lower:]')"
case "$PATH_LC" in
  */download/*|*/downloads/*|*download.php*|*download.asp*|*attachment*|*getfile*|*file-download*)
    raise REVIEW "download_path_hint"
    ;;
esac

# ── URL shorteners (landing host unknown without network resolve) ───────────
case "$HOST" in
  t.co|bit.ly|bitly.com|tinyurl.com|tiny.cc|goo.gl|ow.ly|is.gd|buff.ly|rebrand.ly|cutt.ly|rb.gy|shorturl.at|t.ly|lnkd.in|s.id|v.gd|qr.ae|clck.ru|adf.ly|bc.vc)
    raise REVIEW "url_shortener"
    ;;
esac

# Free / disposable file hosts often used for malware drops
case "$HOST" in
  *mediafire.com|*mega.nz|*mega.co.nz|*anonfiles.*|*pixeldrain.com|*gofile.io|*workupload.com|*transfer.sh|*file.io|*sendspace.com|*zippyshare.com|*rapidshare.*|*uploaded.net|*nitroflare.com|*turbobit.net)
    raise REVIEW "file_host"
    ;;
esac

# Extremely long URLs (possible exfil / tracking dumps)
if [[ "${RAW_LEN:-0}" -gt 2000 ]]; then
  raise REVIEW "very_long_url"
fi
if [[ "${QUERY_LEN:-0}" -gt 500 ]]; then
  raise REVIEW "very_long_query"
fi

# ── Optional allowlist: REVIEW host reputation → ALLOW (never unblocks BLOCK) ─
host_allowlisted() {
  local h="$1" line entry suf
  [[ -n "$ALLOWLIST" && -f "$ALLOWLIST" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    entry="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
    if [[ "$entry" == \*.* ]]; then
      suf="${entry#\*.}"
      [[ "$h" == "$suf" || "$h" == *."$suf" ]] && return 0
    elif [[ "$entry" == "$h" || "$h" == *."$entry" ]]; then
      return 0
    fi
  done <"$ALLOWLIST"
  return 1
}

# Default allowlist path if present
if [[ -z "$ALLOWLIST" && -f "${XDG_CONFIG_HOME:-$HOME/.config}/agent-security/research-allowlist.txt" ]]; then
  ALLOWLIST="${XDG_CONFIG_HOME:-$HOME/.config}/agent-security/research-allowlist.txt"
fi

if [[ "$VERDICT" == "REVIEW" ]] && host_allowlisted "$HOST"; then
  # Only strip host-reputation reasons; keep extension/shortener/download reasons.
  # If any remaining reason is non-host, stay REVIEW.
  STILL_REVIEW=0
  for r in "${REASONS[@]}"; do
    case "$r" in
      insecure_http|ip_literal_host|punycode_host|internal_looking_host|url_shortener|file_host|very_long_url|very_long_query)
        : # allowlist can clear pure host/transport reputation
        ;;
      *)
        STILL_REVIEW=1
        ;;
    esac
  done
  if [[ "$STILL_REVIEW" -eq 0 ]]; then
    VERDICT="ALLOW"
    REASONS+=("allowlisted_host")
  else
    REASONS+=("allowlisted_host_but_other_flags")
  fi
fi

# ── Emit ────────────────────────────────────────────────────────────────────
join_reasons() {
  local IFS=','
  echo "${REASONS[*]-}"
}

REASON_STR="$(join_reasons)"
[[ -z "$REASON_STR" ]] && REASON_STR="ok"

if [[ "$JSON" -eq 1 ]]; then
  # Minimal JSON without requiring jq
  esc() { printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()), end="")' 2>/dev/null || printf '"%s"' "${1//\"/\\\"}"; }
  printf '{"verdict":"%s","url":%s,"host":%s,"scheme":%s,"reasons":%s}\n' \
    "$VERDICT" "$(esc "$URL")" "$(esc "$HOST")" "$(esc "$SCHEME")" "$(esc "$REASON_STR")"
elif [[ "$QUIET" -eq 1 ]]; then
  printf '%s\n' "$VERDICT"
else
  printf 'check-url: %s\n' "$VERDICT"
  printf '  url:     %s\n' "$URL"
  printf '  host:    %s\n' "${HOST:-?}"
  printf '  scheme:  %s\n' "${SCHEME:-?}"
  printf '  reasons: %s\n' "$REASON_STR"
  case "$VERDICT" in
    ALLOW)  printf '  action:  fetch as HTML/text OK; content remains DATA (safe-research.md)\n' ;;
    REVIEW) printf '  action:  stop — get operator approval for this exact URL before fetch\n' ;;
    BLOCK)  printf '  action:  do not fetch; pick another source\n' ;;
  esac
fi

case "$VERDICT" in
  ALLOW) exit 0 ;;
  REVIEW) exit 1 ;;
  BLOCK) exit 2 ;;
  *) exit 3 ;;
esac
