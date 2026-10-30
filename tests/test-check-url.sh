#!/usr/bin/env bash
# Fixture tests for check-url.sh (safe-research pre-fetch classifier).
# Network-free. Usage: bash tests/test-check-url.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHK="$ROOT/scripts/check-url.sh"
FAILURES=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/check-url-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

chmod +x "$CHK" 2>/dev/null || true

run_expect() { # label, expected_exit, url, [flags...]
  local label="$1" expect="$2" url="$3"; shift 3
  local out code=0
  set +e; out=$(bash "$CHK" "$@" "$url" 2>&1); code=$?; set -e
  if [[ "$code" -eq "$expect" ]]; then
    echo "  ok  $label (exit $code)"
  else
    echo "  XX  $label — expected exit $expect got $code"
    echo "$out" | tail -8
    FAILURES=$((FAILURES+1))
  fi
  LAST_OUT="$out"
}
expect_in() {
  if grep -qF -- "$2" <<<"$LAST_OUT"; then echo "  ok  $1"
  else echo "  XX  $1 — output lacks: $2"; FAILURES=$((FAILURES+1)); fi
}

echo "agent-security test-check-url — offline fixtures"
echo "---"

# ALLOW: normal https docs URL
run_expect "https docs ALLOW" 0 "https://docs.python.org/3/library/urllib.html"
expect_in "ALLOW label" "ALLOW"

# ALLOW: github docs-ish path
run_expect "github https ALLOW" 0 "https://github.com/torvalds/linux"

# REVIEW: plain http
run_expect "http REVIEW" 1 "http://example.com/page"
expect_in "insecure_http reason" "insecure_http"

# REVIEW: PDF
run_expect "pdf REVIEW" 1 "https://example.com/whitepaper/report.pdf"
expect_in "pdf extension" "review_extension:.pdf"

# BLOCK: executable
run_expect "exe BLOCK" 2 "https://evil.example/payload.exe"
expect_in "exe blocked" "blocked_extension:.exe"

# BLOCK: archive
run_expect "zip BLOCK" 2 "https://cdn.example/dataset.zip"
expect_in "zip blocked" "blocked_extension:.zip"

# BLOCK: shell installer
run_expect "sh install BLOCK" 2 "https://get.example/install.sh"

# BLOCK: file scheme
run_expect "file: BLOCK" 2 "file:///etc/passwd"
expect_in "file scheme" "blocked_scheme:file"

# BLOCK: javascript scheme
run_expect "javascript: BLOCK" 2 "javascript:alert(1)"

# BLOCK: data scheme
run_expect "data: BLOCK" 2 "data:text/html,hi"

# BLOCK: credentials in URL
run_expect "userinfo BLOCK" 2 "https://user:secret@example.com/x"
expect_in "creds reason" "credentials_in_url"

# REVIEW: IP literal
run_expect "ipv4 REVIEW" 1 "https://203.0.113.10/docs"
expect_in "ip reason" "ip_literal_host"

# REVIEW: punycode
run_expect "punycode REVIEW" 1 "https://xn--e1afmkfd.example/page"
expect_in "punycode reason" "punycode_host"

# REVIEW: shortener
run_expect "bitly REVIEW" 1 "https://bit.ly/abc123"
expect_in "shortener reason" "url_shortener"

# REVIEW: file host
run_expect "mega REVIEW" 1 "https://mega.nz/file/xyz"

# BLOCK: localhost
run_expect "localhost BLOCK" 2 "https://localhost:8443/admin"

# quiet mode
out=$(bash "$CHK" --quiet "https://example.com/"); code=$?
if [[ "$code" -eq 0 && "$out" == "ALLOW" ]]; then echo "  ok  --quiet ALLOW"
else echo "  XX  --quiet ALLOW (got exit=$code out=$out)"; FAILURES=$((FAILURES+1)); fi

# allowlist upgrades pure http REVIEW for listed host (extension still sticks)
printf 'example.com\n' >"$TMP/allow.txt"
run_expect "allowlist upgrades http host" 0 "http://example.com/guide" --allowlist "$TMP/allow.txt"

# allowlist does NOT unblock .exe
run_expect "allowlist cannot unblock exe" 2 "https://example.com/x.exe" --allowlist "$TMP/allow.txt"

# allowlist does NOT unblock PDF alone into ALLOW without clearing extension — PDF stays REVIEW
run_expect "allowlist keeps pdf as REVIEW" 1 "https://example.com/a.pdf" --allowlist "$TMP/allow.txt"

# stdin
out=$(printf 'https://example.org/\n' | bash "$CHK" --quiet); code=$?
if [[ "$code" -eq 0 && "$out" == "ALLOW" ]]; then echo "  ok  stdin URL"
else echo "  XX  stdin URL (exit=$code out=$out)"; FAILURES=$((FAILURES+1)); fi

echo "---"
if [[ "$FAILURES" -eq 0 ]]; then
  echo "ALL PASS"
  exit 0
else
  echo "FAILURES: $FAILURES"
  exit 1
fi
