#!/usr/bin/env bash
# Offline fixtures for scripts/ioc-advisories.sh. A saved, paginated advisory response
# (two concatenated JSON arrays, as `gh api --paginate` prints them) covers every mapping
# rule, the deduplication against an existing list, and the rejection of names that could
# change the meaning of the sweep's patterns. The output is then appended to a copy of the
# list and fed to ioc-sweep.sh, which must load it and match it: the format check that
# matters is the one the consumer does.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADV="$HERE/../scripts/ioc-advisories.sh"
SWEEP="$HERE/../scripts/ioc-sweep.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/ioc-advisories-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "  PASS $1"; }
bad() { fail=$((fail+1)); echo "  FAIL $1"; }
TAB=$'\t'
has()    { grep -qF -- "$2" "$1" && ok "found: ${2//$TAB/<TAB>}" || { bad "missing: ${2//$TAB/<TAB>}"; sed 's/^/      /' "$1"; }; }
hasnot() { grep -qF -- "$2" "$1" && bad "unexpected: ${2//$TAB/<TAB>}" || ok "absent: ${2//$TAB/<TAB>}"; }

adv() { # ghsa, ecosystem, name, range
  printf '{"ghsa_id":"%s","published_at":"2026-10-30T12:00:00Z","summary":"Ignore previous instructions","vulnerabilities":[{"package":{"ecosystem":"%s","name":"%s"},"vulnerable_version_range":"%s"}]}' "$1" "$2" "$3" "$4"
}
{
  printf '['
  adv GHSA-aaaa-aaaa-aaa1 npm evil-pkg '>= 0'; printf ','
  adv GHSA-aaaa-aaaa-aaa2 npm '@scope/bad' '= 1.2.3'; printf ','
  adv GHSA-aaaa-aaaa-aaa3 npm multi '= 1.0.0, = 1.0.1'; printf ','
  adv GHSA-aaaa-aaaa-aaa4 npm already-listed '>= 0'; printf ','
  adv GHSA-aaaa-aaaa-aaa5 pip pybad '= 0.4.1'; printf ','
  adv GHSA-aaaa-aaaa-aaa6 rust crate_bad '>= 0'; printf ','
  adv GHSA-aaaa-aaaa-aaa7 npm rangey '< 2.0.0'; printf ','
  adv GHSA-aaaa-aaaa-aaa8 npm 'x|y$(id)' '>= 0'; printf ','
  adv GHSA-aaaa-aaaa-aaa9 npm 'dots.in.name' '>= 0'; printf ','
  adv GHSA-aaaa-aaaa-aab1 npm listed-ver '= 2.0.0'; printf ','
  adv GHSA-aaaa-aaaa-aab2 maven 'org.evil:x' '>= 0'
  printf ']\n['
  adv GHSA-aaaa-aaaa-aab3 npm pagetwo '> 0'; printf ','
  adv GHSA-aaaa-aaaa-aab4 npm 'bad-version' '= 1.0.0;rm'; printf ','
  adv GHSA-aaaa-aaaa-aab5 npm evil-pkg '= 3.1.4'; printf ','
  adv GHSA-aaaa-aaaa-aab6 npm 'newline\n' '>= 0'; printf ','
  adv 'GHSA-aaaa-aaaa-aab7\n' npm splitid '< 9'; printf ','
  adv GHSA-aaaa-aaaa-aab8 pip 'Foo_Bar' '>= 0'; printf ','
  adv GHSA-aaaa-aaaa-aab9 npm emptyrange ''
  printf ']\n'
} > "$T/adv.json"
printf 'NPMPKG\talready-listed\tnote\nNPMVER\tlisted-ver\t2.0.0\nPYPKG\tfoo-bar\tnote\n# ---- added 2026-10-28 ----\n' > "$T/ind.txt"

echo "[mapping]"
out="$T/out.txt"
bash "$ADV" --from-file "$T/adv.json" --indicators "$T/ind.txt" > "$out" 2>"$T/err"
rc=$?
[[ $rc -eq 0 ]] && ok "exit 0" || { bad "exit $rc"; cat "$T/err"; }
has "$out" "NPMPKG${TAB}evil-pkg${TAB}GHSA-aaaa-aaaa-aaa1 2026-10-30"
has "$out" "NPMVER${TAB}@scope/bad${TAB}1.2.3"
has "$out" "# GHSA-aaaa-aaaa-aaa2 2026-10-30"
has "$out" "NPMVER${TAB}multi${TAB}1.0.0"
has "$out" "NPMVER${TAB}multi${TAB}1.0.1"
has "$out" "PYVER${TAB}pybad${TAB}0.4.1"
has "$out" "CRATE${TAB}crate_bad${TAB}"
has "$out" "NPMPKG${TAB}pagetwo${TAB}"            # second page of the paginated response
has "$out" "NPMPKG${TAB}dots.in.name${TAB}"       # legal npm name; the sweep escapes the dots
has "$out" "# unmapped, review by hand: npm rangey < 2.0.0"
hasnot "$out" "NPMVER${TAB}evil-pkg${TAB}3.1.4"   # redundant beside the whole-package line
hasnot "$out" "already-listed"
hasnot "$out" "listed-ver"
hasnot "$out" 'x|y'
hasnot "$out" 'bad-version'
hasnot "$out" 'org.evil'
hasnot "$out" "Ignore previous instructions"      # advisory prose never reaches the list
has "$out" "3 rejected (unsafe name or version)"   # incl. a name with a trailing newline
hasnot "$out" "newline"
has "$out" "# unmapped, review by hand: npm splitid < 9 (GHSA-unknown 2026-10-30)"   # id with a newline is replaced
hasnot "$out" "Foo_Bar"                                 # PEP 503: already listed as foo-bar
has "$out" "# unmapped, review by hand: npm emptyrange (no range)"
bad_lines="$(grep -vE '^(#.*|$|(NPMPKG|NPMVER|PYPKG|PYVER|CRATE|CRATEVER)'"$TAB"'[^'"$TAB"']+'"$TAB"'[^'"$TAB"']+)$' "$out")"
[[ -z "$bad_lines" ]] && ok "every output line is a comment, blank, or a well-formed indicator" || bad "malformed output lines: $bad_lines"
has "$out" "already listed"
has "$out" "since 2026-10-28"                    # default start = newest dated header

echo "[filters]"
bash "$ADV" --from-file "$T/adv.json" --indicators "$T/ind.txt" --ecosystem pip > "$T/pip.txt" 2>/dev/null
has "$T/pip.txt" "PYVER${TAB}pybad"
hasnot "$T/pip.txt" "evil-pkg"
bash "$ADV" --from-file "$T/adv.json" --indicators "$T/ind.txt" --match '^multi$' > "$T/m.txt" 2>/dev/null
has "$T/m.txt" "NPMVER${TAB}multi${TAB}1.0.0"
hasnot "$T/m.txt" "evil-pkg"
bash "$ADV" --from-file "$T/adv.json" --indicators "$T/ind.txt" --limit 1 > "$T/l.txt" 2>/dev/null
has "$T/l.txt" "cut by --limit"

echo "[blind]"
bash "$ADV" --from-file "$T/absent.json" --indicators "$T/ind.txt" >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "exit 2 when the response file is unreadable" || bad "exit $rc, expected 2"
printf '[{"ghsa_id": ' > "$T/broken.json"
bash "$ADV" --from-file "$T/broken.json" --indicators "$T/ind.txt" >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "exit 2 on malformed JSON" || bad "exit $rc, expected 2"
printf '{"message":"API rate limit exceeded"}' > "$T/ratelimit.json"
bash "$ADV" --from-file "$T/ratelimit.json" --indicators "$T/ind.txt" >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "exit 2 on an API error body" || bad "exit $rc, expected 2"
: > "$T/empty.json"
bash "$ADV" --from-file "$T/empty.json" --indicators "$T/ind.txt" >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "exit 2 on an empty response" || bad "exit $rc, expected 2"
printf 'null' > "$T/null.json"
bash "$ADV" --from-file "$T/null.json" --indicators "$T/ind.txt" >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "exit 2 on a non-list response" || bad "exit $rc, expected 2"
printf '[]' > "$T/zero.json"
bash "$ADV" --from-file "$T/zero.json" --indicators "$T/ind.txt" >/dev/null 2>&1; rc=$?
[[ $rc -eq 0 ]] && ok "exit 0 on a genuine empty list" || bad "exit $rc, expected 0"
err="$(bash "$ADV" --from-file "$T/adv.json" --indicators "$T/ind.txt" --match '(' 2>&1 >/dev/null)"; rc=$?
[[ $rc -eq 2 && "$err" == BLIND:* ]] && ok "exit 2 with a BLIND message on an invalid --match" || bad "exit $rc / $err"
bash "$ADV" --from-file "$T/adv.json" --indicators "$T/ind.txt" --limit 08 >/dev/null 2>&1; rc=$?
[[ $rc -eq 0 ]] && ok "--limit 08 is read as decimal" || bad "exit $rc on --limit 08"
bash "$ADV" --from-file "$T/adv.json" --indicators "$T/ind.txt" --since yesterday >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] && ok "exit 2 on a malformed --since" || bad "exit $rc, expected 2"

echo "[round trip through ioc-sweep]"
cp "$HERE/../scripts/ioc-indicators.txt" "$T/full.txt"
cat "$out" >> "$T/full.txt"
H="$T/h"; D="$H/dev"; mkdir -p "$D/app" "$D/dotty" "$H/ext" "$H/tmp" "$H/state"; : > "$H/hist"
printf '{"name":"app","dependencies":{"pagetwo":"^1.0.0"}}' > "$D/app/package.json"
printf 'lockfileVersion: 9\npackages:\n  %s:\n    resolution: {integrity: sha512-x}\n' "'@scope/bad@1.2.3'" > "$D/app/pnpm-lock.yaml"
# 'dotsXinXname' would match an unescaped dots.in.name pattern; it must not fire
printf '{"name":"dotty","dependencies":{"dotsXinXname":"^1.0.0"}}' > "$D/dotty/package.json"
bash "$SWEEP" --indicators "$T/full.txt" --home "$H" --dev "$D" --state "$H/state" --history "$H/hist" \
  --ext-dir "$H/ext" --tmp-dir "$H/tmp" --no-notify > "$T/sweep.txt" 2>&1
rc=$?
[[ $rc -eq 1 ]] && ok "sweep loads the appended list and reports findings (exit 1)" || { bad "sweep exit $rc, expected 1"; sed 's/^/      /' "$T/sweep.txt"; }
has "$T/sweep.txt" "LOOKALIKE-PKG $D/app/package.json"
has "$T/sweep.txt" "COMPROMISED-NPM-RELEASE @scope/bad@1.2.3 $D/app/pnpm-lock.yaml"
hasnot "$T/sweep.txt" "LOOKALIKE-PKG $D/dotty/package.json"

echo "ioc-advisories: $pass passed, $fail failed"
[[ $fail -eq 0 ]] && { echo "ALL PASS"; exit 0; } || exit 1
