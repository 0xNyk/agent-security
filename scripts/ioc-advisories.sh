#!/usr/bin/env bash
# ioc-advisories.sh — turn GitHub's malware advisories into candidate lines for
# ioc-indicators.txt, so the list stops being one publication behind.
#
# Read-only. It never writes the indicator file: it prints a block you review and then
# append yourself. Advisory text is third-party data, so only the package name, the
# version and the advisory id are used, and each must match a strict ASCII character set
# in full. Anything outside it (a newline, a tab, |, (, $, a space) is rejected, not
# escaped; the dots and pluses that legal names and versions contain are escaped by the
# sweep.
#
# Usage:
#   ioc-advisories.sh                          since the newest "added YYYY-MM-DD" header
#   ioc-advisories.sh --since 2026-10-01       explicit start date (published on or after)
#   ioc-advisories.sh --ecosystem npm          npm | pip | rust | all (default all)
#   ioc-advisories.sh --match 'mcp|agent|cli'  keep only names matching an ERE
#   ioc-advisories.sh --limit 200              cap candidate lines (default 1000)
#   ioc-advisories.sh --from-file advisories.json   offline: parse a saved API response
#   ioc-advisories.sh --indicators FILE        list to deduplicate against
#
# Review, then append:
#   scripts/ioc-advisories.sh --since 2026-10-30 > /tmp/new.txt
#   less /tmp/new.txt && cat /tmp/new.txt >> scripts/ioc-indicators.txt
#
# Mapping: a range of ">= 0" or "> 0" (the whole package is malicious) becomes NPMPKG /
# PYPKG / CRATE; one or more "= x.y.z" become NPMVER / PYVER / CRATEVER lines; anything
# else (an upper-bounded range on a hijacked package) is printed as a comment to review,
# because flagging every older version of a legitimate package would be noise.
#
# Network: GitHub's public advisory API, through `gh api` when gh is installed (paginated,
# authenticated rate limit), else one unauthenticated page through curl.
# Exit: 0 ok (zero candidates is ok), 2 could not run (BLIND).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INDICATORS="$HERE/ioc-indicators.txt"
SINCE=""; ECOS="npm pip rust"; FROM=""; MATCH=""; LIMIT=1000

usage() { sed -n '2,/^set -uo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'; }
die()   { echo "BLIND: $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --since)      [[ $# -ge 2 ]] || die "--since needs a date"; SINCE="$2"; shift 2 ;;
    --ecosystem)  [[ $# -ge 2 ]] || die "--ecosystem needs a value"
                  case "$2" in npm|pip|rust) ECOS="$2" ;; all) ECOS="npm pip rust" ;;
                    *) die "--ecosystem must be npm, pip, rust or all" ;; esac; shift 2 ;;
    --indicators) [[ $# -ge 2 ]] || die "--indicators needs a file"; INDICATORS="$2"; shift 2 ;;
    --from-file)  [[ $# -ge 2 ]] || die "--from-file needs a file"; FROM="$2"; shift 2 ;;
    --match)      [[ $# -ge 2 ]] || die "--match needs a pattern"; MATCH="$2"; shift 2 ;;
    --limit)      [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]] && (( 10#$2 > 0 )) || die "--limit needs a positive whole number"; LIMIT="$((10#$2))"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *)            die "unknown argument: $1 (see --help)" ;;
  esac
done

command -v python3 >/dev/null 2>&1 || die "python3 is required to parse the advisory JSON"
[[ -r "$INDICATORS" ]] || die "indicators file unreadable: $INDICATORS"
if [[ -n "$MATCH" ]]; then
  python3 -I -c 'import re,sys; re.compile(sys.argv[1])' "$MATCH" 2>/dev/null || die "--match is not a valid regular expression"
fi

if [[ -z "$SINCE" ]]; then
  # the newest dated section header in the list is where the last refresh stopped
  SINCE="$(grep -oE '^# ---- added [0-9]{4}-[0-9]{2}-[0-9]{2}' "$INDICATORS" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort | tail -1)"
  [[ -n "$SINCE" ]] || SINCE="$(date -v-7d +%F 2>/dev/null || date -d '7 days ago' +%F)"
fi
[[ "$SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "--since must be YYYY-MM-DD"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ioc-advisories.XXXXXX")" || die "cannot create a work directory"
trap 'rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
RAW="$WORK/advisories.json"; : > "$RAW"

if [[ -n "$FROM" ]]; then
  [[ -r "$FROM" ]] || die "--from-file unreadable: $FROM"
  cat "$FROM" > "$RAW"
  SOURCE="file $FROM"
else
  for eco in $ECOS; do
    if command -v gh >/dev/null 2>&1; then
      gh api -X GET /advisories -f type=malware -f ecosystem="$eco" -f "published=>=$SINCE" \
        -f per_page=100 --paginate >> "$RAW" 2>"$WORK/err" ||
        die "GitHub advisory API failed for $eco: $(head -1 "$WORK/err")"
      SOURCE="gh api (paginated)"
    elif command -v curl >/dev/null 2>&1; then
      curl -fsS --max-time 60 -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/advisories?type=malware&ecosystem=${eco}&published=%3E%3D${SINCE}&per_page=100" \
        >> "$RAW" 2>"$WORK/err" || die "GitHub advisory API failed for $eco: $(head -1 "$WORK/err")"
      SOURCE="curl (first 100 per ecosystem; install gh for pagination)"
    else
      die "neither gh nor curl is installed"
    fi
  done
fi

python3 -I - "$RAW" "$INDICATORS" "$MATCH" "$LIMIT" "$SINCE" "$ECOS" "$SOURCE" <<'PY'
import json, re, sys, datetime
raw, ind, match, limit, since, ecos, source = sys.argv[1:8]
limit = int(limit); want = set(ecos.split())

# gh --paginate concatenates one JSON array per page; decode them one after another.
text = open(raw, encoding="utf-8", errors="replace").read()
dec = json.JSONDecoder(); pos = 0; advisories = []; pages = 0
def blind(msg): print(f"BLIND: {msg}", file=sys.stderr); sys.exit(3)
while True:
    while pos < len(text) and text[pos].isspace(): pos += 1
    if pos >= len(text): break
    try:
        obj, pos = dec.raw_decode(text, pos)
    except ValueError as e:
        blind(f"advisory response is not valid JSON ({e.msg} at {pos})")
    # anything but a list of advisories (an error body, null, a truncated proxy reply that
    # still parses) must not read as "no new advisories"
    if not isinstance(obj, list): blind("advisory response is not a list (API error or proxy reply)")
    advisories.extend(obj); pages += 1
if pages == 0: blind("advisory response is empty")

KINDS = {"npm": ("NPMPKG", "NPMVER"), "pip": ("PYPKG", "PYVER"), "rust": ("CRATE", "CRATEVER")}
# fullmatch, ASCII classes only: `$` alone would accept a trailing newline, and \d would
# accept non-ASCII digits
NAME_RE = {
    "npm":  re.compile(r"(@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9._~-]+", re.ASCII),
    "pip":  re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*", re.ASCII),
    "rust": re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*", re.ASCII),
}
VER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]*", re.ASCII)
GHSA_RE = re.compile(r"GHSA(-[a-z0-9]{4}){3}", re.ASCII)
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)
RANGE_OK = re.compile(r"[0-9A-Za-z.,<>=! +_-]*", re.ASCII)
match_re = re.compile(match) if match else None

def key_name(eco, name):
    # PyPI names compare per PEP 503 (- _ . interchangeable, case-insensitive), like the sweep
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "pip" else name.lower()
ECO_OF = {"NPMPKG": "npm", "NPMVER": "npm", "PYPKG": "pip", "PYVER": "pip", "CRATE": "rust", "CRATEVER": "rust"}

pkg_have, ver_have = set(), set()
for line in open(ind, encoding="utf-8", errors="replace"):
    if not line.strip() or line.startswith("#"): continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2: continue
    kind, value = parts[0], parts[1]
    if kind not in ECO_OF: continue
    kn = key_name(ECO_OF[kind], value)
    if kind in ("NPMPKG", "PYPKG", "CRATE"): pkg_have.add((kind, kn))
    elif len(parts) >= 3: ver_have.add((kind, kn, parts[2].strip()))

out, seen = [], set()
n_listed = n_rejected = n_unmapped = n_filtered = 0
for a in advisories:
    if not isinstance(a, dict): continue
    ghsa = a.get("ghsa_id") or ""
    ghsa = ghsa if isinstance(ghsa, str) and GHSA_RE.fullmatch(ghsa) else "GHSA-unknown"
    pub = str(a.get("published_at") or "")[:10]
    pub = pub if DATE_RE.fullmatch(pub) else "date-unknown"
    for v in a.get("vulnerabilities") or []:
        pkg = (v or {}).get("package") or {}
        eco, name = pkg.get("ecosystem") or "", pkg.get("name") or ""
        if eco not in KINDS or eco not in want: continue
        if not isinstance(name, str) or len(name) > 214 or not NAME_RE[eco].fullmatch(name): n_rejected += 1; continue
        kn = key_name(eco, name)
        if match_re and not match_re.search(name): n_filtered += 1; continue
        pkind, vkind = KINDS[eco]
        rng = str(v.get("vulnerable_version_range") or "").strip()
        if (pkind, kn) in pkg_have: n_listed += 1; continue
        parts = [p.strip() for p in rng.split(",") if p.strip()]
        if rng in (">= 0", "> 0", "*"):   # an empty range is a judgement call: left unmapped
            key = (pkind, kn)
            if key not in seen:
                seen.add(key); out.append((eco, name, "", f"{pkind}\t{name}\t{ghsa} {pub}"))
        elif parts and all(p.startswith("= ") for p in parts):
            for p in parts:
                ver = p[2:].strip()
                if len(ver) > 64 or not VER_RE.fullmatch(ver): n_rejected += 1; continue
                key = (vkind, kn, ver)
                if key in ver_have: n_listed += 1; continue
                if key in seen: continue
                seen.add(key)
                # the third column of a *VER line IS the version, so provenance goes above it
                out.append((eco, name, ver, f"# {ghsa} {pub}\n{vkind}\t{name}\t{ver}"))
        else:
            n_unmapped += 1
            shown = (rng or "(no range)") if RANGE_OK.fullmatch(rng) else "(range withheld: unexpected characters)"
            out.append((eco, name, "~", f"# unmapped, review by hand: {eco} {name} {shown} ({ghsa} {pub})"))

# a whole-package line makes that package's per-version lines redundant
whole = {(t[0], key_name(t[0], t[1])) for t in out if t[2] == ""}
out = [t for t in out if t[2] in ("", "~") or (t[0], key_name(t[0], t[1])) not in whole]
out.sort(key=lambda t: (t[0], t[1].lower(), t[2]))
truncated = max(0, len(out) - limit); out = out[:limit]
today = datetime.date.today().isoformat()
cand = sum(1 for t in out if not t[3].startswith("# unmapped"))
print(f"# ioc-advisories: {len(advisories)} malware advisories published since {since} ({source})")
print(f"#   {cand} new candidate(s), {n_listed} already listed, {n_unmapped} unmapped, "
      f"{n_rejected} rejected (unsafe name or version), {n_filtered} outside --match"
      + (f", {truncated} cut by --limit" if truncated else ""))
print("#   Review every line before appending. A name here means GitHub published it as malware;")
print("#   it does not mean it is on this machine.")
print(f"\n# ---- added {today} (GitHub malware advisories published since {since}) ----")
for t in out: print(t[3])
PY
rc=$?
[[ $rc -eq 0 ]] || exit 2
exit 0
