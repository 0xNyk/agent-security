#!/bin/bash
# repo-guard PreToolUse hook: hard-block DESTRUCTIVE GitHub repository lifecycle
# ops inside Claude Code (or any harness that speaks the PreToolUse JSON contract).
# Companion to the PATH shim (gh-shim.sh) — this hook catches the one case the shim
# cannot: a command invoking gh by ABSOLUTE path (e.g. /opt/homebrew/bin/gh ...),
# which bypasses PATH resolution entirely.
#
#   exit 2 BLOCKS the tool call. Fails closed: unparseable input blocks.
#   Detection parity with the shim (gh-shim.sh).
#
# Blocked (repo-level only): gh repo delete|rename|archive|transfer,
#   gh repo edit --visibility private|internal, gh api DELETE/PATCH on
#   /repos/OWNER/REPO (name|visibility|archived|private), /repos/.../transfer,
#   and graphql deleteRepository/archiveRepository/updateRepository->private.
# NOT blocked: branch/file/label/release sub-resource ops, git push branch
#   deletes, making a repo public, unarchive, view/list/clone/create.
#
# OVERRIDE (human-in-the-loop): prefix the command with the exact repo, e.g.
#   REPO_LIFECYCLE_OK=owner/repo gh repo delete owner/repo --yes
# Also honors REPO_LIFECYCLE_OK from the environment, and the
# --yes-destroy-<repo> token form.

set -uo pipefail
input=$(cat)

verdict=$(printf '%s' "$input" | REPO_LIFECYCLE_OK_ENV="${REPO_LIFECYCLE_OK:-}" python3 -c '
import sys, json, re, shlex, os

def out(s):
    print(s)
    sys.exit(0)

try:
    d = json.load(sys.stdin)
except Exception:
    out("BLOCK\tunparseable hook input (failing closed)\t-")

ti = d.get("tool_input") or {}
if not isinstance(ti, dict):
    ti = {}
cmd = str(ti.get("command") or "")
if not cmd.strip():
    out("OK")

env_override = os.environ.get("REPO_LIFECYCLE_OK_ENV", "")

def is_gh(tok):
    return tok == "gh" or tok.endswith("/gh")

def flag_val(tokens, i, names):
    """Return value for tokens[i] if it is one of names (space or = joined)."""
    t = tokens[i]
    for nm in names:
        if t == nm:
            return tokens[i+1] if i+1 < len(tokens) else ""
        if t.startswith(nm + "="):
            return t[len(nm)+1:]
    return None

def repo_from_flags(gargs):
    for i, t in enumerate(gargs):
        v = flag_val(gargs, i, ["--repo", "-R"])
        if v:
            return v.rstrip("/")
    return ""

def norm_method(gargs):
    m = ""
    for i, t in enumerate(gargs):
        v = flag_val(gargs, i, ["-X", "--method"])
        if v is not None and v != "":
            m = v
        elif re.match(r"^-X[A-Za-z]+$", t):
            m = t[2:]
    return (m or "GET").upper()

def overridden(target, inline_env):
    base = target.split("/")[-1]
    for val in (inline_env, env_override):
        if not val:
            continue
        if val in (target, "--yes-destroy-" + target, "--yes-destroy-" + base):
            return True
    return False

# Split the command into segments; analyse each one that invokes gh.
segments = re.split(r"\|\||&&|\||;|\n|&", cmd)
for seg in segments:
    seg = seg.strip()
    if not seg or "gh" not in seg:
        continue
    try:
        toks = shlex.split(seg)
    except Exception:
        toks = seg.split()
    if not toks:
        continue

    # inline REPO_LIFECYCLE_OK=... env assignment (leading, before gh)
    inline_env = ""
    gh_idx = -1
    for i, t in enumerate(toks):
        if t.startswith("REPO_LIFECYCLE_OK="):
            inline_env = t.split("=", 1)[1]
        if is_gh(t):
            gh_idx = i
            break
    if gh_idx < 0:
        continue

    gargs = toks[gh_idx+1:]
    if not gargs:
        continue
    # help/version never destructive
    if any(a in ("-h", "--help", "--version") for a in gargs):
        continue

    sub1 = gargs[0] if len(gargs) > 0 else ""
    sub2 = gargs[1] if len(gargs) > 1 else ""

    what = ""
    target = ""

    if sub1 == "repo":
        if sub2 in ("delete", "archive", "transfer"):
            what = "repo " + sub2
        elif sub2 == "rename":
            what = "repo rename"
        elif sub2 == "edit":
            vis = ""
            for i in range(len(gargs)):
                v = flag_val(gargs, i, ["--visibility"])
                if v:
                    vis = v
            if vis in ("private", "internal"):
                what = "repo edit --visibility " + vis
            else:
                continue
        else:
            continue
        # resolve target: -R flag, else first positional after subcommand
        target = repo_from_flags(gargs)
        if not target and sub2 != "rename":
            for a in gargs[2:]:
                if not a.startswith("-"):
                    target = a.rstrip("/"); break
        if not target:
            target = "UNKNOWN"

    elif sub1 == "api":
        # graphql light check
        if "graphql" in gargs:
            joined = " ".join(gargs)
            if re.search(r"deleteRepository|archiveRepository", joined):
                what = "repo destruction via graphql"; target = "UNKNOWN"
            elif re.search(r"updateRepository", joined) and re.search(r"visibility.*(PRIVATE|INTERNAL)|private[\x27\"]?\s*:\s*true", joined, re.I):
                what = "repo privatize via graphql"; target = "UNKNOWN"
            else:
                continue
        else:
            method = norm_method(gargs)
            has_fields = any(a in ("-f","-F","--field","--raw-field") or a.startswith(("-f=","-F=","--field=","--raw-field=")) for a in gargs)
            has_input = any(a == "--input" or a.startswith("--input=") for a in gargs)
            ep = ""
            for a in gargs[1:]:
                if a.startswith("-"):
                    continue
                if "repos/" in a:
                    ep = a; break
            if not ep:
                continue
            m = re.search(r"repos/.*$", ep)
            p = m.group(0) if m else ""
            p = p.split("?")[0].rstrip("/").lstrip("/")
            if re.match(r"^repos/[^/]+/[^/]+/transfer$", p):
                what = "repo transfer via gh api"
                target = re.sub(r"^repos/([^/]+/[^/]+)/transfer$", r"\1", p)
            elif re.match(r"^repos/[^/]+/[^/]+$", p):
                target = p[len("repos/"):]
                if method == "DELETE":
                    what = "repo delete via gh api"
                elif method in ("PATCH","PUT") or (has_fields and method in ("POST","GET")):
                    if has_input:
                        what = "repo mutate via gh api (--input to repo root)"
                    else:
                        for a in gargs:
                            if re.match(r"^(name|visibility|archived|private)=", a):
                                what = "repo mutate via gh api (" + a.split("=")[0] + ")"
                                break
                if not what:
                    continue
            else:
                continue
    else:
        continue

    if what:
        if overridden(target, inline_env):
            continue
        out("BLOCK\t" + what + "\t" + target)

out("OK")
')

if [[ "$verdict" == BLOCK* ]]; then
  rest="${verdict#BLOCK$'\t'}"
  what="${rest%%$'\t'*}"
  target="${rest##*$'\t'}"
  logdir="${REPO_GUARD_STATE:-$HOME/.local/state/repo-guard}"
  mkdir -p "$logdir" 2>/dev/null && chmod 700 "$logdir" 2>/dev/null
  printf '%s\tHOOK\tBLOCKED\twhat=%s\ttarget=%s\n' "$(date -u +%FT%TZ)" "$what" "$target" >> "$logdir/blocked.log" 2>/dev/null
  {
    echo "BLOCKED by repo-guard hook: ${what} (repo: ${target})."
    echo "This is a destructive GitHub repository operation. No API call was made."
    echo "A human must confirm the exact repo to proceed. Re-run prefixed with:"
    if [ "$target" = "UNKNOWN" ] || [ "$target" = "-" ]; then
      echo "  REPO_LIFECYCLE_OK=<owner/repo> <your gh command>"
    else
      echo "  REPO_LIFECYCLE_OK=${target} <your gh command>"
    fi
    echo "See the repo-guard section of references/coverage-and-limits.md for the full policy."
  } >&2
  exit 2
fi

exit 0
