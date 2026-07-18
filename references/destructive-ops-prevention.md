# Destructive-ops prevention — the layered model (honest about each layer's limit)

The `repo-guard` this skill installs is **one layer**, and the weakest-sounding kind:
a **local brake**. This document is the honest map of the *whole* stack that actually
prevents the repo-destruction class — an automation deleting/transferring/renaming/
privatizing repositories and wiping thousands of accumulated stars in one command. The
thesis in one line:

> The local guard REDUCES accidental/automated destruction risk. It does NOT guarantee
> prevention — it is bypassed by absolute-path `gh` and by the REST API. **TRUE
> prevention is capability removal at GitHub:** a token without `delete_repo` literally
> cannot delete/transfer, bypass or not; plus org deletion/transfer restrictions and
> branch protection. This skill AUDITS and GUIDES those; **you apply them** (some need
> org-admin — the skill never changes your token or org settings).

Audit the live state with `scripts/harden-check.sh`.

## The layers

| Layer | What it STOPS | What it does NOT stop | Residual risk |
|---|---|---|---|
| **L1 — local repo-guard** (`~/.local/bin/gh` shim + Claude Code PreToolUse hook) | `gh repo delete\|rename\|transfer\|archive`, `edit --visibility private\|internal`, and the equivalent `gh api`/graphql — when gh is **PATH-resolved** (L1) or **absolute-path inside a Claude session** (L3), unless `REPO_LIFECYCLE_OK` names the exact repo. | Absolute-path `gh` **outside** a Claude session; `curl`/octokit against the REST API; any non-`gh` client. It is a per-machine brake, not a server policy. | **BYPASSABLE.** A determined/absolute-path/curl caller destroys anyway. Good against *accidental/automated* `gh`; useless as the *only* control. |
| **L2 — token scope minimization** (no `delete_repo` on automation tokens) | Repo **delete and transfer** — categorically. A token without `delete_repo` **cannot** perform them through *any* client, bypass or not. This is the real backstop. | Does not stop **privatize** or **archive** (those ride the `repo` scope's admin rights) or branch/history damage. | Low for delete/transfer *if* every automation identity lacks the scope. Residual: a human token that still has it, used by an automation by mistake. |
| **L3 — org policy** (member privileges: deletion/transfer restrictions) | Members (and their tokens) deleting/transferring org repos at all — a **server-side** backstop that no local bypass evades. Also base permissions + who can change visibility. | Repos owned by a **personal** account (not the org); actions by org **owners/admins**. | Low when set for the org. Residual: personal-account repos and org-admin identities remain capable. |
| **L4 — branch / tag protection** (protected default branch) | **Force-push**, history rewrite, and **branch deletion** on the protected branch — the "rewrite history / nuke main" class. | Repo-level **delete/transfer/privatize** (the repo object, not a branch). Different threat — L2/L3 own it. | Low for history integrity. Does nothing for the star-loss vector, which was repo-object destruction. |
| **L5 — backups / restore path** (GitHub ~90-day Support window + independent evidence) | Turns some destruction from permanent to recoverable: a **deleted** repo can be restored by GitHub Support within their window; **Wayback/archive.org** snapshots prove pre-incident star counts. | Not prevention — recovery, and only *sometimes*: a **delete+recreate** with the same name does **not** get old stars; the window is finite; stars aren't always restored even when the repo is. | Recovery is best-effort and time-boxed. Treat it as the last net, never the plan. |

**Read the table as a chain, not a menu.** L1 alone is a brake; the durable prevention of the
repo-destruction incident is **L2 + L3**. L4 covers a *different* destructive class (history),
and L5 is the net for when the first four fail.

## Which layer would have stopped which part of the incident

| Destructive action | Stopped by | Not stopped by |
|---|---|---|
| Automated `gh repo delete` (PATH-resolved) | L1 brake · L2 scope · L3 org policy | — |
| Automated delete via **absolute-path gh / curl / octokit** | **L2 scope · L3 org policy** | L1 (bypassed) |
| Repo **transfer** to another owner | L2 scope · L3 org policy | L1 if absolute-path/curl |
| **Privatize** (visibility flip hiding stars) | L3 org policy · L1 (if PATH/Claude) | L2 (`repo` scope still allows it) |
| Force-push / history rewrite on `main` | L4 branch protection | L1/L2/L3 |
| Already-deleted repo, stars gone | L5 recovery (partial, Support window) | everything preventive |

The single change with the largest blast-radius reduction: **remove `delete_repo` from every
automation token (L2)** and **set the org deletion/transfer restriction (L3)**. Those two make
the catastrophic path impossible regardless of the local guard's bypasses.

## Minimal automation-token recipe (what an agent actually needs)

An automation/agent identity should hold the **least** that lets it do its job, and none of
the repo-destroying capabilities. For classic PATs:

- **Grant:** `repo` (or, better, split: `public_repo` if it only touches public repos),
  `read:org`, `workflow` (only if it edits Actions), `gist` (only if it uses gists).
- **Never grant to automation:** `delete_repo` (delete/transfer), `admin:org`,
  `admin:repo_hook`, `admin:enterprise`, `site_admin`.
- **Prefer fine-grained PATs:** scope to *specific repos*, and set **Administration:
  none/read** (never read+write — read+write includes delete). Give **Contents: read+write**
  only where a push is needed.
- **The deliberate tradeoff:** a token without `delete_repo` also **cannot** perform a
  legitimate delete (e.g. removing a malware repo). That is intended — deletion becomes a
  **rare, manual, human** act with a transiently-scoped token, not an ambient automation
  capability.

Verify a token's scopes with `scripts/harden-check.sh` (it parses `gh auth status`; feed a
captured file with `--auth-status-file` to check offline).

## Exact GitHub Settings paths (you apply these — some need org-admin)

- **Org: member deletion/transfer restriction** —
  `https://github.com/organizations/<ORG>/settings/member_privileges`
  → "Allow members to delete or transfer repositories for this organization" = **OFF**.
  (Note: org policy does **not** cover repos owned by a personal account — review those too.)
- **Org: base permissions & repo creation** — same page; keep base permission at the minimum
  and restrict who can create/change visibility.
- **Repo: branch protection** — `https://github.com/<OWNER>/<REPO>/settings/branches`
  → protect the default branch: require PR, **block force-push**, **block deletions**. Apply to
  every public repo that accrues stars.
- **Personal-token audit** — `https://github.com/settings/tokens` (classic) /
  `https://github.com/settings/personal-access-tokens` (fine-grained): revoke anything unused,
  strip `delete_repo` from automation identities.

## Depth

For host/token/infra hardening and least-privilege token patterns, and for OSS-maintainer repo
hygiene (branch protection, star-asset stewardship), consult a dedicated infrastructure-security
and OSS-maintainer reference. If destruction is in progress, follow an ordered incident method
(declare → preserve → contain → scope → hunt persistence → eradicate → recover → learn).

## Honest bottom line

The guard this skill installs is real and worth having — it converts a one-command accident into
a deliberate act on the common path. But if someone asks "are the repos safe from deletion now?"
the honest answer is **only once L2 (token scope) and L3 (org policy) are applied at GitHub** —
which is your action, not something this skill can do for you. Until then, `harden-check.sh`
reports the gap rather than papering over it.
