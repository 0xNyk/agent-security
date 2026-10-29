# Threat model

Four threat classes motivated this skill. All are drawn from real incidents; all
are described here generically, and every claim points at a **public** primary source.

Defensive-documentation note: this file names encoder and sink tokens as taxonomy,
never as runnable payload syntax. It carries no exec-sink call syntax and no hidden
codepoints, so the scanner stays clean on this tree.

---

## Class 1 — obfuscated code-execution droppers (supply-chain)

**What it is.** A dropper is a **deobfuscation/decode stage feeding a dynamic-execution
sink** — not one fixed `atob`+`eval` string. It generalizes on five axes at once, and a
detector has to catch the *class*, not one cell:

| Axis | Values seen 2024–2026 |
|---|---|
| **Encoder** | base64; hex; `String.fromCharCode` / `charCodeAt`; `\x` / `\u` escape runs; string reversal; custom/shuffled base64 alphabet; XOR byte loop; **invisible unicode** |
| **Sink** | `eval`; `new Function`; `vm.runInContext` / `vm.Script`; dynamic `import`; `child_process`; Python `exec` / `compile` / `__import__`; PowerShell `IEX` / `-EncodedCommand` |
| **Carrier** | string literal; `.env` / env var; argv; remote config; image bytes / EXIF / LSB steg; blockchain memo |
| **Hiding spot** | build/test config; test setup; husky / git hook; CI YAML; editor / agent config; `postinstall` |
| **Delivery** | poisoned starter template; typosquat; dependency confusion; compromised maintainer; malicious lifecycle script |

**The motivating incident** maps to exactly one cell: base64 (encoder) → an `eval` sink,
a `.env` value (carrier), a build/test config (hiding spot), a poisoned starter template
(delivery). Template poisoning has **no registry provenance surface at all** — package
scanners never see a git-cloned template, so it must be caught by reading the config.

**Public primary sources for the wider class:**

- **xz-utils backdoor — CVE-2024-3094** (Andres Freund, 2024-03-29): a multi-year
  maintainer takeover hid the payload in **test fixtures + a build macro present only in
  the release tarball**, reaching pre-auth sshd RCE. The source-vs-artifact lesson —
  identical in spirit to a dropper hiding in config.
- **Shai-Hulud** self-replicating npm worm (2025-09, ~500 packages) and **2.0**
  (2025-11, ~796 packages): install-time credential theft + auto-republish loop, public
  exfil repos, self-hosted-runner persistence.
- **Nx / s1ngularity** (2025-08): a `postinstall` script harvested GitHub/npm/SSH/cloud
  tokens and weaponized local AI CLIs with skip-permission flags.
- **GlassWorm** (Koi Security, 2025-10): hid loader text in **supplementary variation
  selectors** (U+E0100–E01EF) passed to an `eval` sink — invisible to both human review
  and token scanners — with a Solana-memo + Google-Calendar command channel.
- **tj-actions/changed-files — CVE-2025-30066** (2025): a third-party GitHub Action pinned
  by mutable tag was compromised, affecting 23,000+ repositories — why CI actions must be
  SHA-pinned and `pull_request_target` reviewed.
- **OWASP** Top 10 for LLM Applications (LLM01:2025 Prompt Injection) and the Agentic
  Security guidance: the umbrella for agent-specific supply-chain and injection risk.

**Where droppers hide (always-read surfaces).** Surfaces that execute on mundane commands
and get *skimmed, not read*: `vite`/`vitest`/`webpack`/`rollup`/`next` config and test
setup; `.husky/*` and `.git/hooks/*`; `package.json` `pre`/`post`/`prepare` scripts;
`.github/workflows/*`; `.vscode/`, `.devcontainer`; and agent config (`.cursor/rules`,
`AGENTS*`, `.mcp.json`). Read them in full in any template or third-party package. Require
a behavioral tell (net/exec/decode/obfuscation) before flagging, so the surface list stays
tight and the gate is never disabled.

**Grounding scale (indicative, not precise — vendor magnitudes differ).** Sonatype /
ReversingLabs 2026 reporting puts droppers in a low single-digit percentage of packages,
with a large share of *malicious* packages obfuscated (mostly base64), and npm carrying the
majority of observed OSS malware. Named starter-template poisoning is researcher- and
community-demonstrated and thin in public advisories — treat that specific vector as
demonstrated, not advisory-quantified.

---

## Class 2 — repository destruction by automation

**What it is.** An automated agent or script with GitHub credentials can **delete, rename,
transfer, privatize, or archive** repositories. When that fires by accident or through a
hijacked automation, it can erase a project's history and its accumulated stars and forks
in a single command. This is not a code-execution bug — it is over-broad authority meeting
an irreversible operation.

**The motivating incident.** An automation performed destructive repo-lifecycle operations
across public repositories and wiped out thousands of accumulated stars before a human
could intervene. GitHub's own docs are explicit that some of this is not cleanly
recoverable: a rename/transfer breaks existing links, and deleting a repo removes its
issues, stars, and forks.

**The defense.** Make repo-*level* destruction require an explicit, per-repo human
confirmation — turning a one-command catastrophe into a deliberate act — while leaving all
normal, non-destructive usage untouched. That is exactly the scope boundary the repo-guard
draws: it blocks delete/rename/transfer/privatize/archive and passes everything else
through unchanged. See `coverage-and-limits.md` for the precise block list, the honest
bypass matrix, and what it deliberately does **not** cover.

**Why "confirm the exact repo" and not "confirm any destruction".** A blanket "are you
sure?" trains reflexive approval. Binding the override to the **specific** `owner/repo`
being destroyed means a mis-targeted automation cannot satisfy the prompt for the wrong
repository — the confirmation has to name the same repo the command will hit.

---

## Class 3 — unsafe research egress

**What it is.** An agent doing research decides what to open. Left ungated it will click
every search result, follow in-page links, open PDFs and archives from unknown hosts, and
retrieve files whose only purpose is to be executed. The URL is the last point where a
cheap, deterministic decision is still possible: after the fetch, the content is already
in context and the only remaining defence is how the agent treats it.

**Why the URL and not the content.** Content inspection happens after retrieval. Retrieval
is itself the risky act for an executable, an archive, a `file:` read, or a `javascript:`
scheme — and for a URL carrying credentials in its userinfo, the request leaks them
whatever the response says. A URL classifier is strictly cheaper and strictly earlier.

**What this ships.** `check-url.sh` classifies from URL shape alone, with no network call,
and `research-egress-install.sh` wires it as a PreToolUse gate so the decision runs before
the fetch tool or `curl`/`wget` executes. `BLOCK` is unconditional; `REVIEW` requires an
explicit operator token naming the exact URL.

**The honest boundary.** Shape is not reputation. A compromised well-known domain serving a
poisoned page classifies as `ALLOW`, correctly and uselessly. The hook only covers the tools
its matcher names. And the behavioural half — prefer primary sources, cap fetches per
question, do not spray-click — is a discipline no hook enforces. See `safe-research.md`.

---

## Class 4 — an implant already running on the host

**What it is.** Malware that arrives outside every gate. It is not committed to a
repository, so a repository scanner never sees it. It does not pass through an agent tool
call, so a tool hook never sees it. It is delivered by something that already runs code on
the machine — a package lifecycle script, a build step, a headless worker — and then it
detaches, its parent exits, and it beacons.

**Why gate-based controls cannot see it.** This is the structural point, and it is the
reason this class is in the threat model at all. Every other control in this project sits
on a path: content entering a repository, content entering an agent's context, a command
about to run. A control on a path only sees what takes the path. A command-line implant
ran for four and a half days on a machine where every one of those controls was installed
and reporting healthy — and each of those reports was true. They were answering "are my
gates wired?", and nobody was asking "is something already running?".

**What this ships.** `runtime-audit.sh`: inline-eval interpreter processes, dropper markers
co-occurring in one command line, orphaned PPID-1 interpreters, and autostart + shell
profile drift against a recorded baseline.

**The honest boundary.** It reads command lines, so an implant that execs from a file or
rewrites its `argv` is invisible. It is point-in-time and nothing schedules it. A baseline
first recorded after an infection treats the infection as normal. It is not EDR — no memory
inspection, no signing checks, no flow analysis. It is a tripwire for a known shape, and
the four-and-a-half-day gap is the honest measure of what a manual, point-in-time check
costs.

---

## The generalization

The dropper is `base64` + `eval` + `.env` + `config` + `template` — one cell. Detection has
to generalize on all five axes at once (encoder, sink, carrier, hiding spot, delivery). The
repo-destruction class is simpler but sharper: bound the blast radius of irreversible
authority with a per-target human gate. Egress is earlier and cheaper than either: decide
before you fetch, because after you fetch the decision is already made.

The fourth class generalizes differently, and it is the one worth carrying away. Classes 1
through 3 are all controls **on a path** — and a control on a path is blind to anything that
does not take the path. Adding more path-controls never closes that gap; it only makes the
green report more convincing. The only way to see the fourth class is to stop asking whether
the gates are wired and start looking at the machine itself.

This skill ships a Tier-1 answer to each and a complete program to none. Read
`coverage-and-limits.md` before you rely on any of it.
