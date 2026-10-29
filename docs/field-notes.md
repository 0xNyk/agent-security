# Field notes

These notes record the engineering judgments behind `agent-security`. They are operational commentary, not additional guarantees.

## A clean scan is a bounded statement

The scanners answer a narrow question: did the selected files match a known, reviewable pattern? They do not answer whether a repository is trustworthy.

That wording matters. Regex can identify a private-key block or an encoder beside an execution sink. It cannot establish provenance, intent, or a cross-file data flow. The scripts therefore print both the finding and the residual risk.

## The outbound and inbound paths stay separate

`scan-repo.sh` examines material a maintainer is about to publish. `vet-incoming.sh` examines material a maintainer may adopt. The commands share pattern logic but have different decisions:

- Outbound findings protect the public boundary and normally block publication.
- Inbound findings protect the workstation boundary and return ADOPT, REVIEW, or REJECT.
- The inbound path never installs dependencies, runs lifecycle scripts, or executes the candidate.

Combining the commands would blur authority. A publish gate should not clone arbitrary URLs, and a vetting tool should not assume the candidate belongs to the current Git history.

## Fixtures must look dangerous without being dangerous

Tests need representative syntax, including decode-to-exec shapes. Those strings are created inside temporary directories and never executed. Credential-like high-entropy values are assembled at test runtime so generic history scanners do not mistake a tracked fixture for a live secret.

Repository self-scan exceptions live in `tests/self-scan.sh`. Each exception names one defensive documentation or fixture line. Broad directory exclusions are not accepted because they create quiet blind spots.

## Three states beat a false green

`harden-check.sh` reports OK, HIGH, or UNKNOWN for token capability. A locked keychain, fine-grained token, or unavailable authentication context can prevent inspection. Earlier designs often collapse that case into a warning while returning success; this project exits with a distinct degraded state instead.

## Local brakes are still useful

The repository guard cannot enforce GitHub policy. It can interrupt the common path where an agent calls `gh` through `PATH`, and the optional hook can inspect absolute-path calls inside a supported host. That buys a human decision point.

The durable controls remain outside this repository:

- remove repository deletion permission from automation credentials;
- restrict deletion and transfer at the organization level;
- protect important branches from force-push and deletion;
- keep recovery authority separate from routine automation.

## A control on a path is blind to whatever avoids the path

The first release shipped five gates and each one sat on a route: content entering a
repository, content entering an agent's context, a command about to run. That framing has
a hole with a precise shape. Anything delivered by something already executing on the
machine takes none of those routes, so no gate has an opinion about it, and every gate
still reports healthy. The reports are not wrong. They answer "are the gates wired",
which is a different question from "is something already running".

Adding a sixth gate would not have closed this. The fix had to look at the host instead,
which is why `runtime-audit` reads the process table rather than a stream.

## Precision is a security property, not housekeeping

The first version of the runtime audit matched one regular expression across an entire
command line. It reported a development server as an implant, because a `-p 3011` port
flag belonging to a package manager looked exactly like the interpreter's own print-eval
flag. The detection now walks tokens and stops at the script path, since every flag after
it belongs to the script.

This mattered more than the usual false-positive complaint. The audit was about to be
scheduled hourly. A tool that reports the same harmless process every hour trains its
reader to skim, then to filter, then to switch it off, and a disabled detector detects
nothing. Noise is not a cosmetic failure in a scheduled control; it is the failure.

## Scheduling is what turns a script into a control

A point-in-time check whose trigger is "someone decides to look" inherits the failure
mode of whatever it was written to catch. Writing the detector feels like closing the
incident, and it is not: detection and eradication are separate steps, and so are
detection and *recurring* detection. `runtime-audit-install.sh` exists so the trigger is
a timer rather than a memory.

Its `--status` reads the interval back out of the installed scheduler entry instead of
restating what was typed at install time. A status line that cannot tell a 30-minute
cadence from a 60-minute one is decoration.

## Agent configs are the new autostart

Every 2026 worm that reached this project's indicator list persisted somewhere a developer
does not read: a `setup.mjs` under `.claude/` or `.vscode/`, a `folderOpen` task, a
`SessionStart` hook, an MCP server entry whose command fetches and executes. These files
are autostart for agents the way plists and cron are autostart for the OS, and they were
being treated as preferences. The sweep now hashes the home agent configs and reads the
`hooks` object of every repository agent config, which is the same baseline-and-drift
model `runtime` applies to launchd.

The precision lesson repeated itself. The first version read whole settings files and
flagged permission allowlists that merely named `curl`; a permission to run a command is
not a hook that runs it. Reading only the `hooks` object removed every false positive and
lost no true one.

## A list is honest about being a list

The indicator sweep is the least clever control here and the one most likely to fire
first, because the campaigns it covers reuse paths and filenames across months. Its
weakness is stated in its name: it catches what has been published. The reason to ship it
anyway is that the alternative, waiting until the loader is a running process, is the
four-and-a-half-day gap again. Append to the list when a report lands; do not wait for
the sweep to learn.

## The scanner cannot know which names are private

Path rules match personal directories by shape, so they caught a literal home path and
missed a home-relative workspace root followed by a repository name. Two real leaks
reached the release candidate through exactly that gap:
a fallback path naming a private sibling repository, and a personal workspace layout in an
installer. The shape rule now covers workspace roots, but the general case is unfixable by
shape alone, because privacy is a fact about your context rather than about the string.
That is what the marker file is for, and the release checklist now carries an explicit
grep step described as the step the tooling cannot do for you.

## Maintainer notebook

When a detector changes, record four facts in the pull request:

1. The observed malicious or leak shape.
2. A positive fixture that the rule catches.
3. A neighboring benign fixture that remains clean.
4. The first known evasion or scope boundary.

If the fourth item is unknown, say so. Do not substitute confidence for evidence.
