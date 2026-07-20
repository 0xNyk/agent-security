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

## Maintainer notebook

When a detector changes, record four facts in the pull request:

1. The observed malicious or leak shape.
2. A positive fixture that the rule catches.
3. A neighboring benign fixture that remains clean.
4. The first known evasion or scope boundary.

If the fourth item is unknown, say so. Do not substitute confidence for evidence.
