# Contributing

Contributions should make a defensive boundary easier to inspect, test, or enforce.

## Ground rules

- **Defensive only.** This project detects and blocks attacks. Contributions that
  add offensive tooling, evasion techniques, or ways to *bypass* detection without
  a corresponding defense will be declined.
- **No overclaiming.** Every detection or protection must state its boundary. If a
  new rule has a known gap, document it in `references/coverage-and-limits.md` in
  the same PR. A security tool that overclaims is worse than none.
- **No real data, ever.** Fixtures use synthetic/placeholder values only. Never
  commit a real secret, path, private name, or marker. CI runs the self-scan; keep
  it green.

## Before you open a PR

```bash
bash tests/run-all.sh            # every tests/test-*.sh, plus the repo self-scan
```

Every suite must pass; CI runs this exact command. `run-all.sh` discovers suites from
disk rather than a list, so a new `tests/test-*.sh` is picked up automatically — you do
not need to register it anywhere. If you add a detection class, add both a positive
fixture (it fires) and a negative fixture (it does not false-positive).

Also run:

```bash
shellcheck -S warning scripts/*.sh scripts/repo-guard/*.sh tests/*.sh
gitleaks git --no-banner --redact .
```

By submitting a contribution, you agree that it may be distributed under this
repository's MIT License and that you have the right to submit it. AI-assisted work is
accepted under the same standard as any other contribution: you remain responsible for
its provenance, correctness, and reviewability. Do not add generated code or assets whose
license or source cannot be explained.

## Reporting a vulnerability

See `SECURITY.md`. Report bypasses **privately**, not in a public issue.
