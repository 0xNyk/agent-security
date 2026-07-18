# Contributing

Thanks for helping make agent supply-chain security a little more boring.

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
bash tests/test-scan.sh          # leak/dropper scanner fixtures
bash tests/test-vet.sh           # inbound vetting fixtures (poisoned template -> REJECT)
bash tests/test-harden.sh        # harden-check scope-parsing (mock gh auth status, offline)
bash tests/test-scan-content.sh  # untrusted-content tripwire fixtures
bash tests/test-guard.sh         # guard, offline fake gh
bash tests/self-scan.sh          # this repo must be clean under its own scanner
```

All six must pass (CI runs the same set). If you add a detection class, add both a
positive fixture (it fires) and a negative fixture (it does not false-positive).

## Reporting a vulnerability

See `SECURITY.md` — report bypasses **privately**, not in a public issue.
