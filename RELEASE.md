# Releasing

This project is defensive tooling — the release gate is **proof that the repo is clean**,
not a version bump. Run every step from the repo root before publishing.

## Pre-publish checklist

1. **Version consistency** — `SKILL.md` frontmatter `version` matches the target tag and
   the top `CHANGELOG.md` entry.
2. **Sanitization gate (blocker)** — the repo must be clean under its own scanner:
   ```sh
   bash tests/self-scan.sh        # must print CLEAN
   ```
   Only inert defensive-example / fixture / taxonomy lines may remain, and each must be
   covered by a documented `--allow` in `tests/self-scan.sh`. No secrets, no absolute
   paths, no real org/repo/person names, no private markers.
3. **All test suites green:**
   ```sh
   for t in test-scan test-vet test-harden test-scan-content test-guard self-scan; do
     bash "tests/$t.sh" || { echo "FAILED: $t"; exit 1; }
   done
   ```
4. **CI mirrors the above** — `.github/workflows/ci.yml` runs all six suites offline,
   with GitHub Actions pinned to full commit SHAs.

## Publish

```sh
# create the repo (operator action), set origin, then:
bash tests/self-scan.sh                 # re-run from root — must be CLEAN
for t in test-scan test-vet test-harden test-scan-content test-guard self-scan; do
  bash "tests/$t.sh" || exit 1
done
git push -u origin main
git tag -s v0.1.0 -m "agent-security 0.1.0"
git push origin v0.1.0
```

Never publish a build where the self-scan is not CLEAN or any suite is red.
