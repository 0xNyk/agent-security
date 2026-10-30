# Releasing

This project is defensive tooling. The release gate is **proof that the repo is clean**,
not a version bump. Run every step from the repo root before publishing.

## Pre-publish checklist

1. **Version consistency:** `SKILL.md` frontmatter `version` matches the target tag and
   the top `CHANGELOG.md` entry.
2. **Sanitization gate (blocker):** the repo must be clean under its own scanner:
   ```sh
   bash tests/self-scan.sh        # must print CLEAN
   ```
   Only inert defensive-example / fixture / taxonomy lines may remain, and each must be
   covered by a documented `--allow` in `tests/self-scan.sh`. No secrets, no absolute
   paths, no real org/repo/person names, no private markers.
3. **All test suites green:**
   ```sh
   bash tests/run-all.sh
   ```
4. **CI mirrors the above:** `.github/workflows/ci.yml` runs `tests/run-all.sh` offline,
   with GitHub Actions pinned to full commit SHAs. The runner discovers suites from disk,
   so the release check and CI cannot drift apart from the suites that actually exist.
5. **Private-context sweep (the scanner cannot do this one for you):** the `PATH` rules
   match personal paths *by shape*. They cannot know which **names** are private to you —
   a sibling private repository, an internal host, a codename — so grep for your own
   before every release:
   ```sh
   git ls-files -z | xargs -0 grep -nIE 'your-private-repo-names|internal-host-names'
   ```
   This step exists because it caught two real leaks that the shape rules did not: a
   private sibling repository named in a fallback path, and a personal workspace layout
   in an installer. Configure `private-markers.txt` so the marker layer catches these
   mechanically next time, and keep the grep as a backstop.
6. **Independent secret-history scan:**
   ```sh
   gitleaks git --no-banner --redact .
   ```
   Review every allowlist entry. An allowlist needs an exact commit, path, value shape,
   and written reason proving the material is synthetic.
7. **Repository metadata check:** inspect commit author/committer identities, image
   metadata, remotes, issue links, and release artifacts. Confirm every published identity
   and contact route is intentional.

## Publish

```sh
# create the repo (operator action), set origin, then:
bash tests/run-all.sh                   # every suite + self-scan; must be ALL TESTS PASSED
git push -u origin main
git tag -s v0.3.0 -m "agent-security 0.3.0"
git push origin v0.3.0
```

Never publish a build where the self-scan is not CLEAN or any suite is red.
