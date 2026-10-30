# Releasing

Releases are cut by maintainers from `main` and published by GitHub Actions.

1. Ensure CI is green and `CHANGELOG.md` is updated.
2. Bump versions in `packages/*/package.json` (semver) and run `npm install` to refresh the lockfile.
3. Create a GitHub Release with tag `vX.Y.Z` (pre-releases use a `-rc.N` suffix and publish under the `next` dist-tag).
4. The `release` workflow runs the full check, publishes every `@biokyn/*` package to npm with **provenance** (`npm publish --provenance`), generates a CycloneDX SBOM and attaches it to the release.
5. Verify the provenance badge on npmjs.com and announce in Discussions.

Requirements: repository secret `NPM_TOKEN` (automation token scoped to `@biokyn`), 2FA enabled for all maintainers on GitHub and npm.

## Security fixes
Developed in a private advisory fork, released with a GitHub Security Advisory and CVE where applicable.
