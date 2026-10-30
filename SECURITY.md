# Security Policy

## Supported versions

Security fixes are released for the latest published version of each `@biokyn/*` package. Please upgrade to the newest release before reporting.

## Reporting a vulnerability

Please report privately through GitHub: **[Report a vulnerability](https://github.com/biokyn/biokyn/security/advisories/new)**. Do not open public issues for security problems.

Include affected package and version, impact, and reproduction steps or a proof of concept.

**What to expect**

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment | within 7 days |
| Fix or mitigation plan for confirmed issues | within 30 days (critical issues sooner) |
| Coordinated disclosure | advisory and CVE published with the fix; reporters credited unless they prefer otherwise |

We follow coordinated disclosure and ask for a reasonable window to ship a fix before details are public. Good-faith research under this policy is welcome and will not be pursued legally.

## Scope

In scope: all packages in this repository, the token format, the VOPRF and DLEQ implementation, WebAuthn handling, adapters and stores. Design documentation: [docs/SECURITY.md](docs/SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Release integrity

npm releases are published from GitHub Actions with provenance attestations and an SBOM attached to each GitHub release. See [docs/RELEASING.md](docs/RELEASING.md).
