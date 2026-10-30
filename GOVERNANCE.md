# Governance

BioKyn is an open source project under the Apache-2.0 license. This document describes how decisions are made.

## Roles

- **Users and contributors**: anyone who uses BioKyn, files issues, improves docs or submits pull requests.
- **Committers**: contributors with merge rights, invited by maintainers after sustained, high-quality contributions.
- **Maintainers**: listed in [MAINTAINERS.md](MAINTAINERS.md). They review and merge changes, cut releases, triage security reports and steward the roadmap.

## Decision making

1. Day-to-day changes are decided through pull request review. One maintainer approval is required; changes to cryptography, token format, wire protocol or security policy require review from a maintainer who is not the author.
2. Larger or breaking changes start as a GitHub Discussion or issue with a written proposal. Maintainers aim for consensus; if none emerges after reasonable discussion, a simple majority of maintainers decides, and the project lead breaks ties.
3. Decisions and rationale are recorded in the public issue or pull request.

## Becoming a committer or maintainer

Sustained, constructive contributions over several months, adherence to the [Code of Conduct](CODE_OF_CONDUCT.md), and a nomination by an existing maintainer. Maintainers may step down at any time; inactive maintainers (12 months) are moved to emeritus status.

## Principles

Privacy first (no tracking or fingerprinting), server-verifiable trust, accessibility for all users, and free software with no paid tiers.

## Conflict resolution and conduct

Conduct issues are handled under the [Code of Conduct](CODE_OF_CONDUCT.md). Disagreements on technical direction follow the decision process above.

## Continuity

All project assets (repository, npm scope, CI secrets) are held by the `biokyn` GitHub organization. At least two maintainers should hold admin access to the organization and the npm scope so the project can continue if one is unavailable.

## Amending this document

Via pull request, approved by a majority of maintainers.
