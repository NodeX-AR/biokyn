# BioKyn 0.4.0-rc.1 — release gates

Legend: ✅ done and executed · 🟡 implemented, needs the named external run · ⛔ requires people/traffic outside this repository.

## Engineering gates

- ✅ RFC 9497 VOPRF replaces the custom OPRF/DLEQ. 🟡 Official vectors: `npm run vectors:fetch && npm run test:vectors` (CI hard gate, `REQUIRE_OFFICIAL_VECTORS=1`).
- ✅ Token redesign (v2) — unlinkability argument and residual risks in [PRIVACY.md](PRIVACY.md). ⛔ Independent review.
- ✅ Atomic cross-instance redemption/idempotency semantics; fail-closed on any store failure. 🟡 Verified against real Redis only by `npm run test:redis` (CI `redis` job).
- ✅ Server-verifiable step-ups only: PoW, or registered-credential WebAuthn with counter checks. Motion output is a signal sink with no verdict.
- ✅ Anonymous WebAuthn registration ceremony (attestation `none`; limits documented in [SECURITY.md](SECURITY.md)).
- ✅ Trusted-proxy resolution, IP normalization, route-aware rate limiter, bounded parsing, shared route matcher. 🟡 `npm run load` against staging with the production Redis topology.
- 🟡 Clean `npm ci` → typecheck → test → build on Node 20/22 (workflow in `.github/workflows/ci.yml`). **Commit `package-lock.json`** (`npm install`, review, commit); `npm run check:lockfile` blocks CI without it.
- ✅ Fuzz/property tests (seeded, dependency-free). ✅ CodeQL workflow. ✅ Dependabot. ⛔ Third-party penetration test.
- ✅ Attack-corpus *tooling* (`eval-kinematics`, synthetic generators). ⛔ Representative corpus and measured rates with confidence intervals ([EVALUATION.md](EVALUATION.md)).
- ✅ Security policy, incident response, data retention, deployment hardening, threat model: [SECURITY.md](SECURITY.md), [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md), [DATA_RETENTION.md](DATA_RETENTION.md), [DEPLOYMENT.md](DEPLOYMENT.md), [THREAT_MODEL.md](THREAT_MODEL.md).

## Evidence gates (must be attached to the release before "production" wording is used)

- [ ] CI run link: `verify` (Node 20, 22) and `redis` (6.2, 7.4) green, including official vectors.
- [ ] Committed lockfile; `npm audit --omit=dev` clean at high severity.
- [ ] Failover drill record (DEPLOYMENT.md) for the chosen Redis topology.
- [ ] Load-test report for `/challenge`, `/issue`, `/siteverify` at target peak × 2.
- [ ] Independent cryptographic review report; all findings closed or risk-accepted in writing.
- [ ] Penetration-test report; same.
- [ ] Accessibility study report ([ACCESSIBILITY.md](ACCESSIBILITY.md)); every blocker closed.
- [ ] Measured human false-positive rate per cohort with upper 95% bound ≤ the policy target (`npm run eval:kinematics`).
- [ ] Deployment-specific threat-model sign-off.

Passing local checks is not certification. Do not describe this software as production-certified until every box above is checked by qualified reviewers.
