# BioKyn 0.4.0-rc.1 — status

**Release candidate. Not production-certified.** This release closes the engineering items from the 0.3.6-rc.3 blocker list and
adds the tooling for the items that need outside evidence. Four gates cannot be closed by code and remain open (see the last section).

## What changed

| Area | 0.3.6-rc.3 | 0.4.0-rc.1 |
|---|---|---|
| OPRF / DLEQ | custom construction; `HashToScalar` used the wrong byte order (non-conformant) | RFC 9497 VOPRF(ristretto255, SHA-512), mode 0x01, spec-exact transcripts; KATs + official-vector CI gate |
| Token privacy | issuance echoed blinded/evaluated points; ad-hoc redemption tag; no key pinning | Privacy-Pass-style v2 token (162 B), key ids, key ring for rotation, nothing but `evaluated‖proof` leaves the issuer — see [PRIVACY.md](PRIVACY.md) |
| Motion / kinematics | browser-reported kinematics alone could mint a token | **advisory only**: evidence can deny, never grant; PoW (or registered WebAuthn) required for every token; motion endpoint returns no verdict |
| WebAuthn | step-up needed pre-registered credentials; no registration | full registration ceremony (attestation `none`, PoW-gated, challenge-bound), credential store (memory/Redis), expiry, revocation, signature-counter clone detection |
| Redis | untested; keys not cluster-safe; unbounded command latency | hash-tagged keys, per-command timeout, every failure → `StoreUnavailableError` → HTTP 503 (fail closed); real-Redis integration suite |
| Proxy / rate limit | integrator's problem | `createClientIpResolver` (trusted-proxy aware), IPv6 /64 bucketing, route-aware `createRateLimiter` |
| Build | no lockfile; `@noble` 1.x pinned while code used the 2.x API; `dist/` shipped | noble 2.x everywhere via one import point; lockfile gate in CI; `dist/` excluded |
| Tests | never executed end-to-end (several failing/contradictory) | 237 tests executed against real noble 2.4.0 and real Argon2id (+ Redis suite, not yet run); fuzz/property suites; mutation-checked security logic |

Findings made while executing the suite for the first time are in [AUDIT_0.4.0-rc.1.md](AUDIT_0.4.0-rc.1.md).

## Verification matrix — read this before trusting any green checkmark

| Claim | How it was verified | Where it still has to be verified |
|---|---|---|
| Group arithmetic, hash-to-group, DeriveKeyPair, Finalize match RFC 9496/9497 | KAT values reproduced by an independent Python reference *and* matching published values (generator, 2G, map vector, OPRF vector 1, VOPRF keys) | `npm run test:vectors` against the **official** appendix (needs network; CI hard gate) |
| DLEQ proof bytes | TypeScript output identical to independent Python implementation (same author, same spec reading) | official VOPRF vectors (same CI gate); **independent cryptographic review** |
| All protocol/server/client logic | executed: 235 tests (217 protocol+server+client, 15 core, 3 script), repeated runs, 3 fuzz seeds | CI on real `vitest` (see below) |
| Types | `tsc` 6.0.3 strict, 0 errors, using ambient stubs for Node/noble | real `npm run typecheck` with `@types/node` and real noble |
| noble API (`ristretto255` hash-to-curve, `.js` import paths, `Fn.ORDER`) | **verified against real `@noble/curves` 2.4.0 / `@noble/hashes` 2.4.0**: full suite passes, and `noble-interop.test.ts` shows my VOPRF interoperates with noble's own `ristretto255_oprf` in both directions (keys, proofs, PRF outputs) | re-run on any noble upgrade (Dependabot groups `@noble/*`) |
| Redis behaviour (races, lock crash, lease renewal, stall, reload) | tests written; **never run** against a real Redis | `npm run test:redis` / CI `redis` job (hard gate) |
| Redis failover (Sentinel/Cluster) | not tested | manual drill in [DEPLOYMENT.md](DEPLOYMENT.md#failover-drill) |
| Production build, `npm ci`, lockfile, `npm audit` | not run (no registry access in the build environment) | CI |

## Gates that code cannot close

1. Independent cryptographic review of the VOPRF integration and the v2 token design.
2. Third-party penetration test.
3. Accessibility study with assistive-technology users (a motion-free path exists; it has not been user-tested).
4. False-positive / detection measurement on representative traffic (tooling: `npm run eval:kinematics`).

Until those are evidenced, keep BioKyn in monitor/shadow mode or as one signal among several, never as the sole control for
sensitive actions. No bot-blocking percentage is claimed. The kinematic judge is known to accept some synthetic bot profiles
(documented in `packages/protocol/test/kinematics.test.ts`); that is safe only because kinematics is advisory.
