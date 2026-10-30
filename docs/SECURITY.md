# Security model

BioKyn is built on one rule: **only server-verifiable work grants trust.**

## Evidence hierarchy

| Evidence | Role |
|---|---|
| Argon2id proof-of-work bound to the request | Grants a token |
| WebAuthn assertion from a credential this server registered (counter-checked) | Grants a token |
| Kinematics, tamper flags, motion telemetry | Advisory: can deny or be logged, never grants |

`kinematicsPolicy: 'unsafe-client-gate'` exists for legacy migration and is refused in production unless `acknowledgeUnsafeKinematicsGate` is set.

## Recommended practice

- **Calibrate before enforcing.** Kinematic thresholds are engineering defaults. Collect captures for mouse, touch and pen at the polling rates you serve ([EVALUATION.md](EVALUATION.md)).
- **Prefer step-up to hard blocking.** Route `ambiguous` evidence to the inclusive Argon2id lane or WebAuthn step-up, which keeps keyboard-only and assistive-technology users included.
- **Share secrets across nodes.** All verifier instances in a deployment share the VOPRF and challenge secrets and use shared nullifier, rate-limit and idempotency stores (Redis).
- **Measure on your own traffic.** Report false-positive and false-negative rates with confidence intervals; no universal blocking rate is asserted.

## Cryptography

- VOPRF: RFC 9497 ristretto255-SHA512, checked against the official vectors in CI.
- DLEQ proofs are bound to a server-derived `(issuer, origin, redemption epoch)` digest.
- Token v2 carries key ids and supports key rings for rotation. Token design and linkability analysis: [PRIVACY.md](PRIVACY.md).
- Constant-time comparisons for secrets; zero scalars rejected; CBOR and body size limits enforced.

## WebAuthn

Only credentials registered by this server are accepted, with signature counter checks. Anonymous registration accepts attestation `none`, costs proof-of-work, expires (default 7 days) and is revocable. The lane is a returning-visitor convenience that proves control of a key.

## Reliability

- **Fail closed.** Any shared-store error or timeout returns 503; nothing is issued or accepted without shared state.
- The in-memory store throws `StoreCapacityError` at capacity (HTTP 503 `store_unavailable`). Use bounded shared stores in production and alert on 503s.
- The process refuses to start with `NODE_ENV=production` without shared stores, HTTPS origins and a rate limiter.

## Reporting vulnerabilities

See the root [SECURITY.md](../SECURITY.md).
