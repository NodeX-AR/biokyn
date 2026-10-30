# BioKyn 0.3.2 patch notes

## Applied
- Restored DC steady-state filter initialization to avoid injecting large coordinate-boundary transients.
- `trustProxy` now accepts `boolean | number`; numeric values select a forwarded hop from the right. IP quota grouping expands IPv6, canonicalizes IPv4-mapped IPv6, and groups native IPv6 by /64.
- WebAuthn step-up is opt-in and defaults to disabled. Tests explicitly enable it when testing the positive path and cover default refusal.
- Replaced issuance-transcript redemption tokens with a compact `{ challengeDigest, input, tag }` format. The client verifies the issuance DLEQ proof, unblinds locally, and sends no blinded/evaluated point or issuance proof to `/siteverify`.
- Added success-only `/siteverify` idempotency cache and in-process coalescing for retries using the same origin/key.
- Added speed coefficient-of-variation to the canonical kinematic evidence encoding and reject flags for near-constant-speed strokes.
- Preserved the 0.3.1 parameter and store validation guards.

## Known release gates
- npm dependency installation timed out in this environment, so no successful full build/typecheck/test run is claimed.
- Idempotency cache is process-local; multi-instance deployments need a shared atomic idempotency store to guarantee cross-node retries.
- The OPRF flow now has blind issuance and client unblinding, but RFC 9497 vector conformance and independent cryptographic review are still required. Do not claim RFC certification or deploy as the sole security boundary until those gates pass.
- The kinematic wire encoding changes; deploy client and server together.
