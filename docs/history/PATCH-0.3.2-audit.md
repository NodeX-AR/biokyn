# BioKyn 0.3.2 audit patch

This patch addresses the reported runtime, security, and business-logic defects while retaining the existing validation guards.

## Changes

- `packages/server/test/helpers.ts`: pass the challenge redemption context in its base64url string form to `beginIssuance`.
- `packages/server/src/webauthn.ts`: pass the actual typed-array views to Web Crypto rather than their entire backing buffers.
- `packages/core/src/middleware.ts`: evaluate explicitly trusted forwarded IP data before framework `req.ip`; retain the direct peer fallback when proxy trust is disabled.
- `packages/server/src/verifier.ts`: reject the Ristretto identity point on issuance.
- `packages/client/src/liveness.ts`: remove the client-only `no_input_cause` penalty for virtual/assistive input.
- `packages/server/src/siteverify.ts`: bind idempotency cache/in-flight keys to SHA-256 of the response and cap the per-verifier cache at 10,000 entries, evicting oldest entries after expiry cleanup.
- `packages/core/src/store.ts`: perform an inline expiry sweep before refusing new keys at capacity.
- `packages/client/src/step-up.ts`: measure gesture duration from pointer-down rather than modal-open time.
- `packages/protocol/src/kinematics.ts`: include `constant-speed` in session-level rejection reasons.
- `packages/server/src/http.ts` and `packages/server/src/middleware/express.ts`: pass the framework/socket peer IP into the framework-neutral request object.
- `packages/protocol/src/ristretto/oprf.ts`: use the exported `ORDER` constant directly.

## Verification

`npm test` was attempted. It stops before compilation because the environment is missing the `@types/node` type definitions (`TS2688: Cannot find type definition file for 'node'`). Install the repository's declared dependencies and rerun `npm test` / `npm run check` before release.
