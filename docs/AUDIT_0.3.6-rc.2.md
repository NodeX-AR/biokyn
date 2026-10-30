> **Historical document (0.3.x).** Superseded where it conflicts with [STATUS.md](STATUS.md) for 0.4.0-rc.1.

# BioKyn 0.3.6-rc.2 — audit follow-up status

This release candidate addresses the reproducible logic issues listed in the follow-up review. It is **not production-certified**.

## Changes made

- **Replay retention:** `BioKynVerifier` configures in-memory nullifiers and each token nullifier insertion for `3 * tokenEpochMs + 60_000`, matching the accepted current plus two previous redemption contexts. `RedisSecurityStore` default TTL is now 16 minutes for a 5-minute epoch; per-insertion TTL remains authoritative.
- **Siteverify cache key:** response hash and full cache key are computed before the capacity check. The cache performs no more than one eviction per request rather than a `while` loop.
- **Early form submit:** client script retries challenge readiness at most 50 times (about five seconds) and displays a timeout message rather than polling forever. It intentionally does not silently submit without a token.
- **Attempt-store capacity:** `MemoryChallengeAttemptStore` throws `StoreCapacityError` at capacity; verifier maps this to `503 store_unavailable`, not `429 challenge_exhausted`.
- **Motion telemetry:** `runMotionStepUp` can POST its metrics to `/biokyn/motion-step-up` with `challengeId`. Client `passed` and `score` are not sent. Server output is labelled `client-untrusted`. This is intentionally not connected as a token-issuance authorization factor because browser telemetry can be fabricated; applications must not use it alone to authorize an action.
- **Anonymous WebAuthn:** not changed into a fake anonymous flow. WebAuthn assertions require a previously registered credential/public key. Sites that need anonymous visitors must use other challenge lanes or implement a proper credential-registration and account/session-binding flow.
- **Liveness parity:** added the missing non-negative deceleration check to client implementation.
- **Host fallback:** `POST /issue` can use the Host header only when it exactly maps to a preconfigured site origin and both Origin and Referer are absent.
- **Semaphore queue:** requests aborted while waiting for the PoW semaphore are removed from the queue. Once Argon2id work has started, it cannot be reliably interrupted by this adapter.

## Validation limits

- ZIP integrity and source/compiled JavaScript syntax checks are suitable local checks.
- Full TypeScript typecheck and full test suite were **not successful / not run to completion** because dependencies could not be installed in this environment.
- Redis concurrency/failover behavior requires integration testing against a real Redis instance.
- No independent cryptographic review, penetration test, load test, or deployment-specific verification was performed.

## Required before production

1. Run `npm ci`, `npm run check`, and all integration tests in clean CI.
2. Test Redis idempotency races, lock expiry, process crashes, failover, and cache eviction across multiple server instances.
3. Add end-to-end replay tests across epoch boundaries with fake time and verify nullifier retention on both Redis and memory stores.
4. Review challenge/token lifetime semantics and VOPRF implementation against the intended protocol specification.
5. Run independent application and cryptographic security reviews and document deployment controls.
