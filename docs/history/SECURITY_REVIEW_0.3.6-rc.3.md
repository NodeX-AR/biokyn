# BioKyn 0.3.6-rc.3 security review status

This archive incorporates a static hardening pass over the supplied project. It is **not a completed security audit and is not certified production-ready**.

## Improvements included

- Package metadata is consistently versioned `0.3.6-rc.3`.
- TypeScript package output roots and npm workspace dependency declarations were corrected in this snapshot.
- Added asynchronous PoW verification and raised default difficulty to 8 bits; PoW is only a cost-raising control.
- Added context-bound proof checks and client-side proof verification to the experimental OPRF path.
- Separated attempt accounting from replay/nullifier capacity and bounded in-memory maps.
- Production server configuration requires an explicitly injected shared atomic nullifier store.
- Tightened site secret/origin validation and request-body handling.
- Added an opt-in motion UI, which is documented as non-authoritative client evidence.

## Unresolved release blockers

1. The custom OPRF/DLEQ implementation is not RFC 9497 conformant. Use a maintained implementation with official known-answer vectors; do not claim conformance for this code.
2. Issuance/redemption unlinkability is not provided by the current token format.
3. The motion step-up UI is not yet bound to a server-verifiable, single-use challenge result.
4. Durable idempotent redemption is not fully implemented.
5. The liveness evidence and risk thresholds are not calibrated on representative real traffic or adversarial datasets.
6. Full dependency installation, typecheck, tests, and build could not be completed in the offline environment.
7. No independent cryptographic review, penetration test, or 99.99% bot-blocking measurement has been performed.

Until all release gates in `docs/RELEASE_GATES.md` pass, use BioKyn only in development or shadow/monitor mode, not as the sole protection for sensitive endpoints.


## Additional server-side hardening in this archive

- Added `RedisSecurityStore`, using Redis `SET NX PX` for replay prevention and Lua scripts for atomic challenge-attempt and sliding-window rate-limit decisions. The adapter is ioredis-compatible and requires a shared Redis deployment configured with TLS/authentication, restricted network access, no-eviction capacity planning, monitoring, and fail-closed handling.
- Production verifier construction now requires shared nullifier and attempt stores. Production HTTP handler construction requires a rate-limit callback. Request body size checks use UTF-8 byte length rather than JavaScript string length.
- These changes close several state/rate-limit gaps but do not resolve the custom OPRF conformance blocker, durable Siteverify idempotency, or the need for independent security review and production load testing.


## Follow-up status

The release candidate adds shared Redis-backed siteverify idempotency and server-side validation of challenge-bound motion telemetry. The motion result remains forgeable risk telemetry, not authentication. Independent review and full CI remain mandatory; this is not certified production-ready.
