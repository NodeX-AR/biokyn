> **Historical document (0.3.x).** Superseded where it conflicts with [STATUS.md](STATUS.md) for 0.4.0-rc.1.

# BioKyn 0.3.6-rc.3 — audit follow-up

## Implemented in this archive

- Retains the rc.2 fixes: replay-window TTL alignment, bounded client retries, siteverify cache-key correction, capacity errors mapped to unavailable, liveness parity, configured Host fallback, cancellation of queued PoW requests, and motion telemetry explicitly marked untrusted.
- Redis siteverify idempotency now renews its lock lease during long-running verification.
- The Redis commit operation atomically checks the lock owner before publishing a cached result; an expired/stale owner fails closed.
- Redis challenge-attempt counters repair keys without an expiry instead of leaving them permanent.
- CI runs the project checks on Node.js 20 and 22.

## Limitations not honestly closable by a local source patch alone

1. **Cryptographic protocol:** the in-tree OPRF/DLEQ remains experimental and has not been shown to conform to RFC 9497. A production migration must use a maintained RFC 9497 implementation, preserve the intended client/server wire contract, and pass official known-answer and negative/tamper vectors. Merely adding a dependency is not a safe migration.
2. **Issuance/redemption unlinkability:** the token construction and protocol need a reviewed redesign; this is not a small cache or TTL fix.
3. **WebAuthn for anonymous visitors:** this archive accepts only server-registered credential IDs/public keys. Anonymous enrollment requires a complete registration ceremony, attestation/client-data validation, session binding, credential storage, and lifecycle/revocation handling. Do not accept a request-supplied public key as a substitute. The inclusive PoW lane remains the non-account-bound alternative.
4. **Motion telemetry:** values reported by a browser can be fabricated. The endpoint scores them server-side but cannot make them proof of humanity. It must not authorize sensitive actions or be the only factor for token issuance.
5. **Accessibility and calibration:** representative user studies are required to measure false positives and ensure the step-up process works for keyboard, screen-reader, reduced-motion, and motor-accessibility users.
6. **Production assurance:** independent cryptographic/application review, penetration testing, dependency/SAST/fuzz audits, load testing, real multi-instance Redis failure tests, and deployment-specific threat-model sign-off have not been performed here.
7. **Reproducible install:** no lockfile is included, so `npm ci` cannot currently be used. Dependency installation timed out in this environment; full typecheck/test/build status remains unverified.

## Validation performed for rc.3

- Source TypeScript syntax transpilation and compiled JavaScript syntax checks are run before packaging.
- ZIP integrity is checked.
- Full test suite and real Redis integration tests could not be completed in this environment because dependencies could not be installed.

## Release decision

**Do not claim production certification.** Keep the service in development or shadow mode and do not use it as the sole control for login, payments, account creation, or other sensitive actions until every gate in `docs/RELEASE_GATES.md` is evidenced by CI and qualified independent reviewers.
