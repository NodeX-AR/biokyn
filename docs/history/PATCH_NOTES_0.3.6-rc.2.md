# BioKyn 0.3.6-rc.2 patch notes

This is a security follow-up release candidate, not a production-certified release.

- Aligned nullifier retention with the full redemption-context acceptance window.
- Prevented undersized in-memory nullifier configurations from silently ignoring requested TTLs; capacity exhaustion is now explicit and maps to service unavailable.
- Fixed siteverify idempotency cache-key ordering and bounded per-request eviction.
- Bounded early-submit retry polling and made the timeout visible.
- Added explicit attempt-store capacity errors, client-abort cancellation for queued PoW, Host fallback for `/issue`, and client/server liveness parity.
- Connected the optional motion UI to its server evaluator when a challenge ID is provided. Its result is still untrusted telemetry and is not a token-issuance authorization factor.

Full build/test execution was blocked by dependency installation timeout. See `docs/AUDIT_0.3.6-rc.2.md` for remaining release gates.
