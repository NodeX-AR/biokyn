> **Historical document (0.3.x).** Superseded where it conflicts with [STATUS.md](STATUS.md) for 0.4.0-rc.1.

# BioKyn 0.3.5 audit patch

## Addressed in this patch

- **Express body draining:** route ownership is checked before reading a request body. Unrelated routes immediately call `next()`.
- **Zero VOPRF scalar:** `deserializeScalar` rejects zero and out-of-range values. Secret-key generation should continue using `randomScalar()`.
- **Liveness divergence:** client and server judge `src: none` consistently as `no_trigger`.
- **Quota IP with port:** valid IPv4 `address:port` values are normalized to the IPv4 address before quota-keying.
- **Idempotency cleanup:** cache cleanup is amortized and capped at 128 entries every 64 relevant calls rather than scanning the entire map for every request. The cache remains process-local and is not distributed idempotency.
- **Fast form submission:** early submit is queued and retried through `requestSubmit()` after the minimum-age gate, rather than silently dropped. Test with forms that have submit handlers and custom submitter semantics.
- **Release metadata:** README and release-gate headings now match 0.3.5; the personal email was removed from CONTRIBUTING.

## Remaining limitations and release gates

- **WebAuthn:** assertions are now verified against server-configured credential IDs and SPKI public keys; request-supplied SPKI is ignored. Enabling `webauthnStepUp` without `webauthnCredentials` fails at startup. This proves possession of a registered key, not physical hardware or attestation. Registration/attestation and signature-counter persistence remain integration responsibilities.
- **Motion step-up:** remains client-side UX/telemetry only. It is explicitly not an authorization result; server-side kinematic evidence and risk policy remain authoritative. There is no secure server gesture challenge in this release, so integrations must not use `passed` to authorize.
- **Secret comparison timing:** comparisons now use fixed-length SHA-256 digests and scan every configured site. This reduces length-dependent comparison behavior but is not a substitute for high-entropy secrets or side-channel review.
- **Epoch transition:** redemption accepts the current epoch and two prior epochs, matching the documented maximum two-epoch token lifetime across boundary transitions. Add a clock-injected regression test before release; accepting older epochs increases the redemption window and should be reconsidered if token lifetime semantics change.
- **MemoryStore capacity:** capacity exhaustion now throws `StoreCapacityError`; core middleware maps it to an explicit 503 `store_unavailable` rather than replay or global rate-limit failures. A shared bounded production store is still recommended.
- **Origin absence:** same-origin GET challenge requests may fall back to Host only when it exactly matches a configured site host. Arbitrary Host values cannot authorize unknown origins. Behind proxies, configure canonical origins and ensure Host forwarding is controlled.
- **`form.submit()`:** it still bypasses submit events by HTML design. Integrations must use `requestSubmit()` or call `BioKynLive.attach(form)` before custom submission; no global monkey patch is installed to avoid breaking framework behavior.
- **Motion step-up:** now explicitly marks its output `trust: client-untrusted`; it remains a UX signal, not server-verified proof. No secure server gesture endpoint is claimed.
- **Distributed siteverify idempotency:** the cache is still process-local; deployments needing cross-instance idempotency must use a shared gateway/store or add a shared idempotency provider before production.
- **RFC 9497, PATs, Cuckoo Cycle, JA4, and hardware attestation:** no compliance or production readiness is claimed without compatible issuers, audited implementations, conformance vectors, and deployment-specific testing.

## Verification

Run `npm install`, `npm run check`, and the security-specific integration tests on Node.js 20+. This archive has not been certified by an independent cryptographic review.


## Follow-up patch status

- Registered WebAuthn credential binding added; attestation trust and persistent sign counters are not implemented.
- Memory-store exhaustion returns explicit unavailable errors.
- Redemption accepts three epoch contexts to cover boundary-crossing lifetime.
- Same-origin GET Host fallback is constrained to preconfigured site hosts.
- Early form submissions are queued with a status message and retried via `requestSubmit`.
- Fixed-length secret digests are compared instead of variable-length raw secrets.
- Motion step-up remains explicitly non-authoritative; no client-provided boolean can establish server-side validity.
