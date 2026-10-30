# Data inventory and retention

| Data | Where | Purpose | Retention |
|---|---|---|---|
| Challenge (id, nonce, epoch) | stateless HMAC; nothing stored | issuance | challenge TTL (default 120 s, max 600 s) |
| Challenge attempt counters | Redis `…:attempt:{h}` / memory | abuse limit | challenge TTL |
| Token nullifiers | Redis `…:used:{h}` / memory | replay protection | 3 epochs + 60 s (≈ 16 min default) |
| Rate-limit entries | Redis sorted sets keyed by IP bucket | abuse limit | window length (default 60 s) |
| `/siteverify` idempotency results | Redis | duplicate-call safety | caller-supplied TTL, ≥ 1 s |
| Registered WebAuthn credentials (id, public key, counter, AAGUID, origin, timestamps) | Redis / memory | step-up | `credentialTtlSec` (default 7 d, max 90 d); deletable by revocation |
| Operational logs | your log pipeline | operations | **you decide; recommended ≤ 30 days**, no tokens/nonces/blinded elements/payloads |

Not collected: names, emails, cookies set by BioKyn, persistent identifiers, fingerprints. The IP appears only inside rate-limit keys (hashed key in Redis,
raw in your edge logs). A WebAuthn credential ID is a stable pseudonymous identifier for up to its TTL: disclose it in your privacy notice if registration is enabled,
and note its AAGUID reveals authenticator model. Motion telemetry sent to `/motion-step-up` is aggregate numbers (no coordinates) and is not stored by BioKyn
unless your `onMotionEvidence` hook stores it.
Legal bases and notices (GDPR/ePrivacy etc.) are the deployer's responsibility; this document is an inventory, not legal advice.
