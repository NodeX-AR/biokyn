> **Historical document (0.3.x).** Superseded where it conflicts with [STATUS.md](STATUS.md) for 0.4.0-rc.1.

# BioKyn 0.3.5 — implementation blueprint and release boundaries

This release advances the integration surface and transparent risk policy. It does **not** claim parity with reCAPTCHA or Turnstile, universal device attestation, RFC conformance, or a measured bot-blocking percentage.

## Status by pillar

| Pillar | 0.3.5 status | Release boundary |
|---|---|---|
| Privacy Pass / PAT (RFC 9578) | Architecture documented; not implemented | Requires a compatible issuer/verifier, key lifecycle, redemption protocol and RFC test vectors. Existing tokens are not PATs. |
| WebAuthn | Existing optional assertion check | Verifies user presence for a challenge; the request-supplied public key means it is not credential registration, hardware attestation, or proof of a physical device. |
| OPRF (RFC 9497) | Existing custom primitive remains experimental | Not conformant. Do not advertise blind issuance as RFC 9497 until replaced by a maintained implementation and official vectors pass. |
| Proof of work | Argon2id remains the implemented lane | Cuckoo Cycle is a research candidate, not a drop-in replacement. Benchmark verifier cost, client energy, ASIC/GPU economics, and DoS behavior before changing algorithms. |
| Kinematic signals | Existing opt-in interaction collector and motion step-up | Probabilistic, privacy-sensitive and forgeable. Unknown input is not evidence of a bot; provide accessible alternatives. No audio capture is implemented. |
| Headless / automation detection | Limited heuristics only | Browser probes are evadable and create false-positive/privacy risk. No claim of detecting all CDP, headless, or scripted sessions. No polymorphic obfuscation is shipped. |
| Explainable risk | Added `assessRisk()` policy helper | Scores are policy points, not calibrated probabilities. Client evidence is capped. Integrators must keep detailed reasons server-side and calibrate on representative traffic. `/siteverify` retains its honest fixed success score. |
| Edge / proxy / shared state | Existing generic HTTP handler and Redis security primitives | Trusted proxy identity must be configured at the deployment boundary. JA4 is not computed by this package; consume it only from a trusted proxy, never a client header. Cross-instance `siteverify` idempotency remains a release gate. |
| Framework UI | Added optional `<biokyn-check>` web component | React/Vue/Svelte/Next wrappers can wrap the custom event, but the component does not authorize actions or replace server verification. |

## Web component

Import `defineBioKynWidget` from `@biokyn/client` and call it once in the browser:

```ts
import { defineBioKynWidget } from '@biokyn/client';
defineBioKynWidget();
```

Then render `<biokyn-check base-path="/biokyn"></biokyn-check>`. Listen for `biokyn-token` and send its `detail.token` to your own backend, which must verify it using the site secret. `biokyn-error` contains a user-facing error message. Never place the site secret in browser code. Keep an accessible alternative to motion-based step-up.

The component emits a token but deliberately does not auto-submit a form or imply that a client-side event grants access. Tokens should be redeemed server-side immediately before the protected action.

## Explainable risk helper

`assessRisk(evidence, policy)` accepts named weighted signals with an explicit trust source. Server-derived evidence contributes normally; `client-untrusted` evidence is capped. The result includes `score`, `band`, `reasons`, `requiresStepUp`, and `denyRecommended`. The helper is intentionally not wired into `/siteverify`: that endpoint currently has no authenticated, server-verifiable risk evidence and must not invent a score or expose an evasion oracle.

Example:

```ts
import { assessRisk } from '@biokyn/server';
const risk = assessRisk([
  { id: 'rate_limit_near_threshold', weight: 20, source: 'server' },
  { id: 'interaction_anomaly', weight: 10, source: 'client-untrusted' },
]);
if (risk.requiresStepUp) { /* offer an accessible step-up */ }
// Log risk.reasons only to access-controlled server telemetry.
```

## Distributed state and edge deployment

Use `RedisSecurityStore` for atomic shared nullifier insertion, attempt limits, and rate limiting. Configure Redis with TLS, authentication, restricted network access, monitoring, capacity planning and a no-eviction policy for security keys. Fail closed if state is unavailable. Do not trust `X-Forwarded-For` or a `JA4` header unless a trusted reverse proxy overwrites and sanitizes it.

The current process-local `/siteverify` idempotency cache is not cross-instance safe. Do not claim exactly-once verification across replicas until a shared, atomic result/claim store is implemented and concurrency-tested. Application-level idempotency for the protected business operation is still required.

## Release gates before production claims

1. Replace the custom OPRF/DLEQ with a reviewed RFC 9497 implementation and pass official vectors.
2. Design and test action-bound tokens; test cross-site and replay boundaries.
3. Implement shared, atomic `/siteverify` idempotency with crash recovery and concurrency tests.
4. Add fuzzing, property tests, dependency audit, independent cryptographic review, and full clean-install CI.
5. Calibrate risk thresholds using representative users, assistive technology, mobile devices, and current automation. Publish false-positive and latency measurements.
6. Benchmark Argon2id and any alternative across low-end phones, desktop browsers, CPUs and GPUs before changing the PoW lane.
7. Add proxy adapters only with documented trust boundaries and an explicit supported-runtime matrix.

## Honest claims

BioKyn is an experimental self-hosted bot-mitigation toolkit. It can add friction, bind tokens to server challenges, detect some simplistic automation patterns, and provide shared replay/attempt/rate-limit primitives. It cannot prove that a visitor is human, that a device is physical, or that an interaction was not synthesized. It has no validated 99.99% block rate and should not be the sole protection for payments, account recovery, or other sensitive actions.
