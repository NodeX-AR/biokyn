# BioKyn 0.3.5

- Added `assessRisk()` as an explainable server-side policy helper with bounded client-untrusted evidence contribution.
- Added optional `<biokyn-check>` browser custom element with `biokyn-token` and `biokyn-error` events.
- Added a full blueprint status matrix for PAT/RFC 9578, WebAuthn, RFC 9497, proof-of-work research, kinematics, anti-automation signals, risk scoring, proxy boundaries, and framework integration.
- Added React, Vue, Svelte and Next.js integration guidance and release gates.
- Kept honest compatibility boundaries: no RFC 9497 claim, no hardware-attestation claim, no Cuckoo Cycle replacement, no JA4 computation, no cross-instance `/siteverify` idempotency claim, and no measured bot-blocking percentage.

Validation status: source-level checks and ZIP integrity should be run for this artifact. A full dependency-installed build and test suite has not yet been established in this environment.
