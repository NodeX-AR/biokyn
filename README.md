# BioKyn (`@biokyn/*`)

Open-source, self-hostable bot-mitigation protocol (Apache-2.0). Biological Kinematics + RFC 9497 VOPRF.

## Status

| Package | State |
| --- | --- |
| `@biokyn/protocol` | **Done, 30 tests passing**: VOPRF/DLEQ (ristretto255-SHA512), delta-lognormal kinematics, token format, wire types |
| `@biokyn/client` | Not finished (telemetry/a11y/anti-tamper drafts only; no Argon2id worker, step-up or orchestrator yet) |
| `@biokyn/shim`, `@biokyn/server`, `@biokyn/nextjs` | Working |

## What `@biokyn/protocol` guarantees

- `voprf.ts`: Blind / BlindEvaluate / Finalize with a batched DLEQ proof (Fiat-Shamir, SHA-512). Clients verify the
  proof, so an issuer cannot silently use a per-user key. Built from RFC 9497's transcripts; **official test vectors
  have not been run yet** — do that before calling it conformant.
- `token.ts`: Privacy-Pass-shaped token (RFC 9577 layout). RFC 9578 registers no ristretto255 type, so `0xFE01` is an
  experimental private-use codepoint.
- `kinematics.ts`: Levenberg-Marquardt fit of Plamondon's delta-lognormal model to each stroke's speed profile;
  scale-free parameters + fit SNR are the only things that leave the device. `judgeKinematics` is server-side.
- `types.ts`: wire types. After a well-formed request the client can learn only `TOKEN_ISSUED` or `STEP_UP_REQUIRED`.
