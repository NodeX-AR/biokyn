# BioKyn (`@biokyn/*`)

Open-source, self-hostable bot-mitigation protocol (Apache-2.0). Biological Kinematics + RFC 9497 VOPRF.

## Status

| Package | State |
| --- | --- |
| `@biokyn/protocol` | **Done, 30 tests passing**: VOPRF/DLEQ (ristretto255-SHA512), delta-lognormal kinematics, token format, wire types |
| `@biokyn/client` | Not finished (telemetry/a11y/anti-tamper drafts only; no Argon2id worker, step-up or orchestrator yet) |
| `@biokyn/shim`, `@biokyn/server`, `@biokyn/nextjs` | Not started |

## What `@biokyn/protocol` guarantees

- `voprf.ts`: Blind / BlindEvaluate / Finalize with a batched DLEQ proof (Fiat-Shamir, SHA-512). Clients verify the
  proof, so an issuer cannot silently use a per-user key. Built from RFC 9497's transcripts; **official test vectors
  have not been run yet** — do that before calling it conformant.
- `token.ts`: Privacy-Pass-shaped token (RFC 9577 layout). RFC 9578 registers no ristretto255 type, so `0xFE01` is an
  experimental private-use codepoint.
- `kinematics.ts`: Levenberg-Marquardt fit of Plamondon's delta-lognormal model to each stroke's speed profile;
  scale-free parameters + fit SNR are the only things that leave the device. `judgeKinematics` is server-side.
- `types.ts`: wire types. After a well-formed request the client can learn only `TOKEN_ISSUED` or `STEP_UP_REQUIRED`.

## Limits you must not paper over

1. **Evidence is client-reported.** The server can check plausibility and consistency, not that real motion occurred.
2. **The model is also a generator.** A bot that synthesizes randomized delta-lognormal strokes with human-range noise
   passes (see the `KNOWN LIMITATION` test). Plain Bezier/min-jerk profiles are *not* automatically rejected by the
   decomposition (they fit at ~18 dB); they are caught here by onset-time bounds, peak-phase asymmetry and
   clone/too-perfect checks, all of which are provisional.
3. **Thresholds are uncalibrated.** Every bound in `DEFAULT_KINEMATIC_JUDGE` is a provisional engineering value tested
   only on synthetic data. Collect real captures per modality (mouse, touch, pen, 30/60/120/1000 Hz) before relying on them.
4. Treat a failed judgment as "step up", never "block".
