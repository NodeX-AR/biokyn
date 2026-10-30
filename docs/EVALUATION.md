# Measuring detection quality and false positives

No detection-rate or false-positive claim is made by this project. The evaluation harness lets *you* measure them on *your* traffic.

## Tooling

```bash
npm run build:protocol
node scripts/eval-kinematics.mjs corpus.jsonl --max-fpr 0.02 --min-humans 400     # exit 1 on FAIL / INSUFFICIENT SAMPLE
```

`corpus.jsonl` lines: `{"label":"human|bot","cohort":"mouse|touch|trackpad|assistive|…","evidence":<KinematicEvidence>}`.
The tool reports, per cohort, the human false-positive rate (any non-`ok` verdict = escalated) and bot catch rate with **95 % Wilson intervals**, and refuses to
pass a cohort whose sample is too small for the interval to meet the target (e.g. 0 FP in 30 humans still has an upper bound of 11 %).
`scripts/lib/stats.mjs` has `requiredSamples()` (≈ 753 humans for ±1 pp at 2 %) and the rule of three.

## Corpus requirements

- **Humans:** consented, representative of your population: device mix, input modalities, ages, accessibility cohorts, locales, bandwidth. Label by construction (authenticated users in a flow, panel recruits), not by the detector.
- **Bots/agents:** current Playwright/Puppeteer/Selenium (stealth variants), Chrome-DevTools-driven agents and LLM computer-use agents, human-trace replay, synthetic trajectories (min-jerk, Bézier, sigma-lognormal), residential-proxy distribution, protocol abuse (replay, malformed, concurrency).
- Keep a held-out split; never tune thresholds on the data used to report the rate. Report counts, not just rates.
- Re-run on every threshold change and on a schedule (agents change).

## Design principle

The synthetic generator in `packages/protocol/test/synth.ts` is a regression fixture, not a population model. Kinematics is therefore an advisory signal, and proof-of-work is mandatory for every token, so that detection quality never gates security.

## Penetration test and cryptographic review — scope to commission

- **Pentest:** all HTTP endpoints (parsing, CORS/origin handling, rate limits, error oracles), replay/race conditions across instances, Redis misuse, PoW DoS, WebAuthn registration abuse, client script injection/CSP, supply chain.
- **Crypto review** (an independent Python reference with known-answer self-test is in `tools/reference/`): `voprf/*` vs RFC 9497 (transcripts, serialization, error handling, constant-time behaviour of noble usage), v2 token construction ([PRIVACY.md](PRIVACY.md)): blindness argument, nonce/nullifier derivation, key-id design, key-consistency story, rotation; the ristretto255 map dependency.
