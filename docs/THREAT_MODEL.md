# Threat model (v0.4.0-rc.1)

| Adversary | Capability | Mitigations | Residual |
|---|---|---|---|
| Scripted bot, no browser | HTTP only | Argon2id PoW per token; per-IP/route rate limits; one issuance per challenge; attempt budgets | PoW cost is the only economic barrier; tune difficulty to attacker value |
| Browser automation / agents | full browser, can synthesize motion | motion cannot grant; PoW still required; tamper/automation flags can only deny | agents pay PoW like anyone; BioKyn does **not** distinguish a human from a patient agent |
| Distributed botnet | many IPs | per-bucket (IPv6 /64) limits, PoW; edge rate limiting required | cost scales linearly with attacker compute |
| Token replay / double-spend | steal or reuse tokens | single-use nullifier (atomic, shared, fail-closed); 3-epoch lifetime; origin-bound digest | Redis data loss reopens replay inside the epoch window |
| Malicious issuer operator | per-user keys, logging | DLEQ proof, key pinning, blindness | pinning must be out-of-band; metadata correlation |
| Network attacker | MITM | TLS (deployment), origin binding, CORS allow-list | — |
| Forged evidence | fabricate kinematics/motion | advisory-only; motion endpoint has no verdict | kinematics is advisory, PoW grants |
| Fake WebAuthn enrollment | virtual authenticators, mass registration | PoW per registration, attestation `none` accepted knowingly, TTL, store capacity, revocation | a registered credential is **not** proof of humanity |
| Store attacker / outage | Redis down or slow | fail closed (503); no token issued/accepted without shared state | availability tradeoff by design |
| Resource exhaustion | expensive verification | PoW semaphore + queue bound; body-size limits; bounded caches; CBOR limits | tune `maxConcurrent` to cores |

Scope boundary: compromise of the server host or secrets, browser extensions with page access, physical attacks, accessibility of third-party sites.
