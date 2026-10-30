# BioKyn architecture

## 1. Challenge

The server creates a stateless challenge bound to the requesting site origin. The challenge carries a fresh nonce, an expiry, an issuer identifier, a redemption context and optional Argon2id parameters.

## 2. Fast lane

The intended fast lane is:

1. Browser collects pointer/touch/pen samples locally.
2. Samples are resampled and reduced to delta-lognormal stroke evidence.
3. Coordinates and raw event timing stay on-device.
4. Only quantized, scale-free evidence is sent.
5. The server runs `judgeKinematics` and decides `ok`, `ambiguous`, or `reject`.
6. Weak/ambiguous evidence should go to step-up, not directly to a permanent block.

The implementation deliberately keeps the judge thresholds in one server-side options object so deployments can calibrate them without changing the wire format.

## 3. Inclusive lane

Assistive and otherwise ambiguous sessions can use the machine-cost lane:

```text
challenge → blinded request → Argon2id proof-of-work → issuance → token
```

The proof is bound to the server nonce and the blinded element, so a solution cannot simply be copied to another issuance request.

## 4. Redemption

The verifier accepts a token at `/siteverify` and consumes a nullifier. The server returns only the compatibility-level result; detailed evidence and reasons remain server-side.

## 5. Framework adapters

`@biokyn/server` exposes:

- framework-neutral `createHandler`
- `biokynExpress` and `requireBioKyn`
- `biokynNext` and `withBioKyn`

The design keeps HTTP parsing separate from the verifier so additional adapters can be added without changing the protocol.
