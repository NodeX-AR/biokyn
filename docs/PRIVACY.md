# Token privacy (v2) — design, argument, residual risk

**Token v2 design notes.** Each claim below is stated so it can be checked; review and issues are welcome.

## Protocol

```
client                                             issuer (holds sk, pk; key_id = SHA-256("biokyn-key-v2" ‖ pk))
 GET /challenge  ───────────────────────────────▶   {challengeId, nonce, redemptionContext, pk, keyId, pow params}
 nonce_t ← 32 random bytes
 input   = type(2) ‖ nonce_t ‖ SHA-256(issuer,origin,redemptionContext) ‖ keyId
 (r, B)  = Blind(input)                              — RFC 9497 §3.3.1
 PoW bound to (nonce, B)
 POST /issue {challengeId, B, pow, …}  ─────────▶   verify PoW (and advisory evidence), one issuance per challenge
                                         ◀─────────   evaluated(32) ‖ DLEQ proof(64)       — RFC 9497 BlindEvaluate
 verify proof against pinned pk, Finalize ⇒ authenticator = F(sk, input)   (64 bytes)
 token = type ‖ nonce_t ‖ digest ‖ keyId ‖ authenticator                    (162 bytes)
 token ──▶ site backend ──▶ /siteverify: recompute F(sk, input), compare, spend nullifier
```

## What the issuer learns, and what it cannot learn

- At issuance: the blinded element `B`, the PoW, request metadata, network address. `B = r·H(input)` with fresh uniform `r` is uniformly
  distributed in the group, so `B` is independent of `nonce_t` (VOPRF blindness).
- At redemption: `nonce_t`, `digest`, `keyId`, authenticator. Nothing in that token is a function of `B` or of the issuance response that
  the issuer can compute without `r`.
- The v1 design additionally echoed `B` and the evaluated element in the issuance blob and bound a bespoke tag. v2 removes every
  value the issuer retained at issuance from the redeemed token; the issuance response is `evaluated ‖ proof` only.
- The unit test `is unlinkable at the protocol level…` asserts the structural property (no shared substrings). It does not and cannot prove
  the cryptographic property; that is the reviewer's job.

## Key consistency (anti-tagging)

A malicious issuer could hand each user a different key and recognize them at redemption by `keyId`. Defences implemented:
the client verifies the DLEQ proof against a key it has pinned (`expectedPublicKey`) and checks that the advertised `keyId` matches the key.
Defence **not** implemented and required for a real anonymity guarantee: clients must obtain the key through a channel the issuer cannot
individually target (pinned in the page/app build, or a transparency/consensus mechanism). Without pinning, per-user keys are undetectable.

## Residual linkability (accept or mitigate explicitly)

1. **Metadata:** timing of `/issue` vs `/siteverify`, IP/User-Agent seen at both ends, `challengeId` logs. Do not log blinded elements, tokens,
   nonces or authenticators; decouple issuance and redemption timing where possible (issue ahead of time, redeem later).
2. **Anonymity set:** a token is as private as the set of people who received tokens under the same `keyId` and epoch. Rotate keys rarely and
   avoid per-user or per-tiny-cohort keys. Token epochs (`redemptionContext`) are 5-minute buckets by default; a coarser epoch is more private
   and less replay-restrictive.
3. **`siteverify` secret holders** are the issuer. A site that runs both ends can correlate by timing/IP regardless of cryptography.
4. **Key rotation window:** during overlap two `keyId`s are live, which splits the anonymity set.

## Replay and spending

`nullifier = SHA-256("biokyn-nullifier-v2" ‖ nonce ‖ digest ‖ keyId)`; stored only after the authenticator verified (garbage cannot fill the
store). Retention is 3 epochs + 60 s. A Redis restart without persistence re-opens the replay window; see DEPLOYMENT.md.
