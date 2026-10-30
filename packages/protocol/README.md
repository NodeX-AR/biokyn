# `@biokyn/protocol`

The protocol package contains the parts that must remain framework-independent:

- compact wire types and canonical encodings
- request/timing commitments
- delta-lognormal kinematic extraction and server-side judgment
- Argon2id proof-of-work for the inclusive lane
- RFC 9497 ristretto255-SHA512 VOPRF primitives and issuance tokens

The VOPRF implementation targets RFC 9497 (ristretto255-SHA512) and is verified against the official test vectors in CI (`npm run vectors:fetch && npm run test:vectors`).
