# Assurance case

How BioKyn argues that it is secure, and where the evidence lives.

| Claim | Evidence |
|---|---|
| Only server-verifiable work grants tokens | Verifier logic and tests in `packages/server`; evidence hierarchy in [SECURITY.md](SECURITY.md) |
| VOPRF is correct | Official RFC 9497 vectors (CI hard gate), noble interop and fuzz tests in `packages/protocol/test` |
| Replay is prevented across nodes | Shared nullifier store, Redis integration tests against Redis 6.2 and 7.4 |
| Failures do not fail open | Fail-closed Redis guard tests; production start-up checks |
| Inputs are bounded | CBOR, body-size and store-capacity limits with fuzz and hardening tests |
| Users are not tracked | [PRIVACY.md](PRIVACY.md), [DATA_RETENTION.md](DATA_RETENTION.md) |
| Supply chain is controlled | Lockfile gate, Dependabot, dependency review, CodeQL, OpenSSF Scorecard, provenance-signed releases |

Threats and mitigations: [THREAT_MODEL.md](THREAT_MODEL.md).
