# Migration

## 0.3.x → 0.4.0 (breaking, wire version 2)

All server and client packages must be upgraded together; v1 requests/tokens are rejected (`version !== 2`, wrong token length/type).

| Change | Action |
|---|---|
| Dependencies | `@noble/curves ^2`, `@noble/hashes ^2`; delete `node_modules` and lockfile, `npm install`, commit the new lockfile |
| Issuer key | existing `voprfSecretKey` values stay valid scalars, but derived public keys/`keyId` are unchanged only if you keep the same secret; tokens issued by 0.3 are invalid |
| `ChallengeResponse` | new `keyId` field |
| `IssuanceRequest` | `version: 2`; fast-lane requests must also carry `pow` (advisory policy) |
| Issuance response | `evaluated ‖ proof` (96 B); no echoed elements |
| Redemption token | 162-byte v2 format (`parseToken`/`encodeToken`) |
| Fast lane | no longer issues without PoW. To keep legacy behaviour temporarily: `kinematicsPolicy: 'unsafe-client-gate'` (+ `acknowledgeUnsafeKinematicsGate` in production). **Not recommended.** |
| `/motion-step-up` | returns `{status:'MOTION_RECEIVED'}` only; `passed`/`score` removed. Use `onMotionEvidence` |
| `runMotionStepUp` result | `passed`/`score`/`serverEvaluation` removed; has `outcome` (`'alternative'` must lead to the PoW lane) |
| WebAuthn step-up | needs credentials from registration (`webauthnRegistration`) or `webauthnCredentials`; assertion `publicKeySpki` is ignored |
| Store errors | now HTTP 503 `store_unavailable`; clients must retry with backoff |
| Redis keys | now include `{hash tags}`; old keys are not read (nullifiers from 0.3 are irrelevant since old tokens are invalid) — **flush the old prefix or change it** |
| Adapters | use `ownsPath` instead of private route lists if you wrote your own adapter |

Rollout: deploy server and client together behind a maintenance window or version the base path (`/biokyn-v2`).
