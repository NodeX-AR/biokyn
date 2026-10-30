# Incident response

| Trigger | Immediate action | Follow-up |
|---|---|---|
| Suspected `voprfSecretKey` leak (attacker can mint tokens offline) | Rotate: deploy new key as current, **drop** the old key from `previousVoprfSecretKeys` immediately (accepting that valid in-flight tokens fail) | Re-issue pinned keys to clients; review logs for abnormal redemption volume; post-mortem |
| `challengeSecret` leak | Replace it (all outstanding challenges and redemption contexts die within one epoch) | Same |
| Site secret leak | Replace the site secret; the leaked one can only call `/siteverify` for that site | Audit who held it |
| Redis data loss / failover | Treat the last `appendfsync` window as a replay window; consider tightening token epoch temporarily | Failover drill record |
| Redis outage | Service fails closed (503). Execute the pre-decided application fallback | Capacity/HA review |
| Bot wave passing PoW | Raise `difficultyBits`, tighten rate limits at the edge, enable monitor-mode logging for evidence | Evaluate attacker economics |
| Fake WebAuthn credential abuse | `verifier.revokeWebAuthnCredential(id)` for known IDs; disable registration (`webauthnRegistration.enabled=false`, redeploy); lower credential TTL | Review registration PoW difficulty |
| Vulnerability report | Acknowledge ≤ 72 h; fix in private; coordinated disclosure ≤ 90 days | Advisory + CVE if warranted |

Roles: an on-call owner, a security lead, a communications lead. Preserve logs before rotating. Never paste tokens or secrets into tickets.
Report vulnerabilities privately via the channel in SECURITY.md; do not open public issues.
