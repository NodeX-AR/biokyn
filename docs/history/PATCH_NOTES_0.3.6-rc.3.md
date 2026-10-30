# BioKyn 0.3.6-rc.3 patch notes

This is a security-hardening release candidate, **not production-certified**.

- Redis siteverify idempotency now renews its lock lease while work is in progress.
- Result publication is guarded by an atomic Redis script that checks current lock ownership, preventing a stale worker from publishing after lease loss.
- Attempt counters with a missing Redis TTL are repaired in the atomic increment script.
- CI now checks Node.js 20 and 22.
- Added regression coverage for stale idempotency lock ownership.

The earlier rc.2 fixes are retained. See `docs/AUDIT_0.3.6-rc.3.md` and `docs/RELEASE_GATES.md`.
