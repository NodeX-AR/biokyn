# BioKyn 0.3.1 hardening patch

## Changes in this patch
- Validate middleware runtime configuration at construction: positive/safe TTLs and quotas, non-negative age/skew values, canonical HTTP(S) origin, and cookie-name syntax.
- Reject malformed action labels at verification time.
- Validate store keys and TTL arguments consistently across MemoryStore, SqliteStore, and RedisStore so invalid expiry inputs cannot silently become immediate or unbounded entries.
- Add black-box regression tests for invalid runtime configuration and invalid store TTLs.
- Preserve the existing multi-package architecture and documented security limitations.

## Verification status
A full test/build run could not complete in this environment because the workspace's Node type definitions are not installed (`TS2688: Cannot find type definition file for 'node'`). Installing workspace dependencies timed out. Do not interpret this patch as a completed independent security audit. See `SECURITY_REVIEW.md` and `docs/RELEASE_GATES.md` for remaining cryptographic, liveness, unlinkability, and deployment release gates.
