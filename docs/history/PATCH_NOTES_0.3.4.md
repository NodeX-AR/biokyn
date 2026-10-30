# BioKyn 0.3.4 audit patch

## Fixes

- Reject null, primitive, and array entries in kinematic stroke arrays as protocol errors rather than allowing a TypeError to escape.
- Align the motion step-up hit test with the rendered target center.
- Bound server PoW configuration by the protocol's `DEFAULT_POW_LIMITS`.
- Use `@noble/hashes/sha256` and `TextEncoder` for the siteverify idempotency response digest, avoiding `node:crypto` in this path.
- Consume inclusive-lane challenge attempts only after the PoW semaphore admits the request, so `503 busy` does not burn an attempt. Requests with PoW disabled/missing parameters still consume an attempt.
- Update package versions and documentation references to 0.3.4; correct the README PoW example to a valid memory setting.

## Known gaps

- `/siteverify` idempotency result caching remains process-local and is not cross-node durable.
- The client package still does not provide a dedicated fast-lane kinematic collector.
- Build and tests were not run successfully in this environment because workspace dependencies are not installed.
