# First run on a networked machine (closes the "not verified here" items)

This release was developed in an environment without registry access. Everything below was **not** run there. Do these in order; each step says what a failure means.

```bash
npm install                    # 1. creates package-lock.json  → review it, COMMIT it (CI uses `npm ci`)
npm run check                  # 2. lockfile gate + typecheck + all tests + build
npm run vectors:fetch          # 3. downloads RFC 9497 and writes packages/protocol/test/vectors/*.json
npm run test:vectors           # 4. official-vector gate (REQUIRE_OFFICIAL_VECTORS=1)
REDIS_URL=redis://127.0.0.1:6379 npm run test:redis   # 5. real-Redis suite (start Redis as in .github/workflows/ci.yml)
npm run audit:prod             # 6. dependency audit
```

| Failure | Meaning / where to look |
|---|---|
| Step 2: `Cannot find module '@noble/hashes/sha2.js'` or a missing export | noble path/API differs from what was assumed. All hash imports are in `packages/protocol/src/hashes.ts` — fix there only. |
| Step 2: `ristretto255.Point.…` is not a function / `does not expose a ristretto255 uniform-bytes map` | noble's ristretto API differs. Adapt `packages/protocol/src/voprf/group.ts` (`elementFromUniformBytes`, `Point.Fn.ORDER`, `fromBytes`, `toBytes`, `multiply`); the KAT tests in `rfc9497.kat.test.ts` tell you immediately whether the result is still RFC-correct. |
| Step 2: type errors | development typechecked with `tsc` 6.0.3 against ambient stubs; real `@types/node` may surface differences. Fix at the reported line. |
| Step 4: parser error | `scripts/rfc9497-parse.mjs` was tested on RFC-formatted text but never on the live document. Inspect the downloaded text around "A.1." and adjust the parser; do **not** weaken the test. |
| Step 4: a vector mismatch | **stop.** Either the parser mis-read a field or the VOPRF code deviates from the RFC. Do not ship. |
| Step 2: tests time out | server tests solve real 8 MiB Argon2id proofs (slow in pure JS). Per-test timeout is 60 s (`vitest.config.ts`); if your CI is slower, lower `difficultyBits` in `packages/server/test/helpers.ts` or raise the timeout. |
| Step 5: any failure | a real concurrency/Lua/configuration defect. Do not ship; fix the store, not the test. |

Then run the failover drill and load test described in [DEPLOYMENT.md](DEPLOYMENT.md).
