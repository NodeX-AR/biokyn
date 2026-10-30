# Deployment hardening guide

BioKyn refuses to start in `NODE_ENV=production` without shared stores, an HTTPS origin and a rate limiter. This guide covers the rest.

## Reference wiring

```ts
import Redis from 'ioredis';
import { BioKynVerifier, RedisSecurityStore, RedisSiteverifyIdempotencyStore, RedisWebAuthnCredentialStore,
         createHandler, createRateLimiter } from '@biokyn/server';

const redis = new Redis(process.env.REDIS_URL!, { tls: {}, maxRetriesPerRequest: 1, enableOfflineQueue: false, commandTimeout: 1500 });
const store = new RedisSecurityStore(redis, 'biokyn:v1:', undefined, { commandTimeoutMs: 1000 });

const verifier = new BioKynVerifier({
  issuer: 'verify.example.com',
  voprfSecretKey: fromSecretManager('BIOKYN_VOPRF_KEY'),          // 32 bytes, from KMS/secret manager, never from git
  challengeSecret: fromSecretManager('BIOKYN_CHALLENGE_SECRET'),
  previousVoprfSecretKeys: rotationOverlapKeys(),                  // empty except during rotation
  sites: [{ origin: 'https://shop.example.com', secret: fromSecretManager('BIOKYN_SITE_SECRET') }],
  nullifiers: store, attempts: store,
  // kinematicsPolicy stays 'advisory' (default). Do not change it.
});
const handler = createHandler(verifier, {
  siteverifyIdempotencyStore: new RedisSiteverifyIdempotencyStore(redis),
  rateLimit: createRateLimiter({ store, clientIp: { trustedProxies: ['10.0.0.0/8'] } }),   // your LB ranges, nothing broader
});
```

## Checklist

**Network / TLS** — terminate TLS at the edge; HTTPS-only origins; HSTS; Redis reachable only from app subnets, `rediss://` + ACL user
limited to `SET GET EVAL EVALSHA PEXPIRE PTTL INCR ZADD ZCARD ZREMRANGEBYSCORE TIME DEL` on the `biokyn:` prefix; no public listener.

**Client IP** — set `trustedProxies` to *exactly* the proxies you operate. With none configured, forwarded headers are ignored. Prefer an
edge that overwrites a single header (e.g. `cf-connecting-ip`) over parsing `X-Forwarded-For`. Also rate-limit at the edge; application limits are the second layer.

**Redis** — dedicated instance or logical isolation; `maxmemory-policy noeviction` (eviction deletes live nullifiers = replay);
`appendonly yes`; `appendfsync everysec` (≤1 s of nullifiers can be lost on crash) or `always` if that window is unacceptable;
size memory for peak tokens/s × 3 epochs × ~150 B. Monitor memory, evictions (must be 0), latency, replication lag, `rejected_connections`.

**Secrets** — `voprfSecretKey`, `challengeSecret`, site secrets come from a secret manager; rotate site secrets independently.
Generate with `generateServerSecrets()` once, store, never regenerate on boot (new keys invalidate in-flight tokens and split the anonymity set).

**Key rotation** — 1) generate new key; 2) deploy with `voprfSecretKey=new`, `previousVoprfSecretKeys=[old]`; 3) clients pick up the new key from `/challenge`;
4) after ≥ 3 epochs (default 15 min) remove `old`. Pinned clients (`expectedPublicKey`) need the new key shipped *before* step 2.

**Proof-of-work** — tune `difficultyBits` to your tolerance for client latency (each bit doubles expected attempts; one Argon2id attempt ≈ tens of ms
in a browser). Keep `maxConcurrent` ≈ physical cores and a small `maxQueue`; overload returns 503 + `retry-after`, never a pass.

**Clock** — NTP on every instance. Epoch contexts derive from wall time; skew > one epoch causes spurious `timeout-or-duplicate`.

**Logging** — never log tokens, nonces, blinded elements, authenticators, WebAuthn payloads or site secrets. Logs carry no personal data by default
(IP is only in the rate-limit key). Retention: see DATA_RETENTION.md.

**Serving the liveness script** — publish `@biokyn/client` built with plain `tsc` (the script is the function's source text). Serve it with a CSP nonce; do not run it through a coverage-instrumenting or name-mangling bundler.

**Failure behaviour** — Redis unreachable/slow ⇒ `/issue` and `/siteverify` fail closed (503 / `internal-error`). Decide whether your application treats that as "deny", "queue" or "temporarily bypass with other controls" *before* an outage.

## Failover drill

Run before launch and after any topology change, against the real Redis (Sentinel or Cluster), with `npm run load` generating background traffic:

1. Issue and redeem a token; record success. Issue a second token but do not redeem it.
2. Kill the Redis primary. Expect: 503s within `commandTimeoutMs`, **no 2xx redemptions and no 5xx other than 503**.
3. After promotion, redeem the second token (should succeed once), then replay both tokens (must fail).
4. Record how many nullifiers written in the last second before the kill were lost (asynchronous replication loses them): that is your replay window. Mitigate with `WAIT 1 100` on writes (custom store) or accept and document.
5. Repeat with a network partition (iptables/toxiproxy) and with `CLIENT PAUSE`.
Attach the record to the release evidence.

## Capacity validation

`npm run load -- --target https://staging --scenario challenge --duration 120 --concurrency 200` and the `issue-invalid` / `siteverify-invalid` scenarios; the tool exits non-zero on unexpected 5xx or p99 over budget.
