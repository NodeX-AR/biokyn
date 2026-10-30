# Usage guide

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
```

## 1. Configure a site

```ts
const verifier = new BioKynVerifier({
  issuer: 'verify.example.com',
  voprfSecretKey,
  challengeSecret,
  sites: [{
    origin: 'https://example.com',
    secret: process.env.BIOKYN_SITE_SECRET!
  }]
});
```

Generate long-lived secrets once and store them in your deployment secret manager. Do not commit them.

## 2. Mount the HTTP API

Express:

```ts
app.use(express.json());
app.use(biokynExpress(verifier));
```

Next.js:

```ts
const routes = biokynNext(verifier, { basePath: '/api/biokyn' });
export const GET = routes.GET;
export const POST = routes.POST;
export const OPTIONS = routes.OPTIONS;
```

## 3. Compatibility verification

Existing reCAPTCHA/Turnstile-style backends can POST:

```text
secret=<site secret>
response=<BioKyn token>
```

to `/siteverify`.

A successful response is deliberately binary with a fixed compatibility score. BioKyn does not pretend it has a meaningful continuous human score.

## 4. Browser liveness

The liveness collector stores raw coordinates and event timing only in a short in-memory buffer. On submission it emits aggregate integers in `_biokyn_live`.

The collector is a **signal**, not an identity system. A determined browser agent can emulate the signals.

## 5. Inclusive proof of work

Use `requestInclusiveToken()` when the fast lane is unavailable or unsuitable. The server chooses memory, iterations, parallelism and difficulty. The browser computes the proof locally.

For a production browser implementation, move the Argon2id solver into a dedicated Worker so a high difficulty cannot freeze the page.

## Production deployment requirements (0.3.0)

The default in-memory replay and attempt stores are for development and single-process tests only. In production, provide a shared atomic store for both token nullifiers and challenge-attempt counters, and provide a shared rate limiter. The server package includes `RedisSecurityStore` for ioredis-compatible Redis clients:

```ts
import Redis from 'ioredis';
import { BioKynVerifier, RedisSecurityStore, createHandler } from '@biokyn/server';

const redis = new Redis(process.env.REDIS_URL!, { enableOfflineQueue: false, maxRetriesPerRequest: 1 });
const sharedStore = new RedisSecurityStore(redis, 'biokyn:prod:', 660_000);
const verifier = new BioKynVerifier({
  issuer: 'your-issuer',
  voprfSecretKey, // load from a secret manager; never generate a new key per process
  challengeSecret, // same secret across instances; rotate through a planned key migration
  sites: [{ origin: 'https://example.com', secret: siteSecret }],
  nullifiers: sharedStore,
  attempts: sharedStore,
});

const handler = createHandler(verifier, {
  rateLimit: async (req) => {
    // Only use this header if your trusted edge proxy overwrites/removes client-supplied copies.
    const clientIp = req.headers['cf-connecting-ip'];
    if (!clientIp) return false;
    return sharedStore.allowRateLimit(`${clientIp}:${req.path}`, 60, 60_000);
  },
});
```

Replace the example limits with values measured against your traffic, and configure the edge so untrusted clients cannot spoof the chosen IP header. Use TLS and Redis authentication, restrict Redis network access, monitor store failures, and configure a no-eviction policy or dedicated instance with adequate memory. Redis failures should fail closed for verification and rate limiting. This setup improves cross-instance state safety; it does **not** certify the custom OPRF implementation or make motion analysis proof of humanity. The crypto release gates remain mandatory.

The handler applies the supplied rate-limit callback to `/challenge`, `/issue`, and `/siteverify` (and preflight requests). If your siteverify calls arrive server-to-server without the same trusted edge headers, use a callback that applies a separate internal-service/network identity policy for those paths; never trust arbitrary client-supplied forwarding headers. Match the Redis nullifier TTL to the configured token epoch (`2 * tokenEpochSec + 60` seconds with the current accepted-epoch policy).
