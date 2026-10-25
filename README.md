# BioKyn (`@biokyn/core`)

Open-source, zero-SaaS bot mitigation and context-bound liveness engine. Apache-2.0.

BioKyn issues short-lived, single-use HMAC-SHA256 tokens bound to
`(timestamp || nonce || formId || sha256(origin) || sha256(sessionId) || sha256(action))`.
A token minted for one form, action, origin or session cannot be replayed or pooled elsewhere.

> **Honest scope:** BioKyn raises the cost of naive scripted abuse (replay, token farming,
> cookie-clearing loops, cross-form reuse). It is not a CAPTCHA replacement against a determined
> attacker running a real browser. Layer it with other defenses for high-value endpoints.

## Install

```bash
npm install @biokyn/core
# optional backends
npm install better-sqlite3   # SqliteStore
npm install ioredis          # RedisStore
```

## Quick start (Express)

```ts
import express from 'express';
import { biokynMiddleware, MemoryStore } from '@biokyn/core';

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(biokynMiddleware({
  secret: process.env.BIOKYN_SECRET!,   // >= 32 bytes, identical across nodes
  store: new MemoryStore(),             // use RedisStore for multi-node
  origin: 'https://example.com',        // recommended behind proxies
  trustProxy: true,                     // only if behind a trusted proxy
}));
app.post('/contact', (req, res) => res.send('ok'));
```

```html
<script src="/__biokyn/client.js" data-base="/__biokyn" defer></script>
<form method="post" action="/contact" data-biokyn="contact">...</form>
```

The client script finds `form[data-biokyn]`, fetches a token, injects a hidden `_biokyn` input,
refreshes it before expiry, and blocks submission until the minimum age has elapsed.

## Quick start (Next.js App Router)

```ts
// lib/biokyn.ts
import { BioKyn, RedisStore } from '@biokyn/core';
export const engine = new BioKyn({ secret: process.env.BIOKYN_SECRET!, store: new RedisStore(redis) });

// app/api/biokyn/challenge/route.ts
import { createChallengeHandler } from '@biokyn/core';
export const GET = createChallengeHandler(engine, { getIp: (r) => r.headers.get('x-real-ip') ?? 'unknown' });

// app/api/contact/route.ts
import { withBioKyn } from '@biokyn/core';
export const POST = withBioKyn(async () => Response.json({ ok: true }), { engine, formId: 'contact' });
```

## Stores

| Store | Use | Notes |
|-------|-----|-------|
| `MemoryStore` | Dev / single node | `.unref()`'d sweeper; state lost on restart |
| `SqliteStore` | Single node, persistent | better-sqlite3; `BEGIN IMMEDIATE` transactions; batched subquery cleanup |
| `RedisStore` | Multi-node / serverless | `SET NX EX` for replay, Lua `INCR`+`EXPIRE` for counters; `adaptNodeRedis` for node-redis v4 |

## Options

See `src/types.ts` (`BioKynOptions`). Defaults: ttl 15 min, minAge 1.5 s, clock skew 5 s,
20 challenges per session, 10 cookieless challenges per IP, 30 verifications per session, per 10 min window. See `docs/ARCHITECTURE.md` for the full table.

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
```

## License

Apache-2.0. See `LICENSE`.
