<div align="center">

# BioKyn

**Bot protection that respects your users.**
Free, open source, self-hosted. No tracking. No third-party CAPTCHA. No puzzles.

[![CI](https://github.com/biokyn/biokyn/actions/workflows/ci.yml/badge.svg)](https://github.com/biokyn/biokyn/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@biokyn/server?label=%40biokyn%2Fserver)](https://www.npmjs.com/package/@biokyn/server)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/biokyn/biokyn/badge)](https://securityscorecards.dev/viewer/?uri=github.com/biokyn/biokyn)

</div>

BioKyn replaces "click all the traffic lights" with cryptographic proof. Visitors do a small, invisible amount of work in their browser; your server verifies it and issues an anonymous, single-use token. Your data stays on your infrastructure, and your users never see a challenge unless they need one.

## Why BioKyn

- **Private by design.** Tokens are issued through an RFC 9497 VOPRF (the Privacy Pass family), so there are no cookies, fingerprints or cross-site identifiers.
- **Trust you can verify.** Tokens are granted only for server-verifiable work: Argon2id proof-of-work or a WebAuthn credential your server registered. Browser signals can only add friction, never grant access.
- **Accessible for everyone.** The default lane needs no pointer, no vision and no puzzle-solving. The optional motion check always has a non-motion alternative.
- **Drop-in.** A reCAPTCHA/Turnstile-compatible `/siteverify` endpoint plus Express and Next.js adapters.
- **Built to scale.** Redis-backed nullifier, rate-limit and idempotency stores; fail-closed behavior; key rotation with key rings.
- **Free forever.** Apache-2.0. No accounts, no usage tiers, no telemetry.

## Packages

| Package | What it gives you |
|---|---|
| [`@biokyn/server`](packages/server) | Verifier, `/siteverify`, Redis stores, WebAuthn registration, rate limiting, Express/Next.js adapters |
| [`@biokyn/client`](packages/client) | Browser token issuance, WebAuthn helpers, accessible motion dialog, `<biokyn-check>` element |
| [`@biokyn/protocol`](packages/protocol) | Wire types, RFC 9497 ristretto255-SHA512 VOPRF, token v2, PoW, kinematics |
| [`@biokyn/core`](packages/core) | Standalone HMAC-token primitives with zero dependencies |
| [`@biokyn/shim`](packages/shim) | Migration helpers |

## Quick start

```bash
npm install @biokyn/server @biokyn/client
```

**Server (Express)**

```ts
import { BioKynVerifier, biokynExpress, generateServerSecrets, createRateLimiter, MemoryRateLimitStore } from '@biokyn/server';

const verifier = new BioKynVerifier({
  issuer: 'verify.example.com',
  ...generateServerSecrets(), // persist real secrets in a secret manager for production
  sites: [{ origin: 'http://localhost:3000', secret: process.env.BIOKYN_SITE_SECRET! }],
  pow: { memoryKiB: 19456, iterations: 1, parallelism: 1, difficultyBits: 8 },
});

app.use(express.json());
app.use(biokynExpress(verifier, {
  basePath: '/biokyn',
  rateLimit: createRateLimiter({ store: new MemoryRateLimitStore() }),
}));
```

**Browser**

```ts
import { requestInclusiveToken } from '@biokyn/client';

const { token } = await requestInclusiveToken({ basePath: '/biokyn', expectedPublicKey });
// send `token` to your backend, which calls POST /siteverify with { secret, response: token }
```

Going live with shared Redis stores, trusted proxies, key rotation and TLS: **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

## How it works

| Evidence | Role |
|---|---|
| Argon2id proof-of-work bound to the request | **Grants** a token |
| WebAuthn assertion from a credential this server registered | **Grants** a token |
| Browser kinematics, tamper flags, motion telemetry | **Advisory**: informs risk and logs, never grants |

Read more in [Architecture](docs/ARCHITECTURE.md), [Security model](docs/SECURITY.md), [Privacy and token design](docs/PRIVACY.md) and the [Threat model](docs/THREAT_MODEL.md).

## Documentation

[Usage](docs/USAGE.md) · [First run](docs/FIRST_RUN.md) · [Framework integrations](docs/FRAMEWORK_INTEGRATIONS.md) · [Deployment](docs/DEPLOYMENT.md) · [Accessibility](docs/ACCESSIBILITY.md) · [Evaluation](docs/EVALUATION.md) · [Incident response](docs/INCIDENT_RESPONSE.md) · [Data retention](docs/DATA_RETENTION.md) · [Migration](docs/MIGRATION.md) · [Changelog](CHANGELOG.md)

## Develop

Node 20.11 or newer.

```bash
npm ci
npm run check                                  # lockfile, typecheck, tests, build
npm run vectors:fetch && npm run test:vectors  # official RFC 9497 vectors
```

## Community

Questions go to [Discussions](https://github.com/biokyn/biokyn/discussions), bugs and ideas to [Issues](https://github.com/biokyn/biokyn/issues). See [CONTRIBUTING](CONTRIBUTING.md), [GOVERNANCE](GOVERNANCE.md), [ROADMAP](ROADMAP.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately via [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE) © BioKyn contributors
