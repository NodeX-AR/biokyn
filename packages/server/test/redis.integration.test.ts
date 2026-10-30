/**
 * Integration tests against a REAL Redis (>= 6.2; started with `--appendonly yes --enable-debug-command yes` in CI).
 * Locally these are skipped unless REDIS_URL is set. In CI (REQUIRE_REDIS=1) an unreachable Redis FAILS the suite.
 *
 *   docker run -d -p 6379:6379 redis:7.4 redis-server --appendonly yes --enable-debug-command yes
 *   REDIS_URL=redis://127.0.0.1:6379 REQUIRE_REDIS=1 npm run test:redis --workspace=@biokyn/server
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { base64urlDecode, base64urlEncode, completeIssuance, decodeIssuance, randomBytes, serializeToken, sha256, utf8 } from '@biokyn/protocol';
import {
  MemoryWebAuthnCredentialStore, RedisSecurityStore, RedisSiteverifyIdempotencyStore, RedisWebAuthnCredentialStore, StoreUnavailableError, siteverify,
  type RedisAtomicClient, type StoredWebAuthnCredential,
} from '../src/index.js';
import { ORIGIN, SECRET, buildRequest, makeVerifier } from './helpers.js';

const url = process.env.REDIS_URL;
const required = process.env.REQUIRE_REDIS === '1';
type Client = RedisAtomicClient & { quit(): Promise<unknown>; call(...a: string[]): Promise<unknown>; get(k: string): Promise<string | null>; pttl(k: string): Promise<number>; set(...a: unknown[]): Promise<unknown> };

describe('Redis integration (real server)', () => {
  it('Redis is reachable when required (CI)', () => { if (required) expect(Boolean(url)).toBe(true); });
  if (!url) return;
  let A: Client, B: Client, admin: Client; let prefix: string;
  const connect = async (extra: Record<string, unknown> = {}): Promise<Client> => {
    const { default: IORedis } = await import('ioredis');
    const c = new IORedis(url, { maxRetriesPerRequest: 1, ...extra }) as unknown as Client;
    return c;
  };
  beforeAll(async () => { A = await connect(); B = await connect(); admin = await connect(); prefix = `biokyn:test:${base64urlEncode(randomBytes(6))}:`; });
  afterAll(async () => { await Promise.all([A, B, admin].map((c) => c.quit())); });
  const stores = (p = prefix) => [new RedisSecurityStore(A, p), new RedisSecurityStore(B, p)] as const;

  it('exactly one of 400 concurrent nullifier inserts across two instances wins', async () => {
    const [a, b] = stores(`${prefix}n:`);
    const results = await Promise.all(Array.from({ length: 400 }, (_, i) => (i % 2 ? a : b).checkAndInsert('token:same', 60_000)));
    expect(results.filter(Boolean)).toHaveLength(1);
    const ttl = await A.pttl(`${prefix}n:used:{${base64urlEncode(sha256(utf8('token:same')))}}`);
    expect(ttl).toBeGreaterThan(0);
  });
  it('the attempt budget is exact under contention from two instances', async () => {
    const [a, b] = stores(`${prefix}a:`);
    const r = await Promise.all(Array.from({ length: 60 }, (_, i) => (i % 2 ? a : b).consumeAttempt('challenge-1', 4, 30_000)));
    expect(r.filter(Boolean)).toHaveLength(4);
  });
  it('the rate limiter admits exactly `limit` requests per window, then recovers', async () => {
    const [a, b] = stores(`${prefix}r:`);
    const r = await Promise.all(Array.from({ length: 100 }, (_, i) => (i % 2 ? a : b).allowRateLimit('ip:1', 10, 500)));
    expect(r.filter(Boolean)).toHaveLength(10);
    await new Promise((res) => setTimeout(res, 650));
    expect(await a.allowRateLimit('ip:1', 10, 500)).toBe(true);
  });

  describe('siteverify idempotency', () => {
    it('20 concurrent identical requests across two instances compute once and agree', async () => {
      const p = `${prefix}i1:`; const sa = new RedisSiteverifyIdempotencyStore(A, p), sb = new RedisSiteverifyIdempotencyStore(B, p);
      let computed = 0;
      const compute = async () => { computed++; await new Promise((r) => setTimeout(r, 200)); return { success: true as const, 'error-codes': [] as string[] }; };
      const out = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? sa : sb).getOrCompute('k1', 5_000, compute)));
      expect(computed).toBe(1);
      expect(new Set(out.map((o) => JSON.stringify(o))).size).toBe(1);
    });
    it('a crashed lock owner (lock left behind) is waited out, then another instance computes', async () => {
      const p = `${prefix}i2:`; const digest = base64urlEncode(sha256(utf8('k2')));
      await admin.set(`${p}{${digest}}:lock`, 'dead-owner', 'PX', 700, 'NX');
      const t0 = Date.now(); let computed = 0;
      const out = await new RedisSiteverifyIdempotencyStore(B, p, 5_000).getOrCompute('k2', 5_000, async () => { computed++; return { success: false, 'error-codes': ['x'] }; });
      expect(computed).toBe(1); expect(out.success).toBe(false); expect(Date.now() - t0).toBeGreaterThanOrEqual(600);
    });
    it('a failing compute releases the lock so the next caller can retry', async () => {
      const s = new RedisSiteverifyIdempotencyStore(A, `${prefix}i3:`);
      await expect(s.getOrCompute('k3', 5_000, async () => { throw new Error('boom'); })).rejects.toThrow('boom');
      expect((await s.getOrCompute('k3', 5_000, async () => ({ success: true, 'error-codes': [] }))).success).toBe(true);
    });
    it('a compute longer than the lock TTL keeps its lease via the heartbeat (12 s)', async () => {
      const p = `${prefix}i4:`; const sa = new RedisSiteverifyIdempotencyStore(A, p, 20_000), sb = new RedisSiteverifyIdempotencyStore(B, p, 20_000);
      let computed = 0;
      const slow = async () => { computed++; await new Promise((r) => setTimeout(r, 12_000)); return { success: true as const, 'error-codes': [] as string[] }; };
      const [x, y] = await Promise.all([sa.getOrCompute('k4', 30_000, slow), (async () => { await new Promise((r) => setTimeout(r, 300)); return sb.getOrCompute('k4', 30_000, slow); })()]);
      expect(computed).toBe(1); expect(x).toEqual(y);
    }, 40_000);
  });

  describe('failure behaviour (fail closed)', () => {
    it('an unreachable Redis surfaces as StoreUnavailableError, never as "not a replay"', async () => {
      const dead = await connect({ port: 1, host: '127.0.0.1', lazyConnect: true, enableOfflineQueue: false, retryStrategy: () => null });
      await expect(new RedisSecurityStore(dead, `${prefix}x:`, 960_000, { commandTimeoutMs: 300 }).checkAndInsert('k')).rejects.toBeInstanceOf(StoreUnavailableError);
    });
    it('a stalled Redis (CLIENT PAUSE) times out closed and recovers afterwards', async () => {
      const s = new RedisSecurityStore(A, `${prefix}p:`, 960_000, { commandTimeoutMs: 250 });
      await admin.call('CLIENT', 'PAUSE', '1200', 'ALL');
      await expect(s.checkAndInsert('during-pause')).rejects.toBeInstanceOf(StoreUnavailableError);
      await new Promise((r) => setTimeout(r, 1300));
      expect(await new RedisSecurityStore(B, `${prefix}p:`).checkAndInsert('after-pause')).toBe(true);
    });
    it('nullifiers survive a Redis restart-equivalent (DEBUG RELOAD with AOF/RDB persistence)', async () => {
      const [a] = stores(`${prefix}d:`);
      expect(await a.checkAndInsert('persisted', 120_000)).toBe(true);
      await admin.call('DEBUG', 'RELOAD');
      expect(await a.checkAndInsert('persisted', 120_000)).toBe(false);
    });
  });

  describe('WebAuthn credential store', () => {
    const cred = (id: string, ttl = 60_000): StoredWebAuthnCredential => ({ credentialId: id, publicKeySpki: 'x'.repeat(100), signCount: 0, createdAt: Date.now(), expiresAt: Date.now() + ttl, origin: ORIGIN });
    it('create is race-free, the counter CAS has exactly one winner, revoke and expiry work', async () => {
      const a = new RedisWebAuthnCredentialStore(A, `${prefix}w:`), b = new RedisWebAuthnCredentialStore(B, `${prefix}w:`);
      const created = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? a : b).create(cred('cred-A'))));
      expect(created.filter(Boolean)).toHaveLength(1);
      const cas = await Promise.all(Array.from({ length: 30 }, (_, i) => (i % 2 ? a : b).updateSignCount('cred-A', 0, i + 1)));
      expect(cas.filter(Boolean)).toHaveLength(1);
      expect(await a.revoke('cred-A')).toBe(true);
      expect(await b.get('cred-A')).toBeUndefined();
      await a.create(cred('cred-B', 1_100));
      await new Promise((r) => setTimeout(r, 1_300));
      expect(await b.get('cred-B')).toBeUndefined();
      expect(MemoryWebAuthnCredentialStore).toBeDefined();
    });
  });

  describe('two verifier instances sharing Redis', () => {
    const pair = () => {
      const p = `${prefix}v${base64urlEncode(randomBytes(4))}:`;
      const first = makeVerifier({ nullifiers: new RedisSecurityStore(A, p), attempts: new RedisSecurityStore(A, p) });
      const secrets = first.verifier as unknown as { opts: { challengeSecret: Uint8Array; voprfSecretKey: Uint8Array } };
      const second = makeVerifier({ challengeSecret: secrets.opts.challengeSecret, voprfSecretKey: secrets.opts.voprfSecretKey, nullifiers: new RedisSecurityStore(B, p), attempts: new RedisSecurityStore(B, p) });
      return [first.verifier, second.verifier] as const;
    };
    const finish = (b: ReturnType<typeof buildRequest>, token: string) => base64urlEncode(serializeToken(completeIssuance(b.pending, decodeIssuance(token), base64urlDecode(b.ch.publicKey))));
    it('a token issued by instance 1 redeems on instance 2 exactly once; a replay on either instance fails', async () => {
      const [v1, v2] = pair();
      const b = buildRequest(v1.challenge(ORIGIN), {});
      const issued = await v1.issue(ORIGIN, b.req); if (issued.status !== 'TOKEN_ISSUED') throw new Error('not issued');
      const token = finish(b, issued.token);
      expect((await siteverify(v2, { secret: SECRET, response: token })).success).toBe(true);
      expect((await siteverify(v1, { secret: SECRET, response: token })).success).toBe(false);
      expect((await siteverify(v2, { secret: SECRET, response: token })).success).toBe(false);
    });
    it('concurrent redemption of one token on both instances yields exactly one success', async () => {
      const [v1, v2] = pair();
      const b = buildRequest(v1.challenge(ORIGIN), {});
      const issued = await v1.issue(ORIGIN, b.req); if (issued.status !== 'TOKEN_ISSUED') throw new Error('not issued');
      const token = finish(b, issued.token);
      const r = await Promise.all(Array.from({ length: 40 }, (_, i) => siteverify(i % 2 ? v1 : v2, { secret: SECRET, response: token })));
      expect(r.filter((x) => x.success)).toHaveLength(1);
    });
    it('concurrent issuance on one challenge across both instances mints exactly one token', async () => {
      const [v1, v2] = pair();
      const ch = v1.challenge(ORIGIN);
      const reqs = Array.from({ length: 6 }, () => buildRequest(ch, {}).req);
      const r = await Promise.allSettled(reqs.map((req, i) => (i % 2 ? v1 : v2).issue(ORIGIN, req)));
      expect(r.filter((x) => x.status === 'fulfilled' && x.value.status === 'TOKEN_ISSUED')).toHaveLength(1);
    });
  });
});
