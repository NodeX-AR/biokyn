import { describe, expect, it } from 'vitest';
import { MemoryChallengeAttemptStore, SlidingNullifierCache, SlidingWindowRateLimiter, StoreCapacityError } from '../src/nullifier.js';
import { RedisSecurityStore, RedisSiteverifyIdempotencyStore } from '../src/redis-store.js';
import { parseSiteverifyBody } from '../src/siteverify.js';

describe('hardening regressions', () => {
  it('does not evict replay entries when the nullifier cache is full', () => {
    const cache = new SlidingNullifierCache({ maxEntries: 1, ttlMs: 60_000, now: () => 1_000 });
    expect(cache.checkAndInsert('token:one')).toBe(true);
    expect(() => cache.checkAndInsert('token:two')).toThrow(StoreCapacityError);
    expect(cache.checkAndInsert('token:one')).toBe(false);
    expect(cache.size).toBe(1);
  });
  it('bounds the rate-limiter key map and fails closed at capacity', () => {
    const limiter = new SlidingWindowRateLimiter(10, 60_000, () => 1_000, 1);
    expect(limiter.allow('client:one')).toBe(true);
    expect(limiter.allow('client:two')).toBe(false);
  });
  it('limits attempts atomically and fails closed when its bounded store is full', () => {
    let now = 1_000;
    const attempts = new MemoryChallengeAttemptStore(() => now, 1);
    expect(attempts.consumeAttempt('challenge:a', 2, 1_000)).toBe(true);
    expect(attempts.consumeAttempt('challenge:a', 2, 1_000)).toBe(true);
    expect(attempts.consumeAttempt('challenge:a', 2, 1_000)).toBe(false);
    expect(() => attempts.consumeAttempt('challenge:b', 2, 1_000)).toThrow(StoreCapacityError);
    now += 1_001;
    expect(attempts.consumeAttempt('challenge:b', 2, 1_000)).toBe(true);
  });
  it('shares siteverify idempotency through Redis and computes one result for concurrent callers', async () => {
    const values = new Map<string, { value: string; expires: number }>();
    const redis = {
      async get(key: string) { const v = values.get(key); if (!v || v.expires <= Date.now()) { values.delete(key); return null; } return v.value; },
      async set(key: string, value: string, _mode: 'PX', ttl: number, condition: 'NX') {
        const current = values.get(key);
        if (condition === 'NX' && current && current.expires > Date.now()) return null;
        values.set(key, { value, expires: Date.now() + ttl }); return 'OK';
      },
      async eval(script: string, _keys: number, ...args: Array<string | number>) {
        if (script.includes("redis.call('GET', KEYS[1]) == ARGV[1]")) {
          const [key, owner] = args as [string, string];
          if (values.get(key)?.value === owner) values.delete(key);
          return 1;
        }
        if (script.includes("redis.call('PEXPIRE', KEYS[1], ARGV[2])")) {
          const [key, owner] = args as [string, string];
          return values.get(key)?.value === owner ? 1 : 0;
        }
        if (script.includes("redis.call('EXISTS', KEYS[2]) == 1")) {
          const [lockKey, cacheKey, owner, raw, ttl] = args as [string, string, string, string, number];
          if (values.get(lockKey)?.value !== owner) return 0;
          const cached = values.get(cacheKey);
          if (cached && cached.expires > Date.now()) return 2;
          values.set(cacheKey, { value: raw, expires: Date.now() + ttl });
          return 1;
        }
        return 1;
      },
    };
    const store = new RedisSiteverifyIdempotencyStore(redis, 'test:', 1_000);
    let computes = 0;
    const compute = async () => { computes++; await new Promise((resolve) => setTimeout(resolve, 30)); return { success: true, score: 0.9, 'error-codes': [] as string[] }; };
    const [a, b] = await Promise.all([store.getOrCompute('same-request', 5_000, compute), store.getOrCompute('same-request', 5_000, compute)]);
    expect(computes).toBe(1);
    expect(a).toEqual(b);
    expect(await store.getOrCompute('same-request', 5_000, compute)).toEqual(a);
    expect(computes).toBe(1);
  });

  it('refuses to publish a siteverify result after the Redis lock lease has been lost', async () => {
    const redis = {
      async get(_key: string) { return null; },
      async set(_key: string, _value: string, _mode: 'PX', _ttl: number, _condition: 'NX') { return 'OK'; },
      async eval(script: string, _keys: number, ..._args: Array<string | number>) {
        if (script.includes("redis.call('EXISTS', KEYS[2]) == 1")) return 0; // lock ownership no longer matches
        return 0;
      },
    };
    const store = new RedisSiteverifyIdempotencyStore(redis, 'lease-test:', 500);
    await expect(store.getOrCompute('lease-lost', 5_000, async () => ({ success: true, 'error-codes': [] })))
      .rejects.toThrow(/could not be committed by the lock owner/);
  });

  it('uses atomic Redis primitives for shared replay and attempt state', async () => {
    const calls: Array<{ command: string; args: unknown[] }> = [];
    const redis = {
      async set(...args: [string, string, 'PX', number, 'NX']) { calls.push({ command: 'set', args }); return 'OK' as const; },
      async eval(...args: [string, number, ...Array<string | number>]) { calls.push({ command: 'eval', args }); return 1; },
    };
    const store = new RedisSecurityStore(redis);
    expect(await store.checkAndInsert('token:abc', 1_260_000)).toBe(true);
    expect(await store.consumeAttempt('challenge:abc', 4, 120_000)).toBe(true);
    expect(await store.allowRateLimit('ip:192.0.2.1', 20, 60_000)).toBe(true);
    expect(calls.map((c) => c.command)).toEqual(['set', 'eval', 'eval']);
    expect(calls[0]?.args[2]).toBe('PX');
    expect(calls[0]?.args[3]).toBe(1_260_000);
    expect(String(calls[2]?.args[0])).toContain("redis.call('TIME')");
    expect(calls[0]?.args[4]).toBe('NX');
  });
  it('parses form-encoded /siteverify payloads', () => {
    expect(parseSiteverifyBody('application/x-www-form-urlencoded', 'secret=abc&response=token&idempotency_key=retry-1')).toEqual({ secret: 'abc', response: 'token', idempotency_key: 'retry-1', remoteip: undefined, sitekey: undefined });
  });
});
