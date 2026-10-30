import { base64urlEncode, randomBytes, sha256, utf8 } from '@biokyn/protocol';
import { StoreUnavailableError, type ChallengeAttemptStore, type NullifierStore } from './nullifier.js';
import type { SiteverifyBody, SiteverifyIdempotencyStore } from './siteverify.js';

/** Minimal ioredis-compatible command surface. Keep Redis access behind this small interface so callers can
 * supply a shared, TLS-authenticated Redis client without coupling BioKyn to one Redis package. */
export interface RedisAtomicClient {
  get?(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'PX', ttlMs: number, condition: 'NX'): Promise<string | null | undefined>;
  eval(script: string, numberOfKeys: number, ...args: Array<string | number>): Promise<number | string>;
}

export interface RedisStoreOptions {
  /** Upper bound on any single Redis command. A slow Redis is treated like a down Redis: fail closed. Default 1000 ms. */
  commandTimeoutMs?: number;
}

/**
 * Wraps a Redis client so that every command is time-bounded and every failure (connection loss, timeout, script
 * error, OOM, READONLY after failover) surfaces as StoreUnavailableError. The verifier maps that to HTTP 503 and
 * never accepts a token or issues one while shared state cannot be consulted.
 */
export function guardRedis(redis: RedisAtomicClient, commandTimeoutMs = 1_000): RedisAtomicClient {
  if (!Number.isSafeInteger(commandTimeoutMs) || commandTimeoutMs < 50 || commandTimeoutMs > 30_000) throw new RangeError('commandTimeoutMs must be from 50 to 30000');
  const bound = async <T>(op: () => Promise<T>): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        op(),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('redis command timed out')), commandTimeoutMs); }),
      ]);
    } catch (cause) { throw new StoreUnavailableError('redis unavailable', { cause }); }
    finally { if (timer) clearTimeout(timer); }
  };
  const guarded: RedisAtomicClient = {
    set: (key, value, mode, ttl, cond) => bound(() => redis.set(key, value, mode, ttl, cond)),
    eval: (script, n, ...args) => bound(() => redis.eval(script, n, ...args)),
  };
  if (typeof redis.get === 'function') guarded.get = (key) => bound(() => redis.get!(key));
  return guarded;
}

const RATE_LIMIT_SCRIPT = `
-- Use Redis server time so app-server clock skew cannot reset or extend a rate-limit window.
local t = redis.call('TIME')
local now = (tonumber(t[1]) * 1000) + math.floor(tonumber(t[2]) / 1000)
local window = tonumber(ARGV[1])
local cutoff = now - window
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
local count = redis.call('ZCARD', KEYS[1])
if count >= tonumber(ARGV[2]) then return 0 end
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], window)
return 1
`;

const ATTEMPT_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
-- Repair keys restored without expiry; never let an attempt counter become permanent.
if current == 1 or redis.call('PTTL', KEYS[1]) < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
if current > tonumber(ARGV[1]) then return 0 end
return 1
`;

/**
 * Shared atomic replay/attempt store for multi-instance deployments.
 *
 * Compatible with ioredis-style `set(key, value, 'PX', ttl, 'NX')` and `eval(script, numKeys, ...args)`.
 * Use a dedicated Redis deployment or namespace, TLS, authentication, bounded network access and monitoring.
 * Do not use Redis eviction policies that can evict live security keys; configure `noeviction` or an isolated
 * instance with sufficient memory. A Redis outage fails closed.
 */
export class RedisSecurityStore implements NullifierStore, ChallengeAttemptStore {
  private readonly redis: RedisAtomicClient;
  constructor(redis: RedisAtomicClient, private readonly prefix = 'biokyn:v1:', private readonly nullifierTtlMs = 960_000, opts: RedisStoreOptions = {}) {
    this.redis = guardRedis(redis, opts.commandTimeoutMs);
    if (!prefix || prefix.length > 128) throw new RangeError('Redis key prefix must be 1-128 characters');
    if (!Number.isSafeInteger(nullifierTtlMs) || nullifierTtlMs < 1_000) throw new RangeError('nullifier TTL must be at least 1000ms');
  }

  private key(kind: string, value: string): string {
    const digest = base64urlEncode(sha256(utf8(value)));
    // {hash tag}: every key for one logical value maps to one Redis Cluster slot (multi-key scripts stay valid).
    return `${this.prefix}${kind}:{${digest}}`;
  }

  async checkAndInsert(key: string, ttlMs = this.nullifierTtlMs): Promise<boolean> {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000) throw new RangeError('nullifier TTL must be at least 1000ms');
    const result = await this.redis.set(this.key('used', key), '1', 'PX', ttlMs, 'NX');
    return result === 'OK';
  }

  /** Atomic sliding-window limiter. `key` must be derived from trusted proxy/client identity by the caller.
   * All timestamps are taken inside Redis to avoid client clock skew across application instances. */
  async allowRateLimit(key: string, limit: number, windowMs: number): Promise<boolean> {
    if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError('limit must be positive');
    if (!Number.isSafeInteger(windowMs) || windowMs < 1) throw new RangeError('windowMs must be positive');
    const member = base64urlEncode(randomBytes(16));
    const result = await this.redis.eval(RATE_LIMIT_SCRIPT, 1, this.key('rate', key), windowMs, limit, member);
    return Number(result) === 1;
  }

  async consumeAttempt(challengeId: string, maxAttempts: number, ttlMs: number): Promise<boolean> {
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) throw new RangeError('maxAttempts must be positive');
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new RangeError('ttlMs must be positive');
    const result = await this.redis.eval(ATTEMPT_SCRIPT, 1, this.key('attempt', challengeId), maxAttempts, ttlMs);
    return Number(result) === 1;
  }
}


const RELEASE_LOCK_SCRIPT = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end`;
const RENEW_LOCK_SCRIPT = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE', KEYS[1], ARGV[2]) else return 0 end`;
// The cache write and ownership check happen in one Redis transaction. A stale lock owner
// must never publish a result after its lease has expired and another instance took over.
const COMMIT_RESULT_SCRIPT = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if redis.call('EXISTS', KEYS[2]) == 1 then return 2 end
redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[3])
return 1
`;

/**
 * Redis-backed cross-instance /siteverify idempotency. Requires Redis GET plus SET PX NX and EVAL.
 * Successful and failed protocol results are cached for a bounded TTL; concurrent callers wait for
 * the lock owner, then read the same result. A lock timeout fails closed rather than double-running.
 */
export class RedisSiteverifyIdempotencyStore implements SiteverifyIdempotencyStore {
  private readonly redis: RedisAtomicClient;
  constructor(redis: RedisAtomicClient, private readonly prefix = 'biokyn:siteverify:v1:', private readonly waitMs = 4_000, opts: RedisStoreOptions = {}) {
    if (typeof redis.get !== 'function') throw new TypeError('Redis client must implement GET for shared siteverify idempotency');
    if (!prefix || prefix.length > 128) throw new RangeError('Redis key prefix must be 1-128 characters');
    if (!Number.isSafeInteger(waitMs) || waitMs < 100 || waitMs > 30_000) throw new RangeError('waitMs must be from 100 to 30000');
    this.redis = guardRedis(redis, opts.commandTimeoutMs);
  }

  private async read(key: string): Promise<SiteverifyBody | undefined> {
    const raw = await this.redis.get!(key);
    if (!raw) return undefined;
    try {
      const value = JSON.parse(raw) as SiteverifyBody;
      if (typeof value.success !== 'boolean' || !Array.isArray(value['error-codes'])) return undefined;
      return { ...value, 'error-codes': [...value['error-codes']] };
    } catch { return undefined; }
  }

  async getOrCompute(key: string, ttlMs: number, compute: () => Promise<SiteverifyBody>): Promise<SiteverifyBody> {
    if (!key || key.length > 2048 || !Number.isSafeInteger(ttlMs) || ttlMs < 1000) throw new RangeError('invalid idempotency key or TTL');
    const digest = base64urlEncode(sha256(utf8(key)));
    // Shared {hash tag}: lock and result keys must live in one Cluster slot for COMMIT_RESULT_SCRIPT (2 keys).
    const cacheKey = `${this.prefix}{${digest}}:result`;
    const lockKey = `${this.prefix}{${digest}}:lock`;
    const cached = await this.read(cacheKey);
    if (cached) return cached;
    const owner = base64urlEncode(randomBytes(18));
    const lockTtl = Math.max(10_000, Math.min(60_000, ttlMs));
    const deadline = Date.now() + this.waitMs;
    for (;;) {
      const acquired = await this.redis.set(lockKey, owner, 'PX', lockTtl, 'NX');
      if (acquired === 'OK') {
        let leaseLost = false;
        let renewal: Promise<void> | undefined;
        const heartbeat = setInterval(() => {
          if (renewal || leaseLost) return;
          renewal = this.redis.eval(RENEW_LOCK_SCRIPT, 1, lockKey, owner, lockTtl)
            .then((n) => { if (Number(n) !== 1) leaseLost = true; })
            .catch(() => { leaseLost = true; })
            .finally(() => { renewal = undefined; });
        }, Math.max(1_000, Math.floor(lockTtl / 3)));
        try {
          const again = await this.read(cacheKey);
          if (again) return again;
          const result = await compute();
          if (renewal) await renewal;
          if (leaseLost) throw new Error('siteverify idempotency lock lease lost');
          const committed = Number(await this.redis.eval(COMMIT_RESULT_SCRIPT, 2, lockKey, cacheKey, owner, JSON.stringify(result), ttlMs));
          if (committed === 1) return result;
          if (committed === 2) {
            const winner = await this.read(cacheKey);
            if (winner) return winner;
          }
          throw new Error('siteverify idempotency result could not be committed by the lock owner');
        } finally {
          clearInterval(heartbeat);
          if (renewal) await renewal;
          await this.redis.eval(RELEASE_LOCK_SCRIPT, 1, lockKey, owner);
        }
      }
      const hit = await this.read(cacheKey);
      if (hit) return hit;
      if (Date.now() >= deadline) throw new Error('siteverify idempotency lock wait timed out');
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
}
