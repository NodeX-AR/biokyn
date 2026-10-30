import type { NodeRedisLike, RedisLike, SqliteLike, SqliteStatement, Store } from './types.js';

export type { Store } from './types.js';

/* ------------------------------- MemoryStore ------------------------------ */

export interface MemoryStoreOptions {
  sweepIntervalMs?: number;
  now?: () => number;
  /** Hard bound on active keys. New keys fail closed when full. */
  maxEntries?: number;
}

export class StoreCapacityError extends Error {
  readonly code = 'BIOKYN_STORE_CAPACITY';
  constructor() { super('BioKyn memory store capacity reached'); this.name = 'StoreCapacityError'; }
}

interface Entry {
  n: number;
  exp: number;
}

export class MemoryStore implements Store {
  private readonly map = new Map<string, Entry>();
  private readonly now: () => number;
  private timer: NodeJS.Timeout | undefined;
  private readonly maxEntries: number;

  constructor(o: MemoryStoreOptions = {}) {
    this.now = o.now ?? Date.now;
    this.maxEntries = Math.max(1, o.maxEntries ?? 100_000);
    this.timer = setInterval(() => this.sweep(), o.sweepIntervalMs ?? 30_000);
    this.timer.unref();
  }

  get size(): number {
    return this.map.size;
  }

  sweep(): void {
    const t = this.now();
    for (const [k, e] of this.map) if (e.exp <= t) this.map.delete(k);
  }

  async setNx(key: string, ttlMs: number): Promise<boolean> {
    if (!key || key.length > 512 || !Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('Store: invalid key or TTL');
    const t = this.now();
    const e = this.map.get(key);
    if (e && e.exp > t) return false;
    if (!this.map.has(key) && this.map.size >= this.maxEntries) {
      this.sweep();
      if (this.map.size >= this.maxEntries) throw new StoreCapacityError();
    }
    this.map.set(key, { n: 1, exp: t + ttlMs });
    return true;
  }

  async incr(key: string, ttlMs: number): Promise<number> {
    if (!key || key.length > 512 || !Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('Store: invalid key or TTL');
    const t = this.now();
    const e = this.map.get(key);
    if (!e || e.exp <= t) {
      if (!e && this.map.size >= this.maxEntries) {
        this.sweep();
        if (this.map.size >= this.maxEntries) throw new StoreCapacityError();
      }
      this.map.set(key, { n: 1, exp: t + ttlMs });
      return 1;
   }
    e.n += 1;
    return e.n;
  }

  async close(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    this.map.clear();
  }
}

/* ------------------------------- SqliteStore ------------------------------ */

const SWEEP_BATCH = 500;

export class SqliteStore implements Store {
  private ops = 0;
  private readonly delExpiredKey: SqliteStatement;
  private readonly insertIgnore: SqliteStatement;
  private readonly bump: SqliteStatement;
  private readonly getN: SqliteStatement;
  private readonly sweepBatch: SqliteStatement;

  constructor(
    private readonly db: SqliteLike,
    private readonly now: () => number = Date.now,
  ) {
    db.exec(
      `CREATE TABLE IF NOT EXISTS biokyn_kv (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         k TEXT NOT NULL UNIQUE,
         n INTEGER NOT NULL,
         exp INTEGER NOT NULL
       );
       CREATE INDEX IF NOT EXISTS biokyn_kv_exp ON biokyn_kv (exp);`,
    );
    this.delExpiredKey = db.prepare('DELETE FROM biokyn_kv WHERE k = ? AND exp <= ?');
    this.insertIgnore = db.prepare('INSERT OR IGNORE INTO biokyn_kv (k, n, exp) VALUES (?, 1, ?)');
    this.bump = db.prepare('UPDATE biokyn_kv SET n = n + 1 WHERE k = ?');
    this.getN = db.prepare('SELECT n FROM biokyn_kv WHERE k = ?');
    this.sweepBatch = db.prepare(
      `DELETE FROM biokyn_kv WHERE id IN (SELECT id FROM biokyn_kv WHERE exp <= ? LIMIT ${SWEEP_BATCH})`,
    );
  }

  private tx<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const r = fn();
      this.db.exec('COMMIT');
      return r;
    } catch (e) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        /* ignore */
      }
      throw e;
    }
  }

  /** Removes all expired rows in bounded batches. Returns number removed. */
  sweep(): number {
    let total = 0;
    for (;;) {
      const changes = Number(this.sweepBatch.run(this.now()).changes);
      total += changes;
      if (changes < SWEEP_BATCH) return total;
    }
  }

  private maybeSweep(): void {
    if (++this.ops % 100 === 0) this.sweepBatch.run(this.now());
  }

  async setNx(key: string, ttlMs: number): Promise<boolean> {
    if (!key || key.length > 512 || !Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('Store: invalid key or TTL');
    const t = this.now();
    const created = this.tx(() => {
      this.delExpiredKey.run(key, t);
      return Number(this.insertIgnore.run(key, t + ttlMs).changes) === 1;
    });
    this.maybeSweep();
    return created;
  }

  async incr(key: string, ttlMs: number): Promise<number> {
    if (!key || key.length > 512 || !Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('Store: invalid key or TTL');
    const t = this.now();
    const n = this.tx(() => {
      this.delExpiredKey.run(key, t);
      if (Number(this.insertIgnore.run(key, t + ttlMs).changes) === 1) return 1;
      this.bump.run(key);
      const row = this.getN.get(key) as { n: number } | undefined;
      return row ? Number(row.n) : 1;
    });
    this.maybeSweep();
    return n;
  }
}

/* -------------------------------- RedisStore ------------------------------ */

const INCR_LUA =
  "local n=redis.call('INCR',KEYS[1]) if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end return n";

export class RedisStore implements Store {
  constructor(
    private readonly redis: RedisLike,
    private readonly prefix = 'biokyn:',
  ) {}

  async setNx(key: string, ttlMs: number): Promise<boolean> {
    if (!key || key.length > 512 || !Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('Store: invalid key or TTL');
    const r = await this.redis.set(this.prefix + key, '1', 'EX', Math.max(1, Math.ceil(ttlMs / 1000)), 'NX');
    return r === 'OK';
  }

  async incr(key: string, ttlMs: number): Promise<number> {
    if (!key || key.length > 512 || !Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('Store: invalid key or TTL');
    const n = await this.redis.eval(INCR_LUA, 1, this.prefix + key, Math.max(1, Math.ceil(ttlMs / 1000)));
    return Number(n);
  }

  async close(): Promise<void> {
    await this.redis.quit?.();
  }
}

/** Adapts a node-redis v4 client to the RedisLike interface. */
export function adaptNodeRedis(c: NodeRedisLike): RedisLike {
  return {
    set: (key, value, _mode, seconds, _flag) => c.set(key, value, { EX: seconds, NX: true }),
    eval: (script, _numKeys, key, ...args) =>
      c.eval(script, { keys: [String(key)], arguments: args.map(String) }),
    quit: () => c.quit(),
  };
}
