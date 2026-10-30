/**
 * Sliding-window nullifier cache (replay / double-spend prevention).
 *
 * A ring of B time buckets, each a Set. Bucket width is ceil(ttl / (B − 1)), so an entry is retained for
 * at least `ttl` and at most ttl + one bucket width, and expiry is O(B) bucket resets rather than a
 * per-entry timer or scan. `checkAndInsert` is atomic because it runs synchronously on the (single-threaded)
 * JS event loop; for multi-process deployments implement {@link NullifierStore} on a shared store (e.g. Redis
 * SET NX PX) and inject it.
 *
 * Capacity policy defaults to FAIL CLOSED: when full, new keys are refused rather than evicting entries that
 * would reopen a replay window.
 */
export interface NullifierStore {
  /** Returns true if `key` was fresh and has now been recorded; false if it was already present (replay). */
  checkAndInsert(key: string, ttlMs?: number): boolean | Promise<boolean>;
}

export interface SlidingNullifierOptions {
  ttlMs?: number;
  buckets?: number;
  maxEntries?: number;
  onFull?: 'reject' | 'evict-oldest';
  now?: () => number;
}

export class SlidingNullifierCache implements NullifierStore {
  private readonly slots: Array<Set<string>>;
  private readonly epochs: number[];
  private readonly bucketMs: number;
  private readonly B: number;
  private readonly maxEntries: number;
  private readonly onFull: 'reject' | 'evict-oldest';
  private readonly now: () => number;
  private count = 0;
  rejectedFull = 0;

  constructor(opts: SlidingNullifierOptions = {}) {
    const ttl = opts.ttlMs ?? 300_000;
    this.B = Math.max(3, Math.floor(opts.buckets ?? 10));
    this.bucketMs = Math.max(1, Math.ceil(ttl / (this.B - 1)));
    this.maxEntries = opts.maxEntries ?? 1_000_000;
    this.onFull = opts.onFull ?? 'reject';
    this.now = opts.now ?? Date.now;
    this.slots = Array.from({ length: this.B }, () => new Set<string>());
    this.epochs = new Array<number>(this.B).fill(-1);
  }

  get size(): number { return this.count; }
  get retentionMs(): number { return (this.B - 1) * this.bucketMs; }

  private advance(epoch: number): void {
    for (let i = 0; i < this.B; i++) {
      const e = this.epochs[i]!;
      if (e !== -1 && epoch - e >= this.B) {
        this.count -= this.slots[i]!.size;
        this.slots[i]!.clear();
        this.epochs[i] = -1;
      }
    }
  }

  checkAndInsert(key: string, ttlMs = this.retentionMs): boolean {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new RangeError('nullifier TTL must be a positive integer');
    // This ring is sized at construction time. Never silently accept a per-key TTL longer than
    // its actual retention window; callers must configure the cache for their maximum token lifetime.
    if (ttlMs > this.retentionMs) throw new RangeError('requested nullifier TTL exceeds configured cache retention');
    const epoch = Math.floor(this.now() / this.bucketMs);
    this.advance(epoch);
    for (let i = 0; i < this.B; i++) if (this.epochs[i] !== -1 && this.slots[i]!.has(key)) return false;

    if (this.count >= this.maxEntries) {
      if (this.onFull === 'reject') { this.rejectedFull++; throw new StoreCapacityError('nullifier store capacity reached'); }
      let oldest = -1, oldestEpoch = Infinity;
      for (let i = 0; i < this.B; i++) if (this.epochs[i] !== -1 && this.epochs[i]! < oldestEpoch && this.slots[i]!.size > 0) { oldest = i; oldestEpoch = this.epochs[i]!; }
      if (oldest >= 0) { this.count -= this.slots[oldest]!.size; this.slots[oldest]!.clear(); }
    }
    const slot = epoch % this.B;
    this.epochs[slot] = epoch;
    this.slots[slot]!.add(key);
    this.count++;
    return true;
  }
}



/** Raised when a shared security store is unreachable, slow, or returns an error. Callers MUST fail closed (HTTP 503). */
export class StoreUnavailableError extends Error {
  constructor(message = 'security store unavailable', options?: { cause?: unknown }) { super(message, options); this.name = 'StoreUnavailableError'; }
}

/** Raised when a bounded in-process security store cannot safely record new state. */
export class StoreCapacityError extends Error {
  constructor(message = 'security store capacity reached') { super(message); this.name = 'StoreCapacityError'; }
}

/** Atomic challenge-attempt counter. Production implementations must use a shared datastore primitive
 * (for example Redis INCR + expiry in one script), never a process-local map. */
export interface ChallengeAttemptStore {
  /** Atomically record one attempt. Returns true only while the challenge remains under maxAttempts. */
  consumeAttempt(challengeId: string, maxAttempts: number, ttlMs: number): boolean | Promise<boolean>;
}

/** Bounded development/test implementation. It fails closed at capacity and is not multi-process safe. */
export class MemoryChallengeAttemptStore implements ChallengeAttemptStore {
  private readonly entries = new Map<string, { count: number; expiresAt: number }>();
  private operations = 0;
  constructor(private readonly now: () => number = Date.now, private readonly maxEntries = 100_000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) throw new RangeError('maxEntries must be a positive integer');
  }
  consumeAttempt(challengeId: string, maxAttempts: number, ttlMs: number): boolean {
    const now = this.now();
    if (++this.operations % 128 === 0 || this.entries.size >= this.maxEntries) {
      for (const [key, value] of this.entries) if (value.expiresAt <= now) this.entries.delete(key);
    }
    let entry = this.entries.get(challengeId);
    if (entry && entry.expiresAt <= now) { this.entries.delete(challengeId); entry = undefined; }
    if (!entry) {
      if (this.entries.size >= this.maxEntries) throw new StoreCapacityError('challenge attempt store capacity reached');
      entry = { count: 0, expiresAt: now + ttlMs };
      this.entries.set(challengeId, entry);
    }
    entry.count += 1;
    return entry.count <= maxAttempts;
  }
}

/** Fixed-window-per-key limiter for the HTTP layer (the verifier itself is IP-agnostic). */
export class SlidingWindowRateLimiter {
  private readonly hits = new Map<string, number[]>();
  private ops = 0;
  constructor(private readonly limit: number, private readonly windowMs: number, private readonly now: () => number = Date.now, private readonly maxKeys = 100_000) {}

  /** Returns true if allowed. New keys fail closed if the bounded map is full. */
  allow(key: string): boolean {
    const t = this.now(); const cutoff = t - this.windowMs;
    const existing = this.hits.get(key);
    if (++this.ops % 256 === 0) for (const [k, v] of this.hits) if (v.length === 0 || v[v.length - 1]! <= cutoff) this.hits.delete(k);
    if (!existing && this.hits.size >= this.maxKeys) return false;
    const arr = (existing ?? []).filter((x) => x > cutoff);
    if (arr.length >= this.limit) { this.hits.set(key, arr); return false; }
    arr.push(t); this.hits.set(key, arr); return true;
  }
}
