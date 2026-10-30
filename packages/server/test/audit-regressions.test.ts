import { describe, expect, it } from 'vitest';
import { MemoryChallengeAttemptStore, SlidingNullifierCache, StoreCapacityError } from '../src/nullifier.js';

describe('audit regression protections', () => {
  it('retains nullifiers for the configured redemption window and rejects an undersized per-key TTL', () => {
    let now = 0;
    const store = new SlidingNullifierCache({ ttlMs: 960_000, buckets: 10, now: () => now, maxEntries: 10 });
    expect(store.checkAndInsert('token-1', 960_000)).toBe(true);
    expect(store.checkAndInsert('token-1', 960_000)).toBe(false);
    expect(() => store.checkAndInsert('token-2', 1_000_000)).toThrow(/exceeds configured cache retention/);
    now = 1_100_000;
    expect(store.checkAndInsert('token-1', 960_000)).toBe(true);
  });

  it('reports challenge-attempt store capacity as unavailable, not exhausted', () => {
    const store = new MemoryChallengeAttemptStore(() => 0, 1);
    expect(store.consumeAttempt('challenge-a', 4, 10_000)).toBe(true);
    expect(() => store.consumeAttempt('challenge-b', 4, 10_000)).toThrow(StoreCapacityError);
  });
});
