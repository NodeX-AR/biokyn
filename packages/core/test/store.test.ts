import { describe, it, expect } from 'vitest';
import { MemoryStore, StoreCapacityError } from '../src/store.js';


describe('MemoryStore capacity behavior', () => {
  it('throws an explicit capacity error rather than masquerading as replay', async () => {
    const store = new MemoryStore({ maxEntries: 1, sweepIntervalMs: 60_000 });
    try {
      expect(await store.setNx('one', 10_000)).toBe(true);
      await expect(store.setNx('two', 10_000)).rejects.toBeInstanceOf(StoreCapacityError);
      await expect(store.incr('three', 10_000)).rejects.toBeInstanceOf(StoreCapacityError);
    } finally { await store.close(); }
  });
});
