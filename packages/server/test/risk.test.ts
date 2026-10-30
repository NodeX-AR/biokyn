import { describe, expect, it } from 'vitest';
import { assessRisk } from '../src/risk.js';

describe('assessRisk', () => {
  it('caps client-untrusted evidence and explains the result', () => {
    const result = assessRisk([
      { id: 'server_velocity', weight: 20, source: 'server' },
      { id: 'client_motion', weight: 90, source: 'client-untrusted' },
    ]);
    expect(result.score).toBe(35);
    expect(result.band).toBe('medium');
    expect(result.requiresStepUp).toBe(true);
    expect(result.denyRecommended).toBe(false);
    expect(result.reasons).toEqual(['server_velocity', 'client_motion']);
  });
  it('rejects invalid policies and evidence', () => {
    expect(() => assessRisk([], { stepUpAt: 80, denyAt: 20 })).toThrow();
    expect(() => assessRisk([{ id: 'bad id', weight: 1, source: 'server' }])).toThrow();
    expect(() => assessRisk([{ id: 'bad_weight', weight: -1, source: 'server' }])).toThrow();
  });
  it('deduplicates reason identifiers', () => {
    expect(assessRisk([
      { id: 'same_signal', weight: 2, source: 'server' },
      { id: 'same_signal', weight: 3, source: 'server' },
    ]).reasons).toEqual(['same_signal']);
  });
});
