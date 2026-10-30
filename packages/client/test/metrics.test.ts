import { describe, expect, it } from 'vitest';
import { computeMotionMetrics } from '../src/step-up.js';

describe('computeMotionMetrics', () => {
  it('straight constant-speed line: path ratio 1.0, zero speed variation', () => {
    const pts = Array.from({ length: 20 }, (_, i) => ({ x: i * 10, y: 0, t: i * 16 }));
    const m = computeMotionMetrics(pts, 0);
    expect(m).toMatchObject({ samples: 20, corrections: 0, pathRatioMilli: 1000, speedCvMilli: 0 });
  });
  it('a detour increases the path ratio; varying speed increases the coefficient of variation', () => {
    const pts = [{ x: 0, y: 0, t: 0 }, { x: 50, y: 80, t: 20 }, { x: 60, y: 10, t: 120 }, { x: 100, y: 0, t: 140 }];
    const m = computeMotionMetrics(pts, 2);
    expect(m.pathRatioMilli).toBeGreaterThan(1500);
    expect(m.speedCvMilli).toBeGreaterThan(300);
    expect(m.corrections).toBe(2);
  });
  it('is total on degenerate input (no NaN/Infinity, which the server would reject)', () => {
    for (const pts of [[], [{ x: 1, y: 1, t: 1 }], [{ x: 1, y: 1, t: 5 }, { x: 1, y: 1, t: 5 }]]) {
      const m = computeMotionMetrics(pts, 0);
      for (const v of Object.values(m)) expect(Number.isFinite(v)).toBe(true);
    }
  });
});
