import test from 'node:test';
import assert from 'node:assert/strict';
import { requiredSamples, ruleOfThree, wilson } from './lib/stats.mjs';

const close = (a, b, eps = 1e-4) => assert.ok(Math.abs(a - b) < eps, `${a} !~ ${b}`);
test('Wilson interval matches independently computed values', () => {
  const a = wilson(5, 100); close(a.lo, 0.021544); close(a.hi, 0.111750);   // agrees with published Wilson tables (0.0215, 0.1118)
  const z = wilson(0, 100); close(z.lo, 0); close(z.hi, 0.036993);
  const all = wilson(100, 100); close(all.lo, 0.963007); close(all.hi, 1);
  const half = wilson(50, 100); close(half.lo, 0.403832); close(half.hi, 0.596168);
});
test('Wilson validates input and handles n = 0', () => {
  assert.throws(() => wilson(5, 3)); assert.throws(() => wilson(-1, 3)); assert.throws(() => wilson(1.5, 3));
  assert.equal(wilson(0, 0).hi, 1);
});
test('sample-size and rule-of-three helpers', () => {
  assert.equal(requiredSamples(0.5, 0.05), 385);
  assert.equal(requiredSamples(0.02, 0.01), 753);
  close(ruleOfThree(1000), 0.003);
  assert.throws(() => requiredSamples(0.5, 0));
});
