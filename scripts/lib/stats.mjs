/** Small, dependency-free statistics used by the evaluation tooling. */
const Z95 = 1.959963984540054;

/** Wilson score interval for a binomial proportion (well-behaved at 0 and n, unlike the normal approximation). */
export function wilson(k, n, z = Z95) {
  if (!Number.isInteger(k) || !Number.isInteger(n) || n < 0 || k < 0 || k > n) throw new RangeError('invalid counts');
  if (n === 0) return { p: NaN, lo: 0, hi: 1 };
  const p = k / n, z2 = z * z, denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return { p, lo: Math.max(0, centre - half), hi: Math.min(1, centre + half) };
}

/** Samples needed so that the (normal-approx.) CI half-width is at most `halfWidth` for an expected rate `p`. */
export function requiredSamples(p, halfWidth, z = Z95) {
  if (!(halfWidth > 0 && halfWidth < 1) || p < 0 || p > 1) throw new RangeError('invalid parameters');
  return Math.ceil((z * z * p * (1 - p)) / (halfWidth * halfWidth));
}

/** "Rule of three": with 0 events in n trials the 95% upper bound on the rate is about 3/n. */
export const ruleOfThree = (n) => (n > 0 ? 3 / n : 1);
