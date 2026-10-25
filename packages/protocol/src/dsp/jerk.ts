/**
 * Kinematic jerk analysis (third derivative of position).
 *
 *   jerk(k) = ( x(k) - 3x(k-1) + 3x(k-2) - x(k-3) ) / Δt³        (Δt in seconds)
 *
 * Metrics per resampled segment:
 *  - dimensionless jerk  DJ = ( Σ |j|² Δt ) · T⁵ / L²   (T = duration, L = path length).
 *    A single minimum-jerk stroke has DJ = 720 exactly; human multi-stroke motion is rougher.
 *  - excess kurtosis of |j|: piecewise-linear / polyline bots have jerk ≈ 0 with sparse
 *    impulses at the vertices (huge kurtosis); noise-injected bots have near-Gaussian jerk.
 *
 * NOTE: the default bounds are provisional engineering values, NOT calibrated against a
 * population dataset. Calibrate on real captures per input modality before relying on them.
 */
import type { ResampledSeries } from './resample.js';

export function thirdDifference(x: Float64Array, dtSec: number): Float64Array {
  const n = x.length;
  if (n < 4) return new Float64Array(0);
  const d3 = dtSec * dtSec * dtSec;
  const out = new Float64Array(n - 3);
  for (let k = 3; k < n; k++) {
    out[k - 3] = (x[k]! - 3 * x[k - 1]! + 3 * x[k - 2]! - x[k - 3]!) / d3;
  }
  return out;
}

export interface JerkBounds {
  dimensionlessJerkMin: number;
  dimensionlessJerkMax: number;
  excessKurtosisMax: number;
  minSamples: number;
  /** Segments with path length below this many px are ignored (essentially stationary). */
  minPathLength: number;
}

export const DEFAULT_JERK_BOUNDS: JerkBounds = {
  dimensionlessJerkMin: 100,
  // DJ grows with T⁵ and with any position noise (pixel quantization alone gives ~1e12 over 15 s),
  // so the upper bound can only guard against absurd values; the lower bound and kurtosis carry the weight.
  dimensionlessJerkMax: 1e18,
  excessKurtosisMax: 100,
  minSamples: 24,
  minPathLength: 20,
};

export interface SegmentJerk {
  samples: number;
  durationSec: number;
  pathLength: number;
  meanSquaredJerk: number;
  rmsJerk: number;
  peakJerk: number;
  dimensionlessJerk: number;
  logDimensionlessJerk: number;
  excessKurtosis: number;
}

export type JerkVerdict = 'ok' | 'too-smooth' | 'too-rough' | 'impulsive' | 'insufficient-data';

export interface JerkResult {
  verdict: JerkVerdict;
  segments: SegmentJerk[];
  medianDimensionlessJerk: number;
  maxExcessKurtosis: number;
}

export function analyzeSegmentJerk(s: ResampledSeries, bounds: JerkBounds = DEFAULT_JERK_BOUNDS): SegmentJerk | null {
  const dt = s.dtMs / 1000;
  const jx = thirdDifference(s.x, dt);
  const jy = thirdDifference(s.y, dt);
  const m = jx.length;
  if (m < bounds.minSamples) return null;

  let path = 0;
  for (let i = 1; i < s.n; i++) path += Math.hypot(s.x[i]! - s.x[i - 1]!, s.y[i]! - s.y[i - 1]!);
  if (path < bounds.minPathLength) return null;

  const mag = new Float64Array(m);
  let sumSq = 0, peak = 0, mean = 0;
  for (let i = 0; i < m; i++) {
    const v = Math.hypot(jx[i]!, jy[i]!);
    mag[i] = v;
    sumSq += v * v;
    mean += v;
    if (v > peak) peak = v;
  }
  mean /= m;
  let m2 = 0, m4 = 0;
  for (let i = 0; i < m; i++) {
    const d = mag[i]! - mean;
    m2 += d * d;
    m4 += d * d * d * d;
  }
  m2 /= m;
  m4 /= m;
  const excessKurtosis = m2 > 0 ? m4 / (m2 * m2) - 3 : 0;

  const T = (s.n - 1) * dt;
  const integral = sumSq * dt;
  const dj = (integral * Math.pow(T, 5)) / (path * path);
  return {
    samples: m,
    durationSec: T,
    pathLength: path,
    meanSquaredJerk: sumSq / m,
    rmsJerk: Math.sqrt(sumSq / m),
    peakJerk: peak,
    dimensionlessJerk: dj,
    logDimensionlessJerk: Math.log(Math.max(dj, 1e-300)),
    excessKurtosis,
  };
}

function median(a: number[]): number {
  const b = [...a].sort((p, q) => p - q);
  const m = b.length >> 1;
  return b.length % 2 ? b[m]! : (b[m - 1]! + b[m]!) / 2;
}

export function analyzeJerk(series: readonly ResampledSeries[], bounds: JerkBounds = DEFAULT_JERK_BOUNDS): JerkResult {
  const segs: SegmentJerk[] = [];
  for (const s of series) {
    const r = analyzeSegmentJerk(s, bounds);
    if (r) segs.push(r);
  }
  if (segs.length === 0) {
    return { verdict: 'insufficient-data', segments: [], medianDimensionlessJerk: NaN, maxExcessKurtosis: NaN };
  }
  const medDj = median(segs.map((s) => s.dimensionlessJerk));
  const maxKurt = Math.max(...segs.map((s) => s.excessKurtosis));
  let verdict: JerkVerdict = 'ok';
  if (medDj < bounds.dimensionlessJerkMin) verdict = 'too-smooth';
  else if (medDj > bounds.dimensionlessJerkMax) verdict = 'too-rough';
  else if (maxKurt > bounds.excessKurtosisMax) verdict = 'impulsive';
  return { verdict, segments: segs, medianDimensionlessJerk: medDj, maxExcessKurtosis: maxKurt };
}
