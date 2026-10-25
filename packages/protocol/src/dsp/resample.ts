/**
 * Uniform temporal resampler.
 *
 * Raw pointer streams arrive at wildly different, jittery rates (1000 Hz gaming mice,
 * 125 Hz office mice, 60/120 Hz touch, 30 Hz battery saver). Spectral analysis requires a
 * uniform grid, so every stream is interpolated onto dt = 10 ms (100 Hz).
 *
 *   linear:  x(k) = x_i + (kΔt - t_i)/(t_{i+1} - t_i) · (x_{i+1} - x_i)
 *   hermite: cubic Hermite with non-uniform three-point finite-difference tangents.
 *
 * Interpolation cannot create information above the native Nyquist frequency, so the result
 * carries `nativeRateHz`; downstream spectral code clamps its analysis band accordingly.
 */
import { ProtocolError } from '../bytes.js';

export interface RawSample {
  /** Timestamp in milliseconds (monotonic clock, e.g. PointerEvent.timeStamp). */
  t: number;
  x: number;
  y: number;
}

export type InterpolationMethod = 'linear' | 'hermite';

export interface ResampleOptions {
  dtMs?: number; // default 10
  method?: InterpolationMethod; // default 'hermite'
  /** Gaps longer than this split the stream (pointer idle / tab hidden). Default 100 ms. */
  maxGapMs?: number;
  /** Minimum raw samples for a segment to be kept. Default 8. */
  minRawSamples?: number;
}

export interface ResampledSeries {
  t0: number;
  dtMs: number;
  fs: number;
  n: number;
  x: Float64Array;
  y: Float64Array;
  /** Median native sampling rate of the raw segment (Hz). */
  nativeRateHz: number;
}

/** Drop non-finite samples, require non-decreasing time, collapse duplicate timestamps (keep last). */
export function normalizeSamples(samples: readonly RawSample[]): RawSample[] {
  const out: RawSample[] = [];
  for (const s of samples) {
    if (!Number.isFinite(s.t) || !Number.isFinite(s.x) || !Number.isFinite(s.y)) continue;
    const last = out[out.length - 1];
    if (last) {
      if (s.t < last.t) throw new ProtocolError('NON_MONOTONIC', 'timestamps must be non-decreasing');
      if (s.t === last.t) {
        out[out.length - 1] = { t: s.t, x: s.x, y: s.y };
        continue;
      }
    }
    out.push({ t: s.t, x: s.x, y: s.y });
  }
  return out;
}

export function splitAtGaps(samples: readonly RawSample[], maxGapMs: number): RawSample[][] {
  const segs: RawSample[][] = [];
  let cur: RawSample[] = [];
  for (const s of samples) {
    const last = cur[cur.length - 1];
    if (last && s.t - last.t > maxGapMs) {
      segs.push(cur);
      cur = [];
    }
    cur.push(s);
  }
  if (cur.length) segs.push(cur);
  return segs;
}

function median(a: number[]): number {
  const b = [...a].sort((p, q) => p - q);
  const m = b.length >> 1;
  return b.length % 2 ? b[m]! : (b[m - 1]! + b[m]!) / 2;
}

function tangents(t: number[], v: number[]): Float64Array {
  const n = t.length;
  const m = new Float64Array(n);
  if (n < 2) return m;
  m[0] = (v[1]! - v[0]!) / (t[1]! - t[0]!);
  m[n - 1] = (v[n - 1]! - v[n - 2]!) / (t[n - 1]! - t[n - 2]!);
  for (let i = 1; i < n - 1; i++) {
    const h0 = t[i]! - t[i - 1]!;
    const h1 = t[i + 1]! - t[i]!;
    const d0 = (v[i]! - v[i - 1]!) / h0;
    const d1 = (v[i + 1]! - v[i]!) / h1;
    m[i] = (h1 * d0 + h0 * d1) / (h0 + h1);
  }
  return m;
}

/** Resample ONE contiguous, normalized segment. */
export function resample(segment: readonly RawSample[], opts: ResampleOptions = {}): ResampledSeries {
  const dt = opts.dtMs ?? 10;
  const method = opts.method ?? 'hermite';
  if (!(dt > 0)) throw new ProtocolError('BAD_DT', 'dtMs must be > 0');
  if (segment.length < 2) throw new ProtocolError('TOO_SHORT', 'need at least 2 samples');

  const t = segment.map((s) => s.t);
  const xs = segment.map((s) => s.x);
  const ys = segment.map((s) => s.y);
  for (let i = 1; i < t.length; i++) {
    if (!(t[i]! > t[i - 1]!)) throw new ProtocolError('NON_MONOTONIC', 'segment must be strictly increasing; call normalizeSamples');
  }
  const t0 = t[0]!;
  const span = t[t.length - 1]! - t0;
  const n = Math.floor(span / dt + 1e-9) + 1;
  const outX = new Float64Array(n);
  const outY = new Float64Array(n);
  const mx = method === 'hermite' ? tangents(t, xs) : null;
  const my = method === 'hermite' ? tangents(t, ys) : null;

  let j = 0;
  for (let k = 0; k < n; k++) {
    const tk = t0 + k * dt;
    while (j < t.length - 2 && t[j + 1]! < tk) j++;
    const ta = t[j]!;
    const tb = t[j + 1]!;
    const h = tb - ta;
    const s = Math.min(1, Math.max(0, (tk - ta) / h));
    if (method === 'linear') {
      outX[k] = xs[j]! + s * (xs[j + 1]! - xs[j]!);
      outY[k] = ys[j]! + s * (ys[j + 1]! - ys[j]!);
    } else {
      const s2 = s * s;
      const s3 = s2 * s;
      const h00 = 2 * s3 - 3 * s2 + 1;
      const h10 = s3 - 2 * s2 + s;
      const h01 = -2 * s3 + 3 * s2;
      const h11 = s3 - s2;
      outX[k] = h00 * xs[j]! + h10 * h * mx![j]! + h01 * xs[j + 1]! + h11 * h * mx![j + 1]!;
      outY[k] = h00 * ys[j]! + h10 * h * my![j]! + h01 * ys[j + 1]! + h11 * h * my![j + 1]!;
    }
  }

  const dts: number[] = [];
  for (let i = 1; i < t.length; i++) dts.push(t[i]! - t[i - 1]!);
  return { t0, dtMs: dt, fs: 1000 / dt, n, x: outX, y: outY, nativeRateHz: 1000 / median(dts) };
}

/** Normalize, split at idle gaps, and resample every usable segment. */
export function resampleSegments(samples: readonly RawSample[], opts: ResampleOptions = {}): ResampledSeries[] {
  const maxGap = opts.maxGapMs ?? 100;
  const minRaw = opts.minRawSamples ?? 8;
  return splitAtGaps(normalizeSamples(samples), maxGap)
    .filter((s) => s.length >= minRaw)
    .map((s) => resample(s, opts));
}
