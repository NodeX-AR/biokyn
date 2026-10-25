/**
 * Kinematic Theory of rapid human movements (Plamondon): delta-lognormal decomposition.
 *
 *   v(t) = D1·Λ(t; t0, μ1, σ1) − D2·Λ(t; t0, μ2, σ2),
 *   Λ(t; t0, μ, σ) = exp(−(ln(t − t0) − μ)² / (2σ²)) / (σ√(2π)(t − t0))   for t > t0
 *
 * Pipeline: resample to 100 Hz → zero-phase low-pass → tangential speed → segment into strokes at
 * pauses / deep dips → fit the 7 parameters (D1, D2, t0, μ1, σ1, μ2, σ2) of each stroke by
 * Levenberg–Marquardt from multiple starts → report fit quality (SNR) and scale-free parameters.
 *
 * WHAT THIS DOES AND DOES NOT PROVE (read before relying on it):
 *  + Plain Bézier/linear-interpolation/constant-velocity paths and PID-like profiles do not produce
 *    lognormal speed profiles, so they fit poorly (low SNR) and are flagged.
 *  + Pasted-in analytic profiles that fit "too well" (SNR above human range) and cloned strokes with
 *    near-identical parameters are flagged.
 *  − The model is also a *generator*: anyone who knows it can synthesize delta-lognormal strokes with
 *    human-range parameters plus noise. Passing proves the client can produce such strokes, not that a
 *    person did. Treat the score as one cost-raising signal, never as proof of humanity.
 *  − Evidence is client-reported; the server can validate plausibility and consistency only.
 */
import { ProtocolError } from './bytes.js';
import { lowpassZeroPhase } from './dsp/filter.js';
import { analyzeJerk, DEFAULT_JERK_BOUNDS } from './dsp/jerk.js';
import { resampleSegments, type RawSample, type ResampleOptions, type ResampledSeries } from './dsp/resample.js';
import { MODALITIES, type ContactSummary, type KinematicEvidence, type Modality, type StrokeEvidence } from './types.js';

const SQRT_2PI = Math.sqrt(2 * Math.PI);

// ------------------------------------------------------------------ model

export function lognormalPdf(t: number, t0: number, mu: number, sigma: number): number {
  const d = t - t0;
  if (d <= 1e-9) return 0;
  const z = (Math.log(d) - mu) / sigma;
  return Math.exp(-0.5 * z * z) / (sigma * SQRT_2PI * d);
}

export interface DeltaLognormalParams {
  D1: number; D2: number;
  /** Onset time (s) relative to the start of the fitted window; negative. */
  t0: number;
  mu1: number; sigma1: number; mu2: number; sigma2: number;
}

export const deltaLognormal = (t: number, p: DeltaLognormalParams): number =>
  p.D1 * lognormalPdf(t, p.t0, p.mu1, p.sigma1) - p.D2 * lognormalPdf(t, p.t0, p.mu2, p.sigma2);

// ------------------------------------------------------------------ fitting (Levenberg–Marquardt)

type Vec = number[];
const LN = Math.log;
const BOUNDS = { g: [LN(0.005), LN(0.12)], s: [LN(0.05), LN(1.5)], mu: [-5, 1.5] } as const;
const clamp = (v: number, lo: number, hi: number): number => (v < lo ? lo : v > hi ? hi : v);

/** Parameter vector u = [ln D1, ln D2, ln(−t0), μ1, ln σ1, μ2, ln σ2], clamped to a sane region. */
function clampU(u: Vec): Vec {
  const out = u.slice();
  out[2] = clamp(u[2]!, BOUNDS.g[0], BOUNDS.g[1]);
  out[3] = clamp(u[3]!, BOUNDS.mu[0], BOUNDS.mu[1]);
  out[4] = clamp(u[4]!, BOUNDS.s[0], BOUNDS.s[1]);
  out[5] = clamp(u[5]!, BOUNDS.mu[0], BOUNDS.mu[1]);
  out[6] = clamp(u[6]!, BOUNDS.s[0], BOUNDS.s[1]);
  out[1] = clamp(u[1]!, u[0]! - 9, u[0]! + LN(0.9)); // 0 < D2 ≤ 0.9·D1
  return out;
}

function unpack(u: Vec): DeltaLognormalParams {
  return { D1: Math.exp(u[0]!), D2: Math.exp(u[1]!), t0: -Math.exp(u[2]!), mu1: u[3]!, sigma1: Math.exp(u[4]!), mu2: u[5]!, sigma2: Math.exp(u[6]!) };
}

function residuals(tau: Float64Array, y: Float64Array, u: Vec): Float64Array {
  const p = unpack(clampU(u));
  const r = new Float64Array(tau.length);
  for (let i = 0; i < tau.length; i++) r[i] = deltaLognormal(tau[i]!, p) - y[i]!;
  return r;
}

const sumSq = (r: Float64Array): number => { let s = 0; for (const v of r) s += v * v; return s; };

/** Gaussian elimination with partial pivoting. Returns null for a singular system. */
function solve(A: number[][], b: number[]): number[] | null {
  const n = b.length;
  const M = A.map((row, i) => [...row, b[i]!]);
  for (let c = 0; c < n; c++) {
    let piv = c;
    for (let r = c + 1; r < n; r++) if (Math.abs(M[r]![c]!) > Math.abs(M[piv]![c]!)) piv = r;
    if (Math.abs(M[piv]![c]!) < 1e-300) return null;
    [M[c], M[piv]] = [M[piv]!, M[c]!];
    for (let r = c + 1; r < n; r++) {
      const f = M[r]![c]! / M[c]![c]!;
      for (let k = c; k <= n; k++) M[r]![k] = M[r]![k]! - f * M[c]![k]!;
    }
  }
  const x = new Array<number>(n).fill(0);
  for (let r = n - 1; r >= 0; r--) {
    let s = M[r]![n]!;
    for (let k = r + 1; k < n; k++) s -= M[r]![k]! * x[k]!;
    x[r] = s / M[r]![r]!;
  }
  return x.every(Number.isFinite) ? x : null;
}

function levenbergMarquardt(tau: Float64Array, y: Float64Array, start: Vec, maxIter = 70): { u: Vec; sse: number } {
  const P = start.length;
  let u = clampU(start);
  let r = residuals(tau, y, u);
  let sse = sumSq(r);
  let lambda = 1e-2;
  for (let iter = 0; iter < maxIter; iter++) {
    const J: Float64Array[] = [];
    for (let j = 0; j < P; j++) {
      const h = 1e-6 * (1 + Math.abs(u[j]!));
      const up = u.slice(); up[j] = up[j]! + h;
      const um = u.slice(); um[j] = um[j]! - h;
      const rp = residuals(tau, y, up);
      const rm = residuals(tau, y, um);
      const col = new Float64Array(tau.length);
      for (let i = 0; i < tau.length; i++) col[i] = (rp[i]! - rm[i]!) / (2 * h);
      J.push(col);
    }
    const A: number[][] = Array.from({ length: P }, () => new Array<number>(P).fill(0));
    const g = new Array<number>(P).fill(0);
    for (let a = 0; a < P; a++) {
      for (let b = a; b < P; b++) {
        let s = 0;
        for (let i = 0; i < tau.length; i++) s += J[a]![i]! * J[b]![i]!;
        A[a]![b] = s; A[b]![a] = s;
      }
      let s = 0;
      for (let i = 0; i < tau.length; i++) s += J[a]![i]! * r[i]!;
      g[a] = -s;
    }
    let improved = false;
    let rel = 0;
    for (let attempt = 0; attempt < 8; attempt++) {
      const Ad = A.map((row, i) => row.map((v, k) => (i === k ? v + lambda * (v + 1e-12) : v)));
      const delta = solve(Ad, g);
      if (delta) {
        const uNew = clampU(u.map((v, i) => v + delta[i]!));
        const rNew = residuals(tau, y, uNew);
        const sseNew = sumSq(rNew);
        if (sseNew < sse) {
          rel = (sse - sseNew) / Math.max(sse, 1e-300);
          u = uNew; r = rNew; sse = sseNew;
          lambda = Math.max(lambda / 3, 1e-9);
          improved = true;
          break;
        }
      }
      lambda *= 4;
    }
    if (!improved || rel < 1e-9) break;
  }
  return { u, sse };
}

export interface StrokeFit {
  params: DeltaLognormalParams;
  /** 10·log10(Σ v² / Σ (v − v̂)²) */
  snrDb: number;
  rmse: number;
}

/** Fit one stroke's speed profile. `tau` is seconds from the start of the window. */
export function fitStroke(tau: Float64Array, speed: Float64Array): StrokeFit | null {
  const n = speed.length;
  if (n < 8 || tau.length !== n) return null;
  let ip = 0, energy = 0, area = 0;
  for (let i = 0; i < n; i++) {
    if (speed[i]! > speed[ip]!) ip = i;
    energy += speed[i]! * speed[i]!;
    if (i > 0) area += 0.5 * (speed[i]! + speed[i - 1]!) * (tau[i]! - tau[i - 1]!);
  }
  if (!(energy > 0) || !(area > 0)) return null;
  const tp = tau[ip]!;

  let best: { u: Vec; sse: number } | null = null;
  for (const g of [0.02, 0.05, 0.1]) {
    for (const sigma of [0.25, 0.45]) {
      const mu1 = LN(tp + g) + sigma * sigma;
      const start: Vec = [LN(area * 1.05), LN(area * 0.1), LN(g), mu1, LN(sigma), mu1 + 0.3, LN(sigma * 1.2)];
      const fit = levenbergMarquardt(tau, speed, start);
      if (!best || fit.sse < best.sse) best = fit;
    }
  }
  if (!best || !Number.isFinite(best.sse)) return null;
  const params = unpack(clampU(best.u));
  const snrDb = best.sse <= 1e-12 * energy ? 99 : 10 * Math.log10(energy / best.sse);
  return { params, snrDb, rmse: Math.sqrt(best.sse / n) };
}

// ------------------------------------------------------------------ speed profile & stroke segmentation

export function speedProfile(s: ResampledSeries, cutoffHz = 10): Float64Array {
  const dt = s.dtMs / 1000;
  const x = lowpassZeroPhase(s.x, cutoffHz, s.fs);
  const y = lowpassZeroPhase(s.y, cutoffHz, s.fs);
  const n = s.n;
  const v = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const a = Math.max(0, i - 1), b = Math.min(n - 1, i + 1);
    v[i] = Math.hypot(x[b]! - x[a]!, y[b]! - y[a]!) / ((b - a) * dt);
  }
  return v;
}

export interface SegmentOptions {
  /** A dip is a stroke boundary only if speed there < dipFraction × the smaller adjacent peak. */
  dipFraction: number;
  minDurationMs: number;
  maxDurationMs: number;
  minPeakSpeed: number; // px/s
  minPathLength: number; // px
  floorFraction: number;
}

export const DEFAULT_SEGMENT: SegmentOptions = {
  dipFraction: 0.35, minDurationMs: 150, maxDurationMs: 3000, minPeakSpeed: 30, minPathLength: 12, floorFraction: 0.03,
};

export interface StrokeWindow { start: number; end: number; peak: number }

export function segmentStrokes(speed: Float64Array, dtSec: number, opt: SegmentOptions = DEFAULT_SEGMENT): StrokeWindow[] {
  const n = speed.length;
  if (n < 10) return [];
  let gmax = 0;
  for (const v of speed) if (v > gmax) gmax = v;
  if (gmax < opt.minPeakSpeed) return [];
  const floor = Math.max(opt.floorFraction * gmax, 2);

  // Active runs separated by >= 3 consecutive below-floor samples (a pause).
  const runs: Array<[number, number]> = [];
  let a = -1, below = 0;
  for (let i = 0; i < n; i++) {
    if (speed[i]! >= floor) {
      if (a < 0) a = i;
      below = 0;
    } else if (a >= 0) {
      below++;
      if (below >= 3) { runs.push([a, i - below]); a = -1; below = 0; }
    }
  }
  if (a >= 0) runs.push([a, n - 1 - below]);

  const out: StrokeWindow[] = [];
  for (const [ra, rb] of runs) {
    const lo = Math.max(0, ra - 1), hi = Math.min(n - 1, rb + 1);
    const bounds: number[] = [lo];
    for (let k = lo + 1; k < hi; k++) if (speed[k]! < speed[k - 1]! && speed[k]! <= speed[k + 1]!) bounds.push(k);
    bounds.push(hi);

    const peakBetween = (p: number, q: number): number => { let m = 0; for (let i = p; i <= q; i++) if (speed[i]! > m) m = speed[i]!; return m; };
    for (;;) {
      let worst = -1, worstRatio = -1;
      for (let b = 1; b < bounds.length - 1; b++) {
        const pl = peakBetween(bounds[b - 1]!, bounds[b]!);
        const pr = peakBetween(bounds[b]!, bounds[b + 1]!);
        const ratio = speed[bounds[b]!]! / Math.max(1e-9, Math.min(pl, pr));
        if (ratio > worstRatio) { worstRatio = ratio; worst = b; }
      }
      if (worst < 0 || worstRatio < opt.dipFraction) break;
      bounds.splice(worst, 1);
    }

    for (let b = 0; b < bounds.length - 1; b++) {
      const s = bounds[b]!, e = bounds[b + 1]!;
      if (e - s + 1 < 10) continue;
      let pk = s, path = 0;
      for (let i = s; i <= e; i++) { if (speed[i]! > speed[pk]!) pk = i; path += speed[i]! * dtSec; }
      const durMs = (e - s) * dtSec * 1000;
      if (durMs < opt.minDurationMs || durMs > opt.maxDurationMs) continue;
      if (speed[pk]! < opt.minPeakSpeed || path < opt.minPathLength) continue;
      out.push({ start: s, end: e, peak: pk });
    }
  }
  return out;
}

// ------------------------------------------------------------------ evidence extraction (client side)

const MAX_STROKES = 16;
const q = (v: number, scale: number, lo: number, hi: number): number => Math.round(clamp(v, lo, hi) * scale);

export interface ExtractOptions {
  resample?: ResampleOptions;
  segment?: SegmentOptions;
  cutoffHz?: number;
}

export function extractKinematicEvidence(
  samples: readonly RawSample[],
  modality: Modality,
  contact?: ContactSummary,
  opt: ExtractOptions = {},
): KinematicEvidence | null {
  const series = resampleSegments(samples, opt.resample);
  const strokes: Array<{ absStartMs: number; ev: Omit<StrokeEvidence, 'startMs'> }> = [];
  const used: ResampledSeries[] = [];

  for (const s of series) {
    const dt = s.dtMs / 1000;
    const speed = speedProfile(s, opt.cutoffHz ?? 10);
    const windows = segmentStrokes(speed, dt, opt.segment ?? DEFAULT_SEGMENT);
    let any = false;
    for (const w of windows) {
      if (strokes.length >= MAX_STROKES) break;
      const len = w.end - w.start + 1;
      const tau = new Float64Array(len);
      const y = new Float64Array(len);
      for (let i = 0; i < len; i++) { tau[i] = i * dt; y[i] = speed[w.start + i]!; }
      const fit = fitStroke(tau, y);
      if (!fit) continue;
      const p = fit.params;
      strokes.push({
        absStartMs: s.t0 + w.start * s.dtMs,
        ev: {
          durationMs: Math.round((len - 1) * s.dtMs),
          snrDeciDb: q(fit.snrDb, 10, -300, 999),
          mu1Milli: q(p.mu1, 1000, -5, 1.5), sigma1Milli: q(p.sigma1, 1000, 0.05, 1.5),
          mu2Milli: q(p.mu2, 1000, -5, 1.5), sigma2Milli: q(p.sigma2, 1000, 0.05, 1.5),
          d2RatioMilli: q(p.D2 / p.D1, 1000, 0, 1),
          peakPhaseMilli: q((w.peak - w.start) / (len - 1), 1000, 0, 1),
        },
      });
      any = true;
    }
    if (any) used.push(s);
  }
  if (strokes.length === 0) return null;

  const first = strokes[0]!.absStartMs;
  const jerk = analyzeJerk(used, DEFAULT_JERK_BOUNDS);
  const kurt = Number.isFinite(jerk.maxExcessKurtosis) ? jerk.maxExcessKurtosis : 0;
  const lastSeries = used[used.length - 1]!;
  const out: KinematicEvidence = {
    version: 1,
    modality,
    strokes: strokes.map((s) => ({ startMs: Math.round(s.absStartMs - first), ...s.ev })),
    jerkKurtCenti: q(kurt, 100, -1000, 1e6),
    nativeRateDeci: Math.round(10 * Math.min(...used.map((s) => s.nativeRateHz))),
    sampleCount: used.reduce((a, s) => a + s.n, 0),
    durationMs: Math.round(lastSeries.t0 + (lastSeries.n - 1) * lastSeries.dtMs - first),
  };
  if (contact) out.contact = contact;
  return out;
}

// ------------------------------------------------------------------ server-side judgment

export interface KinematicJudgeOptions {
  minStrokes: number;
  snrMinDb: number;
  snrMaxDb: number;
  sigma1Min: number; sigma1Max: number;
  mu1Min: number; mu1Max: number;
  sigma2Min: number; sigma2Max: number;
  d2RatioMax: number;
  peakPhaseMin: number; peakPhaseMax: number;
  minPassFraction: number;
  rejectBelowFraction: number;
  /** Strokes whose μ1, σ1 and duration all vary less than this (coefficient of variation) are clones. */
  clonedCvMax: number;
  kurtosisMax: number;
  minSessionMs: number;
  maxSessionMs: number;
  minRadiusCvMilli: number;
  staticContactIsFatal: boolean;
}

/**
 * Provisional bounds, NOT calibrated on real human data. peakPhaseMax encodes the positive skew of lognormal
 * strokes (symmetric min-jerk/sine profiles peak near 0.5); real strokes can be more symmetric, so a failure
 * here should route to step-up, not to a block. Tune per deployment with real captures.
 */
export const DEFAULT_KINEMATIC_JUDGE: KinematicJudgeOptions = {
  minStrokes: 3, snrMinDb: 10, snrMaxDb: 40,
  sigma1Min: 0.08, sigma1Max: 0.9, mu1Min: -3.5, mu1Max: 0,
  sigma2Min: 0.05, sigma2Max: 1.5, d2RatioMax: 0.9,
  peakPhaseMin: 0.15, peakPhaseMax: 0.46,
  minPassFraction: 0.6, rejectBelowFraction: 0.25, clonedCvMax: 0.01, kurtosisMax: 100,
  minSessionMs: 1000, maxSessionMs: 300_000, minRadiusCvMilli: 5, staticContactIsFatal: false,
};

export type KinematicVerdict = 'ok' | 'ambiguous' | 'reject';
export interface KinematicJudgment {
  verdict: KinematicVerdict;
  reasons: string[];
  passFraction: number;
  /** Per-stroke failure tags, for SERVER-SIDE LOGS ONLY (never return to the client). */
  strokeFlags: string[][];
}

const isInt = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n);

export function assertWellFormedKinematics(e: KinematicEvidence): void {
  const bad = (m: string): never => { throw new ProtocolError('MALFORMED', `kinematics: ${m}`); };
  if (e === null || typeof e !== 'object' || e.version !== 1) bad('version');
  if (!MODALITIES.includes(e.modality)) bad('modality');
  if (!Array.isArray(e.strokes) || e.strokes.length > MAX_STROKES) bad('strokes');
  for (const k of ['jerkKurtCenti', 'nativeRateDeci', 'sampleCount', 'durationMs'] as const) if (!isInt(e[k])) bad(k);
  if (e.nativeRateDeci < 0 || e.nativeRateDeci > 100_000 || e.sampleCount < 0 || e.sampleCount > 1_000_000 || e.durationMs < 0 || e.durationMs > 3_600_000) bad('range');
  let prevEnd = 0;
  e.strokes.forEach((s, i) => {
    for (const k of ['startMs', 'durationMs', 'snrDeciDb', 'mu1Milli', 'sigma1Milli', 'mu2Milli', 'sigma2Milli', 'd2RatioMilli', 'peakPhaseMilli'] as const) {
      if (!isInt(s[k])) bad(`stroke.${k}`);
    }
    if (s.startMs < 0 || s.durationMs <= 0 || s.durationMs > 60_000 || s.snrDeciDb < -300 || s.snrDeciDb > 999
      || s.sigma1Milli < 1 || s.sigma1Milli > 5000 || s.sigma2Milli < 1 || s.sigma2Milli > 5000
      || s.mu1Milli < -10_000 || s.mu1Milli > 10_000 || s.mu2Milli < -10_000 || s.mu2Milli > 10_000
      || s.d2RatioMilli < 0 || s.d2RatioMilli > 1000 || s.peakPhaseMilli < 0 || s.peakPhaseMilli > 1000) bad('stroke range');
    if (i > 0 && s.startMs < prevEnd - 20) bad('strokes overlap');
    prevEnd = s.startMs + s.durationMs;
  });
  if (e.strokes.length > 0 && prevEnd > e.durationMs + 50) bad('stroke beyond session');
  if (e.contact) {
    const c = e.contact;
    if (!isInt(c.n) || c.n < 0 || !isInt(c.radiusCvMilli) || !isInt(c.forceCvMilli) || c.radiusCvMilli < 0 || c.forceCvMilli < 0
      || typeof c.staticRadius !== 'boolean' || typeof c.staticForce !== 'boolean') bad('contact');
  }
}

function cv(values: number[]): number {
  const n = values.length;
  const m = values.reduce((a, b) => a + b, 0) / n;
  if (Math.abs(m) < 1e-12) return 0;
  const sd = Math.sqrt(values.reduce((a, b) => a + (b - m) ** 2, 0) / n);
  return sd / Math.abs(m);
}

export function judgeKinematics(e: KinematicEvidence, o: Partial<KinematicJudgeOptions> = {}): KinematicJudgment {
  const opt = { ...DEFAULT_KINEMATIC_JUDGE, ...o };
  assertWellFormedKinematics(e);
  const reasons: string[] = [];
  const fail = (verdict: KinematicVerdict, reason: string, passFraction = 0, flags: string[][] = []): KinematicJudgment =>
    ({ verdict, reasons: [reason, ...reasons], passFraction, strokeFlags: flags });

  if (e.durationMs < opt.minSessionMs) return fail('ambiguous', 'session-too-short');
  if (e.durationMs > opt.maxSessionMs) return fail('reject', 'session-too-long');
  const native = e.nativeRateDeci / 10;
  if (native < 10 || native > 2000) return fail('reject', 'native-rate-implausible');
  if (e.strokes.length < opt.minStrokes) return fail('ambiguous', 'few-strokes');

  const flags: string[][] = [];
  let pass = 0, perfect = 0;
  for (const s of e.strokes) {
    const f: string[] = [];
    const snr = s.snrDeciDb / 10, sg1 = s.sigma1Milli / 1000, mu1 = s.mu1Milli / 1000, sg2 = s.sigma2Milli / 1000;
    const d2 = s.d2RatioMilli / 1000, ph = s.peakPhaseMilli / 1000;
    if (snr < opt.snrMinDb) f.push('poor-fit');
    if (snr > opt.snrMaxDb) { f.push('too-perfect'); perfect++; }
    if (sg1 < opt.sigma1Min || sg1 > opt.sigma1Max) f.push('sigma1-range');
    if (mu1 < opt.mu1Min || mu1 > opt.mu1Max) f.push('mu1-range');
    if (d2 > 0.02 && (sg2 < opt.sigma2Min || sg2 > opt.sigma2Max)) f.push('sigma2-range');
    if (d2 > opt.d2RatioMax) f.push('d2-range');
    if (ph < opt.peakPhaseMin || ph > opt.peakPhaseMax) f.push('peak-phase');
    flags.push(f);
    if (f.length === 0) pass++;
  }
  const passFraction = pass / e.strokes.length;

  if (perfect / e.strokes.length >= 0.5) reasons.push('too-perfect');
  if (e.strokes.length >= 4
    && cv(e.strokes.map((s) => s.mu1Milli)) < opt.clonedCvMax
    && cv(e.strokes.map((s) => s.sigma1Milli)) < opt.clonedCvMax
    && cv(e.strokes.map((s) => s.durationMs)) < opt.clonedCvMax) reasons.push('cloned-strokes');
  if (e.jerkKurtCenti / 100 > opt.kurtosisMax) reasons.push('impulsive-jerk');

  let inconclusive = false;
  if (e.modality !== 'mouse') {
    if (!e.contact) reasons.push('contact-missing');
    else if (e.contact.staticRadius || e.contact.staticForce || e.contact.radiusCvMilli < opt.minRadiusCvMilli) {
      if (opt.staticContactIsFatal) reasons.push('contact-static');
      else inconclusive = true;
    }
  }

  if (reasons.length > 0 || passFraction < opt.rejectBelowFraction) {
    if (passFraction < opt.rejectBelowFraction) reasons.push('low-pass-fraction');
    return { verdict: 'reject', reasons, passFraction, strokeFlags: flags };
  }
  if (passFraction < opt.minPassFraction || inconclusive) {
    return { verdict: 'ambiguous', reasons: inconclusive ? ['contact-static'] : ['mixed-strokes'], passFraction, strokeFlags: flags };
  }
  return { verdict: 'ok', reasons: [], passFraction, strokeFlags: flags };
}
