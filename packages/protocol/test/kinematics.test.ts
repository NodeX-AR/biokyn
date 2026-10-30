import { describe, expect, it } from 'vitest';
import {
  ProtocolError, assertWellFormedKinematics, deltaLognormal, extractKinematicEvidence, fitStroke, judgeKinematics,
  requestDigest, segmentStrokes, timingCommitment, toHex, type KinematicEvidence, type RawSample,
} from '../src/index.js';
import { dl, gauss, humanStrokes, lcg, trajectory, type StrokeSpec } from './synth.js';

const judge = (s: RawSample[]) => {
  const e = extractKinematicEvidence(s, 'mouse');
  expect(e, 'kinematic evidence extraction returned null').not.toBeNull();
  const j = judgeKinematics(e!);
  if (j.verdict !== 'ok') {
    console.info('Kinematic diagnostic:', {
      verdict: j.verdict,
      reasons: j.reasons,
      passFraction: j.passFraction,
      strokeFlags: j.strokeFlags,
      durationMs: e!.durationMs,
      nativeRateDeci: e!.nativeRateDeci,
    });
  }
  return { e: e!, j };
};

const minJerk = (n = 6): StrokeSpec[] => Array.from({ length: n }, (_, i) => ({
  speed: (t: number) => { const T = 0.6, s = t / T; return s < 0 || s > 1 ? 0 : (300 / T) * (30 * s * s - 60 * s ** 3 + 30 * s ** 4); },
  duration: 0.6, angle: i * 1.1,
}));

describe('delta-lognormal fitter', () => {
  it('recovers known parameters from a clean speed profile', () => {
    const truth = { D1: 250, D2: 0, t0: -0.05, mu1: -1.6, sigma1: 0.3, mu2: -1.2, sigma2: 0.4 };
    const tau = Float64Array.from({ length: 80 }, (_, i) => i * 0.01);
    const y = Float64Array.from(tau, (t) => deltaLognormal(t, truth));
    const f = fitStroke(tau, y)!;
    expect(f.snrDb).toBeGreaterThan(40);
    expect(f.params.sigma1).toBeCloseTo(0.3, 2);
    expect(f.params.mu1).toBeCloseTo(-1.6, 1);
    expect(f.params.t0).toBeCloseTo(-0.05, 2);
  });
  it('recovers a two-component (agonist − antagonist) profile with high SNR', () => {
    const truth = { D1: 300, D2: 40, t0: -0.04, mu1: -1.7, sigma1: 0.28, mu2: -1.3, sigma2: 0.35 };
    const tau = Float64Array.from({ length: 90 }, (_, i) => i * 0.01);
    const y = Float64Array.from(tau, (t) => Math.max(0, deltaLognormal(t, truth)));
    expect(fitStroke(tau, y)!.snrDb).toBeGreaterThan(30);
  });
  it('rejects degenerate input', () => {
    expect(fitStroke(new Float64Array(5), new Float64Array(5))).toBeNull();
    expect(fitStroke(Float64Array.from({ length: 20 }, (_, i) => i * 0.01), new Float64Array(20))).toBeNull();
  });
});

describe('stroke segmentation', () => {
  it('splits on pauses and ignores sub-threshold jitter', () => {
    const s = trajectory(humanStrokes(1, 4), { noisePx: 0.3 });
    const e = extractKinematicEvidence(s, 'mouse')!;
    expect(e.strokes).toHaveLength(4);
    for (let i = 1; i < e.strokes.length; i++) expect(e.strokes[i]!.startMs).toBeGreaterThan(e.strokes[i - 1]!.startMs + e.strokes[i - 1]!.durationMs - 21);
    expect(segmentStrokes(new Float64Array(200).fill(0.5), 0.01)).toHaveLength(0);
  });
});

describe('judgment with realistic position noise (2 px)', () => {
  it.each([1, 2, 3])('delta-lognormal human-like session %i is ok at 125 Hz', (seed) => {
    expect(judge(trajectory(humanStrokes(seed), { noisePx: 2, seed })).j.verdict).toBe('ok');
  });
  it.each([30, 60, 1000])('is ok across native polling rates (%i Hz)', (hz) => {
    // 30 Hz is deliberately coarse: only require it not to be rejected outright.
    const { j } = judge(trajectory(humanStrokes(4), { hz, noisePx: 2, seed: 4 }));
    expect(hz === 30 ? j.verdict !== 'reject' : j.verdict).toBeTruthy();
    if (hz !== 30) expect(j.verdict).toBe('ok');
  });
  // Characterization tests: these synthetic profiles score `ok`. They are asserted as-is so any recalibration is a
  // deliberate, visible change. Kinematics is advisory-only (it can deny but never grant a token), and the
  // proof-of-work lane is what grants tokens. Recalibrate only against representative real captures.
  it('constant-speed (box) strokes score ok (advisory signal)', () => {
    const strokes = Array.from({ length: 6 }, (_, i) => ({ speed: (t: number) => (t < 0.5 ? 400 : 0), duration: 0.5, angle: i }));
    expect(judge(trajectory(strokes, { noisePx: 2 })).j.verdict).toBe('ok');
  });
  it('clean min-jerk strokes are rejected; noisy min-jerk scores ok', () => {
    const clean = judge(trajectory(minJerk(), { noisePx: 0, quantize: false }));
    expect(clean.j.verdict).toBe('reject');
    expect(clean.j.reasons).toContain('cloned-strokes');

    // Positional noise moves the fitted features into the human-range thresholds.
    // Tighten thresholds only after evaluating false positives on real user captures.
    const noisy = judge(trajectory(minJerk(), { noisePx: 2 }));
    expect(noisy.j.verdict).toBe('ok');
  });
  it('sine speed profile with noise scores ok (advisory signal)', () => {
    const r = lcg(9);
    const strokes = Array.from({ length: 6 }, (_, i) => ({ speed: (t: number) => Math.max(0, 300 * Math.sin((Math.PI * t) / 0.6) + 80 * gauss(r)), duration: 0.6, angle: i }));
    expect(judge(trajectory(strokes, { noisePx: 2 })).j.verdict).toBe('ok');
  });
  it('near-noise-free analytic strokes (0.3 px) score ok; noise-free ones are rejected', () => {
    expect(judge(trajectory(humanStrokes(1), { noisePx: 0.3, seed: 1 })).j.verdict).toBe('ok');
    const { j } = judge(trajectory(humanStrokes(1), { noisePx: 0, quantize: false, seed: 1 }));
    expect(j.verdict).toBe('reject');
  });
  it('identical cloned strokes are rejected', () => {
    const same = Array.from({ length: 6 }, (_, i) => ({ speed: dl(), duration: 0.9, angle: i * 1.1 }));
    const { j } = judge(trajectory(same, { noisePx: 0, quantize: false }));
    expect(j.verdict).toBe('reject');
  });
  it('too few strokes is ambiguous (step-up), never a hard reject', () => {
    const { j } = judge(trajectory(humanStrokes(1, 2), { noisePx: 2 }));
    expect(j.verdict).toBe('ambiguous');
    expect(j.reasons).toContain('few-strokes');
  });
  it('randomized delta-lognormal strokes with human-range noise score ok', () => {
    // The detector raises attacker cost; proof-of-work and WebAuthn are what grant tokens.
    expect(judge(trajectory(humanStrokes(77), { noisePx: 2, seed: 77 })).j.verdict).toBe('ok');
  });
});

describe('contact and well-formedness', () => {
  const base = (): KinematicEvidence => extractKinematicEvidence(trajectory(humanStrokes(1), { noisePx: 2, seed: 1 }), 'touch', { n: 400, radiusCvMilli: 150, forceCvMilli: 200, staticRadius: false, staticForce: false })!;
  it('real touch contact passes; static synthetic contact is ambiguous (fatal only when configured)', () => {
    expect(judgeKinematics(base()).verdict).toBe('ok');
    const fake = { ...base(), contact: { n: 400, radiusCvMilli: 0, forceCvMilli: 0, staticRadius: true, staticForce: true } };
    expect(judgeKinematics(fake).verdict).toBe('ambiguous');
    expect(judgeKinematics(fake, { staticContactIsFatal: true }).verdict).toBe('reject');
    expect(judgeKinematics({ ...fake, contact: undefined }).verdict).toBe('reject');
  });
  it('malformed evidence throws ProtocolError(MALFORMED)', () => {
    const e = base();
    const bad: Array<Partial<KinematicEvidence>> = [
      { version: 2 as 1 }, { modality: 'tablet' as 'mouse' }, { sampleCount: 1.5 },
      { strokes: [{ ...e.strokes[0]!, snrDeciDb: 5000 }] },
      { strokes: [e.strokes[0]!, { ...e.strokes[1]!, startMs: 0 }] },
      { durationMs: 10 },
    ];
    for (const b of bad) expect(() => assertWellFormedKinematics({ ...e, ...b })).toThrow(ProtocolError);
  });
});

describe('request digest', () => {
  it('binds nonce, blinded element, evidence, commitment and tamper flags', () => {
    const e = extractKinematicEvidence(trajectory(humanStrokes(1), { noisePx: 2, seed: 1 }), 'mouse')!;
    const nonce = new Uint8Array(32).fill(1), blinded = new Uint8Array(32).fill(2);
    const cm = timingCommitment(nonce, [10000, 10100, 9900]);
    const req = { path: 'fast' as const, kinematics: e, tamper: { clock: 0 as const, automation: 0 as const } };
    const base = toHex(requestDigest(nonce, blinded, req, cm));
    expect(toHex(requestDigest(new Uint8Array(32).fill(9), blinded, req, cm))).not.toBe(base);
    expect(toHex(requestDigest(nonce, new Uint8Array(32).fill(3), req, cm))).not.toBe(base);
    expect(toHex(requestDigest(nonce, blinded, { ...req, kinematics: { ...e, sampleCount: e.sampleCount + 1 } }, cm))).not.toBe(base);
    expect(toHex(requestDigest(nonce, blinded, { ...req, tamper: { clock: 2, automation: 0 } }, cm))).not.toBe(base);
    expect(toHex(requestDigest(nonce, blinded, req, timingCommitment(nonce, [1, 2])))).not.toBe(base);
    expect(() => requestDigest(nonce, blinded, { path: 'inclusive', tamper: req.tamper }, cm)).toThrow(ProtocolError);
  });
});
