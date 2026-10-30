import { deltaLognormal, type DeltaLognormalParams, type RawSample } from '@biokyn/protocol';

export function lcg(seed: number) { let s = seed >>> 0; return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32); }
export const gauss = (r: () => number) => Math.sqrt(-2 * Math.log(r() + 1e-12)) * Math.cos(2 * Math.PI * r());

export interface StrokeSpec { speed: (t: number) => number; duration: number; angle: number }

/** Concatenate strokes with pauses; integrate speed along each direction; sample at `hz` with jitter; quantize to whole pixels. */
export function trajectory(strokes: StrokeSpec[], opts: { hz?: number; pauseMs?: number; noisePx?: number; quantize?: boolean; seed?: number; t0?: number } = {}): RawSample[] {
  const hz = opts.hz ?? 125, pause = (opts.pauseMs ?? 300) / 1000, noise = opts.noisePx ?? 0;
  const r = lcg(opts.seed ?? 1);
  const fine = 1 / 2000; // integrate at 2 kHz
  const pts: Array<{ t: number; x: number; y: number }> = [];
  let t = 0, x = 400, y = 300;
  for (const s of strokes) {
    const steps = Math.round(s.duration / fine);
    for (let i = 0; i < steps; i++) {
      const v = Math.max(0, s.speed(i * fine));
      x += v * Math.cos(s.angle) * fine; y += v * Math.sin(s.angle) * fine; t += fine;
      pts.push({ t, x, y });
    }
    const ps = Math.round(pause / fine);
    for (let i = 0; i < ps; i++) { t += fine; pts.push({ t, x, y }); }
  }
  const out: RawSample[] = [];
  const dt = 1 / hz; let next = 0, j = 0;
  while (next <= t && j < pts.length) {
    while (j < pts.length - 1 && pts[j]!.t < next) j++;
    const p = pts[j]!;
    const nx = p.x + noise * gauss(r), ny = p.y + noise * gauss(r);
    out.push({ t: (opts.t0 ?? 1000) + next * 1000 + 0.3 * (r() - 0.5), x: opts.quantize === false ? nx : Math.round(nx), y: opts.quantize === false ? ny : Math.round(ny) });
    next += dt;
  }
  return out;
}

export const dl = (p: Partial<DeltaLognormalParams> = {}): ((t: number) => number) => {
  const q: DeltaLognormalParams = { D1: 250, D2: 0, t0: -0.05, mu1: -1.6, sigma1: 0.3, mu2: -1.2, sigma2: 0.4, ...p };
  return (t) => deltaLognormal(t, q);
};
export const humanStrokes = (seed: number, n = 6): StrokeSpec[] => {
  const r = lcg(seed);
  return Array.from({ length: n }, (_, i) => ({
    speed: dl({ D1: 150 + 250 * r(), D2: 0.12 * (150 + 100 * r()), t0: -(0.03 + 0.05 * r()), mu1: -1.8 + 0.5 * r(), sigma1: 0.22 + 0.2 * r(), mu2: -1.3 + 0.3 * r(), sigma2: 0.3 + 0.2 * r() }),
    duration: 0.9, angle: (i * 1.3 + r()) % (2 * Math.PI),
  }));
};
