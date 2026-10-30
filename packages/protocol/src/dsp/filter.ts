function biquad(kind: 'high' | 'low', fc: number, fs: number) {
  const w = 2 * Math.PI * fc / fs, c = Math.cos(w), s = Math.sin(w), alpha = s / (2 * Math.SQRT1_2), a0 = 1 + alpha;
  const a: [number, number] = [(-2 * c) / a0, (1 - alpha) / a0];
  if (kind === 'high') return { b: [(1 + c) / 2 / a0, -(1 + c) / a0, (1 + c) / 2 / a0] as [number, number, number], a };
  return { b: [(1 - c) / 2 / a0, (1 - c) / a0, (1 - c) / 2 / a0] as [number, number, number], a };
}
function filtfilt(x: Float64Array, kind: 'high' | 'low', fc: number, fs: number): Float64Array {
  if (x.length < 3) return x.slice();
  const { b, a } = biquad(kind, fc, fs); const pass = (src: Float64Array): Float64Array => {
    const y = new Float64Array(src.length); const x0 = src[0]!; const yInit = kind === 'low' ? x0 : 0; let x1 = x0, x2 = x0, y1 = yInit, y2 = yInit;
    for (let i = 0; i < src.length; i++) { const v = b[0]! * src[i]! + b[1]! * x1 + b[2]! * x2 - a[0]! * y1 - a[1]! * y2; y[i] = v; x2 = x1; x1 = src[i]!; y2 = y1; y1 = v; }
    return y;
  };
  const f = pass(x), r = new Float64Array(f.length); for (let i = 0; i < f.length; i++) r[i] = f[f.length - 1 - i]!;
  const rr = pass(r), out = new Float64Array(rr.length); for (let i = 0; i < rr.length; i++) out[i] = rr[rr.length - 1 - i]!;
  return out;
}
export const highpassZeroPhase = (x: Float64Array, fc: number, fs: number) => filtfilt(x, 'high', fc, fs);
export const lowpassZeroPhase = (x: Float64Array, fc: number, fs: number) => filtfilt(x, 'low', fc, fs);
