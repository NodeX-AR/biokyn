/** Zero-phase Butterworth-style (Q = 1/√2) biquad high-/low-pass via forward–backward filtering. */
import { ProtocolError } from '../bytes.js';

function biquad(kind: 'high' | 'low', fc: number, fs: number): { b: [number, number, number]; a: [number, number] } {
  if (!(fc > 0 && fc < fs / 2)) throw new ProtocolError('BAD_CUTOFF', 'cutoff must be in (0, fs/2)');
  const w0 = (2 * Math.PI * fc) / fs;
  const cosw = Math.cos(w0);
  const alpha = Math.sin(w0) / (2 * Math.SQRT1_2);
  const a0 = 1 + alpha;
  const a: [number, number] = [(-2 * cosw) / a0, (1 - alpha) / a0];
  if (kind === 'high') return { b: [(1 + cosw) / 2 / a0, -(1 + cosw) / a0, (1 + cosw) / 2 / a0], a };
  return { b: [(1 - cosw) / 2 / a0, (1 - cosw) / a0, (1 - cosw) / 2 / a0], a };
}

function runBiquad(x: Float64Array, b: [number, number, number], a: [number, number]): Float64Array {
  const y = new Float64Array(x.length);
  let x1 = 0, x2 = 0, y1 = 0, y2 = 0;
  for (let i = 0; i < x.length; i++) {
    const xi = x[i]!;
    const yi = b[0] * xi + b[1] * x1 + b[2] * x2 - a[0] * y1 - a[1] * y2;
    y[i] = yi;
    x2 = x1; x1 = xi; y2 = y1; y1 = yi;
  }
  return y;
}

/** Odd-reflection padded forward/backward high-pass. Effective order 4, zero phase. */
function filtfilt(x: Float64Array, kind: 'high' | 'low', fc: number, fs: number): Float64Array {
  const n = x.length;
  if (n < 8) return Float64Array.from(x);
  const pad = Math.min(n - 1, Math.ceil((3 * fs) / fc));
  const ext = new Float64Array(n + 2 * pad);
  for (let i = 0; i < pad; i++) {
    ext[pad - 1 - i] = 2 * x[0]! - x[Math.min(n - 1, i + 1)]!;
    ext[pad + n + i] = 2 * x[n - 1]! - x[Math.max(0, n - 2 - i)]!;
  }
  ext.set(x, pad);
  const { b, a } = biquad(kind, fc, fs);
  const fwd = runBiquad(ext, b, a);
  fwd.reverse();
  const bwd = runBiquad(fwd, b, a);
  bwd.reverse();
  return bwd.slice(pad, pad + n);
}

export const highpassZeroPhase = (x: Float64Array, fc: number, fs: number): Float64Array => filtfilt(x, 'high', fc, fs);
export const lowpassZeroPhase = (x: Float64Array, fc: number, fs: number): Float64Array => filtfilt(x, 'low', fc, fs);
