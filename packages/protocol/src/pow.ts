/**
 * Memory-hard proof-of-work (Argon2id, RFC 9106) for the Inclusive Path and the non-interactive step-up.
 *
 * Purpose: impose MACHINE cost instead of human motor demands. Baseline parameters follow OWASP's
 * Argon2id minimum (19 MiB, t = 2, p = 1). Difficulty is the number of leading zero bits required in the
 * 32-byte output, so the expected work is 2^bits hashes; the server tunes it per load.
 *
 * Each solution is bound to one issuance (server nonce + blinded element), so it cannot be reused for a
 * different token request. Verification costs the server exactly one Argon2id evaluation: callers MUST
 * bound concurrent verifications (see @biokyn/server) because that evaluation is deliberately expensive.
 */
import { argon2id, argon2idAsync, sha256 } from './hashes.js';
import { ProtocolError, base64urlDecode, base64urlEncode, concat, lp2, randomBytes, utf8 } from './bytes.js';
import type { B64, PowParams, PowSolution } from './types.js';

export const POW_BASELINE = { memoryKiB: 19456, iterations: 2, parallelism: 1 } as const;

/** Upper bounds a CLIENT enforces on server-supplied parameters so a hostile server cannot exhaust its memory/CPU. */
export interface PowLimits { maxMemoryKiB: number; maxIterations: number; maxParallelism: number; maxDifficultyBits: number }
export const DEFAULT_POW_LIMITS: PowLimits = { maxMemoryKiB: 65536, maxIterations: 6, maxParallelism: 4, maxDifficultyBits: 24 };

export function assertSafePowParams(p: PowParams, limits: PowLimits = DEFAULT_POW_LIMITS): Uint8Array {
  const bad = (m: string): never => { throw new ProtocolError('POW_PARAMS', `pow: ${m}`); };
  const int = (v: unknown, lo: number, hi: number, name: string): void => {
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < lo || v > hi) bad(name);
  };
  int(p.parallelism, 1, limits.maxParallelism, 'parallelism');
  int(p.iterations, 1, limits.maxIterations, 'iterations');
  int(p.memoryKiB, 8 * p.parallelism, limits.maxMemoryKiB, 'memoryKiB');
  int(p.difficultyBits, 0, limits.maxDifficultyBits, 'difficultyBits');
  const salt = base64urlDecode(p.salt);
  if (salt.length < 8 || salt.length > 64) bad('salt length');
  return salt;
}

/** SHA-256(domain || nonce || blinded): ties a solution to one server challenge and one blinded element. */
export const powBinding = (serverNonce: Uint8Array, blindedElement: Uint8Array): Uint8Array =>
  sha256(concat(utf8('biokyn-pow-v1'), lp2(serverNonce), lp2(blindedElement)));

const argonOpts = (p: PowParams) => ({ t: p.iterations, m: p.memoryKiB, p: p.parallelism, dkLen: 32, maxmem: 2 ** 32 - 1 });
const password = (nonce8: Uint8Array, binding: Uint8Array): Uint8Array => concat(nonce8, binding);

export function powHash(params: PowParams, nonce8: Uint8Array, binding: Uint8Array, limits?: PowLimits): Uint8Array {
  const salt = assertSafePowParams(params, limits);
  if (nonce8.length !== 8) throw new ProtocolError('POW_NONCE', 'nonce must be 8 bytes');
  return argon2id(password(nonce8, binding), salt, argonOpts(params));
}

export function leadingZeroBits(h: Uint8Array): number {
  let bits = 0;
  for (const b of h) {
    if (b === 0) { bits += 8; continue; }
    bits += Math.clz32(b) - 24;
    break;
  }
  return bits;
}

/** Server-side check of a client's solution. Returns false for any malformed or insufficient solution. */
export function verifyPow(params: PowParams, solution: PowSolution, binding: Uint8Array, limits?: PowLimits): boolean {
  let nonce: Uint8Array;
  try { nonce = base64urlDecode(solution.nonce); } catch { return false; }
  if (nonce.length !== 8) return false;
  return leadingZeroBits(powHash(params, nonce, binding, limits)) >= params.difficultyBits;
}

const nonceFrom = (base: Uint8Array, counter: number): Uint8Array => {
  const n = base.slice();
  // little-endian add of `counter` into the first 6 bytes (2^48 attempts are far beyond any difficulty cap)
  let carry = counter;
  for (let i = 0; i < 6 && carry > 0; i++) { const v = n[i]! + (carry & 0xff); n[i] = v & 0xff; carry = (carry >>> 8) + (v >> 8); }
  return n;
};

export interface SolveOptions {
  limits?: PowLimits;
  signal?: AbortSignal;
  maxAttempts?: number;
  /** Starting nonce (8 bytes); random by default so concurrent solvers search disjoint regions. */
  startNonce?: Uint8Array;
}

/** Blocking solver (use inside a Web Worker). */
export function solvePow(params: PowParams, binding: Uint8Array, opts: SolveOptions = {}): PowSolution {
  const salt = assertSafePowParams(params, opts.limits);
  const base = opts.startNonce ?? randomBytes(8);
  const max = opts.maxAttempts ?? Number.MAX_SAFE_INTEGER;
  const o = argonOpts(params);
  for (let i = 0; i < max; i++) {
    if (opts.signal?.aborted) throw new ProtocolError('POW_ABORTED', 'aborted');
    const nonce = nonceFrom(base, i);
    if (leadingZeroBits(argon2id(password(nonce, binding), salt, o)) >= params.difficultyBits) return { nonce: base64urlEncode(nonce) };
  }
  throw new ProtocolError('POW_EXHAUSTED', 'no solution within maxAttempts');
}

/** Cooperative solver for the main-thread fallback: yields to the event loop while hashing. */
export async function solvePowAsync(params: PowParams, binding: Uint8Array, opts: SolveOptions & { asyncTickMs?: number } = {}): Promise<PowSolution> {
  const salt = assertSafePowParams(params, opts.limits);
  const base = opts.startNonce ?? randomBytes(8);
  const max = opts.maxAttempts ?? Number.MAX_SAFE_INTEGER;
  const o = { ...argonOpts(params), asyncTick: opts.asyncTickMs ?? 10 };
  for (let i = 0; i < max; i++) {
    if (opts.signal?.aborted) throw new ProtocolError('POW_ABORTED', 'aborted');
    const nonce = nonceFrom(base, i);
    const h = await argon2idAsync(password(nonce, binding), salt, o);
    if (leadingZeroBits(h) >= params.difficultyBits) return { nonce: base64urlEncode(nonce) };
  }
  throw new ProtocolError('POW_EXHAUSTED', 'no solution within maxAttempts');
}

export const newPowSalt = (): B64 => base64urlEncode(randomBytes(16));

/** Async server-side PoW verification. Use a bounded concurrency gate before calling this function. */
export async function verifyPowAsync(params: PowParams, solution: PowSolution, binding: Uint8Array, limits?: PowLimits): Promise<boolean> {
  let nonce: Uint8Array;
  try { nonce = base64urlDecode(solution.nonce); assertSafePowParams(params, limits); } catch { return false; }
  if (nonce.length !== 8) return false;
  try {
    const salt = assertSafePowParams(params, limits);
    const h = await argon2idAsync(password(nonce, binding), salt, { ...argonOpts(params), asyncTick: 10 });
    return leadingZeroBits(h) >= params.difficultyBits;
  } catch { return false; }
}
