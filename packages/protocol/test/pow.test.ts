import { describe, expect, it } from 'vitest';
import {
  ProtocolError, POW_BASELINE, assertSafePowParams, base64urlEncode, decodeIssuance, encodeIssuance, leadingZeroBits, newPowSalt,
  powBinding, powHash, randomBytes, solvePow, solvePowAsync, verifyPow, type PowParams, type PowSolution,
} from '../src/index.js';

const fast = (bits: number): PowParams => ({ salt: newPowSalt(), memoryKiB: 64, iterations: 1, parallelism: 1, difficultyBits: bits });
const binding = powBinding(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2));

describe('Argon2id proof-of-work', () => {
  it('solves and verifies; solution is bound to the issuance', () => {
    const p = fast(6);
    const otherBinding = powBinding(new Uint8Array(32).fill(9), new Uint8Array(32).fill(2));
    const otherParams = { ...p, salt: newPowSalt() }, harder = { ...p, difficultyBits: 24 };
    // At this tiny difficulty a mismatched binding/salt would still verify by chance (~1/64 each), so deterministically
    // pick a solution that is valid for the true binding and INVALID for each mismatch.
    let sol: PowSolution | undefined;
    for (let i = 1; i < 2000 && !sol; i++) {
      const start = new Uint8Array(8); new DataView(start.buffer).setUint32(0, i * 104729);
      const cand = solvePow(p, binding, { startNonce: start });
      if (!verifyPow(p, cand, otherBinding) && !verifyPow(otherParams, cand, binding) && !verifyPow(harder, cand, binding)) sol = cand;
    }
    if (!sol) throw new Error('could not construct a counter-example solution');
    expect(verifyPow(p, sol, binding)).toBe(true);
    expect(verifyPow(p, sol, otherBinding)).toBe(false);
    expect(verifyPow(otherParams, sol, binding)).toBe(false);
    expect(verifyPow(harder, sol, binding)).toBe(false);
  });
  it('async cooperative solver finds a valid solution', async () => {
    const p = fast(4);
    expect(verifyPow(p, await solvePowAsync(p, binding, { asyncTickMs: 1 }), binding)).toBe(true);
  });
  it('rejects malformed solutions without throwing', () => {
    const p = fast(0);
    expect(verifyPow(p, { nonce: 'not base64!' }, binding)).toBe(false);
    expect(verifyPow(p, { nonce: base64urlEncode(new Uint8Array(3)) }, binding)).toBe(false);
    expect(verifyPow(p, { nonce: base64urlEncode(randomBytes(8)) }, binding)).toBe(true); // difficulty 0
  });
  it('leadingZeroBits counts across bytes', () => {
    expect(leadingZeroBits(Uint8Array.of(0, 0, 0x10))).toBe(19);
    expect(leadingZeroBits(Uint8Array.of(0x80))).toBe(0);
    expect(leadingZeroBits(new Uint8Array(4))).toBe(32);
  });
  it('clients refuse hostile server parameters', () => {
    const p = fast(1);
    for (const bad of [{ memoryKiB: 2 ** 30 }, { iterations: 100 }, { parallelism: 64 }, { difficultyBits: 64 }, { salt: 'AA' }, { memoryKiB: 4 }]) {
      expect(() => assertSafePowParams({ ...p, ...bad })).toThrow(ProtocolError);
    }
    expect(() => assertSafePowParams({ ...p, ...POW_BASELINE, difficultyBits: 4 })).not.toThrow();
  });
  it('baseline parameters (19 MiB, t=2, p=1) run and are deterministic', () => {
    const p: PowParams = { salt: newPowSalt(), ...POW_BASELINE, difficultyBits: 0 };
    const n = new Uint8Array(8).fill(3);
    const t0 = Date.now();
    const h1 = powHash(p, n, binding);
    const ms = Date.now() - t0;
    expect(Buffer.from(h1).equals(Buffer.from(powHash(p, n, binding)))).toBe(true);
    console.log(`argon2id 19 MiB t=2 p=1: ~${ms} ms per hash in node (noble, pure JS)`);
  });
  it('issuance blob round-trips (evaluated element + DLEQ proof only) and enforces lengths', () => {
    const e = { evaluatedElement: randomBytes(32), proof: randomBytes(64) };
    expect(decodeIssuance(encodeIssuance(e))).toEqual(e);
    expect(() => decodeIssuance(base64urlEncode(randomBytes(95)))).toThrow(ProtocolError);
    expect(() => decodeIssuance(base64urlEncode(randomBytes(160)))).toThrow(ProtocolError); // v1 blobs are refused
  });
});
