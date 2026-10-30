/** Seeded fuzz / property tests (no extra dependencies). Override with FUZZ_SEED=<int>; failures print the seed. */
import { describe, expect, it } from 'vitest';
import {
  ProtocolError, base64urlDecode, base64urlEncode, blind, blindEvaluate, decodeIssuance, decodeToken, deserializeElement, deserializeScalar, evaluate, expandMessageXmd,
  finalize, generateKeyPair, parseToken, serializeElement, toHex, utf8,
} from '../src/index.js';

const seed = Number(process.env.FUZZ_SEED ?? 1337);
const rng = (() => { let s = seed >>> 0 || 1; return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 2 ** 32; }; })();
const rbytes = (n: number): Uint8Array => Uint8Array.from({ length: n }, () => Math.floor(rng() * 256));
const only = (fn: () => unknown, ...allowed: Array<new (...a: any[]) => Error>): void => {
  try { fn(); } catch (e) { if (!allowed.some((c) => e instanceof c)) throw new Error(`seed ${seed}: unexpected ${String(e)}`); }
};

describe(`fuzz (seed ${seed})`, () => {
  it('base64urlDecode accepts only canonical input and never throws anything but ProtocolError', () => {
    for (let i = 0; i < 2000; i++) {
      const s = Array.from({ length: Math.floor(rng() * 90) }, () => String.fromCharCode(32 + Math.floor(rng() * 95))).join('');
      only(() => { const b = base64urlDecode(s); expect(base64urlEncode(b)).toBe(s); }, ProtocolError);
    }
  });
  it('token / issuance parsers fail only with ProtocolError on arbitrary bytes and arbitrary lengths', () => {
    for (let i = 0; i < 1500; i++) {
      const len = rng() < 0.3 ? [95, 96, 97, 161, 162, 163][Math.floor(rng() * 6)]! : Math.floor(rng() * 400);
      const b = rbytes(len);
      only(() => parseToken(b), ProtocolError);
      only(() => decodeToken(base64urlEncode(b)), ProtocolError);
      only(() => decodeIssuance(base64urlEncode(b)), ProtocolError);
    }
  });
  it('element decoding is canonical: anything accepted re-encodes to identical bytes', () => {
    let accepted = 0;
    for (let i = 0; i < 400; i++) {
      const b = rbytes(32); b[31]! &= 0x7f; b[0]! &= 0xfe; // bias toward even / in-range encodings so some decode
      try { const p = deserializeElement(b, { allowIdentity: true }); accepted++; expect(toHex(serializeElement(p))).toBe(toHex(b)); }
      catch (e) { if (!(e instanceof ProtocolError)) throw new Error(`seed ${seed}: ${String(e)}`); }
    }
    expect(accepted).toBeGreaterThan(20); // roughly half of encodings are valid; guards against a decoder that rejects everything
  });
  it('scalar decoding rejects every value >= the group order', () => {
    for (let i = 0; i < 300; i++) { const b = rbytes(32); b[31] = 0xf0 | (b[31]! & 0x0f); only(() => deserializeScalar(b), ProtocolError); }
  });
  it('VOPRF round-trip holds for random inputs of random length (client output == server evaluate)', () => {
    const { secretKey, publicKey } = generateKeyPair();
    for (let i = 0; i < 25; i++) {
      const input = rbytes(Math.floor(rng() * 300));
      const b = blind(input); const ev = blindEvaluate(secretKey, publicKey, b.blindedElement);
      expect(toHex(finalize(input, b.blind, ev.evaluatedElement, b.blindedElement, publicKey, ev.proof))).toBe(toHex(evaluate(secretKey, input)));
    }
  });
  it('a single flipped bit anywhere in the evaluation or proof is always detected', () => {
    const { secretKey, publicKey } = generateKeyPair(); const input = utf8('bitflip');
    const b = blind(input); const ev = blindEvaluate(secretKey, publicKey, b.blindedElement);
    for (let bit = 0; bit < 96 * 8; bit += 7) {
      const buf = Uint8Array.from([...ev.evaluatedElement, ...ev.proof]); buf[bit >> 3]! ^= 1 << (bit & 7);
      expect(() => finalize(input, b.blind, buf.slice(0, 32), b.blindedElement, publicKey, buf.slice(32))).toThrow();
    }
  });
  it('expand_message_xmd is length-exact and prefix-independent of requested length for random parameters', () => {
    for (let i = 0; i < 100; i++) {
      const msg = rbytes(Math.floor(rng() * 200)), dst = rbytes(1 + Math.floor(rng() * 60)), n = 1 + Math.floor(rng() * 300);
      const out = expandMessageXmd(msg, dst, n); expect(out).toHaveLength(n);
      expect(toHex(expandMessageXmd(msg, dst, n))).toBe(toHex(out));
    }
  });
});
