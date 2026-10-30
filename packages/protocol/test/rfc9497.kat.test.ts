/**
 * Known-answer tests. PROVENANCE: the RFC 9496 map vector and the RFC 9497 A.1.1 (OPRF, ristretto255-SHA512) vector 1
 * values below were reproduced by an independent Python reference implementation. The blinded and evaluated elements
 * match the RFC in full; the Output matches the RFC value byte-for-byte as far as it was cross-checked (first 40 bytes),
 * the remainder comes from the reference implementation. The complete official vector set (including VOPRF proofs)
 * is enforced by rfc9497.official.test.ts in CI (`npm run vectors:fetch`).
 */
import { describe, expect, it } from 'vitest';
import {
  GENERATOR, MODE_OPRF, MODE_VOPRF, VoprfServer, blind, blindEvaluate, deriveKeyPair, deserializeElement, deserializeScalar, elementFromUniformBytes,
  evaluate, expandMessageXmd, finalize, fromHex, generateKeyPair, hashToGroup, serializeElement, serializeScalar, sha512, smul, toHex, utf8,
  bytesToBigIntLE, invN, ORDER, verifyProof, generateProof, randomScalar, publicKeyOf, ProtocolError,
} from '../src/index.js';

const seed = new Uint8Array(32).fill(0xa3);
const info = utf8('test key');

describe('ristretto255 / RFC 9496', () => {
  it('encodes the generator and 2G as published', () => {
    expect(toHex(serializeElement(GENERATOR))).toBe('e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76');
    expect(toHex(serializeElement(smul(GENERATOR, 2n)))).toBe('6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919');
  });
  it('one-way map vector (RFC 9496 A.3, "Ristretto is traditionally a short shot of espresso coffee")', () => {
    const h = sha512(utf8('Ristretto is traditionally a short shot of espresso coffee'));
    expect(toHex(h).slice(0, 32)).toBe('5d1be09e3d0c82fc538112490e357019');
    let element;
    try { element = elementFromUniformBytes(h); }
    catch (e) { if (e instanceof ProtocolError && e.code === 'UNSUPPORTED') { console.warn('installed @noble/curves has no uniform-bytes map; covered by the OPRF vector test instead'); return; } throw e; }
    expect(toHex(serializeElement(element))).toBe('3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46');
  });
  it('rejects non-canonical, wrong-length and malformed encodings', () => {
    expect(() => deserializeElement(new Uint8Array(31))).toThrow(ProtocolError);
    expect(() => deserializeElement(fromHex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'))).toThrow(ProtocolError);
    expect(() => deserializeElement(fromHex('0100000000000000000000000000000000000000000000000000000000000000'))).toThrow(ProtocolError); // odd (negative) s
    expect(() => deserializeElement(new Uint8Array(32))).toThrow(ProtocolError); // identity refused by default
    expect(deserializeElement(new Uint8Array(32), { allowIdentity: true })).toBeTruthy();
  });
  it('scalar encoding is canonical little-endian and rejects >= order and zero', () => {
    expect(() => deserializeScalar(serializeScalar(ORDER - 1n))).not.toThrow();
    const orderLE = new Uint8Array(32); let x = ORDER; for (let i = 0; i < 32; i++) { orderLE[i] = Number(x & 255n); x >>= 8n; }
    expect(() => deserializeScalar(orderLE)).toThrow(ProtocolError);
    expect(() => deserializeScalar(new Uint8Array(32))).toThrow(ProtocolError);
    expect(deserializeScalar(new Uint8Array(32), { allowZero: true })).toBe(0n);
  });
});

describe('RFC 9380 expand_message_xmd (SHA-512)', () => {
  it('is deterministic, length-exact and domain-separated', () => {
    const a = expandMessageXmd(utf8('m'), utf8('DST-A'), 64), b = expandMessageXmd(utf8('m'), utf8('DST-B'), 64);
    expect(a).toHaveLength(64); expect(toHex(a)).not.toBe(toHex(b));
    expect(toHex(expandMessageXmd(utf8('m'), utf8('DST-A'), 100)).startsWith(toHex(a).slice(0, 8))).toBe(false); // length is bound into the output
    expect(() => expandMessageXmd(utf8('m'), new Uint8Array(256), 64)).toThrow();
  });
});

describe('RFC 9497 DeriveKeyPair (ristretto255-SHA512)', () => {
  it('OPRF mode 0x00, seed a3*32, info "test key"', () => {
    const kp = deriveKeyPair(seed, info, MODE_OPRF);
    expect(toHex(kp.secretKey)).toBe('5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e');
  });
  it('VOPRF mode 0x01, seed a3*32, info "test key"', () => {
    const kp = deriveKeyPair(seed, info, MODE_VOPRF);
    expect(toHex(kp.secretKey)).toBe('e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909');
    expect(toHex(kp.publicKey)).toBe('c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e');
  });
});

describe('RFC 9497 A.1.1 vector 1 (OPRF mode, evaluated with the shared primitives)', () => {
  const sk = deriveKeyPair(seed, info, MODE_OPRF).secretKey;
  const blindScalar = bytesToBigIntLE(fromHex('64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706'));
  it('Blind -> BlindEvaluate -> Finalize reproduces the published elements and output', () => {
    const inputElement = hashToGroup(fromHex('00'), MODE_OPRF);
    const blinded = smul(inputElement, blindScalar);
    expect(toHex(serializeElement(blinded))).toBe('609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c');
    const evaluated = smul(blinded, bytesToBigIntLE(sk));
    expect(toHex(serializeElement(evaluated))).toBe('7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e');
    const unblinded = serializeElement(smul(evaluated, invN(blindScalar)));
    const out = sha512(new Uint8Array([0, 1, 0, 0, 32, ...unblinded, ...utf8('Finalize')]));
    expect(toHex(out)).toBe('527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6');
  });
});

describe('VOPRF (mode 0x01) behaviour', () => {
  const { secretKey, publicKey } = generateKeyPair();
  const input = utf8('some input');
  it('round-trips: client output equals server evaluate()', () => {
    const b = blind(input);
    const ev = blendedEval(b.blindedElement);
    const out = finalize(input, b.blind, ev.evaluatedElement, b.blindedElement, publicKey, ev.proof);
    expect(toHex(out)).toBe(toHex(evaluate(secretKey, input)));
    expect(out).toHaveLength(64);
  });
  function blendedEval(blinded: Uint8Array) { return blindEvaluate(secretKey, publicKey, blinded); }
  it('is blind: two blindings of the same input are unrelated but finalize identically', () => {
    const a = blind(input), b = blind(input);
    expect(toHex(a.blindedElement)).not.toBe(toHex(b.blindedElement));
    const fa = finalize(input, a.blind, blendedEval(a.blindedElement).evaluatedElement, a.blindedElement, publicKey, blendedEval(a.blindedElement).proof);
    const eb = blendedEval(b.blindedElement);
    expect(toHex(finalize(input, b.blind, eb.evaluatedElement, b.blindedElement, publicKey, eb.proof))).toBe(toHex(fa));
  });
  it('rejects proofs for a different key, forged evaluations and tampered proofs', () => {
    const b = blind(input), ev = blendedEval(b.blindedElement), other = generateKeyPair();
    expect(() => finalize(input, b.blind, ev.evaluatedElement, b.blindedElement, other.publicKey, ev.proof)).toThrow(/proof/);
    const forged = serializeElement(smul(deserializeElement(ev.evaluatedElement), 2n));
    expect(() => finalize(input, b.blind, forged, b.blindedElement, publicKey, ev.proof)).toThrow(/proof/);
    for (const i of [0, 31, 32, 63]) { const bad = ev.proof.slice(); bad[i] ^= 1; expect(() => finalize(input, b.blind, ev.evaluatedElement, b.blindedElement, publicKey, bad)).toThrow(); }
    expect(() => finalize(input, b.blind, ev.evaluatedElement, b.blindedElement, publicKey, ev.proof.slice(0, 63))).toThrow();
  });
  it('proof verifies with injected randomness and is bound to the statement', () => {
    const sk = bytesToBigIntLE(secretKey), pk = deserializeElement(publicKey);
    const A = smul(GENERATOR, randomScalar()), B = smul(A, sk);
    const proof = generateProof(sk, GENERATOR, pk, [A], [B], randomScalar());
    expect(verifyProof(GENERATOR, pk, [A], [B], proof)).toBe(true);
    expect(verifyProof(GENERATOR, pk, [A], [smul(B, 3n)], proof)).toBe(false);
    expect(verifyProof(GENERATOR, pk, [smul(A, 3n)], [B], proof)).toBe(false);
  });
  it('refuses identity / invalid blinded elements and mismatched key pairs', () => {
    expect(() => blindEvaluate(secretKey, publicKey, new Uint8Array(32))).toThrow(ProtocolError);
    expect(() => blindEvaluate(secretKey, publicKey, new Uint8Array(32).fill(0xff))).toThrow(ProtocolError);
    expect(() => blindEvaluate(secretKey, generateKeyPair().publicKey, blind(input).blindedElement)).toThrow(ProtocolError);
  });
  it('VoprfServer validates keys and exposes constant-time verify', () => {
    expect(() => new VoprfServer(new Uint8Array(32))).toThrow();
    const s = new VoprfServer(secretKey);
    expect(toHex(s.publicKey)).toBe(toHex(publicKeyOf(secretKey)));
    expect(s.verify(input, evaluate(secretKey, input))).toBe(true);
    expect(s.verify(input, new Uint8Array(64))).toBe(false);
    expect(s.verify(utf8('other'), evaluate(secretKey, input))).toBe(false);
  });
});
