import { describe, expect, it } from 'vitest';
import {
  PROOF_LENGTH, ProtocolError, TOKEN_LEN, VoprfServer, beginIssuance, blind, challengeDigest, completeIssuance,
  concat, deriveKeyPair, finalize, fromAuthorizationHeader, generateProof, parseToken, serializeToken,
  tokenNullifier, toAuthorizationHeader, utf8, verifyProof, verifyToken, toHex,
} from '../src/index.js';
import { expandMessageXmd } from '../src/ristretto/hash.js';
import { GENERATOR, deserializeElement, deserializeScalar, randomScalar, smul } from '../src/ristretto/group.js';

describe('expand_message_xmd', () => {
  it('RFC 9380 K.1 vector (SHA-256 is covered upstream; here SHA-512 is length/determinism checked)', () => {
    const a = expandMessageXmd(utf8('abc'), utf8('QUUX-V01-CS02-with-expander-SHA512-256'), 100);
    const b = expandMessageXmd(utf8('abc'), utf8('QUUX-V01-CS02-with-expander-SHA512-256'), 100);
    expect(a).toHaveLength(100);
    expect(toHex(a)).toBe(toHex(b));
    expect(toHex(expandMessageXmd(utf8('abd'), utf8('QUUX-V01-CS02-with-expander-SHA512-256'), 100))).not.toBe(toHex(a));
  });
});

describe('VOPRF', () => {
  const server = VoprfServer.generate();
  it('blind → evaluate → finalize equals direct evaluation (and blinding is randomized)', () => {
    const x = utf8('hello biokyn');
    const b1 = blind(x), b2 = blind(x);
    expect(toHex(b1.blindedElement)).not.toBe(toHex(b2.blindedElement));
    const ev = server.blindEvaluate(b1.blindedElement);
    const out = finalize(x, b1.blind, b1.blindedElement, ev, server.publicKey);
    expect(toHex(out)).toBe(toHex(server.evaluate(x)));
    const ev2 = server.blindEvaluate(b2.blindedElement);
    expect(toHex(finalize(x, b2.blind, b2.blindedElement, ev2, server.publicKey))).toBe(toHex(out));
  });
  it('rejects a proof made under a different key', () => {
    const evil = VoprfServer.generate();
    const x = utf8('x'), b = blind(x);
    expect(() => finalize(x, b.blind, b.blindedElement, evil.blindEvaluate(b.blindedElement), server.publicKey)).toThrow(ProtocolError);
  });
  it('rejects a tampered evaluation and tampered proof bytes', () => {
    const x = utf8('x'), b = blind(x), ev = server.blindEvaluate(b.blindedElement);
    const badProof = ev.proof.slice(); badProof[5]! ^= 1;
    expect(() => finalize(x, b.blind, b.blindedElement, { ...ev, proof: badProof }, server.publicKey)).toThrow();
    const other = server.blindEvaluate(blind(utf8('y')).blindedElement);
    expect(() => finalize(x, b.blind, b.blindedElement, { evaluatedElement: other.evaluatedElement, proof: ev.proof }, server.publicKey)).toThrow();
  });
  it('rejects identity / malformed elements', () => {
    expect(() => server.blindEvaluate(new Uint8Array(32))).toThrow(ProtocolError);
    expect(() => server.blindEvaluate(new Uint8Array(31))).toThrow(ProtocolError);
  });
  it('DeriveKeyPair is deterministic', () => {
    const seed = new Uint8Array(32).fill(7);
    expect(toHex(deriveKeyPair(seed, utf8('k')).pk)).toBe(toHex(deriveKeyPair(seed, utf8('k')).pk));
    expect(toHex(deriveKeyPair(seed, utf8('k')).pk)).not.toBe(toHex(deriveKeyPair(seed, utf8('j')).pk));
  });
});

describe('DLEQ (batched)', () => {
  it('proves and verifies for several pairs; fails if one pair uses a different key', () => {
    const k = randomScalar();
    const B = smul(GENERATOR, k);
    const C = [1, 2, 3].map(() => smul(GENERATOR, randomScalar()));
    const D = C.map((c) => smul(c, k));
    const proof = generateProof(k, GENERATOR, B, C, D);
    expect(proof).toHaveLength(PROOF_LENGTH);
    expect(verifyProof(GENERATOR, B, C, D, proof)).toBe(true);
    const D2 = [...D]; D2[1] = smul(C[1]!, randomScalar());
    expect(verifyProof(GENERATOR, B, C, D2, proof)).toBe(false);
    expect(verifyProof(GENERATOR, B, C, D, new Uint8Array(63))).toBe(false);
    expect(verifyProof(GENERATOR, B, C, D, new Uint8Array(64).fill(0xff))).toBe(false);
  });
  it('scalar codec rejects non-canonical values', () => {
    expect(() => deserializeScalar(new Uint8Array(32).fill(0xff))).toThrow();
    expect(() => deserializeElement(new Uint8Array(32).fill(0xff))).toThrow();
  });
});

describe('token issuance and redemption', () => {
  const server = VoprfServer.generate();
  const challenge = { issuer: 'verify.example', origin: 'https://example.com', redemptionContext: new Uint8Array(32).fill(1) };
  it('full round trip, header codec, wrong-challenge and forgery rejection', () => {
    const pending = beginIssuance(challenge, server.publicKey);
    const token = completeIssuance(pending, server.blindEvaluate(pending.blindedElement), server.publicKey);
    expect(serializeToken(token)).toHaveLength(TOKEN_LEN);

    const wire = fromAuthorizationHeader(toAuthorizationHeader(token));
    expect(verifyToken(server, wire, challengeDigest(challenge))).toEqual({ ok: true });
    expect(verifyToken(server, wire, challengeDigest({ ...challenge, origin: 'https://evil.test' }))).toEqual({ ok: false, reason: 'wrong-challenge' });

    const forged = parseToken(serializeToken(token));
    forged.authenticator[0]! ^= 1;
    expect(verifyToken(server, forged, challengeDigest(challenge))).toEqual({ ok: false, reason: 'bad-authenticator' });
    expect(verifyToken(VoprfServer.generate(), wire, challengeDigest(challenge))).toEqual({ ok: false, reason: 'wrong-key' });
  });
  it('nullifier is stable per token and distinct across tokens', () => {
    const mk = () => { const p = beginIssuance(challenge, server.publicKey); return completeIssuance(p, server.blindEvaluate(p.blindedElement), server.publicKey); };
    const a = mk(), b = mk();
    expect(toHex(tokenNullifier(a))).toBe(toHex(tokenNullifier(a)));
    expect(toHex(tokenNullifier(a))).not.toBe(toHex(tokenNullifier(b)));
    expect(concat(new Uint8Array(1)).length).toBe(1);
  });
});
