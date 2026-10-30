/** Interoperability with @noble/curves' own maintained RFC 9497 implementation (an independent oracle). */
import { describe, expect, it } from 'vitest';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { MODE_VOPRF, blind, blindEvaluate, deriveKeyPair, evaluate, finalize, randomBytes, toHex, utf8 } from '../src/index.js';

type NobleVoprf = {
  deriveKeyPair(seed: Uint8Array, info: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array };
  generateKeyPair(): { secretKey: Uint8Array; publicKey: Uint8Array };
  blind(input: Uint8Array): { blind: Uint8Array; blinded: Uint8Array };
  blindEvaluate(sk: Uint8Array, pk: Uint8Array, blinded: Uint8Array): { evaluated: Uint8Array; proof: Uint8Array };
  finalize(input: Uint8Array, blind: Uint8Array, evaluated: Uint8Array, blinded: Uint8Array, pk: Uint8Array, proof: Uint8Array): Uint8Array;
  evaluate(sk: Uint8Array, input: Uint8Array): Uint8Array;
};
const noble = (ristretto255_oprf as unknown as { voprf: NobleVoprf }).voprf;

describe('interop with noble ristretto255_oprf (VOPRF)', () => {
  it('derives identical keys', () => {
    const seed = new Uint8Array(32).fill(0xa3), info = utf8('test key');
    const a = noble.deriveKeyPair(seed, info), b = deriveKeyPair(seed, info, MODE_VOPRF);
    expect(toHex(a.secretKey)).toBe(toHex(b.secretKey)); expect(toHex(a.publicKey)).toBe(toHex(b.publicKey));
  });
  it('my client verifies noble\'s server proofs; noble\'s client verifies mine; all PRF outputs agree', () => {
    for (let i = 0; i < 10; i++) {
      const input = randomBytes(i * 13), kp = noble.generateKeyPair();
      const direct = toHex(noble.evaluate(kp.secretKey, input));
      const mine = blind(input), theirEval = noble.blindEvaluate(kp.secretKey, kp.publicKey, mine.blindedElement);
      expect(toHex(finalize(input, mine.blind, theirEval.evaluated, mine.blindedElement, kp.publicKey, theirEval.proof))).toBe(direct);
      const theirs = noble.blind(input), myEval = blindEvaluate(kp.secretKey, kp.publicKey, theirs.blinded);
      expect(toHex(noble.finalize(input, theirs.blind, myEval.evaluatedElement, theirs.blinded, kp.publicKey, myEval.proof))).toBe(direct);
      expect(toHex(evaluate(kp.secretKey, input))).toBe(direct);
    }
  });
});
