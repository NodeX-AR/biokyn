import { describe, expect, it } from 'vitest';
import { parseRfc9497 } from '../../../scripts/rfc9497-parse.mjs';

const sample = `
A.1.  ristretto255-SHA512

A.1.1.  OPRF Mode

   seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
   KeyInfo = 74657374206b6579
   skSm = 5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e

   Input = 00
   Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706
   BlindedElement = 609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c
   EvaluationElement = 7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e
   Output = 527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3\\
   ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6

A.1.2.  VOPRF Mode

   seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
   KeyInfo = 74657374206b6579
   skSm = e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909
   pkSm = c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e

   Input = 00
   Blind = aa
   BlindedElement = bb
   EvaluationElement = cc
   Proof = dd
   ProofRandomScalar = ee
   Output = ff
   Input = 00, 5a5a
   Blind = aa, bb
A.2.  decaf448-SHAKE256
`;
describe('RFC 9497 vector parser', () => {
  it('parses sets, folded lines, and skips batch vectors', () => {
    const sets = parseRfc9497(sample);
    expect(sets).toHaveLength(2);
    expect(sets[0].mode).toBe(0);
    expect(sets[0].vectors[0].Output).toHaveLength(128);
    expect(sets[1].pkSm).toMatch(/^c803/);
    expect(sets[1].vectors).toHaveLength(1);
    expect(sets[1].vectors[0].ProofRandomScalar).toBe('ee');
  });
  it('fails loudly on unexpected documents', () => { expect(() => parseRfc9497('nothing here')).toThrow(); });
});

// Mimics the real document's quirks: a table of contents repeating the heading, page header/footer inside the appendix,
// a value starting on the line after "=", and a long value wrapped across a page break.
const realistic = `Table of Contents

   Appendix A.  Test Vectors . . . . . . . . . . . . . . . . . . . 55
     A.1.  ristretto255-SHA512 . . . . . . . . . . . . . . . . . . 56
       A.1.1.  OPRF Mode . . . . . . . . . . . . . . . . . . . . . 56
       A.1.2.  VOPRF Mode  . . . . . . . . . . . . . . . . . . . . 57
     A.2.  decaf448-SHAKE256 . . . . . . . . . . . . . . . . . . . 61

Appendix A.  Test Vectors

A.1.  ristretto255-SHA512

A.1.1.  OPRF Mode

   seed =
   a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
   KeyInfo = 74657374206b6579
   skSm = 5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e

A.1.1.1.  Test Vector 1, Batch Size 1

   Input = 00
   Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706
   BlindedElement = 609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c
   EvaluationElement = 7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e
   Output =
   527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd6995



Davidson, et al.             Informational                    [Page 56]
RFC 9497                          OPRF                    December 2023


   5851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6

A.1.2.  VOPRF Mode

   seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
   KeyInfo = 74657374206b6579
   skSm = e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909
   pkSm = c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e

   Input = 00
   Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706
   BlindedElement = 863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945
   EvaluationElement = aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e
   Proof = ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d
   ProofRandomScalar = 222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e
   Output = 00

A.2.  decaf448-SHAKE256
`;
describe('RFC 9497 vector parser (realistic layout)', () => {
  it('skips the table of contents and reassembles values wrapped across page breaks', () => {
    const sets = parseRfc9497(realistic);
    expect(sets).toHaveLength(2);
    expect(sets[0].seed).toHaveLength(64);
    expect(sets[0].vectors[0].Output).toBe('527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6');
    expect(sets[1].pkSm).toMatch(/^c803e2cc/);
  });
  it('a document with only a table-of-contents entry fails with a specific message', () => {
    expect(() => parseRfc9497('Contents\n   A.1.  ristretto255-SHA512 . . . . . . 56\n')).toThrow(/outside the table of contents/);
  });
});
