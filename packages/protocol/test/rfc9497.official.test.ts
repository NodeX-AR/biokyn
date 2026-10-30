/**
 * Official RFC 9497 Appendix A.1 vectors (ristretto255-SHA512). The JSON file is produced from the RFC text by
 * `npm run vectors:fetch` (scripts/fetch-rfc9497-vectors.mjs). In CI (REQUIRE_OFFICIAL_VECTORS=1) a missing or
 * unparsable file FAILS the build; locally the suite reports itself as not run rather than silently passing.
 */
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { MODE_OPRF, MODE_VOPRF, blindEvaluate, bytesToBigIntLE, deriveKeyPair, deserializeElement, evaluate, finalize, fromHex, hashToGroup, invN, serializeElement, sha512, smul, toHex, utf8 } from '../src/index.js';

interface Vec { mode: number; seed: string; keyInfo: string; skSm: string; pkSm?: string; vectors: Array<{ Input: string; Blind: string; BlindedElement: string; EvaluationElement: string; Output: string; Proof?: string; ProofRandomScalar?: string }> }
const file = fileURLToPath(new URL('./vectors/rfc9497-ristretto255-sha512.json', import.meta.url));
const required = process.env.REQUIRE_OFFICIAL_VECTORS === '1';

describe('RFC 9497 official vectors', () => {
  it('vector file is present when required', () => { if (required) expect(existsSync(file)).toBe(true); });
  if (!existsSync(file)) return;
  const sets = JSON.parse(readFileSync(file, 'utf8')) as Vec[];
  it('contains the OPRF and VOPRF sets', () => { expect(sets.some((s) => s.mode === MODE_OPRF)).toBe(true); expect(sets.some((s) => s.mode === MODE_VOPRF)).toBe(true); });
  for (const set of sets.filter((s) => s.mode === MODE_OPRF || s.mode === MODE_VOPRF)) {
    describe(`mode ${set.mode}`, () => {
      const kp = deriveKeyPair(fromHex(set.seed), fromHex(set.keyInfo), set.mode);
      it('DeriveKeyPair', () => { expect(toHex(kp.secretKey)).toBe(set.skSm); if (set.pkSm) expect(toHex(kp.publicKey)).toBe(set.pkSm); });
      set.vectors.forEach((v, i) => it(`vector ${i + 1}`, () => {
        const input = fromHex(v.Input), r = bytesToBigIntLE(fromHex(v.Blind));
        const blinded = smul(hashToGroup(input, set.mode), r);
        expect(toHex(serializeElement(blinded))).toBe(v.BlindedElement);
        const evaluated = smul(blinded, bytesToBigIntLE(kp.secretKey));
        expect(toHex(serializeElement(evaluated))).toBe(v.EvaluationElement);
        if (set.mode === MODE_VOPRF) {
          const ev = blindEvaluate(kp.secretKey, kp.publicKey, fromHex(v.BlindedElement), bytesToBigIntLE(fromHex(v.ProofRandomScalar!)));
          expect(toHex(ev.proof)).toBe(v.Proof);
          expect(toHex(finalize(input, fromHex(v.Blind), fromHex(v.EvaluationElement), fromHex(v.BlindedElement), kp.publicKey, fromHex(v.Proof!)))).toBe(v.Output);
        } else {
          const out = sha512(new Uint8Array([(input.length >> 8) & 255, input.length & 255, ...input, 0, 32, ...serializeElement(smul(evaluated, invN(r))), ...utf8('Finalize')]));
          expect(toHex(out)).toBe(v.Output);
        }
        expect(toHex(evaluate(kp.secretKey, input, set.mode))).toBe(v.Output);
      }));
    });
  }
});
