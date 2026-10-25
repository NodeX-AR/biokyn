/**
 * Batched DLEQ proof of RFC 9497 §2.2.2 (ristretto255-SHA512, VOPRF mode).
 *
 * Statement: ∃ k such that  B = k·A  and  D_i = k·C_i  for every i.
 * Non-interactive via Fiat–Shamir (challenge = HashToScalar over a SHA-512-based transcript).
 *
 *   prover:  r ←$ Z_q;  t2 = r·A;  t3 = r·M;  c = H(B, M, Z, t2, t3);  s = r − c·k
 *   verifier: t2' = s·A + c·B;  t3' = s·M + c·Z;  accept iff H(B, M, Z, t2', t3') = c
 *
 * where (M, Z) are random-linear-combination composites of the (C_i, D_i) pairs.
 */
import { ProtocolError, concat, ctEqual, i2osp, lp2, utf8 } from '../bytes.js';
import {
  IDENTITY, NS, deserializeScalar, modN, randomScalar, serializeElement, serializeScalar, smul, type Element,
} from './group.js';
import { contextString, hash, hashToScalar, MODE_VOPRF } from './hash.js';

export const PROOF_LENGTH = 2 * NS;

function seedFor(B: Element): Uint8Array {
  const seedDst = concat(utf8('Seed-'), contextString(MODE_VOPRF));
  return hash(concat(lp2(serializeElement(B)), lp2(seedDst)));
}

function compositeScalar(seed: Uint8Array, i: number, Ci: Element, Di: Element): bigint {
  const input = concat(lp2(seed), i2osp(i, 2), lp2(serializeElement(Ci)), lp2(serializeElement(Di)), utf8('Composite'));
  return hashToScalar(input, 'HashToScalar-');
}

function checkLists(C: Element[], D: Element[]): void {
  if (C.length !== D.length || C.length === 0 || C.length >= 2 ** 16) {
    throw new ProtocolError('DLEQ_INPUT', 'C and D must be equal-length, non-empty lists');
  }
}

/** ComputeCompositesFast (prover, knows k):  M = Σ d_i·C_i,  Z = k·M. */
function compositesProver(k: bigint, B: Element, C: Element[], D: Element[]): { M: Element; Z: Element } {
  checkLists(C, D);
  const seed = seedFor(B);
  let M = IDENTITY;
  for (let i = 0; i < C.length; i++) M = M.add(smul(C[i]!, compositeScalar(seed, i, C[i]!, D[i]!)));
  return { M, Z: smul(M, k) };
}

/** ComputeComposites (verifier):  M = Σ d_i·C_i,  Z = Σ d_i·D_i. */
function compositesVerifier(B: Element, C: Element[], D: Element[]): { M: Element; Z: Element } {
  checkLists(C, D);
  const seed = seedFor(B);
  let M = IDENTITY;
  let Z = IDENTITY;
  for (let i = 0; i < C.length; i++) {
    const d = compositeScalar(seed, i, C[i]!, D[i]!);
    M = M.add(smul(C[i]!, d));
    Z = Z.add(smul(D[i]!, d));
  }
  return { M, Z };
}

function challenge(B: Element, M: Element, Z: Element, t2: Element, t3: Element): bigint {
  const transcript = concat(
    lp2(serializeElement(B)), lp2(serializeElement(M)), lp2(serializeElement(Z)),
    lp2(serializeElement(t2)), lp2(serializeElement(t3)), utf8('Challenge'),
  );
  return hashToScalar(transcript, 'HashToScalar-');
}

/** GenerateProof(k, A, B, C, D) -> c || s  (each a 32-byte little-endian scalar). */
export function generateProof(k: bigint, A: Element, B: Element, C: Element[], D: Element[]): Uint8Array {
  const { M, Z } = compositesProver(k, B, C, D);
  const r = randomScalar();
  const t2 = smul(A, r);
  const t3 = smul(M, r);
  const c = challenge(B, M, Z, t2, t3);
  const s = modN(r - c * k);
  return concat(serializeScalar(c), serializeScalar(s));
}

/** VerifyProof(A, B, C, D, proof). Never throws on a malformed proof; returns false. */
export function verifyProof(A: Element, B: Element, C: Element[], D: Element[], proof: Uint8Array): boolean {
  if (proof.length !== PROOF_LENGTH) return false;
  let c: bigint, s: bigint;
  try {
    c = deserializeScalar(proof.subarray(0, NS));
    s = deserializeScalar(proof.subarray(NS));
  } catch {
    return false;
  }
  const { M, Z } = compositesVerifier(B, C, D);
  const t2 = smul(A, s).add(smul(B, c));
  const t3 = smul(M, s).add(smul(Z, c));
  const expected = challenge(B, M, Z, t2, t3);
  return ctEqual(serializeScalar(expected), serializeScalar(c));
}
