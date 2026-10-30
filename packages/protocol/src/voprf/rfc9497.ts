/**
 * RFC 9497 VOPRF (mode 0x01) for the ristretto255-SHA512 ciphersuite: key derivation, blind, blind-evaluate with a
 * DLEQ proof, finalize (verifying that proof) and the server-side direct evaluation.
 *
 * Status: implemented from the RFC text and cross-checked against an independent reference implementation and the
 * RFC 9496 / RFC 9497 known-answer values in test/rfc9497.kat.test.ts. The *official* appendix vectors are
 * enforced in CI by `npm run vectors:fetch` + test/rfc9497.official.test.ts. Only single-element batches
 * (m = 1) are supported; this is all BioKyn needs.
 */
import { concat, i2osp, lp2, utf8, ProtocolError, ctEqual } from '../bytes.js';
import { sha512 } from '../hashes.js';
import {
  GENERATOR, IDENTITY, ORDER, addPoints, bytesToBigIntLE, deserializeElement, deserializeScalar, hashToElement, invN,
  modN, randomScalar, serializeElement, serializeScalar, smul, type Element,
} from './group.js';

export const MODE_OPRF = 0x00;
export const MODE_VOPRF = 0x01;
export const IDENTIFIER = 'ristretto255-SHA512';
export const OUTPUT_LENGTH = 64;
export const PROOF_LENGTH = 64;

/** contextString = "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier */
export const contextString = (mode: number = MODE_VOPRF): Uint8Array => concat(utf8('OPRFV1-'), i2osp(mode, 1), utf8(`-${IDENTIFIER}`));
const dst = (prefix: string, mode: number): Uint8Array => concat(utf8(prefix), contextString(mode));

/** expand_message_xmd with SHA-512 (RFC 9380 §5.3.1). */
export function expandMessageXmd(msg: Uint8Array, dstBytes: Uint8Array, len: number): Uint8Array {
  const bInBytes = 64, rInBytes = 128, ell = Math.ceil(len / bInBytes);
  if (ell > 255 || len > 65535 || dstBytes.length > 255 || len < 1) throw new ProtocolError('XMD', 'invalid expand_message_xmd parameters');
  const dstPrime = concat(dstBytes, i2osp(dstBytes.length, 1));
  const b0 = sha512(concat(new Uint8Array(rInBytes), msg, i2osp(len, 2), i2osp(0, 1), dstPrime));
  const out: Uint8Array[] = []; let bi = sha512(concat(b0, i2osp(1, 1), dstPrime)); out.push(bi);
  for (let i = 2; i <= ell; i++) {
    const x = new Uint8Array(b0.length); for (let j = 0; j < x.length; j++) x[j] = b0[j]! ^ bi[j]!;
    bi = sha512(concat(x, i2osp(i, 1), dstPrime)); out.push(bi);
  }
  return concat(...out).slice(0, len);
}

/** RFC 9497 §4.1: 64 expanded bytes interpreted LITTLE-endian, reduced mod the group order. */
export function hashToScalar(msg: Uint8Array, domain: Uint8Array = dst('HashToScalar-', MODE_VOPRF)): bigint {
  return modN(bytesToBigIntLE(expandMessageXmd(msg, domain, 64)));
}
export function hashToGroup(msg: Uint8Array, mode: number = MODE_VOPRF): Element {
  return hashToElement(msg, dst('HashToGroup-', mode), expandMessageXmd);
}

export interface KeyPair { secretKey: Uint8Array; publicKey: Uint8Array }
export interface BlindResult { blind: Uint8Array; blindedElement: Uint8Array }
export interface Evaluation { evaluatedElement: Uint8Array; proof: Uint8Array }

/** RFC 9497 §3.2.1 DeriveKeyPair. */
export function deriveKeyPair(seed: Uint8Array, info: Uint8Array, mode: number = MODE_VOPRF): KeyPair {
  if (seed.length !== 32 || info.length > 65535) throw new ProtocolError('KEY', 'seed must be 32 bytes');
  const deriveInput = concat(seed, lp2(info));
  for (let counter = 0; counter <= 255; counter++) {
    const sk = hashToScalar(concat(deriveInput, i2osp(counter, 1)), dst('DeriveKeyPair', mode));
    if (sk !== 0n) return { secretKey: serializeScalar(sk), publicKey: serializeElement(smul(GENERATOR, sk)) };
  }
  throw new ProtocolError('KEY', 'DeriveKeyPair failed');
}
export function generateKeyPair(): KeyPair {
  const sk = randomScalar();
  return { secretKey: serializeScalar(sk), publicKey: serializeElement(smul(GENERATOR, sk)) };
}
export const publicKeyOf = (secretKey: Uint8Array): Uint8Array => serializeElement(smul(GENERATOR, deserializeScalar(secretKey)));

/** RFC 9497 §3.3.1 Blind. `r` is injectable only for known-answer tests. */
export function blind(input: Uint8Array, r: bigint = randomScalar()): BlindResult {
  const inputElement = hashToGroup(input, MODE_VOPRF);
  if (inputElement.equals(IDENTITY)) throw new ProtocolError('INPUT', 'input maps to the identity element');
  return { blind: serializeScalar(r), blindedElement: serializeElement(smul(inputElement, r)) };
}

// ------------------------------------------------------------------ DLEQ proof (RFC 9497 §2.2.1)

const composites = (k: bigint | null, B: Element, C: Element[], D: Element[]): { M: Element; Z: Element } => {
  const bm = serializeElement(B);
  const seedDst = dst('Seed-', MODE_VOPRF);
  const seed = sha512(concat(lp2(bm), lp2(seedDst)));
  let M = IDENTITY, Z = IDENTITY;
  for (let i = 0; i < C.length; i++) {
    const di = hashToScalar(concat(lp2(seed), i2osp(i, 2), lp2(serializeElement(C[i]!)), lp2(serializeElement(D[i]!)), utf8('Composite')), dst('HashToScalar-', MODE_VOPRF));
    M = addPoints(smul(C[i]!, di), M);
    if (k === null) Z = addPoints(smul(D[i]!, di), Z);
  }
  if (k !== null) Z = smul(M, k);
  return { M, Z };
};
const challengeScalar = (B: Element, M: Element, Z: Element, t2: Element, t3: Element): bigint =>
  hashToScalar(concat(lp2(serializeElement(B)), lp2(serializeElement(M)), lp2(serializeElement(Z)), lp2(serializeElement(t2)), lp2(serializeElement(t3)), utf8('Challenge')), dst('HashToScalar-', MODE_VOPRF));

export function generateProof(k: bigint, A: Element, B: Element, C: Element[], D: Element[], r: bigint = randomScalar()): Uint8Array {
  const { M, Z } = composites(k, B, C, D);
  const t2 = smul(A, r), t3 = smul(M, r);
  const c = challengeScalar(B, M, Z, t2, t3);
  return concat(serializeScalar(c), serializeScalar(modN(r - c * k)));
}
export function verifyProof(A: Element, B: Element, C: Element[], D: Element[], proof: Uint8Array): boolean {
  try {
    if (proof.length !== PROOF_LENGTH) return false;
    const c = deserializeScalar(proof.subarray(0, 32), { allowZero: true }), s = deserializeScalar(proof.subarray(32), { allowZero: true });
    const { M, Z } = composites(null, B, C, D);
    const t2 = addPoints(smul(A, s), smul(B, c)), t3 = addPoints(smul(M, s), smul(Z, c));
    return challengeScalar(B, M, Z, t2, t3) === c;
  } catch { return false; }
}

// ------------------------------------------------------------------ evaluation / finalization

/** RFC 9497 §3.3.2 BlindEvaluate. `proofRandomness` is injectable only for known-answer tests. */
export function blindEvaluate(secretKey: Uint8Array, publicKey: Uint8Array, blindedElement: Uint8Array, proofRandomness?: bigint): Evaluation {
  const sk = deserializeScalar(secretKey);
  const A = deserializeElement(blindedElement);
  const pk = deserializeElement(publicKey);
  const B = smul(A, sk);
  if (!smul(GENERATOR, sk).equals(pk)) throw new ProtocolError('KEY', 'public key does not match secret key');
  return { evaluatedElement: serializeElement(B), proof: generateProof(sk, GENERATOR, pk, [A], [B], proofRandomness) };
}

const finalizeHash = (input: Uint8Array, unblinded: Uint8Array): Uint8Array => sha512(concat(lp2(input), lp2(unblinded), utf8('Finalize')));

/** RFC 9497 §3.3.2 Finalize: verifies the DLEQ proof, unblinds, and returns the 64-byte PRF output. */
export function finalize(input: Uint8Array, blindBytes: Uint8Array, evaluatedElement: Uint8Array, blindedElement: Uint8Array, publicKey: Uint8Array, proof: Uint8Array): Uint8Array {
  const r = deserializeScalar(blindBytes);
  const B = deserializeElement(evaluatedElement, { allowIdentity: true });
  const A = deserializeElement(blindedElement);
  const pk = deserializeElement(publicKey);
  if (!verifyProof(GENERATOR, pk, [A], [B], proof)) throw new ProtocolError('PROOF', 'invalid proof');
  return finalizeHash(input, serializeElement(smul(B, invN(r))));
}

/** RFC 9497 §3.3.2 Evaluate: the server-side direct PRF value F(sk, input). */
export function evaluate(secretKey: Uint8Array, input: Uint8Array, mode: number = MODE_VOPRF): Uint8Array {
  const sk = deserializeScalar(secretKey);
  const inputElement = hashToGroup(input, mode);
  if (inputElement.equals(IDENTITY)) throw new ProtocolError('INPUT', 'input maps to the identity element');
  return finalizeHash(input, serializeElement(smul(inputElement, sk)));
}

/** Holds one issuer key. The secret scalar never leaves this object. */
export class VoprfServer {
  readonly publicKey: Uint8Array;
  private readonly sk: Uint8Array;
  constructor(secretKey: Uint8Array) {
    deserializeScalar(secretKey); // validates canonical, non-zero
    this.sk = Uint8Array.from(secretKey);
    this.publicKey = publicKeyOf(this.sk);
  }
  blindEvaluate(blindedElement: Uint8Array, proofRandomness?: bigint): Evaluation { return blindEvaluate(this.sk, this.publicKey, blindedElement, proofRandomness); }
  evaluate(input: Uint8Array): Uint8Array { return evaluate(this.sk, input); }
  /** Constant-time check that `candidate` equals F(sk, input). */
  verify(input: Uint8Array, candidate: Uint8Array): boolean { try { return ctEqual(this.evaluate(input), candidate); } catch { return false; } }
}
export { ORDER };
