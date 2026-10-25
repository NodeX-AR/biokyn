/**
 * RFC 9497 VOPRF (mode 0x01) over ristretto255-SHA512: Blind, BlindEvaluate, Finalize, Evaluate.
 *
 *   client:  T = HashToGroup(x);  r ←$ Z_q*;  A = r·T            (blind)
 *   server:  B = k·A;  π = DLEQ(G, k·G, A, B)                     (blindEvaluate)
 *   client:  verify π;  N = r⁻¹·B = k·T;  K = H(x, N, "Finalize")  (finalize)
 */
import { ProtocolError, concat, lp2, utf8 } from '../bytes.js';
import {
  GENERATOR, IDENTITY, deserializeElement, deserializeScalar, invN, randomScalar, serializeElement,
  serializeScalar, smul, type Element,
} from './group.js';
import { generateProof, verifyProof } from './dleq.js';
import { contextString, hash, hashToGroup, hashToScalar, MODE_VOPRF } from './hash.js';

export interface BlindResult {
  /** 32-byte LE scalar. Secret; keep client-side only. */
  blind: Uint8Array;
  /** 32-byte ristretto255 element to send to the server. */
  blindedElement: Uint8Array;
}

export interface Evaluation {
  evaluatedElement: Uint8Array;
  /** c || s, 64 bytes. */
  proof: Uint8Array;
}

/** RFC 9497 §3.2.1 DeriveKeyPair. */
export function deriveKeyPair(seed: Uint8Array, info: Uint8Array): { sk: Uint8Array; pk: Uint8Array } {
  if (seed.length !== 32) throw new ProtocolError('SEED_LENGTH', 'seed must be 32 bytes');
  const deriveInput = concat(seed, lp2(info));
  let sk = 0n;
  for (let counter = 0; sk === 0n; counter++) {
    if (counter > 255) throw new ProtocolError('DERIVE_KEY_PAIR', 'DeriveKeyPairError');
    sk = hashToScalar(concat(deriveInput, new Uint8Array([counter])), 'DeriveKeyPair');
  }
  return { sk: serializeScalar(sk), pk: serializeElement(smul(GENERATOR, sk)) };
}

export function generateKeyPair(): { sk: Uint8Array; pk: Uint8Array } {
  const sk = randomScalar();
  return { sk: serializeScalar(sk), pk: serializeElement(smul(GENERATOR, sk)) };
}

/** Finalize hash: Hash(len(x)||x || len(N)||N || "Finalize"). */
function finalizeHash(input: Uint8Array, unblinded: Uint8Array): Uint8Array {
  return hash(concat(lp2(input), lp2(unblinded), utf8('Finalize')));
}

// ---------------------------------------------------------------- client

export function blind(input: Uint8Array): BlindResult {
  const T = hashToGroup(input, MODE_VOPRF);
  if (T.equals(IDENTITY)) throw new ProtocolError('INVALID_INPUT', 'input maps to the identity element');
  const r = randomScalar();
  return { blind: serializeScalar(r), blindedElement: serializeElement(smul(T, r)) };
}

/** Verifies the DLEQ proof, unblinds, and returns the 64-byte PRF output. Throws on bad proof. */
export function finalize(
  input: Uint8Array,
  blindScalar: Uint8Array,
  blindedElement: Uint8Array,
  evaluation: Evaluation,
  serverPublicKey: Uint8Array,
): Uint8Array {
  const pkS = deserializeElement(serverPublicKey);
  const A = deserializeElement(blindedElement);
  const B = deserializeElement(evaluation.evaluatedElement);
  if (!verifyProof(GENERATOR, pkS, [A], [B], evaluation.proof)) {
    throw new ProtocolError('PROOF_INVALID', 'DLEQ proof verification failed');
  }
  const r = deserializeScalar(blindScalar);
  const N = smul(B, invN(r));
  return finalizeHash(input, serializeElement(N));
}

// ---------------------------------------------------------------- server

export class VoprfServer {
  readonly publicKey: Uint8Array;
  private readonly k: bigint;
  private readonly pk: Element;

  constructor(secretKey: Uint8Array) {
    this.k = deserializeScalar(secretKey);
    if (this.k === 0n) throw new ProtocolError('BAD_KEY', 'secret key must be non-zero');
    this.pk = smul(GENERATOR, this.k);
    this.publicKey = serializeElement(this.pk);
  }

  static generate(): VoprfServer {
    return new VoprfServer(generateKeyPair().sk);
  }

  /** BlindEvaluate: sees only the blinded element, returns B = k·A and a DLEQ proof. */
  blindEvaluate(blindedElement: Uint8Array): Evaluation {
    const A = deserializeElement(blindedElement);
    const B = smul(A, this.k);
    const proof = generateProof(this.k, GENERATOR, this.pk, [A], [B]);
    return { evaluatedElement: serializeElement(B), proof };
  }

  /** Direct (unblinded) PRF evaluation, used at redemption to recompute the authenticator. */
  evaluate(input: Uint8Array): Uint8Array {
    const T = hashToGroup(input, MODE_VOPRF);
    if (T.equals(IDENTITY)) throw new ProtocolError('INVALID_INPUT', 'input maps to the identity element');
    return finalizeHash(input, serializeElement(smul(T, this.k)));
  }
}

export { contextString };
