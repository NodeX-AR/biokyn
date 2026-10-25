/**
 * ristretto255 group + scalar field helpers (RFC 9496 encodings, RFC 9497 ciphersuite
 * "ristretto255-SHA512"). Scalar multiplication in @noble/curves is constant-time
 * (Montgomery-ladder-style wNAF with fake-point masking); `multiplyUnsafe` is never used.
 */
import { RistrettoPoint, ed25519 } from '@noble/curves/ed25519';
import { invert, mod } from '@noble/curves/abstract/modular';
import { ProtocolError, os2ip, randomBytes } from '../bytes.js';

export type Element = InstanceType<typeof RistrettoPoint>;

export const ORDER: bigint = ed25519.CURVE.n;
export const GENERATOR: Element = RistrettoPoint.BASE;
export const IDENTITY: Element = RistrettoPoint.ZERO;
export const NE = 32;
export const NS = 32;

export const modN = (a: bigint): bigint => mod(a, ORDER);
export const invN = (a: bigint): bigint => invert(modN(a), ORDER);

/** k·P with k reduced mod n; k = 0 yields the identity (noble rejects 0 scalars). */
export function smul(p: Element, k: bigint): Element {
  const s = modN(k);
  return s === 0n ? IDENTITY : p.multiply(s);
}

export const serializeElement = (p: Element): Uint8Array => p.toRawBytes();

export function deserializeElement(b: Uint8Array): Element {
  if (b.length !== NE) throw new ProtocolError('DESERIALIZE_ELEMENT', 'element must be 32 bytes');
  let p: Element;
  try {
    p = RistrettoPoint.fromHex(b);
  } catch {
    throw new ProtocolError('DESERIALIZE_ELEMENT', 'invalid ristretto255 encoding');
  }
  if (p.equals(IDENTITY)) throw new ProtocolError('DESERIALIZE_ELEMENT', 'identity element rejected');
  return p;
}

/** Little-endian 32-byte scalar encoding (RFC 9497 §4.1 for ristretto255). */
export function serializeScalar(s: bigint): Uint8Array {
  let v = modN(s);
  const out = new Uint8Array(NS);
  for (let i = 0; i < NS; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function deserializeScalar(b: Uint8Array): bigint {
  if (b.length !== NS) throw new ProtocolError('DESERIALIZE_SCALAR', 'scalar must be 32 bytes');
  let v = 0n;
  for (let i = NS - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
  if (v >= ORDER) throw new ProtocolError('DESERIALIZE_SCALAR', 'non-canonical scalar');
  return v;
}

/** Uniform non-zero scalar: 512 random bits reduced mod n (statistical distance ≈ 2⁻²⁶⁰). */
export function randomScalar(): bigint {
  for (;;) {
    const s = modN(os2ip(randomBytes(64)));
    if (s !== 0n) return s;
  }
}
