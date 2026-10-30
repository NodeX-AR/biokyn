/**
 * ristretto255 group adapter. All curve arithmetic is delegated to @noble/curves (audited, constant-time scalar
 * multiplication); this file only adapts its API to the exact operations RFC 9497 needs and enforces the
 * RFC's encoding rules (canonical scalars, rejection of invalid / identity elements).
 */
import * as ed from '@noble/curves/ed25519.js';
import { ProtocolError, randomBytes } from '../bytes.js';

/**
 * Minimal structural view of a ristretto255 element. Deliberately NOT derived from noble's class type: that class has
 * private members, which makes `declaration: true` fail (TS4094) for any exported value typed from it, and it would leak
 * the dependency's types into this package's public API.
 */
export interface Element {
  add(other: Element): Element;
  multiply(scalar: bigint): Element;
  equals(other: Element): boolean;
  toBytes(): Uint8Array;
}
interface PointConstructor {
  BASE: Element;
  ZERO: Element;
  Fn: { ORDER: bigint };
  fromBytes(bytes: Uint8Array): Element;
  hashToCurve?: (uniform: Uint8Array) => Element;
}
interface Hasher {
  hashToCurve?: (msg: Uint8Array, opts: { DST: Uint8Array | string }) => Element;
  deriveToCurve?: (uniform: Uint8Array) => Element;
}
const Point = (ed as unknown as { ristretto255: { Point: PointConstructor } }).ristretto255.Point;
const hasher = (ed as unknown as { ristretto255_hasher?: Hasher }).ristretto255_hasher;

export const ORDER: bigint = BigInt(Point.Fn.ORDER);
export const GENERATOR: Element = Point.BASE;
export const IDENTITY: Element = Point.ZERO;
export const ELEMENT_LENGTH = 32;
export const SCALAR_LENGTH = 32;

export const modN = (x: bigint): bigint => ((x % ORDER) + ORDER) % ORDER;

/** Little-endian bytes -> integer (RFC 9497 §4.1 scalar encoding for ristretto255). */
export const bytesToBigIntLE = (b: Uint8Array): bigint => { let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!); return x; };

export const invN = (x: bigint): bigint => {
  let a = modN(x), b = ORDER, u = 1n, v = 0n;
  while (b) { const q = a / b; [a, b] = [b, a - q * b]; [u, v] = [v, u - q * v]; }
  if (a !== 1n) throw new ProtocolError('SCALAR', 'not invertible');
  return modN(u);
};

/** Uniform non-zero scalar: 64 random bytes reduced mod the group order (bias < 2^-250), zero rejected. */
export const randomScalar = (): bigint => {
  for (;;) { const x = modN(bytesToBigIntLE(randomBytes(64))); if (x !== 0n) return x; }
};

/** Scalar multiplication that tolerates 0 (noble's `multiply` rejects it) and always reduces mod the order. */
export const smul = (p: Element, k: bigint): Element => { const s = modN(k); return s === 0n ? IDENTITY : p.multiply(s); };
export const addPoints = (a: Element, b: Element): Element => a.add(b);

export const serializeElement = (p: Element): Uint8Array => p.toBytes();
/** RFC 9497 DeserializeElement: rejects wrong lengths and non-canonical / invalid encodings. */
export function deserializeElement(b: Uint8Array, opts: { allowIdentity?: boolean } = {}): Element {
  if (!(b instanceof Uint8Array) || b.length !== ELEMENT_LENGTH) throw new ProtocolError('ELEMENT', 'length');
  let p: Element;
  try { p = Point.fromBytes(b); } catch { throw new ProtocolError('ELEMENT', 'invalid ristretto255 encoding'); }
  if (!opts.allowIdentity && p.equals(IDENTITY)) throw new ProtocolError('ELEMENT', 'identity element');
  return p;
}

export function serializeScalar(s: bigint): Uint8Array {
  let x = modN(s); const o = new Uint8Array(SCALAR_LENGTH);
  for (let i = 0; i < SCALAR_LENGTH; i++) { o[i] = Number(x & 255n); x >>= 8n; }
  return o;
}
/** RFC 9497 DeserializeScalar: canonical little-endian value strictly below the group order. */
export function deserializeScalar(b: Uint8Array, opts: { allowZero?: boolean } = {}): bigint {
  if (!(b instanceof Uint8Array) || b.length !== SCALAR_LENGTH) throw new ProtocolError('SCALAR', 'length');
  const x = bytesToBigIntLE(b);
  if (x >= ORDER) throw new ProtocolError('SCALAR', 'out of range');
  if (x === 0n && !opts.allowZero) throw new ProtocolError('SCALAR', 'zero');
  return x;
}

/**
 * hash_to_ristretto255 (RFC 9380 App. B): expand_message_xmd(SHA-512, DST, 64) followed by the ristretto255 one-way map
 * (RFC 9496 §4.3.4). noble has exposed this under different names across releases, so every known shape is tried, in order:
 *   1. Point.hashToCurve(uniform64)            2. ristretto255_hasher.deriveToCurve(uniform64)
 *   3. ristretto255_hasher.hashToCurve(msg, { DST })  (does its own expand_message_xmd with SHA-512)
 * Whatever is picked is validated by the RFC known-answer tests, so a library change fails loudly, never silently.
 */
export function hashToElement(msg: Uint8Array, dstBytes: Uint8Array, expand: (msg: Uint8Array, dst: Uint8Array, len: number) => Uint8Array): Element {
  if (typeof Point.hashToCurve === 'function') return Point.hashToCurve(expand(msg, dstBytes, 64));
  if (hasher && typeof hasher.deriveToCurve === 'function') return hasher.deriveToCurve(expand(msg, dstBytes, 64));
  if (hasher && typeof hasher.hashToCurve === 'function') return hasher.hashToCurve(msg, { DST: dstBytes });
  throw new ProtocolError('UNSUPPORTED', 'installed @noble/curves exposes no ristretto255 hash-to-curve');
}

/** Maps 64 uniform bytes to a group element (used by tests for the RFC 9496 one-way-map vector). */
export function elementFromUniformBytes(uniform: Uint8Array): Element {
  if (uniform.length !== 64) throw new ProtocolError('ELEMENT', 'uniform input must be 64 bytes');
  if (typeof Point.hashToCurve === 'function') return Point.hashToCurve(uniform);
  if (hasher && typeof hasher.deriveToCurve === 'function') return hasher.deriveToCurve(uniform);
  throw new ProtocolError('UNSUPPORTED', 'installed @noble/curves has no uniform-bytes ristretto255 map');
}
