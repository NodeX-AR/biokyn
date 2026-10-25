/** RFC 9380 expand_message_xmd(SHA-512) and the RFC 9497 HashToScalar / HashToGroup / contextString. */
import { sha512 } from '@noble/hashes/sha512';
import { RistrettoPoint } from '@noble/curves/ed25519';
import { ProtocolError, concat, i2osp, os2ip, utf8 } from '../bytes.js';
import { ORDER, type Element } from './group.js';

export const IDENTIFIER = 'ristretto255-SHA512';
export const MODE_VOPRF = 0x01;
export const NH = 64; // SHA-512 output length

/** "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier */
export const contextString = (mode: number = MODE_VOPRF): Uint8Array =>
  concat(utf8('OPRFV1-'), i2osp(mode, 1), utf8('-' + IDENTIFIER));

export function expandMessageXmd(msg: Uint8Array, dst: Uint8Array, lenInBytes: number): Uint8Array {
  const bIn = 64;
  const rIn = 128;
  const ell = Math.ceil(lenInBytes / bIn);
  if (ell > 255 || lenInBytes > 65535 || dst.length > 255 || dst.length === 0) {
    throw new ProtocolError('XMD_PARAMS', 'invalid expand_message_xmd parameters');
  }
  const dstPrime = concat(dst, i2osp(dst.length, 1));
  const b0 = sha512(concat(new Uint8Array(rIn), msg, i2osp(lenInBytes, 2), i2osp(0, 1), dstPrime));
  const out = new Uint8Array(ell * bIn);
  let prev = sha512(concat(b0, i2osp(1, 1), dstPrime));
  out.set(prev, 0);
  for (let i = 2; i <= ell; i++) {
    const x = new Uint8Array(bIn);
    for (let j = 0; j < bIn; j++) x[j] = b0[j]! ^ prev[j]!;
    prev = sha512(concat(x, i2osp(i, 1), dstPrime));
    out.set(prev, (i - 1) * bIn);
  }
  return out.slice(0, lenInBytes);
}

/** hash_to_field with m = 1, L = 48 over the group order (RFC 9497 §4.1). */
export function hashToScalar(msg: Uint8Array, dstPrefix: string, mode: number = MODE_VOPRF): bigint {
  const dst = concat(utf8(dstPrefix), contextString(mode));
  return os2ip(expandMessageXmd(msg, dst, 48)) % ORDER;
}

/** hash_to_ristretto255 (RFC 9380 ristretto255_XMD:SHA-512_R255MAP_RO_). */
export function hashToGroup(msg: Uint8Array, mode: number = MODE_VOPRF): Element {
  const dst = concat(utf8('HashToGroup-'), contextString(mode));
  return RistrettoPoint.hashToCurve(expandMessageXmd(msg, dst, 64));
}

export const hash = (b: Uint8Array): Uint8Array => sha512(b);
