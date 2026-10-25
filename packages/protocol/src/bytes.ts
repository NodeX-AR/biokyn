/** Byte-level helpers shared by the DSP and cryptographic layers. */

export class ProtocolError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** RFC 8017 I2OSP for lengths <= 6 bytes (values are JS safe integers). */
export function i2osp(value: number, length: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || length < 1 || length > 6 || value >= 2 ** (8 * length)) {
    throw new ProtocolError('I2OSP_RANGE', `I2OSP: ${value} does not fit in ${length} bytes`);
  }
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = v % 256;
    v = Math.floor(v / 256);
  }
  return out;
}

/** Big-endian bytes -> bigint. */
export function os2ip(b: Uint8Array): bigint {
  let r = 0n;
  for (const x of b) r = (r << 8n) | BigInt(x);
  return r;
}

/** Length-prefixed (2-byte) encoding used throughout RFC 9497 transcripts. */
export const lp2 = (b: Uint8Array): Uint8Array => concat(i2osp(b.length, 2), b);

/** Constant-time (w.r.t. content) equality. Length is not secret. */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new ProtocolError('HEX', 'invalid hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function base64urlEncode(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlDecode(s: string): Uint8Array {
  if (/[^A-Za-z0-9_-]/.test(s)) throw new ProtocolError('B64', 'invalid base64url');
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
