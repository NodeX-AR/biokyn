import { randomBytes as nodeRandomBytes } from 'node:crypto';

export class ProtocolError extends Error {
  constructor(readonly code: string, message: string) { super(message); this.name = 'ProtocolError'; }
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const concat = (...parts: Uint8Array[]): Uint8Array => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
export const i2osp = (v: number, len: number): Uint8Array => {
  if (!Number.isSafeInteger(v) || v < 0) throw new ProtocolError('ENCODING', 'invalid integer');
  const out = new Uint8Array(len); let x = BigInt(v);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(x & 255n); x >>= 8n; }
  if (x !== 0n) throw new ProtocolError('ENCODING', 'integer does not fit');
  return out;
};
export const lp2 = (b: Uint8Array): Uint8Array => concat(i2osp(b.length, 2), b);
export const base64urlEncode = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
export const base64urlDecode = (s: string): Uint8Array => {
  // Buffer.from(..., 'base64url') is deliberately permissive (it can ignore invalid characters).
  // Protocol inputs are security-sensitive, so accept only canonical unpadded base64url.
  if (typeof s !== 'string' || s.length > 4096 || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
    throw new ProtocolError('ENCODING', 'invalid base64url');
  }
  const out = new Uint8Array(Buffer.from(s, 'base64url'));
  if (base64urlEncode(out) !== s) throw new ProtocolError('ENCODING', 'non-canonical base64url');
  return out;
};
export const randomBytes = (n: number): Uint8Array => {
  const out = new Uint8Array(n);
  if (typeof globalThis.crypto?.getRandomValues === 'function') globalThis.crypto.getRandomValues(out);
  else out.set(nodeRandomBytes(n));
  return out;
};
export const ctEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let x = 0; for (let i = 0; i < a.length; i++) x |= a[i]! ^ b[i]!;
  return x === 0;
};
export const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
export const fromHex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'hex'));
export const sha256Bytes = async (b: Uint8Array): Promise<Uint8Array> => {
  const { sha256 } = await import('./hashes.js'); return sha256(b);
};
