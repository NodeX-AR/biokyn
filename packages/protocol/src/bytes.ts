// Pure-JS byte/base64/hex utilities.
// No node:crypto, no Buffer — works in browsers, workers, Deno, Bun and Node 20+.

export class ProtocolError extends Error {
  constructor(readonly code: string, message: string) { super(message); this.name = 'ProtocolError'; }
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export const concat = (...parts: Uint8Array[]): Uint8Array => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

export const i2osp = (v: number, len: number): Uint8Array => {
  if (!Number.isSafeInteger(v) || v < 0) throw new ProtocolError('ENCODING', 'invalid integer');
  const out = new Uint8Array(len);
  let x = BigInt(v);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(x & 255n); x >>= 8n; }
  if (x !== 0n) throw new ProtocolError('ENCODING', 'integer does not fit');
  return out;
};

export const lp2 = (b: Uint8Array): Uint8Array => concat(i2osp(b.length, 2), b);

// ---------- base64url (RFC 4648 §5, unpadded) ----------

const B64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// Lookup table: char code -> 6-bit value, or -1 for "not in the base64url alphabet".
const B64URL_LOOKUP = (() => {
  const m = new Int16Array(256).fill(-1);
  for (let i = 0; i < B64URL_CHARS.length; i++) m[B64URL_CHARS.charCodeAt(i)] = i;
  return m;
})();

export const base64urlEncode = (b: Uint8Array): string => {
  let out = '';
  for (let i = 0; i < b.length; i += 3) {
    const a = b[i]!;
    const c = i + 1 < b.length ? b[i + 1]! : 0;
    const d = i + 2 < b.length ? b[i + 2]! : 0;
    out += B64URL_CHARS[a >> 2];
    out += B64URL_CHARS[((a & 3) << 4) | (c >> 4)];
    if (i + 1 < b.length) out += B64URL_CHARS[((c & 15) << 2) | (d >> 6)];
    if (i + 2 < b.length) out += B64URL_CHARS[d & 63];
  }
  return out;
};

export const base64urlDecode = (s: string): Uint8Array => {
  // Reject non-canonical base64url strictly. Buffer.from(...,'base64url') is permissive,
  // which is unsafe for protocol inputs.
  if (typeof s !== 'string' || s.length > 4096 || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
    throw new ProtocolError('ENCODING', 'invalid base64url');
  }
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let o = 0, buffer = 0, bits = 0;
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    const v = code < 256 ? B64URL_LOOKUP[code]! : -1;
    if (v < 0) throw new ProtocolError('ENCODING', 'invalid base64url');
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) { bits -= 8; out[o++] = (buffer >> bits) & 255; }
  }
  const result = out.slice(0, o);
  if (base64urlEncode(result) !== s) throw new ProtocolError('ENCODING', 'non-canonical base64url');
  return result;
};

// ---------- random bytes ----------

export const randomBytes = (n: number): Uint8Array => {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    throw new ProtocolError('ENCODING', 'secure random unavailable');
  }
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
};

// ---------- constant-time equality ----------

export const ctEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a[i]! ^ b[i]!;
  return x === 0;
};

// ---------- hex ----------

const hexValue = (c: number): number => {
  if (c >= 48 && c <= 57) return c - 48;    // 0-9
  if (c >= 65 && c <= 70) return c - 55;    // A-F
  if (c >= 97 && c <= 102) return c - 87;   // a-f
  return -1;
};

export const toHex = (b: Uint8Array): string => {
  let out = '';
  for (let i = 0; i < b.length; i++) out += b[i]!.toString(16).padStart(2, '0');
  return out;
};

export const fromHex = (s: string): Uint8Array => {
  // Mirrors Buffer.from(s, 'hex'): parse valid pairs, stop at first invalid char.
  const bytes: number[] = [];
  for (let i = 0; i + 1 < s.length; i += 2) {
    const hi = hexValue(s.charCodeAt(i));
    const lo = hexValue(s.charCodeAt(i + 1));
    if (hi < 0 || lo < 0) break;
    bytes.push((hi << 4) | lo);
  }
  return new Uint8Array(bytes);
};

// ---------- sha256 (unchanged, already environment-agnostic) ----------

export const sha256Bytes = async (b: Uint8Array): Promise<Uint8Array> => {
  const { sha256 } = await import('./hashes.js');
  return sha256(b);
};
