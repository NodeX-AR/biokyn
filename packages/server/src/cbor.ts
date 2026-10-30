/**
 * Minimal, STRICT CBOR decoder for WebAuthn attestation objects and COSE keys (RFC 8949 subset).
 * Supports unsigned/negative integers (safe-integer range only), byte strings, text strings, arrays and maps with
 * definite lengths. Rejects indefinite lengths, tags, floats, simple values, duplicate map keys and anything nested
 * deeper than 8 levels or larger than 256 items. Untrusted input only ever reaches this via bounded request fields.
 */
export class CborError extends Error { constructor(m: string) { super(m); this.name = 'CborError'; } }
export type CborValue = number | Uint8Array | string | CborValue[] | Map<string | number, CborValue>;

const MAX_DEPTH = 8, MAX_ITEMS = 256;

export function decodeCbor(buf: Uint8Array, offset = 0): { value: CborValue; end: number } {
  let items = 0;
  const readArg = (info: number, o: number): { n: number; o: number } => {
    if (info < 24) return { n: info, o };
    const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
    if (!size) throw new CborError('unsupported additional info (indefinite lengths are not allowed)');
    if (o + size > buf.length) throw new CborError('truncated');
    let n = 0n; for (let i = 0; i < size; i++) n = (n << 8n) | BigInt(buf[o + i]!);
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError('integer too large');
    // canonical (shortest) argument encoding is not enforced: COSE keys from authenticators are canonical, and
    // non-canonical forms cannot change semantics here because we never re-serialize.
    return { n: Number(n), o: o + size };
  };
  const read = (o: number, depth: number): { value: CborValue; end: number } => {
    if (depth > MAX_DEPTH) throw new CborError('nesting too deep');
    if (++items > MAX_ITEMS) throw new CborError('too many items');
    if (o >= buf.length) throw new CborError('truncated');
    const major = buf[o]! >> 5, info = buf[o]! & 31;
    const { n, o: p } = readArg(info, o + 1);
    switch (major) {
      case 0: return { value: n, end: p };
      case 1: return { value: -1 - n, end: p };
      case 2: case 3: {
        if (p + n > buf.length) throw new CborError('truncated');
        const bytes = buf.slice(p, p + n);
        if (major === 2) return { value: bytes, end: p + n };
        try { return { value: new TextDecoder('utf-8', { fatal: true }).decode(bytes), end: p + n }; } catch { throw new CborError('invalid utf-8'); }
      }
      case 4: {
        if (n > MAX_ITEMS) throw new CborError('array too large');
        const arr: CborValue[] = []; let q = p;
        for (let i = 0; i < n; i++) { const r = read(q, depth + 1); arr.push(r.value); q = r.end; }
        return { value: arr, end: q };
      }
      case 5: {
        if (n > MAX_ITEMS) throw new CborError('map too large');
        const map = new Map<string | number, CborValue>(); let q = p;
        for (let i = 0; i < n; i++) {
          const k = read(q, depth + 1); q = k.end;
          if (typeof k.value !== 'string' && typeof k.value !== 'number') throw new CborError('unsupported map key type');
          if (map.has(k.value)) throw new CborError('duplicate map key');
          const v = read(q, depth + 1); q = v.end; map.set(k.value, v.value);
        }
        return { value: map, end: q };
      }
      default: throw new CborError('unsupported major type');
    }
  };
  return read(offset, 0);
}

/** Tiny encoder used by tests and tooling to build attestation fixtures. */
export function encodeCbor(v: CborValue): Uint8Array {
  const head = (major: number, n: number): number[] => {
    if (n < 24) return [(major << 5) | n];
    if (n < 256) return [(major << 5) | 24, n];
    if (n < 65536) return [(major << 5) | 25, n >> 8, n & 255];
    return [(major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
  };
  const cat = (...p: Array<number[] | Uint8Array>): Uint8Array => Uint8Array.from(p.flatMap((x) => Array.from(x)));
  if (typeof v === 'number') return Uint8Array.from(v >= 0 ? head(0, v) : head(1, -1 - v));
  if (v instanceof Uint8Array) return cat(head(2, v.length), v);
  if (typeof v === 'string') { const b = new TextEncoder().encode(v); return cat(head(3, b.length), b); }
  if (Array.isArray(v)) return cat(head(4, v.length), ...v.map(encodeCbor));
  return cat(head(5, v.size), ...[...v].flatMap(([k, x]) => [encodeCbor(k), encodeCbor(x)]));
}
