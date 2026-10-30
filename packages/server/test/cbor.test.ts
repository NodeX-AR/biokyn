import { describe, expect, it } from 'vitest';
import { CborError, decodeCbor, encodeCbor } from '../src/index.js';

describe('strict CBOR', () => {
  it('round-trips the supported subset', () => {
    const v = new Map<string | number, any>([['fmt', 'none'], [1, -7], [-2, new Uint8Array([1, 2, 3])], ['arr', [1, 'a', new Uint8Array(0)]], ['big', 70000]]);
    expect(decodeCbor(encodeCbor(v)).value).toEqual(v);
  });
  it('rejects indefinite lengths, tags, floats, duplicate keys, truncation, deep nesting, oversize containers', () => {
    const bad: number[][] = [[0x9f, 0xff], [0xc1, 0x01], [0xf9, 0x00, 0x00], [0xa2, 0x01, 0x01, 0x01, 0x02], [0x59, 0x00, 0x10, 0x00], [0x19, 0x01], [0x61, 0xff], [0x99, 0xff, 0xff]];
    for (const b of bad) expect(() => decodeCbor(Uint8Array.from(b))).toThrow(CborError);
    expect(() => decodeCbor(Uint8Array.from([...Array(20).fill(0x81), 0x00]))).toThrow(/deep/);
    expect(() => decodeCbor(Uint8Array.from([0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))).toThrow(/too large/);
  });
  it('reports where the value ended so callers can reject trailing data', () => {
    expect(decodeCbor(Uint8Array.from([0x01, 0x02])).end).toBe(1);
  });
});
