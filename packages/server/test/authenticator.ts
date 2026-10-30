/** Software WebAuthn authenticator for tests: produces real "none" attestations and real ES256 assertions. */
import { base64urlEncode, concat, randomBytes, sha256 } from '@biokyn/protocol';
import { encodeCbor } from '../src/cbor.js';

export const p1363ToDer = (sig: Uint8Array): Uint8Array => {
  const enc = (v: Uint8Array): Uint8Array => { let i = 0; while (i < v.length - 1 && v[i] === 0) i++; let r = v.subarray(i); if (r[0]! & 0x80) r = concat(Uint8Array.of(0), r); return concat(Uint8Array.of(0x02, r.length), r); };
  const r = enc(sig.subarray(0, 32)), s = enc(sig.subarray(32));
  return concat(Uint8Array.of(0x30, r.length + s.length), r, s);
};

export interface AttestOpts { challenge: Uint8Array; origin: string; rpId: string; flags?: number; type?: string; fmt?: string; attStmt?: Map<string, number>; trailing?: Uint8Array; idLen?: number; badKey?: boolean }
export interface AssertOpts { challenge: Uint8Array; origin: string; rpId: string; flags?: number; type?: string; counter?: number }

export async function makeAuthenticator() {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const x = new Uint8Array(Buffer.from(jwk.x!, 'base64url')), y = new Uint8Array(Buffer.from(jwk.y!, 'base64url'));
  const credId = randomBytes(32);
  const credentialId = base64urlEncode(credId);
  const be32 = (n: number): Uint8Array => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  return {
    credentialId, x, y,
    publicKeySpki: base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey))),
    attest(o: AttestOpts) {
      const cose = encodeCbor(new Map<string | number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, o.badKey ? new Uint8Array(32) : x], [-3, y]]));
      const id = o.idLen ? randomBytes(o.idLen) : credId;
      const authData = concat(sha256(new TextEncoder().encode(o.rpId)), Uint8Array.of(o.flags ?? 0x41), be32(0), new Uint8Array(16), Uint8Array.of(id.length >> 8, id.length & 255), id, cose, o.trailing ?? new Uint8Array(0));
      const attestationObject = encodeCbor(new Map<string, any>([['fmt', o.fmt ?? 'none'], ['attStmt', o.attStmt ?? new Map()], ['authData', authData]]));
      const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: o.type ?? 'webauthn.create', challenge: base64urlEncode(o.challenge), origin: o.origin }));
      return { id: base64urlEncode(id), attestationObject: base64urlEncode(attestationObject), clientDataJSON: base64urlEncode(clientDataJSON) };
    },
    async assert(o: AssertOpts) {
      const authData = concat(sha256(new TextEncoder().encode(o.rpId)), Uint8Array.of(o.flags ?? 0x01), be32(o.counter ?? 0));
      const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: o.type ?? 'webauthn.get', challenge: base64urlEncode(o.challenge), origin: o.origin }));
      const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, new Uint8Array(concat(authData, sha256(clientDataJSON)))));
      return { credentialId, authenticatorData: base64urlEncode(authData), clientDataJSON: base64urlEncode(clientDataJSON), signature: base64urlEncode(p1363ToDer(sig)) };
    },
  };
}
