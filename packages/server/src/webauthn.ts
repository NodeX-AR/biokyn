/**
 * Server-side verification of the step-up WebAuthn assertion (ES256 only).
 *
 * What a valid result means: SOME authenticator signed this exact server challenge, for this rpId and origin,
 * with the user-presence flag set. Credential IDs and public keys are pinned in server configuration; request-
 * supplied public keys are ignored. This proves possession of a registered key, not hardware attestation or a
 * physical device. Virtual authenticators can still pass if they control a registered private key.
 */
import { base64urlDecode, base64urlEncode, concat, ctEqual, sha256, type WebAuthnAssertionB64 } from '@biokyn/protocol';
import { CborError, decodeCbor } from './cbor.js';

export interface AssertionCheck { origin: string; rpId: string; expectedChallenge: Uint8Array; credentialId: string; publicKeySpki: string }
/** Copies into a fresh ArrayBuffer-backed array: WebCrypto's BufferSource rejects Uint8Array<ArrayBufferLike> on current TypeScript. */
const bs = (u: Uint8Array) => new Uint8Array(u);

export type AssertionResult = { ok: true; signCount: number; userVerified: boolean } | { ok: false; reason: string };

/** ASN.1 DER ECDSA signature -> IEEE P1363 (r || s, 64 bytes). */
export function derToP1363(der: Uint8Array): Uint8Array | null {
  let o = 0;
  if (der[o++] !== 0x30) return null;
  let len = der[o++]!;
  if (len & 0x80) { const n = len & 0x7f; if (n < 1 || n > 2) return null; len = 0; for (let i = 0; i < n; i++) len = (len << 8) | der[o++]!; }
  if (o + len !== der.length) return null;
  const readInt = (): Uint8Array | null => {
    if (der[o++] !== 0x02) return null;
    const l = der[o++]!;
    if (l === 0 || o + l > der.length) return null;
    let v = der.subarray(o, o + l);
    o += l;
    while (v.length > 1 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) return null;
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = readInt();
  const s = r ? readInt() : null;
  if (!r || !s || o !== der.length) return null;
  return concat(r, s);
}

export async function verifyAssertion(a: WebAuthnAssertionB64, c: AssertionCheck, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<AssertionResult> {
  try {
    const clientDataJSON = base64urlDecode(a.clientDataJSON);
    const authData = base64urlDecode(a.authenticatorData);
    const sig = derToP1363(base64urlDecode(a.signature));
    if (!sig) return { ok: false, reason: 'bad-signature-encoding' };

    const cd = JSON.parse(new TextDecoder().decode(clientDataJSON)) as { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
    if (cd.type !== 'webauthn.get') return { ok: false, reason: 'wrong-type' };
    if (typeof cd.challenge !== 'string' || !ctEqual(new TextEncoder().encode(cd.challenge), new TextEncoder().encode(base64urlEncode(c.expectedChallenge)))) return { ok: false, reason: 'challenge-mismatch' };
    if (cd.origin !== c.origin) return { ok: false, reason: 'origin-mismatch' };
    if (cd.crossOrigin === true) return { ok: false, reason: 'cross-origin' };

    if (authData.length < 37) return { ok: false, reason: 'authdata-short' };
    if (!ctEqual(authData.subarray(0, 32), sha256(new TextEncoder().encode(c.rpId)))) return { ok: false, reason: 'rpid-mismatch' };
    if ((authData[32]! & 0x01) === 0) return { ok: false, reason: 'user-presence-missing' };

    // The credential ID and public key must come from server-side registration, never from this request.
    if (a.credentialId !== c.credentialId) return { ok: false, reason: 'credential-mismatch' };
    const publicKeyBytes = base64urlDecode(c.publicKeySpki);
    const signatureBytes = new Uint8Array(sig);
    const signed = concat(authData, sha256(clientDataJSON));
    const key = await subtle.importKey('spki', bs(publicKeyBytes), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, bs(signatureBytes), bs(signed));
    if (!ok) return { ok: false, reason: 'signature-invalid' };
    const signCount = ((authData[33]! << 24) | (authData[34]! << 16) | (authData[35]! << 8) | authData[36]!) >>> 0;
    return { ok: true, signCount, userVerified: (authData[32]! & 0x04) !== 0 };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

// ------------------------------------------------------------------ registration ceremony (webauthn.create)

export interface RegistrationResponseB64 { id: string; attestationObject: string; clientDataJSON: string }
export interface RegistrationCheck { origin: string; rpId: string; expectedChallenge: Uint8Array; requireUserVerification?: boolean }
export type RegistrationResult =
  | { ok: true; credentialId: string; publicKeySpki: string; signCount: number; aaguid: string; backupEligible: boolean; userVerified: boolean }
  | { ok: false; reason: string };

/** DER prefix of SubjectPublicKeyInfo for an uncompressed P-256 ECDSA key (id-ecPublicKey, prime256v1). */
const P256_SPKI_PREFIX = Uint8Array.from([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04]);
export const p256Spki = (x: Uint8Array, y: Uint8Array): Uint8Array => concat(P256_SPKI_PREFIX, x, y);

/**
 * Verifies an anonymous registration. Accepted: attestation format "none" only. Anonymous sites cannot evaluate
 * x5c/TPM/android-key chains (no trust roots, no metadata service), and a self-attested key proves nothing beyond
 * "a private key exists". Verified: ceremony type, server challenge, exact origin, rpIdHash, user presence (and
 * optionally verification), attested credential data layout, ES256 COSE key, and that the point is a valid P-256 key.
 */
export async function verifyRegistration(r: RegistrationResponseB64, c: RegistrationCheck, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<RegistrationResult> {
  try {
    const clientDataJSON = base64urlDecode(r.clientDataJSON);
    const cd = JSON.parse(new TextDecoder().decode(clientDataJSON)) as { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
    if (cd.type !== 'webauthn.create') return { ok: false, reason: 'wrong-type' };
    if (typeof cd.challenge !== 'string' || !ctEqual(new TextEncoder().encode(cd.challenge), new TextEncoder().encode(base64urlEncode(c.expectedChallenge)))) return { ok: false, reason: 'challenge-mismatch' };
    if (cd.origin !== c.origin) return { ok: false, reason: 'origin-mismatch' };
    if (cd.crossOrigin === true) return { ok: false, reason: 'cross-origin' };

    const att = decodeCbor(base64urlDecode(r.attestationObject));
    if (!(att.value instanceof Map) || att.end !== base64urlDecode(r.attestationObject).length) return { ok: false, reason: 'bad-attestation-object' };
    const fmt = att.value.get('fmt'), stmt = att.value.get('attStmt'), authData = att.value.get('authData');
    if (fmt !== 'none') return { ok: false, reason: 'unsupported-attestation-format' };
    if (!(stmt instanceof Map) || stmt.size !== 0) return { ok: false, reason: 'unexpected-attestation-statement' };
    if (!(authData instanceof Uint8Array) || authData.length < 55) return { ok: false, reason: 'authdata-short' };

    if (!ctEqual(authData.subarray(0, 32), sha256(new TextEncoder().encode(c.rpId)))) return { ok: false, reason: 'rpid-mismatch' };
    const flags = authData[32]!;
    if ((flags & 0x01) === 0) return { ok: false, reason: 'user-presence-missing' };
    if (c.requireUserVerification && (flags & 0x04) === 0) return { ok: false, reason: 'user-verification-missing' };
    if ((flags & 0x40) === 0) return { ok: false, reason: 'no-attested-credential-data' };
    if ((flags & 0x80) !== 0) return { ok: false, reason: 'extensions-not-supported' };
    const signCount = ((authData[33]! << 24) | (authData[34]! << 16) | (authData[35]! << 8) | authData[36]!) >>> 0;
    const aaguid = Array.from(authData.subarray(37, 53), (b) => b.toString(16).padStart(2, '0')).join('');
    const idLen = (authData[53]! << 8) | authData[54]!;
    if (idLen < 16 || idLen > 1023 || 55 + idLen >= authData.length) return { ok: false, reason: 'bad-credential-id-length' };
    const credId = authData.slice(55, 55 + idLen);
    const key = decodeCbor(authData, 55 + idLen);
    if (key.end !== authData.length) return { ok: false, reason: 'trailing-authdata' };
    const cose = key.value;
    if (!(cose instanceof Map) || cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1) return { ok: false, reason: 'unsupported-credential-key' };
    const x = cose.get(-2), y = cose.get(-3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) return { ok: false, reason: 'bad-credential-key' };
    const credentialId = base64urlEncode(credId);
    if (r.id !== credentialId) return { ok: false, reason: 'credential-id-mismatch' };
    const spki = p256Spki(x, y);
    await subtle.importKey('spki', bs(spki), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']); // rejects points not on the curve
    return { ok: true, credentialId, publicKeySpki: base64urlEncode(spki), signCount, aaguid, backupEligible: (flags & 0x08) !== 0, userVerified: (flags & 0x04) !== 0 };
  } catch (e) {
    return { ok: false, reason: e instanceof CborError ? 'bad-cbor' : 'malformed' };
  }
}
