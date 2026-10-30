/**
 * Browser helpers for the optional WebAuthn step-up lane: anonymous credential registration and assertions.
 *
 * What this lane is and is not: a registered credential proves the visitor controls a key that the site registered
 * earlier. Anonymous registration uses attestation "none", so it cannot distinguish a hardware authenticator from a
 * software/virtual one; it is an accessibility- and friction-friendly *returning visitor* factor, not proof of
 * humanity. Registration costs proof-of-work so enrollment cannot be mass-produced for free.
 */
import { base64urlDecode, base64urlEncode, powBinding, solvePowAsync, utf8, type ChallengeResponse, type PowParams, type WebAuthnAssertionB64 } from '@biokyn/protocol';

export interface WebAuthnClientOptions { basePath?: string; signal?: AbortSignal; credentials?: CredentialsContainer }
const bytes = (b64: string): ArrayBuffer => { const u = base64urlDecode(b64); return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer; };
const enc = (b: ArrayBuffer | ArrayBufferView): string => base64urlEncode(b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength));

async function post<T>(url: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const r = await fetch(url, { method: 'POST', credentials: 'same-origin', cache: 'no-store', signal, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`BioKyn HTTP ${r.status}`);
  return await r.json() as T;
}

/** Runs the full registration ceremony and returns the credential ID to remember (e.g. in localStorage). */
export async function registerWebAuthnCredential(opts: WebAuthnClientOptions = {}): Promise<{ credentialId: string; expiresAt: number }> {
  const base = (opts.basePath ?? '/biokyn').replace(/\/+$/, '');
  const creds = opts.credentials ?? (typeof navigator !== 'undefined' ? navigator.credentials : undefined);
  if (!creds) throw new Error('WebAuthn is not available in this browser');
  const ch = await (await fetch(`${base}/challenge`, { credentials: 'same-origin', cache: 'no-store', signal: opts.signal })).json() as ChallengeResponse;
  if (!ch.pow) throw new Error('BioKyn server did not offer a proof-of-work lane');
  const pow = await solvePowAsync(ch.pow as PowParams, powBinding(base64urlDecode(ch.nonce), utf8('biokyn-webauthn-register')), { signal: opts.signal });
  const o = await post<{ rp: { id: string; name: string }; user: { id: string; name: string; displayName: string }; challenge: string; pubKeyCredParams: PublicKeyCredentialParameters[]; authenticatorSelection: AuthenticatorSelectionCriteria; timeout: number }>(
    `${base}/webauthn/register/options`, { challengeId: ch.challengeId, pow }, opts.signal);
  const cred = await creds.create({ publicKey: {
    rp: o.rp, user: { id: bytes(o.user.id), name: o.user.name, displayName: o.user.displayName }, challenge: bytes(o.challenge),
    pubKeyCredParams: o.pubKeyCredParams, authenticatorSelection: o.authenticatorSelection, attestation: 'none', timeout: o.timeout,
  }, signal: opts.signal }) as PublicKeyCredential | null;
  if (!cred) throw new Error('WebAuthn registration was cancelled');
  const r = cred.response as AuthenticatorAttestationResponse;
  const out = await post<{ status: string; credentialId: string; expiresAt: number }>(`${base}/webauthn/register/verify`, {
    challengeId: ch.challengeId, credential: { id: enc(cred.rawId), attestationObject: enc(r.attestationObject), clientDataJSON: enc(r.clientDataJSON) },
  }, opts.signal);
  if (out.status !== 'REGISTERED') throw new Error('BioKyn registration failed');
  return { credentialId: out.credentialId, expiresAt: out.expiresAt };
}

/** Produces the `stepUp` assertion for a STEP_UP_REQUIRED response, using a previously registered credential. */
export async function getWebAuthnAssertion(stepUpChallenge: string, credentialId: string, opts: WebAuthnClientOptions = {}): Promise<WebAuthnAssertionB64> {
  const creds = opts.credentials ?? (typeof navigator !== 'undefined' ? navigator.credentials : undefined);
  if (!creds) throw new Error('WebAuthn is not available in this browser');
  const a = await creds.get({ publicKey: { challenge: bytes(stepUpChallenge), allowCredentials: [{ type: 'public-key', id: bytes(credentialId) }], userVerification: 'preferred', timeout: 60_000 }, signal: opts.signal }) as PublicKeyCredential | null;
  if (!a) throw new Error('WebAuthn assertion was cancelled');
  const r = a.response as AuthenticatorAssertionResponse;
  return { credentialId: enc(a.rawId), authenticatorData: enc(r.authenticatorData), clientDataJSON: enc(r.clientDataJSON), signature: enc(r.signature) };
}
