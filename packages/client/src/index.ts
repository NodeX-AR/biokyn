import { base64urlDecode, base64urlEncode, beginIssuance, completeIssuance, decodeIssuance, encodeToken, powBinding, solvePowAsync, tokenKeyId, type ChallengeResponse, type PowParams } from '@biokyn/protocol';
import { getWebAuthnAssertion } from './webauthn.js';
export { LIVENESS_SCRIPT, installLiveness, livenessScriptTag } from './live-script.js';
export * from './liveness.js';

export interface BioKynClientOptions {
  basePath?: string; signal?: AbortSignal;
  /** 32-byte issuer public key pinned from trusted deployment configuration (strongly recommended). */
  expectedPublicKey?: Uint8Array;
  /** Registered WebAuthn credential to use if the server answers STEP_UP_REQUIRED (see registerWebAuthnCredential). */
  webauthnCredentialId?: string;
}
export interface InclusiveResult { token: string; challenge: ChallengeResponse; }

async function json<T>(r: Response): Promise<T> {
  if (!r.ok) throw new Error(`BioKyn HTTP ${r.status}`);
  return await r.json() as T;
}
const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Obtains a token through the server-verifiable lane: Argon2id proof-of-work bound to this challenge and this blinded
 * element. The issuer sees only a blinded element (RFC 9497 VOPRF); the token it returns is verified locally (DLEQ
 * proof against the pinned/advertised key) before it is handed to the application.
 */
export async function requestInclusiveToken(opts: BioKynClientOptions = {}): Promise<InclusiveResult> {
  const base = (opts.basePath ?? '/biokyn').replace(/\/+$/, '');
  const challenge = await json<ChallengeResponse>(await fetch(`${base}/challenge`, { credentials: 'same-origin', cache: 'no-store', signal: opts.signal }));
  if (!challenge.pow) throw new Error('BioKyn server did not offer the inclusive lane');
  const publicKey = base64urlDecode(challenge.publicKey);
  if (opts.expectedPublicKey && !sameBytes(opts.expectedPublicKey, publicKey)) throw new Error('BioKyn public-key pin mismatch');
  if (!sameBytes(base64urlDecode(challenge.keyId), tokenKeyId(publicKey))) throw new Error('BioKyn key id does not match the advertised public key');
  const pending = beginIssuance(challenge, publicKey);
  const binding = powBinding(base64urlDecode(challenge.nonce), pending.blindedElement);
  const pow = await solvePowAsync(challenge.pow as PowParams, binding, { signal: opts.signal });
  const req = {
    version: 2 as const, challengeId: challenge.challengeId, blindedElement: base64urlEncode(pending.blindedElement),
    path: 'inclusive' as const, pow, timingCommitment: base64urlEncode(new Uint8Array(32)), tamper: { clock: 0 as const, automation: 0 as const },
  };
  const send = async (body: unknown): Promise<{ status: string; token?: string; challenge?: string }> => json(await fetch(`${base}/issue`, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: opts.signal, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }));
  let issued = await send(req);
  if (issued.status === 'STEP_UP_REQUIRED' && issued.challenge && opts.webauthnCredentialId) {
    issued = await send({ ...req, stepUp: await getWebAuthnAssertion(issued.challenge, opts.webauthnCredentialId, { signal: opts.signal }) });
  }
  if (issued.status !== 'TOKEN_ISSUED' || !issued.token) throw new Error(issued.status === 'STEP_UP_REQUIRED' ? 'BioKyn step-up required' : 'BioKyn issuance failed');
  const verified = completeIssuance(pending, decodeIssuance(issued.token), publicKey);
  return { token: encodeToken(verified), challenge };
}

export { registerWebAuthnCredential, getWebAuthnAssertion, type WebAuthnClientOptions } from './webauthn.js';
export { computeMotionMetrics, type MotionMetrics, type MotionOutcome, type MotionPoint } from './step-up.js';
export { runMotionStepUp, type MotionStepUpOptions, type MotionStepUpResult } from './step-up.js';
export { defineBioKynWidget, type BioKynWidgetOptions } from './widget.js';
