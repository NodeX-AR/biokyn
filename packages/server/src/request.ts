/** Strict structural validation of untrusted issuance requests. Anything off-spec is a 400, never a risk verdict. */
import {
  ProtocolError, assertWellFormedKinematics, base64urlDecode,
  type IssuanceRequest, type KinematicEvidence, type PowSolution, type TamperLevel, type WebAuthnAssertionB64,
} from '@biokyn/protocol';
import { BioKynHttpError } from './errors.js';

const bad = (): never => { throw new BioKynHttpError(400, 'bad_request'); };
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const str = (v: unknown, max: number): string => (typeof v === 'string' && v.length > 0 && v.length <= max ? v : bad());
const bytesOfLen = (v: unknown, len: number): string => {
  const s = str(v, 200);
  try { if (base64urlDecode(s).length !== len) bad(); } catch (e) { if (e instanceof BioKynHttpError) throw e; bad(); }
  return s;
};
const level = (v: unknown): TamperLevel => (v === 0 || v === 1 || v === 2 ? v : bad());

function parseStepUp(v: unknown): WebAuthnAssertionB64 {
  if (!isObj(v)) return bad();
  return {
    credentialId: str(v.credentialId, 1400),
    ...(v.publicKeySpki !== undefined ? { publicKeySpki: str(v.publicKeySpki, 400) } : {}),
    authenticatorData: str(v.authenticatorData, 2048),
    clientDataJSON: str(v.clientDataJSON, 4096),
    signature: str(v.signature, 512),
  };
}

export function parseIssuanceRequest(raw: unknown): IssuanceRequest {
  if (!isObj(raw) || raw.version !== 2) return bad();
  const path = raw.path === 'fast' || raw.path === 'inclusive' ? raw.path : bad();
  if (!isObj(raw.tamper)) return bad();
  const req: IssuanceRequest = {
    version: 2,
    challengeId: str(raw.challengeId, 100),
    blindedElement: bytesOfLen(raw.blindedElement, 32),
    path,
    timingCommitment: bytesOfLen(raw.timingCommitment, 32),
    tamper: { clock: level(raw.tamper.clock), automation: level(raw.tamper.automation) },
  };
  if (raw.assistive !== undefined) {
    if (typeof raw.assistive !== 'number' || !Number.isInteger(raw.assistive) || raw.assistive < 0 || raw.assistive > 255) return bad();
    req.assistive = raw.assistive;
  }
  if (path === 'fast') {
    if (!isObj(raw.kinematics)) return bad();
    try { assertWellFormedKinematics(raw.kinematics as unknown as KinematicEvidence); } catch (e) { if (e instanceof ProtocolError) bad(); throw e; }
    req.kinematics = raw.kinematics as unknown as KinematicEvidence;
    // Fast-path requests may also carry the server-verifiable proof-of-work (required unless a step-up assertion is attached).
    if (raw.pow !== undefined) { if (!isObj(raw.pow)) return bad(); req.pow = { nonce: str(raw.pow.nonce, 32) } satisfies PowSolution; }
  } else {
    if (!isObj(raw.pow) || raw.kinematics !== undefined) return bad();
    req.pow = { nonce: str(raw.pow.nonce, 32) } satisfies PowSolution;
  }
  if (raw.stepUp !== undefined) req.stepUp = parseStepUp(raw.stepUp);
  return req;
}

export function parseRegistrationOptionsRequest(raw: unknown): { challengeId: string; pow: PowSolution } {
  if (!isObj(raw) || !isObj(raw.pow)) return bad();
  return { challengeId: str(raw.challengeId, 100), pow: { nonce: str(raw.pow.nonce, 32) } };
}

export function parseRegistrationVerifyRequest(raw: unknown): { challengeId: string; credential: { id: string; attestationObject: string; clientDataJSON: string } } {
  if (!isObj(raw) || !isObj(raw.credential)) return bad();
  const c = raw.credential;
  return { challengeId: str(raw.challengeId, 100), credential: { id: str(c.id, 1400), attestationObject: str(c.attestationObject, 4096), clientDataJSON: str(c.clientDataJSON, 4096) } };
}
