import {
  base64urlDecode, base64urlEncode, beginIssuance, concat, extractKinematicEvidence, powBinding, solvePow, timingCommitment, utf8,
  requestDigest, sha256Bytes, type ChallengeResponse, type IssuanceRequest, type KinematicEvidence, type PendingIssuance, type PowParams,
} from '@biokyn/protocol';
import { humanStrokes, trajectory } from './synth.js';
import { BioKynVerifier, generateServerSecrets, type VerifierOptions } from '../src/index.js';

export const ORIGIN = 'https://shop.example.com';
export const SECRET = 'test-only-secret-1-0123456789abcdef';

export function clock(start = 1_700_000_000_000) {
  const c = { t: start, now: () => c.t, advance: (ms: number) => { c.t += ms; } };
  return c;
}

export function makeVerifier(over: Partial<VerifierOptions> = {}, c = clock()) {
  const verifier = new BioKynVerifier({
    issuer: 'verify.example.com',
    ...generateServerSecrets(),
    sites: [{ secret: SECRET, origin: ORIGIN }, { secret: 'test-only-secret-2-0123456789abcdef', origin: 'https://blog.example.com' }],
    pow: { memoryKiB: 8192, iterations: 1, parallelism: 1, difficultyBits: 2 },
    now: c.now,
    ...over,
  });
  return { verifier, c };
}

export const goodEvidence = (): KinematicEvidence => extractKinematicEvidence(trajectory(humanStrokes(1), { noisePx: 2, seed: 1 }), 'mouse')!;
export const badEvidence = (): KinematicEvidence => ({ ...goodEvidence(), jerkKurtCenti: 500_000 });

export interface Built { req: IssuanceRequest; pending: PendingIssuance; ch: ChallengeResponse }

/** Client-side request construction (what @biokyn/client does), for server-only tests. */
export function buildRequest(ch: ChallengeResponse, lane: { kinematics?: KinematicEvidence; pow?: boolean; withoutPow?: boolean; tamper?: { clock: 0 | 1 | 2; automation: 0 | 1 | 2 } }): Built {
  const pending = beginIssuance({ issuer: ch.issuer, origin: ch.origin, redemptionContext: ch.redemptionContext }, base64urlDecode(ch.publicKey));
  const nonce = base64urlDecode(ch.nonce);
  const commitment = timingCommitment(nonce, [10000, 10100, 9900]);
  const tamper = lane.tamper ?? { clock: 0, automation: 0 };
  const inclusive = lane.pow === true;
  const req: IssuanceRequest = {
    version: 2, challengeId: ch.challengeId, blindedElement: base64urlEncode(pending.blindedElement), path: inclusive ? 'inclusive' : 'fast',
    timingCommitment: base64urlEncode(commitment), tamper,
  };
  if (inclusive || !lane.withoutPow) req.pow = solvePow(ch.pow as PowParams, powBinding(nonce, pending.blindedElement));
  if (!inclusive) req.kinematics = lane.kinematics ?? goodEvidence();
  return { req, pending, ch };
}

export const digestOf = (b: Built): Uint8Array =>
  requestDigest(base64urlDecode(b.ch.nonce), base64urlDecode(b.req.blindedElement), b.req, base64urlDecode(b.req.timingCommitment));

export { concat, utf8, sha256Bytes };
