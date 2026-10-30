/** Shared wire types and the canonical request digest. */
import { sha256 } from './hashes.js';
import { ProtocolError, concat, i2osp, lp2, utf8 } from './bytes.js';

export type B64 = string; // base64url, no padding
export type Modality = 'mouse' | 'touch' | 'pen';
export const MODALITIES: readonly Modality[] = ['mouse', 'touch', 'pen'];

/** Touch/pen contact moments (never the raw series). `radius` carries tilt magnitude for pens. */
export interface ContactSummary {
  n: number;
  radiusCvMilli: number;
  forceCvMilli: number;
  staticRadius: boolean;
  staticForce: boolean;
}

/** One fitted delta-lognormal stroke, quantized to integers. Scale-free: path length is NOT included. */
export interface StrokeEvidence {
  /** Stroke start relative to the first stroke start (ms). */
  startMs: number;
  durationMs: number;
  /** Signal-to-noise ratio of the fit in 0.1 dB. */
  snrDeciDb: number;
  /** Agonist log-time delay and log-response time (μ1, σ1) ×1000; t measured in seconds from onset t0. */
  mu1Milli: number;
  sigma1Milli: number;
  mu2Milli: number;
  sigma2Milli: number;
  /** D2/D1 ×1000. */
  d2RatioMilli: number;
  /** (time of peak speed − stroke start) / duration ×1000. */
  peakPhaseMilli: number;
  /** Coefficient of variation of sampled tangential speed ×1000. */
  speedCvMilli: number;
}

export interface KinematicEvidence {
  version: 1;
  modality: Modality;
  strokes: StrokeEvidence[];
  /** Excess kurtosis of |jerk| ×100. */
  jerkKurtCenti: number;
  nativeRateDeci: number;
  sampleCount: number;
  durationMs: number;
  contact?: ContactSummary;
}

/** Argon2id proof-of-work solution (inclusive path). The server recomputes one hash to verify. */
export interface PowSolution {
  /** 8-byte nonce. */
  nonce: B64;
}

export interface PowParams {
  salt: B64;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  /** Required number of leading zero bits in the Argon2id output. */
  difficultyBits: number;
}

/** 0 = clean / ok, 1 = unavailable or weak signal, 2 = suspect. */
export type TamperLevel = 0 | 1 | 2;
export interface TamperReport { clock: TamperLevel; automation: TamperLevel }

export interface WebAuthnAssertionB64 {
  credentialId: B64;
  /** Ignored by the server (keys come from registration); kept optional for wire compatibility. */
  publicKeySpki?: B64;
  authenticatorData: B64;
  clientDataJSON: B64;
  signature: B64;
}

export interface ChallengeResponse {
  challengeId: string;
  nonce: B64; // 32 random bytes
  issuedAt: number;
  ttlSec: number;
  issuer: string;
  origin: string;
  redemptionContext: B64; // 32 random bytes
  publicKey: B64; // issuer VOPRF public key (pin it)
  /** SHA-256-derived identifier of `publicKey` (see tokenKeyId). Compare across independent channels to detect per-user keys. */
  keyId: B64;
  /** Present only if the server wants the inclusive path available (assistive flags asserted). */
  pow?: PowParams;
}

export type IssuancePath = 'fast' | 'inclusive';

export interface IssuanceRequest {
  version: 2;
  challengeId: string;
  blindedElement: B64;
  path: IssuancePath;
  /** Client-reported motion evidence. ADVISORY ONLY: it can lower trust (force step-up) but never grants a token. */
  kinematics?: KinematicEvidence;
  /** Argon2id solution. Required for issuance unless the verifier runs the explicit unsafe kinematics gate. */
  pow?: PowSolution;
  /** Optional accessibility/input-mode hint. It is telemetry only and is cryptographically bound to this request. */
  assistive?: number;
  /** SHA-256 commitment to the nonce-bound inter-event timing sequence. */
  timingCommitment: B64;
  tamper: TamperReport;
  /** Present only on the step-up retry (see StepUpResponse). */
  stepUp?: WebAuthnAssertionB64;
}

/**
 * Anti-oracle contract: after a well-formed request, the client can only ever learn one of these two
 * states. Scores, reasons and thresholds exist only in server logs.
 */
export interface IssuedResponse { status: 'TOKEN_ISSUED'; token: B64 }
export interface StepUpResponse {
  status: 'STEP_UP_REQUIRED';
  /** Server-chosen WebAuthn user-presence challenge for the intentional step-up gesture. */
  challenge: B64;
}
export type IssuanceResponse = IssuedResponse | StepUpResponse;

// ------------------------------------------------------------------ canonical encoding

const s32 = (v: number): Uint8Array => i2osp(v + 2 ** 31, 4);

export function kinematicsBytes(e: KinematicEvidence): Uint8Array {
  const parts: Uint8Array[] = [i2osp(e.version, 1), i2osp(MODALITIES.indexOf(e.modality), 1), i2osp(e.strokes.length, 2)];
  for (const s of e.strokes) {
    parts.push(
      i2osp(s.startMs, 4), i2osp(s.durationMs, 4), i2osp(s.snrDeciDb + 32768, 4), s32(s.mu1Milli), i2osp(s.sigma1Milli, 4),
      s32(s.mu2Milli), i2osp(s.sigma2Milli, 4), s32(s.d2RatioMilli), i2osp(s.peakPhaseMilli, 4), i2osp(s.speedCvMilli, 4),
    );
  }
  parts.push(s32(e.jerkKurtCenti), i2osp(e.nativeRateDeci, 4), i2osp(e.sampleCount, 4), i2osp(e.durationMs, 4));
  if (e.contact) {
    const c = e.contact;
    parts.push(i2osp(1, 1), i2osp(c.n, 4), i2osp(c.radiusCvMilli, 4), i2osp(c.forceCvMilli, 4), i2osp((c.staticRadius ? 1 : 0) | (c.staticForce ? 2 : 0), 1));
  } else {
    parts.push(i2osp(0, 1));
  }
  return concat(...parts);
}

/** Commitment to inter-event deltas (µs); binds the timing profile to the server nonce (freshness only). */
export function timingCommitment(nonce: Uint8Array, deltasUs: readonly number[]): Uint8Array {
  const d = deltasUs.slice(-4096);
  const parts: Uint8Array[] = [utf8('biokyn-timing-v1'), lp2(nonce), i2osp(d.length, 4)];
  for (const v of d) parts.push(i2osp(Math.max(0, Math.min(0xffffffff, Math.round(v))), 4));
  return sha256(concat(...parts));
}

/**
 * Digest of the exact issuance request. It is the WebAuthn challenge of the step-up gesture, so a
 * user-presence assertion cannot be replayed onto a different blinded element or different evidence.
 */
export function requestDigest(
  nonce: Uint8Array,
  blinded: Uint8Array,
  req: Pick<IssuanceRequest, 'path' | 'kinematics' | 'pow' | 'tamper' | 'assistive'>,
  commitment: Uint8Array,
): Uint8Array {
  if (req.path === 'fast' && !req.kinematics) throw new ProtocolError('MALFORMED', 'fast path requires kinematics');
  if (req.path === 'inclusive' && !req.pow) throw new ProtocolError('MALFORMED', 'inclusive path requires pow');
  const motion = req.kinematics ? kinematicsBytes(req.kinematics) : new Uint8Array(0);
  const work = req.pow ? utf8(req.pow.nonce) : new Uint8Array(0);
  return sha256(concat(
    utf8('biokyn-issuance-v2'), lp2(nonce), lp2(blinded), i2osp(req.path === 'fast' ? 0 : 1, 1), lp2(motion), lp2(work), lp2(commitment),
    i2osp(req.tamper.clock, 1), i2osp(req.tamper.automation, 1), i2osp(req.assistive ?? 0, 1),
  ));
}
