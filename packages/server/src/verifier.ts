/**
 * BioKynVerifier: issuer + redeemer.
 *
 * Anti-oracle contract: `issue()` returns only { TOKEN_ISSUED, token } or { STEP_UP_REQUIRED, challenge }.
 * Everything that explains the decision (kinematic verdict, per-stroke flags, tamper levels, lane, timings) goes to
 * the injected Logger and nowhere else. Residual leakage is inherent to any binary oracle, so each challenge allows a
 * small number of attempts and callers should rate-limit challenge issuance (see http.ts).
 */
import {
  ProtocolError, VoprfServer, base64urlDecode, base64urlEncode, challengeDigest, ctEqual, encodeIssuance, generateKeyPair, judgeKinematics, parseToken,
  powBinding, requestDigest, tokenKeyId, tokenNullifier, toHex, utf8, verifyPowAsync, verifyToken as verifyVoprfToken, deserializeElement, POW_BASELINE, DEFAULT_POW_LIMITS,
  randomBytes, sha256, type ChallengeResponse, type IssuanceRequest, type IssuanceResponse, type KinematicJudgeOptions, type PowParams, type PowSolution,
} from '@biokyn/protocol';
import { ChallengeAuthority } from './challenge.js';
import { BioKynHttpError } from './errors.js';
import { MemoryChallengeAttemptStore, SlidingNullifierCache, StoreCapacityError, StoreUnavailableError, type ChallengeAttemptStore, type NullifierStore } from './nullifier.js';
import { parseIssuanceRequest, parseRegistrationOptionsRequest, parseRegistrationVerifyRequest } from './request.js';
import type { RiskEvidence } from './risk.js';
import { verifyAssertion, verifyRegistration } from './webauthn.js';
import { MemoryWebAuthnCredentialStore, type WebAuthnCredentialStore } from './webauthn-store.js';

export interface Logger {
  info(event: string, data: Record<string, unknown>): void;
  warn(event: string, data: Record<string, unknown>): void;
}
export const silentLogger: Logger = { info() {}, warn() {} };
export const consoleLogger: Logger = {
  info: (e, d) => console.log(JSON.stringify({ level: 'info', event: e, ...d })),
  warn: (e, d) => console.warn(JSON.stringify({ level: 'warn', event: e, ...d })),
};

export interface SiteConfig {
  /** Server-side secret the site's backend presents to /siteverify. */
  secret: string;
  /** Exact page origin, e.g. "https://shop.example.com". */
  origin: string;
}

export interface PowConfig {
  memoryKiB?: number;
  iterations?: number;
  parallelism?: number;
  /** Leading zero bits required; may be a function so load-based policies can raise it. */
  difficultyBits?: number | (() => number);
  /** Concurrent Argon2id verifications (each is hundreds of ms of CPU and ~19 MiB). */
  maxConcurrent?: number;
  /** Waiting verifications beyond which requests get 503. */
  maxQueue?: number;
}

export interface WebAuthnCredentialConfig { credentialId: string; publicKeySpki: string }

export interface WebAuthnRegistrationConfig {
  /** Enables POST {base}/webauthn/register/{options,verify}. Requires the PoW lane (anonymous enrollment must cost work). */
  enabled: boolean;
  /** Lifetime of anonymously registered credentials. Default 7 days, maximum 90. */
  credentialTtlSec?: number;
  rpName?: string;
  requireUserVerification?: boolean;
}

/**
 * How client-reported motion evidence (kinematics, tamper flags) is used.
 *  - "advisory" (default): evidence can DENY or escalate but never GRANT. A token is issued only after a server-verifiable
 *    Argon2id proof-of-work (or a registered-credential WebAuthn assertion). Fabricated evidence therefore cannot mint tokens.
 *  - "unsafe-client-gate": legacy behaviour, kinematics alone can authorize issuance. Forgeable by any script that can
 *    synthesize plausible strokes; production use additionally requires acknowledgeUnsafeKinematicsGate.
 */
export type KinematicsPolicy = 'advisory' | 'unsafe-client-gate';

export interface VerifierOptions {
  issuer: string;
  /** 32-byte little-endian ristretto255 scalar (see generateServerSecrets). Used for issuance and redemption. */
  voprfSecretKey: Uint8Array;
  /** Retired issuer keys still accepted for REDEMPTION during rotation. Keep each for at least 3 token epochs after rotating. */
  previousVoprfSecretKeys?: Uint8Array[];
  /** >= 32 random bytes, shared by all instances of one deployment. */
  challengeSecret: Uint8Array;
  sites: SiteConfig[];
  challengeTtlSec?: number;
  /** Redemption context accepts the current and two previous epochs; without an issuance timestamp, worst-case acceptance approaches 3x this epoch. */
  tokenEpochSec?: number;
  maxAttemptsPerChallenge?: number;
  /** false disables the Argon2id lane entirely. */
  pow?: PowConfig | false;
  /** Enable only with server-registered credential IDs and public keys. This proves key possession, not hardware attestation. */
  webauthnStepUp?: boolean;
  webauthnCredentials?: WebAuthnCredentialConfig[];
  kinematics?: Partial<KinematicJudgeOptions>;
  kinematicsPolicy?: KinematicsPolicy;
  /** Must be true to run "unsafe-client-gate" with NODE_ENV=production. */
  acknowledgeUnsafeKinematicsGate?: boolean;
  /** Receives motion-step-up evidence as an untrusted risk signal (feed it to assessRisk). It can never mint or grant a token. */
  onMotionEvidence?: (event: { origin: string; evidence: RiskEvidence }) => void;
  webauthnRegistration?: WebAuthnRegistrationConfig;
  /** Shared registry for registered credentials. Production multi-instance deployments must supply RedisWebAuthnCredentialStore. */
  webauthnCredentialStore?: WebAuthnCredentialStore;
  /** `score` reported by /siteverify for any valid token. */
  successScore?: number;
  nullifiers?: NullifierStore;
  /** Atomic per-challenge attempt counter; production must provide a shared implementation. */
  attempts?: ChallengeAttemptStore;
  logger?: Logger;
  now?: () => number;
}

export type VerifyOutcome =
  | { success: true; hostname: string; challengeTs: string }
  | { success: false; errors: string[] };

class Semaphore {
  private active = 0;
  private readonly waiters: Array<{ resolve: () => void; reject: (error: Error) => void; signal?: AbortSignal; onAbort?: () => void }> = [];
  constructor(private readonly max: number, private readonly maxQueue: number) {}
  async run<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    if (signal?.aborted) throw new Error('request_aborted');
    if (this.active >= this.max) {
      if (this.waiters.length >= this.maxQueue) throw new BioKynHttpError(503, 'busy', 1);
      await new Promise<void>((resolve, reject) => {
        const waiter: { resolve: () => void; reject: (error: Error) => void; signal?: AbortSignal; onAbort?: () => void } = { resolve, reject, signal };
        if (signal) {
          waiter.onAbort = () => {
            const index = this.waiters.indexOf(waiter);
            if (index >= 0) this.waiters.splice(index, 1);
            reject(new Error('request_aborted'));
          };
          signal.addEventListener('abort', waiter.onAbort, { once: true });
        }
        this.waiters.push(waiter);
      });
    } else this.active++;
    if (signal?.aborted) {
      const next = this.nextWaiter();
      if (next) next(); else this.active--;
      throw new Error('request_aborted');
    }
    try { return await fn(); } finally {
      const next = this.nextWaiter();
      if (next) next(); else this.active--;
    }
  }
  private nextWaiter(): (() => void) | undefined {
    while (this.waiters.length) {
      const waiter = this.waiters.shift()!;
      if (waiter.signal?.aborted) { waiter.reject(new Error('request_aborted')); continue; }
      if (waiter.signal && waiter.onAbort) waiter.signal.removeEventListener('abort', waiter.onAbort);
      return waiter.resolve;
    }
    return undefined;
  }
}

export function generateServerSecrets(): { voprfSecretKey: Uint8Array; challengeSecret: Uint8Array } {
  return { voprfSecretKey: generateKeyPair().secretKey, challengeSecret: randomBytes(32) };
}

const normOrigin = (o: string): string => {
  const u = new URL(o);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new RangeError('site origin must use HTTP or HTTPS');
  if (u.username || u.password || u.pathname !== '/' || u.search || u.hash) throw new RangeError('site origin must contain only scheme, host, and optional port');
  if (process.env.NODE_ENV === 'production' && u.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)) {
    throw new RangeError('production site origins must use HTTPS');
  }
  return u.origin;
};

export class BioKynVerifier {
  readonly voprf: VoprfServer;
  readonly authority: ChallengeAuthority;
  private readonly sites: Array<SiteConfig & { origin: string }>;
  private readonly webauthnCredentials: Map<string, WebAuthnCredentialConfig & { signCount: number }>;
  private readonly keyring = new Map<string, VoprfServer>();
  private readonly kinematicsPolicy: KinematicsPolicy;
  private readonly credentialStore: WebAuthnCredentialStore;
  private readonly registration: { credentialTtlMs: number; rpName: string; requireUserVerification: boolean } | null;
  private readonly now: () => number;
  private readonly log: Logger;
  private readonly nullifiers: NullifierStore;
  private readonly attemptStore: ChallengeAttemptStore;
  private readonly challengeTtlMs: number;
  private readonly epochMs: number;
  private readonly maxAttempts: number;
  private readonly pow: Required<Omit<PowConfig, 'difficultyBits'>> & { difficultyBits: number | (() => number) } | null;
  private readonly powGate: Semaphore | null;
  private readonly webauthn: boolean;
  private readonly successScore: number;

  constructor(private readonly opts: VerifierOptions) {
    if (opts.sites.length === 0) throw new RangeError('at least one site is required');
    if (!opts.issuer || opts.issuer.length > 255) throw new RangeError('issuer must be a non-empty identifier of at most 255 characters');
    const seenOrigins = new Set<string>(); const seenSecrets = new Set<string>();
    for (const site of opts.sites) {
      const origin = normOrigin(site.origin);
      if (seenOrigins.has(origin)) throw new RangeError(`duplicate site origin: ${origin}`);
      if (typeof site.secret !== 'string' || site.secret.length < 32 || /^(replace|changeme|example|your[-_])/i.test(site.secret)) throw new RangeError('each site secret must be at least 32 characters of random secret material');
      if (seenSecrets.has(site.secret)) throw new RangeError('site secrets must be unique');
      seenOrigins.add(origin); seenSecrets.add(site.secret);
    }
    if (process.env.NODE_ENV === 'production' && !opts.nullifiers) throw new Error('BioKyn production requires an explicitly configured shared atomic NullifierStore');
    if (process.env.NODE_ENV === 'production' && !opts.attempts) throw new Error('BioKyn production requires an explicitly configured shared atomic ChallengeAttemptStore');
    this.now = opts.now ?? Date.now;
    this.log = opts.logger ?? silentLogger;
    this.voprf = new VoprfServer(opts.voprfSecretKey);
    this.keyring.set(toHex(tokenKeyId(this.voprf.publicKey)), this.voprf);
    for (const previous of opts.previousVoprfSecretKeys ?? []) {
      const server = new VoprfServer(previous); const id = toHex(tokenKeyId(server.publicKey));
      if (this.keyring.has(id)) throw new RangeError('previousVoprfSecretKeys must not repeat the current key or each other');
      this.keyring.set(id, server);
    }
    if (this.keyring.size > 4) throw new RangeError('at most 3 previous issuer keys may be retained');
    this.kinematicsPolicy = opts.kinematicsPolicy ?? 'advisory';
    if (this.kinematicsPolicy !== 'advisory' && this.kinematicsPolicy !== 'unsafe-client-gate') throw new RangeError('invalid kinematicsPolicy');
    if (this.kinematicsPolicy === 'unsafe-client-gate') {
      if (process.env.NODE_ENV === 'production' && !opts.acknowledgeUnsafeKinematicsGate) throw new Error('kinematicsPolicy "unsafe-client-gate" lets forgeable browser evidence authorize issuance; set acknowledgeUnsafeKinematicsGate to run it in production');
      (opts.logger ?? silentLogger).warn('unsafe_kinematics_gate_enabled', { note: 'client-reported motion can authorize token issuance' });
    }
    const challengeTtlSec = opts.challengeTtlSec ?? 120;
    const tokenEpochSec = opts.tokenEpochSec ?? 300;
    const maxAttempts = opts.maxAttemptsPerChallenge ?? 4;
    if (!Number.isSafeInteger(challengeTtlSec) || challengeTtlSec < 10 || challengeTtlSec > 600) throw new RangeError('challengeTtlSec must be an integer from 10 to 600');
    if (!Number.isSafeInteger(tokenEpochSec) || tokenEpochSec < 30 || tokenEpochSec > 3600) throw new RangeError('tokenEpochSec must be an integer from 30 to 3600');
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 20) throw new RangeError('maxAttemptsPerChallenge must be an integer from 1 to 20');
    this.challengeTtlMs = challengeTtlSec * 1000;
    this.epochMs = tokenEpochSec * 1000;
    this.authority = new ChallengeAuthority(opts.challengeSecret, this.challengeTtlMs, this.epochMs, this.now);
    this.sites = opts.sites.map((s) => ({ secret: s.secret, origin: normOrigin(s.origin) }));
    this.nullifiers = opts.nullifiers ?? new SlidingNullifierCache({ ttlMs: 3 * this.epochMs + 60_000, now: this.now });
    this.attemptStore = opts.attempts ?? new MemoryChallengeAttemptStore(this.now);
    this.maxAttempts = maxAttempts;
    this.webauthn = opts.webauthnStepUp ?? false;
    this.webauthnCredentials = new Map();
    for (const credential of opts.webauthnCredentials ?? []) {
      if (!credential || typeof credential.credentialId !== 'string' || !/^[A-Za-z0-9_-]{16,1400}$/.test(credential.credentialId) || typeof credential.publicKeySpki !== 'string' || credential.publicKeySpki.length > 400) throw new RangeError('invalid registered WebAuthn credential');
      try { if (base64urlDecode(credential.publicKeySpki).length < 64) throw new Error(); } catch { throw new RangeError('invalid registered WebAuthn SPKI'); }
      if (this.webauthnCredentials.has(credential.credentialId)) throw new RangeError('duplicate WebAuthn credential ID');
      this.webauthnCredentials.set(credential.credentialId, { ...credential, signCount: 0 });
    }
    const reg = opts.webauthnRegistration;
    if (reg?.enabled) {
      const ttlSec = reg.credentialTtlSec ?? 7 * 86_400;
      if (!Number.isSafeInteger(ttlSec) || ttlSec < 60 || ttlSec > 90 * 86_400) throw new RangeError('credentialTtlSec must be from 60 to 7776000');
      if (!this.webauthn) throw new Error('webauthnRegistration requires webauthnStepUp: true');
      if (opts.pow === false) throw new Error('anonymous WebAuthn registration requires the PoW lane so enrollment costs work');
      if (process.env.NODE_ENV === 'production' && !opts.webauthnCredentialStore) throw new Error('BioKyn production requires an explicitly configured shared webauthnCredentialStore when registration is enabled');
      this.registration = { credentialTtlMs: ttlSec * 1000, rpName: reg.rpName ?? 'BioKyn', requireUserVerification: reg.requireUserVerification ?? false };
    } else this.registration = null;
    this.credentialStore = opts.webauthnCredentialStore ?? new MemoryWebAuthnCredentialStore(this.now);
    if (this.webauthn && this.webauthnCredentials.size === 0 && !this.registration && !opts.webauthnCredentialStore) throw new Error('WebAuthn step-up requires pre-registered credentials, a credential store, or registration enabled');
    this.successScore = opts.successScore ?? 0.9;
    if (!Number.isFinite(this.successScore) || this.successScore < 0 || this.successScore > 1) throw new RangeError('successScore must be between 0 and 1');
    if (opts.pow === false) {
      this.pow = null; this.powGate = null;
    } else {
      const p = opts.pow ?? {};
      const memoryKiB = p.memoryKiB ?? POW_BASELINE.memoryKiB;
      const iterations = p.iterations ?? POW_BASELINE.iterations;
      const parallelism = p.parallelism ?? POW_BASELINE.parallelism;
      const maxConcurrent = p.maxConcurrent ?? 2;
      const maxQueue = p.maxQueue ?? 8;
      const limits = DEFAULT_POW_LIMITS;
      if (!Number.isSafeInteger(memoryKiB) || memoryKiB < 8_192 || memoryKiB > limits.maxMemoryKiB) throw new RangeError(`PoW memoryKiB must be from 8192 to ${limits.maxMemoryKiB}`);
      if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > limits.maxIterations) throw new RangeError(`PoW iterations must be from 1 to ${limits.maxIterations}`);
      if (!Number.isSafeInteger(parallelism) || parallelism < 1 || parallelism > limits.maxParallelism) throw new RangeError(`PoW parallelism must be from 1 to ${limits.maxParallelism}`);
      if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 32) throw new RangeError('PoW maxConcurrent must be from 1 to 32');
      if (!Number.isSafeInteger(maxQueue) || maxQueue < 0 || maxQueue > 10_000) throw new RangeError('PoW maxQueue must be from 0 to 10000');
      this.pow = { memoryKiB, iterations, parallelism, difficultyBits: p.difficultyBits ?? 8, maxConcurrent, maxQueue };
      this.powGate = new Semaphore(this.pow.maxConcurrent, this.pow.maxQueue);
    }
  }

  get publicKey(): string { return base64urlEncode(this.voprf.publicKey); }

  siteForOrigin(origin: string | undefined): (SiteConfig & { origin: string }) | undefined {
    if (!origin) return undefined;
    let o: string;
    try { o = normOrigin(origin); } catch { return undefined; }
    return this.sites.find((s) => s.origin === o);
  }

  /** Resolve a Host header only when it exactly matches an already configured site host. */
  siteOriginForHost(host: string | undefined): string | undefined {
    if (!host || host.length > 255 || /[\s/@\\]/.test(host)) return undefined;
    return this.sites.find((s) => { try { return new URL(s.origin).host.toLowerCase() === host.toLowerCase(); } catch { return false; } })?.origin;
  }

  private difficulty(): number {
    if (!this.pow) return 0;
    const d = typeof this.pow.difficultyBits === 'function' ? this.pow.difficultyBits() : this.pow.difficultyBits;
    return Math.max(0, Math.min(24, Math.floor(d)));
  }

  private powParams(salt: Uint8Array, bits: number): PowParams {
    const p = this.pow!;
    return { salt: base64urlEncode(salt), memoryKiB: p.memoryKiB, iterations: p.iterations, parallelism: p.parallelism, difficultyBits: bits };
  }

  /**
   * Accept a challenge-bound motion telemetry report as an UNTRUSTED RISK SIGNAL.
   *
   * Client-generated motion values are forgeable by any script, so this endpoint can never grant anything: it does not
   * issue tokens, does not change what /issue will accept, and does not tell the caller whether the report "passed"
   * (a pass/score response would be an evasion oracle). The heuristic result is logged and handed to
   * `onMotionEvidence` as a capped, `client-untrusted` RiskEvidence item for the site's own risk policy (see assessRisk).
   * The challenge is one-use so reports cannot be replayed or brute-forced.
   */
  async verifyMotionStepUp(origin: string | undefined, raw: unknown): Promise<{ status: 'MOTION_RECEIVED' }> {
    const site = this.siteForOrigin(origin);
    if (!site) throw new BioKynHttpError(403, 'origin_not_allowed');
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new BioKynHttpError(400, 'bad_request');
    const v = raw as Record<string, unknown>;
    const int = (x: unknown): number => (typeof x === 'number' && Number.isSafeInteger(x) ? x : (() => { throw new BioKynHttpError(400, 'bad_request'); })());
    if (typeof v.challengeId !== 'string' || v.challengeId.length > 100 || !['touch', 'pointer'].includes(String(v.modality))) throw new BioKynHttpError(400, 'bad_request');
    const d = int(v.durationMs), n = int(v.samples), c = int(v.corrections), p = int(v.pathRatioMilli), cv = int(v.speedCvMilli);
    const ch = this.authority.open(v.challengeId, site.origin);
    if (!ch) throw new BioKynHttpError(400, 'invalid_challenge');
    if (!(await this.insertNullifier(`motion:${ch.id}`, this.challengeTtlMs + 60_000))) throw new BioKynHttpError(400, 'invalid_challenge');
    let weight = 0; const reasons: string[] = [];
    const flag = (cond: boolean, w: number, id: string): void => { if (cond) { weight += w; reasons.push(id); } };
    if (d < 250 || d > 30_000 || n < 8 || n > 2_000 || c < 0 || c > 100 || p < 1_000 || p > 20_000 || cv < 0 || cv > 5_000) { weight = 15; reasons.push('motion-out-of-range'); }
    else {
      flag(d < 400 || d > 15_000, 3, 'motion-duration'); flag(n < 12, 4, 'motion-few-samples'); flag(c === 0, 2, 'motion-no-corrections');
      flag(p < 1_100 || p > 8_000, 3, 'motion-path-ratio'); flag(cv < 30 || cv > 2_500, 3, 'motion-speed-variation');
    }
    this.log.info('motion_evidence', { origin: site.origin, weight, reasons, durationMs: d, samples: n });
    try { this.opts.onMotionEvidence?.({ origin: site.origin, evidence: { id: 'motion-heuristic', weight: Math.min(15, weight), source: 'client-untrusted', detail: reasons.join(',') } }); }
    catch (e) { this.log.warn('motion_evidence_hook_failed', { error: e instanceof Error ? e.message : 'unknown' }); }
    return { status: 'MOTION_RECEIVED' };
  }

  challenge(origin: string | undefined): ChallengeResponse {
    const site = this.siteForOrigin(origin);
    if (!site) throw new BioKynHttpError(403, 'origin_not_allowed');
    const c = this.authority.create(site.origin, this.difficulty());
    const out: ChallengeResponse = {
      challengeId: c.id,
      nonce: base64urlEncode(c.nonce),
      issuedAt: c.issuedAt,
      ttlSec: Math.floor(this.challengeTtlMs / 1000),
      issuer: this.opts.issuer,
      origin: site.origin,
      redemptionContext: base64urlEncode(this.authority.redemptionContextAt(site.origin, c.issuedAt)),
      publicKey: this.publicKey,
      keyId: base64urlEncode(tokenKeyId(this.voprf.publicKey)),
    };
    if (this.pow) out.pow = this.powParams(c.powSalt, c.difficultyBits);
    return out;
  }

  private async insertNullifier(key: string, ttlMs: number): Promise<boolean> {
    try { return await this.nullifiers.checkAndInsert(key, ttlMs); } catch (e) { throw this.storeFailure(e); }
  }

  private async takeAttempt(id: string): Promise<boolean> {
    try { return await this.attemptStore.consumeAttempt(id, this.maxAttempts, this.challengeTtlMs); } catch (e) { throw this.storeFailure(e); }
  }

  /** Any shared-state failure fails closed: 503 + retry-after, never an issuance or an accepted token. */
  private storeFailure(e: unknown): unknown {
    if (e instanceof BioKynHttpError) return e;
    if (e instanceof StoreCapacityError || e instanceof StoreUnavailableError) {
      this.log.warn('store_unavailable', { kind: e.name });
      return new BioKynHttpError(503, 'store_unavailable', 1);
    }
    return e;
  }

  async issue(origin: string | undefined, raw: unknown, signal?: AbortSignal): Promise<IssuanceResponse> {
    const started = this.now();
    const site = this.siteForOrigin(origin);
    if (!site) throw new BioKynHttpError(403, 'origin_not_allowed');
    const req = parseIssuanceRequest(raw);
    // Server-verifiable work is mandatory under the advisory policy (a registered-credential assertion is the only alternative).
    if (this.kinematicsPolicy === 'advisory' && !req.pow && !req.stepUp) throw new BioKynHttpError(400, 'bad_request');
    const ch = this.authority.open(req.challengeId, site.origin);
    if (!ch) throw new BioKynHttpError(400, 'invalid_challenge');
    const blinded = base64urlDecode(req.blindedElement);
    try { deserializeElement(blinded); } catch { throw new BioKynHttpError(400, 'bad_request'); } // rejects invalid and identity encodings
    let digest: Uint8Array;
    try { digest = requestDigest(ch.nonce, blinded, req, base64urlDecode(req.timingCommitment)); } catch (e) {
      if (e instanceof ProtocolError) throw new BioKynHttpError(400, 'bad_request');
      throw e;
    }

    if (req.path !== 'inclusive' || req.stepUp) {
      if (!(await this.takeAttempt(ch.id))) throw new BioKynHttpError(429, 'challenge_exhausted');
    }
    const decision = await this.decide(site, req, ch.id, ch.nonce, blinded, ch.powSalt, ch.difficultyBits, digest, signal);
    this.log.info('issuance', {
      origin: site.origin, challengeAgeMs: started - ch.issuedAt, path: req.path, lane: decision.lane, allowed: decision.allow,
      verdict: decision.verdict, reasons: decision.reasons, passFraction: decision.passFraction, strokeFlags: decision.strokeFlags,
      tamper: req.tamper, assistive: req.assistive ?? 0, stepUp: Boolean(req.stepUp), durationMs: this.now() - started,
    });

    if (!decision.allow) return { status: 'STEP_UP_REQUIRED', challenge: base64urlEncode(this.authority.stepUpChallenge(digest)) };
    if (!(await this.insertNullifier(`c:${ch.id}`, this.challengeTtlMs + 60_000))) throw new BioKynHttpError(400, 'invalid_challenge');
    // Only the evaluated element and its DLEQ proof leave the issuer: no echo of the blinded element, no digest, no key id.
    return { status: 'TOKEN_ISSUED', token: encodeIssuance(this.voprf.blindEvaluate(blinded)) };
  }

  private async lookupCredential(id: string): Promise<{ publicKeySpki: string; signCount: number; source: 'static' | 'store' } | undefined> {
    const fixed = this.webauthnCredentials.get(id);
    if (fixed) return { publicKeySpki: fixed.publicKeySpki, signCount: fixed.signCount, source: 'static' };
    try {
      const c = await this.credentialStore.get(id);
      return c ? { publicKeySpki: c.publicKeySpki, signCount: c.signCount, source: 'store' } : undefined;
    } catch (e) { throw this.storeFailure(e); }
  }

  private async decide(
    site: SiteConfig & { origin: string }, req: IssuanceRequest, challengeId: string, nonce: Uint8Array, blinded: Uint8Array, powSalt: Uint8Array,
    difficultyBits: number, digest: Uint8Array, signal?: AbortSignal,
  ): Promise<{ allow: boolean; lane: string; verdict?: string; reasons?: string[]; passFraction?: number; strokeFlags?: string[][] }> {
    if (req.stepUp) {
      if (!this.webauthn) return { allow: false, lane: 'webauthn-disabled' };
      const credential = await this.lookupCredential(req.stepUp.credentialId);
      if (!credential) return { allow: false, lane: 'webauthn', reasons: ['credential-unregistered'] };
      const r = await verifyAssertion(req.stepUp, { origin: site.origin, rpId: new URL(site.origin).hostname, expectedChallenge: this.authority.stepUpChallenge(digest), credentialId: req.stepUp.credentialId, publicKeySpki: credential.publicKeySpki });
      if (!r.ok) return { allow: false, lane: 'webauthn', reasons: [r.reason] };
      // Clone detection: a non-zero counter must strictly increase. Authenticators that always report 0 are tolerated.
      if (r.signCount !== 0 || credential.signCount !== 0) {
        if (r.signCount <= credential.signCount) return { allow: false, lane: 'webauthn', reasons: ['counter-regression'] };
        let advanced: boolean;
        if (credential.source === 'static') { this.webauthnCredentials.get(req.stepUp.credentialId)!.signCount = r.signCount; advanced = true; }
        else { try { advanced = await this.credentialStore.updateSignCount(req.stepUp.credentialId, credential.signCount, r.signCount); } catch (e) { throw this.storeFailure(e); } }
        if (!advanced) return { allow: false, lane: 'webauthn', reasons: ['counter-conflict'] };
      }
      return { allow: true, lane: 'webauthn', reasons: [] };
    }

    const gate = this.kinematicsPolicy === 'unsafe-client-gate';
    let motion: { verdict?: string; reasons?: string[]; passFraction?: number; strokeFlags?: string[][] } = {};
    if (req.path === 'fast') {
      const j = judgeKinematics(req.kinematics!, this.opts.kinematics);
      const tampered = req.tamper.automation === 2 || req.tamper.clock === 2;
      motion = { verdict: j.verdict, reasons: tampered ? [...j.reasons, 'tamper'] : j.reasons, passFraction: j.passFraction, strokeFlags: j.strokeFlags };
      // Evidence can only lower trust. A negative verdict ends the request before any expensive verification.
      if (j.verdict !== 'ok' || tampered) return { allow: false, lane: gate ? 'fast' : 'fast-advisory', ...motion };
      if (gate) return { allow: true, lane: 'fast', ...motion };
    }

    // Everything below grants trust, so it must rest on server-verifiable cost: the Argon2id proof-of-work.
    if (!this.pow || !this.powGate || !req.pow) {
      if (req.path === 'inclusive' && !(await this.takeAttempt(challengeId))) throw new BioKynHttpError(429, 'challenge_exhausted');
      return { allow: false, lane: this.pow ? 'pow-missing' : 'pow-disabled', ...motion };
    }
    const params = this.powParams(powSalt, difficultyBits);
    const pow: PowSolution = req.pow;
    const ok = await this.powGate.run(async () => {
      // Consume the attempt only after the semaphore admits this request, so a 503 busy response does not burn an attempt.
      if (req.path === 'inclusive' && !(await this.takeAttempt(challengeId))) throw new BioKynHttpError(429, 'challenge_exhausted');
      return verifyPowAsync(params, pow, powBinding(nonce, blinded));
    }, signal);
    return { allow: ok, lane: req.path === 'fast' ? 'fast-advisory+pow' : 'pow', ...motion, reasons: ok ? motion.reasons ?? [] : [...(motion.reasons ?? []), 'pow-invalid'] };
  }

  // ------------------------------------------------------------------ anonymous WebAuthn registration

  /** Step 1: solve PoW on a fresh challenge, receive creation options bound to that challenge. */
  async webauthnRegistrationOptions(origin: string | undefined, raw: unknown, signal?: AbortSignal): Promise<Record<string, unknown>> {
    const site = this.siteForOrigin(origin);
    if (!site) throw new BioKynHttpError(403, 'origin_not_allowed');
    if (!this.registration || !this.pow || !this.powGate) throw new BioKynHttpError(404, 'not_found');
    const req = parseRegistrationOptionsRequest(raw);
    const ch = this.authority.open(req.challengeId, site.origin);
    if (!ch) throw new BioKynHttpError(400, 'invalid_challenge');
    if (!(await this.takeAttempt(`reg-opt:${ch.id}`))) throw new BioKynHttpError(429, 'challenge_exhausted');
    const params = this.powParams(ch.powSalt, ch.difficultyBits);
    const ok = await this.powGate.run(async () => verifyPowAsync(params, req.pow, powBinding(ch.nonce, utf8('biokyn-webauthn-register'))), signal);
    if (!ok) throw new BioKynHttpError(400, 'invalid_challenge');
    const rpId = new URL(site.origin).hostname;
    return {
      rp: { id: rpId, name: this.registration.rpName },
      user: { id: base64urlEncode(this.authority.registrationUserHandle(ch.nonce)), name: 'anonymous', displayName: 'Anonymous visitor' },
      challenge: base64urlEncode(this.authority.registrationChallenge(ch.nonce)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'discouraged', userVerification: this.registration.requireUserVerification ? 'required' : 'preferred' },
      attestation: 'none',
      timeout: 60_000,
    };
  }

  /** Step 2: verify the attestation and persist the credential. One successful registration per challenge. */
  async webauthnRegister(origin: string | undefined, raw: unknown): Promise<{ status: 'REGISTERED'; credentialId: string; expiresAt: number }> {
    const site = this.siteForOrigin(origin);
    if (!site) throw new BioKynHttpError(403, 'origin_not_allowed');
    if (!this.registration) throw new BioKynHttpError(404, 'not_found');
    const req = parseRegistrationVerifyRequest(raw);
    const ch = this.authority.open(req.challengeId, site.origin);
    if (!ch) throw new BioKynHttpError(400, 'invalid_challenge');
    if (!(await this.takeAttempt(`reg-ver:${ch.id}`))) throw new BioKynHttpError(429, 'challenge_exhausted');
    const r = await verifyRegistration(req.credential, {
      origin: site.origin, rpId: new URL(site.origin).hostname, expectedChallenge: this.authority.registrationChallenge(ch.nonce), requireUserVerification: this.registration.requireUserVerification,
    });
    this.log.info('webauthn_registration', { origin: site.origin, ok: r.ok, reason: r.ok ? undefined : r.reason, userVerified: r.ok ? r.userVerified : undefined });
    if (!r.ok) throw new BioKynHttpError(400, 'registration_failed');
    // Consume the challenge BEFORE persisting so two concurrent successful ceremonies cannot both register.
    if (!(await this.insertNullifier(`wr:${ch.id}`, this.challengeTtlMs + 60_000))) throw new BioKynHttpError(400, 'invalid_challenge');
    const createdAt = this.now(), expiresAt = createdAt + this.registration.credentialTtlMs;
    let created: boolean;
    try { created = await this.credentialStore.create({ credentialId: r.credentialId, publicKeySpki: r.publicKeySpki, signCount: r.signCount, createdAt, expiresAt, origin: site.origin, aaguid: r.aaguid, backupEligible: r.backupEligible }); }
    catch (e) { throw this.storeFailure(e); }
    if (!created || this.webauthnCredentials.has(r.credentialId)) throw new BioKynHttpError(400, 'registration_failed');
    return { status: 'REGISTERED', credentialId: r.credentialId, expiresAt };
  }

  /** Administrative revocation (incident response). Returns false if the credential is unknown. */
  async revokeWebAuthnCredential(credentialId: string): Promise<boolean> {
    try { return await this.credentialStore.revoke(credentialId); } catch (e) { throw this.storeFailure(e); }
  }

  // ------------------------------------------------------------------ redemption (/siteverify)

  async verifyToken(secret: string | undefined, response: string | undefined): Promise<VerifyOutcome> {
    if (!secret) return { success: false, errors: ['missing-input-secret'] };
    if (!response) return { success: false, errors: ['missing-input-response'] };
    let site: (SiteConfig & { origin: string }) | undefined;
    const suppliedSecretHash = sha256(utf8(secret));
    for (const s of this.sites) if (ctEqual(sha256(utf8(s.secret)), suppliedSecretHash) && !site) site = s; // fixed-length digest compare; no early exit
    if (!site) return { success: false, errors: ['invalid-input-secret'] };

    // The response is an opaque token. Never accept an action suffix supplied by the caller:
    // it would let an attacker forge the action returned by a reCAPTCHA-compatible siteverify API.
    let token;
    try {
      token = parseToken(base64urlDecode(response));
    } catch { return { success: false, errors: ['invalid-input-response'] }; }

    let epochStart: number | undefined;
    let digest: Uint8Array | undefined;
    for (const { context, epochStart: es } of this.authority.acceptedRedemptionContexts(site.origin)) {
      const d = challengeDigest({ issuer: this.opts.issuer, origin: site.origin, redemptionContext: base64urlEncode(context) });
      if (ctEqual(d, token.challengeDigest) && digest === undefined) { digest = d; epochStart = es; }
    }
    if (!digest || epochStart === undefined) return { success: false, errors: ['timeout-or-duplicate'] };

    // Select the issuer key by key id (current key, or a retired key kept for rotation overlap).
    const key = this.keyring.get(toHex(token.keyId));
    if (!key) return { success: false, errors: ['invalid-input-response'] };
    if (!verifyVoprfToken(key, token, digest).ok) return { success: false, errors: ['invalid-input-response'] };
    // Replay protection runs only after the authenticator verified, so garbage cannot fill the nullifier store.
    if (!(await this.insertNullifier(`t:${base64urlEncode(tokenNullifier(token))}`, 3 * this.epochMs + 60_000))) return { success: false, errors: ['timeout-or-duplicate'] };

    this.log.info('redemption', { origin: site.origin, epochStart });
    return { success: true, hostname: new URL(site.origin).hostname, challengeTs: new Date(epochStart).toISOString() };
  }

  get scoreOnSuccess(): number { return this.successScore; }
  get tokenEpochMs(): number { return this.epochMs; }
  idempotencyOrigin(secret: string | undefined): string | undefined {
    if (!secret) return undefined;
    let found: string | undefined;
    const suppliedSecretHash = sha256(utf8(secret));
    for (const site of this.sites) if (ctEqual(sha256(utf8(site.secret)), suppliedSecretHash) && !found) found = site.origin;
    return found;
  }
}
