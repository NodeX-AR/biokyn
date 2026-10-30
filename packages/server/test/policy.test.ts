import { describe, expect, it } from 'vitest';
import { base64urlDecode, base64urlEncode, completeIssuance, decodeIssuance, generateKeyPair, serializeToken, tokenKeyId, type IssuanceResponse } from '@biokyn/protocol';
import { BioKynHttpError, RedisSecurityStore, StoreUnavailableError, createHandler, siteverify, guardRedis, type NullifierStore, type RiskEvidence } from '../src/index.js';
import { ORIGIN, SECRET, badEvidence, buildRequest, clock, makeVerifier, type Built } from './helpers.js';

const redeem = (b: Built, r: IssuanceResponse): string => {
  if (r.status !== 'TOKEN_ISSUED') throw new Error('not issued');
  return base64urlEncode(serializeToken(completeIssuance(b.pending, decodeIssuance(r.token), base64urlDecode(b.ch.publicKey))));
};

describe('motion/kinematics evidence is advisory (cannot grant)', () => {
  it('a perfect, fabricated kinematics report WITHOUT proof-of-work cannot mint a token', async () => {
    const { verifier } = makeVerifier();
    const b = buildRequest(verifier.challenge(ORIGIN), { withoutPow: true });
    await expect(verifier.issue(ORIGIN, b.req)).rejects.toMatchObject({ status: 400, code: 'bad_request' });
  });
  it('perfect kinematics with an INVALID proof-of-work gets no token', async () => {
    const { verifier } = makeVerifier({ pow: { memoryKiB: 8192, iterations: 1, parallelism: 1, difficultyBits: 20 } });
    const b = buildRequest(verifier.challenge(ORIGIN), { withoutPow: true });
    const r = await verifier.issue(ORIGIN, { ...b.req, pow: { nonce: base64urlEncode(new Uint8Array(8)) } });
    expect(r.status).toBe('STEP_UP_REQUIRED');
  });
  it('perfect kinematics + valid proof-of-work is issued (motion only ever lowers trust)', async () => {
    const { verifier } = makeVerifier();
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    expect((await verifier.issue(ORIGIN, b.req)).status).toBe('TOKEN_ISSUED');
  });
  it('bad kinematics deny even with a valid proof-of-work (evidence can deny)', async () => {
    const { verifier } = makeVerifier();
    expect((await verifier.issue(ORIGIN, buildRequest(verifier.challenge(ORIGIN), { kinematics: badEvidence() }).req)).status).toBe('STEP_UP_REQUIRED');
  });
  it('the explicit unsafe gate restores legacy behaviour, and production refuses it without acknowledgement', async () => {
    const { verifier } = makeVerifier({ kinematicsPolicy: 'unsafe-client-gate' });
    const b = buildRequest(verifier.challenge(ORIGIN), { withoutPow: true });
    expect((await verifier.issue(ORIGIN, b.req)).status).toBe('TOKEN_ISSUED');
    const prev = process.env.NODE_ENV; process.env.NODE_ENV = 'production';
    try {
      const shared = { nullifiers: new (class implements NullifierStore { checkAndInsert() { return true; } })(), attempts: { consumeAttempt: () => true } };
      expect(() => makeVerifier({ kinematicsPolicy: 'unsafe-client-gate', ...shared })).toThrow(/acknowledgeUnsafeKinematicsGate/);
      expect(() => makeVerifier({ kinematicsPolicy: 'unsafe-client-gate', acknowledgeUnsafeKinematicsGate: true, ...shared })).not.toThrow();
    } finally { process.env.NODE_ENV = prev; }
  });
});

describe('/motion-step-up is a signal sink, not a verdict', () => {
  const body = (challengeId: string) => ({ challengeId, modality: 'pointer', durationMs: 1200, samples: 40, corrections: 3, pathRatioMilli: 1300, speedCvMilli: 400 });
  it('returns a neutral acknowledgement (no pass/score oracle) and hands capped untrusted evidence to the hook', async () => {
    const events: Array<{ origin: string; evidence: RiskEvidence }> = [];
    const { verifier } = makeVerifier({ onMotionEvidence: (e) => events.push(e) });
    const out = await verifier.verifyMotionStepUp(ORIGIN, body(verifier.challenge(ORIGIN).challengeId));
    expect(out).toEqual({ status: 'MOTION_RECEIVED' });
    expect(JSON.stringify(out)).not.toMatch(/pass|score|trust/i);
    expect(events).toHaveLength(1);
    expect(events[0]!.evidence.source).toBe('client-untrusted');
    expect(events[0]!.evidence.weight).toBeLessThanOrEqual(15);
  });
  it('is one-use per challenge, validates input, and a throwing hook cannot break it', async () => {
    const { verifier } = makeVerifier({ onMotionEvidence: () => { throw new Error('boom'); } });
    const id = verifier.challenge(ORIGIN).challengeId;
    expect((await verifier.verifyMotionStepUp(ORIGIN, body(id))).status).toBe('MOTION_RECEIVED');
    await expect(verifier.verifyMotionStepUp(ORIGIN, body(id))).rejects.toMatchObject({ status: 400 });
    await expect(verifier.verifyMotionStepUp(ORIGIN, { ...body(id), samples: 'x' })).rejects.toBeInstanceOf(BioKynHttpError);
    await expect(verifier.verifyMotionStepUp('https://evil.example', body(id))).rejects.toMatchObject({ status: 403 });
  });
  it('a motion report never changes what /issue demands', async () => {
    const { verifier } = makeVerifier();
    const ch = verifier.challenge(ORIGIN);
    await verifier.verifyMotionStepUp(ORIGIN, body(ch.challengeId));
    await expect(verifier.issue(ORIGIN, buildRequest(ch, { withoutPow: true }).req)).rejects.toMatchObject({ code: 'bad_request' });
  });
});

describe('issuer key rotation and key ids', () => {
  it('advertises a key id derived from the public key', () => {
    const { verifier } = makeVerifier();
    const ch = verifier.challenge(ORIGIN);
    expect(ch.keyId).toBe(base64urlEncode(tokenKeyId(base64urlDecode(ch.publicKey))));
  });
  it('tokens from a retired key redeem only while it is retained', async () => {
    const c = clock();
    const { verifier: v1 } = makeVerifier({}, c);
    const secrets = { challengeSecret: (v1 as unknown as { opts: { challengeSecret: Uint8Array } }).opts.challengeSecret, voprfSecretKey: (v1 as unknown as { opts: { voprfSecretKey: Uint8Array } }).opts.voprfSecretKey };
    const b = buildRequest(v1.challenge(ORIGIN), {});
    const token = redeem(b, await v1.issue(ORIGIN, b.req));
    const next = generateKeyPair().secretKey;
    const kept = makeVerifier({ challengeSecret: secrets.challengeSecret, voprfSecretKey: next, previousVoprfSecretKeys: [secrets.voprfSecretKey] }, c).verifier;
    expect((await siteverify(kept, { secret: SECRET, response: token })).success).toBe(true);
    const dropped = makeVerifier({ challengeSecret: secrets.challengeSecret, voprfSecretKey: next }, c).verifier;
    expect(await siteverify(dropped, { secret: SECRET, response: token })).toEqual({ success: false, 'error-codes': ['invalid-input-response'] });
  });
  it('rejects duplicate or excessive retained keys', () => {
    const k = generateKeyPair().secretKey;
    expect(() => makeVerifier({ voprfSecretKey: k, previousVoprfSecretKeys: [k] })).toThrow(/must not repeat/);
    expect(() => makeVerifier({ previousVoprfSecretKeys: Array.from({ length: 4 }, () => generateKeyPair().secretKey) })).toThrow(/at most 3/);
  });
});

describe('shared-store failures fail closed', () => {
  const down: NullifierStore = { checkAndInsert: () => { throw new StoreUnavailableError(); } };
  it('issuance returns 503 (never a token) when the nullifier store is down', async () => {
    const { verifier } = makeVerifier({ nullifiers: down });
    await expect(verifier.issue(ORIGIN, buildRequest(verifier.challenge(ORIGIN), {}).req)).rejects.toMatchObject({ status: 503, code: 'store_unavailable' });
  });
  it('redemption is refused (never success) when the nullifier store is down', async () => {
    let healthy = true;
    const store: NullifierStore = { checkAndInsert: () => { if (!healthy) throw new StoreUnavailableError(); return true; } };
    const { verifier } = makeVerifier({ nullifiers: store });
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    const token = redeem(b, await verifier.issue(ORIGIN, b.req));
    healthy = false;
    const out = await siteverify(verifier, { secret: SECRET, response: token });
    expect(out.success).toBe(false);
  });
  it('the HTTP layer maps store outages to a retryable 503', async () => {
    const { verifier } = makeVerifier({ attempts: { consumeAttempt: () => { throw new StoreUnavailableError(); } } });
    const handle = createHandler(verifier);
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    const res = await handle({ method: 'POST', path: '/biokyn/issue', headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify(b.req) });
    expect(res?.status).toBe(503);
    expect(res?.headers['retry-after']).toBe('1');
  });
  it('a hung or erroring Redis becomes StoreUnavailableError within the command timeout', async () => {
    const hung = { set: () => new Promise<never>(() => {}), eval: () => new Promise<never>(() => {}) };
    const t0 = Date.now();
    await expect(new RedisSecurityStore(hung, 'p:', 960_000, { commandTimeoutMs: 80 }).checkAndInsert('k')).rejects.toBeInstanceOf(StoreUnavailableError);
    expect(Date.now() - t0).toBeLessThan(1500);
    const broken = { set: async () => { throw new Error('ECONNRESET'); }, eval: async () => { throw new Error('READONLY'); } };
    await expect(new RedisSecurityStore(broken).consumeAttempt('c', 4, 1000)).rejects.toBeInstanceOf(StoreUnavailableError);
    expect(() => guardRedis(broken, 10)).toThrow(RangeError);
  });
  it('Redis keys carry a hash tag so multi-key scripts stay in one Cluster slot', async () => {
    const keys: string[] = [];
    const redis = { async set(k: string) { keys.push(k); return 'OK' as const; }, async eval() { return 1; } };
    await new RedisSecurityStore(redis).checkAndInsert('abc');
    expect(keys[0]).toMatch(/^biokyn:v1:used:\{[A-Za-z0-9_-]{43}\}$/);
  });
});
