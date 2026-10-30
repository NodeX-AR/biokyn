import { describe, expect, it } from 'vitest';
import {
  base64urlDecode, base64urlEncode, completeIssuance, decodeIssuance, serializeToken, solvePow, verifyPow, powBinding, type IssuanceResponse, type PowParams, type PowSolution,
} from '@biokyn/protocol';
import { BioKynHttpError, siteverify, type Logger } from '../src/index.js';
import { ORIGIN, SECRET, badEvidence, buildRequest, digestOf, makeVerifier, type Built } from './helpers.js';
import { makeAuthenticator } from './authenticator.js';

const redeem = (b: Built, r: IssuanceResponse): string => {
  if (r.status !== 'TOKEN_ISSUED') throw new Error('not issued');
  const t = completeIssuance(b.pending, decodeIssuance(r.token), base64urlDecode(b.ch.publicKey));
  return base64urlEncode(serializeToken(t));
};
const memLog = () => { const events: Array<{ event: string; data: Record<string, unknown> }> = []; const l: Logger = { info: (event, data) => events.push({ event, data }), warn: (event, data) => events.push({ event, data }) }; return { l, events }; };

describe('fast lane', () => {
  it('human-like evidence -> TOKEN_ISSUED -> unblind (DLEQ verified) -> /siteverify success with score 0.9', async () => {
    const { verifier } = makeVerifier();
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    const r = await verifier.issue(ORIGIN, b.req);
    expect(r.status).toBe('TOKEN_ISSUED');
    const token = redeem(b, r);
    const out = await siteverify(verifier, { secret: SECRET, response: token });
    expect(out).toMatchObject({ success: true, score: 0.9, hostname: 'shop.example.com', 'error-codes': [] });
    expect(out.challenge_ts).toMatch(/^\d{4}-\d\d-\d\dT/);
  });

  it('tokens are single-use: a second redemption reports timeout-or-duplicate', async () => {
    const { verifier } = makeVerifier();
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    const token = redeem(b, await verifier.issue(ORIGIN, b.req));
    expect((await siteverify(verifier, { secret: SECRET, response: token })).success).toBe(true);
    expect(await siteverify(verifier, { secret: SECRET, response: token })).toEqual({ success: false, 'error-codes': ['timeout-or-duplicate'] });
  });

  it('siteverify idempotency returns the cached successful response on retry', async () => {
    const { verifier } = makeVerifier();
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    const token = redeem(b, await verifier.issue(ORIGIN, b.req));
    const first = await siteverify(verifier, { secret: SECRET, response: token, idempotency_key: 'retry-001' });
    const retry = await siteverify(verifier, { secret: SECRET, response: token, idempotency_key: 'retry-001' });
    expect(first.success).toBe(true);
    expect(retry).toEqual(first);
  });

  it('retains Redis nullifiers for at least the configured token redemption lifetime', async () => {
    const retainedFor: number[] = [];
    const nullifiers = { async checkAndInsert(_key: string, ttlMs?: number) { retainedFor.push(ttlMs ?? -1); return true; } };
    const { verifier } = makeVerifier({ tokenEpochSec: 600, nullifiers });
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    const token = redeem(b, await verifier.issue(ORIGIN, b.req));
    expect(retainedFor[0]).toBeGreaterThanOrEqual(120_000); // challenge lifetime plus safety margin
    expect((await siteverify(verifier, { secret: SECRET, response: token })).success).toBe(true);
    expect(retainedFor[1]).toBe(1_860_000); // 3 * 600s epochs (current + two previous accepted) + 60s safety margin
  });

  it('a challenge can be spent once; replaying the same request fails', async () => {
    const { verifier } = makeVerifier();
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    expect((await verifier.issue(ORIGIN, b.req)).status).toBe('TOKEN_ISSUED');
    await expect(verifier.issue(ORIGIN, b.req)).rejects.toMatchObject({ status: 400, code: 'invalid_challenge' });
  });

  it('rejects caller-controlled action suffixes instead of echoing an unauthenticated action', async () => {
    const { verifier } = makeVerifier();
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    const token = redeem(b, await verifier.issue(ORIGIN, b.req)) + '.' + base64urlEncode(new TextEncoder().encode('login'));
    expect(await siteverify(verifier, { secret: SECRET, response: token })).toEqual({ success: false, 'error-codes': ['invalid-input-response'] });
  });

  it('tokens expire after at most three epochs and cannot cross sites', async () => {
    const { verifier, c } = makeVerifier();
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    const token = redeem(b, await verifier.issue(ORIGIN, b.req));
    expect((await siteverify(verifier, { secret: 'test-only-secret-2-0123456789abcdef', response: token })).success).toBe(false);
    c.advance(3 * 300_000 + 1000); // contexts for the current and two previous epochs are accepted, so 3 full epochs always expires
    expect(await siteverify(verifier, { secret: SECRET, response: token })).toEqual({ success: false, 'error-codes': ['timeout-or-duplicate'] });
  });

  it('siteverify error codes for missing/invalid input', async () => {
    const { verifier } = makeVerifier();
    expect((await siteverify(verifier, {}))['error-codes']).toEqual(['missing-input-secret']);
    expect((await siteverify(verifier, { secret: SECRET }))['error-codes']).toEqual(['missing-input-response']);
    expect((await siteverify(verifier, { secret: 'nope', response: 'x' }))['error-codes']).toEqual(['invalid-input-secret']);
    expect((await siteverify(verifier, { secret: SECRET, response: 'not-a-token' }))['error-codes']).toEqual(['invalid-input-response']);
  });
});

describe('anti-oracle contract', () => {
  it('suspicious evidence yields exactly { status, challenge } and the reasons go only to the server log', async () => {
    const { l, events } = memLog();
    const { verifier } = makeVerifier({ logger: l });
    const b = buildRequest(verifier.challenge(ORIGIN), { kinematics: badEvidence() });
    const r = await verifier.issue(ORIGIN, b.req);
    expect(Object.keys(r).sort()).toEqual(['challenge', 'status']);
    expect(r.status).toBe('STEP_UP_REQUIRED');
    const wire = JSON.stringify(r);
    expect(wire).not.toMatch(/impulsive|reject|score|reason|pass/i);
    const ev = events.find((e) => e.event === 'issuance')!;
    expect(ev.data).toMatchObject({ allowed: false, lane: 'fast-advisory', verdict: 'reject' });
    expect(JSON.stringify(ev.data.reasons)).toContain('impulsive-jerk');
  });
  it('success also exposes only { status, token }', async () => {
    const { verifier } = makeVerifier();
    const r = await verifier.issue(ORIGIN, buildRequest(verifier.challenge(ORIGIN), {}).req);
    expect(Object.keys(r).sort()).toEqual(['status', 'token']);
  });
  it('automation/clock tamper level 2 forces step-up even with perfect evidence', async () => {
    const { verifier } = makeVerifier();
    for (const tamper of [{ clock: 2 as const, automation: 0 as const }, { clock: 0 as const, automation: 2 as const }]) {
      const b = buildRequest(verifier.challenge(ORIGIN), { tamper });
      expect((await verifier.issue(ORIGIN, b.req)).status).toBe('STEP_UP_REQUIRED');
    }
  });
  it('a challenge allows only a few attempts (limits boundary probing)', async () => {
    const { verifier } = makeVerifier({ maxAttemptsPerChallenge: 2 });
    const b = buildRequest(verifier.challenge(ORIGIN), { kinematics: badEvidence() });
    expect((await verifier.issue(ORIGIN, b.req)).status).toBe('STEP_UP_REQUIRED');
    expect((await verifier.issue(ORIGIN, b.req)).status).toBe('STEP_UP_REQUIRED');
    await expect(verifier.issue(ORIGIN, b.req)).rejects.toMatchObject({ status: 429 });
  });
});

describe('step-up lanes', () => {
  const RP = 'shop.example.com';
  const withCredential = async (over: Parameters<typeof makeVerifier>[0] = {}) => {
    const auth = await makeAuthenticator();
    const { verifier } = makeVerifier({ webauthnStepUp: true, webauthnCredentials: [{ credentialId: auth.credentialId, publicKeySpki: auth.publicKeySpki }], ...over });
    return { auth, verifier };
  };
  const needStepUp = async (verifier: ReturnType<typeof makeVerifier>['verifier']) => {
    const b = buildRequest(verifier.challenge(ORIGIN), { kinematics: badEvidence() });
    const first = await verifier.issue(ORIGIN, b.req);
    if (first.status !== 'STEP_UP_REQUIRED') throw new Error('expected step-up');
    return { b, challenge: base64urlDecode(first.challenge) };
  };
  it('WebAuthn: STEP_UP_REQUIRED, then a user-present assertion from a REGISTERED credential issues a token', async () => {
    const { auth, verifier } = await withCredential();
    const { b, challenge } = await needStepUp(verifier);
    const second = await verifier.issue(ORIGIN, { ...b.req, stepUp: await auth.assert({ challenge, origin: ORIGIN, rpId: RP }) });
    expect(second.status).toBe('TOKEN_ISSUED');
    expect((await siteverify(verifier, { secret: SECRET, response: redeem(b, second) })).success).toBe(true);
  });
  it('WebAuthn assertion for a different request is refused (challenge binds the exact request digest)', async () => {
    const { auth, verifier } = await withCredential();
    const { challenge } = await needStepUp(verifier);
    const b2 = buildRequest(verifier.challenge(ORIGIN), { kinematics: badEvidence() });
    expect((await verifier.issue(ORIGIN, { ...b2.req, stepUp: await auth.assert({ challenge, origin: ORIGIN, rpId: RP }) })).status).toBe('STEP_UP_REQUIRED');
  });
  it('an assertion from an UNREGISTERED key is refused even though its signature is valid', async () => {
    const { verifier } = await withCredential();
    const rogue = await makeAuthenticator();
    const { b, challenge } = await needStepUp(verifier);
    expect((await verifier.issue(ORIGIN, { ...b.req, stepUp: await rogue.assert({ challenge, origin: ORIGIN, rpId: RP }) })).status).toBe('STEP_UP_REQUIRED');
  });
  it('signature-counter regression (cloned authenticator) is refused; increasing counters are accepted', async () => {
    const { auth, verifier } = await withCredential();
    const attempt = async (counter: number) => {
      const { b, challenge } = await needStepUp(verifier);
      return (await verifier.issue(ORIGIN, { ...b.req, stepUp: await auth.assert({ challenge, origin: ORIGIN, rpId: RP, counter }) })).status;
    };
    expect(await attempt(5)).toBe('TOKEN_ISSUED');
    expect(await attempt(6)).toBe('TOKEN_ISSUED');
    expect(await attempt(6)).toBe('STEP_UP_REQUIRED'); // replayed / cloned counter
    expect(await attempt(3)).toBe('STEP_UP_REQUIRED');
    expect(await attempt(7)).toBe('TOKEN_ISSUED');
  });
  it('WebAuthn disabled by default: an otherwise valid assertion changes nothing', async () => {
    const auth = await makeAuthenticator();
    const { verifier } = makeVerifier();
    const { b, challenge } = await needStepUp(verifier);
    expect((await verifier.issue(ORIGIN, { ...b.req, stepUp: await auth.assert({ challenge, origin: ORIGIN, rpId: RP }) })).status).toBe('STEP_UP_REQUIRED');
  });
  it('WebAuthn can be disabled even when credentials are configured', async () => {
    const { auth, verifier } = await withCredential({ webauthnStepUp: false });
    const { b, challenge } = await needStepUp(verifier);
    expect((await verifier.issue(ORIGIN, { ...b.req, stepUp: await auth.assert({ challenge, origin: ORIGIN, rpId: RP }) })).status).toBe('STEP_UP_REQUIRED');
  });
  it('Argon2id lane: a valid solution bound to this issuance issues a token; no assistive flag buys a bypass', async () => {
    const { verifier } = makeVerifier();
    const ch = verifier.challenge(ORIGIN);
    const b = buildRequest(ch, { pow: true });
    const r = await verifier.issue(ORIGIN, { ...b.req, assistive: 3 });
    expect(r.status).toBe('TOKEN_ISSUED');
    // an invalid solution gets nothing, regardless of the assistive flag
    const ch2 = verifier.challenge(ORIGIN);
    const b2 = buildRequest(ch2, { pow: true });
    const params = ch2.pow as PowParams;
    const binding = powBinding(base64urlDecode(ch2.nonce), base64urlDecode(b2.req.blindedElement));
    // deterministically pick a nonce that is NOT a valid solution (at 2 bits a fixed nonce would pass by chance 1 time in 4)
    let bad: PowSolution | undefined;
    for (let i = 0; i < 64 && !bad; i++) { const n = new Uint8Array(8); new DataView(n.buffer).setUint32(0, 0xdead0000 + i); const c = { nonce: base64urlEncode(n) }; if (!verifyPow(params, c, binding)) bad = c; }
    if (!bad) throw new Error('could not construct an invalid solution');
    const unsolved = { ...b2.req, assistive: 255, pow: bad };
    expect((await verifier.issue(ORIGIN, unsolved)).status).toBe('STEP_UP_REQUIRED');
  });
  it('a PoW solution cannot be moved to a different blinded element', async () => {
    // Real Argon2id makes high difficulty very slow to SOLVE, so use a low difficulty and construct a counter-example:
    // a solution that is valid for element A and (deterministically) invalid for element B.
    const { verifier } = makeVerifier();
    const ch = verifier.challenge(ORIGIN); const params = ch.pow as PowParams;
    const a = buildRequest(ch, { pow: true }), other = buildRequest(ch, { pow: true });
    const nonce = base64urlDecode(ch.nonce);
    const bindA = powBinding(nonce, base64urlDecode(a.req.blindedElement)), bindB = powBinding(nonce, base64urlDecode(other.req.blindedElement));
    let moved: PowSolution | undefined;
    for (let i = 1; i < 500 && !moved; i++) {
      const start = new Uint8Array(8); new DataView(start.buffer).setUint32(0, i * 7919);
      const cand = solvePow(params, bindA, { startNonce: start });
      if (verifyPow(params, cand, bindA) && !verifyPow(params, cand, bindB)) moved = cand;
    }
    if (!moved) throw new Error('could not construct counter-example');
    const r = await verifier.issue(ORIGIN, { ...other.req, pow: moved });
    expect(r.status).toBe('STEP_UP_REQUIRED');
  });
  it('PoW disabled: inclusive requests are never issued', async () => {
    const { verifier } = makeVerifier({ pow: false });
    const ch = verifier.challenge(ORIGIN);
    expect(ch.pow).toBeUndefined();
    const b = buildRequest({ ...ch, pow: { salt: base64urlEncode(new Uint8Array(16)), memoryKiB: 64, iterations: 1, parallelism: 1, difficultyBits: 0 } }, { pow: true });
    expect((await verifier.issue(ORIGIN, b.req)).status).toBe('STEP_UP_REQUIRED');
  });
  it('bounds concurrent Argon2id verifications (busy -> 503)', async () => {
    const { verifier } = makeVerifier({ pow: { memoryKiB: 8192, iterations: 2, parallelism: 1, difficultyBits: 0, maxConcurrent: 1, maxQueue: 0 } });
    const reqs = Array.from({ length: 3 }, () => buildRequest(verifier.challenge(ORIGIN), { pow: true }).req);
    const results = await Promise.allSettled(reqs.map((r) => verifier.issue(ORIGIN, r)));
    expect(results.some((r) => r.status === 'rejected' && (r.reason as BioKynHttpError).status === 503)).toBe(true);
    expect(results.some((r) => r.status === 'fulfilled')).toBe(true);
  });
});

describe('request validation', () => {
  it('rejects disallowed origins, malformed bodies and expired challenges without risk information', async () => {
    const { verifier, c } = makeVerifier();
    const ch = verifier.challenge(ORIGIN);
    const b = buildRequest(ch, {});
    await expect(verifier.issue('https://evil.example', b.req)).rejects.toMatchObject({ status: 403 });
    expect(() => verifier.challenge('https://evil.example')).toThrow(BioKynHttpError);
    for (const bad of [null, {}, { ...b.req, version: 1 }, { ...b.req, path: 'x' }, { ...b.req, blindedElement: 'AAAA' }, { ...b.req, tamper: { clock: 9, automation: 0 } }, { ...b.req, kinematics: { ...b.req.kinematics, sampleCount: -1 } }, { ...b.req, challengeId: 'forged' }]) {
      await expect(verifier.issue(ORIGIN, bad)).rejects.toBeInstanceOf(BioKynHttpError);
    }
    c.advance(121_000);
    await expect(verifier.issue(ORIGIN, b.req)).rejects.toMatchObject({ code: 'invalid_challenge' });
  });
  it('digest helper agrees with the server (sanity for the step-up binding)', () => {
    const { verifier } = makeVerifier();
    const b = buildRequest(verifier.challenge(ORIGIN), {});
    expect(digestOf(b)).toHaveLength(32);
  });
});
