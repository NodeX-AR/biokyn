import { describe, expect, it } from 'vitest';
import { base64urlEncode, randomBytes } from '@biokyn/protocol';
import { makeAuthenticator } from './authenticator.js';
import { ChallengeAuthority, SlidingNullifierCache, StoreCapacityError, SlidingWindowRateLimiter, derToP1363, verifyAssertion } from '../src/index.js';
import { clock } from './helpers.js';

describe('SlidingNullifierCache', () => {
  it('accepts a key once and rejects replays', () => {
    const c = new SlidingNullifierCache({ ttlMs: 1000 });
    expect(c.checkAndInsert('a')).toBe(true);
    expect(c.checkAndInsert('a')).toBe(false);
    expect(c.checkAndInsert('b')).toBe(true);
    expect(c.size).toBe(2);
  });
  it('retains entries for at least the TTL and forgets them afterwards', () => {
    const k = clock(0);
    const c = new SlidingNullifierCache({ ttlMs: 10_000, buckets: 5, now: k.now });
    expect(c.checkAndInsert('x')).toBe(true);
    k.advance(9_999);
    expect(c.checkAndInsert('x')).toBe(false); // still inside TTL: never forgotten early
    k.advance(c.retentionMs + 5_000);
    expect(c.checkAndInsert('x')).toBe(true); // forgotten, and memory released
    expect(c.size).toBe(1);
  });
  it('fails closed at capacity by default, and can evict the oldest bucket when configured', () => {
    const k = clock(0);
    const closed = new SlidingNullifierCache({ ttlMs: 1000, maxEntries: 3, now: k.now });
    for (const key of ['1', '2', '3']) expect(closed.checkAndInsert(key)).toBe(true);
    expect(() => closed.checkAndInsert('4')).toThrow(StoreCapacityError); // 503 upstream; never reported as a replay
    expect(closed.rejectedFull).toBe(1);
    expect(closed.checkAndInsert('1')).toBe(false); // existing entries are still remembered
    const open = new SlidingNullifierCache({ ttlMs: 1000, maxEntries: 3, onFull: 'evict-oldest', now: k.now });
    for (const key of ['1', '2', '3']) open.checkAndInsert(key);
    k.advance(400);
    expect(open.checkAndInsert('4')).toBe(true);
  });
  it('sustains high throughput', () => {
    const c = new SlidingNullifierCache({ ttlMs: 60_000, maxEntries: 2_000_000 });
    const t0 = performance.now();
    for (let i = 0; i < 200_000; i++) c.checkAndInsert(`k${i}`);
    const ms = performance.now() - t0;
    expect(c.size).toBe(200_000);
    console.log(`nullifier: 200k inserts in ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(5000);
  });
});

describe('SlidingWindowRateLimiter', () => {
  it('limits per key within the window and recovers', () => {
    const k = clock(0);
    const r = new SlidingWindowRateLimiter(2, 1000, k.now);
    expect([r.allow('a'), r.allow('a'), r.allow('a'), r.allow('b')]).toEqual([true, true, false, true]);
    k.advance(1001);
    expect(r.allow('a')).toBe(true);
  });
});

describe('ChallengeAuthority', () => {
  const secret = randomBytes(32);
  const mk = (k = clock()) => ({ k, a: new ChallengeAuthority(secret, 120_000, 300_000, k.now) });
  it('opens what it created and derives stable values', () => {
    const { a } = mk();
    const c = a.create('https://a.example', 5);
    const o = a.open(c.id, 'https://a.example')!;
    expect(o.difficultyBits).toBe(5);
    expect(Buffer.from(o.nonce).equals(Buffer.from(c.nonce))).toBe(true);
  });
  it('rejects forged, wrong-origin, truncated and expired ids', () => {
    const { a, k } = mk();
    const c = a.create('https://a.example', 0);
    expect(a.open(c.id, 'https://b.example')).toBeNull();
    expect(a.open(c.id.slice(0, -2), 'https://a.example')).toBeNull();
    const raw = Buffer.from(c.id, 'base64url'); raw[12]! ^= 1;
    expect(a.open(raw.toString('base64url'), 'https://a.example')).toBeNull();
    expect(new ChallengeAuthority(randomBytes(32), 120_000, 300_000, k.now).open(c.id, 'https://a.example')).toBeNull();
    k.advance(120_001);
    expect(a.open(c.id, 'https://a.example')).toBeNull();
  });
  it('redemption contexts rotate per epoch and retain two prior epochs for boundary-crossing token lifetime', () => {
    const { a, k } = mk(clock(300_000 * 100 + 1000));
    const first = a.currentRedemptionContext('https://a.example');
    k.advance(300_000);
    expect(a.currentRedemptionContext('https://a.example')).not.toEqual(first);
    expect(a.acceptedRedemptionContexts('https://a.example').some((x) => Buffer.from(x.context).equals(Buffer.from(first)))).toBe(true);
    k.advance(300_000);
    expect(a.acceptedRedemptionContexts('https://a.example').some((x) => Buffer.from(x.context).equals(Buffer.from(first)))).toBe(true);
    k.advance(300_000);
    expect(a.acceptedRedemptionContexts('https://a.example').some((x) => Buffer.from(x.context).equals(Buffer.from(first)))).toBe(false);
  });
  it('rejects short secrets', () => { expect(() => new ChallengeAuthority(randomBytes(16), 1, 1, Date.now)).toThrow(); });
});

// ---------------------------------------------------------------- WebAuthn

export async function fakeAssertion(opts: { challenge: Uint8Array; origin: string; rpId: string; flags?: number; type?: string; counter?: number }) {
  const auth = await makeAuthenticator();
  return { ...(await auth.assert(opts)), publicKeySpki: auth.publicKeySpki };
}

describe('WebAuthn step-up verification', () => {
  const baseCheck = { origin: 'https://shop.example.com', rpId: 'shop.example.com', expectedChallenge: randomBytes(32) };
  const mk = (o: Partial<Parameters<typeof fakeAssertion>[0]> = {}) => fakeAssertion({ challenge: baseCheck.expectedChallenge, origin: baseCheck.origin, rpId: baseCheck.rpId, ...o });
  const trustedCheck = (a: Awaited<ReturnType<typeof mk>>, over: Partial<typeof baseCheck> = {}) => ({ ...baseCheck, ...over, credentialId: a.credentialId, publicKeySpki: a.publicKeySpki });

  it('accepts a correct user-present assertion using a server-pinned key', async () => {
    const a = await mk();
    expect(await verifyAssertion(a, trustedCheck(a))).toMatchObject({ ok: true, signCount: 0, userVerified: false });
  });
  it.each([
    ['challenge', { challenge: randomBytes(32) }, 'challenge-mismatch'],
    ['origin', { origin: 'https://evil.example' }, 'origin-mismatch'],
    ['rpId', { rpId: 'evil.example' }, 'rpid-mismatch'],
    ['user presence', { flags: 0x00 }, 'user-presence-missing'],
    ['type', { type: 'webauthn.create' }, 'wrong-type'],
  ])('rejects wrong %s', async (_n: string, o: Partial<Parameters<typeof fakeAssertion>[0]>, reason: string) => {
    const a = await mk(o);
    expect(await verifyAssertion(a, trustedCheck(a))).toEqual({ ok: false, reason });
  });
  it('ignores a request-supplied public key when a trusted registered key is configured', async () => {
    const a = await mk();
    const fake = await mk();
    expect(await verifyAssertion({ ...a, publicKeySpki: fake.publicKeySpki }, trustedCheck(a))).toMatchObject({ ok: true });
  });
  it('rejects an unregistered credential even when the request supplies its own key', async () => {
    const a = await mk();
    expect(await verifyAssertion(a, { ...trustedCheck(a), credentialId: base64urlEncode(randomBytes(16)) })).toEqual({ ok: false, reason: 'credential-mismatch' });
  });
  it('rejects a tampered signature and garbage input', async () => {
    const a = await mk();
    const sig = Buffer.from(a.signature, 'base64url'); sig[sig.length - 1]! ^= 1;
    expect((await verifyAssertion({ ...a, signature: sig.toString('base64url') }, trustedCheck(a))).ok).toBe(false);
    expect((await verifyAssertion({ ...a, clientDataJSON: 'AAAA' }, trustedCheck(a))).ok).toBe(false);
    expect(derToP1363(new Uint8Array([1, 2, 3]))).toBeNull();
  });
});
