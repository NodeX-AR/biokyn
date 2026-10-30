import { describe, expect, it } from 'vitest';
import { base64urlDecode, base64urlEncode, powBinding, solvePow, utf8, verifyPow, type PowParams, type PowSolution } from '@biokyn/protocol';
import { MemoryWebAuthnCredentialStore, StoreCapacityError, verifyRegistration } from '../src/index.js';
import { makeAuthenticator, type AttestOpts } from './authenticator.js';
import { ORIGIN, badEvidence, buildRequest, clock, makeVerifier } from './helpers.js';

const RP = 'shop.example.com';
const setup = (over: Parameters<typeof makeVerifier>[0] = {}, c = clock()) => {
  const store = new MemoryWebAuthnCredentialStore(c.now);
  const { verifier } = makeVerifier({ webauthnStepUp: true, webauthnRegistration: { enabled: true, credentialTtlSec: 3600 }, webauthnCredentialStore: store, ...over }, c);
  return { verifier, store, c };
};
/** Runs step 1 and returns what a browser would hand to navigator.credentials.create(). */
const options = async (verifier: ReturnType<typeof makeVerifier>['verifier']) => {
  const ch = verifier.challenge(ORIGIN);
  const pow = solvePow(ch.pow as PowParams, powBinding(base64urlDecode(ch.nonce), utf8('biokyn-webauthn-register')));
  const opts = await verifier.webauthnRegistrationOptions(ORIGIN, { challengeId: ch.challengeId, pow });
  return { ch, opts, challenge: base64urlDecode(opts.challenge as string) };
};
const attestWith = async (o: Partial<AttestOpts> = {}) => {
  const s = setup(); const { ch, challenge } = await options(s.verifier); const auth = await makeAuthenticator();
  const credential = auth.attest({ challenge, origin: ORIGIN, rpId: RP, ...o });
  return { ...s, ch, auth, credential, run: () => s.verifier.webauthnRegister(ORIGIN, { challengeId: ch.challengeId, credential }) };
};

describe('anonymous WebAuthn registration ceremony', () => {
  it('registers a credential, then that credential can authorize a step-up', async () => {
    const { verifier, store, ch, auth, credential } = await attestWith();
    const out = await verifier.webauthnRegister(ORIGIN, { challengeId: ch.challengeId, credential });
    expect(out.status).toBe('REGISTERED');
    expect(out.credentialId).toBe(auth.credentialId);
    expect((await store.get(auth.credentialId))?.publicKeySpki).toBe(auth.publicKeySpki);

    const b = buildRequest(verifier.challenge(ORIGIN), { kinematics: badEvidence() });
    const first = await verifier.issue(ORIGIN, b.req);
    if (first.status !== 'STEP_UP_REQUIRED') throw new Error('expected step-up');
    const second = await verifier.issue(ORIGIN, { ...b.req, stepUp: await auth.assert({ challenge: base64urlDecode(first.challenge), origin: ORIGIN, rpId: RP, counter: 1 }) });
    expect(second.status).toBe('TOKEN_ISSUED');
  });
  it('creation options are well-formed, ES256-only, attestation "none", bound to this origin', async () => {
    const { opts } = await options(setup().verifier);
    expect(opts).toMatchObject({ rp: { id: RP }, attestation: 'none', pubKeyCredParams: [{ type: 'public-key', alg: -7 }] });
    expect(base64urlDecode(opts.challenge as string)).toHaveLength(32);
    expect(base64urlDecode((opts.user as { id: string }).id)).toHaveLength(16);
  });
  it('requires proof-of-work for options, enforces one success per challenge, and counts attempts', async () => {
    const { verifier } = setup({ pow: { memoryKiB: 8192, iterations: 1, parallelism: 1, difficultyBits: 20 } }); // 2^-20 chance a zero nonce passes
    const ch = verifier.challenge(ORIGIN);
    await expect(verifier.webauthnRegistrationOptions(ORIGIN, { challengeId: ch.challengeId, pow: { nonce: base64urlEncode(new Uint8Array(8)) } })).rejects.toMatchObject({ status: 400 });
    const s = await attestWith();
    expect((await s.run()).status).toBe('REGISTERED');
    await expect(s.run()).rejects.toMatchObject({ status: 400 }); // same challenge cannot register twice
  });
  it('one challenge can register at most one credential, even a DIFFERENT credential (replay guard, not just duplicate-id)', async () => {
    const s = await attestWith();
    expect((await s.run()).status).toBe('REGISTERED');
    const second = await makeAuthenticator();
    const { challenge } = { challenge: (s.verifier as any).authority.registrationChallenge(base64urlDecode(s.ch.nonce)) as Uint8Array };
    const other = second.attest({ challenge, origin: ORIGIN, rpId: RP });
    await expect(s.verifier.webauthnRegister(ORIGIN, { challengeId: s.ch.challengeId, credential: other })).rejects.toMatchObject({ status: 400 });
    expect(await s.store.get(second.credentialId)).toBeUndefined();
  });
  it('registration attempts per challenge are bounded (429 after the budget, even for a valid ceremony)', async () => {
    const s = await attestWith(); const bad = { ...s.credential, attestationObject: 'AAAA' };
    for (let i = 0; i < 4; i++) await expect(s.verifier.webauthnRegister(ORIGIN, { challengeId: s.ch.challengeId, credential: bad })).rejects.toMatchObject({ status: 400 });
    await expect(s.run()).rejects.toMatchObject({ status: 429 });
  });
  it('a PoW solved for another binding (e.g. issuance) cannot be reused to register', async () => {
    const { verifier } = setup();
    const ch = verifier.challenge(ORIGIN); const params = ch.pow as PowParams;
    const issuanceBinding = powBinding(base64urlDecode(ch.nonce), new Uint8Array(32)), registerBinding = powBinding(base64urlDecode(ch.nonce), utf8('biokyn-webauthn-register'));
    // Deterministically construct a solution that is valid for the issuance binding but INVALID for registration
    // (a mismatched binding would otherwise still verify by chance at the tiny test difficulty).
    let pow: PowSolution | undefined;
    for (let i = 1; i < 500 && !pow; i++) {
      const start = new Uint8Array(8); new DataView(start.buffer).setUint32(0, i * 7919);
      const cand = solvePow(params, issuanceBinding, { startNonce: start });
      if (verifyPow(params, cand, issuanceBinding) && !verifyPow(params, cand, registerBinding)) pow = cand;
    }
    if (!pow) throw new Error('could not construct counter-example');
    await expect(verifier.webauthnRegistrationOptions(ORIGIN, { challengeId: ch.challengeId, pow })).rejects.toMatchObject({ status: 400 });
  });
  it('is unavailable unless enabled, and cannot be enabled without step-up or PoW', async () => {
    const { verifier } = makeVerifier();
    await expect(verifier.webauthnRegistrationOptions(ORIGIN, { challengeId: 'x', pow: { nonce: 'AAAA' } })).rejects.toMatchObject({ status: 404 });
    expect(() => makeVerifier({ webauthnRegistration: { enabled: true } })).toThrow(/webauthnStepUp/);
    expect(() => makeVerifier({ webauthnStepUp: true, webauthnRegistration: { enabled: true }, pow: false })).toThrow(/PoW/);
  });

  const bad: Array<[string, Partial<AttestOpts>]> = [
    ['wrong challenge', { challenge: new Uint8Array(32) }],
    ['wrong origin', { origin: 'https://evil.example' }],
    ['wrong rpId hash', { rpId: 'evil.example' }],
    ['wrong ceremony type', { type: 'webauthn.get' }],
    ['non-"none" attestation format', { fmt: 'packed' }],
    ['non-empty attestation statement', { attStmt: new Map([['alg', -7]]) }],
    ['missing user presence', { flags: 0x40 }],
    ['missing attested credential data', { flags: 0x01 }],
    ['extension data flag', { flags: 0xc1 }],
    ['trailing bytes after the COSE key', { trailing: new Uint8Array([0]) }],
    ['credential id too short', { idLen: 8 }],
    ['public key not on the P-256 curve', { badKey: true }],
  ];
  it.each(bad)('rejects %s', async (_name: string, o: Partial<AttestOpts>) => {
    const s = await attestWith(o);
    await expect(s.run()).rejects.toMatchObject({ status: 400 });
    expect(await s.store.get(s.auth.credentialId)).toBeUndefined();
  });
  it.each([
    ['wrong challenge', { challenge: new Uint8Array(32) }, 'challenge-mismatch'],
    ['wrong origin', { origin: 'https://evil.example' }, 'origin-mismatch'],
    ['wrong rpId hash', { rpId: 'evil.example' }, 'rpid-mismatch'],
    ['wrong ceremony type', { type: 'webauthn.get' }, 'wrong-type'],
    ['non-"none" attestation format', { fmt: 'packed' }, 'unsupported-attestation-format'],
    ['non-empty attestation statement', { attStmt: new Map([['alg', -7]]) }, 'unexpected-attestation-statement'],
    ['missing user presence', { flags: 0x40 }, 'user-presence-missing'],
    ['missing attested credential data', { flags: 0x01 }, 'no-attested-credential-data'],
    ['extension data flag', { flags: 0xc1 }, 'extensions-not-supported'],
    ['trailing bytes after the COSE key', { trailing: new Uint8Array([0]) }, 'trailing-authdata'],
    ['credential id too short', { idLen: 8 }, 'bad-credential-id-length'],
    ['public key not on the P-256 curve', { badKey: true }, 'malformed'],
  ])('reports the precise reason for %s', async (_n: string, o: Partial<AttestOpts>, reason: string) => {
    const auth = await makeAuthenticator(); const challenge = new Uint8Array(32).fill(9);
    const res = await verifyRegistration(auth.attest({ challenge, origin: ORIGIN, rpId: RP, ...o }), { origin: ORIGIN, rpId: RP, expectedChallenge: challenge });
    expect(res).toEqual({ ok: false, reason });
  });
  it('rejects a mismatched credential.id and garbage attestation objects', async () => {
    const s = await attestWith();
    await expect(s.verifier.webauthnRegister(ORIGIN, { challengeId: s.ch.challengeId, credential: { ...s.credential, id: base64urlEncode(new Uint8Array(32)) } })).rejects.toMatchObject({ status: 400 });
    const t = await attestWith();
    await expect(t.verifier.webauthnRegister(ORIGIN, { challengeId: t.ch.challengeId, credential: { ...t.credential, attestationObject: 'AAAA' } })).rejects.toMatchObject({ status: 400 });
  });
  it('user verification can be required', async () => {
    const s = setup({ webauthnRegistration: { enabled: true, requireUserVerification: true } });
    const { ch, challenge } = await options(s.verifier); const auth = await makeAuthenticator();
    await expect(s.verifier.webauthnRegister(ORIGIN, { challengeId: ch.challengeId, credential: auth.attest({ challenge, origin: ORIGIN, rpId: RP, flags: 0x41 }) })).rejects.toMatchObject({ status: 400 });
    const t = setup({ webauthnRegistration: { enabled: true, requireUserVerification: true } });
    const o2 = await options(t.verifier);
    expect((await t.verifier.webauthnRegister(ORIGIN, { challengeId: o2.ch.challengeId, credential: auth.attest({ challenge: o2.challenge, origin: ORIGIN, rpId: RP, flags: 0x45 }) })).status).toBe('REGISTERED');
  });
  it('registered credentials expire and can be revoked', async () => {
    const s = await attestWith();
    const { credentialId } = await s.run();
    expect(await s.store.get(credentialId)).toBeDefined();
    expect(await s.verifier.revokeWebAuthnCredential(credentialId)).toBe(true);
    expect(await s.store.get(credentialId)).toBeUndefined();
    const e = await attestWith();
    const reg = await e.run();
    e.c.advance(3601_000);
    expect(await e.store.get(reg.credentialId)).toBeUndefined();
  });
  it('a full credential store fails closed with 503, not silently', async () => {
    const c = clock(); const store = new MemoryWebAuthnCredentialStore(c.now, 1);
    const { verifier } = makeVerifier({ webauthnStepUp: true, webauthnRegistration: { enabled: true }, webauthnCredentialStore: store }, c);
    for (const [i, expected] of [[0, 'REGISTERED'], [1, 503]] as const) {
      const { ch, challenge } = await options(verifier); const auth = await makeAuthenticator();
      const call = verifier.webauthnRegister(ORIGIN, { challengeId: ch.challengeId, credential: auth.attest({ challenge, origin: ORIGIN, rpId: RP }) });
      if (i === 0) expect((await call).status).toBe(expected); else await expect(call).rejects.toMatchObject({ status: expected });
    }
    expect(() => new MemoryWebAuthnCredentialStore(Date.now, 0)).toThrow(RangeError);
    expect(StoreCapacityError).toBeDefined();
  });
  it('verifyRegistration is usable on its own and reports precise reasons', async () => {
    const auth = await makeAuthenticator(); const challenge = new Uint8Array(32).fill(7);
    const ok = await verifyRegistration(auth.attest({ challenge, origin: ORIGIN, rpId: RP }), { origin: ORIGIN, rpId: RP, expectedChallenge: challenge });
    expect(ok).toMatchObject({ ok: true, credentialId: auth.credentialId });
    expect(await verifyRegistration(auth.attest({ challenge, origin: ORIGIN, rpId: RP, fmt: 'tpm' }), { origin: ORIGIN, rpId: RP, expectedChallenge: challenge })).toEqual({ ok: false, reason: 'unsupported-attestation-format' });
  });
});
