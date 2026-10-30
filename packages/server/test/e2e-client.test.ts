/** End-to-end: the real browser client code talking to the real server handler (fetch is routed in-process). */
import { afterEach, describe, expect, it } from 'vitest';
import { VoprfServer, base64urlDecode, base64urlEncode, encodeIssuance, generateKeyPair, tokenKeyId } from '@biokyn/protocol';
import { createHandler, siteverify } from '../src/index.js';
import { registerWebAuthnCredential, requestInclusiveToken } from '../../client/src/index.js';
import { getWebAuthnAssertion } from '../../client/src/webauthn.js';
import { makeAuthenticator } from './authenticator.js';
import { ORIGIN, SECRET, buildRequest, makeVerifier } from './helpers.js';

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
const route = (verifier: ReturnType<typeof makeVerifier>['verifier'], tamper?: (path: string, body: any, requestBody?: any) => any): void => {
  const handle = createHandler(verifier);
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = new URL(String(input), ORIGIN);
    const res = await handle({ method: init?.method ?? 'GET', path: url.pathname, headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: init?.body as string | undefined, ip: '198.51.100.4' });
    let body = res!.body; if (tamper) body = JSON.stringify(tamper(url.pathname, JSON.parse(body), init?.body ? JSON.parse(String(init.body)) : undefined));
    return new Response(body, { status: res!.status, headers: res!.headers as Record<string, string> });
  }) as typeof fetch;
};

describe('client <-> server', () => {
  it('requestInclusiveToken obtains a token that redeems exactly once', async () => {
    const { verifier } = makeVerifier(); route(verifier);
    const { token } = await requestInclusiveToken({ expectedPublicKey: base64urlDecode(verifier.challenge(ORIGIN).publicKey) });
    expect((await siteverify(verifier, { secret: SECRET, response: token })).success).toBe(true);
    expect((await siteverify(verifier, { secret: SECRET, response: token })).success).toBe(false);
  });
  it('rejects a wrong pinned key and an inconsistent advertised key id before doing any work', async () => {
    const { verifier } = makeVerifier(); route(verifier);
    await expect(requestInclusiveToken({ expectedPublicKey: generateKeyPair().publicKey })).rejects.toThrow(/pin mismatch/);
    route(verifier, (p, b) => (p.endsWith('/challenge') ? { ...b, keyId: base64urlEncode(new Uint8Array(32)) } : b));
    await expect(requestInclusiveToken()).rejects.toThrow(/key id/);
  });
  it('refuses a well-formed issuance signed under a different key (per-user key tagging) and a malformed one', async () => {
    const { verifier } = makeVerifier();
    const rogue = new VoprfServer(generateKeyPair().secretKey);
    route(verifier, (p, b, req) => (p.endsWith('/issue') && b.status === 'TOKEN_ISSUED' ? { ...b, token: encodeIssuance(rogue.blindEvaluate(base64urlDecode(req.blindedElement))) } : b));
    await expect(requestInclusiveToken()).rejects.toThrow(/proof/);
    route(verifier, (p, b) => (p.endsWith('/issue') && b.status === 'TOKEN_ISSUED' ? { ...b, token: 'AAAA' } : b));
    await expect(requestInclusiveToken()).rejects.toThrow();
  });
  it('full anonymous WebAuthn registration through the client helper, then a step-up assertion', async () => {
    const { verifier } = makeVerifier({ webauthnStepUp: true, webauthnRegistration: { enabled: true } }); route(verifier);
    const auth = await makeAuthenticator(); let createdWith: any;
    const credentials = {
      create: async (o: any) => {
        createdWith = o.publicKey;
        const att = auth.attest({ challenge: new Uint8Array(o.publicKey.challenge), origin: ORIGIN, rpId: o.publicKey.rp.id });
        const u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url')).buffer;
        return { rawId: u(att.id), response: { attestationObject: u(att.attestationObject), clientDataJSON: u(att.clientDataJSON) } };
      },
      get: async (o: any) => {
        const a = await auth.assert({ challenge: new Uint8Array(o.publicKey.challenge), origin: ORIGIN, rpId: 'shop.example.com', counter: 3 });
        const u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url')).buffer;
        return { rawId: u(a.credentialId), response: { authenticatorData: u(a.authenticatorData), clientDataJSON: u(a.clientDataJSON), signature: u(a.signature) } };
      },
    } as unknown as CredentialsContainer;
    const reg = await registerWebAuthnCredential({ credentials });
    expect(reg.credentialId).toBe(auth.credentialId);
    expect(createdWith.attestation).toBe('none');
    // The step-up flow with the registered credential.
    const b = buildRequest(verifier.challenge(ORIGIN), { kinematics: { ...(await import('./helpers.js')).badEvidence() } });
    const first = await verifier.issue(ORIGIN, b.req);
    if (first.status !== 'STEP_UP_REQUIRED') throw new Error('expected step-up');
    const stepUp = await getWebAuthnAssertion(first.challenge, reg.credentialId, { credentials });
    expect((await verifier.issue(ORIGIN, { ...b.req, stepUp })).status).toBe('TOKEN_ISSUED');
  });
  it('tokenKeyId agrees between client and server', () => {
    const { verifier } = makeVerifier(); const ch = verifier.challenge(ORIGIN);
    expect(ch.keyId).toBe(base64urlEncode(tokenKeyId(base64urlDecode(ch.publicKey))));
  });
});
