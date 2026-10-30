import { describe, expect, it } from 'vitest';
import {
  ProtocolError, TOKEN_LENGTH, VoprfServer, base64urlEncode, beginIssuance, challengeDigest, completeIssuance, decodeIssuance, decodeToken, encodeIssuance, encodeToken,
  generateKeyPair, parseToken, serializeToken, tokenKeyId, tokenNullifier, toHex, verifyToken, randomBytes, type ChallengeResponse,
} from '../src/index.js';

const ctxFor = (origin = 'https://shop.example.com', ctx = randomBytes(32)) => ({ issuer: 'verify.example.com', origin, redemptionContext: base64urlEncode(ctx) }) as Pick<ChallengeResponse, 'issuer' | 'origin' | 'redemptionContext'>;
const setup = () => { const kp = generateKeyPair(); return { kp, server: new VoprfServer(kp.secretKey), ctx: ctxFor() }; };
const issue = (s: ReturnType<typeof setup>) => {
  const pending = beginIssuance(s.ctx, s.kp.publicKey);
  const evaluation = decodeIssuance(encodeIssuance(s.server.blindEvaluate(pending.blindedElement)));
  return { pending, token: completeIssuance(pending, evaluation, s.kp.publicKey) };
};

describe('token v2', () => {
  it('issues, serializes (162 bytes) and verifies', () => {
    const s = setup(); const { token } = issue(s);
    const raw = serializeToken(token);
    expect(raw).toHaveLength(TOKEN_LENGTH);
    const parsed = decodeToken(encodeToken(token));
    expect(verifyToken(s.server, parsed, challengeDigest(s.ctx))).toEqual({ ok: true });
  });
  it('rejects wrong digest, wrong key, tampered authenticator / nonce / key id, wrong type and length', () => {
    const s = setup(); const { token } = issue(s); const d = challengeDigest(s.ctx);
    expect(verifyToken(s.server, token, challengeDigest(ctxFor())).ok).toBe(false);
    expect(verifyToken(new VoprfServer(generateKeyPair().secretKey), token, d).ok).toBe(false);
    for (const field of ['authenticator', 'nonce', 'keyId', 'challengeDigest'] as const) {
      const t = { ...token, [field]: token[field].slice() }; t[field][0] ^= 1;
      expect(verifyToken(s.server, t, d).ok).toBe(false);
    }
    const raw = serializeToken(token).slice(); raw[0] ^= 1;
    expect(() => parseToken(raw)).toThrow(ProtocolError);
    expect(() => parseToken(raw.slice(1))).toThrow(ProtocolError);
  });
  it('client refuses an issuance signed under a different key or with a forged proof', () => {
    const s = setup(); const pending = beginIssuance(s.ctx, s.kp.publicKey);
    const rogue = new VoprfServer(generateKeyPair().secretKey);
    expect(() => completeIssuance(pending, rogue.blindEvaluate(pending.blindedElement), s.kp.publicKey)).toThrow(/proof/);
    expect(() => completeIssuance(pending, s.server.blindEvaluate(pending.blindedElement), generateKeyPair().publicKey)).toThrow(/public key/);
  });
  it('is unlinkable at the protocol level: the issuer-visible blinded element differs across clients and from anything in the token', () => {
    const s = setup(); const a = issue(s), b = issue(s);
    expect(toHex(a.pending.blindedElement)).not.toBe(toHex(b.pending.blindedElement));
    const tokenHex = toHex(serializeToken(a.token));
    expect(tokenHex.includes(toHex(a.pending.blindedElement))).toBe(false);
    expect(tokenHex.includes(toHex(a.pending.blind))).toBe(false);
    // the issuance response (what the issuer sees leave) shares no bytes-substring with the redeemed token
    const resp = encodeIssuance(s.server.blindEvaluate(a.pending.blindedElement));
    expect(tokenHex.includes(toHex(decodeIssuance(resp).evaluatedElement))).toBe(false);
  });
  it('key id and nullifier are stable, distinct per token, and bound to the key', () => {
    const s = setup(); const a = issue(s), b = issue(s);
    expect(toHex(tokenKeyId(s.kp.publicKey))).toBe(toHex(a.token.keyId));
    expect(toHex(tokenNullifier(a.token))).toBe(toHex(tokenNullifier(a.token)));
    expect(toHex(tokenNullifier(a.token))).not.toBe(toHex(tokenNullifier(b.token)));
  });
  it('rejects malformed server keys and identity-element requests', () => {
    expect(() => beginIssuance(ctxFor(), new Uint8Array(32))).toThrow(ProtocolError);
    expect(() => beginIssuance(ctxFor(), new Uint8Array(31))).toThrow(ProtocolError);
    expect(() => decodeIssuance('AAAA')).toThrow(ProtocolError);
  });
});
