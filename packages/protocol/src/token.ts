/**
 * BioKyn token, laid out like the Privacy Pass token of RFC 9577 §2.2:
 *
 *   struct { uint16 token_type; uint8 nonce[32]; uint8 challenge_digest[32];
 *            uint8 token_key_id[32]; uint8 authenticator[64]; } Token;
 *
 * The authenticator is the VOPRF(ristretto255-SHA512) output over TokenInput
 * (type || nonce || challenge_digest || token_key_id). Note: Privacy Pass is specified in
 * RFC 9576 (architecture), 9577 (HTTP auth scheme) and 9578 (issuance protocols); RFC 9578
 * registers P-384 VOPRF and RSA blind-signature types only, so the ristretto255 type below is
 * an EXPERIMENTAL / private-use codepoint, not an IANA-registered one.
 */
import { sha256 } from '@noble/hashes/sha256';
import {
  ProtocolError, base64urlDecode, base64urlEncode, concat, ctEqual, i2osp, lp2, randomBytes, utf8,
} from './bytes.js';
import { blind, finalize, type Evaluation, type VoprfServer } from './voprf.js';

export const TOKEN_TYPE_BioKyn_R255 = 0xfe01;
const NONCE_LEN = 32;
const DIGEST_LEN = 32;
const KEY_ID_LEN = 32;
const AUTH_LEN = 64;
export const TOKEN_INPUT_LEN = 2 + NONCE_LEN + DIGEST_LEN + KEY_ID_LEN;
export const TOKEN_LEN = TOKEN_INPUT_LEN + AUTH_LEN;

export interface TokenChallenge {
  /** Issuer identifier (hostname of the verifier). */
  issuer: string;
  /** Origin the token will be redeemed at; binds the token to a site. Empty = any. */
  origin: string;
  /** Server-chosen random context for this challenge (replay-bounded freshness). */
  redemptionContext: Uint8Array; // 0 or 32 bytes
}

export interface Token {
  tokenType: number;
  nonce: Uint8Array;
  challengeDigest: Uint8Array;
  tokenKeyId: Uint8Array;
  authenticator: Uint8Array;
}

export function encodeChallenge(c: TokenChallenge): Uint8Array {
  if (c.redemptionContext.length !== 0 && c.redemptionContext.length !== 32) {
    throw new ProtocolError('BAD_CONTEXT', 'redemptionContext must be 0 or 32 bytes');
  }
  return concat(i2osp(TOKEN_TYPE_BioKyn_R255, 2), lp2(utf8(c.issuer)), lp2(c.redemptionContext), lp2(utf8(c.origin)));
}

export const challengeDigest = (c: TokenChallenge): Uint8Array => sha256(encodeChallenge(c));
export const tokenKeyId = (serverPublicKey: Uint8Array): Uint8Array => sha256(serverPublicKey);

export function tokenInput(nonce: Uint8Array, digest: Uint8Array, keyId: Uint8Array): Uint8Array {
  if (nonce.length !== NONCE_LEN || digest.length !== DIGEST_LEN || keyId.length !== KEY_ID_LEN) {
    throw new ProtocolError('BAD_TOKEN_INPUT', 'field length mismatch');
  }
  return concat(i2osp(TOKEN_TYPE_BioKyn_R255, 2), nonce, digest, keyId);
}

export function serializeToken(t: Token): Uint8Array {
  if (t.authenticator.length !== AUTH_LEN) throw new ProtocolError('BAD_TOKEN', 'authenticator length');
  return concat(tokenInput(t.nonce, t.challengeDigest, t.tokenKeyId), t.authenticator);
}

export function parseToken(b: Uint8Array): Token {
  if (b.length !== TOKEN_LEN) throw new ProtocolError('BAD_TOKEN', 'wrong token length');
  const type = (b[0]! << 8) | b[1]!;
  if (type !== TOKEN_TYPE_BioKyn_R255) throw new ProtocolError('BAD_TOKEN', 'unknown token type');
  let o = 2;
  const take = (n: number) => { const s = b.slice(o, o + n); o += n; return s; };
  return { tokenType: type, nonce: take(NONCE_LEN), challengeDigest: take(DIGEST_LEN), tokenKeyId: take(KEY_ID_LEN), authenticator: take(AUTH_LEN) };
}

/** `Authorization: PrivateToken token=<base64url>` (RFC 9577 §2.2 shape). */
export const toAuthorizationHeader = (t: Token): string => `PrivateToken token=${base64urlEncode(serializeToken(t))}`;

export function fromAuthorizationHeader(h: string): Token {
  const m = /^PrivateToken\s+token=([A-Za-z0-9_-]+)$/.exec(h.trim());
  if (!m) throw new ProtocolError('BAD_HEADER', 'not a PrivateToken authorization header');
  return parseToken(base64urlDecode(m[1]!));
}

/** SHA-256(domain || nonce || challenge_digest): the replay-cache key. Reveals nothing about the client. */
export function tokenNullifier(t: Pick<Token, 'nonce' | 'challengeDigest'>): Uint8Array {
  return sha256(concat(utf8('biokyn-nullifier-v1'), t.nonce, t.challengeDigest));
}

// ------------------------------------------------------------- client side

export interface PendingIssuance {
  input: Uint8Array;
  nonce: Uint8Array;
  challengeDigest: Uint8Array;
  tokenKeyId: Uint8Array;
  blind: Uint8Array;
  blindedElement: Uint8Array;
}

/** Step 1 (client): pick a fresh nonce and blind TokenInput. Send `blindedElement` only. */
export function beginIssuance(challenge: TokenChallenge, serverPublicKey: Uint8Array): PendingIssuance {
  const nonce = randomBytes(NONCE_LEN);
  const digest = challengeDigest(challenge);
  const keyId = tokenKeyId(serverPublicKey);
  const input = tokenInput(nonce, digest, keyId);
  const { blind: r, blindedElement } = blind(input);
  return { input, nonce, challengeDigest: digest, tokenKeyId: keyId, blind: r, blindedElement };
}

/** Step 3 (client): verify DLEQ, unblind, assemble the token. */
export function completeIssuance(p: PendingIssuance, evaluation: Evaluation, serverPublicKey: Uint8Array): Token {
  const authenticator = finalize(p.input, p.blind, p.blindedElement, evaluation, serverPublicKey);
  return {
    tokenType: TOKEN_TYPE_BioKyn_R255,
    nonce: p.nonce,
    challengeDigest: p.challengeDigest,
    tokenKeyId: p.tokenKeyId,
    authenticator,
  };
}

// ------------------------------------------------------------- server side

export type RedeemFailure = 'wrong-key' | 'wrong-challenge' | 'bad-authenticator';

/** Recompute the VOPRF output and compare in constant time. Does NOT check replay (see server). */
export function verifyToken(
  server: VoprfServer,
  token: Token,
  expectedChallengeDigest: Uint8Array,
): { ok: true } | { ok: false; reason: RedeemFailure } {
  if (!ctEqual(token.tokenKeyId, tokenKeyId(server.publicKey))) return { ok: false, reason: 'wrong-key' };
  if (!ctEqual(token.challengeDigest, expectedChallengeDigest)) return { ok: false, reason: 'wrong-challenge' };
  const expected = server.evaluate(tokenInput(token.nonce, token.challengeDigest, token.tokenKeyId));
  return ctEqual(expected, token.authenticator) ? { ok: true } : { ok: false, reason: 'bad-authenticator' };
}
