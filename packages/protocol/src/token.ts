/**
 * BioKyn token protocol v2 — a Privacy-Pass-style redesign on top of RFC 9497 VOPRF(ristretto255, SHA-512).
 *
 * Why v1 was replaced:
 *  - v1 echoed the client's blinded element and the evaluated element inside the issuance token and used a bespoke
 *    DLEQ transcript and an ad-hoc redemption tag. Anything the issuer retained at issuance (blinded/evaluated points,
 *    challenge digests) was a candidate join key against redemption, and nothing pinned the issuer to ONE key.
 *  - v2 uses only RFC 9497 operations. The token input is (type, random nonce, challenge digest, key id); the issuer
 *    sees only a blinded element of it, so by VOPRF blindness it cannot link an issuance to a later redemption
 *    except through out-of-band metadata (timing, network address, per-key anonymity-set size — see docs/PRIVACY.md).
 *  - The redemption "authenticator" is the RFC 9497 PRF output F(sk, tokenInput), recomputable only by the key holder.
 *  - Every token carries a key id = SHA-256(publicKey). Clients can pin keys / compare key ids across an out-of-band
 *    channel to detect an issuer that hands different users different keys (key-tagging attack).
 *
 * Token wire format (redemption, 162 bytes):
 *   token_type(2) || nonce(32) || challenge_digest(32) || key_id(32) || authenticator(64)
 * Issuance response (96 bytes): evaluated_element(32) || dleq_proof(64).
 *
 * Design rationale and residual-risk analysis: docs/PRIVACY.md.
 */
import { base64urlDecode, base64urlEncode, concat, ctEqual, i2osp, lp2, randomBytes, utf8, ProtocolError } from './bytes.js';
import { sha256 } from './hashes.js';
import { blind, finalize, type Evaluation, type VoprfServer } from './voprf/rfc9497.js';
import { deserializeElement } from './voprf/group.js';
import type { ChallengeResponse } from './types.js';

/** Private-use token type for BioKyn VOPRF(ristretto255, SHA-512). Not an IANA-registered Privacy Pass type. */
export const TOKEN_TYPE = 0xb101;
export const NONCE_LENGTH = 32;
export const TOKEN_LENGTH = 2 + 32 + 32 + 32 + 64;
export const ISSUANCE_LENGTH = 32 + 64;

export interface PendingIssuance {
  tokenInput: Uint8Array;
  nonce: Uint8Array;
  blind: Uint8Array;
  blindedElement: Uint8Array;
  challengeDigest: Uint8Array;
  keyId: Uint8Array;
}
export interface Token { challengeDigest: Uint8Array; nonce: Uint8Array; keyId: Uint8Array; authenticator: Uint8Array }

export const tokenKeyId = (publicKey: Uint8Array): Uint8Array => sha256(concat(utf8('biokyn-key-v2'), publicKey));

export const challengeDigest = (c: Pick<ChallengeResponse, 'issuer' | 'origin' | 'redemptionContext'>): Uint8Array =>
  sha256(concat(utf8('biokyn-challenge-v2'), lp2(utf8(c.issuer)), lp2(utf8(c.origin)), lp2(base64urlDecode(c.redemptionContext))));

export const tokenInput = (nonce: Uint8Array, digest: Uint8Array, keyId: Uint8Array): Uint8Array => {
  if (nonce.length !== NONCE_LENGTH || digest.length !== 32 || keyId.length !== 32) throw new ProtocolError('TOKEN', 'invalid token input lengths');
  return concat(i2osp(TOKEN_TYPE, 2), nonce, digest, keyId);
};

/** Client step 1: pick a fresh nonce and blind the token input. `nonce` is injectable for tests only. */
export function beginIssuance(c: Pick<ChallengeResponse, 'issuer' | 'origin' | 'redemptionContext'>, publicKey: Uint8Array, nonce: Uint8Array = randomBytes(NONCE_LENGTH)): PendingIssuance {
  if (publicKey.length !== 32 || nonce.length !== NONCE_LENGTH) throw new ProtocolError('PUBLIC_KEY', 'invalid public key or nonce');
  deserializeElement(publicKey); // reject malformed / identity keys before doing any work
  const digest = challengeDigest(c), keyId = tokenKeyId(publicKey);
  const input = tokenInput(nonce, digest, keyId);
  const b = blind(input);
  return { tokenInput: input, nonce: nonce.slice(), blind: b.blind, blindedElement: b.blindedElement, challengeDigest: digest, keyId };
}

export function encodeIssuance(e: Evaluation): string {
  if (e.evaluatedElement.length !== 32 || e.proof.length !== 64) throw new ProtocolError('BAD_ISSUANCE', 'bad issuance lengths');
  return base64urlEncode(concat(e.evaluatedElement, e.proof));
}
export function decodeIssuance(raw: string): Evaluation {
  const b = base64urlDecode(raw);
  if (b.length !== ISSUANCE_LENGTH) throw new ProtocolError('TOKEN', 'issuance length');
  return { evaluatedElement: b.slice(0, 32), proof: b.slice(32) };
}

/** Client step 2: verify the issuer's DLEQ proof against the pinned/advertised key and derive the token. */
export function completeIssuance(pending: PendingIssuance, issued: Evaluation, publicKey: Uint8Array): Token {
  try {
    if (!ctEqual(tokenKeyId(publicKey), pending.keyId)) throw new ProtocolError('CONTEXT', 'public key does not match the key used to build this request');
    const authenticator = finalize(pending.tokenInput, pending.blind, issued.evaluatedElement, pending.blindedElement, publicKey, issued.proof);
    return { challengeDigest: pending.challengeDigest.slice(), nonce: pending.nonce.slice(), keyId: pending.keyId.slice(), authenticator };
  } catch (e) { if (e instanceof ProtocolError) throw e; throw new ProtocolError('PROOF', 'invalid proof'); }
}

export function serializeToken(t: Token): Uint8Array {
  if (t.challengeDigest.length !== 32 || t.nonce.length !== NONCE_LENGTH || t.keyId.length !== 32 || t.authenticator.length !== 64) throw new ProtocolError('TOKEN', 'invalid redemption token lengths');
  return concat(i2osp(TOKEN_TYPE, 2), t.nonce, t.challengeDigest, t.keyId, t.authenticator);
}
export const encodeToken = (t: Token): string => base64urlEncode(serializeToken(t));
export function parseToken(raw: Uint8Array): Token {
  if (raw.length !== TOKEN_LENGTH) throw new ProtocolError('TOKEN', 'redemption token length');
  if (((raw[0]! << 8) | raw[1]!) !== TOKEN_TYPE) throw new ProtocolError('TOKEN', 'unsupported token type');
  return { nonce: raw.slice(2, 34), challengeDigest: raw.slice(34, 66), keyId: raw.slice(66, 98), authenticator: raw.slice(98, 162) };
}
export const decodeToken = (raw: string): Token => parseToken(base64urlDecode(raw));

/** Issuer-side verification: recompute F(sk, tokenInput) and compare in constant time. */
export function verifyToken(server: VoprfServer, token: Token, expectedDigest: Uint8Array): { ok: boolean } {
  try {
    if (!ctEqual(token.challengeDigest, expectedDigest) || !ctEqual(token.keyId, tokenKeyId(server.publicKey))) return { ok: false };
    return { ok: server.verify(tokenInput(token.nonce, token.challengeDigest, token.keyId), token.authenticator) };
  } catch { return { ok: false }; }
}

/** Single-use identifier. Contains no issuer secret, so replay protection needs no key material. */
export const tokenNullifier = (t: Token): Uint8Array =>
  sha256(concat(utf8('biokyn-nullifier-v2'), lp2(t.nonce), lp2(t.challengeDigest), lp2(t.keyId)));
