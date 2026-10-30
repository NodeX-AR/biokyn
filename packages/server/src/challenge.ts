/**
 * Stateless challenge authority. A challenge id is
 *    version(1) | difficultyBits(1) | issuedAtMs(8) | random(16) | mac(16)
 * with mac = HMAC-SHA256(secret, "biokyn-challenge-v1" || fields || origin), so any server instance sharing the
 * secret can authenticate it without a database. The server nonce and PoW salt are derived from the id, and the
 * token redemption context is derived from the current epoch, so a token verifies without any stored state.
 */
import { base64urlDecode, base64urlEncode, concat, ctEqual, hmac, i2osp, randomBytes, sha256, utf8 } from '@biokyn/protocol';

export interface OpenedChallenge {
  id: string;
  issuedAt: number;
  difficultyBits: number;
  nonce: Uint8Array;
  powSalt: Uint8Array;
}

const mac = (secret: Uint8Array, label: string, ...parts: Uint8Array[]): Uint8Array => hmac(sha256, secret, concat(utf8(label), ...parts));

export class ChallengeAuthority {
  constructor(
    private readonly secret: Uint8Array,
    private readonly ttlMs: number,
    private readonly epochMs: number,
    private readonly now: () => number,
  ) {
    if (secret.length < 32) throw new RangeError('challenge secret must be at least 32 bytes');
  }

  create(origin: string, difficultyBits: number): OpenedChallenge {
    const head = concat(i2osp(1, 1), i2osp(Math.max(0, Math.min(255, Math.floor(difficultyBits))), 1), i2osp(this.now(), 8), randomBytes(16));
    const tag = mac(this.secret, 'biokyn-challenge-v1', head, utf8(origin)).subarray(0, 16);
    return this.derive(base64urlEncode(concat(head, tag)), head, origin);
  }

  /** Returns null for forged, malformed, expired or future-dated ids. */
  open(id: string, origin: string): OpenedChallenge | null {
    let raw: Uint8Array;
    try { raw = base64urlDecode(id); } catch { return null; }
    if (raw.length !== 42 || raw[0] !== 1) return null;
    const head = raw.subarray(0, 26);
    const expected = mac(this.secret, 'biokyn-challenge-v1', head, utf8(origin)).subarray(0, 16);
    if (!ctEqual(expected, raw.subarray(26))) return null;
    const out = this.derive(id, head, origin);
    const age = this.now() - out.issuedAt;
    if (age < -5000 || age > this.ttlMs) return null;
    return out;
  }

  private derive(id: string, head: Uint8Array, origin: string): OpenedChallenge {
    let t = 0;
    for (let i = 2; i < 10; i++) t = t * 256 + head[i]!;
    return {
      id,
      issuedAt: t,
      difficultyBits: head[1]!,
      nonce: mac(this.secret, 'biokyn-nonce-v1', head, utf8(origin)),
      powSalt: mac(this.secret, 'biokyn-salt-v1', head, utf8(origin)).subarray(0, 16),
    };
  }

  /** WebAuthn step-up challenge: bound to the exact issuance request digest. */
  stepUpChallenge(requestDigest: Uint8Array): Uint8Array {
    return mac(this.secret, 'biokyn-stepup-v1', requestDigest);
  }

  /** WebAuthn registration challenge / user handle, derived from the (already authenticated) challenge nonce. */
  registrationChallenge(nonce: Uint8Array): Uint8Array { return mac(this.secret, 'biokyn-webauthn-register-v1', nonce); }
  registrationUserHandle(nonce: Uint8Array): Uint8Array { return mac(this.secret, 'biokyn-webauthn-user-v1', nonce).subarray(0, 16); }

  private epoch(at: number): number { return Math.floor(at / this.epochMs); }
  private contextFor(origin: string, epoch: number): Uint8Array { return mac(this.secret, 'biokyn-redemption-v1', utf8(origin), i2osp(epoch, 6)); }

  currentRedemptionContext(origin: string): Uint8Array { return this.contextFor(origin, this.epoch(this.now())); }
  redemptionContextAt(origin: string, at: number): Uint8Array { return this.contextFor(origin, this.epoch(at)); }

  /** Contexts a presented token may carry, newest first, with the start time of each epoch. */
  acceptedRedemptionContexts(origin: string): Array<{ context: Uint8Array; epochStart: number }> {
    const e = this.epoch(this.now());
    // A token is valid for up to two epoch lengths from issuance. Include two previous epochs. This means the oldest accepted context can remain valid for nearly three epoch lengths;
    // verifier nullifiers must be retained for at least the same window plus clock-skew margin.
    return [e, e - 1, e - 2].map((k) => ({ context: this.contextFor(origin, k), epochStart: k * this.epochMs }));
  }
}
