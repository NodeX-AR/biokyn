/** Server-side registry of WebAuthn credentials created through the registration ceremony (or pre-provisioned). */
import { base64urlEncode, sha256, utf8 } from '@biokyn/protocol';
import { StoreCapacityError } from './nullifier.js';
import type { RedisAtomicClient } from './redis-store.js';

export interface StoredWebAuthnCredential {
  credentialId: string;        // base64url
  publicKeySpki: string;       // base64url DER SubjectPublicKeyInfo, ES256 / P-256
  signCount: number;
  createdAt: number;           // ms epoch
  expiresAt: number;           // ms epoch; anonymous credentials are deliberately short-lived
  origin: string;
  revoked?: boolean;
  aaguid?: string;
  backupEligible?: boolean;
}

export interface WebAuthnCredentialStore {
  /** Returns undefined for unknown, expired or revoked credentials. */
  get(credentialId: string): Promise<StoredWebAuthnCredential | undefined> | StoredWebAuthnCredential | undefined;
  /** Atomically create; false if the credential ID already exists. Must fail closed at capacity (StoreCapacityError). */
  create(cred: StoredWebAuthnCredential): Promise<boolean> | boolean;
  /** Compare-and-set the signature counter. false if the stored counter no longer equals `expected`. */
  updateSignCount(credentialId: string, expected: number, next: number): Promise<boolean> | boolean;
  revoke(credentialId: string): Promise<boolean> | boolean;
}

export class MemoryWebAuthnCredentialStore implements WebAuthnCredentialStore {
  private readonly map = new Map<string, StoredWebAuthnCredential>();
  constructor(private readonly now: () => number = Date.now, private readonly maxEntries = 100_000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) throw new RangeError('maxEntries must be a positive integer');
  }
  private sweep(): void { const t = this.now(); for (const [k, v] of this.map) if (v.expiresAt <= t) this.map.delete(k); }
  get size(): number { return this.map.size; }
  get(id: string): StoredWebAuthnCredential | undefined {
    const c = this.map.get(id);
    if (!c) return undefined;
    if (c.expiresAt <= this.now()) { this.map.delete(id); return undefined; }
    return c.revoked ? undefined : { ...c };
  }
  create(cred: StoredWebAuthnCredential): boolean {
    const existing = this.map.get(cred.credentialId);
    if (existing && existing.expiresAt > this.now()) return false;
    if (!existing && this.map.size >= this.maxEntries) { this.sweep(); if (this.map.size >= this.maxEntries) throw new StoreCapacityError('credential store capacity reached'); }
    this.map.set(cred.credentialId, { ...cred }); return true;
  }
  updateSignCount(id: string, expected: number, next: number): boolean {
    const c = this.map.get(id);
    if (!c || c.revoked || c.expiresAt <= this.now() || c.signCount !== expected) return false;
    c.signCount = next; return true;
  }
  revoke(id: string): boolean { const c = this.map.get(id); if (!c) return false; c.revoked = true; return true; }
}

const CAS_SCRIPT = `
local raw = redis.call('GET', KEYS[1]); if not raw then return 0 end
local c = cjson.decode(raw)
if c.revoked or c.signCount ~= tonumber(ARGV[1]) then return 0 end
c.signCount = tonumber(ARGV[2])
local ttl = redis.call('PTTL', KEYS[1]); if ttl <= 0 then return 0 end
redis.call('SET', KEYS[1], cjson.encode(c), 'PX', ttl); return 1`;
const REVOKE_SCRIPT = `
local raw = redis.call('GET', KEYS[1]); if not raw then return 0 end
local c = cjson.decode(raw); c.revoked = true
local ttl = redis.call('PTTL', KEYS[1]); if ttl <= 0 then return 0 end
redis.call('SET', KEYS[1], cjson.encode(c), 'PX', ttl); return 1`;

/** Shared credential registry for multi-instance deployments. Keys carry a {hash tag} for Redis Cluster. */
export class RedisWebAuthnCredentialStore implements WebAuthnCredentialStore {
  constructor(private readonly redis: RedisAtomicClient, private readonly prefix = 'biokyn:webauthn:v1:', private readonly now: () => number = Date.now) {
    if (typeof redis.get !== 'function') throw new TypeError('Redis client must implement GET');
    if (!prefix || prefix.length > 128) throw new RangeError('Redis key prefix must be 1-128 characters');
  }
  private key(id: string): string { return `${this.prefix}cred:{${base64urlEncode(sha256(utf8(id)))}}`; }
  async get(id: string): Promise<StoredWebAuthnCredential | undefined> {
    const raw = await this.redis.get!(this.key(id));
    if (!raw) return undefined;
    try {
      const c = JSON.parse(raw) as StoredWebAuthnCredential;
      if (c.credentialId !== id || c.revoked || c.expiresAt <= this.now() || typeof c.publicKeySpki !== 'string' || !Number.isSafeInteger(c.signCount)) return undefined;
      return c;
    } catch { return undefined; }
  }
  async create(cred: StoredWebAuthnCredential): Promise<boolean> {
    const ttl = cred.expiresAt - this.now();
    if (!Number.isSafeInteger(ttl) || ttl < 1000) throw new RangeError('credential lifetime must be at least 1000ms');
    return (await this.redis.set(this.key(cred.credentialId), JSON.stringify(cred), 'PX', ttl, 'NX')) === 'OK';
  }
  async updateSignCount(id: string, expected: number, next: number): Promise<boolean> { return Number(await this.redis.eval(CAS_SCRIPT, 1, this.key(id), expected, next)) === 1; }
  async revoke(id: string): Promise<boolean> { return Number(await this.redis.eval(REVOKE_SCRIPT, 1, this.key(id))) === 1; }
}
