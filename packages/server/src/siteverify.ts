/**
 * Drop-in /siteverify (Google reCAPTCHA v2/v3 and Cloudflare Turnstile compatible).
 *
 *   request  (form or JSON):  secret, response, [remoteip], [idempotency_key], [sitekey]
 *   success  : { success: true,  score: 0.9, challenge_ts, hostname, action?, "error-codes": [] }
 *   failure  : { success: false, "error-codes": [ ... ] }
 *
 * `score` is a constant (default 0.9) because BioKyn only knows "issued" or "not issued"; it never invents
 * granularity. `challenge_ts` is the start of the token's validity epoch (tokens carry no timestamp, by design).
 * Action is deliberately omitted: the current token format does not cryptographically bind an action, and
 * echoing an action suffix would allow clients to forge it. Add action binding to the challenge/token protocol first.
 */
import { sha256 } from '@biokyn/protocol';
import type { BioKynVerifier } from './verifier.js';

export interface SiteverifyParams { secret?: string; response?: string; remoteip?: string; idempotency_key?: string; sitekey?: string }

export interface SiteverifyIdempotencyStore {
  /** Atomically return a cached result or coordinate one computation across all instances. */
  getOrCompute(key: string, ttlMs: number, compute: () => Promise<SiteverifyBody>): Promise<SiteverifyBody>;
}

export interface SiteverifyBody {
  success: boolean;
  score?: number;
  challenge_ts?: string;
  hostname?: string;
  'error-codes': string[];
}

const pick = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

export function parseSiteverifyBody(contentType: string | undefined, body: string | Record<string, unknown> | undefined): SiteverifyParams | null {
  if (body === undefined) return {};
  let obj: Record<string, unknown>;
  if (typeof body !== 'string') {
    obj = body;
  } else if ((contentType ?? '').toLowerCase().includes('application/json')) {
    try {
      const parsed: unknown = JSON.parse(body);
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
      obj = parsed as Record<string, unknown>;
    } catch { return null; }
  } else {
    obj = Object.fromEntries(new URLSearchParams(body));
  }
  return { secret: pick(obj.secret), response: pick(obj.response), remoteip: pick(obj.remoteip), idempotency_key: pick(obj.idempotency_key), sitekey: pick(obj.sitekey) };
}

const idempotencyCache = new WeakMap<BioKynVerifier, Map<string, { expiresAt: number; body: SiteverifyBody }>>();
const idempotencyInFlight = new WeakMap<BioKynVerifier, Map<string, Promise<SiteverifyBody>>>();
const cleanupOps = new WeakMap<BioKynVerifier, number>();

export async function siteverify(verifier: BioKynVerifier, params: SiteverifyParams, sharedStore?: SiteverifyIdempotencyStore): Promise<SiteverifyBody> {
  const origin = verifier.idempotencyOrigin(params.secret);
  const key = params.idempotency_key;
  if (key !== undefined && (key.length < 1 || key.length > 255 || /[\u0000-\u001f\u007f]/.test(key))) {
    return { success: false, 'error-codes': ['invalid-input-response'] };
  }
  if (key && origin && sharedStore) {
    const responseBytes = new TextEncoder().encode(params.response ?? '');
    const responseHash = Array.from(sha256(responseBytes), (b) => b.toString(16).padStart(2, '0')).join('');
    const cacheKey = `${origin}:${key}:${responseHash}`;
    try { return await sharedStore.getOrCompute(cacheKey, verifier.tokenEpochMs, () => verifyAndFormat(verifier, params)); }
    catch { return { success: false, 'error-codes': ['internal-error'] }; }
  }
  if (key && origin) {
    let cache = idempotencyCache.get(verifier);
    if (!cache) { cache = new Map(); idempotencyCache.set(verifier, cache); }
    const now = Date.now();
    // Amortize cleanup and cap work per request; never linearly sweep the full cache on every call.
    const op = (cleanupOps.get(verifier) ?? 0) + 1;
    cleanupOps.set(verifier, op);
    if ((op & 63) === 0) {
      let checked = 0;
      for (const [k, v] of cache) {
        if (v.expiresAt <= now) cache.delete(k);
        if (++checked >= 128) break;
      }
    }
    const responseBytes = new TextEncoder().encode(params.response ?? '');
    const responseHash = Array.from(sha256(responseBytes), (b) => b.toString(16).padStart(2, '0')).join('');
    const cacheKey = `idemp:${origin}:${key}:${responseHash}`;
    if (cache.size >= 10_000 && !cache.has(cacheKey)) {
      // One bounded eviction per request; avoid a synchronous loop under high load.
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
    const hit = cache.get(cacheKey);
    if (hit && hit.expiresAt > now) return { ...hit.body, 'error-codes': [...hit.body['error-codes']] };
    let flights = idempotencyInFlight.get(verifier);
    if (!flights) { flights = new Map(); idempotencyInFlight.set(verifier, flights); }
    const pending = flights.get(cacheKey);
    if (pending) { const result = await pending; return { ...result, 'error-codes': [...result['error-codes']] }; }
    if (flights.size >= 10_000) return { success: false, 'error-codes': ['internal-error'] };
    const work = verifyAndFormat(verifier, params);
    flights.set(cacheKey, work);
    try {
      const out = await work;
      if (out.success) {
        const expiresAt = Date.now() + verifier.tokenEpochMs;
        cache.delete(cacheKey);
        cache.set(cacheKey, { expiresAt, body: out });
        while (cache.size > 10_000) {
          const oldest = cache.keys().next().value;
          if (oldest === undefined) break;
          cache.delete(oldest);
        }
      }
      return out;
    } finally { flights.delete(cacheKey); }
  }
  return verifyAndFormat(verifier, params);
}

async function verifyAndFormat(verifier: BioKynVerifier, params: SiteverifyParams): Promise<SiteverifyBody> {
  try {
    const r = await verifier.verifyToken(params.secret, params.response);
    if (!r.success) return { success: false, 'error-codes': r.errors };
    return { success: true, score: verifier.scoreOnSuccess, challenge_ts: r.challengeTs, hostname: r.hostname, 'error-codes': [] };
  } catch {
    return { success: false, 'error-codes': ['internal-error'] };
  }
}
