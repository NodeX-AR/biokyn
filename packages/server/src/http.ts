/**
 * Framework-neutral HTTP core. Adapters (Express, Next.js, plain node:http, Hono, ...) translate to/from
 * HttpRequestLike / HttpResponseLike.
 *
 *   GET|POST {base}/challenge     -> ChallengeResponse                     (Origin header must be an allowed site)
 *   POST     {base}/issue         -> { status: "TOKEN_ISSUED", token } | { status: "STEP_UP_REQUIRED", challenge }
 *   POST     /siteverify          -> reCAPTCHA / Turnstile compatible JSON (server-to-server; also at the Google and
 *                                    Cloudflare path aliases so only the host has to change)
 */
import { BioKynHttpError } from './errors.js';
import { StoreCapacityError, StoreUnavailableError } from './nullifier.js';
import { parseSiteverifyBody, siteverify, type SiteverifyIdempotencyStore } from './siteverify.js';
import type { BioKynVerifier } from './verifier.js';

/** Linear-time trailing slash trim. Avoids quadratic backtracking of /\/+$/ on adversarial input. */
function trimTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47 /* '/' */) end--;
  return end === s.length ? s : s.slice(0, end);
}


export interface HttpRequestLike {
  method: string;
  /** Pathname only, no query string. */
  path: string;
  headers: Record<string, string | undefined>;
  /** Framework/socket peer IP; never infer trust from forwarded headers here. */
  ip?: string;
  /** Raw text, or an already-parsed object (e.g. express.json() / express.urlencoded()). */
  body?: string | Record<string, unknown>;
  /** Aborted when the underlying client disconnects. */
  signal?: AbortSignal;
}

export interface HttpResponseLike { status: number; headers: Record<string, string>; body: string }

export interface HandlerOptions {
  /** Prefix of the browser-facing routes. Default "/biokyn". */
  basePath?: string;
  /** Primary /siteverify path. Default "/siteverify". Aliases for Google and Turnstile are always accepted. */
  siteverifyPath?: string;
  maxBodyBytes?: number;
  /** Return true to allow the request, false to rate-limit it. Supply a production limiter keyed by a trusted client IP; no default IP limiter is inferred by this framework-neutral adapter. */
  rateLimit?: (req: HttpRequestLike) => boolean | Promise<boolean>;
  /** Shared Redis-backed /siteverify idempotency. Required for multi-instance production deployments that use idempotency_key. */
  siteverifyIdempotencyStore?: SiteverifyIdempotencyStore;
}

const SITEVERIFY_ALIASES = ['/recaptcha/api/siteverify', '/turnstile/v0/siteverify'];
const API_SUFFIXES = ['/challenge', '/issue', '/motion-step-up', '/webauthn/register/options', '/webauthn/register/verify'];

/** True for every route this handler owns. Adapters must use this instead of keeping their own route list. */
export function ownsPath(rawPath: string, opts: Pick<HandlerOptions, 'basePath' | 'siteverifyPath'> = {}): boolean {
  const path = trimTrailingSlashes(rawPath) || '/';
  const base = trimTrailingSlashes(opts.basePath ?? '/biokyn');
  return API_SUFFIXES.some((s) => path === `${base}${s}`) || path === (opts.siteverifyPath ?? '/siteverify') || SITEVERIFY_ALIASES.includes(path);
}

const json = (status: number, body: unknown, extra: Record<string, string> = {}): HttpResponseLike => ({
  status, body: JSON.stringify(body), headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra },
});

function originOf(req: HttpRequestLike): string | undefined {
  const o = req.headers.origin;
  if (o && o !== 'null') return o;
  const ref = req.headers.referer;
  if (ref) { try { return new URL(ref).origin; } catch { return undefined; } }
  return undefined;
}

export function createHandler(verifier: BioKynVerifier, opts: HandlerOptions = {}): (req: HttpRequestLike) => Promise<HttpResponseLike | null> {
  const base = trimTrailingSlashes(opts.basePath ?? '/biokyn');
  const svPath = opts.siteverifyPath ?? '/siteverify';
  const svPaths = new Set([svPath, ...SITEVERIFY_ALIASES]);
  const maxBody = opts.maxBodyBytes ?? 65_536;
  if (process.env.NODE_ENV === 'production' && !opts.rateLimit) {
    throw new Error('BioKyn production HTTP handler requires a rateLimit callback backed by trusted client identity and shared state');
  }

  const cors = (origin: string | undefined): Record<string, string> =>
    origin && verifier.siteForOrigin(origin)
      ? { 'access-control-allow-origin': origin, vary: 'Origin', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'content-type', 'access-control-max-age': '600' }
      : { vary: 'Origin' };

  return async (req) => {
    const method = req.method.toUpperCase();
    const path = trimTrailingSlashes(req.path) || '/';
    const isApi = path === `${base}/challenge` || path === `${base}/issue` || path === `${base}/motion-step-up` || path === `${base}/webauthn/register/options` || path === `${base}/webauthn/register/verify`;
    const isSv = svPaths.has(path);
    if (!isApi && !isSv) return null;

    try {
      const size = typeof req.body === 'string' ? new TextEncoder().encode(req.body).byteLength : req.body ? new TextEncoder().encode(JSON.stringify(req.body)).byteLength : 0;
      if (size > maxBody) return json(413, { error: 'payload_too_large' });

      // Browsers omit Origin on ordinary same-origin GETs. A Host fallback is accepted only
      // when it maps to an exact preconfigured site origin; arbitrary Host values never authorize.
      const headerOrigin = originOf(req);
      const origin = headerOrigin ?? ((method === 'GET' && path === `${base}/challenge`) || (method === 'POST' && path === `${base}/issue`) ? verifier.siteOriginForHost(req.headers.host) : undefined);
      if (opts.rateLimit && !(await opts.rateLimit(req))) return json(429, { error: 'rate_limited' }, { ...cors(origin), 'retry-after': '5' });

      if (isSv) {
        if (method !== 'POST') return json(405, { error: 'method_not_allowed' }, { allow: 'POST' });
        const params = parseSiteverifyBody(req.headers['content-type'], req.body);
        if (!params) return json(200, { success: false, 'error-codes': ['bad-request'] });
        return json(200, await siteverify(verifier, params, opts.siteverifyIdempotencyStore));
      }

      if (method === 'OPTIONS') return { status: 204, headers: { ...cors(origin), 'cache-control': 'no-store' }, body: '' };

      if (path.endsWith('/challenge')) {
        if (method !== 'GET' && method !== 'POST') return json(405, { error: 'method_not_allowed' }, cors(origin));
        return json(200, verifier.challenge(origin), cors(origin));
      }
      if (method !== 'POST') return json(405, { error: 'method_not_allowed' }, cors(origin));
      let parsed: unknown;
      try { parsed = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; } catch { throw new BioKynHttpError(400, 'bad_request'); }
      if (path === `${base}/motion-step-up`) return json(200, await verifier.verifyMotionStepUp(origin, parsed), cors(origin));
      if (path === `${base}/webauthn/register/options`) return json(200, await verifier.webauthnRegistrationOptions(origin, parsed, req.signal), cors(origin));
      if (path === `${base}/webauthn/register/verify`) return json(200, await verifier.webauthnRegister(origin, parsed), cors(origin));
      return json(200, await verifier.issue(origin, parsed, req.signal), cors(origin));
    } catch (e) {
      if (e instanceof BioKynHttpError) {
        return json(e.status, { error: e.code }, e.retryAfterSec ? { 'retry-after': String(e.retryAfterSec) } : {});
      }
      // Shared-state failures (Redis down/slow, bounded store full) fail closed with a retryable 503, never a 500 or a pass.
      if (e instanceof StoreUnavailableError || e instanceof StoreCapacityError) return json(503, { error: 'store_unavailable' }, { 'retry-after': '1' });
      return json(500, { error: 'internal_error' });
    }
  };
}
