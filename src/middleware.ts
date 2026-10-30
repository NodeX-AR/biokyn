import { CLIENT_SCRIPT } from './client.js';
import {
  isValidAction,
  isValidFormId,
  parseCookie,
  parseToken,
  randomId,
  readSid,
  sha256Hex,
  signSid,
  signToken,
  verifyToken,
} from './crypto.js';
import type {
  BioKynMiddlewareOptions,
  BioKynOptions,
  IssueResult,
  NodeRequestLike,
  NodeResponseLike,
  OriginHints,
  RequestInfo,
  ResolvedOptions,
  VerifiedInfo,
  VerifyReason,
  VerifyResult,
} from './types.js';

export type { BioKynOptions, VerifiedInfo, VerifyResult, IssueResult } from './types.js';

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const TOKEN_FIELD = '_biokyn';
const TOKEN_HEADER = 'x-biokyn-token';

/* --------------------------------- Engine --------------------------------- */

export class BioKyn {
  readonly cfg: ResolvedOptions;
  private readonly secret: Buffer;

  constructor(o: BioKynOptions) {
    const secret = typeof o.secret === 'string' ? Buffer.from(o.secret, 'utf8') : Buffer.from(o.secret);
    if (!o.origin && process.env['NODE_ENV'] === 'production') throw new Error('BioKyn: configure an explicit origin in production');
    if (secret.length < 32) throw new Error('BioKyn: secret must be at least 32 bytes');
    if (!o.store) throw new Error('BioKyn: store is required');
    this.secret = secret;
    this.cfg = {
      store: o.store,
      ttlMs: o.ttlMs ?? 15 * 60_000,
      minAgeMs: o.minAgeMs ?? 1_500,
      clockSkewMs: o.clockSkewMs ?? 5_000,
      quota: o.quota ?? 20,
      anonQuota: o.anonQuota ?? 10,
      verifyQuota: o.verifyQuota ?? 30,
      windowMs: o.windowMs ?? 10 * 60_000,
      origin: o.origin ? new URL(o.origin).origin : undefined,
      trustProxy: o.trustProxy ?? false,
      secureCookie: process.env['NODE_ENV'] === 'production' ? true : (o.secureCookie ?? false),
      cookieName: o.cookieName ?? '__biokyn_sid',
      sessionTtlMs: o.sessionTtlMs ?? 7 * 86_400_000,
      now: o.now ?? Date.now,
    };
  }

  /** Canonical origin used for binding. Origin header > Referer origin > proto://host. */
  originFor(h: OriginHints): string {
    if (this.cfg.origin) return this.cfg.origin;
    if (h.origin && h.origin !== 'null') {
      try {
        return new URL(h.origin).origin;
      } catch {
        /* fall through */
      }
    }
    if (h.referer) {
      try {
        return new URL(h.referer).origin;
      } catch {
        /* fall through */
      }
    }
    return `${h.proto}://${h.host ?? 'localhost'}`;
  }

  private sessionCookie(sid: string): string {
    const c = this.cfg;
    return (
      `${c.cookieName}=${signSid(this.secret, sid)}; Path=/; HttpOnly; SameSite=Lax; ` +
      `Max-Age=${Math.floor(c.sessionTtlMs / 1000)}${c.secureCookie ? '; Secure' : ''}`
    );
  }

  /**
   * Issues a challenge. Clients without a valid signed session cookie receive a new session and a single
   * zero-quota (bootstrap) token that can never verify; they must come back with the cookie for a real one.
   * Cookieless issuance is rate limited per IP, so cookie-clearing loops are throttled.
   */
  async issue(req: RequestInfo, formId: string, action: string): Promise<IssueResult> {
    const c = this.cfg;
    if (!isValidFormId(formId) || !isValidAction(action)) return { ok: false, reason: 'bad_request' };
    if (c.origin && req.originHeader && req.originHeader !== c.origin) {
      return { ok: false, reason: 'origin_mismatch' };
    }
    const raw = parseCookie(req.cookieHeader, c.cookieName);
    let sid = raw ? readSid(this.secret, raw) : null;
    let bootstrap = false;
    let setCookie: string | undefined;

    if (sid === null) {
      const n = await c.store.incr(`anon:${sha256Hex(req.ip)}`, c.windowMs);
      if (n > c.anonQuota) return { ok: false, reason: 'rate_limited', retryAfterMs: c.windowMs };
      sid = randomId(24);
      bootstrap = true;
      setCookie = this.sessionCookie(sid);
    } else {
      const n = await c.store.incr(`iss:${sha256Hex(sid)}`, c.windowMs);
      if (n > c.quota) return { ok: false, reason: 'rate_limited', retryAfterMs: c.windowMs };
    }

    const issuedAt = c.now();
    const token = signToken(this.secret, {
      ts: issuedAt,
      nonce: randomId(16),
      flags: bootstrap ? 1 : 0,
      formId,
      origin: req.origin,
      sid,
      action,
    });
    return {
      ok: true,
      token,
      bootstrap,
      issuedAt,
      ttlMs: c.ttlMs,
      minAgeMs: c.minAgeMs,
      ...(setCookie ? { setCookie } : {}),
    };
  }

  /** Verifies and consumes a token. Failed attempts never consume a valid token. */
  async verify(
    req: RequestInfo,
    token: string | undefined,
    action: string,
    expectedFormId?: string,
  ): Promise<VerifyResult> {
    const c = this.cfg;
    const fail = (reason: VerifyReason): VerifyResult => ({ ok: false, reason });
    if (!token) return fail('missing_token');
    const parsed = parseToken(token);
    if (!parsed) return fail('malformed');
    const raw = parseCookie(req.cookieHeader, c.cookieName);
    const sid = raw ? readSid(this.secret, raw) : null;
    if (!sid) return fail('no_session');
    if (c.origin && req.originHeader && req.originHeader !== c.origin) return fail('origin_mismatch');
    if (expectedFormId !== undefined && parsed.formId !== expectedFormId) return fail('form_mismatch');

    const q = await c.store.incr(`ver:${sha256Hex(sid)}`, c.windowMs);
    if (q > c.verifyQuota) return { ok: false, reason: 'rate_limited', retryAfterMs: c.windowMs };

    if (!verifyToken(this.secret, parsed, { formId: parsed.formId, origin: req.origin, sid, action })) {
      return fail('bad_signature');
    }
    if (parsed.flags === 1) return fail('bootstrap_token');

    const age = c.now() - parsed.ts;
    if (age < -c.clockSkewMs) return fail('malformed');
    if (age < c.minAgeMs) return fail('too_fast');
    if (age > c.ttlMs) return fail('expired');

    const fresh = await c.store.setNx(`rp:${sha256Hex(parsed.nonce)}`, c.ttlMs + c.clockSkewMs + 1_000);
    if (!fresh) return fail('replayed');
    return { ok: true, formId: parsed.formId, issuedAt: parsed.ts };
  }
}

const publicReason = (reason: string): string => reason === 'rate_limited' ? 'rate_limited' : 'verification_failed';

const statusFor = (reason: string): number =>
  reason === 'rate_limited' ? 429 : reason === 'bad_request' ? 400 : 403;

const toEngine = (e: BioKyn | BioKynOptions): BioKyn => (e instanceof BioKyn ? e : new BioKyn(e));

/* ------------------------- Express / Connect adapter ----------------------- */

export type NodeMiddleware = (
  req: NodeRequestLike,
  res: NodeResponseLike,
  next: (err?: unknown) => void,
) => Promise<void>;

const one = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);
const firstCsv = (v: string | undefined): string | undefined => v?.split(',')[0]?.trim() || undefined;

/** Canonicalize IPv4-mapped IPv6 and group native IPv6 to /64 for anonymous quotas. */
function quotaIp(raw: string): string {
  const ip = raw.trim().toLowerCase();
  if (ip.startsWith('::ffff:')) return ip.slice(7);
  if (ip.includes(':')) return `${ip.split(':').slice(0, 4).join(':')}::/64`;
  return ip;
}

function nodeInfo(engine: BioKyn, req: NodeRequestLike, getIp?: (r: NodeRequestLike) => string): RequestInfo {
  const h = req.headers;
  const trust = engine.cfg.trustProxy;
  const ip =
    getIp?.(req) ??
    req.ip ??
    (trust ? firstCsv(one(h['x-forwarded-for'])) : undefined) ??
    req.socket?.remoteAddress ??
    'unknown';
  const proto =
    (trust ? firstCsv(one(h['x-forwarded-proto'])) : undefined) ?? (req.socket?.encrypted ? 'https' : 'http');
  const oh = one(h['origin']);
  return {
    ip: quotaIp(ip),
    origin: engine.originFor({ origin: oh, referer: one(h['referer']), host: one(h['host']), proto }),
    originHeader: oh && oh !== 'null' ? oh : undefined,
    cookieHeader: one(h['cookie']),
  };
}

function defaultNodeToken(req: NodeRequestLike): string | undefined {
  const hv = one(req.headers[TOKEN_HEADER]);
  if (hv) return hv;
  const b = req.body;
  if (b && typeof b === 'object') {
    const t = (b as Record<string, unknown>)[TOKEN_FIELD];
    if (typeof t === 'string') return t;
  }
  return undefined;
}

function sendJson(res: NodeResponseLike, status: number, body: unknown, retryAfterMs?: number): void {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  if (retryAfterMs) res.setHeader('Retry-After', String(Math.ceil(retryAfterMs / 1000)));
  res.end(JSON.stringify(body));
}

function appendSetCookie(res: NodeResponseLike, cookie: string): void {
  const prev = res.getHeader('Set-Cookie');
  const list = Array.isArray(prev) ? prev.map(String) : prev ? [String(prev)] : [];
  res.setHeader('Set-Cookie', [...list, cookie]);
}

/**
 * Express/Connect middleware. Serves `${basePath}/challenge` and `${basePath}/client.js`, and rejects
 * unsafe-method requests lacking a valid single-use token bound to (origin, session, action, form).
 * Mount body parsers BEFORE this middleware if tokens are delivered in the body field `_biokyn`.
 */
export function biokynMiddleware(
  options: BioKynMiddlewareOptions,
): NodeMiddleware & { engine: BioKyn } {
  const engine = new BioKyn(options);
  const configuredBase = options.basePath ?? '/__biokyn';
  let baseEnd = configuredBase.length;

  while (
    baseEnd > 0 &&
    configuredBase.charCodeAt(baseEnd - 1) === 47
  ) {
    baseEnd--;
  }

  const base = configuredBase.slice(0, baseEnd);
  const shouldProtect =
    options.shouldProtect ?? ((m: string, p: string) => UNSAFE.has(m) && !p.startsWith(`${base}/`));
  const actionFor = options.actionFor ?? ((m: string, p: string) => `${m}:${p}`);
  const getToken = options.getToken ?? defaultNodeToken;

  const mw: NodeMiddleware = async (req, res, next) => {
    try {
      const method = (req.method ?? 'GET').toUpperCase();
      const url = new URL(req.originalUrl ?? req.url ?? '/', 'http://localhost');
      const path = url.pathname;

      if (method === 'GET' && path === `${base}/client.js`) {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
        res.setHeader('Cache-Control', 'public, max-age=3600');
        res.end(CLIENT_SCRIPT);
        return;
      }

      if (method === 'GET' && path === `${base}/challenge`) {
        const r = await engine.issue(
          nodeInfo(engine, req, options.getIp),
          url.searchParams.get('form') ?? '',
          url.searchParams.get('action') ?? '',
        );
        if (!r.ok) {
          sendJson(res, statusFor(r.reason), { error: publicReason(r.reason), retryAfterMs: r.retryAfterMs }, r.retryAfterMs);
          return;
        }
        if (r.setCookie) appendSetCookie(res, r.setCookie);
        sendJson(res, 200, { token: r.token, bootstrap: r.bootstrap, ttlMs: r.ttlMs, minAgeMs: r.minAgeMs });
        return;
      }

      if (!shouldProtect(method, path)) {
        next();
        return;
      }

      const r = await engine.verify(nodeInfo(engine, req, options.getIp), getToken(req), actionFor(method, path), options.formId);
      if (!r.ok) {
        sendJson(res, statusFor(r.reason), { error: publicReason(r.reason) }, r.retryAfterMs);
        return;
      }
      req.biokyn = { formId: r.formId, issuedAt: r.issuedAt };
      next();
    } catch (e) {
      next(e);
    }
  };

  return Object.assign(mw, { engine });
}

/* --------------------------- Next.js App Router ---------------------------- */

export interface WithBioKynOptions {
  engine: BioKyn | BioKynOptions;
  /** Fixed action label, or derive from the request. Default `${METHOD}:${pathname}`. */
  action?: string | ((req: Request) => string);
  /** Require this specific formId. */
  formId?: string;
  getToken?: (req: Request) => string | undefined | Promise<string | undefined>;
  /** Required for per-client anonymous quotas when not using trustProxy. */
  getIp?: (req: Request) => string;
  /** Maximum request body size used while extracting the token. Default 65536 bytes. */
  maxBodyBytes?: number;
}

function webInfo(engine: BioKyn, req: Request, getIp?: (r: Request) => string): RequestInfo {
  const h = req.headers;
  const url = new URL(req.url);
  const trust = engine.cfg.trustProxy;
  const ip = getIp?.(req) ?? (trust ? firstCsv(h.get('x-forwarded-for') ?? undefined) : undefined) ?? 'unknown';
  const proto =
    (trust ? firstCsv(h.get('x-forwarded-proto') ?? undefined) : undefined) ?? url.protocol.replace(':', '');
  const oh = h.get('origin') ?? undefined;
  return {
    ip: quotaIp(ip),
    origin: engine.originFor({
      origin: oh,
      referer: h.get('referer') ?? undefined,
      host: h.get('host') ?? url.host,
      proto,
    }),
    originHeader: oh && oh !== 'null' ? oh : undefined,
    cookieHeader: h.get('cookie') ?? undefined,
  };
}

async function readRequestTextLimited(req: Request, maxBytes: number): Promise<string | undefined> {
  const reader = req.body?.getReader(); if (!reader) return undefined;
  const chunks: Uint8Array[] = []; let size = 0;
  try { for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > maxBytes) { await reader.cancel(); throw new Error('payload_too_large'); } chunks.push(part.value); } }
  finally { reader.releaseLock(); }
  const all = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder().decode(all);
}

async function defaultWebToken(req: Request, maxBytes = 65_536): Promise<string | undefined> {
  const hv = req.headers.get(TOKEN_HEADER);
  if (hv) return hv;
  const ct = req.headers.get('content-type') ?? '';
  try {
    if (ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')) {
      const raw = await readRequestTextLimited(req.clone(), maxBytes);
      const formHeaders = new Headers(req.headers); formHeaders.delete('content-length');
      const formReq = new Request(req.url, { method: req.method, headers: formHeaders, body: raw ?? '' });
      const v = (await formReq.formData()).get(TOKEN_FIELD);
      return typeof v === 'string' ? v : undefined;
    }
    if (ct.includes('application/json')) {
      const raw = await readRequestTextLimited(req.clone(), maxBytes);
      const j = JSON.parse(raw ?? 'null') as Record<string, unknown> | null;
      const v = j?.[TOKEN_FIELD];
      return typeof v === 'string' ? v : undefined;
    }
  } catch {
    /* unreadable body => no token */
  }
  return undefined;
}

function webJson(status: number, body: unknown, setCookie?: string, retryAfterMs?: number): Response {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  if (retryAfterMs) headers.set('Retry-After', String(Math.ceil(retryAfterMs / 1000)));
  if (setCookie) headers.append('Set-Cookie', setCookie);
  return new Response(JSON.stringify(body), { status, headers });
}

/** GET route handler for the challenge endpoint: `export const GET = createChallengeHandler(engine)`. */
export function createChallengeHandler(
  engine: BioKyn | BioKynOptions,
  o: { getIp?: (req: Request) => string } = {},
): (req: Request) => Promise<Response> {
  const e = toEngine(engine);
  if (process.env['NODE_ENV'] === 'production' && !o.getIp && !e.cfg.trustProxy) throw new Error('BioKyn: Next.js production adapter requires getIp or explicitly trusted proxy headers');
  return async (req) => {
    const url = new URL(req.url);
    const r = await e.issue(
      webInfo(e, req, o.getIp),
      url.searchParams.get('form') ?? '',
      url.searchParams.get('action') ?? '',
    );
    if (!r.ok) {
      return webJson(statusFor(r.reason), { error: publicReason(r.reason), retryAfterMs: r.retryAfterMs }, undefined, r.retryAfterMs);
    }
    return webJson(
      200,
      { token: r.token, bootstrap: r.bootstrap, ttlMs: r.ttlMs, minAgeMs: r.minAgeMs },
      r.setCookie,
    );
  };
}

/** GET route handler serving the embedded client script. */
export function clientScriptHandler(): () => Response {
  return () =>
    new Response(CLIENT_SCRIPT, {
      status: 200,
      headers: {
        'Content-Type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'public, max-age=3600',
      },
    });
}

/** Wraps an App Router route handler; the handler runs only when a valid single-use token is presented. */
export function withBioKyn<C = unknown>(
  handler: (req: Request, ctx: C, verified: VerifiedInfo) => Response | Promise<Response>,
  config: WithBioKynOptions,
): (req: Request, ctx: C) => Promise<Response> {
  const engine = toEngine(config.engine);
  if (process.env['NODE_ENV'] === 'production' && !config.getIp && !engine.cfg.trustProxy) throw new Error('BioKyn: Next.js production adapter requires getIp or explicitly trusted proxy headers');
  return async (req, ctx) => {
    const url = new URL(req.url);
    const action =
      typeof config.action === 'function'
        ? config.action(req)
        : (config.action ?? `${req.method.toUpperCase()}:${url.pathname}`);
    const declared = Number(req.headers.get('content-length') ?? 0);
    if (Number.isFinite(declared) && declared > (config.maxBodyBytes ?? 65_536)) return webJson(413, { error: 'verification_failed' });
    const token = config.getToken ? await config.getToken(req) : await defaultWebToken(req, config.maxBodyBytes ?? 65_536);
    const r = await engine.verify(webInfo(engine, req, config.getIp), token, action, config.formId);
    if (!r.ok) {
      return webJson(statusFor(r.reason), { error: publicReason(r.reason) }, undefined, r.retryAfterMs);
    }
    return handler(req, ctx, { formId: r.formId, issuedAt: r.issuedAt });
  };
}
