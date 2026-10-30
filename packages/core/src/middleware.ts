import { isIP } from 'node:net';
import { CLIENT_SCRIPT } from './client.js';
import { StoreCapacityError } from './store.js';
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
    const positive = (name: string, value: number | undefined, fallback: number): number => {
      const n = value ?? fallback;
      if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`BioKyn: ${name} must be a positive safe integer`);
      return n;
    };
    const nonNegative = (name: string, value: number | undefined, fallback: number): number => {
      const n = value ?? fallback;
      if (!Number.isSafeInteger(n) || n < 0) throw new Error(`BioKyn: ${name} must be a non-negative safe integer`);
      return n;
    };
    if (o.origin !== undefined) {
      let parsedOrigin: URL;
      try { parsedOrigin = new URL(o.origin); } catch { throw new Error('BioKyn: origin must be a valid absolute URL'); }
      if (!['http:', 'https:'].includes(parsedOrigin.protocol) || parsedOrigin.origin !== o.origin.replace(/\/$/, '')) {
        throw new Error('BioKyn: origin must be a canonical HTTP(S) origin without a path');
      }
    }
    if (o.cookieName !== undefined && !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(o.cookieName)) {
      throw new Error('BioKyn: cookieName is not a valid cookie token');
    }
    if (typeof o.trustProxy === 'number' && (!Number.isSafeInteger(o.trustProxy) || o.trustProxy < 1 || o.trustProxy > 32)) throw new Error('BioKyn: trustProxy hop count must be an integer from 1 to 32');
    this.secret = secret;
    this.cfg = {
      store: o.store,
      ttlMs: positive('ttlMs', o.ttlMs, 15 * 60_000),
      minAgeMs: nonNegative('minAgeMs', o.minAgeMs, 1_500),
      clockSkewMs: nonNegative('clockSkewMs', o.clockSkewMs, 5_000),
      quota: positive('quota', o.quota, 20),
      anonQuota: positive('anonQuota', o.anonQuota, 10),
      verifyQuota: positive('verifyQuota', o.verifyQuota, 30),
      windowMs: positive('windowMs', o.windowMs, 10 * 60_000),
      origin: o.origin ? new URL(o.origin).origin : undefined,
      trustProxy: o.trustProxy ?? false,
      secureCookie: process.env['NODE_ENV'] === 'production' ? true : (o.secureCookie ?? false),
      cookieName: o.cookieName ?? '__biokyn_sid',
      sessionTtlMs: positive('sessionTtlMs', o.sessionTtlMs, 7 * 86_400_000),
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
      let n: number;
      try { n = await c.store.incr(`anon:${sha256Hex(req.ip)}`, c.windowMs); } catch (e) { if (e instanceof StoreCapacityError) return { ok: false, reason: 'store_unavailable', retryAfterMs: 1_000 }; throw e; }
      if (n > c.anonQuota) return { ok: false, reason: 'rate_limited', retryAfterMs: c.windowMs };
      sid = randomId(24);
      bootstrap = true;
      setCookie = this.sessionCookie(sid);
    } else {
      let n: number;
      try { n = await c.store.incr(`iss:${sha256Hex(sid)}`, c.windowMs); } catch (e) { if (e instanceof StoreCapacityError) return { ok: false, reason: 'store_unavailable', retryAfterMs: 1_000 }; throw e; }
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
    if (!isValidAction(action)) return fail('malformed');
    if (!token) return fail('missing_token');
    const parsed = parseToken(token);
    if (!parsed) return fail('malformed');
    const raw = parseCookie(req.cookieHeader, c.cookieName);
    const sid = raw ? readSid(this.secret, raw) : null;
    if (!sid) return fail('no_session');
    if (c.origin && req.originHeader && req.originHeader !== c.origin) return fail('origin_mismatch');
    if (expectedFormId !== undefined && parsed.formId !== expectedFormId) return fail('form_mismatch');

    let q: number;
    try { q = await c.store.incr(`ver:${sha256Hex(sid)}`, c.windowMs); } catch (e) { if (e instanceof StoreCapacityError) return fail('store_unavailable'); throw e; }
    if (q > c.verifyQuota) return { ok: false, reason: 'rate_limited', retryAfterMs: c.windowMs };

    if (!verifyToken(this.secret, parsed, { formId: parsed.formId, origin: req.origin, sid, action })) {
      return fail('bad_signature');
    }
    if (parsed.flags === 1) return fail('bootstrap_token');

    const age = c.now() - parsed.ts;
    if (age < -c.clockSkewMs) return fail('malformed');
    if (age < c.minAgeMs) return fail('too_fast');
    if (age > c.ttlMs) return fail('expired');

    let fresh: boolean;
    try { fresh = await c.store.setNx(`rp:${sha256Hex(parsed.nonce)}`, c.ttlMs + c.clockSkewMs + 1_000); } catch (e) { if (e instanceof StoreCapacityError) return fail('store_unavailable'); throw e; }
    if (!fresh) return fail('replayed');
    return { ok: true, formId: parsed.formId, issuedAt: parsed.ts };
  }
}

const publicReason = (reason: string): string => reason === 'rate_limited' ? 'rate_limited' : reason === 'store_unavailable' ? 'store_unavailable' : 'verification_failed';

const statusFor = (reason: string): number =>
  reason === 'store_unavailable' ? 503 : reason === 'rate_limited' ? 429 : reason === 'bad_request' ? 400 : 403;

const toEngine = (e: BioKyn | BioKynOptions): BioKyn => (e instanceof BioKyn ? e : new BioKyn(e));

/* ------------------------- Express / Connect adapter ----------------------- */

export type NodeMiddleware = (
  req: NodeRequestLike,
  res: NodeResponseLike,
  next: (err?: unknown) => void,
) => Promise<void>;

const one = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);
function expandIpv6(input: string): number[] | null {
  let ip = input;
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (v4) {
    const o = v4.slice(1).map(Number);
    if (o.some((n) => n > 255)) return null;
    ip = `${ip.slice(0, ip.length - v4[0].length)}${((o[0]! << 8) | o[1]!).toString(16)}:${((o[2]! << 8) | o[3]!).toString(16)}`;
  }
  const parts = ip.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  let groups: string[];
  if (parts.length === 1) groups = head;
  else {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = [...head, ...new Array<string>(fill).fill('0'), ...tail];
  }
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

function quotaIp(raw: string): string {
  let ip = raw.trim().toLowerCase();
  if (ip.startsWith('[') && ip.includes(']')) ip = ip.slice(1, ip.indexOf(']'));
  else if (isIP(ip) === 0) {
    // Normalize IPv4:port and bare IPv4-mapped proxy values before quota-keying.
    const m = ip.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/);
    if (m && isIP(m[1]!) === 4 && Number(ip.slice(ip.lastIndexOf(':') + 1)) <= 65535) ip = m[1]!;
  }
  const zone = ip.indexOf('%');
  if (zone >= 0) ip = ip.slice(0, zone);
  if (isIP(ip) === 4) return ip;
  if (isIP(ip) !== 6) return ip.slice(0, 64) || 'unknown';
  const g = expandIpv6(ip);
  if (!g) return ip.slice(0, 64);
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return `${g[6]! >> 8}.${g[6]! & 255}.${g[7]! >> 8}.${g[7]! & 255}`;
  return `${g.slice(0, 4).map((x) => x.toString(16)).join(':')}::/64`;
}

function forwarded(v: string | undefined, trust: boolean | number): string | undefined {
  const hops = trust === true ? 1 : typeof trust === 'number' ? trust : 0;
  if (!Number.isSafeInteger(hops) || hops < 1 || !v) return undefined;
  const parts = v.split(',').map((s) => s.trim()).filter(Boolean);
  return parts.length ? parts[Math.max(0, parts.length - hops)] : undefined;
}

function nodeInfo(engine: BioKyn, req: NodeRequestLike, getIp?: (r: NodeRequestLike) => string): RequestInfo {
  const h = req.headers;
  const trust = engine.cfg.trustProxy;
  const ip =
    getIp?.(req) ??
    (trust ? forwarded(one(h['x-forwarded-for']), trust) : undefined) ??
    req.ip ??
    req.socket?.remoteAddress ??
    'unknown';
  const proto =
    forwarded(one(h['x-forwarded-proto']), trust) ?? (req.socket?.encrypted ? 'https' : 'http');
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
  const ip = getIp?.(req) ?? forwarded(h.get('x-forwarded-for') ?? undefined, trust) ?? 'unknown';
  const proto =
    forwarded(h.get('x-forwarded-proto') ?? undefined, trust) ?? url.protocol.replace(':', '');
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
