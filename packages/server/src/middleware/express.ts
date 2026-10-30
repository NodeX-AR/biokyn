/**
 * Express adapter. Works with Express 4/5 and anything with the same (req, res, next) shape (Connect, Fastify's
 * middie, Polka). Types are structural so @types/express is not required.
 *
 *   app.use(biokynExpress(verifier));                                  // mounts /biokyn/* and /siteverify
 *   app.post('/signup', requireBioKyn(verifier, { secret }), handler);  // guards a route
 */
import { createHandler, ownsPath, type HandlerOptions, type HttpRequestLike } from '../http.js';
import type { BioKynVerifier } from '../verifier.js';

export interface ExpressRequestLike {
  method: string;
  url: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  socket?: { remoteAddress?: string };
  body?: unknown;
  on?: (event: string, cb: (...a: any[]) => void) => unknown;
  readableEnded?: boolean;
  aborted?: boolean;
}
export interface ExpressResponseLike {
  status(code: number): ExpressResponseLike;
  set(name: string, value: string): ExpressResponseLike;
  send(body: string): unknown;
  headersSent?: boolean;
}
export type NextFn = (err?: unknown) => void;

const flat = (h: ExpressRequestLike['headers']): Record<string, string | undefined> => {
  const out: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
  return out;
};

function readBody(req: ExpressRequestLike, max: number): Promise<string | undefined> {
  return new Promise((resolve, reject) => {
    if (!req.on || req.readableEnded) return resolve(undefined);
    const chunks: Uint8Array[] = [];
    let n = 0;
    req.on('data', (c: Uint8Array | string) => {
      const b = typeof c === 'string' ? new TextEncoder().encode(c) : c;
      n += b.length;
      if (n > max) { reject(new Error('payload too large')); return; }
      chunks.push(b);
    });
    req.on('end', () => resolve(chunks.length ? new TextDecoder().decode(Buffer.concat(chunks)) : undefined));
    req.on('error', reject);
  });
}

export function biokynExpress(verifier: BioKynVerifier, opts: HandlerOptions = {}): (req: ExpressRequestLike, res: ExpressResponseLike, next: NextFn) => void {
  const handle = createHandler(verifier, opts);
  const max = opts.maxBodyBytes ?? 65_536;
  return (req, res, next) => {
    void (async () => {
      const url = new URL(req.originalUrl ?? req.url, 'http://local');
      const handled = ownsPath(url.pathname, opts);
      // Never consume a host application's request stream for routes BioKyn does not own.
      if (!handled) { next(); return; }
      let body: string | Record<string, unknown> | undefined;
      if (typeof req.body === 'string') body = req.body;
      else if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) body = req.body as Record<string, unknown>;
      else if (Buffer.isBuffer(req.body)) body = req.body.toString('utf8');
      else if (req.method.toUpperCase() === 'POST') {
        try { body = await readBody(req, max); } catch { res.status(413).set('content-type', 'application/json').send('{"error":"payload_too_large"}'); return; }
      }
      const controller = new AbortController();
      req.on?.('aborted', () => controller.abort());
      const r: HttpRequestLike = { method: req.method, path: url.pathname, headers: flat(req.headers), body, ip: req.ip ?? req.socket?.remoteAddress, signal: controller.signal }; 
      const out = await handle(r);
      if (!out) { next(); return; }
      res.status(out.status);
      for (const [k, v] of Object.entries(out.headers)) res.set(k, v);
      res.send(out.body);
    })().catch(next);
  };
}

export interface RequireOptions {
  /** This site's /siteverify secret. */
  secret: string;
  /** Body fields checked in order. */
  fields?: string[];
}

/** Route guard: verifies (and consumes) the token from the request body before the handler runs. */
export function requireBioKyn(verifier: BioKynVerifier, opts: RequireOptions): (req: ExpressRequestLike, res: ExpressResponseLike, next: NextFn) => void {
  const fields = opts.fields ?? ['biokyn-token', 'g-recaptcha-response', 'cf-turnstile-response'];
  return (req, res, next) => {
    void (async () => {
      const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
      const header = req.headers['x-biokyn-token'];
      const token = (Array.isArray(header) ? header[0] : header) ?? fields.map((f) => body[f]).find((v): v is string => typeof v === 'string' && v.length > 0);
      const r = await verifier.verifyToken(opts.secret, token);
      if (r.success) { next(); return; }
      res.status(403).set('content-type', 'application/json').send(JSON.stringify({ error: 'verification_failed', 'error-codes': r.errors }));
    })().catch(next);
  };
}
