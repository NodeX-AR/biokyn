/**
 * Next.js App Router adapter (Web Request/Response; works in Node and Edge runtimes).
 *
 *   // app/api/biokyn/[...path]/route.ts
 *   const h = biokynNext(verifier, { basePath: '/api/biokyn' });
 *   export const GET = h.GET, POST = h.POST, OPTIONS = h.OPTIONS;
 *
 *   // app/api/signup/route.ts
 *   export const POST = withBioKyn(verifier, { secret }, async (req) => Response.json({ ok: true }));
 */
import { createHandler, type HandlerOptions } from '../http.js';
import type { BioKynVerifier } from '../verifier.js';

type RouteHandler = (req: Request, ctx?: unknown) => Promise<Response>;

async function readTextLimited(req: Request, max: number): Promise<string> {
  const reader = req.body?.getReader(); if (!reader) return '';
  const chunks: Uint8Array[] = []; let size = 0;
  try { for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > max) { await reader.cancel(); throw new Error('payload_too_large'); } chunks.push(part.value); } }
  finally { reader.releaseLock(); }
  const all = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder().decode(all);
}

export interface NextHandlerOptions extends HandlerOptions {
  /** Extract a trusted client IP from deployment-controlled headers or platform metadata. Do not trust arbitrary forwarded headers. */
  clientIp?: (req: Request) => string | undefined;
}

export function biokynNext(verifier: BioKynVerifier, opts: NextHandlerOptions = {}): { GET: RouteHandler; POST: RouteHandler; OPTIONS: RouteHandler } {
  const handle = createHandler(verifier, opts);
  const run: RouteHandler = async (req) => {
    const url = new URL(req.url);
    const headers: Record<string, string> = {};
    req.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    let text: string | undefined;
    if (req.method !== 'GET' && req.method !== 'OPTIONS' && req.method !== 'HEAD') {
      const max = opts.maxBodyBytes ?? 65_536;
      const declared = Number(req.headers.get('content-length') ?? 0);
      if (Number.isFinite(declared) && declared > max) return new Response('{"error":"payload_too_large"}', { status: 413, headers: { 'content-type': 'application/json' } });
      const reader = req.body?.getReader();
      if (reader) {
        const chunks: Uint8Array[] = []; let size = 0;
        try { for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > max) { await reader.cancel(); return new Response('{"error":"payload_too_large"}', { status: 413, headers: { 'content-type': 'application/json' } }); } chunks.push(part.value); } }
        finally { reader.releaseLock(); }
        const all = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length; }
        text = new TextDecoder().decode(all);
      }
    }
    const out = await handle({ method: req.method, path: url.pathname, headers, body: text, ip: opts.clientIp?.(req) });
    if (!out) return new Response('{"error":"not_found"}', { status: 404, headers: { 'content-type': 'application/json' } });
    return new Response(out.status === 204 ? null : out.body, { status: out.status, headers: out.headers });
  };
  return { GET: run, POST: run, OPTIONS: run };
}

export interface WithOptions { secret: string; fields?: string[]; maxBodyBytes?: number }

/** Wraps a route handler so it only runs after a valid, unspent BioKyn token is presented. */
export function withBioKyn(verifier: BioKynVerifier, opts: WithOptions, handler: RouteHandler): RouteHandler {
  const fields = opts.fields ?? ['biokyn-token', 'g-recaptcha-response', 'cf-turnstile-response'];
  return async (req, ctx) => {
    let token = req.headers.get('x-biokyn-token') ?? undefined;
    let forward = req;
    if (!token) {
      const maxBody = opts.maxBodyBytes ?? 65_536;
      const contentLength = Number(req.headers.get('content-length') ?? 0);
      if (Number.isFinite(contentLength) && contentLength > maxBody) return Response.json({ error: 'verification_failed' }, { status: 413 });
      const ct = req.headers.get('content-type') ?? '';
      const copy = req.clone();
      forward = copy;
      try {
        if (ct.includes('application/json')) {
          const raw = await readTextLimited(req, maxBody);
          const b = JSON.parse(raw) as Record<string, unknown>;
          token = fields.map((f) => b[f]).find((v): v is string => typeof v === 'string' && v.length > 0);
        } else if (ct.includes('form')) {
          const raw = await readTextLimited(req, maxBody);
          const headers = new Headers(req.headers); headers.delete('content-length');
          const formReq = new Request(req.url, { method: req.method, headers, body: raw });
          const f = await formReq.formData();
          token = fields.map((k) => f.get(k)).find((v): v is string => typeof v === 'string' && v.length > 0);
        }
      } catch { token = undefined; }
    }
    const r = await verifier.verifyToken(opts.secret, token);
    if (!r.success) return Response.json({ error: 'verification_failed' }, { status: 403 });
    return handler(forward, ctx);
  };
}
