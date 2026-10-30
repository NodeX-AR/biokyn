/**
 * Trusted-proxy aware client IP resolution, IP normalization and route-aware rate limiting.
 *
 * Forwarded headers are attacker-controlled unless the TCP peer is a proxy you operate. The resolver therefore
 * trusts a forwarded header ONLY when the socket peer is inside `trustedProxies`, and then walks X-Forwarded-For
 * from the right, skipping trusted proxy hops, so spoofed left-hand entries are never believed.
 */
import { BlockList, isIP } from 'node:net';
import type { HttpRequestLike } from './http.js';

/** Linear-time trailing slash trim. Avoids quadratic backtracking of /\/+$/ on adversarial input. */
function trimTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47 /* '/' */) end--;
  return end === s.length ? s : s.slice(0, end);
}


export interface ClientIpOptions {
  /** IPs or CIDRs of proxies/load balancers you operate. Empty/omitted = never trust forwarded headers. */
  trustedProxies?: readonly string[];
  /** Header carrying the chain. Default x-forwarded-for. Use a single-value header (e.g. cf-connecting-ip) only if your edge overwrites it. */
  header?: string;
  /** Maximum chain length considered (defence against header stuffing). Default 16. */
  maxHops?: number;
}

/** Canonical textual form: lower-case, zone id removed, IPv4-mapped IPv6 collapsed to IPv4, IPv6 fully expanded. */
export function normalizeIp(input: string | undefined): string | undefined {
  if (!input) return undefined;
  let ip = input.trim().toLowerCase();
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  const zone = ip.indexOf('%'); if (zone >= 0) ip = ip.slice(0, zone);
  const v = isIP(ip);
  if (v === 4) return ip.split('.').map((o) => String(Number(o))).join('.');
  if (v !== 6) return undefined;
  const mapped = /^(?:0{0,4}:){0,5}:?ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip) ?? /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
  if (mapped && isIP(mapped[1]!) === 4) return normalizeIp(mapped[1]);
  return expandIPv6(ip);
}
function expandIPv6(ip: string): string | undefined {
  let tail = '';
  // Extract trailing IPv4 dotted-quad without regex (avoids polynomial backtracking on dot-heavy input).
  const lastColon = ip.lastIndexOf(':');
  if (lastColon >= 0 && ip.indexOf('.', lastColon) > 0) {
    const v4part = ip.slice(lastColon + 1);
    const parts = v4part.split('.');
    if (parts.length === 4 && parts.every((p) => {
      if (p.length === 0 || p.length > 3) return false;
      for (let i = 0; i < p.length; i++) if (p.charCodeAt(i) < 48 || p.charCodeAt(i) > 57) return false;
      return true;
    })) {
      const o = parts.map(Number);
      if (o.every((n) => n >= 0 && n <= 255)) {
        ip = ip.slice(0, lastColon + 1) + ((o[0]! << 8) | o[1]!).toString(16) + ':' + ((o[2]! << 8) | o[3]!).toString(16);
      }
    }
  }
  void tail;
  const halves = ip.split('::');
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(':') : [], rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - rest.length;
  if ((halves.length === 1 && head.length !== 8) || missing < (halves.length === 2 ? 1 : 0)) return undefined;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...rest];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return undefined;
  return groups.map((g) => g.padStart(4, '0')).join(':');
}

/** Rate-limit bucket: IPv4 -> the address; IPv6 -> its /64 (one subscriber commonly controls the whole /64). */
export function rateLimitBucket(ip: string | undefined): string {
  const n = normalizeIp(ip);
  if (!n) return 'unknown';
  return n.includes(':') ? `v6:${n.split(':').slice(0, 4).join(':')}` : `v4:${n}`;
}

export function createClientIpResolver(opts: ClientIpOptions = {}): (req: Pick<HttpRequestLike, 'ip' | 'headers'>) => string | undefined {
  const trusted = new BlockList();
  for (const entry of opts.trustedProxies ?? []) {
    const [addr, bits] = entry.split('/');
    const family = isIP(addr ?? '') === 6 ? 'ipv6' : 'ipv4';
    if (!addr || !isIP(addr)) throw new RangeError(`invalid trusted proxy entry: ${entry}`);
    if (bits === undefined) trusted.addAddress(addr, family);
    else { const p = Number(bits); if (!Number.isInteger(p) || p < 0 || p > (family === 'ipv6' ? 128 : 32)) throw new RangeError(`invalid CIDR prefix: ${entry}`); trusted.addSubnet(addr, p, family); }
  }
  const header = (opts.header ?? 'x-forwarded-for').toLowerCase();
  const maxHops = opts.maxHops ?? 16;
  const isTrusted = (ip: string): boolean => trusted.check(ip, ip.includes(':') ? 'ipv6' : 'ipv4');
  return (req) => {
    const peer = normalizeIp(req.ip);
    if (!peer) return undefined;
    if (!(opts.trustedProxies?.length) || !isTrusted(peer)) return peer;
    const raw = req.headers[header];
    if (!raw || raw.length > 2048) return peer;
    const chain = raw.split(',').map((s) => s.trim()).filter(Boolean);
    if (chain.length === 0 || chain.length > maxHops) return peer;
    for (let i = chain.length - 1; i >= 0; i--) {
      const hop = normalizeIp(chain[i]);
      if (!hop) return peer;                       // malformed entry: distrust the whole header
      if (!isTrusted(hop) || i === 0) return hop;  // first untrusted hop from the right (or the leftmost entry)
    }
    return peer;
  };
}

export interface RateLimitStore { allowRateLimit(key: string, limit: number, windowMs: number): boolean | Promise<boolean> }
export interface RouteLimit { limit: number; windowMs: number }
export interface RateLimiterOptions {
  store: RateLimitStore;
  clientIp?: ClientIpOptions;
  basePath?: string;
  /** Per-IP limits by route class. Defaults are conservative starting points, not tuned values. */
  limits?: Partial<Record<'challenge' | 'issue' | 'register' | 'siteverify' | 'other', RouteLimit>>;
}
const DEFAULT_LIMITS: Record<'challenge' | 'issue' | 'register' | 'siteverify' | 'other', RouteLimit> = {
  challenge: { limit: 60, windowMs: 60_000 }, issue: { limit: 20, windowMs: 60_000 }, register: { limit: 6, windowMs: 60_000 },
  siteverify: { limit: 600, windowMs: 60_000 }, other: { limit: 60, windowMs: 60_000 },
};

/** Builds the `rateLimit` callback for createHandler. Route class + normalized client bucket form the key. */
export function createRateLimiter(opts: RateLimiterOptions): (req: HttpRequestLike) => Promise<boolean> {
  const resolve = createClientIpResolver(opts.clientIp);
  const base = trimTrailingSlashes(opts.basePath ?? '/biokyn');
  const limits = { ...DEFAULT_LIMITS, ...opts.limits };
  return async (req) => {
    const path = trimTrailingSlashes(req.path) || '/';
    const cls = path === `${base}/challenge` ? 'challenge' : path === `${base}/issue` ? 'issue' : path.startsWith(`${base}/webauthn/register`) ? 'register'
      : /siteverify$/.test(path) ? 'siteverify' : 'other';
    const { limit, windowMs } = limits[cls];
    return await opts.store.allowRateLimit(`${cls}:${rateLimitBucket(resolve(req))}`, limit, windowMs);
  };
}

/** Bounded in-process limiter store for single-instance deployments and tests. Not shared across processes. */
export class MemoryRateLimitStore implements RateLimitStore {
  private readonly hits = new Map<string, number[]>();
  constructor(private readonly now: () => number = Date.now, private readonly maxKeys = 100_000) {}
  allowRateLimit(key: string, limit: number, windowMs: number): boolean {
    const t = this.now(), cutoff = t - windowMs;
    if (this.hits.size >= this.maxKeys && !this.hits.has(key)) { for (const [k, v] of this.hits) if (v.length === 0 || v[v.length - 1]! <= cutoff) this.hits.delete(k); if (this.hits.size >= this.maxKeys) return false; }
    const arr = (this.hits.get(key) ?? []).filter((x) => x > cutoff);
    if (arr.length >= limit) { this.hits.set(key, arr); return false; }
    arr.push(t); this.hits.set(key, arr); return true;
  }
}
