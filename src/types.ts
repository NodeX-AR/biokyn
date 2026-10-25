export interface Store {
  /** Atomically create `key` with TTL if absent. Resolves true only for the caller that created it. */
  setNx(key: string, ttlMs: number): Promise<boolean>;
  /** Atomically increment a fixed-window counter (TTL starts on first increment). Resolves the new count. */
  incr(key: string, ttlMs: number): Promise<number>;
  close?(): Promise<void> | void;
}

/** ioredis-compatible subset. */
export interface RedisLike {
  set(key: string, value: string, mode: 'EX', seconds: number, flag: 'NX'): Promise<unknown>;
  eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<unknown>;
  quit?(): Promise<unknown>;
}

/** node-redis v4 compatible subset (use adaptNodeRedis). */
export interface NodeRedisLike {
  set(key: string, value: string, opts: { EX: number; NX: true }): Promise<unknown>;
  eval(script: string, opts: { keys: string[]; arguments: string[] }): Promise<unknown>;
  quit(): Promise<unknown>;
}

export interface SqliteStatement {
  run(...params: unknown[]): { changes: number | bigint };
  get(...params: unknown[]): unknown;
}

/** better-sqlite3 compatible subset. */
export interface SqliteLike {
  exec(sql: string): unknown;
  prepare(sql: string): SqliteStatement;
}

export interface BioKynOptions {
  /** HMAC secret, >= 32 bytes. Must be identical across nodes. */
  secret: string | Uint8Array;
  store: Store;
  /** Challenge lifetime. Default 15 min. */
  ttlMs?: number;
  /** Minimum time between issue and submit. Default 1500. */
  minAgeMs?: number;
  /** Tolerated clock skew. Default 5000. */
  clockSkewMs?: number;
  /** Challenges per session per window. Default 20. */
  quota?: number;
  /** Cookieless (bootstrap) challenges per IP per window. Default 10. */
  anonQuota?: number;
  /** Verification attempts per session per window. Default 30. */
  verifyQuota?: number;
  /** Counter window. Default 10 min. */
  windowMs?: number;
  /** Canonical origin (e.g. https://example.com). Strongly recommended behind proxies. */
  origin?: string;
  /** Trust X-Forwarded-For / X-Forwarded-Proto. Default false. */
  trustProxy?: boolean;
  /** Secure cookie flag. Default: NODE_ENV === 'production'. */
  secureCookie?: boolean;
  cookieName?: string;
  /** Session cookie lifetime. Default 7 days. */
  sessionTtlMs?: number;
  /** Clock injection (tests). */
  now?: () => number;
}

export interface ResolvedOptions {
  store: Store;
  ttlMs: number;
  minAgeMs: number;
  clockSkewMs: number;
  quota: number;
  anonQuota: number;
  verifyQuota: number;
  windowMs: number;
  origin?: string | undefined;
  trustProxy: boolean;
  secureCookie: boolean;
  cookieName: string;
  sessionTtlMs: number;
  now: () => number;
}

export interface RequestInfo {
  ip: string;
  /** Resolved origin the token is bound to. */
  origin: string;
  /** Raw Origin header when present and not "null". */
  originHeader?: string | undefined;
  cookieHeader?: string | undefined;
}

export interface OriginHints {
  origin?: string | undefined;
  referer?: string | undefined;
  host?: string | undefined;
  proto: string;
}

/** Everything a token is cryptographically bound to (besides ts/nonce/flags). */
export interface ChallengeContext {
  formId: string;
  origin: string;
  sid: string;
  action: string;
}

export interface TokenBinding extends ChallengeContext {
  ts: number;
  nonce: string;
  /** 0 = normal, 1 = bootstrap (zero-quota, never verifiable). */
  flags: number;
}

export interface ParsedToken {
  ts: number;
  nonce: string;
  flags: number;
  formId: string;
  mac: Buffer;
}

export type VerifyReason =
  | 'missing_token'
  | 'malformed'
  | 'no_session'
  | 'origin_mismatch'
  | 'form_mismatch'
  | 'rate_limited'
  | 'bad_signature'
  | 'bootstrap_token'
  | 'too_fast'
  | 'expired'
  | 'replayed';

export type VerifyResult =
  | { ok: true; formId: string; issuedAt: number }
  | { ok: false; reason: VerifyReason; retryAfterMs?: number };

export type IssueResult =
  | {
      ok: true;
      token: string;
      bootstrap: boolean;
      issuedAt: number;
      ttlMs: number;
      minAgeMs: number;
      setCookie?: string;
    }
  | { ok: false; reason: 'rate_limited' | 'bad_request' | 'origin_mismatch'; retryAfterMs?: number };

export interface VerifiedInfo {
  formId: string;
  issuedAt: number;
}

export interface NodeRequestLike {
  method?: string;
  url?: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string | undefined; encrypted?: boolean };
  ip?: string | undefined;
  body?: unknown;
  biokyn?: VerifiedInfo;
}

export interface NodeResponseLike {
  statusCode: number;
  setHeader(name: string, value: string | string[] | number): unknown;
  getHeader(name: string): unknown;
  end(chunk?: string): unknown;
}

export interface BioKynMiddlewareOptions extends BioKynOptions {
  /** Mount path for the challenge + client script endpoints. Default /__biokyn. */
  basePath?: string;
  /** Which requests must carry a valid token. Default: POST/PUT/PATCH/DELETE outside basePath. */
  shouldProtect?: (method: string, path: string) => boolean;
  /** Action label bound into the token. Default `${METHOD}:${pathname}`. */
  actionFor?: (method: string, path: string) => string;
  /** Token extractor. Default: x-biokyn-token header, then parsed body `_biokyn`. */
  getToken?: (req: NodeRequestLike) => string | undefined;
  getIp?: (req: NodeRequestLike) => string;
}
