import { describe, expect, it } from 'vitest';
import { BioKyn, biokynMiddleware, createChallengeHandler, withBioKyn } from '../src/middleware.js';
import { MemoryStore, SqliteStore } from '../src/store.js';
import { CLIENT_SCRIPT } from '../src/client.js';
import type { BioKynOptions, NodeRequestLike, RequestInfo } from '../src/types.js';

const SECRET = 'k'.repeat(48);
const ORIGIN = 'https://app.test';

function harness(over: Partial<BioKynOptions> = {}) {
  const clock = { t: 1_800_000_000_000 };
  const now = () => clock.t;
  const store = new MemoryStore({ now, sweepIntervalMs: 60_000 });
  const engine = new BioKyn({ secret: SECRET, store, now, ...over });
  return { clock, now, store, engine };
}

class Client {
  cookie: string | undefined;
  constructor(
    readonly engine: BioKyn,
    public ip = '203.0.113.7',
    public origin = ORIGIN,
  ) {}
  info(): RequestInfo {
    return { ip: this.ip, origin: this.origin, ...(this.cookie ? { cookieHeader: this.cookie } : {}) };
  }
  async issue(formId = 'contact', action = 'POST:/contact') {
    const r = await this.engine.issue(this.info(), formId, action);
    if (r.ok && r.setCookie) this.cookie = r.setCookie.split(';')[0];
    return r;
  }
  async boot(formId = 'contact', action = 'POST:/contact'): Promise<string> {
    const r = await this.issue(formId, action);
    if (!r.ok || !r.bootstrap) throw new Error('expected bootstrap token');
    return r.token;
  }
  async token(formId = 'contact', action = 'POST:/contact'): Promise<string> {
    if (!this.cookie) await this.boot();
    const r = await this.issue(formId, action);
    if (!r.ok || r.bootstrap) throw new Error('expected real token');
    return r.token;
  }
  verify(token: string | undefined, action = 'POST:/contact', formId?: string) {
    return this.engine.verify(this.info(), token, action, formId);
  }
}

describe('BioKyn engine', () => {
  it('valid flow: bootstrap is unusable, real token passes after min age', async () => {
    const { clock, engine } = harness();
    const c = new Client(engine);
    const boot = await c.boot();
    clock.t += 2_000;
    expect(await c.verify(boot)).toMatchObject({ ok: false, reason: 'bootstrap_token' });

    const tok = await c.token();
    expect(await c.verify(tok)).toMatchObject({ ok: false, reason: 'too_fast' });
    clock.t += 2_000;
    expect(await c.verify(tok)).toMatchObject({ ok: true, formId: 'contact' });
  });

  it('rejects missing token, missing session, malformed and forged cookies', async () => {
    const { clock, engine } = harness();
    const c = new Client(engine);
    const tok = await c.token();
    clock.t += 2_000;
    expect(await c.verify(undefined)).toMatchObject({ reason: 'missing_token' });
    expect(await c.verify('garbage')).toMatchObject({ reason: 'malformed' });
    const cookieless = new Client(engine, '198.51.100.1');
    expect(await cookieless.verify(tok)).toMatchObject({ reason: 'no_session' });

    const forged = new Client(engine, '198.51.100.2');
    forged.cookie = '__biokyn_sid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAA';
    const r = await forged.issue();
    expect(r.ok && r.bootstrap).toBe(true);
  });

  it('rejects replay of a consumed token', async () => {
    const { clock, engine } = harness();
    const c = new Client(engine);
    const tok = await c.token();
    clock.t += 2_000;
    expect(await c.verify(tok)).toMatchObject({ ok: true });
    expect(await c.verify(tok)).toMatchObject({ ok: false, reason: 'replayed' });
  });

  it('rejects cross-action, cross-origin, cross-session and cross-form use without burning the token', async () => {
    const { clock, engine } = harness();
    const c = new Client(engine);
    const tok = await c.token('contact', 'POST:/a');
    clock.t += 2_000;

    expect(await c.verify(tok, 'POST:/b')).toMatchObject({ ok: false, reason: 'bad_signature' });

    const evil = new Client(engine);
    evil.cookie = c.cookie;
    evil.origin = 'https://evil.test';
    expect(await evil.verify(tok, 'POST:/a')).toMatchObject({ ok: false, reason: 'bad_signature' });

    const pooled = new Client(engine, '198.51.100.9');
    await pooled.boot();
    expect(await pooled.verify(tok, 'POST:/a')).toMatchObject({ ok: false, reason: 'bad_signature' });

    expect(await c.verify(tok, 'POST:/a', 'newsletter')).toMatchObject({ ok: false, reason: 'form_mismatch' });
    expect(await c.verify(tok, 'POST:/a', 'contact')).toMatchObject({ ok: true });
  });

  it('expires tokens after ttl', async () => {
    const { clock, engine } = harness();
    const c = new Client(engine);
    const tok = await c.token();
    clock.t += 15 * 60_000 + 1;
    expect(await c.verify(tok)).toMatchObject({ ok: false, reason: 'expired' });
  });

  it('enforces per-session challenge quota', async () => {
    const { engine } = harness({ quota: 3 });
    const c = new Client(engine);
    await c.boot();
    for (let i = 0; i < 3; i++) await c.token();
    expect(await c.issue()).toMatchObject({ ok: false, reason: 'rate_limited' });
  });

  it('throttles cookie-clearing loops via the anonymous per-IP quota', async () => {
    const { engine } = harness({ anonQuota: 2 });
    expect((await new Client(engine).issue()).ok).toBe(true);
    expect((await new Client(engine).issue()).ok).toBe(true);
    expect(await new Client(engine).issue()).toMatchObject({ ok: false, reason: 'rate_limited' });
  });

  it('enforces verification quota and resets after the window', async () => {
    const { clock, engine } = harness({ verifyQuota: 2 });
    const c = new Client(engine);
    const tok = await c.token();
    expect(await c.verify(tok)).toMatchObject({ reason: 'too_fast' });
    expect(await c.verify(tok)).toMatchObject({ reason: 'too_fast' });
    expect(await c.verify(tok)).toMatchObject({ ok: false, reason: 'rate_limited' });
    clock.t += 10 * 60_000 + 1;
    expect(await c.verify(tok)).toMatchObject({ ok: true });
  });

  it('rejects short secrets', () => {
    expect(() => new BioKyn({ secret: 'short', store: new MemoryStore() })).toThrow();
  });
});

describe('MemoryStore', () => {
  it('honours TTLs for setNx/incr and sweeps expired keys', async () => {
    const clock = { t: 1_000 };
    const s = new MemoryStore({ now: () => clock.t });
    expect(await s.setNx('a', 100)).toBe(true);
    expect(await s.setNx('a', 100)).toBe(false);
    expect(await s.incr('n', 100)).toBe(1);
    expect(await s.incr('n', 100)).toBe(2);
    clock.t += 101;
    expect(await s.setNx('a', 100)).toBe(true);
    expect(await s.incr('n', 100)).toBe(1);
    clock.t += 101;
    s.sweep();
    expect(s.size).toBe(0);
    await s.close();
  });
});

const sqliteMod: { default: new (path: string) => never } | null = await import(
  /* @vite-ignore */ ['better-sqlite3'].join('')
).catch(() => null);

describe.skipIf(!sqliteMod)('SqliteStore', () => {
  it('implements setNx/incr with TTL and batched sweep', async () => {
    const Database = sqliteMod!.default as unknown as new (p: string) => {
      prepare(sql: string): { get(): { c: number } };
    };
    const db = new Database(':memory:') as never;
    const clock = { t: 5_000 };
    const s = new SqliteStore(db, () => clock.t);
    expect(await s.setNx('r', 100)).toBe(true);
    expect(await s.setNx('r', 100)).toBe(false);
    expect(await s.incr('c', 100)).toBe(1);
    expect(await s.incr('c', 100)).toBe(2);
    for (let i = 0; i < 1_200; i++) await s.incr(`bulk:${i}`, 100);
    clock.t += 101;
    expect(s.sweep()).toBeGreaterThanOrEqual(1_200);
    expect(await s.setNx('r', 100)).toBe(true);
  });
});

class FakeRes {
  statusCode = 200;
  headers = new Map<string, unknown>();
  body = '';
  setHeader(n: string, v: unknown) {
    this.headers.set(n.toLowerCase(), v);
  }
  getHeader(n: string) {
    return this.headers.get(n.toLowerCase());
  }
  end(b?: string) {
    this.body = b ?? '';
  }
}

async function run(mw: ReturnType<typeof biokynMiddleware>, req: NodeRequestLike) {
  const res = new FakeRes();
  let nexted = false;
  await mw(req, res, () => {
    nexted = true;
  });
  return { res, nexted };
}

describe('Express middleware', () => {
  it('serves challenges and guards unsafe routes end to end', async () => {
    const { clock, now, store } = harness();
    const mw = biokynMiddleware({ secret: SECRET, store, now });
    const q = `/__biokyn/challenge?form=contact&action=${encodeURIComponent('POST:/contact')}`;
    const getHeaders = (cookie?: string) => ({
      host: 'app.test',
      referer: `${ORIGIN}/contact`,
      ...(cookie ? { cookie } : {}),
    });

    const first = await run(mw, { method: 'GET', url: q, headers: getHeaders(), ip: '203.0.113.7' });
    expect(first.res.statusCode).toBe(200);
    expect(JSON.parse(first.res.body).bootstrap).toBe(true);
    const cookie = String((first.res.getHeader('set-cookie') as string[])[0]).split(';')[0]!;
    expect(String((first.res.getHeader('set-cookie') as string[])[0])).toContain('HttpOnly');
    expect(String((first.res.getHeader('set-cookie') as string[])[0])).toContain('SameSite=Lax');

    const second = await run(mw, { method: 'GET', url: q, headers: getHeaders(cookie), ip: '203.0.113.7' });
    const { token, bootstrap } = JSON.parse(second.res.body);
    expect(bootstrap).toBe(false);
    clock.t += 2_000;

    const post = (tok?: string): NodeRequestLike => ({
      method: 'POST',
      url: '/contact',
      ip: '203.0.113.7',
      headers: { host: 'app.test', origin: ORIGIN, cookie, ...(tok ? { 'x-biokyn-token': tok } : {}) },
    });

    const ok = post(token);
    const passed = await run(mw, ok);
    expect(passed.nexted).toBe(true);
    expect(ok.biokyn?.formId).toBe('contact');

    const replay = await run(mw, post(token));
    expect(replay.nexted).toBe(false);
    expect(replay.res.statusCode).toBe(403);
    expect(JSON.parse(replay.res.body).reason).toBe('replayed');

    const missing = await run(mw, post());
    expect(JSON.parse(missing.res.body).reason).toBe('missing_token');

    const safe = await run(mw, { method: 'GET', url: '/page', headers: getHeaders(cookie) });
    expect(safe.nexted).toBe(true);
  });
});

describe('Next.js App Router wrapper', () => {
  it('guards a route handler with single-use tokens', async () => {
    const { clock, now, store } = harness();
    const engine = new BioKyn({ secret: SECRET, store, now });
    const challenge = createChallengeHandler(engine);
    const guarded = withBioKyn(async () => new Response('ok'), { engine });
    const url = `${ORIGIN}/api/biokyn/challenge?form=contact&action=${encodeURIComponent('POST:/api/contact')}`;

    const r1 = await challenge(new Request(url));
    expect((await r1.json()).bootstrap).toBe(true);
    const cookie = r1.headers.get('set-cookie')!.split(';')[0]!;
    const r2 = await challenge(new Request(url, { headers: { cookie } }));
    const { token } = await r2.json();
    clock.t += 2_000;

    const mk = () =>
      new Request(`${ORIGIN}/api/contact`, {
        method: 'POST',
        headers: { cookie, origin: ORIGIN, 'x-biokyn-token': token },
        body: 'a=1',
      });
    const good = await guarded(mk(), {});
    expect(good.status).toBe(200);
    expect(await good.text()).toBe('ok');
    const again = await guarded(mk(), {});
    expect(again.status).toBe(403);
    expect((await again.json()).reason).toBe('replayed');
  });
});

describe('client script', () => {
  it('stays under 1.5KB', () => {
    expect(Buffer.byteLength(CLIENT_SCRIPT, 'utf8')).toBeLessThan(1500);
  });
});
