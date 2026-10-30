/** Seeded fuzzing of every untrusted entry point. The handler must never answer 500 or throw. FUZZ_SEED overrides the seed. */
import { describe, expect, it } from 'vitest';
import { base64urlEncode } from '@biokyn/protocol';
import { CborError, createHandler, decodeCbor, verifyRegistration } from '../src/index.js';
import { ORIGIN, buildRequest, makeVerifier } from './helpers.js';

const seed = Number(process.env.FUZZ_SEED ?? 4242);
const rng = (() => { let s = seed >>> 0 || 1; return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 2 ** 32; }; })();
const pick = <T>(a: readonly T[]): T => a[Math.floor(rng() * a.length)]!;
const junk = (): unknown => pick([null, undefined, 0, -1, 1e308, NaN, '', 'x'.repeat(5000), '../../etc/passwd', true, [], {}, [1, 2], { a: { b: {} } }, '\u0000', '💥', 2 ** 53]);
function mutate(v: unknown, depth = 0): unknown {
  if (Array.isArray(v)) return rng() < 0.3 ? junk() : v.map((x) => (rng() < 0.2 ? mutate(x, depth + 1) : x));
  if (v && typeof v === 'object') {
    const o: Record<string, unknown> = { ...(v as object) }; const keys = Object.keys(o);
    if (keys.length && rng() < 0.7) { const k = pick(keys); if (rng() < 0.25) delete o[k]; else o[k] = rng() < 0.5 || depth > 3 ? junk() : mutate(o[k], depth + 1); }
    if (rng() < 0.1) o[pick(['__proto__', 'constructor', 'extra'])] = junk();
    return o;
  }
  return rng() < 0.5 ? junk() : v;
}

describe(`handler fuzz (seed ${seed})`, () => {
  it('mutated /issue, /motion-step-up and registration bodies never cause a 500 or an exception', async () => {
    const { verifier } = makeVerifier({ webauthnStepUp: true, webauthnRegistration: { enabled: true } });
    const handle = createHandler(verifier);
    const statuses = new Map<number, number>();
    // Real Argon2id makes each valid request cost ~1 s, so mutate from a pre-built pool instead of solving per iteration.
    const pool = Array.from({ length: 16 }, (_, k) => { const ch = verifier.challenge(ORIGIN); return { ch, req: buildRequest(ch, k % 2 ? { pow: true } : {}).req }; });
    for (let i = 0; i < 400; i++) {
      const { ch, req: base } = pick(pool);
      const target = pick(['/biokyn/issue', '/biokyn/motion-step-up', '/biokyn/webauthn/register/options', '/biokyn/webauthn/register/verify'] as const);
      const body = target === '/biokyn/issue' ? mutate(base) : mutate({ challengeId: ch.challengeId, modality: 'pointer', durationMs: 1000, samples: 20, corrections: 2, pathRatioMilli: 1500, speedCvMilli: 300, pow: base.pow, credential: { id: 'a', attestationObject: 'b', clientDataJSON: 'c' } });
      const res = await handle({ method: 'POST', path: target, headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify(body) });
      expect(res).toBeTruthy();
      statuses.set(res!.status, (statuses.get(res!.status) ?? 0) + 1);
      if (res!.status >= 500 && res!.status !== 503) throw new Error(`seed ${seed} iteration ${i}: HTTP ${res!.status} for ${JSON.stringify(body).slice(0, 300)}`);
    }
    expect([...statuses.keys()].every((s) => s < 500)).toBe(true);
  }, 180_000);
  it('raw garbage bodies, wrong content types and hostile headers are rejected cleanly', async () => {
    const handle = createHandler(makeVerifier().verifier);
    for (let i = 0; i < 200; i++) {
      const raw = pick(['', '{', '[]', 'null', '"x"', '{"a":'.repeat(50), '\u0000\u0001', 'x'.repeat(70_000), JSON.stringify({ __proto__: { polluted: true } })]);
      const res = await handle({ method: pick(['POST', 'GET', 'PUT', 'DELETE'] as const), path: pick(['/biokyn/issue', '/biokyn/challenge', '/biokyn/nope', '/biokyn/issue/']), headers: { origin: pick([ORIGIN, 'null', 'https://evil.example', '']), 'content-type': pick(['application/json', 'text/plain', '', 'application/json; charset=utf-16']) }, body: raw });
      if (res) expect(res.status).toBeLessThan(500);
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
  it('CBOR and registration verification fail only in controlled ways on arbitrary bytes', async () => {
    for (let i = 0; i < 1500; i++) {
      const b = Uint8Array.from({ length: Math.floor(rng() * 120) }, () => Math.floor(rng() * 256));
      try { decodeCbor(b); } catch (e) { if (!(e instanceof CborError)) throw new Error(`seed ${seed}: ${String(e)}`); }
    }
    for (let i = 0; i < 200; i++) {
      const r = await verifyRegistration({ id: 'x', attestationObject: base64urlEncode(Uint8Array.from({ length: 60 }, () => Math.floor(rng() * 256))), clientDataJSON: base64urlEncode(new TextEncoder().encode(JSON.stringify(mutate({ type: 'webauthn.create', challenge: 'a', origin: ORIGIN })))) }, { origin: ORIGIN, rpId: 'shop.example.com', expectedChallenge: new Uint8Array(32) });
      expect(r.ok).toBe(false);
    }
  });
});
