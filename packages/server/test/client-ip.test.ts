import { describe, expect, it } from 'vitest';
import { MemoryRateLimitStore, createClientIpResolver, createRateLimiter, normalizeIp, rateLimitBucket } from '../src/index.js';

const req = (ip: string | undefined, xff?: string) => ({ ip, headers: xff === undefined ? {} : { 'x-forwarded-for': xff } });

describe('IP normalization', () => {
  it('canonicalizes IPv4, IPv4-mapped IPv6, zones, brackets and IPv6 expansion', () => {
    expect(normalizeIp('203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeIp('::ffff:203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeIp('[2001:DB8::1]')).toBe('2001:0db8:0000:0000:0000:0000:0000:0001');
    expect(normalizeIp('fe80::1%eth0')).toBe('fe80:0000:0000:0000:0000:0000:0000:0001');
    expect(normalizeIp('2001:db8::')).toBe('2001:0db8:0000:0000:0000:0000:0000:0000');
    for (const bad of ['', 'nope', '999.1.1.1', '1.2.3', '1::2::3', undefined]) expect(normalizeIp(bad as string)).toBeUndefined();
  });
  it('buckets IPv6 by /64 and falls back to a shared "unknown" bucket', () => {
    expect(rateLimitBucket('2001:db8:1:2:aaaa::1')).toBe(rateLimitBucket('2001:db8:1:2:bbbb::9'));
    expect(rateLimitBucket('2001:db8:1:3::1')).not.toBe(rateLimitBucket('2001:db8:1:2::1'));
    expect(rateLimitBucket(undefined)).toBe('unknown');
  });
});

describe('trusted-proxy resolution', () => {
  const resolve = createClientIpResolver({ trustedProxies: ['10.0.0.0/8', '2001:db8:ffff::/48'] });
  it('ignores forwarded headers from untrusted peers (spoofing)', () => { expect(resolve(req('198.51.100.9', '1.2.3.4'))).toBe('198.51.100.9'); });
  it('walks X-Forwarded-For from the right, skipping trusted hops', () => {
    expect(resolve(req('10.1.1.1', '6.6.6.6, 203.0.113.5, 10.2.2.2'))).toBe('203.0.113.5');
    expect(resolve(req('10.1.1.1', '203.0.113.5'))).toBe('203.0.113.5');
    expect(resolve(req('10.1.1.1', '10.3.3.3, 10.2.2.2'))).toBe('10.3.3.3');
  });
  it('distrusts malformed, empty, oversized or over-long chains', () => {
    for (const x of ['garbage', '203.0.113.5, ??', '', ',', 'a'.repeat(3000), Array(40).fill('1.1.1.1').join(',')]) expect(resolve(req('10.1.1.1', x))).toBe('10.1.1.1');
  });
  it('trusts nothing by default and validates configuration', () => {
    expect(createClientIpResolver()(req('10.1.1.1', '1.2.3.4'))).toBe('10.1.1.1');
    expect(() => createClientIpResolver({ trustedProxies: ['not-an-ip'] })).toThrow(RangeError);
    expect(() => createClientIpResolver({ trustedProxies: ['10.0.0.0/40'] })).toThrow(RangeError);
  });
});

describe('route-aware rate limiter', () => {
  it('limits per route class and per client bucket, honouring the forwarded client', async () => {
    let t = 0; const store = new MemoryRateLimitStore(() => t);
    const limit = createRateLimiter({ store, clientIp: { trustedProxies: ['10.0.0.0/8'] }, limits: { issue: { limit: 2, windowMs: 1000 } } });
    const r = (xff: string, path = '/biokyn/issue') => ({ method: 'POST', path, headers: { 'x-forwarded-for': xff }, ip: '10.0.0.1' } as never);
    expect(await limit(r('203.0.113.1'))).toBe(true);
    expect(await limit(r('203.0.113.1'))).toBe(true);
    expect(await limit(r('203.0.113.1'))).toBe(false);
    expect(await limit(r('203.0.113.2'))).toBe(true);                       // other client unaffected
    expect(await limit(r('203.0.113.1', '/biokyn/challenge'))).toBe(true);   // other route class unaffected
    t = 1001; expect(await limit(r('203.0.113.1'))).toBe(true);              // window slides
  });
  it('the memory store is bounded and fails closed when full', () => {
    const s = new MemoryRateLimitStore(() => 0, 2);
    expect(s.allowRateLimit('a', 5, 1000)).toBe(true); expect(s.allowRateLimit('b', 5, 1000)).toBe(true);
    expect(s.allowRateLimit('c', 5, 1000)).toBe(false);
  });
});
