#!/usr/bin/env node
/**
 * Dependency-free load generator for a running BioKyn deployment.
 *
 *   node scripts/load-test.mjs --target https://verify.example.com --scenario challenge --duration 30 --concurrency 50 [--origin https://shop.example.com]
 *
 * Scenarios: challenge (GET /biokyn/challenge), issue-invalid (POST malformed /biokyn/issue: exercises parsing, rate limits
 * and store round trips without minting tokens), siteverify-invalid (POST a bogus token). It reports latency percentiles and
 * status counts, and EXITS NON-ZERO if any response is a 5xx other than a deliberate 503 (fail-closed) or if the p99 exceeds --max-p99-ms.
 * Run it against staging, with the production Redis topology, before relying on capacity numbers.
 */
const a = process.argv.slice(2);
const opt = (n, d) => { const i = a.indexOf(`--${n}`); return i >= 0 ? a[i + 1] : d; };
const target = opt('target'); if (!target) { console.error('--target is required'); process.exit(2); }
const scenario = opt('scenario', 'challenge'), duration = Number(opt('duration', 30)) * 1000, conc = Number(opt('concurrency', 50));
const origin = opt('origin', target), maxP99 = Number(opt('max-p99-ms', 1000)), base = opt('base-path', '/biokyn');
const secret = opt('secret', 'load-test-secret');

const request = {
  challenge: () => fetch(`${target}${base}/challenge`, { headers: { origin } }),
  'issue-invalid': () => fetch(`${target}${base}/issue`, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify({ version: 2, challengeId: 'x'.repeat(20) }) }),
  'siteverify-invalid': () => fetch(`${target}/siteverify`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ secret, response: 'AAAA' }) }),
}[scenario];
if (!request) { console.error(`unknown scenario ${scenario}`); process.exit(2); }

const lat = [], codes = new Map(); let errors = 0; const end = Date.now() + duration;
await Promise.all(Array.from({ length: conc }, async () => {
  while (Date.now() < end) {
    const t0 = performance.now();
    try { const r = await request(); await r.arrayBuffer(); codes.set(r.status, (codes.get(r.status) ?? 0) + 1); }
    catch { errors++; }
    lat.push(performance.now() - t0);
  }
}));
lat.sort((x, y) => x - y);
const q = (p) => lat[Math.min(lat.length - 1, Math.floor(p * lat.length))] ?? NaN;
const bad5xx = [...codes].filter(([c]) => c >= 500 && c !== 503).reduce((n, [, v]) => n + v, 0);
const report = { scenario, target, requests: lat.length, rps: +(lat.length / (duration / 1000)).toFixed(1), networkErrors: errors, statuses: Object.fromEntries(codes), p50: +q(0.5).toFixed(1), p95: +q(0.95).toFixed(1), p99: +q(0.99).toFixed(1) };
console.log(JSON.stringify(report, null, 2));
if (bad5xx > 0) { console.error(`FAIL: ${bad5xx} unexpected 5xx responses`); process.exit(1); }
if (report.p99 > maxP99) { console.error(`FAIL: p99 ${report.p99}ms > ${maxP99}ms`); process.exit(1); }
