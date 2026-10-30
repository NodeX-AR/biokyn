#!/usr/bin/env node
/**
 * Writes the official RFC 9497 ristretto255-SHA512 vectors used by test/rfc9497.official.test.ts.
 *
 *   npm run vectors:fetch                         download https://www.rfc-editor.org/rfc/rfc9497.txt
 *   npm run vectors:fetch -- --file rfc9497.txt   parse a copy you saved yourself (offline / proxy-blocked machines)
 *
 * On any failure it prints ONE clear reason, and (if the document was obtained but could not be parsed) saves it to
 * ./rfc9497.debug.txt so the parser can be fixed against the real text.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { parseRfc9497 } from './rfc9497-parse.mjs';

const out = new URL('../packages/protocol/test/vectors/rfc9497-ristretto255-sha512.json', import.meta.url);
const args = process.argv.slice(2);
const fileIdx = args.indexOf('--file');
const url = process.env.RFC9497_URL ?? 'https://www.rfc-editor.org/rfc/rfc9497.txt';
const fail = (msg) => { console.error(`\nvectors:fetch FAILED: ${msg}\n`); process.exit(1); };

let text, source;
try {
  if (fileIdx >= 0) {
    const path = args[fileIdx + 1];
    if (!path) fail('--file needs a path');
    source = path; text = readFileSync(path, 'utf8');
  } else {
    source = url;
    let res;
    try { res = await fetch(url, { headers: { 'user-agent': 'biokyn-vectors/1.0' }, signal: AbortSignal.timeout(30_000) }); }
    catch (e) { fail(`could not download ${url}\n  reason: ${e?.cause?.code ?? e?.cause?.message ?? e?.message ?? e}\n  (proxy/firewall/offline?) Save the page in a browser as rfc9497.txt and run:\n    npm run vectors:fetch -- --file rfc9497.txt`); }
    if (!res.ok) fail(`HTTP ${res.status} from ${url}`);
    text = await res.text();
  }
} catch (e) { fail(`could not read input: ${e?.message ?? e}`); }

let sets;
try { sets = parseRfc9497(text); }
catch (e) {
  writeFileSync('rfc9497.debug.txt', text);
  const i = text.search(/A\.1\.\s+ristretto255/i);
  fail(`downloaded ${text.length} bytes from ${source} but the parser rejected it: ${e.message}\n  Saved the document to ./rfc9497.debug.txt.\n  "A.1. ristretto255" found at offset ${i}. Please send me the 40 lines starting there:\n    (Get-Content rfc9497.debug.txt) | Select-String -Pattern 'A\\.1\\.' -Context 0,40 | Select-Object -First 1`);
}
mkdirSync(new URL('./', out), { recursive: true });
writeFileSync(out, JSON.stringify(sets, null, 2) + '\n');
const n = sets.reduce((a, s) => a + s.vectors.length, 0);
console.log(`OK: wrote ${n} vectors in ${sets.length} sets from ${source} (sha256 ${createHash('sha256').update(text).digest('hex').slice(0, 16)}…)`);
console.log(`    ${sets.map((s) => `mode ${s.mode}: ${s.vectors.length} vectors`).join(', ')}`);
