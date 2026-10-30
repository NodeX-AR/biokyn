#!/usr/bin/env node
/**
 * fix-redos.mjs — apply ReDoS fixes for OpenSSF/CodeQL alerts #1–#7.
 *
 * Usage (from repo root):
 *   node scripts/fix-redos.mjs            → dry run (prints what would change)
 *   node scripts/fix-redos.mjs --write    → apply, back up originals to .bak
 *   node scripts/fix-redos.mjs --rollback → restore .bak files
 */
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const MODE = process.argv.includes('--write') ? 'write'
           : process.argv.includes('--rollback') ? 'rollback'
           : 'dry';
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const TARGETS = [
  'packages/server/src/http.ts',
  'packages/server/src/client-ip.ts',
  'packages/client/src/webauthn.ts',
  'packages/client/src/index.ts',
];

const HELPER = `
/** Linear-time trailing slash trim. Avoids quadratic backtracking of /\\/+$/ on adversarial input. */
function trimTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47 /* '/' */) end--;
  return end === s.length ? s : s.slice(0, end);
}
`;

// Order matters: longest / most specific receiver first.
const TRIM_REPLACEMENTS = [
  ["(opts.basePath ?? '/biokyn').replace(/\\/+$/, '')", "trimTrailingSlashes(opts.basePath ?? '/biokyn')"],
  ["rawPath.replace(/\\/+$/, '')", "trimTrailingSlashes(rawPath)"],
  ["req.path.replace(/\\/+$/, '')", "trimTrailingSlashes(req.path)"],
];

const IPV4_OLD = `  const v4 = /(\\d+\\.\\d+\\.\\d+\\.\\d+)$/.exec(ip);
  if (v4) { const o = v4[1]!.split('.').map(Number); ip = ip.slice(0, -v4[1]!.length) + ((o[0]! << 8) | o[1]!).toString(16) + ':' + ((o[2]! << 8) | o[3]!).toString(16); }`;

const IPV4_NEW = `  // Extract trailing IPv4 dotted-quad without regex (avoids polynomial backtracking on dot-heavy input).
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
  }`;

function rollback() {
  for (const rel of TARGETS) {
    const bak = join(ROOT, rel + '.bak');
    if (existsSync(bak)) {
      writeFileSync(join(ROOT, rel), readFileSync(bak));
      unlinkSync(bak);
      console.log(`restored: ${rel}`);
    }
  }
  console.log('Rollback complete.');
}

function processFile(rel) {
  const path = join(ROOT, rel);
  if (!existsSync(path)) { console.log(`SKIP (not found): ${rel}`); return; }
  let src = readFileSync(path, 'utf8');
  const before = src;
  let changed = false;

  // 1. Trailing-slash pattern
  for (const [from, to] of TRIM_REPLACEMENTS) {
    if (src.includes(from)) {
      const count = src.split(from).length - 1;
      src = src.split(from).join(to);
      console.log(`  ${rel}: replaced ${count}x  ${from.slice(0, 60)}...`);
      changed = true;
    }
  }

  // 2. Inject helper after last import if we changed anything
  if (changed && !src.includes('function trimTrailingSlashes')) {
    const lines = src.split('\n');
    let insertAt = 0;
    for (let i = 0; i < lines.length; i++) if (lines[i].startsWith('import ')) insertAt = i + 1;
    if (insertAt > 0) {
      lines.splice(insertAt, 0, HELPER);
      src = lines.join('\n');
      console.log(`  ${rel}: injected trimTrailingSlashes helper`);
    }
  }

  // 3. IPv4 regex fix (only in client-ip.ts)
  if (rel === 'packages/server/src/client-ip.ts' && src.includes(IPV4_OLD)) {
    src = src.replace(IPV4_OLD, IPV4_NEW);
    console.log(`  ${rel}: replaced IPv4 dotted-quad regex with manual parse`);
    changed = true;
  }

  if (!changed) { console.log(`no change: ${rel}`); return; }

  if (MODE === 'write') {
    writeFileSync(path + '.bak', before);
    writeFileSync(path, src);
    console.log(`  → wrote: ${rel}  (backup: ${rel}.bak)`);
  } else {
    console.log(`  (dry run — not written: ${rel})`);
  }
}

function verify() {
  console.log('\n=== Verification ===');
  let ok = true;
  for (const rel of TARGETS) {
    const path = join(ROOT, rel);
    if (!existsSync(path)) continue;
    const src = readFileSync(path, 'utf8');
    const remaining = src.match(/\.replace\(\/\\\/\+\$\/, ''\)/g);
    if (remaining) { console.log(`✗ ${rel}: still contains ${remaining.length} risky .replace(/\\/+$/, '')`); ok = false; }
    if (rel === 'packages/server/src/client-ip.ts' && src.includes('/(\\d+\\.\\d+\\.\\d+\\.\\d+)$/.exec(ip)')) {
      console.log(`✗ ${rel}: still contains the IPv4 dotted-quad regex`); ok = false;
    }
  }
  if (ok) console.log('✓ All targeted patterns removed.');
  return ok;
}

console.log(`fix-redos.mjs — Mode: ${MODE}\n`);
if (MODE === 'rollback') {
  rollback();
} else {
  for (const rel of TARGETS) processFile(rel);
  if (MODE === 'write') {
    verify();
    console.log('\nNext steps:');
    console.log('  1. npm run typecheck && npm test');
    console.log('  2. Remove .bak files: Get-ChildItem -Recurse -Filter *.bak | Remove-Item');
    console.log('  3. git add . && git commit -m "fix: eliminate polynomial ReDoS in http/client-ip/webauthn/index"');
    console.log('  4. git push   (CodeQL re-scans in ~5 min; the 7 alerts should auto-close)');
  } else {
    console.log('\nDry run complete. Pass --write to apply. Pass --rollback to undo after write.');
  }
}
