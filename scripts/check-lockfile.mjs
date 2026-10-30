#!/usr/bin/env node
/**
 * Fails unless a package-lock.json is committed (reproducible installs via `npm ci`) and every REQUIRED registry
 * package in it carries an integrity hash.
 *
 * Optional platform packages (e.g. @esbuild/win32-x64, @rollup/rollup-*) are only warned about: npm frequently writes
 * them without `integrity` when the lockfile is generated on a different OS, and they are never installed elsewhere.
 * Set STRICT_LOCKFILE=1 to fail on those too (recommended once the lockfile is regenerated on the CI platform).
 */
import { existsSync, readFileSync } from 'node:fs';
const lock = new URL('../package-lock.json', import.meta.url);
if (!existsSync(lock)) {
  console.error('package-lock.json is missing.\nGenerate it once with `npm install`, review it, and commit it.\nCI and releases use `npm ci`, which refuses to run without it.');
  process.exit(1);
}
const j = JSON.parse(readFileSync(lock, 'utf8'));
const missing = Object.entries(j.packages ?? {}).filter(([k, v]) => k && !v.link && !v.integrity && !k.startsWith('packages/') && !k.includes('node_modules/@biokyn/'));
const isOptionalPlatform = ([, v]) => v.optional === true || Boolean(v.os) || Boolean(v.cpu);
const optional = missing.filter(isOptionalPlatform), required = missing.filter((e) => !isOptionalPlatform(e));
if (optional.length) console.warn(`warning: ${optional.length} optional/platform packages have no integrity hash (e.g. ${optional[0][0]}); harmless locally, regenerate on Linux/CI to fill them`);
if (required.length || (process.env.STRICT_LOCKFILE === '1' && optional.length)) {
  const bad = required.length ? required : optional;
  console.error(`lockfile has ${bad.length} entries without integrity hashes, e.g. ${bad[0][0]}`);
  process.exit(1);
}
console.log(`package-lock.json OK (${Object.keys(j.packages ?? {}).length} packages)`);
