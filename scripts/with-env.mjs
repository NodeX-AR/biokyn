#!/usr/bin/env node
/** Cross-platform "VAR=value command": node scripts/with-env.mjs REQUIRE_X=1 OTHER=2 -- npm run something */
import { spawn } from 'node:child_process';

const argv = process.argv.slice(2);
const sep = argv.indexOf('--');
if (sep < 0 || sep === argv.length - 1) { console.error('usage: with-env.mjs VAR=value [VAR=value…] -- command [args…]'); process.exit(2); }

const env = { ...process.env };
for (const kv of argv.slice(0, sep)) {
  const i = kv.indexOf('=');
  if (i < 1) { console.error(`bad assignment: ${kv}`); process.exit(2); }
  env[kv.slice(0, i)] = kv.slice(i + 1);
}

// shell:true is required on Windows to run npm/vitest (.cmd shims). Quote anything that is not plainly safe.
const SAFE = /^[\w@%+=:,./\\-]+$/;
const quote = (a) => (SAFE.test(a) ? a : `"${a.replace(/(["\\$`])/g, '\\$1')}"`);
const child = spawn(argv.slice(sep + 1).map(quote).join(' '), { env, stdio: 'inherit', shell: true });
child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
