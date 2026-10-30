import { defineConfig } from 'vitest/config';

// Server/protocol tests solve real Argon2id proofs-of-work (>= 8 MiB, pure-JS noble): allow generous per-test time.
export default defineConfig({ test: { include: ['test/**/*.test.ts'], testTimeout: 60_000, hookTimeout: 60_000 } });
