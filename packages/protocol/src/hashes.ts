/**
 * Single import point for @noble/hashes. noble-hashes 2.x requires explicit `.js` sub-paths; keeping every
 * hash import here means a future path change is a one-line fix instead of a repo-wide search.
 */
export { sha256, sha512 } from '@noble/hashes/sha2.js';
export { hmac } from '@noble/hashes/hmac.js';
export { argon2id, argon2idAsync } from '@noble/hashes/argon2.js';
