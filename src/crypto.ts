import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { ChallengeContext, ParsedToken, TokenBinding } from './types.js';

const FORM_ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const ACTION_RE = /^[\x21-\x7e]{1,128}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{16,32}$/;
const SID_RE = /^[A-Za-z0-9_-]{22,43}$/;

export const isValidFormId = (v: string): boolean => FORM_ID_RE.test(v);
export const isValidAction = (v: string): boolean => ACTION_RE.test(v);

export const sha256Hex = (v: string): string => createHash('sha256').update(v, 'utf8').digest('hex');
export const b64u = (b: Buffer): string => b.toString('base64url');
export const fromB64u = (s: string): Buffer => Buffer.from(s, 'base64url');
export const randomId = (bytes = 16): string => randomBytes(bytes).toString('base64url');

export function hmac(secret: Buffer, message: string): Buffer {
  return createHmac('sha256', secret).update(message, 'utf8').digest();
}

export function safeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** timestamp || nonce || formId || sha256(origin) || sha256(sid) || sha256(action) (+ version, flags). */
export function bindingMessage(b: TokenBinding): string {
  return [
    'bk1',
    b.ts,
    b.nonce,
    b.flags,
    b.formId,
    sha256Hex(b.origin),
    sha256Hex(b.sid),
    sha256Hex(b.action),
  ].join('|');
}

/** Token wire format: bk1.<ts>.<nonce>.<flags>.<b64u(formId)>.<b64u(mac)> */
export function signToken(secret: Buffer, b: TokenBinding): string {
  const mac = hmac(secret, bindingMessage(b));
  return ['bk1', b.ts, b.nonce, b.flags, b64u(Buffer.from(b.formId, 'utf8')), b64u(mac)].join('.');
}

export function parseToken(token: string): ParsedToken | null {
  if (token.length > 512) return null;
  const p = token.split('.');
  if (p.length !== 6 || p[0] !== 'bk1') return null;
  const [, tsS, nonce, flagS, fidS, macS] = p as [string, string, string, string, string, string];
  if (!/^\d{1,16}$/.test(tsS) || !/^[01]$/.test(flagS) || !NONCE_RE.test(nonce)) return null;
  const ts = Number(tsS);
  if (!Number.isSafeInteger(ts) || ts <= 0) return null;
  const formId = fromB64u(fidS).toString('utf8');
  if (!isValidFormId(formId)) return null;
  const mac = fromB64u(macS);
  if (mac.length !== 32) return null;
  return { ts, nonce, flags: Number(flagS), formId, mac };
}

export function verifyToken(secret: Buffer, parsed: ParsedToken, ctx: ChallengeContext): boolean {
  const expected = hmac(
    secret,
    bindingMessage({
      ts: parsed.ts,
      nonce: parsed.nonce,
      flags: parsed.flags,
      formId: parsed.formId,
      origin: ctx.origin,
      sid: ctx.sid,
      action: ctx.action,
    }),
  );
  return safeEqual(expected, parsed.mac);
}

export function signSid(secret: Buffer, sid: string): string {
  return `${sid}.${b64u(hmac(secret, `sid|${sid}`))}`;
}

/** Returns the session id only when the cookie value carries a valid server signature. */
export function readSid(secret: Buffer, value: string): string | null {
  const i = value.indexOf('.');
  if (i < 1) return null;
  const sid = value.slice(0, i);
  if (!SID_RE.test(sid)) return null;
  const mac = fromB64u(value.slice(i + 1));
  return safeEqual(mac, hmac(secret, `sid|${sid}`)) ? sid : null;
}

export function parseCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}
