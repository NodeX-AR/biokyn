# Architecture

## Token

Wire format: `bk1.<ts>.<nonce>.<flags>.<b64url(formId)>.<b64url(hmac)>`

MAC input: `bk1|ts|nonce|flags|formId|sha256(origin)|sha256(sid)|sha256(action)`.
`origin`, `sid` and `action` are never transmitted in the token; the verifier recomputes them from
the request, so any mismatch yields `bad_signature`.

## Session identity

`__biokyn_sid` is `HttpOnly; SameSite=Lax` (plus `Secure` in production) and carries
`<sid>.<HMAC(sid)>`. Forged or unsigned cookies are treated as absent.

A client without a valid cookie gets a new session and one **bootstrap** token (`flags=1`) that can
never verify. Cookieless issuance is counted per IP (`anonQuota`), so clearing cookies in a loop
is throttled. The client script transparently fetches a real token once the cookie is set.

## Verification order

1. token present and parseable
2. valid signed session cookie
3. Origin header matches configured origin (if set)
4. formId matches expected (if given)
5. per-session verify quota (`verifyQuota`)
6. HMAC check (timing-safe)
7. reject bootstrap tokens
8. age checks: future (> skew), `too_fast` (< minAge), `expired` (> ttl)
9. atomic `setNx` on the nonce hash: failure means `replayed`

Failed checks before step 9 never consume the nonce, so a legitimate user can retry.

## Options table

| Option | Default |
|--------|---------|
| ttlMs | 900000 (15 min) |
| minAgeMs | 1500 |
| clockSkewMs | 5000 |
| quota (challenges / session / window) | 20 |
| anonQuota (cookieless / IP / window) | 10 |
| verifyQuota (verifications / session / window) | 30 |
| windowMs | 600000 |
| trustProxy | false |
| secureCookie | NODE_ENV === 'production' |
| cookieName | `__biokyn_sid` |
| sessionTtlMs | 7 days |

## Operational notes

- All nodes must share the same `secret` and a shared store (Redis) for replay protection.
- Behind a proxy, set `origin` explicitly and `trustProxy: true` only if the proxy overwrites
  `X-Forwarded-*`. Otherwise per-IP quotas can be spoofed.
- Rotate the secret by deploying a new one; in-flight tokens and sessions become invalid (clients re-bootstrap).
- Fixed-window counters allow brief bursts at window boundaries.
