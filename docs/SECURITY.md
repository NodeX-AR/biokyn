# Security Policy

Report vulnerabilities privately to the maintainers (e.g. via GitHub Security Advisories) rather than opening a public issue.

## Threat model

Mitigated: token replay, cross-action / cross-form / cross-origin token reuse, token pooling across
sessions, cookie-clearing quota evasion, instant form-fill bots (min age), forged session cookies.

Not mitigated: real-browser automation that executes the client script, residential-proxy IP rotation
defeating per-IP anon quotas, XSS on your origin, compromised secrets.

## Hardening checklist

- 32+ random bytes for `secret`, from a secret manager
- HTTPS everywhere; keep `secureCookie` on
- Set `origin` explicitly; enable `trustProxy` only behind a trusted proxy
- Use `RedisStore` for multi-node deployments
- Add `Content-Security-Policy` allowing your own `client.js`
