# Security Policy

Report vulnerabilities privately to the maintainers (e.g. via GitHub Security Advisories) rather than opening a public issue.


## Hardening checklist

- 32+ random bytes for `secret`, from a secret manager
- HTTPS everywhere; keep `secureCookie` on
- Set `origin` explicitly; enable `trustProxy` only behind a trusted proxy
- Use `RedisStore` for multi-node deployments
- Add `Content-Security-Policy` allowing your own `client.js`
