# Contributing to BioKyn

Thank you for helping make bot protection private and accessible. All contributions are welcome: code, tests, docs, bug reports and ideas.

## Ways to contribute
- **Questions and ideas:** [Discussions](https://github.com/biokyn/biokyn/discussions)
- **Bugs and features:** [Issues](https://github.com/biokyn/biokyn/issues/new/choose)
- **Security issues:** private advisory only, see [SECURITY.md](SECURITY.md)

## Development setup
Node 20.11 or newer.

```bash
git clone https://github.com/biokyn/biokyn && cd biokyn
npm ci
npm run check        # lockfile gate, typecheck, tests, build
```

Official RFC 9497 vectors: `npm run vectors:fetch && npm run test:vectors`. Redis integration: `docker compose -f docker-compose.redis.yml up -d` then `npm run test:redis`.

## Pull request guidelines
1. Open an issue or discussion first for sizeable changes.
2. Keep each PR focused on one logical change.
3. Add or update tests; new features need tests and docs. Bug fixes need a regression test.
4. `npm run check` must pass.
5. Update [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
6. Sign off every commit (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/).

## Coding standards
- Strict TypeScript, no `any`, no unused exports.
- Security-sensitive code (crypto, parsing, stores) uses constant-time comparisons, bounded inputs and fail-closed errors.
- No telemetry, fingerprinting or third-party network calls.
- User-facing UI must be keyboard and screen-reader accessible.
- New runtime dependencies need justification; prefer small, audited libraries.

## Review and releases
Maintainers aim to respond within a week. Changes to cryptography or the wire protocol need a second reviewer. See [GOVERNANCE.md](GOVERNANCE.md) and [docs/RELEASING.md](docs/RELEASING.md).

## Conduct
Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
