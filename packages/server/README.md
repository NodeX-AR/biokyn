# `@biokyn/server`

Server-side BioKyn verifier and adapters.

## Endpoints

- `GET /biokyn/challenge`
- `POST /biokyn/issue`
- `POST /siteverify`
- `/recaptcha/api/siteverify`
- `/turnstile/v0/siteverify`

The verifier keeps detailed risk reasons in the server logger and exposes only the minimum compatibility response to callers.
