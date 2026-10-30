# `@biokyn/client`

Browser-side helpers for the recreated BioKyn architecture.

The package currently contains:

- privacy-conscious interaction-liveness collection
- a form-attaching `live.js` script
- an inclusive Argon2id issuance helper

The production follow-up is to move Argon2id work into a dedicated Worker and add the WebAuthn step-up UX.


## Motion step-up

`runMotionStepUp()` displays a blocking square movement interaction for use only after a server-side risk decision. It returns aggregate gesture features; it does not prove humanity, and those client-provided features are forgeable. Do not grant access based only on `passed`; submit the result to a fresh, server-validated challenge and combine it with independent server-side signals. Always provide an accessible non-motion alternative. The helper is opt-in and is not automatically invoked by `requestInclusiveToken()`.
