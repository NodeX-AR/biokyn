# @biokyn/core

The BioKyn core package provides the original application-facing bot-mitigation primitives: token signing and verification, request middleware, browser client script, and storage adapters.

It is a first-class package in the BioKyn monorepo. It is intentionally kept as the stable compatibility/application layer while `@biokyn/protocol`, `@biokyn/client`, and `@biokyn/server` expose the newer protocol-oriented architecture.

## Build

From the repository root:

```bash
npm install
npm run typecheck --workspace=@biokyn/core
npm test --workspace=@biokyn/core
npm run build --workspace=@biokyn/core
```

## Migration

Existing integrations can continue importing `@biokyn/core`. New integrations that need the protocol challenge/issuance flow should use `@biokyn/server` and `@biokyn/client`.
