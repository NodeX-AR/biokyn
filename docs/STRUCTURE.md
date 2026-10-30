> **Historical document (0.3.x).** Superseded where it conflicts with [STATUS.md](STATUS.md) for 0.4.0-rc.1.

# Repository structure

BioKyn is maintained as one monorepo. The original core implementation is part of the project as `packages/core`; it is not kept in a separate legacy tree.

```text
biokyn/
├── package.json
├── README.md
├── CHANGELOG.md
├── LICENSE
├── .env.example
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── USAGE.md
│   ├── MIGRATION.md
│   └── STRUCTURE.md
└── packages/
    ├── core/       # Core bot-mitigation, storage and framework primitives
    ├── protocol/   # Wire protocol, kinematics, PoW and experimental VOPRF
    ├── client/     # Browser collection and issuance helpers
    ├── server/     # Challenge, verification, nullifiers and adapters
    └── shim/       # Integration compatibility helpers
```

The `core` package retains its existing public API where practical while the newer protocol/client/server packages provide the new architecture. Shared project configuration belongs at the repository root; package-specific source, tests, examples and documentation stay with their package.
