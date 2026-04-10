# Supported versions

This repository is currently maintained as the Tidecoin Rust workspace.

## Active crates

The live crate graph is organized around these supported surfaces:

- `tidecoin`: high-level Tidecoin library and public ergonomics.
- `tidecoin-primitives`: canonical protocol, transaction, script, opcode, witness, and block types.
- `tidecoin-consensus-core`: reusable Tidecoin validation engine.
- `consensus`: standalone byte-oriented validation adapter over `tidecoin-consensus-core`.
- `tidecoin-consensus-encoding`: sans-I/O consensus codec primitives.
- `tidecoin-p2p-messages`: peer message layer built on lower shared crates.

## Maintenance policy

This branch maintains the Tidecoin crate line as the active API surface. Historical migration
artifacts may remain temporarily during migration, but they are not part of the intended
steady-state architecture and should be deleted once their Tidecoin-native replacement coverage is
accepted.

Dependency versions are tracked in the workspace manifests and lockfile. Prefer committed `version`
or pinned `git` dependencies for reproducibility; local developer overrides should not be committed
as external path dependencies.
