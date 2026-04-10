# Changelog

All notable Tidecoin-specific changes for protocol primitives are documented here.

## Unreleased

- Made this crate the canonical home for Tidecoin transaction, block, script, witness, locktime, and header primitives.
- Centralized primitive serialization through `tidecoin-consensus-encoding`.
- Added Tidecoin header and AuxPoW data structures used by the node-parity and consensus layers.
- Kept primitive types below validation logic so higher-level crates do not duplicate protocol data models.
- Set the crate MSRV to Rust 1.94.1.
