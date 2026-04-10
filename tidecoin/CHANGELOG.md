# Changelog

All notable Tidecoin-specific changes for the public Tidecoin crate are documented here.

## Unreleased

- Reoriented the crate around Tidecoin-native transaction, block, script, address, network, and post-quantum key surfaces.
- Routed consensus validation through the shared Tidecoin consensus runtime and node-parity harness instead of inherited validation dependencies.
- Delegated protocol primitives and consensus serialization to the lower-level `tidecoin-primitives` and `tidecoin-consensus-encoding` crates.
- Removed inherited signing and validation surfaces that do not describe Tidecoin consensus.
- Set the crate MSRV to Rust 1.94.1.
