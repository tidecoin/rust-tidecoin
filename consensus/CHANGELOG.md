# Changelog

All notable Tidecoin-specific changes for the standalone consensus adapter are documented here.

## Unreleased

- Reworked the crate as a standalone adapter over `tidecoin-consensus-core`.
- Preserved byte-oriented entry points only where they serve the active Tidecoin validation boundary.
- Replaced inherited differential assumptions with Tidecoin fixture and node-parity workflows.
- Delegated transaction decoding and script execution to the shared lower-level crates.
- Set the crate MSRV to Rust 1.94.1.
