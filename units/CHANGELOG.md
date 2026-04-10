# Changelog

All notable Tidecoin-specific changes for units are documented here.

## Unreleased

- Reoriented amount, weight, feerate, and locktime helpers around Tidecoin crate ownership.
- Kept consensus encoding integration delegated to `tidecoin-consensus-encoding`.
- Preserved no-std-capable numeric utility boundaries for lower-level protocol crates.
- Set the crate MSRV to Rust 1.94.1.
