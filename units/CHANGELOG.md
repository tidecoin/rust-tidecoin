# Changelog

All notable Tidecoin-specific changes for units are documented here.

## Unreleased — 0.3.1

- Fix fractional fee-rate multiplication and add node-compatible integer-vsize fee calculation; existing types and signatures remain compatible.

## 0.3.0 — published 2026-04-30

- Reoriented amount, weight, feerate, and locktime helpers around Tidecoin crate ownership.
- Kept consensus encoding integration delegated to `tidecoin-consensus-encoding`.
- Preserved no-std-capable numeric utility boundaries for lower-level protocol crates.
- Set the crate MSRV to Rust 1.94.1.
