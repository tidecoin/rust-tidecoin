# Changelog

All notable Tidecoin-specific changes for Base58Check encoding are documented here.

## Unreleased — 0.4.1

- Require the updated hash and internal implementations and enforce the unsafe-code restriction; the Base58 API is unchanged.

## 0.4.0 — published 2026-04-30

- Kept this crate as the shared Base58Check utility for Tidecoin address and key encoding surfaces.
- Aligned crate metadata and documentation with Tidecoin workspace ownership.
- Preserved the lower-level dependency boundary so address encoding does not duplicate codec logic elsewhere.
- Set the crate MSRV to Rust 1.94.1.
