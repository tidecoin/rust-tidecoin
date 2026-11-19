# Changelog

All notable Tidecoin-specific changes for internal workspace helpers are documented here.

## Unreleased — 0.5.1

- Replace unsafe slice chunking with safe equivalents; public signatures are unchanged.

- Replaced slice chunking pointer casts with safe standard-library methods,
  retaining compile-time rejection of zero-sized chunks. The slice module forbids unsafe code.

## 0.5.0 — published 2026-04-30

- Kept this crate as the shared internal macro and utility layer for Tidecoin crates.
- Preserved internal-only status so public protocol semantics stay in the dedicated protocol crates.
- Aligned crate metadata and documentation with Tidecoin workspace ownership.
- Set the crate MSRV to Rust 1.94.1.
