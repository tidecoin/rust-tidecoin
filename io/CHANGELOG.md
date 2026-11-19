# Changelog

All notable Tidecoin-specific changes for I/O helpers are documented here.

## Unreleased — 0.6.0

- Breaking dependency update: the public hashes re-export and hash I/O interfaces use tidecoin_hashes 0.21.

## 0.5.0 — published 2026-04-30

- Kept this crate as the shared minimal I/O abstraction layer for Tidecoin no-std-capable code.
- Preserved the bridge between encoding, hashing, and allocation-aware reader/writer helpers.
- Aligned crate metadata and documentation with Tidecoin workspace ownership.
- Set the crate MSRV to Rust 1.94.1.
