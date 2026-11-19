# Changelog

All notable Tidecoin-specific changes for consensus encoding are documented here.

## Unreleased — 0.1.1

- Enforce the unsafe-code restriction and require the updated internal helpers; encoding APIs are unchanged.

## 0.1.0 — published 2026-04-30

- Made this crate the canonical serialization layer for Tidecoin consensus data.
- Kept encoding traits, varint handling, vectors, strings, arrays, and hash integrations in one shared no-std-capable crate.
- Removed compatibility helpers whose only purpose was preserving old API shape.
- Provided the single codec path used by primitives, consensus, p2p, and top-level crate surfaces.
- Set the crate MSRV to Rust 1.94.1.
