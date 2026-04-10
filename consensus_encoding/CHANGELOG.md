# Changelog

All notable Tidecoin-specific changes for consensus encoding are documented here.

## Unreleased

- Made this crate the canonical serialization layer for Tidecoin consensus data.
- Kept encoding traits, varint handling, vectors, strings, arrays, and hash integrations in one shared no-std-capable crate.
- Removed compatibility helpers whose only purpose was preserving old API shape.
- Provided the single codec path used by primitives, consensus, p2p, and top-level crate surfaces.
- Set the crate MSRV to Rust 1.94.1.
