# Changelog

All notable Tidecoin-specific changes for peer-to-peer messages are documented here.

## Unreleased

- Reoriented the crate around Tidecoin peer-to-peer message and transport semantics.
- Routed message serialization through `tidecoin-consensus-encoding` and shared primitives.
- Kept transport cryptography in the dedicated local crypto helper crates.
- Removed inherited compatibility framing that duplicated lower-level codec responsibilities.
- Set the crate MSRV to Rust 1.94.1.
