# Changelog

All notable Tidecoin-specific changes for network identifiers are documented here.

## Unreleased

- Kept this crate focused on Tidecoin network identity types: `Network`, `NetworkKind`, and `TestnetVersion`.
- Preserved the narrow dependency boundary so network selection remains reusable from primitives, p2p, and the top-level crate.
- Set the crate MSRV to Rust 1.94.1.
