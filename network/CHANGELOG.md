# Changelog

All notable Tidecoin-specific changes for network identifiers are documented here.

## Unreleased — 0.1.1

- Enforce the unsafe-code restriction and require the updated internal helpers; network types are unchanged.

## 0.1.0 — published 2026-04-30

- Kept this crate focused on Tidecoin network identity types: `Network`, `NetworkKind`, and `TestnetVersion`.
- Preserved the narrow dependency boundary so network selection remains reusable from primitives, p2p, and the top-level crate.
- Set the crate MSRV to Rust 1.94.1.
