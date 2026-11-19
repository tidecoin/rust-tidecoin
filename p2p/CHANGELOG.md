# Changelog

All notable Tidecoin-specific changes for peer-to-peer messages are documented here.

## Unreleased — 0.2.0

- Include unit-test data in release archives so extracted library tests compile.

- Breaking dependency update: public primitives and hash/I/O types move to the new versions. Include rc3 message limits and safe command decoding.

- Replaced unchecked command-string construction with checked UTF-8 conversion,
  retaining ASCII validation and null-padding behavior. The library forbids unsafe code.

## 0.1.0 — published 2026-04-30

- Reoriented the crate around Tidecoin peer-to-peer message and transport semantics.
- Routed message serialization through `tidecoin-consensus-encoding` and shared primitives.
- Kept transport cryptography in the dedicated local crypto helper crates.
- Removed inherited compatibility framing that duplicated lower-level codec responsibilities.
- Set the crate MSRV to Rust 1.94.1.
