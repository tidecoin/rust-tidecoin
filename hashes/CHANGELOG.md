# Changelog

All notable Tidecoin-specific changes for hashes are documented here.

## Unreleased

- Reoriented the hash utility crate for Tidecoin workspace ownership.
- Kept hash newtypes, hex formatting, and encoding integrations available to primitives, p2p, and consensus layers.
- Preserved the low-level no-std boundary so hashing remains independent from protocol validation.
- Set the crate MSRV to Rust 1.94.1.
