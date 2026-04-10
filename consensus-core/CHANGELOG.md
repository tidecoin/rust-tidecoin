# Changelog

All notable Tidecoin-specific changes for the shared consensus engine are documented here.

## Unreleased

- Added the shared Tidecoin consensus engine crate used by both public adapters and tests.
- Moved Tidecoin script, witness, flag, error, and verification semantics into the lower-level consensus runtime.
- Added the post-quantum verification facade required by Tidecoin witness validation.
- Kept consensus execution independent from high-level crate API compatibility concerns.
- Set the crate MSRV to Rust 1.94.1.
