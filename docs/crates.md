# rust-tidecoin stack of crates

The `rust-tidecoin` repository is a Tidecoin-native crate graph with explicit lower-level
ownership.

## Current crates

- `tidecoin`: main Tidecoin product crate
- `primitives`: canonical Tidecoin protocol types, including script and opcodes
- `consensus-core`: reusable Tidecoin validation engine
- `consensus`: standalone byte-oriented validation adapter
- `node-parity`: Tidecoin node-backed parity/test support
- `p2p`: Tidecoin peer-to-peer message types
- `consensus_encoding`: consensus encoding and decoding
- `hashes`: Tidecoin hash library
- `units`: amount, weight, locktime, fee-rate, and related units
- `network`: Tidecoin network kinds/types
- `io`: minimal I/O support for `no_std`
- `internals`: internal macros and utilities
- `base58`: Tidecoin base58 encoding and decoding
- `chacha20_poly1305`: AEAD encryption

## Ownership model

- `primitives` owns the canonical protocol model
- `consensus-core` owns the reusable validation engine
- `consensus` owns the standalone byte-oriented verification API
- `tidecoin` owns the public product ergonomics and orchestration

## Re-export policy

See `./policy.md`.
