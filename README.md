<div align="center">
  <h1>Rust Tidecoin</h1>

  <p>Library and crate stack for Tidecoin protocol data, scripting, validation, and network messages.</p>

  <p>
    <a href="https://github.com/tidecoin/rust-tidecoin/blob/master/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
    <a href="https://github.com/tidecoin/rust-tidecoin/actions"><img alt="CI Status" src="https://github.com/tidecoin/rust-tidecoin/actions/workflows/rust.yml/badge.svg"></a>
    <a href="https://www.rust-lang.org/tools/install"><img alt="Rustc Version 1.94.1+" src="https://img.shields.io/badge/rustc-1.94.1%2B-lightgrey.svg"/></a>
  </p>
</div>

## Scope

This repository provides:

- Tidecoin protocol encoding and decoding
- Tidecoin blocks, transactions, addresses, scripts, and network messages
- canonical lower protocol types in `primitives`
- a reusable validation engine in `consensus-core`
- a standalone byte-oriented validation adapter in `consensus`
- Tidecoin node-backed parity support in `node-parity`
- post-quantum cryptography helpers for Tidecoin-specific schemes

## Tidecoin-specific features

Key Tidecoin-specific behavior:

- AuxPoW merged-mining support with Tidecoin-specific chain parameters
- post-quantum signature and KEM support
- `OP_SHA512` and witness-v1-512 support
- Tidecoin-native validation flags and node-parity-tested consensus behavior

## Architecture

The crate graph is intentionally layered:

- `primitives`: canonical Tidecoin protocol model, including script and opcodes
- `consensus-core`: reusable Tidecoin validation engine
- `consensus`: standalone byte-oriented verification wrapper
- `tidecoin`: public product crate and higher-level ergonomics
- `node-parity`: Tidecoin Core differential/parity support for tests

## Consensus-sensitive changes

Pure-Rust validation is checked against the real Tidecoin node. Consensus-sensitive changes should
be treated as node-parity-sensitive engineering work and verified with the Tidecoin fixture and
differential suites, not only with local unit tests.

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features on **Rust 1.94.1**.

Use `Cargo-minimal.lock` to build the MSRV by copying to `Cargo.lock` and building.

## No-std support

The `std` cargo feature is enabled by default. To build without the Rust standard library, use
`--no-default-features` or set `default-features = false` in your dependency declaration.

## Crate structure

| Crate | Description |
|---|---|
| `tidecoin` | Main Tidecoin product crate |
| `primitives` | Canonical Tidecoin protocol types |
| `consensus-core` | Shared Tidecoin validation engine |
| `consensus` | Standalone byte-oriented validation adapter |
| `node-parity` | Tidecoin node-backed parity/test support |
| `p2p` | Tidecoin peer-to-peer message types |
| `consensus_encoding` | Consensus-compatible encoding/decoding |
| `hashes` | Tidecoin hash functions |
| `units` | Amount, weight, locktime, fee-rate, and related units |
| `network` | Tidecoin network kind/types |
| `io` | Minimal I/O traits for `no_std` |
| `internals` | Internal macros and utilities |
| `base58` | Base58 encoding/decoding |
| `chacha20_poly1305` | AEAD encryption |

## Contributing

Contributions are welcome. For larger changes, discuss architecture first to avoid duplicate work
or boundary regressions.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
