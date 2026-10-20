<div align="center">
  <h1>Rust Tidecoin</h1>

  <p>Library and crate stack for Tidecoin protocol data, scripting, validation, and network messages.</p>

  <p>
    <a href="https://github.com/tidecoin/rust-tidecoin/blob/v2/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
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

- AuxPoW header/data and chain-parameter support; full validation-vector parity,
  yespower/scrypt PoW-hash selection, and AuxPoW parent-PoW validation remain
  tracked as active consensus coverage work
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

## PQ Type Ownership

The workspace intentionally has similarly named PQ and validation-side types in
more than one crate.

- `tidecoin::*` is the normal product-facing Rust API for app, wallet, and
  plumbing code
- `consensus-core::*` is the shared verifier/engine layer used to implement
  validation and lower-level consensus behavior

So when both crates expose names like `PqPublicKey`, `PqSignature`, or
`PqError`, downstream Rust code should usually start with `tidecoin::*` unless
it is deliberately building on the lower-level shared engine.

## Consensus-sensitive changes

The rc2 protocol-library compatibility checkpoint is validated locally against
node `7d653be5d24e73b49d101578afb33d8d7a889c1d` (`v1.0.0rc2`). This covers the
script, caller-context, header/PoW and stateless policy surfaces listed in the
[proof matrix](ai-docs/NODE_PARITY_PROOF_MATRIX.md). Full chainstate/mempool
acceptance and Rust PSBT interoperability remain outside that claim.

CI targets `v2`/`main` and pull requests. Its `Required rc2 node parity` job
checks out `node-parity/NODE_REVISION`, fails on unavailable/mismatched oracle
configuration, and runs workspace tests, product node parity, Clippy and feature
checks. The workflow is configured; a hosted run and branch-protection status
have not been verified. See [node compatibility](docs/supported-versions.md) and
the [migration evidence](ai-docs/RC2_MIGRATION_PLAN.md).

Pure-Rust validation is checked against the real Tidecoin node. Consensus-sensitive changes should
be treated as node-parity-sensitive engineering work and verified with the Tidecoin fixture and
differential suites, not only with local unit tests.

Normal CI and formatting use Rust **1.99.1**, pinned in `Cargo.toml`. For local
format checks use `cargo +1.99.1 fmt --all -- --check`. Nightly remains for
specialized checks and inherited maintainer-tool audits. Building the original
C++ validation oracle is documented in the
[migration evidence](ai-docs/RC2_MIGRATION_PLAN.md#original-node-validation-follow-up-2026-10-20).

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features on **Rust 1.94.1**.

## No-std support

The `std` cargo feature is enabled by default. To build without the Rust standard library, use
`--no-default-features` or set `default-features = false` in your dependency declaration.

## Feature note

The `tidecoin-node-validation` feature exists for real-node parity tests and dev-only adapters.
Normal downstream builds should keep product validation on the default pure-Rust path and should
not enable that feature.

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
