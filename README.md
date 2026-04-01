<div align="center">
  <h1>Rust Tidecoin</h1>

  <p>Library with support for de/serialization, parsing and executing on data-structures
    and network messages related to Tidecoin.
  </p>

  <p>
    <a href="https://github.com/nicenemo/rust-tidecoin/blob/master/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
    <a href="https://github.com/nicenemo/rust-tidecoin/actions"><img alt="CI Status" src="https://github.com/nicenemo/rust-tidecoin/actions/workflows/rust.yml/badge.svg"></a>
    <a href="https://blog.rust-lang.org/2023/11/16/Rust-1.74.0/"><img alt="Rustc Version 1.74.0+" src="https://img.shields.io/badge/rustc-1.74.0%2B-lightgrey.svg"/></a>
  </p>
</div>

Supports (or should support)

* De/serialization of Tidecoin protocol network messages
* De/serialization of blocks and transactions (including AuxPoW merge-mined blocks)
* Script de/serialization
* Private keys and address creation, de/serialization and validation (including full BIP-0032 support)
* Post-quantum cryptography via FN-DSA (Falcon) signatures
* PSBT v0 de/serialization and all but the Input Finalizer role
* P2WSH-512 witness programs for post-quantum key material

## Tidecoin-Specific Features

This library is a fork of [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) adapted for the Tidecoin network. Key differences from Bitcoin:

* **AuxPoW (Merged Mining)** — full support for auxiliary proof-of-work headers with chain ID 8
* **Post-Quantum Signatures** — Falcon-512/1024 via vendored FN-DSA crates
* **Network Parameters** — 60-second block target, Tidecoin-specific difficulty adjustment
* **Denominations** — TDC and tidoshi (1 TDC = 100,000,000 tidoshi)

## Known Limitations

### Consensus

This library **must not** be used for consensus code (i.e. fully validating blockchain data). It
technically supports doing this, but doing so is very ill-advised because there are many deviations,
known and unknown, between this library and the Tidecoin Core reference implementation. In a
consensus-based cryptocurrency such as Tidecoin, it is critical that all parties are using the same
rules to validate data, and this library is simply unable to implement the same rules as Core.

Given the complexity of both C++ and Rust, it is unlikely that this will ever be fixed, and there
are no plans to do so. Of course, patches to fix specific consensus incompatibilities are welcome.

### Support for 16-bit pointer sizes

16-bit pointer sizes are not supported, and we can't promise they will be. If you care about them
please let us know, so we can know how large the interest is and possibly decide to support them.

### Semver compliance

We try hard to maintain strict semver compliance with our releases. This codebase includes some
public functions marked unstable (e.g., `pub fn foo__unstable()`). These functions do not adhere to
semver rules; use them at your own discretion.

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features on **Rust 1.74.0**.

Use `Cargo-minimal.lock` to build the MSRV by copying to `Cargo.lock` and building.

## No-std support

The `std` cargo feature is enabled by default. To build this project without the Rust standard
library, use the `--no-default-features` flag or set `default-features = false` in your dependency
declaration when adding it to your project.

## External dependencies

We integrate with a few external libraries, most notably `serde`. These
are available via feature flags. To ensure compatibility and MSRV stability, we
provide two lock files as a means of inspecting compatible versions:
`Cargo-minimal.lock` containing minimal versions of dependencies and
`Cargo-recent.lock` containing recent versions of dependencies tested in our CI.

We do not provide any guarantees about the content of these lock files outside
of "our CI didn't fail with these versions". Specifically, we do not guarantee
that the committed hashes are free from malware. It is your responsibility to
review them.

## Crate Structure

| Crate | Description |
|---|---|
| `tidecoin` | Main library — blocks, transactions, consensus, scripts |
| `tidecoin-primitives` | Core types (Block, Header, AuxPow, Transaction) |
| `tidecoin_hashes` | Hash functions (SHA-256, SHA-512, RIPEMD-160, etc.) |
| `tidecoin-units` | Numeric units (Amount, BlockHeight, Weight, FeeRate) |
| `tidecoin-p2p-messages` | P2P network message types |
| `tidecoin-consensus-encoding` | Consensus-compatible encoding/decoding |
| `tidecoin-network-kind` | Network type (Tidecoin, Testnet, Regtest) |
| `tidecoin-io` | Minimal I/O traits for no-std support |
| `tidecoin-internals` | Internal macros and utilities |
| `base58ck` | Base58 encoding with checksum |
| `chacha20-poly1305` | AEAD encryption |
| `fn-dsa` | FN-DSA (Falcon) post-quantum signatures (vendored) |

## Contributing

Contributions are generally welcome. If you intend to make larger changes please discuss them in an
issue before PRing them to avoid duplicate work and architectural mismatches.

For more information, please see [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Release Notes

Release notes are done per crate, see:

- [`addresses` CHANGELOG](addresses/CHANGELOG.md)
- [`base58` CHANGELOG](base58/CHANGELOG.md)
- [`bip158` CHANGELOG](bip158/CHANGELOG.md)
- [`bitcoin` CHANGELOG](bitcoin/CHANGELOG.md)
- [`chacha20_poly1305` CHANGELOG](chacha20_poly1305/CHANGELOG.md)
- [`consensus_encoding` CHANGELOG](consensus_encoding/CHANGELOG.md)
- [`crypto` CHANGELOG](crypto/CHANGELOG.md)
- [`hashes` CHANGELOG](hashes/CHANGELOG.md)
- [`internals` CHANGELOG](internals/CHANGELOG.md)
- [`io` CHANGELOG](io/CHANGELOG.md)
- [`p2p` CHANGELOG](p2p/CHANGELOG.md)
- [`primitives` CHANGELOG](primitives/CHANGELOG.md)
- [`units` CHANGELOG](units/CHANGELOG.md)

## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
