# rust-tidecoin stack of crates

The `rust-tidecoin` project is a fork of `rust-bitcoin` adapted for the
Tidecoin network. The original single crate has been broken into a number
of pieces and this work is ongoing. Both current and future crates are
documented here. Future crates typically have an entry in [roadmap.md]
and likely also a file of their own.

## Current crates

- `addresses`: **Empty** placeholder (see future crates below).
- `base58`: Tidecoin base58 encoding and decoding (for pre-segwit addresses).
- `bitcoin`: The main `tidecoin` crate.
- `chacha20_poly1305`: ChaCha20 stream cipher with the Poly1305 MAC.
- `consensus_encoding`: Consensus encoding and decoding.
- `crypto`: Cryptography support for the rust-tidecoin ecosystem.
- `tide-fn-dsa`: external Tidecoin-specific FN-DSA (Falcon) post-quantum signature crates.
- `hashes`: Tidecoin hashes library.
- `internals`: Used internally by crates in this repo.
- `io`: Tidecoin I/O library (to support `no_std`).
- `network`: Tidecoin network kind (Tidecoin, Testnet, Regtest).
- `p2p`: Tidecoin peer to peer message types.
- `primitives`: Tidecoin primitive types (Block, Header, AuxPow, Transaction).
- `units`: Tidecoin unit types (Amount, BlockHeight, Weight, FeeRate).

## Future crates

- `addresses`: Tidecoin addresses (see [addresses.md])
- `bip-32`: BIP-0032 (and maybe BIP-0380) support (see [bip-32.md])
- `psbt`: PSBTv2 support (see [psbt.md])
- `keys`/`crypto`: Cryptography stuff or maybe just keys (see [keys.md])

## Re-export policy

See `./policy.md`.

[addresses.md]: ./addresses.md
[bip-32.md]: ./bip-32.md
[keys.md]: ./keys.md
[psbt.md]: ./psbt.md
