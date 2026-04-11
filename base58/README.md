# Tidecoin base58 encoding

This crate provides encoding and decoding of base58 strings as defined by the Tidecoin ecosystem
including the checksum.

There are a bunch of crates on crates.io that implement base58 encoding and decoding. The more
obviously named ones differ from this crate because:

1. Some base58 crates are transpiled from C++ node implementations, whereas this crate is a pure
   Rust implementation intended to be production-ready and to provide a Rust-idiomatic API.

2. [base58](https://crates.io/crates/base58) implements parsing but does not validate checksums (see
   `base58check`). It may be appropriate in cases where performance is more important than safety.
   Appears unmaintained.

3. [base58check](https://crates.io/crates/base58check) Adds checksum to the `base58` crate and
   depends on [sha2](https://crates.io/crates/sha2/0.8.2) for hashing. Appears unmaintained.

This crate uses [tidecoin_hashes](https://crates.io/crates/tidecoin_hashes) when hashing to calculate
the checksum.
