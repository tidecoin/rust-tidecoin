# Falcon/PQ Gap Report

This report captures the Falcon/PQ behaviors that are still missing from the Rust port after the latest validation and fixing pass.

Validation basis:

- Tidecoin node source under `/home/kiel/work/tidecoin-node`
- Rust port source under `/home/kiel/work/rust-tidecoin`
- multi-agent re-scan after the AuxPoW, `Sighash512`, PSBT, PQHD, and PQ crypto bridge work

## What Exists In Rust Today

- random PQ key generation for all five schemes in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs)
- strict PQ signing and verification for 32-byte and 64-byte messages in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs)
- node-compatible public-key derivation from secret keys in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs)
- node-compatible Falcon-512 legacy signing and verification helpers in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs)
- scheme-height gating helper in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs)
- `Sighash512` and `p2wsh512_signature_hash()` in [bitcoin/src/crypto/sighash.rs](bitcoin/src/crypto/sighash.rs)
- PQHD v1 KDF/path validation in [bitcoin/src/pqhd.rs](bitcoin/src/pqhd.rs)
- deterministic PQHD key generation from stream-key material in [bitcoin/src/pqhd.rs](bitcoin/src/pqhd.rs)
- prefixed and legacy raw PQ secret-key codecs in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs)
- ML-KEM-512 keypair, deterministic keypair, encapsulate, deterministic encapsulate, and decapsulate helpers in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs)
- `pqhd(...)` parsing, deterministic derivation, and wallet descriptor string generation in [key_expression/src/lib.rs](/home/kiel/work/rust-tidecoin/key_expression/src/lib.rs)
- Tidecoin PSBT PQHD origin and PQ partial-signature helpers in [bitcoin/src/psbt/tidecoin.rs](bitcoin/src/psbt/tidecoin.rs)
- PQ witness helper `Witness::p2wsh512_pq()` in [bitcoin/src/blockdata/witness.rs](bitcoin/src/blockdata/witness.rs)
- Tidecoin v2 PQ packet cipher parity in [p2p/src/bip324_pq.rs](p2p/src/bip324_pq.rs)

## Remaining Validated Gaps

1. Interpreter/runtime PQ behavior is still missing.
Node implements `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and PQ signature execution in [src/script/interpreter.h](/home/kiel/work/tidecoin-node/src/script/interpreter.h) and [src/script/interpreter.cpp](/home/kiel/work/tidecoin-node/src/script/interpreter.cpp).
Rust still does not expose a Tidecoin script interpreter or validation runtime. The optional validation module is still Bitcoin-specific in [bitcoin/src/consensus_validation.rs](bitcoin/src/consensus_validation.rs).

2. Node PQ script/transaction/multisig corpora are still not migrated as executable Rust coverage.
The node executes `script_tests_pq.json`, `tx_valid_pq.json`, `tx_invalid_pq.json`, PQ asset tests, and PQ multisig tests in:
- [src/test/script_tests.cpp](/home/kiel/work/tidecoin-node/src/test/script_tests.cpp)
- [src/test/transaction_tests.cpp](/home/kiel/work/tidecoin-node/src/test/transaction_tests.cpp)
- [src/test/script_assets_tests.cpp](/home/kiel/work/tidecoin-node/src/test/script_assets_tests.cpp)
- [src/test/pq_multisig_tests.cpp](/home/kiel/work/tidecoin-node/src/test/pq_multisig_tests.cpp)
Rust has coverage for crypto containers, PQHD, PSBT metadata, and witness layout, but not the node PQ execution corpora.

## Bottom Line

The Rust port now has real PQ crypto primitives for:

- key generation
- deterministic PQHD-backed key generation
- public-key derivation from secret keys
- prefixed and legacy raw secret-key codecs
- ML-KEM-512 keypair / encapsulate / decapsulate helpers
- strict signing/verification
- Falcon-512 legacy signing/verification
- Tidecoin v2 PQ transport key derivation and packet encryption/decryption

The remaining missing layers are Tidecoin runtime validation behavior and node PQ corpus migration.
