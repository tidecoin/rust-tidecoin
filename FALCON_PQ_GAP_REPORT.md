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
- Tidecoin PSBT PQHD origin and PQ partial-signature helpers in [bitcoin/src/psbt/tidecoin.rs](bitcoin/src/psbt/tidecoin.rs)
- PQ witness helper `Witness::p2wsh512_pq()` in [bitcoin/src/blockdata/witness.rs](bitcoin/src/blockdata/witness.rs)

## Remaining Validated Gaps

1. Deterministic PQHD key generation is still missing.
Node exposes `KeyGenFromSeed`, `KeyGenFromSeedBytes`, and `KeyGenFromLeafMaterial` in [src/pq/pq_api.h](/home/kiel/work/tidecoin-node/src/pq/pq_api.h) and uses that flow in [src/test/pq_pubkey_container_tests.cpp](/home/kiel/work/tidecoin-node/src/test/pq_pubkey_container_tests.cpp).
Rust derives PQHD leaf material in [bitcoin/src/pqhd.rs](bitcoin/src/pqhd.rs), but it still has no API that converts that material into the node-compatible deterministic `(PqPublicKey, PqSecretKey)` pair.

2. PQ secret-key codec parity is still incomplete.
Node has prefixed/raw secret-key decode and encode helpers, including legacy raw-secret acceptance, in [src/pq/pq_api.h](/home/kiel/work/tidecoin-node/src/pq/pq_api.h).
Rust still only accepts raw secret bytes via explicit scheme in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs). There is no equivalent prefixed secret-key parser/serializer or legacy-raw compatibility layer.

3. PQHD descriptor/key-expression integration is still missing.
Node builds `pqhd(...)` descriptors and enforces wallet-facing network and height policy in [src/wallet/walletutil.cpp](/home/kiel/work/tidecoin-node/src/wallet/walletutil.cpp).
Rust has no `pqhd(...)` parser or descriptor/key-expression surface in `bitcoin/src` or `key_expression/`.

4. Interpreter/runtime PQ behavior is still missing.
Node implements `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and PQ signature execution in [src/script/interpreter.h](/home/kiel/work/tidecoin-node/src/script/interpreter.h) and [src/script/interpreter.cpp](/home/kiel/work/tidecoin-node/src/script/interpreter.cpp).
Rust still does not expose a Tidecoin script interpreter or validation runtime. The optional validation module is still Bitcoin-specific in [bitcoin/src/consensus_validation.rs](bitcoin/src/consensus_validation.rs).

5. Node PQ script/transaction/multisig corpora are still not migrated as executable Rust coverage.
The node executes `script_tests_pq.json`, `tx_valid_pq.json`, `tx_invalid_pq.json`, PQ asset tests, and PQ multisig tests in:
- [src/test/script_tests.cpp](/home/kiel/work/tidecoin-node/src/test/script_tests.cpp)
- [src/test/transaction_tests.cpp](/home/kiel/work/tidecoin-node/src/test/transaction_tests.cpp)
- [src/test/script_assets_tests.cpp](/home/kiel/work/tidecoin-node/src/test/script_assets_tests.cpp)
- [src/test/pq_multisig_tests.cpp](/home/kiel/work/tidecoin-node/src/test/pq_multisig_tests.cpp)
Rust has coverage for crypto containers, PQHD, PSBT metadata, and witness layout, but not the node PQ execution corpora.

6. ML-KEM-512 and Tidecoin PQ transport are still missing.
Node exposes ML-KEM-512 operations in [src/pq/pq_api.h](/home/kiel/work/tidecoin-node/src/pq/pq_api.h) and builds the Tidecoin packet cipher in [src/bip324_pq.h](/home/kiel/work/tidecoin-node/src/bip324_pq.h) and [src/bip324_pq.cpp](/home/kiel/work/tidecoin-node/src/bip324_pq.cpp).
Rust has no ML-KEM or PQ transport module in `bitcoin/src` or `p2p/src`.

## Bottom Line

The Rust port now has real PQ crypto primitives for:

- key generation
- public-key derivation from secret keys
- strict signing/verification
- Falcon-512 legacy signing/verification

The remaining missing layers are deterministic PQHD-backed key generation, secret-key codec parity, descriptor integration, Tidecoin runtime validation behavior, node PQ corpus migration, and ML-KEM/PQ transport.
