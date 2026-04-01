# Porting Gap Analysis: rust-tidecoin Library

Generated: 2026-04-01
Revalidated after the AuxPoW, `Sighash512`, PQHD/PSBT, and PQ crypto-bridge passes.

Node source: `/home/kiel/work/tidecoin-node`
Rust source: `/home/kiel/work/rust-tidecoin`

## Scope

This report is limited to gaps that still belong in a Tidecoin protocol library.

Out of scope:

- full node validation pipeline
- mempool/chainstate/wallet/RPC/mining
- full script interpreter execution engine
- network peer state machines

## Closed Since The Original Gap Report

- AuxPoW header serialization and sizing
- `Sighash512` and witness-v1-512 sighash support
- PSBT PQ partial-signature storage
- `SENDTXRCNCL`
- `PqScheme::is_allowed_at_height(...)`
- `Witness::p2wsh512_pq(...)`
- `from_tdc` / `to_tdc` / `as_tdc` public rename layer
- PQ random key generation, strict sign/verify, public-key derivation from secret keys
- Falcon-512 legacy signing/verification helpers

## Remaining Library-Scope Gaps

### 1. Deterministic PQHD key generation

Rust has the PQHD KDF in [bitcoin/src/pqhd.rs](bitcoin/src/pqhd.rs), but it still cannot turn derived PQHD leaf material into the deterministic Tidecoin-node keypair.

Node reference:
- [src/pq/pq_api.h](/home/kiel/work/tidecoin-node/src/pq/pq_api.h)
- [src/test/pq_pubkey_container_tests.cpp](/home/kiel/work/tidecoin-node/src/test/pq_pubkey_container_tests.cpp)

### 2. PQ secret-key codec parity

Rust still lacks prefixed secret-key parsing/serialization and legacy raw-secret compatibility.

Node reference:
- [src/pq/pq_api.h](/home/kiel/work/tidecoin-node/src/pq/pq_api.h)

Rust state:
- raw explicit-scheme secret-key parsing only in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs)

### 3. `pqhd(...)` descriptor / key-expression support

Rust has PQHD primitives but still lacks the node-facing descriptor/key-expression surface.

Node reference:
- [src/wallet/walletutil.cpp](/home/kiel/work/tidecoin-node/src/wallet/walletutil.cpp)

### 4. Tidecoin-specific validation surface

The optional validation API is still wired to upstream `bitcoinconsensus`, not Tidecoin-node semantics.

Rust state:
- [bitcoin/src/consensus_validation.rs](bitcoin/src/consensus_validation.rs)
- [bitcoin/Cargo.toml](bitcoin/Cargo.toml)

This matters because Tidecoin-specific PQ script flags and runtime behavior are not available there.

### 5. PQ execution corpus migration

Rust still does not execute the node PQ corpora:

- [src/test/data/script_tests_pq.json](/home/kiel/work/tidecoin-node/src/test/data/script_tests_pq.json)
- [src/test/data/tx_valid_pq.json](/home/kiel/work/tidecoin-node/src/test/data/tx_valid_pq.json)
- [src/test/data/tx_invalid_pq.json](/home/kiel/work/tidecoin-node/src/test/data/tx_invalid_pq.json)
- [src/test/pq_multisig_tests.cpp](/home/kiel/work/tidecoin-node/src/test/pq_multisig_tests.cpp)

This remains blocked on the absence of a Tidecoin script/runtime validation layer in the library.

### 6. ML-KEM-512 and Tidecoin PQ transport

Rust still has no ML-KEM-512 helper layer and no Tidecoin PQ packet cipher.

Node reference:
- [src/pq/pq_api.h](/home/kiel/work/tidecoin-node/src/pq/pq_api.h)
- [src/bip324_pq.h](/home/kiel/work/tidecoin-node/src/bip324_pq.h)

### 7. Stale non-PQ cleanup

These are still real cleanup gaps, though lower priority than protocol blockers:

- stale unused Bitcoin fixtures remain in `bitcoin/tests/data/mainnet_block_*.raw` and `bitcoin/tests/data/testnet_block_*.raw`
- stale `bitcoin/tests/data/legacy_sighash.json` remains in-tree even though node-backed `sighash.json` is now present
- obsolete `alert` / `reject` P2P message variants still exist in [p2p/src/message.rs](p2p/src/message.rs) while the node’s current message list no longer advertises them
- some public docs/comments still say `Bitcoin`, `Bitcoin Core`, or `BTC/kB`

## Priority Order

1. Deterministic PQHD key generation and secret-key codec parity
2. `pqhd(...)` descriptor/key-expression support
3. Decide the fate of the Bitcoin-specific validation API
4. PQ corpus migration, if a Tidecoin validation/runtime layer is added
5. ML-KEM/PQ transport
6. stale fixture / obsolete-message / wording cleanup
