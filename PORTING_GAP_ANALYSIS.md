# Porting Gap Analysis: rust-tidecoin Library

Generated: 2026-04-01
Revalidated after the AuxPoW, `Sighash512`, PQHD/PSBT, PQ crypto-bridge, ML-KEM-512, and `bip324_pq` transport passes.

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
- deterministic PQHD key generation
- prefixed and legacy raw PQ secret-key codecs
- `pqhd(...)` key-expression parsing, deterministic derivation, and wallet descriptor string generation
- ML-KEM-512 keypair / deterministic keypair / encapsulate / deterministic encapsulate / decapsulate helpers in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs)
- Tidecoin v2 PQ packet cipher parity in [p2p/src/bip324_pq.rs](p2p/src/bip324_pq.rs), including node-derived FSChaCha20 / FSChaCha20Poly1305 / `bip324_pq` tests
- stale unused `legacy_sighash.json` and mainnet/testnet `.raw` fixtures
- Tidecoin-facing dust/sighash docs that still used `BTC/kB` or "today's Bitcoin network" wording
- P2P message cleanup audit: `NetworkMessage` already demotes legacy `reject` payloads to `Unknown`, while `message_network::Alert` is intentionally retained because Tidecoin node still sends the final alert to peers at protocol version `<= 70012`

## Remaining Library-Scope Gaps

### 1. Tidecoin-specific validation surface

The optional validation API is still wired to upstream `bitcoinconsensus`, not Tidecoin-node semantics.

Rust state:
- [bitcoin/src/consensus_validation.rs](bitcoin/src/consensus_validation.rs)
- [bitcoin/Cargo.toml](bitcoin/Cargo.toml)

This matters because Tidecoin-specific PQ script flags and runtime behavior are not available there.

### 2. PQ execution corpus migration

Rust still does not execute the node PQ corpora:

- [src/test/data/script_tests_pq.json](/home/kiel/work/tidecoin-node/src/test/data/script_tests_pq.json)
- [src/test/data/tx_valid_pq.json](/home/kiel/work/tidecoin-node/src/test/data/tx_valid_pq.json)
- [src/test/data/tx_invalid_pq.json](/home/kiel/work/tidecoin-node/src/test/data/tx_invalid_pq.json)
- [src/test/pq_multisig_tests.cpp](/home/kiel/work/tidecoin-node/src/test/pq_multisig_tests.cpp)

This remains blocked on the absence of a Tidecoin script/runtime validation layer in the library.

## Priority Order

1. Decide the fate of the Bitcoin-specific validation API
2. PQ corpus migration, if a Tidecoin validation/runtime layer is added
