# Porting Gap Analysis: rust-tidecoin Library

Generated: 2026-04-01
Revalidated after the AuxPoW, `Sighash512`, PQHD/PSBT, PQ crypto-bridge, ML-KEM-512, `bip324_pq`, and node-backed validation/runtime passes.

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
- Tidecoin-specific validation/runtime surface in [bitcoin/src/consensus_validation.rs](bitcoin/src/consensus_validation.rs), [bitcoin/src/consensus_validation_node.rs](bitcoin/src/consensus_validation_node.rs), and [bitcoin/src/consensus_validation_tidecoin.rs](bitcoin/src/consensus_validation_tidecoin.rs)
- node PQ execution corpus migration covering `script_tests_pq.json`, `tx_valid_pq.json`, `tx_invalid_pq.json`, `script_assets_test.json`, mixed witness-v0/v1-512 cases, PQ multisig cases, committed-hash cases, and legacy base-signature cases
- stale unused `legacy_sighash.json` and mainnet/testnet `.raw` fixtures
- Tidecoin-facing dust/sighash docs that still used `BTC/kB` or "today's Bitcoin network" wording
- P2P message cleanup audit: `NetworkMessage` already demotes legacy `reject` payloads to `Unknown`, while `message_network::Alert` is intentionally retained because Tidecoin node still sends the final alert to peers at protocol version `<= 70012`

## Remaining Library-Scope Gaps

No confirmed library-scope protocol gaps remain from the original report.

Follow-up work that may still be desirable, but was not part of the original library-scope gap list:

- expose additional node policy entry points such as witness-standardness or standard-tx helpers if callers need policy parity instead of consensus/runtime parity
- continue expanding imported node cases as new Tidecoin node behavior lands upstream

## Priority Order

1. Keep the node-backed validation bridge green as Tidecoin node evolves
2. Add extra policy wrappers only if downstream callers need them
