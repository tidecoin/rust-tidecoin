# Porting Gap Analysis: rust-tidecoin Library

Generated: 2026-04-01
Revalidated after the AuxPoW, `Sighash512`, PQHD/PSBT, PQ crypto-bridge, ML-KEM-512, Tidecoin PQ v2 transport, and node-backed validation/runtime passes.

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
- node-compatible PQ base58 secret import/export for prefixed and legacy Falcon-512 WIF paths
- ML-KEM-512 keypair / deterministic keypair / encapsulate / deterministic encapsulate / decapsulate helpers in [tidecoin/src/crypto/pq.rs](../tidecoin/src/crypto/pq.rs)
- Tidecoin v2 PQ packet cipher parity in [p2p/src/pq_v2_transport.rs](../p2p/src/pq_v2_transport.rs), including node-derived FSChaCha20 / FSChaCha20Poly1305 / PQ v2 transport tests
- Tidecoin-specific validation/runtime surface in [tidecoin/src/consensus_validation.rs](../tidecoin/src/consensus_validation.rs), [tidecoin/src/consensus_validation_node.rs](../tidecoin/src/consensus_validation_node.rs), and [tidecoin/src/consensus_validation_tidecoin.rs](../tidecoin/src/consensus_validation_tidecoin.rs)
- node PQ execution corpus migration covering `script_tests_pq.json`, `tx_valid_pq.json`, `tx_invalid_pq.json`, `script_assets_test.json`, mixed witness-v0/v1-512 cases, PQ multisig cases, committed-hash cases, and legacy base-signature cases
- node policy helper parity for dust thresholds, witness-program classification, standard-tx reasons, exact legacy sigop boundaries, and PQ input-vsize formulas
- exact node `key_io` legacy-WIF BASE-sighash verification vector and the library-equivalent toolpath regression
- PQ bech32 namespace/checksum rejection coverage from `key_io_tests.cpp`, plus parser namespace enforcement for PQ HRPs
- single-scheme PQ multisig and committed-hash matrix coverage from `pq_multisig_tests.cpp`
- strict-mode PQ multisig coverage and the remaining witness-script / bare-policy / worst-case-weight tails from `pq_multisig_tests.cpp`
- stale unused `legacy_sighash.json` and mainnet/testnet `.raw` fixtures
- Tidecoin-facing dust/sighash docs that still used `BTC/kB` or "today's Bitcoin network" wording
- P2P message cleanup audit: `NetworkMessage` already demotes legacy `reject` payloads to `Unknown`, while `message_network::Alert` is intentionally retained because Tidecoin node still sends the final alert to peers at protocol version `<= 70012`

## Remaining Library-Scope Gaps

No confirmed library-scope protocol gaps remain from the original report.

Taproot status note:

- live taproot execution/address/script support is removed from the Tidecoin-facing API surface
- remaining taproot mentions in the tree are limited to explicit rejection paths, disabled-opcode/raw-decoding compatibility, x-only secp utilities, and historical upstream changelog material

Follow-up work that may still be desirable, but was not part of the original library-scope gap list:

- expose additional node policy entry points such as witness-standardness or standard-tx helpers if callers need policy parity instead of consensus/runtime parity
- continue expanding imported node cases as new Tidecoin node behavior lands upstream

## Remaining Executable Coverage Debt

No confirmed residual executable-coverage debt remains from the previously tracked node test list.

## Priority Order

1. Keep the node-backed validation and policy suite green as Tidecoin node evolves
2. Import new upstream Tidecoin node cases as they land
3. Add extra wrappers only if downstream callers need more of the node surface
