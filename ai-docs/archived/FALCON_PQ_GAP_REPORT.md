# Falcon/PQ Gap Report

Status: historical parity report; no active Falcon/PQ library-scope gaps remain
in the tracked set.

This report captures the Falcon/PQ behaviors revalidated against the Rust port after the latest validation and fixing pass.

Validation basis:

- Tidecoin node source under `~/dev/tidecoin/tidecoin`
- Rust port source under `/home/yaroslav/dev/tidecoin/rust-tidecoin`
- re-scan after AuxPoW header/modeling work, `Sighash512`, PQHD, PQ crypto
  bridge work, `consensus-core` extraction, and node-backed validation/runtime
  migration

## What Exists In Rust Today

- random PQ key generation for all five schemes in [tidecoin/src/crypto/pq.rs](../../tidecoin/src/crypto/pq.rs)
- strict PQ signing and verification for 32-byte and 64-byte messages in [tidecoin/src/crypto/pq.rs](../../tidecoin/src/crypto/pq.rs)
- node-compatible public-key derivation from secret keys in [tidecoin/src/crypto/pq.rs](../../tidecoin/src/crypto/pq.rs)
- node-compatible Falcon-512 legacy signing and verification helpers in [tidecoin/src/crypto/pq.rs](../../tidecoin/src/crypto/pq.rs)
- scheme-height gating helper in [tidecoin/src/crypto/pq.rs](../../tidecoin/src/crypto/pq.rs)
- `Sighash512` and `p2wsh512_signature_hash()` in [consensus-core/src/sighash.rs](../../consensus-core/src/sighash.rs)
- PQHD v1 KDF/path validation in [tidecoin/src/pqhd.rs](../../tidecoin/src/pqhd.rs)
- deterministic PQHD key generation from stream-key material in [tidecoin/src/pqhd.rs](../../tidecoin/src/pqhd.rs)
- prefixed and legacy raw PQ secret-key codecs in [tidecoin/src/crypto/pq.rs](../../tidecoin/src/crypto/pq.rs)
- node-compatible PQ base58 secret import/export in [tidecoin/src/crypto/key.rs](../../tidecoin/src/crypto/key.rs)
- ML-KEM-512 keypair, deterministic keypair, encapsulate, deterministic encapsulate, and decapsulate helpers in [tidecoin/src/crypto/pq.rs](../../tidecoin/src/crypto/pq.rs)
- `pqhd(...)` parsing, deterministic derivation, and wallet descriptor string generation in [tidecoin/src/key_expression.rs](../../tidecoin/src/key_expression.rs)
- PQ witness helper `Witness::p2wsh512_pq()` in [tidecoin/src/blockdata/witness.rs](../../tidecoin/src/blockdata/witness.rs)
- Tidecoin v2 PQ packet cipher parity in [p2p/src/pq_v2_transport.rs](../../p2p/src/pq_v2_transport.rs)
- Tidecoin validation/runtime behavior for PQ scripts in [tidecoin/src/consensus_validation.rs](../../tidecoin/src/consensus_validation.rs), [tidecoin/src/consensus_validation_node.rs](../../tidecoin/src/consensus_validation_node.rs), and [tidecoin/src/consensus_validation_tidecoin.rs](../../tidecoin/src/consensus_validation_tidecoin.rs)
- node-backed executable PQ corpus coverage for:
  - `script_tests_pq.json`
  - `tx_valid_pq.json`
  - `tx_invalid_pq.json`
  - `script_assets_test.json`
  - mixed witness-v0/v1-512 cases
  - exact legacy-WIF `key_io` BASE-sighash verification vectors
  - PQ bech32 namespace/checksum rejection cases
  - single-scheme PQ multisig and committed-hash matrices
  - strict-mode PQ multisig cases
  - PQ multisig mixed/negative/limit cases
  - committed-hash mixed/failure cases
  - legacy base-signature verification cases

## Remaining Validated Gaps

No confirmed Falcon/PQ library-scope runtime gaps remain in the previously tracked set.

No confirmed executable-coverage debt remains inside the previously tracked Falcon/PQ set.

Optional future expansion areas, if the library needs to expose more of the node surface:

- additional node policy helpers layered above the current validation bridge
- future node PQ vectors beyond the currently imported script, transaction, asset, and multisig cases
- chain-level AuxPoW, yespower/scrypt PoW-hash selection, and difficulty
  coverage are outside this Falcon/PQ report; they are tracked in the master
  plan and validation backlog.

## Bottom Line

The Rust port now has real PQ crypto primitives for:

- key generation
- deterministic PQHD-backed key generation
- public-key derivation from secret keys
- prefixed and legacy raw secret-key codecs
- ML-KEM-512 keypair / encapsulate / decapsulate helpers
- strict signing/verification
- Falcon-512 legacy signing/verification
- Tidecoin runtime validation behavior for PQ scripts, `OP_SHA512`, and witness-v1-512
- node-backed PQ script, transaction, asset, and multisig regression coverage
- Tidecoin v2 PQ transport key derivation and packet encryption/decryption

The remaining work is maintenance and future parity growth, not an identified missing Falcon/PQ library slice from this report.
