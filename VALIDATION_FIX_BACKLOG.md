# Validation Fix Backlog

This file is updated as issues are validated and moved through the state machine.

## Open

- None in the currently tracked library-scope validation set.

## Closed

- `done` Implement the Tidecoin validation/runtime surface in `bitcoin/src/consensus_validation.rs`, `bitcoin/src/consensus_validation_node.rs`, and `bitcoin/src/consensus_validation_tidecoin.rs`, then migrate the node PQ script/transaction/asset/multisig corpora with additional mixed witness-v0/v1-512 and legacy base-signature regression coverage.
- `done` Fence off the optional `bitcoinconsensus` validation surface in `bitcoin/src/consensus_validation.rs` so Tidecoin-only flags and `p2wsh512` outputs fail explicitly instead of being forwarded to Bitcoin Core semantics.
- `done` Record the validated Falcon/PQ runtime gap report in `FALCON_PQ_GAP_REPORT.md` and align the tracker with the current node-vs-Rust compatibility status.
- `done` Implement the first PQHD parity slice: node-mirrored PQHD v1 KDF/path validation in `bitcoin/src/pqhd.rs`, Tidecoin PSBT PQHD origin helpers in `bitcoin/src/psbt/tidecoin.rs`, and regression coverage for roundtrip/combine/malformed cases.
- `done` Implement PQ public-key derivation and Falcon legacy-mode signing/verification parity in `bitcoin/src/crypto/pq.rs` using a small node-compatible PQClean bridge, with regression coverage across all five schemes.
- `done` Implement deterministic PQHD key generation and PQ secret-key codec parity in `bitcoin/src/pqhd.rs` and `bitcoin/src/crypto/pq.rs`, with exact node hash vectors and prefixed/raw-secret roundtrip coverage.
- `done` Implement `pqhd(...)` parsing, deterministic derivation, and wallet descriptor string generation in `key_expression/src/lib.rs`, with node-style parsing and policy tests.
- `done` Implement ML-KEM-512 keypair / deterministic keypair / encapsulate / deterministic encapsulate / decapsulate helpers in `bitcoin/src/crypto/pq.rs`, with node-style roundtrip and deterministic regression coverage.
- `done` Implement Tidecoin v2 PQ transport parity from node `src/bip324_pq.h` in `p2p/src/bip324_pq.rs`, with node-derived FSChaCha20, FSChaCha20Poly1305, and packet-cipher tests.
- `done` Remove the dead `legacy_sighash.json` and unused mainnet/testnet raw fixtures, correct the remaining Tidecoin-facing `BTC/kB` / "today's Bitcoin network" docs, and confirm that legacy `reject` payloads already decode as `Unknown` while `alert` remains live for old-peer compatibility.
- `done` Complete repository publish flow by pushing the validated tree to `origin` branch `v2` (`d8bbe1e`).
- `done` Replace stale `Network::Bitcoin` references in feature-gated tests and examples so `cargo check -p tidecoin --all-features --tests --examples` succeeds.
- `done` Remove stale mainnet address literals and legacy Bitcoin wording from examples/docs/fuzz generator.
- `done` Remove or refactor unused PQ code paths and clippy violations in `bitcoin/src/crypto/pq.rs`, and add real PQ coverage.
- `done` Reconcile legacy base58 behavior with the Tidecoin node, including dual P2SH decode prefixes.
- `done` Eliminate remaining warnings and dead code across requested compile targets; strict clippy currently passes.
- `done` Delete the unused internal taproot signature module and the disabled taproot-only sighash layer so strict clippy passes without dead-code allowances.
- `done` Remove the dedicated `TapScriptTag` marker from primitives and collapse `TapScript{,Buf}` onto the witness-script types to reduce taproot-specific surface while preserving workspace compilation.
- `done` Remove the hidden `bitcoin/src/taproot/**` module and its dependent consensus/key hooks.
- `done` Align regtest legacy address and WIF formatting with Tidecoin node prefixes instead of collapsing regtest into generic testnet handling.
- `done` Align `MAX_STANDARD_TX_WEIGHT` with the Tidecoin node policy constant and add regression coverage.
- `done` Migrate Tidecoin node `key_io_valid.json` and `key_io_invalid.json` into integration coverage for addresses and WIF keys.
- `done` Audit every live `#[ignore]` and close the code-level ignore debt; no Rust `#[ignore]` test attributes remain.
- `done` Convert avoidable ignored doctests to checked examples and document the three remaining justified ignored doctest sketches.
- `done` Remove the residual `is_p2tr()` API and taproot-era serde fixtures while retaining `OP_CHECKSIGADD` only as a disabled node-compatibility opcode.
