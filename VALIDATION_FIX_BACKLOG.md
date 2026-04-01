# Validation Fix Backlog

This file is updated as issues are validated and moved through the state machine.

## Open

- `ready_to_fix` Implement runtime script support for `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and `SignatureHash512`, then migrate the node PQ script/transaction/multisig/policy corpora.
- `ready_to_fix` Replace or remove the optional `bitcoinconsensus` validation surface in `bitcoin/src/consensus_validation.rs`, since it validates against Bitcoin Core semantics rather than Tidecoin node semantics.

## Closed

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
