# Validation Fix Backlog

This file is updated as issues are validated and moved through the state machine.

## Open

- `ready_to_fix` Implement the remaining PQ crypto parity with Tidecoin node `src/pq/pq_api.h`: prefixed/legacy secret-key codecs, deterministic PQHD-backed key generation from derived stream material, and ML-KEM-512 operations.
- `ready_to_fix` Implement the remaining PQHD surface above the new KDF/PSBT helpers: `pqhd(...)` key-expression parsing, descriptor generation, wallet-facing policy/gating behavior, and deterministic PQ key generation from the derived stream material.
- `ready_to_fix` Implement runtime script support for `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and `SignatureHash512`, then migrate the node PQ script/transaction/multisig/policy corpora.
- `ready_to_fix` Implement Tidecoin v2 PQ transport parity with node `src/bip324_pq.h`.
- `ready_to_fix` Decide and execute the non-PQ cleanup slice for exact node/library parity: replace or remove the stale `legacy_sighash.json`/unused Bitcoin raw fixtures, trim obsolete `alert`/`reject` P2P messages if desired, and close the remaining Bitcoin-branded public docs/comments.
- `ready_to_fix` Replace or remove the optional `bitcoinconsensus` validation surface in `bitcoin/src/consensus_validation.rs`, since it validates against Bitcoin Core semantics rather than Tidecoin node semantics.

## Closed

- `done` Record the validated Falcon/PQ runtime gap report in `FALCON_PQ_GAP_REPORT.md` and align the tracker with the current node-vs-Rust compatibility status.
- `done` Implement the first PQHD parity slice: node-mirrored PQHD v1 KDF/path validation in `bitcoin/src/pqhd.rs`, Tidecoin PSBT PQHD origin helpers in `bitcoin/src/psbt/tidecoin.rs`, and regression coverage for roundtrip/combine/malformed cases.
- `done` Implement PQ public-key derivation and Falcon legacy-mode signing/verification parity in `bitcoin/src/crypto/pq.rs` using a small node-compatible PQClean bridge, with regression coverage across all five schemes.
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
