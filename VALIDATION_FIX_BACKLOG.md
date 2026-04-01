# Validation Fix Backlog

This file is updated as issues are validated and moved through the state machine.

## Open

- `fixing` Complete repository publish flow by pushing the validated tree to `origin` branch `v2`.

## Closed

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
