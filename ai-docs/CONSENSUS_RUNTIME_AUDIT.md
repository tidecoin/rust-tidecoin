# Consensus Runtime Audit

This note is a historical audit record for the imported
[`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) runtime.
The migration it originally planned is now complete for the active runtime.

Do not use this file as the next implementation checklist. The current active
plan is [README.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/README.md)
and the current consensus checklist is
[consensus/docs/pq-integration-plan.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/docs/pq-integration-plan.md).

## Audit Standard

Primary source of truth:

- Tidecoin node checkout at `~/dev/tidecoin/tidecoin`

Supporting internal evidence:

- [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
- [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
- [consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
- [consensus-core/src/sighash.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs)
- [consensus-core/src/witness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs)
- [consensus-core/src/pq.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)

Not valid as the acceptance target:

- upstream Bitcoin behavior
- `bitcoinconsensus`
- upstream `bitcoin` transaction/script/sighash types as the runtime model

## Current Result

- [`consensus/src/lib.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
  is now a Tidecoin-native byte-oriented adapter over
  [`consensus-core/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core).
- The old local engine files `consensus/src/script.rs` and `consensus/src/tx.rs`
  have been removed.
- [`consensus-core/src/interpreter.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  owns the shared Tidecoin script interpreter.
- [`consensus-core/src/tx.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
  owns the shared typed transaction context and precompute layer.
- [`consensus-core/src/sighash.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs)
  owns consensus sighash computation.
- [`consensus-core/src/witness.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs)
  owns witness-program classification and execution planning.
- [`consensus-core/src/pq.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)
  owns the verification-only PQ facade used by consensus execution.
- Active runtime code no longer depends on upstream `bitcoin::*`,
  `bitcoinconsensus`, ECDSA, Schnorr, Taproot, or Tapscript as the consensus
  model.

## Tidecoin Node Runtime Model

The Tidecoin node runtime model used for this migration is:

- active post-auxpow script flags:
  - `SCRIPT_VERIFY_PQ_STRICT`
  - `SCRIPT_VERIFY_WITNESS_V1_512`
  - `SCRIPT_VERIFY_SHA512`
- active script versions:
  - `BASE`
  - `WITNESS_V0`
  - `WITNESS_V1_512`
- post-quantum signature verification with legacy Falcon gating via
  `allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT)`
- `OP_SHA512` execution only when `SCRIPT_VERIFY_SHA512` is active
- witness-v1-512 execution, not Taproot/Tapscript execution

## Closed Findings

These were the original active runtime findings and are now closed:

- `consensus/src/lib.rs` no longer exports Taproot, DER/low-S, or Bitcoin-only
  public validation flags.
- `height_to_flags(...)` no longer models Bitcoin activation heights; the
  Tidecoin surface has an auxpow-aware helper.
- `verify(...)` and `verify_with_details(...)` no longer enable Taproot based on
  `spent_outputs`.
- Taproot-specific public error messages such as
  `ERR_SPENT_OUTPUTS_REQUIRED` and `ERR_SPENT_OUTPUTS_MISMATCH` were removed.
- The shared interpreter no longer uses secp256k1, ECDSA, Schnorr, Taproot
  control blocks, annex handling, or Tapscript validation-weight logic.
- The shared transaction layer no longer contains Taproot precompute fields.
- The active test suite no longer treats Bitcoin or `bitcoinconsensus` as the
  runtime reference model.
- The explicitly Bitcoin/Core-diff integration suite is archived under
  [consensus/tests/archived/](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived)
  and is not part of the active Cargo test surface.

## Current Remaining Work

The runtime migration itself is not the blocker anymore. Remaining work is:

- reconcile the archived proof classes against active Tidecoin-node parity tests
  in
  [CONSENSUS_TEST_COVERAGE_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md)
- keep auditing new top-level wrapper/error seams for real duplicate
  validation logic before adding new `consensus-core` APIs
- keep `consensus/` as a byte-oriented standalone adapter and prevent it from
  regaining local transaction, script, witness, PQ, or sighash models
- delete archived historical tests once their proof value has either been
  replaced or explicitly rejected as non-Tidecoin behavior
