# Removed Validation Test Surfaces

This note records validation-test surfaces that were removed when the live
[`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) crate stopped
depending on `bitcoinconsensus`.

These surfaces were initially deferred as explicit test debt. They are now
restored in the live Tidecoin validation tests, and this note remains as the
record of what was removed and how it was replaced.

## Why These Tests Were Removed

Two tests in the main crate were tied directly to the old Bitcoin-only
`bitcoinconsensus` backend:

- [`tidecoin/src/blockdata/script/tests.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/script/tests.rs)
  - removed test: `bitcoinconsensus()`
- [`tidecoin/src/blockdata/transaction.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/transaction.rs)
  - removed test: `transaction_verify()`

They were removed because:

- they exercised a backend the live Tidecoin crate no longer exposes
- they used Bitcoin ECDSA / Bitcoin witness-era transactions, not Tidecoin-native fixtures
- keeping them would falsely imply that `bitcoinconsensus` is still part of the
  supported Tidecoin validation surface

## What Those Tests Actually Covered

Even though the fixtures were wrong, the public-surface coverage they provided
was real. That coverage should be restored with Tidecoin-native transactions and
scripts.

### 1. Direct `ScriptPubKeyExt::verify(...)` Acceptance Path

Previously covered by:

- the removed `bitcoinconsensus()` test

What it proved:

- the public byte-oriented validation API could accept a fully signed witness
  spend end to end

Tidecoin-native replacement target:

- add a direct `ScriptPubKeyExt::verify(...)` success test using a Tidecoin
  native spend
- prefer a node-backed fixture or a locally constructed PQ-native spend over a
  synthetic Bitcoin witness example

Recommended fixture shape:

- PQ legacy-base spend, or
- witness-v1-512 spend, or
- another Tidecoin-native witness path that is already node-parity-tested

Status:

- restored in
  [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
  by `verify_script_public_api_accepts_pq_strict_base_spend`

### 2. Public `verify_transaction_with_flags(...)` / `TransactionExt::verify(...)` Success Path

Previously covered by:

- the removed `transaction_verify()` test

What it proved:

- the transaction-level public API could validate a signed transaction against a
  spent-output provider

Tidecoin-native replacement target:

- add a success-path test using a Tidecoin-native signed transaction
- prefer more than one input once a good fixture exists, because the removed
  test exercised multi-input transaction validation

Status:

- restored in
  [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
  by `verify_transaction_public_api_accepts_pq_strict_two_input_spend`

### 3. Transaction-Level Failure On Reused / Missing Spent Outputs

Previously covered by:

- the removed `transaction_verify()` test using a `HashMap` that consumed
  spent outputs

What it proved:

- `TransactionExt::verify(...)` surfaces a transaction-level failure when the
  spent-output provider cannot supply an output for a later input

Important nuance:

- this is mostly public-API/provider behavior, not Tidecoin cryptography
- it is still worth preserving because it exercises the ergonomics and error
  path of the transaction-level verification helper

Tidecoin-native replacement target:

- add a test that reuses a Tidecoin-native input or otherwise causes the spent
  output provider to fail on the second lookup
- assert that the public API returns the expected transaction-level error

Status:

- restored in
  [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
  by:
  - `verify_transaction_public_api_errors_on_missing_spent_output`
  - `verify_transaction_public_api_errors_on_reused_spent_output`

### 4. Transaction-Level Rejection For Corrupted Signature / Witness Data

Previously covered by:

- the removed `transaction_verify()` test after mutating witness bytes

What it proved:

- the public transaction-level API rejects a transaction when otherwise valid
  signature or witness material is corrupted

Tidecoin-native replacement target:

- add a test that corrupts Tidecoin-native signature data
- prefer a node-backed or already parity-checked fixture, so the failure is tied
  to real Tidecoin semantics instead of a hand-waved synthetic example

Status:

- restored in
  [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
  by `verify_transaction_public_api_errors_on_corrupted_signature`

## Current Audit Result

Current live validation coverage in the main crate:

- [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
  currently carries:
  - `verify_script_with_flags_accepts_pq_legacy_base_spend`
  - `verify_transaction_public_api_accepts_pq_legacy_base_spend`
  - `verify_script_public_api_accepts_pq_strict_base_spend`
  - `verify_transaction_public_api_accepts_pq_strict_two_input_spend`
  - `verify_transaction_public_api_errors_on_missing_spent_output`
  - `verify_transaction_public_api_errors_on_reused_spent_output`
  - `verify_transaction_public_api_errors_on_corrupted_signature`

Additional audit result:

- no other direct Bitcoin-consensus-backed validation tests remain in the live
  [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) crate
- the remaining Bitcoin-looking tests in `blockdata/script/tests.rs` and
  `blockdata/transaction.rs` are mostly structural/classification/serialization/weight
  tests, not validation-backend tests

## Separate Cleanup Candidates (Not The Same As Removed Validation Coverage)

These tests are not the same problem as the removed `bitcoinconsensus` tests,
but they still carry Bitcoin- or ECDSA-era fixtures and may deserve later
rewriting if the goal is broader Tidecoin-only semantics in the main crate.

### Structural Script Tests With Bitcoin Witness Fixtures

Candidate examples:

- [tidecoin/src/blockdata/script/tests.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/script/tests.rs)
  - `p2sh_p2wsh_conversion()`
  - `script_generators()` uses `new_p2wpkh()` / `new_p2wsh()`

Why they are not immediate validation debt:

- they test script construction/classification utilities
- they do not exercise the public validation backend

Why they may still deserve later review:

- the fixtures and naming are inherited from Bitcoin Core-era compatibility
- if the main crate wants to stop foregrounding Bitcoin witness-era script
  templates, these are candidates to rewrite around Tidecoin-native script forms
  or to move under a clearly labeled compatibility surface

### Structural Transaction Tests With Bitcoin Witness Fixtures

Candidate examples:

- [tidecoin/src/blockdata/transaction.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/transaction.rs)
  - `txid()`
  - `ntxid()`
  - `txin_txout_weight()`
  - `tx_sigop_count()`
  - weight-prediction helpers using `P2WPKH` / `P2WSH`

Why they are not immediate validation debt:

- they test txid/wtxid/weight/sigop and helper behavior
- they do not prove or gate the live Tidecoin validation backend

Why they may still deserve later review:

- they still foreground Bitcoin witness-era fixture shapes
- some helper names, comments, and fixture choices remain compatibility-driven
  rather than Tidecoin-native in tone

## Practical Priority Rule

Use this priority order:

1. Finish the `consensus/` migration and shared node-parity harness work.
2. Revisit the broader structural Bitcoin/ECDSA-era fixture cleanup in
   `blockdata/script/tests.rs` and `blockdata/transaction.rs`.

## Required Replacement Checklist

- [x] Add an explicit direct `ScriptPubKeyExt::verify(...)` Tidecoin-native success test.
- [x] Add a Tidecoin-native multi-input `verify_transaction_with_flags(...)` success test.
- [x] Add a Tidecoin-native `TransactionExt::verify(...)` failure test for missing/reused spent outputs.
- [x] Add a Tidecoin-native `TransactionExt::verify(...)` failure test for corrupted signature or witness data.
- [x] Prefer fixtures that are already verified against the Tidecoin node or are
      loaded through the shared node-parity harness.

## Recommended Landing Point

Preferred home for the replacement tests:

- short term:
  [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
  or
  [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)
- longer term:
  shared Tidecoin-native validation tests built around
  [`node-parity/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity) and
  the extracted `tidecoin-consensus-core`
