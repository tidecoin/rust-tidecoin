# Tidecoin Validation To Core Audit

This note records the top-level Tidecoin validation audit that followed the
large `consensus` to `consensus-core` engine refactor, and the resulting
adapter move that is now landed.

It answers a narrower question than the earlier `consensus` runtime audit:

- what in the top-level Tidecoin validator is still the real reusable engine?
- what is now duplicate engine code that should be replaced by
  [`consensus-core/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core)?
- what should intentionally stay in the top-level crate as wrapper/routing code?

## Scope

Primary files:

- [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
- [tidecoin/src/consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)

Shared-core comparison target:

- [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
- [consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
- [consensus-core/src/witness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs)
- [consensus-core/src/pq.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)
- [consensus-core/src/sighash.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs)

Acceptance standard:

- the actual Tidecoin node at `~/dev/tidecoin/tidecoin`

## Main Finding

The imported [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus)
crate is no longer the architectural blocker. The remaining duplication was in
the top-level Tidecoin validator, and that duplication has now been removed.

Specifically, [consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)
used to contain a second full interpreter body that overlapped heavily with the
engine now owned by [`consensus-core/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core).
That file is now a thin adapter over the shared core and no longer owns the
engine.

## Keep / Replace Map

### Keep In Top-Level `tidecoin`

These are top-level wrapper or routing responsibilities and should remain in the
top-level crate.

#### `consensus_validation.rs`

Keep:

- public API entrypoints:
  - `verify_script`
  - `verify_script_with_flags`
  - `verify_transaction`
  - `verify_transaction_with_flags`
- public wrapper error types:
  - `ValidationError`
  - `TxVerifyError`
- extension traits:
  - `ScriptPubKeyExt`
  - `TransactionExt`
- node-routing orchestration between:
  - node-backed validation
  - pure-Rust validation

Reason:

- this is the public Tidecoin crate API surface
- it should stay the orchestration layer above the shared engine

#### Top-level routing heuristics in `consensus_validation_tidecoin.rs`

Keep:

- `should_use_tidecoin_validation`
- helper predicates used only by that routing decision:
  - `script_contains_opcode`
  - `script_contains_pq_material`
  - `witness_contains_pq_material`
  - `witness_contains_opcode_script`

Reason:

- these functions decide when the top-level crate routes to the Tidecoin-aware
  path
- they are not the reusable validation engine itself
- they are wrapper/policy dispatch above script execution

### Replaced With Shared-Core Use

These items in
[consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)
were duplicate engine code. They have now been replaced by direct
`consensus-core` use and deleted from the top-level crate.

#### Public-looking adapter that is now thin

- `verify_script_input`

Current shape:

- thin adapter over:
  - `consensus_core::TransactionContext`
  - `consensus_core::SpentOutputs`
  - `consensus_core::SpendContext`
  - `consensus_core::ScriptFlags`
  - `consensus_core::Interpreter`

Result:

- this is the top-level Tidecoin fallback verifier
- it now builds the shared typed context and calls the `consensus-core`
  interpreter directly

#### Interpreter-owned internals deleted from top-level

- `SigVersion`
- `Stack`
- `EvalContext`
- `eval_script`
- `checksig`
- `checkmultisig`
- `checksig_against_code`
- `build_script_code_for_checksig`
- `build_multisig_script_code`
- `verify_signature`
- `verify_witness_program`
- `split_signature_hash_type`
- `bool_bytes`
- `encode_script_num`
- `decode_script_num`
- `op_to_num`
- `find_and_delete`
- `push_script`
- `check_lock_time`
- `check_sequence`
- `witness_program_from_script`

Result:

- these are not Tidecoin-wrapper responsibilities
- they were the actual validation engine
- they now live in:
  - [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  - [consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
  - [consensus-core/src/witness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs)
  - [consensus-core/src/pq.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)
  - [consensus-core/src/sighash.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs)

### Transitional shim still worth revisiting

In [consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs):

- `map_fallback_validation_error`

Why:

- this exists because the current node-validation routing still maps between a
  node-facing public error surface and the `consensus-core` fallback surface
- it is much smaller now, but it is still an adapter seam that could likely be
  simplified further

## Concrete Gap Between `tidecoin` And `consensus-core`

The main engine-duplication gap is now closed.

The remaining work is narrower:

- keep wrapper/orchestration responsibilities in the top-level
  [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) crate
- keep lowering any still-reusable validation/runtime helpers that only exist
  in top-level Tidecoin modules but belong in shared core
- simplify the remaining error/adaptation seams between:
  - [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
  - [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)
  - [`consensus-core/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core)

## Recommended Next Refactor

1. Review the remaining public/error adapter seam in
   [consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
   and decide whether `map_fallback_validation_error` can be collapsed further.

2. Audit any still-top-level validation helpers outside the already-thin
   [consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)
   and move them down only if they are truly shared engine responsibilities.

3. Keep the top-level crate focused on:
   - public wrapper entrypoints
   - routing heuristics
   - node-backed parity integration
   rather than engine ownership.

## Exit Criteria

This audit is complete when:

- `tidecoin/src/consensus_validation_tidecoin.rs` no longer owns a second full
  interpreter body
- the top-level Tidecoin crate uses `consensus-core` as its pure-Rust fallback
  engine
- only routing/public-wrapper logic remains in the top-level validation files

Current status:

- complete
