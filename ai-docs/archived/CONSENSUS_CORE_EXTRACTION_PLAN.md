# Consensus Core Extraction Plan

Status: archived completed architecture reference.

This note records the current shared-core architecture and the remaining
boundary work.

The extraction itself is complete. This file is preserved only as historical
context for the architecture decisions that led to the current shared-core
boundary.

Priority for the next implementation pass:

- keep the shared-core boundary narrow and avoid speculative new
  `consensus-core` APIs
- centralize any remaining consensus/protocol logic only when a code audit
  shows real duplicate behavior
- reconcile the archived proof classes against active Tidecoin-native tests
  before deleting the historical material
- fill the chain-rule coverage gaps that sit below script execution, especially
  AuxPoW validation, yespower/scrypt PoW-hash selection, and exact difficulty
  behavior

Current status:

- the first runtime audit map now exists in
  [CONSENSUS_RUNTIME_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived/CONSENSUS_RUNTIME_AUDIT.md)
- the large interpreter-boundary refactor is now landed:
  - the mature script engine lives in
    [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  - the typed transaction context/precompute layer lives in
    [consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
  - [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs) is now the byte-oriented wrapper over that shared engine
  - the old local engine files `consensus/src/script.rs` and `consensus/src/tx.rs` have been removed
- the next implementation task is not another broad extraction pass; it is a
  targeted boundary audit for any newly discovered duplicate validation or
  protocol logic

Audit standard:

- judge the `consensus/` runtime and API surface against the actual Tidecoin core node in `~/dev/tidecoin/tidecoin`
- use the in-repo [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) implementation as supporting evidence only
- do not treat upstream Bitcoin behavior as the acceptance target for migration decisions

## Decision Summary

The shared crate is:

- directory: `consensus-core/`
- package name: `tidecoin-consensus-core`

It is the single reusable Tidecoin consensus-validation engine inside this
monorepo.

The dependency direction should be:

- lower crates:
  - `consensus_encoding`
  - `hashes`
  - `internals`
  - `io`
  - `primitives`
  - `units`
  - lower PQ crates/facades
- shared engine:
  - `tidecoin-consensus-core`
- consumers:
  - top-level [`tidecoin`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin)
  - imported [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus)

The Tidecoin node remains the only external parity reference.

Follow-up audit for the next lowering phase:

- [TIDECOIN_VALIDATION_CORE_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived/TIDECOIN_VALIDATION_CORE_AUDIT.md)
  records the completed top-level fallback-engine audit and adapter move, and
  now serves as the guide for any narrower follow-up lowering from the
  top-level validation surface

The Tidecoin node-backed bridge itself must not live inside
`tidecoin-consensus-core`. That bridge now lives in the separate
shared parity/test-support layer; see
[NODE_PARITY_HARNESS_PLAN.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived/NODE_PARITY_HARNESS_PLAN.md).

## Current Reality

The extracted core can already depend on:

- transaction model types from [`primitives/src/transaction.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/transaction.rs)
- script types from [`primitives/src/script/mod.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/script/mod.rs)
- witness types from [`primitives/src/witness.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/witness.rs)
- amount/sequence/locktime types re-exported by [`primitives/src/lib.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/lib.rs)

The script ownership boundary is now explicit too:

- the canonical Tidecoin script representation/parsing/building layer lives in
  [`primitives/src/script/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/script)
- [`consensus-core/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core) executes over
  that lower script layer
- the top-level [`tidecoin/src/blockdata/script/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/script)
  layer is now a Tidecoin-specific convenience layer over `primitives`, not a
  second competing script implementation

That means the shared core does not need to depend on the top-level
[`tidecoin`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) crate just to
get transactions, scripts, or witnesses.

The opcode ownership boundary is now explicit too:

- the canonical Tidecoin opcode model lives in
  [`primitives/src/opcodes.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/opcodes.rs)
- [`consensus-core/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core) and the top-level
  [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) crate both consume that same
  lower opcode layer
- [`tidecoin/src/blockdata/opcodes.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/opcodes.rs)
  is now only a reexport/public-API layer

Remaining boundary work is now narrower than the original extraction plan:

- [`consensus-core/src/sighash.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs)
  owns the consensus sighash engine used by validation; there is no longer a
  live `tidecoin/src/crypto/sighash.rs` implementation to lower.
- [`consensus-core/src/witness.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs)
  owns consensus witness-program classification and execution planning; the
  top-level script layer should remain a convenience facade only.
- [`consensus-core/src/pq.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)
  owns verification-side PQ parsing and verification; top-level
  [`tidecoin/src/crypto/pq.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/crypto/pq.rs)
  should keep signing, keygen, key I/O, and transport helpers.

Future work should audit only real remaining duplication or facade leakage
against the Tidecoin node, not replay the original extraction checklist.

## Ownership Map

### Move Into `tidecoin-consensus-core`

These are consensus-engine responsibilities and should no longer live only as
private internals of the top-level crate.

#### From `tidecoin/src/consensus_validation_tidecoin.rs`

Moved:

- verification flag constants
- `ScriptError`
- `TidecoinValidationError`
- script interpreter and evaluator internals
- witness program verification flow
- transaction input verification helpers
- script classification helpers that are about consensus behavior, not wrapper
  dispatch

Concretely, the shared core now owns logic equivalent to:

- `verify_script_input` behind a top-level adapter
- `eval_script`
- `verify_witness_program`
- `check_lock_time`
- `check_sequence`
- `check_sig`
- `check_multisig`
- stack and opcode execution helpers

The remaining top-level file should stay thin and keep only wrapper/routing
responsibilities.

#### Sighash Ownership

Moved:

- `SighashCache`
- legacy/base sighash support
- witness-v0 sighash support
- `Sighash512` / witness-v1-512 sighash support
- script-code handling required by verification

The consensus-critical sighash engine now lives in
[`consensus-core/src/sighash.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs).
There is no active top-level `tidecoin/src/crypto/sighash.rs` module; future
cleanup should focus on keeping public signing ergonomics as thin wrappers over
the shared core when those ergonomics are needed.

#### Witness-Program Ownership

Moved:

- `WitnessProgram`
- witness-v0 / witness-v1-512 recognition used by the verifier
- any Tidecoin-specific witness-program length rules that are part of consensus

The consensus-critical witness-program parser, classifier, commitment checks,
stack preparation, executed-script selection, and sigop mode now live in
[`consensus-core/src/witness.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs).

The top-level script layer should keep only address/script-construction
ergonomics and public wrappers.

#### From `tidecoin/src/crypto/pq.rs`

Moved:

- PQ public-key parsing needed by `CHECKSIG` / `CHECKMULTISIG`
- PQ signature parsing needed by script evaluation
- message verification entry points for:
  - Falcon strict
  - Falcon legacy-accepting mode
  - ML-DSA

The shared core does not need and must not grow wallet key generation, WIF
codecs, PQHD, signing, or ML-KEM transport logic.

Status:

- the lower-level PQ verification facade now lives in
  [consensus-core/src/pq.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)
- [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  now consumes that facade directly
- `consensus/` no longer depends on the top-level `tidecoin` crate for PQ
  verification types
- the shared witness-program parser now lives in
  [consensus-core/src/witness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs)
- [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  and [consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
  are the active engine consumers of `consensus_core::WitnessProgram`
- Tidecoin witness version/length/flag classification now also lives in
  [consensus-core/src/witness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs)
  through `WitnessProgramClass`
- the active shared interpreter delegates witness gating decisions to that
  shared-core logic instead of keeping a separate version/length decision tree
- witness commitment checks, witness-stack preparation, executed-script
  selection, and sigop-accounting mode now also live in
  [consensus-core/src/witness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs)
  through `WitnessExecutionPlan`
- [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  is now the active executor over that shared witness execution plan
- lower script ownership is now also clarified:
  - rich instruction parsing/indices logic lives in
    [primitives/src/script/instruction.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/script/instruction.rs)
  - canonical push-bytes handling lives in
    [primitives/src/script/push_bytes.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/script/push_bytes.rs)
  - canonical lower builder and mutable script-buffer mutation logic live in
    [primitives/src/script/builder.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/script/builder.rs)
    and [primitives/src/script/owned.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/script/owned.rs)
  - the duplicated top-level instruction and push-bytes implementation files in
    [`tidecoin/src/blockdata/script/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/script)
    were removed in favor of that canonical lower layer

### Keep In The Top-Level `tidecoin` Crate

These are still useful public wrappers, but they should become thin layers over
the shared core.

#### In `tidecoin/src/consensus_validation.rs`

Keep:

- byte-oriented convenience API:
  - `verify_script`
  - `verify_script_with_flags`
  - `verify_transaction`
  - `verify_transaction_with_flags`
- error wrappers that bridge multiple backends:
  - `ValidationError`
  - `TxVerifyError`
- top-level extension traits and public re-exports

This file should become wrapper/orchestration code, not the main engine.

#### In `tidecoin/src/consensus_validation_node.rs`

Keep:

- node-parity helper functions
- node-backed tests and fixture harnesses

This module is not the shared core. It is an optional parity/bridge layer.

Current direction:

- raw FFI, native bridge wiring, and reusable harness code now live in
  [`node-parity/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity)
- the top-level `tidecoin` crate should keep only thin adapter/routing code here

#### In `tidecoin/src/crypto/pq.rs`

Keep:

- key generation
- secret/public key ownership types unless a clean lower PQ crate is introduced
- PQHD-related helpers
- WIF and secret serialization helpers
- ML-KEM transport helpers

Only signing, keygen, key I/O, PQHD, and transport ergonomics should remain
high-level.

### Keep Out Of The Shared Core Entirely

Do not move these into `tidecoin-consensus-core`:

- address encoding/decoding
- descriptors and key expressions
- wallet or PSBT authoring logic
- P2P code
- RPC/node runtime code
- mempool/policy logic unless it is proven consensus-critical
- node bridge build glue
- repo-specific test harness code

That node bridge and harness code now lives in the shared parity support layer
described in
[NODE_PARITY_HARNESS_PLAN.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived/NODE_PARITY_HARNESS_PLAN.md).

## Concrete Module Plan

The current extracted module layout is small and explicit:

- `consensus-core/src/lib.rs`
- `consensus-core/src/flags.rs`
- `consensus-core/src/error.rs`
- `consensus-core/src/sighash.rs`
- `consensus-core/src/witness.rs`
- `consensus-core/src/pq.rs`
- `consensus-core/src/interpreter.rs`
- `consensus-core/src/tx.rs`

Current ownership:

- `flags.rs`
  - validation flags
  - supported-flag checks
  - default flag bundles
  - future central height/activation mapping if the wrapper-level helper is
    lowered
- `error.rs`
  - `ScriptError`
  - `TidecoinValidationError`
- `sighash.rs`
  - consensus-critical sighash engine
- `witness.rs`
  - witness-program parsing/validation pieces needed by consensus
- `pq.rs`
  - verification-only PQ facade used by the interpreter
- `interpreter.rs`
  - stack machine
  - opcode execution
  - `CHECKSIG` / `CHECKMULTISIG`
  - `OP_SHA512`
  - script-input verification dispatch between base / P2SH / witness /
    witness-v1-512 paths
- `tx.rs`
  - typed transaction context
  - prevout context and precompute inputs used by the interpreter

The node-backed bridge does not belong in this module layout.

## Wrapper Surface After Extraction

Now that extraction has landed, the top-level
[`tidecoin/src/consensus_validation.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
should stay limited to:

1. deserialize transaction bytes
2. choose backend:
   - node bridge
   - shared core
3. map errors into the existing public wrapper enums
4. preserve the current ergonomic API surface

The byte API stays in `tidecoin`. The engine is already lowered.

## Dependency-Lowering Tasks

These are the boundary rules that keep the completed extraction clean. Treat
new violations as consensus-core work, not as side issues.

### 1. Keep `SighashCache` Lowered

`SighashCache` and the verification-facing sighash types now live in
[`consensus-core/src/sighash.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs).

Action:

- keep the lowered engine as the only consensus implementation
- add any future signing convenience surface as wrappers over `consensus-core`,
  not as a second top-level sighash implementation

Current state:

- a verification-facing sighash implementation exists in
  [`consensus-core/src/sighash.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs)
- the pure-Rust Tidecoin validator now uses the lowered `SighashCache`,
  `TxSighashType`, `LegacySighash`, `SegwitV0Sighash`, and `Sighash512`
- no live `tidecoin/src/crypto/sighash.rs` implementation remains

### 2. Keep witness-program consensus types lowered

`WitnessProgram` and related witness-version logic now live under
[`consensus-core/src/witness.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs).

Action:

- keep the consensus-critical witness-program representation in the shared core
- leave non-critical formatting helpers in `tidecoin`

### 3. Lower PQ verification dependencies

Done for verification: the shared core does not depend on the whole top-level
crypto module.

Action:

- keep verification-only PQ parsing and verification in
  [`consensus-core/src/pq.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)
- keep signing/keygen/key I/O in
  [`tidecoin/src/crypto/pq.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/crypto/pq.rs)
- avoid reintroducing a top-level verification implementation

The important distinction is:

- keygen / secret handling / PQHD stay high-level
- verification needed by consensus stays low

Dependency hygiene note:

- [`consensus-core/Cargo.toml`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/Cargo.toml)
  depends directly on `tide-fn-dsa-vrfy` with `default-features = false`
- [`tidecoin/Cargo.toml`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/Cargo.toml)
  depends directly on `tide-fn-dsa-kgen` and `tide-fn-dsa-sign` with
  `default-features = false`
- upstream `tide-fn-dsa-comm` still pulls default-featured `rand_core` and
  backend defaults internally; fixing that requires an upstream
  `tide-fn-dsa` feature-hygiene change

### 4. Height-to-flags logic belongs in the core

The library still lacks a central node-faithful height-to-flags mapping for
AuxPoW-era activation of:

- `PQ_STRICT`
- `WITNESS_V1_512`
- `SHA512`

Current status:

- [`consensus/src/lib.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
  exposes an auxpow-aware wrapper helper today.
- If this helper becomes a shared consensus rule rather than a standalone
  wrapper convenience, lower it into `consensus-core/src/flags.rs` instead of
  duplicating it in another caller.

## Migration Order

### Step 1: Create The Crate Skeleton

- [x] Add `consensus-core/` to the workspace.
- [x] Name the package `tidecoin-consensus-core`.
- [x] Add only lower-level dependencies.
- [x] Do not depend on the top-level `tidecoin` crate.

### Step 2: Move Flags And Errors First

- [x] Move validation flags out of
  [`tidecoin/src/consensus_validation_tidecoin.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs).
- [x] Move `ScriptError` and the shared validation error type for the pure-Rust validation path.
- [x] Re-export shared flags from the top-level `tidecoin` crate.
- [ ] Decide whether the node bridge keeps its own bridge-extended error type or is folded into a common public validation error.

This is the smallest safe first slice.

### Step 3: Move Sighash And Witness Support

- [x] Extract consensus-critical sighash code.
- [x] Extract witness-program parsing/recognition pieces.
- [~] Extract witness-program validation pieces beyond parsing/recognition.
  - shared-core now owns parsing, classification, commitment checks, stack
    preparation, executed-script selection, and sigop mode
  - remaining work is mainly the generic post-execution success path and any
    further interpreter extraction
- [x] Remove compatibility-shaped top-level sighash API baggage instead of
  preserving a second public implementation.

### Step 4: Move The Interpreter

- [x] Move evaluator state and opcode execution helpers.
- [x] Move `verify_script_input` behind a top-level adapter.
- [x] Move transaction-input verification helpers.
- [x] Add internal core tests before rewiring wrappers.

### Step 5: Rewire `tidecoin`

- [x] Make [`tidecoin/src/consensus_validation.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
  a wrapper over the shared core.
  - the pure-Rust fallback path is routed through `consensus-core` via
    [tidecoin/src/consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)
  - any remaining wrapper/error cleanup is normal facade narrowing, not an
    extraction blocker
- [x] Keep the node bridge optional and outside the shared core.
- [x] Delete compatibility-only public API shape where it conflicts with
  Tidecoin-native ownership; retain only current Tidecoin ergonomic wrappers.

### Step 6: Rebase `consensus/`

- [x] Replace direct interpreter logic with calls into `tidecoin-consensus-core`.
- [x] Keep the standalone byte-oriented surface as a Tidecoin-native API choice,
  not as a Bitcoin compatibility promise.
- [x] Remove live Bitcoin/Taproot/Core-diff assumptions after the core is wired
  in; archived historical proof material remains separated until explicitly
  deleted.

## Next Cleanup Slice

The extraction boundary now exists. The remaining work is narrower:

1. keep lowering reusable consensus/protocol logic into `primitives` or
   `consensus-core`
2. reconcile coverage matrices against the live Tidecoin-node parity tests
3. delete archived historical corpora when the project no longer wants the
   reference material

## Success Criteria

This work is successful when all of the following are true:

- the shared validation engine no longer lives only inside the top-level crate
- the top-level `tidecoin` crate is mostly wrappers/re-exports at the
  consensus-validation entry points
- the imported `consensus/` crate depends on `tidecoin-consensus-core`, not on
  upstream Bitcoin semantics
- the Tidecoin node remains the only external parity target
- height/flag activation logic is centralized instead of being caller-specific
