# Tidecoin Node Parity Harness Plan

Status: archived completed harness reference.

This note defines the shared Tidecoin node-backed parity layer that sits
next to, but not inside, `tidecoin-consensus-core`.

It is intentionally a test/dev support layer, not part of the main production
consensus engine. This file is preserved as historical architecture context,
not as an active implementation checklist.

## Why This Exists

The repository already has a good Tidecoin-specific node bridge:

- build wiring now in [node-parity/build.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/build.rs)
- native bridge code now hosted in [node-parity/c_src/tidecoin_validation_bridge.cpp](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src/tidecoin_validation_bridge.cpp)
- Rust FFI wrappers and parity tests in [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)

The imported [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus)
crate originally had a cleaner differential harness shape in its Core-era
tests:

- archived backend abstraction in [consensus/tests/archived/core_diff_bridge.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_diff_bridge.rs)
- archived vector/random differential use in [consensus/tests/archived/script_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/script_vectors.rs) and [consensus/tests/archived/random_consistency.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/random_consistency.rs)

We want both:

- Tidecoin bridge semantics and Tidecoin node truth
- cleaner reusable harness structure

## Decision Summary

The node-backed parity layer is extracted into a shared internal support crate.

Current shape:

- directory: `node-parity/`
- package name: `tidecoin-node-parity`
- intended usage: `dev-dependency` or optional internal dependency

This is not a product/API crate. It is shared parity infrastructure for:

- tests in [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin)
- tests in [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus)
- future differential fuzzing

## Current State

The extraction is in place:

- [`node-parity/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity) exists in the workspace
- shared `ScriptError` mapping lives in
  [node-parity/src/error.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/error.rs)
- raw bridge FFI declarations live in
  [node-parity/src/ffi.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/ffi.rs)
- shared Tidecoin node fixture discovery lives in
  [node-parity/src/fixtures.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/fixtures.rs)
- native bridge compilation now lives in
  [node-parity/build.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/build.rs)
- native bridge sources live in
  [node-parity/c_src/](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src)
- a first reusable byte-oriented harness lives in
  [node-parity/src/harness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/harness.rs)
- [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)
  is now an adapter over the shared harness for:
  - transaction-input verification
  - transaction sanity
  - script-ASM parsing
  - isolated script-case verification
  - PQ/PQHD parity helper calls used by the node-backed tests
- [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus)
  now has a first shared-harness Tidecoin parity test in
  [consensus/tests/tidecoin_node_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs)
  covering:
  - `script_tests_pq.json`
  - `tx_valid_pq.json`
  - `tx_invalid_pq.json`

Still missing:

- explicit matrix mapping from each retired historical coverage class to the
  Tidecoin-native parity or local-invariant test that replaces it
- any additional capability/reporting APIs the shared harness still needs after
  that matrix reconciliation

## Hard Rules

### Must Not Depend On `tidecoin-consensus-core`

The pure Rust validation engine must stay usable without:

- a node checkout
- C/C++ compilation
- FFI
- environment variables

So:

- `tidecoin-consensus-core` must stay pure Rust
- `tidecoin-node-parity` may depend on `tidecoin-consensus-core` consumers, but
  not the other way around

### Must Not Be The Public Runtime API

The parity layer should not become part of the normal end-user Tidecoin API.

It exists to:

- compare Rust behavior against the Tidecoin node
- run fixture-backed parity tests
- run differential fuzzing
- optionally provide node-backed verification in gated development flows

## Current Source Material

### Reuse From The Existing Tidecoin Bridge

Keep the semantics and native bridge surface from:

- [node-parity/build.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/build.rs)
- [node-parity/c_src/tidecoin_validation_bridge.cpp](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src/tidecoin_validation_bridge.cpp)
- [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)

These are the important Tidecoin-specific capabilities:

- direct script/input verification against the node
- PQ deterministic keygen parity
- PQHD deterministic derivation parity
- PQ public-key derivation parity
- PQ sign/verify parity
- script-ASM parsing backed by the node
- transaction sanity checks backed by the node

### Reuse From The Existing `consensus/` Harness

The useful structural patterns have been ported from:

- [consensus/tests/archived/core_diff_bridge.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_diff_bridge.rs)

The useful design ideas are:

- one harness type instead of free-floating helpers
- centralized environment discovery
- cached build/discovery logic
- clean backend labeling and capability reporting
- shared helper methods used by both vector and randomized tests

Do not copy:

- `libbitcoinconsensus` fallback
- Bitcoin Core subprocess helper as the primary Tidecoin path
- Bitcoin/Taproot-specific flag assumptions

## Current Responsibilities

The parity support crate owns:

### 1. Native Build Support

- env discovery for `TIDECOIN_NODE_REPO`
- bridge/native build logic in
  [node-parity/build.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/build.rs)
- source list for compiled Tidecoin node files
- rerun/build metadata

### 2. Native Bridge Sources

- [tidecoin_validation_bridge.cpp](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src/tidecoin_validation_bridge.cpp)
- any bridge-local helper C/C++ code
- the randombytes stub or equivalent local support file

### 3. FFI Layer

- raw `extern "C"` declarations
- safe Rust wrappers over raw calls
- script error code mapping
- bridge failure reporting

### 4. Harness API

Current public test-support API:

- `TidecoinNodeHarness::from_env()`
- `backend_label()`
- `node_repo()`
- `check_transaction_hex(...)`
- `pq_p2wpkh_input_vsize(...)`
- `pq_p2sh_p2wpkh_input_vsize(...)`
- `verify_tx_input_hex(...)`
- `verify_script_case(...)`
- `parse_script_asm(...)`
- `pq_keypair_from_seed(...)`
- `pq_keypair_from_stream_key(...)`
- `pq_public_key_from_secret(...)`
- `pq_sign_message(...)`
- `pq_verify_message(...)`

### 5. Fixture Support

- node fixture root discovery from `TIDECOIN_NODE_REPO`
- shared helpers for `src/test/data`
- shared JSON loading/parsing for Tidecoin node corpora

### 6. Differential Fuzz Support

- stable harness entrypoints suitable for proptest/fuzz-style use
- capability reporting for tests to skip unsupported combinations explicitly
- standardized mismatch reporting

## Current Module Layout

Current crate layout:

- `node-parity/Cargo.toml`
- `node-parity/build.rs`
- `node-parity/c_src/tidecoin_validation_bridge.cpp`
- `node-parity/c_src/randombytes_stub.c`
- `node-parity/src/lib.rs`
- `node-parity/src/error.rs`
- `node-parity/src/ffi.rs`
- `node-parity/src/harness.rs`
- `node-parity/src/fixtures.rs`

Current ownership:

- `error.rs`
  - bridge error enum
  - node script error enum or mapping table
- `ffi.rs`
  - raw `extern "C"` declarations
- `harness.rs`
  - `TidecoinNodeHarness`
  - env/build/capability surface
  - script/input/tx verification wrappers
  - PQ/PQHD parity helper wrappers
- `fixtures.rs`
  - fixture root discovery
  - test-data loaders

Resolved note:

- the earlier orphaned `src/build_support.rs` helper has been deleted
- `node-parity/build.rs` is the only live build integration surface now

## Migration Map

### Moved Out Of `tidecoin/`

Moved:

- build-side node compilation logic from
  [node-parity/build.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/build.rs)
- bridge sources from the old `tidecoin/c_src/` location into
  [node-parity/c_src/](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src)
- remaining FFI wrapper code from
  [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs#L209)
- script error mapping from
  [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs#L33)
- fixture/path helpers and node-backed PQ helpers from the test section of
  [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs#L460)

### Keep In `tidecoin/`

Keep:

- top-level routing logic deciding when to use node-backed validation
- public Tidecoin-facing convenience APIs
- any product-facing feature flags that gate optional node-backed validation

## Current Validation

The shared harness path is now validated by both primary consumers:

- [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)
  runs its node-backed parity tests through `TidecoinNodeHarness`
- [consensus/tests/tidecoin_node_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs)
  uses the same harness against Tidecoin node `script_tests_pq.json`

The next migration step is not bridge extraction anymore. The active tests have
moved to the shared Tidecoin harness; the remaining work is matrix
reconciliation for archived Core-era proof classes and any extra diagnostics
that reconciliation proves useful.

`tidecoin/src/consensus_validation_node.rs` is now an adapter over the shared
harness crate.

### Reuse In `consensus/`

Keep the active `consensus/` tests on the shared Tidecoin node harness.

That means:

- keep [consensus/tests/archived/core_diff_bridge.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_diff_bridge.rs)
  archived as historical reference only
- keep the ported harness shape in the Tidecoin parity crate
- keep `consensus/tests` depending on `tidecoin-node-parity` for node-backed
  comparisons

## Checklist

### Phase 1: Freeze The Contract

- [x] Confirm this layer is test/dev support, not production consensus core
- [x] Confirm crate name and directory
- [x] Define the minimal public harness API
- [x] Define what remains in top-level `tidecoin`

### Phase 2: Extract The Bridge Substrate

- [x] Create the new crate skeleton
- [x] Move native bridge sources into it
- [x] Move build.rs node compilation logic into it
- [x] Move raw FFI declarations into it
- [x] Move script error mapping into it
- [x] Move fixture/path helpers into it

### Phase 3: Build The Reusable Harness

- [x] Introduce `TidecoinNodeHarness`
- [x] Add env discovery / backend labeling
- [x] Add fixture root helpers
- [x] Add the first safe wrappers for script verification
- [x] Add the first safe wrappers for PQ/PQHD parity helpers

### Phase 4: Rewire Existing Tidecoin Tests

- [x] Replace the first direct node-FFI test helpers in
  [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)
  tests with the shared harness
- [x] Finish migrating the remaining Tidecoin-side node helper calls
- [x] Keep Tidecoin node-backed validation behavior unchanged
- [x] Re-run existing Tidecoin node-parity tests

### Phase 5: Rewire `consensus/` Differential Surface

- [x] Stop extending the Bitcoin-specific diff harness as the long-term path
- [x] Introduce Tidecoin node-parity usage in `consensus/tests`
- [x] Port applicable vector-based differential tests to the shared harness
- [x] Port applicable randomized or generated corpus-style differential tests to
  Tidecoin-native parity/local-invariant coverage
- [ ] Reconcile the coverage matrix against each retired historical coverage
  class so future audits can see the replacement test explicitly

### Phase 6: Tighten The Coverage Model

- [x] Make Tidecoin node the only external parity target
- [x] Remove `libbitcoinconsensus` fallback from the long-term plan
- [x] Remove Bitcoin/Taproot-specific helper assumptions from migrated tests
- [ ] Add any remaining Tidecoin-specific mismatch diagnostics and coverage
  counters that the matrix reconciliation proves useful

## Success Criteria

This work is complete when:

- the Tidecoin node bridge code exists in one place only
- both [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) and
  [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) consume
  the same parity harness
- `tidecoin-consensus-core` remains pure Rust and bridge-free
- Tidecoin node-backed vector tests and differential/random tests no longer
  depend on duplicated bridge logic
- the Tidecoin node is the single external behavioral reference across the repo
