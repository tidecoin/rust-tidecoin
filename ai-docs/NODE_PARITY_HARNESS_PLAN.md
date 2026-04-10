# Tidecoin Node Parity Harness Plan

This note defines the shared Tidecoin node-backed parity layer that should sit
next to, but not inside, `tidecoin-consensus-core`.

It is intentionally a test/dev support layer, not part of the main production
consensus engine.

## Why This Exists

The repository already has a good Tidecoin-specific node bridge:

- build wiring now in [node-parity/build.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/build.rs)
- native bridge code now hosted in [node-parity/c_src/tidecoin_validation_bridge.cpp](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src/tidecoin_validation_bridge.cpp)
- Rust FFI wrappers and parity tests in [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)

The imported [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus)
crate already has a cleaner differential harness shape:

- backend abstraction in [consensus/tests/core_diff_bridge.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/core_diff_bridge.rs)
- systematic vector/random differential use in [consensus/tests/script_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/script_vectors.rs) and [consensus/tests/random_consistency.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/random_consistency.rs)

We want both:

- Tidecoin bridge semantics and Tidecoin node truth
- cleaner reusable harness structure

## Decision Summary

The node-backed parity layer should be extracted into a shared internal support
crate.

Suggested shape:

- directory: `node-parity/`
- package name: `tidecoin-node-parity`
- intended usage: `dev-dependency` or optional internal dependency

This is not a product/API crate. It is shared parity infrastructure for:

- tests in [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin)
- tests in [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus)
- future differential fuzzing

## Current State

The first extraction slice is already in place:

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

- broader `consensus/` test integration beyond the first script/transaction fixture-backed parity tests
- any additional capability/reporting APIs the shared harness may still need

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

Copy the structural patterns from:

- [consensus/tests/core_diff_bridge.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/core_diff_bridge.rs)

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

## Target Responsibilities

The parity support crate should own:

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

Suggested public test-support API:

- `TidecoinNodeHarness::from_env()`
- `backend_label()`
- `supported_flags_mask()`
- `verify_script_input(...)`
- `verify_script_case(...)`
- `check_transaction(...)`
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

## Proposed Module Layout

Current first-pass crate layout:

- `node-parity/Cargo.toml`
- `node-parity/build.rs`
- `node-parity/c_src/tidecoin_validation_bridge.cpp`
- `node-parity/c_src/randombytes_stub.c`
- `node-parity/src/lib.rs`
- `node-parity/src/error.rs`
- `node-parity/src/ffi.rs`
- `node-parity/src/harness.rs`
- `node-parity/src/fixtures.rs`
- `node-parity/src/pq.rs`
- `node-parity/src/script.rs`

Suggested ownership:

- `error.rs`
  - bridge error enum
  - node script error enum or mapping table
- `ffi.rs`
  - raw `extern "C"` declarations
- `harness.rs`
  - `TidecoinNodeHarness`
  - env/build/capability surface
- `fixtures.rs`
  - fixture root discovery
  - test-data loaders
- `pq.rs`
  - PQ/PQHD parity helper wrappers
- `script.rs`
  - script/input/tx verification wrappers
  - script ASM parsing helpers

## Migration Map

### Move Out Of `tidecoin/`

Move:

- build-side node compilation logic from
  [node-parity/build.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/build.rs)
- bridge sources from
  [tidecoin/c_src/](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/c_src)
  into
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

The next migration step is not bridge extraction anymore. It is replacing
`consensus/tests/core_diff_bridge.rs` and the Bitcoin-specific differential
surface with this shared Tidecoin harness.

After extraction, `tidecoin/src/consensus_validation_node.rs` should become a
thin adapter over the shared harness crate.

### Reuse In `consensus/`

Replace the current Bitcoin/Core diff backend in tests with the shared Tidecoin
node harness.

That means:

- stop growing [consensus/tests/core_diff_bridge.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/core_diff_bridge.rs)
  as a Bitcoin-specific long-term solution
- port the good harness shape into the new Tidecoin parity crate
- make `consensus/tests` depend on `tidecoin-node-parity` for node-backed
  comparisons

## Checklist

### Phase 1: Freeze The Contract

- [x] Confirm this layer is test/dev support, not production consensus core
- [x] Confirm crate name and directory
- [ ] Define the minimal public harness API
- [ ] Define what remains in top-level `tidecoin`

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
- [ ] Keep Tidecoin node-backed validation behavior unchanged
- [ ] Re-run existing Tidecoin node-parity tests

### Phase 5: Rewire `consensus/` Differential Surface

- [ ] Stop extending the Bitcoin-specific diff harness as the long-term path
- [ ] Introduce Tidecoin node-parity usage in `consensus/tests`
- [ ] Port applicable vector-based differential tests to the shared harness
- [ ] Port applicable randomized differential tests to the shared harness

### Phase 6: Tighten The Coverage Model

- [ ] Make Tidecoin node the only external parity target
- [x] Remove `libbitcoinconsensus` fallback from the long-term plan
- [ ] Remove Bitcoin/Taproot-specific helper assumptions from migrated tests
- [ ] Add Tidecoin-specific mismatch diagnostics and coverage counters

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
