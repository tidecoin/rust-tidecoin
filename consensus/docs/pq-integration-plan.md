# PQ Integration Plan

The first runtime-conversion slices are already landed. Based on the current
byte-oriented wrapper in [src/lib.rs](src/lib.rs), the shared engine now in
[../consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
and [../consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs),
and the Tidecoin-native Rust implementation in
[consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs),
[consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs),
and [pq.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/crypto/pq.rs),
the cleanest path is still to stop extending the current Bitcoin-specific
interpreter and instead extract a shared Tidecoin consensus core that both
`rust-tidecoin` and this `consensus` crate can consume.

This document should be read together with [rust-tidecoin-migration-handoff.md](rust-tidecoin-migration-handoff.md). The shared-core decision is the current baseline. Directly rebasing `consensus/` onto the top-level `tidecoin` crate is not the target architecture.

Implementation order for the next phase:

1. finish the remaining runtime/API cleanup in [src/lib.rs](src/lib.rs) and related runtime modules so the crate no longer carries residual Bitcoin/Taproot/`bitcoinconsensus`
2. only then retire or rewrite the old Bitcoin differential tests and harnesses in `tests/` so they follow the new Tidecoin runtime model instead of preserving the old one
3. preserve the archived suite's proof depth by rebuilding its coverage classes
   against the Tidecoin node, not by accepting a smaller active test surface

Current status:

- the first runtime audit pass has been captured in
  [../../ai-docs/CONSENSUS_RUNTIME_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_RUNTIME_AUDIT.md)
- that audit is the active conversion map for:
  - `src/lib.rs`
  - `consensus-core/src/interpreter.rs`
  - `consensus-core/src/tx.rs`
- the active witness-v1 runtime path in the shared interpreter now follows
  Tidecoin witness-v1-512 program semantics instead of Taproot control-block semantics
- `src/lib.rs` no longer carries the large Taproot/Tapscript-heavy unit block;
  it now has Tidecoin witness-v1-512 tests instead
- the PQ verification facade is now lowered into
  [consensus-core/src/pq.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs),
  so `consensus/` no longer depends directly on the top-level `tidecoin` crate
  for PQ verification
- witness-program parsing and version/length/flag classification are now
  lowered into
  [consensus-core/src/witness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs),
  and are consumed by the shared engine instead of duplicated in `consensus`
- witness commitment checks, witness-stack preparation, executed-script
  selection, and sigop-accounting mode are now also lowered into
  [consensus-core/src/witness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs),
  so the shared interpreter executes a shared witness plan instead of hosting
  separate P2WPKH/P2WSH/witness-v1 wrappers
- the large interpreter-boundary refactor is now landed:
  - the shared engine lives in `consensus-core`
  - `consensus/src/lib.rs` is the byte-oriented wrapper
  - the old local engine files `src/script.rs` and `src/tx.rs` have been removed

Audit standard for that runtime work:

- primary source of truth: the Tidecoin core node checkout at `~/dev/tidecoin/tidecoin`
- secondary internal reference: the Tidecoin-native Rust implementation in [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin)
- not acceptable as final authority: upstream Bitcoin behavior or the `bitcoinconsensus` crate

## Checklist

1. Dependency and architecture reset
- [x] Do not solve the migration by making `consensus/` depend directly on the top-level `tidecoin` crate; use a shared Tidecoin consensus core instead.
- [ ] Confirm we use Tidecoin Rust PQ primitives from `rust-tidecoin` (`tide-fn-dsa`, ML-DSA via `fips204`, ML-KEM via `ml-kem`) through the `tidecoin` crate surface.
- [ ] Remove Bitcoin-only assumptions from crate metadata, README, docs, features, and comments.
- [ ] Decide whether this crate stays as a thin compatibility wrapper or re-exports more Tidecoin-native types directly.
- [ ] Make this crate the canonical Tidecoin consensus crate; do not plan on a separate Tidecoin analogue of the `bitcoinconsensus` crate.
- [ ] Treat the Tidecoin node as the only external consensus reference implementation for parity testing.
- [ ] Extract the Tidecoin validation core into a new shared crate instead of leaving it only inside `rust-tidecoin`.
- [ ] Define ownership so both this `consensus` crate and `rust-tidecoin` depend on that shared crate, rather than duplicating or copy-pasting validation logic.

## Dependency Audit: `bitcoin` crate today vs `tidecoin` crate target

Before implementation, we need an import-by-import audit of what the current crate gets from upstream `bitcoin` and what the Tidecoin crate should replace.

### What the current crate takes from upstream `bitcoin`

The current crate uses `bitcoin` for far more than wire types:

- Transaction model and encoding:
  - `Transaction`, `TxIn`, `TxOut`, `OutPoint`, `Amount`, `Witness`, `Sequence`, version and locktime types
- Script model:
  - `Script`, `ScriptBuf`, `Builder`, `Instruction`, `PushBytesBuf`
- Opcodes:
  - `opcodes::{all, Opcode}`
- Hashing:
  - `hash160`, `ripemd160`, `sha1`, `sha256`, `sha256d`
- Sighash support:
  - `SighashCache`, segwit-v0 sighash helpers, annex/prevout helpers
- secp256k1 and Bitcoin signature machinery:
  - ECDSA signatures, Schnorr signatures, public key types, verification contexts
- Taproot/Tapscript support:
  - Taproot key types, leaf/control-block types, Taproot sighash types, Taproot constants
- Test-only construction helpers:
  - extensive transaction/script builders and secp-based signing used across the current tests

This means the current `bitcoin` dependency is both:

- a primitives dependency
- a consensus implementation dependency

That second role is what must be removed.

### What the shared Tidecoin consensus core should take from lower crates

The future shared core should be built from lower-level Tidecoin crates, not from the top-level `tidecoin` crate.

It should consume:

- Tidecoin transaction and amount primitives
- Tidecoin script and opcode types
- Tidecoin consensus encoding/decoding
- Tidecoin sighash helpers
- Tidecoin PQ crypto surface and wrappers needed for validation

### What higher layers should get from the shared core

The shared core should become the source of:

- validation flags
- script/transaction verification APIs
- Tidecoin-specific script semantics for `PQ_STRICT`, `WITNESS_V1_512`, and `SHA512`

### What we likely stop taking entirely

- Upstream `bitcoin` Taproot/Tapscript types
- Upstream secp/Schnorr validation logic as a consensus dependency
- `bitcoinconsensus` as a parity/reference dependency
- Bitcoin-specific activation-height helpers and Bitcoin-only flag sets

### Audit checklist

- [ ] Build a file-by-file map of every `bitcoin::...` import in `src/`, `tests/`, and `benches/`.
- [ ] Classify each import as one of:
  - primitive/container
  - script model
  - sighash utility
  - secp/signature logic
  - Taproot-only logic
  - test helper only
- [ ] For each import, decide whether the replacement is:
  - lower-level Tidecoin crate replacement
  - shared-core replacement
  - delete entirely
- [ ] Separate runtime dependencies from test-only dependencies so test scaffolding does not drive production architecture.
- [ ] Produce a replacement matrix before code edits begin.

### Replacement matrix to produce before implementation

- [ ] `bitcoin` transaction types -> Tidecoin transaction types
- [ ] `bitcoin` script/opcode types -> Tidecoin script/opcode types
- [ ] `bitcoin` sighash helpers -> Tidecoin sighash helpers
- [ ] `bitcoin::secp256k1` / ECDSA / Schnorr -> Tidecoin PQ crypto types
- [ ] `bitcoin` Taproot types -> delete or replace with Tidecoin witness-v1-512 logic
- [ ] Bitcoin-oriented test builders -> Tidecoin PQ-aware test builders

## Shared Core Crate Decision

It looks increasingly likely that the Tidecoin validation logic should live in a separate reusable crate rather than only inside `rust-tidecoin`.

Rationale:

- this `consensus` crate will need the same Tidecoin script/sighash/PQ validation core
- `rust-tidecoin` already contains Tidecoin-specific validation logic that is broader than simple wrappers
- keeping the core only inside one crate will force one of:
  - duplication
  - internal-module reach-through
  - copy-based divergence over time

### Proposed direction

- [ ] Introduce a shared validation crate, tentatively something like `tidecoin-consensus-core`.
- [ ] Move Tidecoin-specific script validation logic there.
- [ ] Move Tidecoin-specific sighash and witness-v1-512 support there if it is consensus-critical.
- [ ] Move PQ verification integration there if it is part of consensus evaluation.
- [ ] Keep wallet, address, descriptor, network, RPC, and node-specific concerns out of that crate.
- [ ] Keep the node bridge, if still needed, outside the shared core crate.

### What should live in the shared crate

- [ ] Verification flags and flag parsing/validation
- [ ] Script error types
- [ ] Script interpreter / evaluator
- [ ] Legacy, witness-v0, and witness-v1-512 sighash logic needed by consensus validation
- [ ] PQ public key / signature verification glue needed by the interpreter
- [ ] Transaction input verification helpers

### What should not live in the shared crate

- [ ] Wallet policy logic
- [ ] Standardness / mempool policy unless truly required by consensus consumers
- [ ] Address encoding/decoding
- [ ] Descriptor generation
- [ ] P2P, RPC, or node runtime code
- [ ] Test harness code that is specific to one repo

### Consumer model

- [ ] `tidecoin-consensus-core` provides the reusable validation engine
- [ ] `rust-tidecoin` depends on it and re-exports or wraps the relevant public API
- [ ] this `consensus` crate depends on it and exposes the byte-oriented API expected by callers

### Decision gate before implementation

- [ ] Confirm whether we are extracting a shared crate first, or temporarily integrating against `rust-tidecoin` and extracting immediately after stabilization.
- [ ] If extraction is chosen, define the crate boundary before touching the current interpreter replacement.

2. Public API migration
- [x] Audit [src/lib.rs](src/lib.rs) and classify Bitcoin/Taproot/`bitcoinconsensus` assumptions as `delete`, `rewrite`, or `replace via shared core`.
- [ ] Keep the existing byte-oriented API in [src/lib.rs](src/lib.rs) so callers do not need a full rewrite.
- [x] Re-map verification flags to Tidecoin flags: keep `P2SH`, `NULLDUMMY`, `SIGPUSHONLY`, `MINIMALDATA`, `CLEANSTACK`, `CLTV`, `CSV`, `WITNESS`, `MINIMALIF`, `NULLFAIL`, `CONST_SCRIPTCODE`, and add `PQ_STRICT`, `WITNESS_V1_512`, `SHA512`.
- [x] Replace the active witness-v1 wrapper with Tidecoin witness-v1-512 program semantics.
- [~] Remove unsupported Bitcoin-only flags and paths: `DERSIG`, `LOW_S`, `WITNESS_PUBKEYTYPE`, Taproot/Tapscript, Schnorr, Taproot spent-output handling.
  - `DERSIG`, `LOW_S`, and the temporary ECDSA fallback are now removed from the live runtime
  - remaining work is the residual Bitcoin/Taproot metadata, docs, and archived-proof cleanup surface
- [ ] Revisit `verify`, `verify_with_flags`, `verify_with_details`, `verify_with_flags_detailed`, and decide whether `spent_outputs` remains accepted-but-ignored for compatibility.
- [x] Update `Error` and `ScriptError` enums to Tidecoin semantics and naming.

3. Validation backend replacement
- [x] Replace the custom interpreter with the shared Tidecoin consensus core.
- [x] Replace custom tx parsing/precompute code with shared-core or lower-level Tidecoin transaction parsing and sighash support.
  - the active engine now lives in
    [../consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
    and
    [../consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
  - `consensus/src/lib.rs` is now the byte-oriented wrapper over that engine
  - active tx parsing/storage is on `tidecoin-consensus-encoding` + `tidecoin-primitives`
  - active interpreter sighash use is on `consensus_core::SighashCache`
  - witness-program parsing/classification and witness execution planning are on
    `consensus_core::WitnessProgram`, `WitnessProgramClass`, and `WitnessExecutionPlan`
- [x] Route PQ public key and signature verification through the shared core's Tidecoin PQ validation glue.
  - verification-only PQ types and verify helpers now live in
    [consensus-core/src/pq.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)
  - the shared interpreter no longer depends directly on the top-level
    `tidecoin` crate for PQ verification
- [x] Base and `WITNESS_V0` execution in the shared interpreter now use Tidecoin PQ pubkeys and PQ verification.
- [ ] Reintroduce the removed ECDSA-era unit surfaces as Tidecoin-native PQ tests:
  - witness-v0 code-separator sighash behavior
  - witness-v0 raw hashtype behavior
  - explicit witness amount authority
  - legacy code-separator signature behavior
  - any meaningful replacement for the old multisig intermediate-mismatch edge case
- [ ] Ensure legacy Falcon-512 acceptance behavior is controlled by `PQ_STRICT` exactly like Tidecoin node behavior.
- [ ] Ensure witness-v1-512 and `OP_SHA512` are wired exactly as in the Tidecoin validator.

4. Activation and flag schedule
- [ ] Replace Bitcoin height-based activation logic with Tidecoin activation logic.
- [ ] Confirm whether this crate should expose a single generic `height_to_flags` or network-specific helpers.
- [ ] Encode AuxPoW-era activation for `PQ_STRICT`, `WITNESS_V1_512`, and `SHA512`.

5. Fixture and corpus replacement
- [ ] Remove Bitcoin-only vendored fixtures from `tests/data/`.
- [ ] Vendor Tidecoin fixtures from `~/dev/tidecoin/tidecoin/src/test/data/`: `script_tests_pq.json`, `tx_valid_pq.json`, `tx_invalid_pq.json`, `script_assets_test.json`, and reuse `sighash.json` where still applicable.
  - [x] first shared-harness consumers now exist for `script_tests_pq.json`, `tx_valid_pq.json`, and `tx_invalid_pq.json` in [tests/tidecoin_node_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs)
  - [x] first direct `script_assets_test.json` consumer now exists in [tests/tidecoin_script_assets.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets.rs), using the Tidecoin node corpus rather than the stale vendored Bitcoin-era file
  - [x] Tidecoin-native generated large-corpus/provenance replacement now exists in [tests/tidecoin_script_assets_generated.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets_generated.rs), with pinned metadata in [tests/data/tidecoin_script_assets_generated_metadata.json](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/data/tidecoin_script_assets_generated_metadata.json)
- [ ] Update fixture hash/integrity tests to pin Tidecoin upstream files, not Bitcoin Core files.
- [ ] Rewrite parser/token maps so flags like `PQ_STRICT`, `WITNESS_V1_512`, and `SHA512` are understood everywhere.

6. Test suite rewrite
- [~] Remove Bitcoin Core differential tests, `bitcoinconsensus`-based differential tests, and Taproot-specific tests.
  - done for the former live `core_*` test/bench surface, which is now archived
  - open for Tidecoin-native replacement coverage
- [ ] Preserve the archived suite's proof depth by rebuilding its coverage
  classes as Tidecoin-native/node-parity tests.
- [ ] Redesign the test surface around node parity instead of `bitcoinconsensus` crate parity.
- [ ] Keep or adapt generic tests that still apply: script parsing, CLTV/CSV, stack semantics, sigop accounting, sighash caching where relevant.
- [ ] Add PQ-focused tests for P2PK/P2PKH, P2SH, witness, witness-v1-512, `OP_SHA512`, and Falcon legacy-vs-strict behavior.
- [ ] Add tests for prefixed PQ public keys and ML-DSA/Falcon signature verification through the wrapper API.
- [x] Add multisig parity tests using Tidecoin PQ public keys.
- [ ] Ensure script-assets and tx-vector harnesses follow Tidecoin flag combinations and monotonicity rules.
- [x] Tidecoin-native script-assets generated corpus now derives from `tx_valid_pq.json` and `tx_invalid_pq.json`, and the generated artifact provenance is pinned through [scripts/generate_tidecoin_script_assets_generated_metadata.py](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py).
- [ ] Rewrite helper binaries, fixtures, and harness adapters so they compare against the Tidecoin node directly rather than against the `bitcoinconsensus` crate.

## Test Surface Migration

The current test suite is built around Bitcoin-oriented assumptions:

- Bitcoin JSON vectors and script assets in `tests/data/`
- Bitcoin Core helper binaries and runtime diff harnesses
- direct or indirect parity checks against the `bitcoinconsensus` crate
- Taproot/Tapscript/Schnorr/secp-specific unit coverage

That surface has to be reworked, not just renamed.

### Phase 0: Must-delete now

Execution note:

- these test deletions/rewrites should track the runtime/API migration
- do not remove a large Bitcoin differential test surface before the corresponding runtime replacement exists, unless the test is pure dead weight

- [ ] Remove `bitcoinconsensus`-driven parity assumptions from all tests and docs.
- [x] Archive the explicitly Bitcoin/Core-diff integration files that no longer
  match the live runtime under `tests/archived/`.
- [ ] Use
  [../../ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md)
  as the required archived-to-Tidecoin replacement map.
- [ ] Remove Taproot/Tapscript/Schnorr-specific tests and fixtures.
- [ ] Remove Bitcoin Core C++ helper/runtime diff infrastructure if it only exists to validate Bitcoin behavior.
- [ ] Remove Bitcoin-only fixture integrity checks and fixture hash expectations.
- [ ] Remove tests whose only purpose is parity against Bitcoin activation heights or Bitcoin flag sets.

Likely affected files:

- [x] [tests/archived/core_cpp_runtime_diff.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_cpp_runtime_diff.rs)
- [x] [tests/archived/core_diff_bridge.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_diff_bridge.rs)
- [x] [tests/archived/core_cpp_helper/core_consensus_helper.cpp](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_cpp_helper/core_consensus_helper.cpp)
- [x] [tests/archived/core_bip341_wallet_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_bip341_wallet_vectors.rs)
- [x] [tests/archived/core_witness_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_witness_unit_parity.rs) archived as historical Bitcoin-era coverage
- [x] [tests/archived/core_sighash_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_sighash_vectors.rs) archived as historical Bitcoin-era coverage
- [x] [tests/archived/core_tx_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_tx_vectors.rs)
- [x] [tests/archived/script_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/script_vectors.rs)
- [x] [tests/archived/core_fixture_hashes.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_fixture_hashes.rs) archived pending Tidecoin fixture-pinning replacement

Exit criteria:

- [ ] The repo no longer claims Bitcoin Core or `bitcoinconsensus` as the live parity target.
- [ ] No test depends on Taproot/Tapscript/Schnorr-specific fixtures or flags.
- [ ] The remaining suite is small enough to re-anchor on Tidecoin without mixed assumptions.

### Phase 1: Rewrite existing harnesses around Tidecoin

- [ ] Rewrite vector harnesses so they load Tidecoin fixture files and Tidecoin flag tokens.
  - [x] first Tidecoin script/tx fixture harness landed in [tests/tidecoin_node_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs)
- [ ] Rewrite all external-reference tests to compare against the Tidecoin node itself.
  - [x] first runtime diff/error suite now exists in [tests/tidecoin_runtime_diff.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_runtime_diff.rs), comparing pure-Rust `consensus` against the Tidecoin node for `script_tests_pq.json`, `tx_valid_pq.json`, and `tx_invalid_pq.json`
  - [x] exercised Tidecoin flag-token / flag-bit / flag-combo and error-class accounting now also exists in [tests/tidecoin_runtime_diff.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_runtime_diff.rs)
- [ ] Rewrite fixture integrity tests to pin Tidecoin upstream fixture files from `~/dev/tidecoin/tidecoin/src/test/data/`.
- [ ] Rewrite script-assets coverage tests around Tidecoin PQ coverage expectations.
- [~] Rewrite sighash tests around Tidecoin legacy, witness-v0, and witness-v1-512 rules.
  - [x] active Tidecoin-node `sighash.json` replay now exists in [tests/tidecoin_sighash_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_vectors.rs)
  - [x] active deep legacy/witness-v0 cache and randomized coverage now exists in [tests/tidecoin_sighash_cache_randomized.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_cache_randomized.rs)
  - remaining work is any witness-v1-512-specific precompute/sighash proof surface that is genuinely consensus-relevant
- [x] Rewrite multisig tests around PQ public keys and PQ signatures.
- [ ] Rewrite parser and script-ASM tests if opcode/flag/token vocab differs.

Likely rewrite targets:

- [ ] [tests/script_assets.rs](/home/yaroslav/dev/tidecoin/consensus/tests/script_assets.rs)
- [ ] [tests/script_vectors.rs](/home/yaroslav/dev/tidecoin/consensus/tests/script_vectors.rs)
- [ ] [tests/core_tx_vectors.rs](/home/yaroslav/dev/tidecoin/consensus/tests/core_tx_vectors.rs)
- [x] [tests/archived/core_sighash_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_sighash_vectors.rs)
- [x] [tests/archived/core_sighash_cache_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_sighash_cache_parity.rs)
- [x] [tests/archived/core_sighash_randomized.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_sighash_randomized.rs)
- [x] [tests/archived/core_multisig_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_multisig_unit_parity.rs)
- [x] [tests/archived/core_script_p2sh_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_script_p2sh_unit_parity.rs)
- [x] [tests/archived/core_scriptnum_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_scriptnum_unit_parity.rs)
- [ ] [tests/script_asm.rs](/home/yaroslav/dev/tidecoin/consensus/tests/script_asm.rs)
- [ ] [tests/script_parse_parity.rs](/home/yaroslav/dev/tidecoin/consensus/tests/script_parse_parity.rs)

Exit criteria:

- [ ] All rewritten harnesses load Tidecoin fixtures only.
- [ ] All external parity checks run against the Tidecoin node only.
- [ ] All flag token parsers understand Tidecoin-specific flags including `PQ_STRICT`, `WITNESS_V1_512`, and `SHA512`.
- [ ] The suite has a stable Tidecoin-oriented baseline before adding new coverage.

### Phase 1A: Keep or adapt low-risk local tests

- [ ] Keep generic script parser, stack, and numeric semantics tests where Tidecoin semantics still match.
- [ ] Keep generic CLTV/CSV tests, but re-anchor them to Tidecoin flag and activation expectations.
- [ ] Keep generic sigop accounting tests if the opcode counting rules remain valid.
- [ ] Keep randomized consistency tests if they exercise invariant behavior that is still consensus-relevant.

Likely keep/adapt candidates:

- [x] [tests/tidecoin_random_consistency.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_random_consistency.rs)
- [x] [tests/archived/core_scriptnum_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_scriptnum_unit_parity.rs)
- [x] [tests/archived/core_script_p2sh_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_script_p2sh_unit_parity.rs)
- [x] [tests/archived/core_sigop_surface.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/core_sigop_surface.rs)

Exit criteria:

- [ ] Surviving local tests are explicitly Tidecoin-valid, not just inherited from Bitcoin.
- [ ] There is a clear split between local invariant tests and node-parity tests.

### Phase 2: Add back Tidecoin-specific coverage

- [ ] Add Tidecoin-node parity tests for PQ P2PK and P2PKH spends.
- [ ] Add Tidecoin-node parity tests for PQ P2SH spends.
- [ ] Add Tidecoin-node parity tests for witness-v0 PQ spends.
- [ ] Add Tidecoin-node parity tests for witness-v1-512 spends.
- [ ] Add Tidecoin-node parity tests for `OP_SHA512`.
- [ ] Add Tidecoin-node parity tests for `PQ_STRICT` versus legacy Falcon-512 acceptance.
- [ ] Add Tidecoin-node parity tests for ML-DSA-44, ML-DSA-65, and ML-DSA-87 verification.
- [x] Add Tidecoin-node parity tests for PQ multisig.
- [ ] Add Tidecoin fixture hash tests for `script_tests_pq.json`, `tx_valid_pq.json`, `tx_invalid_pq.json`, and `script_assets_test.json`.

### Acceptance criteria for the migrated test surface

- [ ] No test refers to `bitcoinconsensus` as the reference implementation.
- [ ] No test depends on Taproot/Tapscript/Schnorr fixtures or flags.
- [ ] All external parity tests compare against the Tidecoin node only.
- [ ] All loaded vector files come from Tidecoin fixture sources.
- [ ] All flag token parsers understand Tidecoin-specific flags including `PQ_STRICT`, `WITNESS_V1_512`, and `SHA512`.
- [ ] The suite clearly separates pure local unit tests from Tidecoin-node differential tests.
- [ ] Tidecoin-specific PQ coverage is at least comparable in breadth to the removed Bitcoin-specific coverage, but centered on node behavior instead of crate-to-crate parity.

7. Docs and crate identity
- [ ] Rewrite [README.md](README.md) to describe Tidecoin consensus, not Bitcoin consensus.
- [x] Archive the old Core-era roadmap at [docs/archived/integration-roadmap.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/docs/archived/integration-roadmap.md) and keep active Tidecoin guidance in [docs/github-ci.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/docs/github-ci.md) plus this plan.
- [ ] Update examples, benchmark descriptions, and env-var names to point at Tidecoin repositories and fixtures.

8. Verification and acceptance
- [ ] `cargo test` passes on the rewritten suite.
- [ ] PQ fixture suites pass against Tidecoin JSON corpora.
- [ ] Flag behavior matches Tidecoin expectations for strict/non-strict Falcon-512, witness-v1-512, and `OP_SHA512`.
- [ ] No Taproot/Schnorr/Bitcoin-only assumptions remain in the public surface or tests.
- [ ] Final crate behavior is driven by `rust-tidecoin` validation and crypto, not the old custom Bitcoin interpreter.

## Recommended Execution Order

1. Replace dependencies and public flag/error surface.
2. Swap verification internals to `rust-tidecoin`.
3. Delete Bitcoin-only interpreter/tests.
4. Import Tidecoin fixtures and rewire harnesses.
5. Run/fix tests and tighten docs.

## Main Risk Areas

- The current crate API has Bitcoin-era fields and errors that do not map 1:1 onto Tidecoin.
- `spent_outputs` and Taproot-related code should be removed carefully to avoid accidental API breakage.
- The existing test suite is heavily Bitcoin-shaped, so fixture replacement is not just a file swap.
- The current tests assume a `bitcoinconsensus` reference crate exists; in Tidecoin that assumption is gone, so the whole parity surface has to be reworked around the node itself.

## Next Step

Continue the remaining architectural cleanup in this order:

1. lower more reusable validation logic into `tidecoin-consensus-core`
2. decide whether the byte-oriented `consensus` API should remain unchanged
3. decide whether archived Core-era proof materials remain in-repo or are deleted
