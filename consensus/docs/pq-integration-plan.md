# Tidecoin Consensus Architecture Plan

Status: active consensus-crate architecture reference beneath
[ai-docs/README.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/README.md).

This document tracks the active Tidecoin consensus architecture and the remaining
Tidecoin-native proof work. Historical upstream-era migration notes belong in
archived docs and tests; they are not the live implementation target.

## Current Ownership

- [`consensus-core/src/interpreter.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  owns the shared script interpreter.
- [`consensus-core/src/tx.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
  owns the shared transaction view consumed by the interpreter.
- [`consensus-core/src/sighash.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs)
  owns Tidecoin consensus sighash computation.
- [`consensus-core/src/witness.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs)
  owns witness-program classification, witness-stack preparation, executed-script
  selection, witness commitment checks, and sigop-accounting mode.
- [`consensus-core/src/pq.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)
  owns the verification-only PQ facade needed by consensus evaluation.
- [`consensus/src/lib.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
  is the standalone byte-oriented crate wrapper over the shared core.
- [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin)
  is the high-level crate facade and should not duplicate consensus-critical
  validation logic owned by `consensus-core` or protocol data owned by
  `primitives`.
- [`node-parity/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity)
  owns the optional Tidecoin-node bridge used by parity tests and by the
  `tidecoin-node-validation` feature.

The shared-core extraction is complete. Do not re-open the old decision about
whether to introduce `tidecoin-consensus-core`; the remaining work is to tighten
the surfaces that still look like historical compatibility or incomplete
Tidecoin proof coverage.

## Parity Standard

- The only external consensus authority is the Tidecoin core node checkout at
  `~/dev/tidecoin/tidecoin`.
- Active tests must prove Tidecoin semantics against the node or against shared
  lower-level Tidecoin primitives.
- Archived upstream-era material is reference-only and must not drive live
  runtime behavior.
- The `consensus` crate remains byte-oriented for standalone verification, but
  this is now a Tidecoin-native API choice, not a compatibility constraint.

## Current Runtime State

- [x] `consensus/` does not depend on the top-level `tidecoin` crate for runtime
  validation.
- [x] `consensus-core` owns the interpreter, flags, error types, sighash,
  witness classification, and PQ verification facade.
- [x] `consensus/src/lib.rs` delegates runtime verification to
  `consensus-core`.
- [x] Active transaction parsing/storage is on `tidecoin-consensus-encoding`
  plus `tidecoin-primitives`.
- [x] Base and witness-v0 script execution use Tidecoin PQ public keys and PQ
  verification.
- [x] Tidecoin witness-v1-512 and `OP_SHA512` are represented in the shared
  core.
- [x] `spent_outputs` is active prevout context for witness classification,
  scriptPubKey cross-checking, and witness-v1 precomputation. It is not
  accepted-and-ignored compatibility baggage.

## Remaining Architecture Work

- [ ] Finish metadata/provenance cleanup only where inherited upstream-era
  wording still appears in live public crate docs or package metadata.
- [ ] Audit new wrapper code for real duplicate validation/protocol logic before
  lowering anything else; do not create speculative `consensus-core` APIs.
- [ ] Keep `consensus/` as a byte-oriented standalone adapter over
  `tidecoin-consensus-core`; it must not regain its own transaction, script,
  witness, PQ, or sighash model.
- [x] Remove the old compatibility-shaped public APIs from the active Rust
  surface; any remaining naming cleanup is tracked as metadata/provenance
  cleanup rather than API compatibility work.
- [x] Keep wallet, address, descriptor, p2p, RPC, policy, and node-runtime code
  out of `consensus-core` unless a rule is genuinely required by consensus
  validation.
- [x] Keep the node bridge outside `consensus-core`; it is a test and optional
  parity surface, not production consensus logic.
- [ ] Track the upstream `tide-fn-dsa` feature-hygiene limitation separately:
  this repo now depends on direct verification/signing/keygen FN-DSA subcrates
  with `default-features = false`, but upstream `tide-fn-dsa-comm` still
  enables default-featured backend dependencies internally.

## Active Test Surface

Current Tidecoin-node parity coverage includes:

- [x] `script_tests_pq.json`, `tx_valid_pq.json`, and `tx_invalid_pq.json`
  shared-harness coverage in
  [`tests/tidecoin_node_parity.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs).
- [x] Runtime diff/error coverage against the Tidecoin node in
  [`tests/tidecoin_runtime_diff.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_runtime_diff.rs).
- [x] Direct `script_assets_test.json` coverage in
  [`tests/tidecoin_script_assets.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets.rs).
- [x] Generated large-corpus/provenance replacement in
  [`tests/tidecoin_script_assets_generated.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets_generated.rs)
  with pinned metadata in
  [`tests/data/tidecoin_script_assets_generated_metadata.json`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/data/tidecoin_script_assets_generated_metadata.json).
- [x] Fixture hash checks for `script_tests_pq.json`, `tx_valid_pq.json`,
  `tx_invalid_pq.json`, and `script_assets_test.json` in
  [`tests/tidecoin_fixture_hashes.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_fixture_hashes.rs).
- [x] PQ multisig node parity in
  [`tests/tidecoin_pq_multisig_parity.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_pq_multisig_parity.rs)
  and the node-validation test module in
  [`tidecoin/src/consensus_validation_node.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs).
- [x] Tidecoin `sighash.json` legacy replay in
  [`tests/tidecoin_sighash_vectors.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_vectors.rs).
- [x] Deep legacy/witness-v0 sighash cache and randomized coverage in
  [`tests/tidecoin_sighash_cache_randomized.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_cache_randomized.rs).
- [x] Local Tidecoin-valid script number, P2SH, witness, and sigop surfaces in
  `tests/tidecoin_*_parity.rs` and `tests/tidecoin_sigop_surface.rs`.

## Remaining Coverage Work

- [ ] Add or identify explicit node-parity coverage for every surviving
  archived historical coverage class listed in
  [`../../ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md`](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md).
- [ ] Add more direct, named parity cases for PQ P2PK, PQ P2SH, and witness-v0
  PQ spends. P2PKH, multisig, and mixed-scheme paths already have coverage, but
  the coverage matrix should make the mapping explicit.
- [ ] Add any witness-v1-512-specific precompute/sighash cases that are
  genuinely consensus-relevant and not already covered through runtime diff or
  node-validation tests.
- [ ] Keep testing `PQ_STRICT` versus legacy Falcon-512 acceptance against the
  Tidecoin node; the current multisig and node-validation tests cover key
  paths, but the coverage matrix should record the exact replacement for each
  retired historical test.
- [ ] Ensure all surviving local invariant tests are explicitly Tidecoin-valid,
  not merely inherited.
- [ ] Delete archived historical tests when the project decides the archive is
  no longer useful. Until then, archived material must remain clearly separated
  from live parity targets.

## Acceptance Criteria

- [x] No live runtime code depends on a non-Tidecoin consensus model.
- [x] No live test treats a non-Tidecoin implementation as the parity target.
- [x] All external parity tests compare against the Tidecoin node only.
- [x] Loaded active vector files come from Tidecoin fixture sources; archived
  upstream-era vectors remain isolated as historical reference material.
- [x] All flag token parsers understand Tidecoin-specific flags including
  `PQ_STRICT`, `WITNESS_V1_512`, and `SHA512`.
- [x] The suite clearly separates pure local invariant tests from Tidecoin-node
  differential tests.
- [ ] Tidecoin-specific PQ coverage is comparable in breadth to the removed
  historical coverage, but centered on node behavior instead of crate-to-crate
  parity. The current suite has node-backed fixture, runtime-diff, generated
  corpus, sighash, multisig, and local invariant coverage; the remaining work is
  explicit coverage-matrix reconciliation by retired historical class.

## Next Steps

1. Reconcile the coverage matrix against the active tests listed above.
2. Continue local architecture cleanup where correctness is already proven but
   ownership or maintainability is still weaker than the current crate layout.
