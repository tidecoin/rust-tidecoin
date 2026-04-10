# Consensus Test Coverage Matrix

This file defines how the archived Bitcoin/Core-diff `consensus/` test suite
maps onto the Tidecoin-native replacement surface.

The archived set now also includes the final active Bitcoin-era residue that was
removed from the live crate surface:

- `core_fixture_hashes.rs`
- `core_script_p2sh_unit_parity.rs`
- `core_script_segwit_detection_parity.rs`
- `core_scriptnum_unit_parity.rs`
- `core_sighash_cache_parity.rs`
- `core_sighash_randomized.rs`
- `core_sighash_vectors.rs`
- `core_sigop_surface.rs`
- `core_witness_unit_parity.rs`
- `verification_bench.rs`

It exists to preserve the original intent of the imported consensus test suite:

- prove parity against an external consensus reference
- cover both corpus-level behavior and targeted edge cases
- keep enough breadth that runtime rewrites do not silently narrow coverage

For the Tidecoin migration, the required replacement standard is:

- same proof depth class as the archived suite
- Tidecoin node at `~/dev/tidecoin/tidecoin` as the only external reference
- Tidecoin semantics and flags only
- no restoration of Bitcoin/Taproot/`bitcoinconsensus` assumptions

## Status Legend

- `done`: active Tidecoin-native replacement exists
- `planned`: replacement shape is clear but not implemented yet
- `partial`: some Tidecoin-native coverage exists, but not yet at archived depth
- `delete`: no Tidecoin analogue should be preserved directly

## Coverage Classes We Must Preserve

The archived suite covered several distinct proof classes:

1. Corpus parity
- script-vector parity
- tx-valid / tx-invalid parity

2. Runtime differential behavior
- accept/reject parity
- script-error parity
- flag-projection parity

3. Targeted unit parity
- multisig edges
- sighash edges
- parser / token / fixture semantics

4. Randomized differential coverage
- generated cases compared against the reference implementation

5. Fixture integrity
- exact fixture provenance and reproducibility

Tidecoin must regain all five classes, except where a class is truly Bitcoin-only
and has no Tidecoin analogue.

## Archived File Matrix

### `core_diff_bridge.rs`

Old role:
- backend abstraction over Bitcoin Core helper / `bitcoinconsensus`
- capability reporting
- spent-output API gating
- differential helper plumbing

Tidecoin replacement:
- use shared [node-parity/src/harness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/harness.rs)
- extend it where needed instead of restoring a Bitcoin-specific bridge

Status:
- `done`

Needed to reach parity:
- expose capability reporting needed by all surviving `consensus/tests/*`
- centralize Tidecoin flag support / fixture helpers / node metadata
- make it the only external-parity harness used by `consensus/`

### `script_vectors.rs`

Old role:
- script corpus parity runner
- flag token parsing
- expected script-error mapping
- optional differential run against Core backends

Tidecoin replacement:
- new Tidecoin script corpus parity runner
- primary corpus: `script_tests_pq.json`
- future additional corpora: Tidecoin-specific script assets and any non-JSON
  executable script corpus imported from the node

Status:
- `partial`

What already exists:
- [consensus/tests/tidecoin_node_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs)
  covers `script_tests_pq.json`

What is still needed:
- full Tidecoin flag-token parser:
  - `PQ_STRICT`
  - `WITNESS_V1_512`
  - `SHA512`
- expected-error mapping using Tidecoin node `script_error.h`
- corpus-level stats/reporting comparable to the archived runner
- any remaining useful parser/fixture helper logic split out of the archived file

### `core_tx_vectors.rs`

Old role:
- tx-valid / tx-invalid corpus parity
- flag projection
- spent-output handling
- backend diff execution

Tidecoin replacement:
- Tidecoin tx corpus parity runner using:
  - `tx_valid_pq.json`
  - `tx_invalid_pq.json`
- shared `TidecoinNodeHarness`

Status:
- `partial`

What already exists:
- [consensus/tests/tidecoin_node_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs)
  covers `tx_valid_pq.json` and `tx_invalid_pq.json`

What is still needed:
- richer per-case diagnostics
- explicit flag-coverage accounting
- any meaningful spent-output shape validation needed for future corpora

### `core_cpp_runtime_diff.rs`

Old role:
- broad differential runtime/error surface
- script-error mapping
- exercised-flag accounting
- helper-process runtime comparisons

Tidecoin replacement:
- a Tidecoin runtime diff suite over `TidecoinNodeHarness`
- compare:
  - accept/reject
  - script error category
  - relevant flag behavior

Status:
- `partial`

Why it matters:
- this is the archived file closest to “proof harness”
- without a Tidecoin-native analogue, we do not yet have archived-level
  runtime differential depth

What already exists:
- [consensus/tests/tidecoin_runtime_diff.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_runtime_diff.rs)
  compares pure-Rust `consensus` behavior against Tidecoin node for:
  - `script_tests_pq.json`
  - `tx_valid_pq.json`
  - `tx_invalid_pq.json`
  - accept/reject parity
  - script-error parity
  - exercised Tidecoin flag-token accounting
  - normalized flag-bit accounting
  - flag-combination accounting
  - Rust/node error-class distribution reporting

### `script_assets.rs`

Old role:
- Bitcoin fixture/token/error vocabulary
- script asset parsing and normalization helpers
- flag monotonicity and parser support

Tidecoin replacement:
- Tidecoin-specific fixture/token/error vocabulary support
- target node corpus: `script_assets_test.json`

Status:
- `done`

Needed:
- import and pin Tidecoin `script_assets_test.json`
- preserve any generic fixture utility logic that still applies

What already exists:
- [consensus/tests/tidecoin_test_support.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_test_support.rs)
  now centralizes Tidecoin flag parsing, fixture loading, prevout parsing, and
  Rust/node error mapping used by the active parity tests
- [consensus/tests/tidecoin_script_assets.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets.rs)
  replays the Tidecoin node `script_assets_test.json` corpus directly and
  checks subset/superset monotonicity against both:
  - the pure-Rust `consensus` engine
  - the Tidecoin node via `TidecoinNodeHarness`
- [consensus/tests/tidecoin_script_assets_generated.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets_generated.rs)
  derives a larger Tidecoin-native script-assets corpus from
  `tx_valid_pq.json` and `tx_invalid_pq.json`, replays the same
  subset/superset monotonicity proof, and pins its provenance with
  [consensus/tests/data/tidecoin_script_assets_generated_metadata.json](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/data/tidecoin_script_assets_generated_metadata.json)
  generated by
  [consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py)

Migration note:
- the old vendored corpus is now archived at
  [consensus/tests/archived/data/script_assets_test.json](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/data/script_assets_test.json)
  and is not the active Tidecoin source of truth

### `core_scriptnum_unit_parity.rs`

Old role:
- targeted `ScriptNum` creation/operator parity coverage
- boundary behavior for default 4-byte script-number decoding

Tidecoin replacement:
- Tidecoin-native `ScriptNum` creation/operator matrix using the migrated
  `consensus` runtime
- compare against the Tidecoin node when `TIDECOIN_NODE_REPO` is available

Status:
- `done`

What already exists:
- [consensus/tests/tidecoin_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_unit_parity.rs)
  covers the default-max-size creation and operator matrices against:
  - the pure-Rust `consensus` interpreter
  - the Tidecoin node harness when available

### `core_script_p2sh_unit_parity.rs`

Old role:
- targeted P2SH detection and recursion-rule parity

Tidecoin replacement:
- Tidecoin-native P2SH detection matrix
- Tidecoin-native recursion/switchover parity cases
- compare runtime cases against the Tidecoin node when available

Status:
- `done`

What already exists:
- [consensus/tests/tidecoin_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_unit_parity.rs)
  covers:
  - P2SH detection matrix
  - no-recurse behavior
  - old-vs-new-rule switchover behavior

### `core_sigop_surface.rs`

Old role:
- targeted witness/P2SH sigop-count surface parity
- especially witness-v0 activation toggles at the public verification surface

Tidecoin replacement:
- Tidecoin-native sigop-surface parity suite for:
  - native P2WPKH witness toggles
  - native P2WSH witness toggles
  - P2SH-P2WSH witness toggles
- compare against the Tidecoin node when `TIDECOIN_NODE_REPO` is available

Status:
- `done`

What already exists:
- [consensus/tests/tidecoin_sigop_surface.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sigop_surface.rs)
  covers the witness/sigop surface toggles against:
  - the pure-Rust `consensus` interpreter
  - the Tidecoin node harness when available

### `core_fixture_hashes.rs`

Old role:
- pin the exact fixture corpus version used by the active consensus proof suite
- detect silent fixture drift

Tidecoin replacement:
- pin the active Tidecoin node corpora used by the live `consensus` parity
  suite:
  - `script_tests_pq.json`
  - `tx_valid_pq.json`
  - `tx_invalid_pq.json`
  - `script_assets_test.json`
  - `sighash.json`

Status:
- `done`

What already exists:
- [consensus/tests/tidecoin_fixture_hashes.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_fixture_hashes.rs)
  hashes the active Tidecoin node fixtures directly and checks them against
  pinned SHA-256 values whenever `TIDECOIN_NODE_REPO` is set

### `core_sighash_vectors.rs`

Old role:
- corpus-based legacy sighash vector parity using `sighash.json`

Tidecoin replacement:
- Tidecoin-native `sighash.json` runner on lower Tidecoin transaction/script
  types and the lowered `consensus_core::SighashCache`

Status:
- `done`

What already exists:
- [consensus/tests/tidecoin_sighash_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_vectors.rs)
  replays the active Tidecoin node `sighash.json` corpus against the lowered
  Tidecoin `SighashCache`

### `core_sighash_cache_parity.rs`

Old role:
- deterministic legacy sighash cache-prefix parity against the old model

Tidecoin replacement:
- keep the vector-based legacy sighash gate
- add Tidecoin-native cache/no-cache parity on lowered Tidecoin types

Status:
- `done`

What already exists:
- [consensus/tests/tidecoin_sighash_cache_randomized.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_cache_randomized.rs)
  covers:
  - randomized legacy sighash equivalence against an independent old-model serializer
  - deterministic BASE cache-vs-no-cache parity
  - deterministic witness-v0 cache-vs-no-cache parity

### `core_sighash_randomized.rs`

Old role:
- randomized legacy sighash equivalence against the old non-cached model

Tidecoin replacement:
- randomized legacy sighash equivalence on lowered Tidecoin types

Status:
- `done`

What already exists:
- [consensus/tests/tidecoin_sighash_cache_randomized.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_cache_randomized.rs)
  includes a large randomized legacy sighash-equivalence pass

### `core_witness_unit_parity.rs`

Old role:
- targeted witness-v0/P2SH witness edge-case parity

Tidecoin replacement:
- Tidecoin-native witness unit parity suite for:
  - wrapped-witness detection surface
  - wrong-length / empty / mismatch cases
  - witness malleation / unexpected-witness cases
- compare runtime cases against the Tidecoin node when available

Status:
- `done`

What already exists:
- [consensus/tests/tidecoin_witness_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_witness_unit_parity.rs)
  covers the active witness-unit edge cases against:
  - the pure-Rust `consensus` interpreter
  - the Tidecoin node harness when available

### `random_consistency.rs`

Old role:
- randomized differential testing against Core/libbitcoinconsensus backends

Tidecoin replacement:
- Tidecoin-native randomized differential suite
- compare pure Rust `consensus` behavior against Tidecoin node via
  `TidecoinNodeHarness`

Status:
- `done`

Constraint:
- this must generate only Tidecoin-meaningful flag/opcode/script combinations
- no Taproot/Schnorr/Bitcoin-only flag generation

What already exists:
- [consensus/tests/tidecoin_random_consistency.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_random_consistency.rs)
  covers deterministic random:
  - legacy arithmetic/control-flow/minimaldata cases
  - P2SH cases
  - witness-v0 cases
  - witness-v1-512 + `OP_SHA512` cases
  - direct Tidecoin-node accept/reject and script-error parity

### `core_multisig_unit_parity.rs`

Old role:
- targeted multisig parity edge cases from Bitcoin Core

Tidecoin replacement:
- PQ multisig parity suite
- node-backed targeted edge cases:
  - valid PQ multisig
  - invalid signature ordering/selection
  - `NULLDUMMY`
  - `NULLFAIL`
  - strict-vs-legacy Falcon behavior where relevant

Status:
- `done`

Note:
- this should not be ported literally; it needs Tidecoin/PQ cases, not ECDSA
  Core script cases

What now exists:
- [consensus/tests/tidecoin_pq_multisig_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_pq_multisig_parity.rs)
  covers:
  - single-scheme PQ multisig matrix parity
  - mixed-scheme direct and wrapped parity
  - invalid signature ordering / outsider / wrong-sighash cases
  - `NULLDUMMY`
  - `NULLFAIL`
  - pubkey-count and push-size limit edges
  - strict-mode positive Falcon512 witness-v0 coverage

### `core_bip341_wallet_vectors.rs`

Old role:
- Taproot/BIP341 wallet and sighash vectors

Tidecoin replacement:
- no literal replacement
- split intent:
  - `delete` Taproot-only semantics
  - preserve only generic sighash/precompute coverage if it maps to:
    - base
    - witness-v0
    - witness-v1-512

Status:
- `delete` as a direct analogue
- `planned` as partial replacement via Tidecoin sighash/precompute tests

### `core_cpp_helper/`

Old role:
- helper binary used only for Bitcoin/Core differential execution

Tidecoin replacement:
- none as a standalone path
- its role is superseded by `node-parity/`

Status:
- `done` for architectural replacement
- keep archived only as historical reference

## Active Tidecoin-Native Replacements

These tests are already part of the new proof surface:

- [consensus/tests/tidecoin_node_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs)
  - `script_tests_pq.json`
  - `tx_valid_pq.json`
  - `tx_invalid_pq.json`

- [consensus/tests/tidecoin_runtime_diff.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_runtime_diff.rs)
  - `script_tests_pq.json`
  - `tx_valid_pq.json`
  - `tx_invalid_pq.json`
  - accept/reject parity
  - script-error parity

- [consensus/tests/tidecoin_script_assets.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets.rs)
  - node `script_assets_test.json`
  - subset/superset monotonicity parity
  - shared Tidecoin flag/token/prevout support

- [consensus/tests/tidecoin_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_unit_parity.rs)
  - Tidecoin-native `ScriptNum` creation/operator parity
  - Tidecoin-native P2SH detection/recursion/switchover parity
  - optional Tidecoin-node comparison for runtime cases

- [consensus/tests/tidecoin_sigop_surface.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sigop_surface.rs)
  - Tidecoin-native witness-v0/P2SH sigop surface parity
  - Tidecoin-node comparison for the active runtime cases

- [consensus/tests/tidecoin_witness_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_witness_unit_parity.rs)
  - Tidecoin-native witness-unit edge-case parity
  - Tidecoin-node comparison for runtime cases

- [consensus/tests/tidecoin_sighash_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_vectors.rs)
  - Tidecoin-node `sighash.json` corpus replay on lowered Tidecoin types

- [consensus/tests/tidecoin_sighash_cache_randomized.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_cache_randomized.rs)
  - randomized legacy sighash equivalence
  - BASE / witness-v0 cache parity on lowered Tidecoin types

- [consensus/tests/tidecoin_random_consistency.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_random_consistency.rs)
  - Tidecoin-native randomized differential coverage against the Tidecoin node

- [consensus/tests/tidecoin_pq_multisig_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_pq_multisig_parity.rs)
  - Tidecoin-native PQ multisig parity and edge-case coverage against the Tidecoin node

- [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
  lib tests
  - Tidecoin witness-v1-512 behavior
  - generic stack/opcode/witness invariants still meaningful under Tidecoin
  - PQ-oriented live runtime checks

## Gaps Versus Archived Coverage

The current Tidecoin-native test surface is good enough to keep migration
moving, but it is not yet equal to the archived proof depth.

Main remaining gaps:

1. The stale vendored Core-era corpora have been archived under [consensus/tests/archived/data](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/data); they are temporary migration reference only and should be deleted later once the Tidecoin-native proof surface is accepted.

## Implementation Order

1. Expand corpus runners
- deepen the current `tidecoin_node_parity.rs`
- deepen `tidecoin_runtime_diff.rs`
- add richer diagnostics and coverage accounting

2. Deepen targeted replacements where useful
- partially replace `core_bip341_wallet_vectors.rs` where there is a genuine
  Tidecoin analogue

## Acceptance Standard

We are done with the archived-suite migration only when:

- the active Tidecoin-native suite covers the same proof classes as the
  archived suite
- all external parity is against the Tidecoin node only
- no active test depends on Bitcoin/Taproot/`bitcoinconsensus`
- the archived files are no longer needed to explain missing proof depth
