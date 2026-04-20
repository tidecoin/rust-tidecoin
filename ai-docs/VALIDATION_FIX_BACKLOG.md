# Validation Fix Backlog

Status: active implementation backlog beneath
[README.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/README.md).

This file is updated as issues are validated and moved through the state machine.

## Open

### Tidecoin shared consensus core boundary cleanup (current)

The main open architecture problem is no longer missing PQ primitives, missing node-backed validation tails, or a missing shared interpreter. `tidecoin-consensus-core` now owns the shared interpreter, typed transaction context, sighash subset, PQ verification facade, witness execution planning, and flag core. The remaining problem is boundary cleanup: some wrapper/orchestration logic and node-parity adapter behavior still lives in the top-level `tidecoin` crate, while `consensus/` should remain the byte-oriented standalone adapter over the shared core.

That leaves the repo with active boundary-polish debt:

- the top-level `tidecoin` crate still owns public validation orchestration and node-backed test adapters
- the in-repo `consensus/` crate is now Tidecoin-native, but its historical byte-oriented test/proof surface still needs cleanup
- the shared Tidecoin consensus core is the right dependency boundary, but it still needs a final audit for any validation logic that should move down
- a direct `consensus -> tidecoin` dependency would create the wrong layering and likely a Cargo cycle once the top-level crate also wants to depend on the extracted consensus engine

Needed:

- keep refining the `tidecoin-consensus-core` boundary:
  - wrapper-free verification flags and supported-flag checks
  - script error types
  - consensus-critical sighash logic
  - witness-v0 and witness-v1-512 validation logic
  - `OP_SHA512`
  - PQ verification glue
  - transaction input verification helpers
- keep wallet/address/descriptor/P2P/node-runtime code out of that shared crate
- keep the node bridge outside the shared core crate
- make both the top-level `tidecoin` crate and any compatibility-facing `consensus` crate depend on the shared core instead of duplicating validation logic

### Shared Tidecoin node-parity harness matrix reconciliation (current)

The repository now has the right shared Tidecoin-specific node bridge
infrastructure and the active consumers are migrated:

- native build logic now lives in `node-parity/build.rs`
- bridge sources now live in `node-parity/c_src/**`
- raw FFI, fixture helpers, script-error mapping, and the first reusable
  `TidecoinNodeHarness` live in `node-parity/src/**`
- `tidecoin/src/consensus_validation_node.rs` is now an adapter over that
  shared harness
- `consensus/tests/tidecoin_node_parity.rs` now uses the same harness against
  Tidecoin node fixtures, currently covering:
  - `script_tests_pq.json`
  - `tx_valid_pq.json`
  - `tx_invalid_pq.json`

The older `consensus/tests/core_diff_bridge.rs` harness and its consumers are
now archived under `consensus/tests/archived/`. They remain reference material
only; active Tidecoin validation and differential tests must use the shared
Tidecoin node harness or local Tidecoin-native invariants.

Needed:

- keep the shared Tidecoin harness as test/dev parity infrastructure, not part
  of the pure-Rust production consensus core
- keep both `tidecoin` and `consensus/` tests on the same Tidecoin node-backed
  harness
- reconcile every archived Core-era proof class against its Tidecoin-native
  replacement in `ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md`
- do not restore archived Core-diff files to the active test set unless they are
  rewritten as Tidecoin-native node-parity tests

### `consensus/` crate migration to Tidecoin semantics (current)

The active `consensus/` crate is now a Tidecoin-native byte-oriented adapter
over `tidecoin-consensus-core`. Remaining migration debt is historical and
coverage-oriented:

- archived Bitcoin/Core proof files that still need Tidecoin-native replacements
- residual Bitcoin-oriented docs/metadata and historical notes
- explicit coverage-matrix reconciliation by retired historical class

Needed:

- keep `consensus/` rebased on the shared Tidecoin consensus core, not on the
  top-level `tidecoin` crate
- keep the crate's node-backed differential surface on the shared Tidecoin
  node-parity harness
- do not preserve old codec compatibility helpers; keep only Tidecoin-native byte-oriented
  validation APIs that are part of the standalone consensus contract
- replace Bitcoin/Taproot/Core-diff assumptions in metadata, docs, and archived proof-class replacements with Tidecoin node parity
- keep archived Bitcoin/Core-diff test files as historical reference only; do
  not restore them to the active test set without Tidecoin-node-based rewrite
- replace the removed Bitcoin/ECDSA unit surfaces with Tidecoin-native PQ coverage:
  - witness-v0 code-separator sighash behavior
  - witness-v0 raw hashtype behavior
  - explicit witness amount authority
  - legacy code-separator signature behavior
  - multisig intermediate-mismatch behavior, if still meaningful under Tidecoin rules

### Tidecoin consensus vector and parity migration (current)

The shared core boundary and first Tidecoin-oriented executable corpora now exist. The remaining work is not “invent a second standalone interpreter”, but “finish reconciling the old imported proof classes against the Tidecoin-native corpus and add only the missing parity tails”.

Needed:

- keep the imported Tidecoin node fixtures and corpora wired through the shared core / `consensus` test surface:
  - `script_tests_pq.json`
  - `tx_valid_pq.json`
  - `tx_invalid_pq.json`
  - `script_assets_test.json`
  - applicable sighash fixtures
- direct Tidecoin-node-backed consumers now exist for:
  - `script_tests_pq.json`
  - `tx_valid_pq.json`
  - `tx_invalid_pq.json`
  - `script_assets_test.json`
- Tidecoin-native generated large-corpus/provenance coverage now exists via:
  - [consensus/tests/tidecoin_script_assets_generated.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets_generated.rs)
  - [consensus/tests/data/tidecoin_script_assets_generated_metadata.json](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/data/tidecoin_script_assets_generated_metadata.json)
  - [consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py)
- remaining debt:
  - delete the archived Core-era script-assets payloads under
    `consensus/tests/archived/data/` later; they are temporary migration
    reference only
  - delete the broader archived Core-era corpora under
    `consensus/tests/archived/data/` later once the Tidecoin-native proof
    surface is accepted
- flag/token parsing around Tidecoin flags is now active:
  - `PQ_STRICT`
  - `WITNESS_V1_512`
  - `SHA512`
- the active Bitcoin Core / `bitcoinconsensus` differential tests have been
  replaced with shared Tidecoin-node parity tests
- preserve only generic local invariant tests that still make sense under Tidecoin semantics
- preserve archived proof depth explicitly, using the replacement matrix in
  [ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md),
  instead of letting the active test surface silently shrink
- the archived `ScriptNum` and P2SH unit proof classes are now replaced by
  [consensus/tests/tidecoin_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_unit_parity.rs);
  the archived sigop surface is now replaced by
  [consensus/tests/tidecoin_sigop_surface.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sigop_surface.rs);
  the archived witness-unit surface is now replaced by
  [consensus/tests/tidecoin_witness_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_witness_unit_parity.rs);
  the active `sighash.json` corpus is now replayed by
  [consensus/tests/tidecoin_sighash_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_vectors.rs);
  the archived deep sighash proof class is now further restored by
  [consensus/tests/tidecoin_sighash_cache_randomized.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_cache_randomized.rs);
  the archived randomized differential class is now replaced by
  [consensus/tests/tidecoin_random_consistency.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_random_consistency.rs);
  the archived multisig proof class is now replaced by
  [consensus/tests/tidecoin_pq_multisig_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_pq_multisig_parity.rs);
  the runtime-diff exercised-token/flag/error accounting is now restored in
  [consensus/tests/tidecoin_runtime_diff.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_runtime_diff.rs);
  the remaining proof-class gap is mainly stale fixture cleanup

Priority note:

- do not treat test migration as the lead task
- use the shared Tidecoin node harness as the active proof path; `core_diff_bridge`
  is archived historical material now, so remaining work is matrix reconciliation,
  fixture provenance cleanup, and filling explicitly documented node-parity gaps

### Chain-rule coverage below the new core boundary (current)

Below the architecture work, a few protocol checks still deserve explicit coverage once the shared core and migrated harnesses are in place.

#### AuxPoW validation vectors

Rust now has `tidecoin::pow::validate_auxpow_context(...)` for the node-shaped
pure-header AuxPoW context path. It checks AuxPoW flag/payload consistency,
pre-activation rejection, strict chain ID enforcement, chain ID bits without the
AuxPoW flag, merge-mining header/root placement, coinbase-to-parent merkle
branch validation, deterministic chain index, and parent scrypt PoW against the
child header `nBits`.

Implementation direction:
- keep `primitives` as the owner of AuxPoW/header wire structures and codecs
- keep consensus-context checks in `tidecoin::pow`, not in the codec layer
- match the Tidecoin node's `CheckAuxPowContext(...)` path in
  `/home/yaroslav/dev/tidecoin/tidecoin/src/validation.cpp`
- do not route AuxPoW parent validation through `HeaderExt::validate_pow(...)`;
  the parent proof is checked with the parent header's scrypt PoW hash against
  the child block's `nBits`, matching `CAuxPow::getParentBlockHash()`
- use the focused node-parity header PoW bridge for
  `HasValidProofOfWork`-style checks without pulling full `validation.cpp` into
  the test harness

Current fixture coverage:
- The current fixture file
  `tidecoin/tests/data/auxpow_headers.json` covers valid regtest AuxPoW,
  parent PoW failure, wrong chain ID, parent chain ID collision, wrong chain
  index, invalid transaction merkle branch, invalid chain merkle branch,
  missing chain merkle root, missing and duplicated merged-mining headers,
  misplaced merged-mining header, merkle-size mismatch, missing size/nonce
  metadata, testnet activation acceptance, pre-activation rejection, and missing
  payload decode rejection.
- `tidecoin/tests/data/testnet_retarget_windows.json` now contains real
  active-chain RPC testnet headers for genesis-to-activation legacy
  min-difficulty walk-back, activation, the first local AuxPoW payload, an early
  post-AuxPoW span, and later AuxPoW spans through height 16120. Mainnet AuxPoW
  vectors are not applicable while mainnet `auxpow_start_height` is disabled in
  Tidecoin chain params.

Needed:
- Invalid AuxPoW blocks beyond the current fixture file: remaining historical
  edge cases observed from node data, especially any real-chain malformed
  commitment cases not covered by the synthetic node-functional fixture matrix.
- More parent block header validation vectors (pure 80-byte, no nested AuxPoW)

#### PoW hash algorithm selection

Rust currently has target arithmetic, exact node-style compact target
derivation, an explicit height-gated `pow_hash_algorithm_at_height(...)`
selector, yespower and scrypt pure-header mining hashes, and node-bridge oracles
for both hash classes. The node uses yespower 1.0 (`N = 2048`, `r = 8`) for
`GetPoWHash()` before auxpow activation and scrypt-1024-1-1-256 for
`GetScryptPoWHash()` after auxpow activation. `CheckProofOfWork(block, params,
height)` selects between those two through `UsePostAuxpowPowRules(...)`.

The inherited rust-bitcoin helper model is not enough here. Upstream
rust-bitcoin's `HeaderExt::validate_pow(required_target)` is a narrow helper for
Bitcoin's SHA256d header-hash PoW: it decodes `nBits`, compares the result with a
caller-supplied target, and checks `target.is_met_by(header.block_hash())`. That
shape only works for Bitcoin because Bitcoin's mining hash is the block header
hash. Tidecoin must keep the same target comparison primitive, but feed it the
selected Tidecoin mining hash instead of `header.block_hash()`.

Implementation direction:
- `HeaderExt::validate_pow(params, height, required_target)` is now narrowed to
  a pure-header helper: it takes height and chain params, derives target
  validity from `nBits`, and no longer uses `header.block_hash()` for mining
  proof checks
- `validate_pow_at_height(header, params, height)` is now the node-shaped
  pure-header `CheckProofOfWork(block, params, height)` equivalent; it derives
  the target from header `nBits`, selects the height-dependent mining hash, and
  checks that hash against the header target
- `validate_pow_any(header, params)` is now the node-shaped heightless
  `CheckProofOfWorkAny(block, params)` equivalent for header-sync/anti-DoS
  contexts where height is not known
- `validate_pow_at_height_against_target(...)` and
  `HeaderExt::validate_pow(...)` add the separate caller-supplied expected
  target check for contextual difficulty validation; keep a separate
  block/header context API for AuxPoW payload checks
- derive target validity from `nBits` and the active network pow limit, matching
  node `DeriveTarget(...)`; only compare against caller-supplied expected target
  after the header's own `nBits` has passed node-style target decoding
- select the mining hash with the same rule as the node:
  `UsePostAuxpowPowRules(params, height)` selects scrypt at and after
  AuxPoW activation, otherwise yespower
- add pure 80-byte header hash functions matching node
  `CPureBlockHeader::GetPoWHash()` and `CPureBlockHeader::GetScryptPoWHash()`
  from `/home/yaroslav/dev/tidecoin/tidecoin/src/primitives/pureheader.cpp`

Current state:
- Tidecoin-native pure-header PoW hash APIs exist:
  `yespower_pow_hash`, `scrypt_pow_hash`, and height-gated selection.
- `validate_pow_at_height(...)` validates the selected hash against `nBits`,
  not the header identity hash, with node-bridge pass/fail coverage for
  height-aware yespower and scrypt proof checks.
- `validate_pow_any(...)` mirrors the node heightless `CheckProofOfWorkAny`
  path, with node-bridge pass/fail coverage for yespower and scrypt.
- `tidecoin::block_validation::contextual_check_block_header(...)` now uses
  `next_target_after(...)` to check exact contextual `nBits`, MTP, BIP94
  timewarp, version gates, and selected PoW/AuxPoW proof.
- `tidecoin::block_validation::contextual_check_block(...)` now adds the
  node-shaped non-UTXO block context layer: context-free block sanity,
  contextual header checks, transaction finality using the CSV-height cutoff
  rule, BIP34 coinbase height, and pre-activation witness rejection. Focused
  node-bridge tests cover these cases plus larger 65-transaction final and
  non-final blocks.
- Real testnet fixture windows are generated from node active-chain RPC and
  cover genesis-to-activation legacy min-difficulty walk-back, activation, the
  first local AuxPoW payload, an early post-AuxPoW range, and a later AuxPoW
  range through height 16120. Rust verifies both observed `nBits` and
  contextual header acceptance over the checkable contiguous candidates.

Needed:
- add broader historical contextual header walks outside the current
  active-chain fixture set if new node data exposes additional edges
- defer UTXO/chain-connect ownership to the future crate described in
  [`CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md`](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md)
  if Rust is meant to validate full node block connection. BIP30, sequence
  locks, spend availability, coinbase maturity, fees, value-in/value-out
  checks, and coinbase reward-claim validation require a chainstate/UTXO
  database and do not belong in this protocol-library crate.

#### Subsidy/reward schedule

Status: `done` for the library-scope schedule.

The Tidecoin reward schedule uses doubling-interval quartering (40 TDC base,
right-shift by 2 per era), distinct from Bitcoin's simple halving. It is now
implemented in `tidecoin::subsidy::block_subsidy(...)` and covered against the
node `GetBlockSubsidy` schedule from `validation.cpp`.

Coverage now mirrors the node's `validation_tests.cpp` boundary-walk shape,
including:

- mainnet/testnet interval `262_800`
- regtest interval `20`
- custom interval probes `150` and `1000`
- every reachable transition boundary in the pure Rust test helper
- every node-bridge-representable transition boundary for mainnet, testnet,
  and regtest
- the node's pinned total subsidy through height `14_000_000`

Coinbase reward-claim validation is not part of this schedule helper. The node
checks `coinbase_value <= fees + GetBlockSubsidy(height, params)` in
`ConnectBlock`, and fee calculation requires chainstate/UTXO data. That belongs
to the deferred chain-connect crate rather than this protocol-library layer.
The proposed crate boundary, traits, and minimum parity test matrix are recorded
in
[`CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md`](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md).

#### Difficulty retargeting edge cases

Focused retargeting tests now exist in `tidecoin/src/pow.rs`, including the
node legacy overflow-guarded scaling path, first mainnet historical retarget,
activation-boundary behavior, insufficient post-AuxPoW window behavior,
real testnet genesis-to-activation, activation, first-AuxPoW, and early
post-AuxPoW plus later AuxPoW windows, and transition-envelope checks.
Current state:
- The missing node parameter fields are now represented in
  `tidecoin::network::Params`: strict AuxPoW chain ID, post-AuxPoW averaging
  window, max adjust up/down, and the optional post-AuxPoW min-difficulty
  activation height.
- `tidecoin::pow::next_target_after(...)` now ports the Tidecoin node's
  `GetNextWorkRequired(...)` switch: legacy interval retargeting before AuxPoW
  activation and post-AuxPoW per-block averaging-window retargeting after
  activation. The legacy path now uses the node's overflow-guarded scaling
  behavior.
- `CalculateNextWorkRequiredNew(...)` behavior is now mirrored for the Rust
  retarget path, including median-time-past inputs, `AveragingWindowTimespan`,
  `MinActualTimespan`, `MaxActualTimespan`, and node-style divide-before-multiply
  rounding.
- `permitted_difficulty_transition(...)` now ports
  `PermittedDifficultyTransition(...)` so header-window validation can check
  both pre-activation legacy bounds and post-activation max-adjust bounds.
- `tidecoin/tests/data/testnet_retarget_windows.json` provides real
  node active-chain RPC windows for genesis-to-activation legacy min-difficulty
  walk-back, `auxpow_start_height`, the first local AuxPoW payload, an early
  post-AuxPoW span, and a later AuxPoW span through height 16120; Rust verifies
  observed `nBits` through `next_target_after(...)` and validates checkable
  contextual headers.

Still missing:
- Historical chain difficulty walks outside the current active-chain fixture set
- Overflow and minimum-difficulty boundary cases
- Additional testnet min-difficulty edge cases if historical data exposes them

#### Standalone PQ signature operation tests

The standalone high-level `tidecoin` PQ surface now covers the local
signing/keygen/key-I/O responsibilities that do not belong in verification-only
`tidecoin-consensus-core`:

- Falcon-512/1024 sign-then-verify roundtrip with deterministic randomized
  messages
- ML-DSA-44/65/87 sign-then-verify roundtrip with deterministic randomized
  messages
- signature size bound assertions per scheme
- public key size validation per scheme
- invalid/corrupted signature rejection per scheme
- cross-scheme signature/key rejection across all active signature schemes

Remaining depth work belongs in the node-backed corpus, not in a second
verification implementation in `tidecoin`: add any missing node PQ vectors to
the shared Tidecoin-node harness and keep consensus-core as the single verifier.

#### Continuous fuzz parity

Rust now has active cargo-fuzz targets for the Tidecoin-node fuzz surfaces that
belong inside this repository:

- `consensus_script_runtime` mirrors the stateless interpreter execution paths
  from node `script_interpreter.cpp` through the byte-oriented consensus API.
- `tidecoin_transaction_policy` mirrors the stateless transaction and policy
  checks from node `transaction.cpp`.
- `tidecoin_script_policy` mirrors the script classification, sigop, dust, and
  standardness checks from node `script.cpp`, including policy script-flag
  derivation.
- `tidecoin_tx_out_policy` mirrors the library-owned output-policy pieces from
  node `tx_out.cpp`: output consensus encoding, size/weight accounting, and dust
  threshold helpers.
- `tidecoin_block_sanity` mirrors the library-owned block sanity checks from
  node `block.cpp`: context-free block sanity, merkle/witness-root derivation,
  checked-block construction, block hash, weight, and BIP34 coinbase-height
  extraction.
- `tidecoin_pow` mirrors compact target, mining hash selection, PoW validation,
  AuxPoW context, difficulty-transition, and next-work checks from node
  `pow.cpp`.

Still future scope:

- `coins_view.cpp` parity needs UTXO set ownership.
- package-policy fuzz needs mempool/package ownership.

Those targets should be added when the chain-connect/mempool validation crate is
introduced, not by duplicating chainstate or mempool logic in `rust-tidecoin`.

## Closed

- `done` Close the final residual node-test tails from the post-push audit:
  - exact legacy-WIF `key_io_txcreatesignv1_p2pkh_legacy_wif_verifies`
  - library-equivalent coverage for the `key_io_txcreatesignv1_p2pkh_toolpath_verifies` BASE-sighash path
  - PQ bech32 namespace/checksum rejection coverage from `key_io_tests.cpp`
  - single-scheme PQ multisig and committed-hash matrix coverage
  - strict-mode PQ multisig coverage
  - witness-script size, bare-PQ-multisig, and worst-case `20-of-20` ML-DSA-87 policy tails
- `done` Finish the remaining direct Tidecoin node executable-coverage tails after the parity sweep. The current tree now carries direct coverage for the previously listed witness-v1-512 script edges, transaction/policy tails (`spends_witness_prog`, `test_IsStandard`, `max_standard_legacy_sigops`), PQ input-vsize formulas, and the non-JSON PQ `key_io` WIF behavior.
- `done` Re-run the final Tidecoin crate verification sweep and tie the tracker state to actual commands:
  - `cargo check --workspace`
  - `cargo test --workspace`
  - `cargo check -p tidecoin --all-features --tests --examples`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `git diff --check`
- `done` Implement the Tidecoin validation/runtime surface in `tidecoin/src/consensus_validation.rs`, `tidecoin/src/consensus_validation_node.rs`, and `tidecoin/src/consensus_validation_tidecoin.rs`, then migrate the node PQ script/transaction/asset/multisig corpora with additional mixed witness-v0/v1-512 and legacy base-signature regression coverage.
- `done` Remove the optional `bitcoinconsensus` validation surface from `tidecoin/src/consensus_validation.rs` so the top-level Tidecoin crate validates through Tidecoin-native runtime paths only.
- `done` Restore the public validation surfaces that were lost when the Bitcoin-only `bitcoinconsensus` tests were removed:
  - direct `ScriptPubKeyExt::verify(...)` success path
  - Tidecoin-native multi-input transaction success path
  - missing/reused spent-output failure path
  - corrupted signature failure path
  - exact record and remaining broader cleanup candidates are documented in [ai-docs/archived/REMOVED_VALIDATION_TEST_SURFACES.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived/REMOVED_VALIDATION_TEST_SURFACES.md)
- `done` Record the validated Falcon/PQ runtime gap report in [ai-docs/archived/FALCON_PQ_GAP_REPORT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived/FALCON_PQ_GAP_REPORT.md) and align the tracker with the current node-vs-Rust compatibility status.
- `done` Implement the first PQHD parity slice: node-mirrored PQHD v1 KDF/path validation in `tidecoin/src/pqhd.rs`, with regression coverage for roundtrip/combine/malformed cases. PSBT PQHD helper work was part of the earlier migration history and is not a current live module.
- `done` Implement PQ public-key derivation and Falcon legacy-mode signing/verification parity in `tidecoin/src/crypto/pq.rs` using a small node-compatible PQClean bridge, with regression coverage across all five schemes.
- `done` Implement deterministic PQHD key generation and PQ secret-key codec parity in `tidecoin/src/pqhd.rs` and `tidecoin/src/crypto/pq.rs`, with exact node hash vectors and prefixed/raw-secret roundtrip coverage.
- `done` Implement `pqhd(...)` parsing, deterministic derivation, and wallet descriptor string generation in `tidecoin/src/key_expression.rs`, with node-style parsing and policy tests.
- `done` Implement ML-KEM-512 keypair / deterministic keypair / encapsulate / deterministic encapsulate / decapsulate helpers in `tidecoin/src/crypto/pq.rs`, with node-style roundtrip and deterministic regression coverage.
- `done` Implement Tidecoin v2 PQ transport parity from node transport semantics in `p2p/src/pq_v2_transport.rs`, with node-derived FSChaCha20, FSChaCha20Poly1305, and packet-cipher tests.
- `done` Remove the dead `legacy_sighash.json` and unused mainnet/testnet raw fixtures, correct the remaining stale fee-unit/network-policy docs, and confirm that legacy `reject` payloads already decode as `Unknown` while `alert` remains live for old-peer compatibility.
- `done` Complete repository publish flow by pushing the validated tree to `origin` branch `v2` (`d8bbe1e`).
- `done` Replace stale `Network::Bitcoin` references in feature-gated tests and examples so `cargo check -p tidecoin --all-features --tests --examples` succeeds.
- `done` Remove stale mainnet address literals and legacy Bitcoin wording from examples/docs/fuzz generator.
- `done` Remove or refactor unused PQ code paths and clippy violations in `tidecoin/src/crypto/pq.rs`, and add real PQ coverage.
- `done` Reconcile legacy base58 behavior with the Tidecoin node, including dual P2SH decode prefixes.
- `done` Eliminate remaining warnings and dead code across requested compile targets; strict clippy currently passes.
- `done` Delete the unused internal taproot signature module and the disabled taproot-only sighash layer so strict clippy passes without dead-code allowances.
- `done` Remove the dedicated `TapScriptTag` marker from primitives and collapse `TapScript{,Buf}` onto the witness-script types to reduce taproot-specific surface while preserving workspace compilation.
- `done` Remove the hidden `tidecoin/src/taproot/**` module and its dependent consensus/key hooks.
- `done` Align regtest legacy address and WIF formatting with Tidecoin node prefixes instead of collapsing regtest into generic testnet handling.
- `done` Align `MAX_STANDARD_TX_WEIGHT` with the Tidecoin node policy constant and add regression coverage.
- `done` Migrate Tidecoin node `key_io_valid.json` and `key_io_invalid.json` into integration coverage for addresses and WIF keys.
- `done` Audit every live `#[ignore]` and close the code-level ignore debt; no Rust `#[ignore]` test attributes remain.
- `done` Convert avoidable ignored doctests to checked examples and document the three remaining justified ignored doctest sketches.
- `done` Remove the residual `is_p2tr()` API and taproot-era serde fixtures while retaining `OP_CHECKSIGADD` only as a disabled node-compatibility opcode.
