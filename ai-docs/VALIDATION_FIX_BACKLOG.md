# Validation Fix Backlog

This file is updated as issues are validated and moved through the state machine.

## Open

### Tidecoin shared consensus core boundary cleanup (planned)

The main open architecture problem is no longer missing PQ primitives, missing node-backed validation tails, or a missing shared interpreter. `tidecoin-consensus-core` now owns the shared interpreter, typed transaction context, sighash subset, PQ verification facade, witness execution planning, and flag core. The remaining problem is boundary cleanup: some wrapper/orchestration logic and node-parity adapter behavior still lives in the top-level `tidecoin` crate, while `consensus/` should remain the byte-oriented standalone adapter over the shared core.

That leaves the repo in an unstable shape:

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

### Shared Tidecoin node-parity harness migration is incomplete (planned)

The repository now has the right shared Tidecoin-specific node bridge
infrastructure, but the migration is not finished:

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

At the same time, the imported `consensus/` crate has a cleaner differential
harness shape in `consensus/tests/core_diff_bridge.rs`, but it is built around
the wrong external target: Bitcoin Core / `libbitcoinconsensus`.

That leaves the repo with one remaining split:

- the shared Tidecoin harness exists and works
- but `consensus/` still carries the older Bitcoin-specific
  `core_diff_bridge` differential path alongside it

Needed:

- keep the shared Tidecoin harness as test/dev parity infrastructure, not part
  of the pure-Rust production consensus core
- continue the migration by replacing `consensus/tests/core_diff_bridge.rs`,
  `script_vectors.rs`, `core_tx_vectors.rs`, and the Bitcoin/Core differential
  path with the shared Tidecoin harness
- the explicitly incompatible Bitcoin/Core-diff files have now been archived
  under `consensus/tests/archived/`; they should stay archived unless and until
  they are rewritten as Tidecoin-native node-parity tests
- make both `tidecoin` and `consensus/` tests use the same Tidecoin node-backed
  harness
- stop growing the Bitcoin-specific `core_diff_bridge` as the long-term path

### `consensus/` crate migration to Tidecoin semantics (planned)

The imported `consensus/` crate still carries Bitcoin-shaped migration debt:

- archived Bitcoin/Core proof files that still need Tidecoin-native replacements
- residual Bitcoin-oriented docs/metadata and historical notes
- some surviving semantics/tests that still need to be replaced by Tidecoin-specific coverage classes

Needed:

- first audit `consensus/src/lib.rs` and the runtime/API surface, then classify each Bitcoin/Taproot/`bitcoinconsensus` assumption as:
  - delete
  - rewrite
  - replace via shared `tidecoin-consensus-core`
- stop treating direct dependency on the top-level `tidecoin` crate as the target architecture
- rebase the crate on the shared Tidecoin consensus core instead
- make the crate's node-backed differential surface use the shared Tidecoin
  node-parity harness
- do not preserve old codec compatibility helpers; keep only Tidecoin-native byte-oriented
  validation APIs that are part of the standalone consensus contract
- remove Bitcoin-only flags and paths from the public contract
- replace Bitcoin/Taproot/Core-diff assumptions in metadata, docs, and archived proof-class replacements with Tidecoin node parity
- keep archived Bitcoin/Core-diff test files as historical reference only; do
  not restore them to the active test set without Tidecoin-node-based rewrite
- replace the removed Bitcoin/ECDSA unit surfaces with Tidecoin-native PQ coverage:
  - witness-v0 code-separator sighash behavior
  - witness-v0 raw hashtype behavior
  - explicit witness amount authority
  - legacy code-separator signature behavior
  - multisig intermediate-mismatch behavior, if still meaningful under Tidecoin rules

### Tidecoin consensus vector and parity migration (planned)

Once the shared core boundary exists, the next missing layer is a Tidecoin-oriented executable corpus around it. The priority is not “invent a second standalone interpreter”, but “re-anchor the existing imported test surface on Tidecoin semantics”.

Needed:

- import Tidecoin node fixtures and corpora into the shared core / `consensus` test surface:
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
- rewrite flag/token parsing around Tidecoin flags:
  - `PQ_STRICT`
  - `WITNESS_V1_512`
  - `SHA512`
- replace Bitcoin Core / `bitcoinconsensus` differential tests with shared
  Tidecoin-node parity tests
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
- use the new shared Tidecoin node harness to support the real migration, but only retire large `core_diff_bridge` consumers after the corresponding runtime/API assumptions in `consensus/src/lib.rs` have been rewritten or removed

### Chain-rule coverage below the new core boundary (planned)

Below the architecture work, a few protocol checks still deserve explicit coverage once the shared core and migrated harnesses are in place.

#### AuxPoW validation vectors

No tests currently exercise AuxPoW chain-ID validation, merge-mining branch verification, or coinbase commitment checking. The struct and serialization layer is solid but the consensus-rule enforcement is untested.

Needed:
- Known mainnet AuxPoW block headers with verified chain_id = 8
- Invalid AuxPoW blocks: wrong chain ID, invalid merkle branch, missing coinbase commitment
- Boundary: blocks at auxpow_start_height transition
- Parent block header validation (pure 80-byte, no nested AuxPoW)

#### Subsidy/reward schedule

The Tidecoin reward schedule uses doubling-interval quartering (40 TDC base, right-shift by 2 per era), distinct from Bitcoin's simple halving. No tests validate this schedule. SUBSIDY_HALVING_INTERVAL is defined but never exercised.

Needed:
- Block reward at height 0, at each era boundary, and after final halving
- Comparison with the Tidecoin node's GetBlockSubsidy output

#### Difficulty retargeting edge cases

Basic retargeting tests exist (4 cases in pow.rs), but the following are missing:
- AuxPoW-era difficulty adjustment
- Historical chain difficulty walk with known block headers
- Overflow and minimum-difficulty boundary cases
- Testnet min-difficulty rule activation and walk-back behavior with more than one historical block

#### Standalone PQ signature operation tests

The `tidecoin-node-validation` feature covers PQ execution through the C++ bridge, but no standalone Rust tests exercise:
- Falcon-512/1024 sign-then-verify roundtrip with random messages
- ML-DSA-44/65/87 sign-then-verify roundtrip with random messages
- Signature size bounds enforcement per scheme
- Public key size validation per scheme
- Invalid/corrupted signature rejection
- Cross-scheme rejection (Falcon sig against ML-DSA key)

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
  - exact record and remaining broader cleanup candidates are documented in [ai-docs/REMOVED_VALIDATION_TEST_SURFACES.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/REMOVED_VALIDATION_TEST_SURFACES.md)
- `done` Record the validated Falcon/PQ runtime gap report in `FALCON_PQ_GAP_REPORT.md` and align the tracker with the current node-vs-Rust compatibility status.
- `done` Implement the first PQHD parity slice: node-mirrored PQHD v1 KDF/path validation in `tidecoin/src/pqhd.rs`, Tidecoin PSBT PQHD origin helpers in `tidecoin/src/psbt/tidecoin.rs`, and regression coverage for roundtrip/combine/malformed cases.
- `done` Implement PQ public-key derivation and Falcon legacy-mode signing/verification parity in `tidecoin/src/crypto/pq.rs` using a small node-compatible PQClean bridge, with regression coverage across all five schemes.
- `done` Implement deterministic PQHD key generation and PQ secret-key codec parity in `tidecoin/src/pqhd.rs` and `tidecoin/src/crypto/pq.rs`, with exact node hash vectors and prefixed/raw-secret roundtrip coverage.
- `done` Implement `pqhd(...)` parsing, deterministic derivation, and wallet descriptor string generation in `key_expression/src/lib.rs`, with node-style parsing and policy tests.
- `done` Implement ML-KEM-512 keypair / deterministic keypair / encapsulate / deterministic encapsulate / decapsulate helpers in `tidecoin/src/crypto/pq.rs`, with node-style roundtrip and deterministic regression coverage.
- `done` Implement Tidecoin v2 PQ transport parity from node `src/bip324_pq.h` in `p2p/src/bip324_pq.rs`, with node-derived FSChaCha20, FSChaCha20Poly1305, and packet-cipher tests.
- `done` Remove the dead `legacy_sighash.json` and unused mainnet/testnet raw fixtures, correct the remaining Tidecoin-facing `BTC/kB` / "today's Bitcoin network" docs, and confirm that legacy `reject` payloads already decode as `Unknown` while `alert` remains live for old-peer compatibility.
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
