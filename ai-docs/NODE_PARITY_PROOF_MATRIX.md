# Node Parity Proof Matrix

Status: rc3 migration evidence; see the active plan for completed checks.

This matrix is subordinate to [README.md](README.md). It maps stateless and
caller-context Rust validation to evidence against C++ node
`ffed4e92e60ff2de30361648a71cba64531f9077` (`v1.0.0rc3`). The
[active migration record](RC3_MIGRATION_PLAN.md)
owns commands, results and CI status. Passing these cases is a bounded
compatibility checkpoint, not proof of every possible input.

## rc3 additions

| Surface | Original-source comparison |
| --- | --- |
| Legacy Falcon negative zero/final bits, strict padding and relay error order | rc3 cases in `consensus/tests/tidecoin_rc2_rules.rs`; original verifier, classifier and interpreter |
| PQHD purposes/coin types and KDF, WIF identity, Falcon key encoding, ML-KEM coefficients | `tidecoin/tests/rc3_key_boundaries.rs`; original PQHD, key I/O and cryptography |
| Witness dependence, native/wrapped sigops and policy | `tidecoin/tests/rc3_witness_context.rs`; original interpreter and policy functions |
| AuxPoW header size, reply size/count, message constants | rc3 header test in `rc2_original_validation.rs`, `rc3_witness_context.rs`; original admission and size tracker |
| P2P payload/frame boundary enforcement | `p2p/tests/rc3_message_limits.rs`; slice and incremental decoding |

The signing/fee follow-up adds `tidecoin/tests/rc3_fee_estimation.rs`: original
C++ dummy creators in both modes, serialized transaction weights, rounded fees,
dust thresholds and push lengths (2,580 cases). It fixes earlier dust rounding
and fractional rate precision gaps. Signing tests also cover nonce freshness,
forced completed retries, exhaustion, entropy failure and repeated original-node
verification. See the follow-up in [the migration plan](RC3_MIGRATION_PLAN.md).

The script, witness and decoding review adds `fuzz/tests/node_oracle.rs` and the
`consensus_node_differential` fuzz target. Both compare exact script errors from
original C++ `VerifyScript` with fresh, byte-API and repeated-interpreter Rust
verification, and compare wire decoding and transaction sanity as separate
layers. Both also run each case's scripts through original `EvalScript` and
compare the complete resulting stack, or the exact error, under all three
sigversions. Nine Rust discrepancies were found and fixed: interpreter reuse,
witness-v1 `MINIMALIF`, witness program recognition, v0 standardness, multisig
tail order, opcode-limit order, numeric stack depth, `FindAndDelete` push
encoding and witness stack depth before execution. Mutation testing of the
interpreter guided the targeted comparisons. See
[the review record](RC3_MIGRATION_PLAN.md#script-witness-and-decoding-review-2026-11-16).
A later digest comparison found a tenth discrepancy, in legacy script-code
serialization; see
[signature hash comparison](RC3_MIGRATION_PLAN.md#signature-hash-comparison-2026-11-18).

## Retained and updated differential suites

Historical `rc2` filenames retain regression provenance; required runs now use
the rc3 pin and updated source-derived expectations.

| Surface | Evidence | Oracle boundary |
| --- | --- | --- |
| V1 SHA-512 commitments, six modes, ordered spent outputs, missing context, SINGLE boundaries and cache invalidation | `consensus/tests/tidecoin_rc2_context.rs`, `tidecoin/tests/rc2_spent_output_context.rs` | Original `SignatureHash512` and interpreter; independent digest vector in `tidecoin_rc2_oracle.rs`. |
| Activation, native/wrapped v1, ordinary preactivation scripts, independent flags, scheme eligibility | `consensus/tests/tidecoin_rc2_rules.rs` | Original C++ interpreter and PQ routines. |
| All 256 legacy/v0 hash bytes, defined v1 modes, error ordering, NULLFAIL and multisig | same rules suite and context suite | Original C++ interpreter; preserves historical legacy/v0 semantics. |
| Legacy, witness-v0 and witness-v1-512 digests for generated transaction shapes, raw legacy/v0 hash types, separator and malformed script code, shared caches | `compare_random_sighashes` (fuzz kind 4), `fuzz/tests/node_oracle.rs`, `consensus/tests/tidecoin_sighash_vectors.rs` (raw `sighash.json` scripts) | Original `SignatureHash` (cached, precomputed and uncached paths must agree) and `SignatureHash512`; v1 queries use the six defined modes. |
| Three-input single-key spends across legacy/v0/v1, per-input hash modes, paired edits and activation | `mixed_signed_inputs_match_rc3`, `mixed_signed_wire_weight_and_fees_match_rc3`, kind-3 fuzz extension | Exact per-input results and first failing input error for the Rust transaction API. Rust weight, vsize and fee at a rate match node functions. The paid fee from node `CheckTxInputs` matches test arithmetic on supplied prevouts. [Evidence](RC3_MIGRATION_PLAN.md#mixed-input-signed-transactions-2026-11-18). |
| Legacy Falcon length and strict/legacy padding profiles | `legacy_falcon_size_and_v1_strictness_match_node_boundaries`, `falcon_padding_profiles_match_node_and_script_activation` | Original node legacy and PQClean verifiers; synthetic boundary fixture has its own generator. |
| Flag-aware witness sigops | `sigop_cost_uses_candidate_flags_and_matches_node_count_witness_sigops` | Original `CountWitnessSigOps`. |
| Header activation, versions, chain ID, timestamps, retargets and replaceable proof classification | `tidecoin/tests/rc2_original_validation.rs`, existing block/PoW tests | Original `ContextualCheckBlockHeader` and `CheckBlockHeader`; unmodified node defaults checked separately. |
| Regtest genesis and yespower/scrypt | rc2 oracle/product tests and `tidecoin::pow` tests | Original `pow.cpp` and node crypto, with isolated yespower symbols. |
| Required oracle availability and identity | `node-parity/tests/configuration.rs` | Missing/invalid runtime configuration, a different checkout, absent executable and stale executable identities must fail. |

Block/context/subsidy comparisons now call the unmodified original `validation.cpp`
through a standalone executable. The [follow-up record](RC2_MIGRATION_PLAN.md#original-node-validation-follow-up-2026-10-20)
owns build commands, boundary coverage and caller-context limits.
Caller-supplied spent outputs are checked for shape and current-input consistency;
the library cannot authenticate their actual outpoint association without UTXO state.

Full node acceptance parity is intentionally out of scope here. `ConnectBlock`,
`CheckTxInputs`, BIP30, coinbase maturity, UTXO-backed sequence locks, fee and
subsidy connect checks, `MemPoolAccept`, package topology, RBF/conflicts, and
ephemeral dust packages belong to future stateful crates.

## Policy Flags And Relay Prechecks

| Node surface | Rust owner | Proof artifact |
| --- | --- | --- |
| P2P message-start constants | `tidecoin_p2p_messages::Magic` / `NetworkExt` | `p2p/tests/tidecoin_node_magic_parity.rs` |
| Mandatory script flags | `tidecoin::policy::MANDATORY_SCRIPT_VERIFY_FLAGS` | `tidecoin/src/policy.rs::standard_policy_script_flags_match_node_auxpow_activation` |
| Standard script flags before AuxPoW | `tidecoin::policy::STANDARD_NOT_MANDATORY_VERIFY_FLAGS` | same activation test |
| Post-AuxPoW PQ flags | `tidecoin::policy::standard_policy_script_flags` | same activation test proves `PQ_STRICT`, `WITNESS_V1_512`, and `SHA512` are height-gated |
| `IsStandardTx` output/script policy | `tidecoin::policy::is_standard_tx` | `is_standard_tx_matches_node_p2pk_classification`, `is_standard_tx_matches_node_multisig_pubkey_validation`, `is_standard_tx_reasons_match_node_policy`, `is_standard_tx_covers_additional_node_cases` |
| Stateless mempool prechecks | `tidecoin::policy::check_standard_relay_prechecks` | small non-witness size, pre-AuxPoW witness-v1 output, standard sigop cost, and stateless TRUC vsize tests in `tidecoin/src/policy.rs` |
| Input standardness | `tidecoin::policy::are_inputs_standard` | P2SH sigop-limit tests in `tidecoin/src/policy.rs`; UTXO lookup is caller supplied |
| Witness standardness | `tidecoin::policy::is_witness_standard` | native and wrapped P2WSH/P2WSH-512 boundary tests in `tidecoin/src/policy.rs` |
| Dust thresholds | `ScriptPubKeyExt` / `TxOutExt` dust helpers | `dust_thresholds_match_tidecoin_node_pq_proxies`, plus `tidecoin_tx_out_policy` fuzz |

## Script And Witness Consensus Limits

| Node surface | Rust owner | Proof artifact |
| --- | --- | --- |
| `OP_SHA512` disabled/enabled/discouraged behavior | `consensus-core` interpreter via `consensus` byte API | `consensus/tests/tidecoin_unit_parity.rs::tidecoin_sha512_opcode_flag_boundary_matches_node` |
| `OP_CODESEPARATOR` under `CONST_SCRIPTCODE` | `consensus-core` interpreter | `tidecoin_const_scriptcode_and_script_size_boundaries_match_node` |
| Base script size `65_536/65_537` | `consensus-core` interpreter | `tidecoin_const_scriptcode_and_script_size_boundaries_match_node` |
| Push element size `8192/8193` | `consensus-core` interpreter | `tidecoin_push_size_boundary_matches_node` |
| Witness-v0 `MINIMALIF` | `consensus-core` witness execution | `consensus/tests/tidecoin_witness_unit_parity.rs::tidecoin_witness_minimalif_boundary_matches_node` |
| Witness-v1-512 hash dispatch and script-size limit | `consensus-core` witness execution | `tidecoin_witness_v1_512_script_size_boundary_matches_node`, `tidecoin_script_assets`, generated script assets |
| Script number creation/operators | `consensus-core` interpreter and `primitives::script` | `tidecoin_scriptnum_creation_matrix_default_max_num_size`, `tidecoin_scriptnum_operator_matrix_default_max_num_size`, randomized runtime consistency |

## PQ Multisig Consensus And Policy

| Node surface | Rust owner | Proof artifact |
| --- | --- | --- |
| Single-scheme PQ multisig | `consensus-core` PQ verifier and interpreter | `consensus/tests/tidecoin_pq_multisig_parity.rs::tidecoin_pq_multisig_single_scheme_matrix_matches_node` |
| Mixed-scheme PQ multisig | same | `tidecoin_pq_multisig_mixed_scheme_direct_and_wrapped_match_node` |
| Negative and limit cases | same | `tidecoin_pq_multisig_negative_and_limit_cases_match_node` |
| `NULLDUMMY`, `NULLFAIL`, and strict Falcon behavior | same | `tidecoin_pq_multisig_nulldummy_nullfail_and_strict_match_node` |
| Policy-level PQ size/dust formulas | `tidecoin::policy` and transaction weight prediction | `pq_input_vsize_matches_node_formulas_all_schemes`, optional node-bridge size test, `tidecoin_transaction_policy` fuzz |

## Transaction And Block Sanity

| Node surface | Rust owner | Proof artifact |
| --- | --- | --- |
| Context-free `CheckTransaction` | `primitives::transaction::check_transaction_sanity` | zero input/output, duplicate input, coinbase scriptSig `1/2/100/101/106/107`, value range, output sum, stripped-size tests |
| Transaction decoder sanity gate | `primitives::transaction::TransactionDecoder` | decoder tests assert sanity-invalid canonical encodings are rejected |
| Context-free `CheckBlock` | `primitives::block::check_block_sanity` | merkle root, coinbase position/count, duplicate txids, stripped-size, sigop-cost, witness-root/commitment tests |
| Non-UTXO contextual block checks | `tidecoin::block_validation` | contextual header/block tests for previous hash, MTP, difficulty, finality, BIP34 coinbase height, witness commitment, PoW/AuxPoW |
| Subsidy schedule | `tidecoin::blockdata::subsidy` | mainnet/regtest transition and node-shaped total tests |
| PoW/AuxPoW target behavior | `tidecoin::pow` | yespower/scrypt vectors, AuxPoW context tests, testnet header windows, `tidecoin_pow` fuzz |

## Fuzz And Property Coverage

| Node fuzz surface | Rust fuzz/proof target | Status |
| --- | --- | --- |
| `script_interpreter.cpp` | `consensus_script_runtime`, `tidecoin_random_consistency`, script assets | active stateless coverage |
| `script_interpreter.cpp` verdicts, errors and resulting stacks | `consensus_node_differential` (original C++ comparison, ASan), `fuzz/tests/node_oracle.rs` | active differential coverage |
| `script_ops.cpp`, `scriptnum_ops.cpp` | scriptnum unit matrices and runtime consistency | active test/property coverage |
| `script.cpp` | `tidecoin_script_policy` | active fuzz coverage |
| `tx_out.cpp` | `tidecoin_tx_out_policy` | active fuzz coverage |
| `transaction.cpp` stateless pieces | `tidecoin_transaction_policy` | active fuzz coverage |
| `block.cpp` context-free pieces | `tidecoin_block_sanity` | active fuzz coverage |
| `pow.cpp` | `tidecoin_pow` | active fuzz coverage |
| `coins_view.cpp`, `coinscache_sim.cpp`, `utxo_total_supply.cpp` | future `tidecoin-chain-validation` crate | intentionally out of current scope |
| package/mempool fuzz targets | future mempool-policy crate | intentionally out of current scope |

## Provenance refresh

Compared with April node `fe36ef8dde80f730f02fd1e64c80432d06b1c436`,
`script_tests_pq.json` grows from 177 to 181 entries. The node updates v1
ALL/NONE/SINGLE and wrapped signatures for spent-output commitments, retains
old signatures as rejection cases, and changes preactivation/hash-type errors.
The current hash is pinned in `tidecoin_fixture_hashes.rs`; the node corpus and
Rust differential tests verify the changed expectations.

The regenerated monotonicity corpus is still 30 cases with identical canonical
hash. Both source transaction corpora are unchanged. The policy corpus is still
33 cases with unchanged constants and case hash. Six source-file hashes change:
policy header/implementation, descriptor implementation/tests, ephemeral dust
and TRUC functional tests. Reviewed changes include cluster/reorg behavior and
PQHD/wsh512 descriptor fixes; these hashes do not claim that the Rust stateless
cases cover those new stateful/descriptor features. PSBT/descriptor work remains
phase 5. Existing real-chain fixtures retain their historical provenance.

## Provenance Partitions

The active proof corpus is intentionally partitioned by source so generated,
synthetic, functional, and chain-derived data do not blur together:

| Source partition | Rust artifact | Role |
| --- | --- | --- |
| Node unit-test vectors | consensus PQ corpora, policy boundary tests, PQ size/dust tests | Proves Rust behavior against explicit node unit-test semantics. |
| Node functional-test semantics | policy matrices for datacarrier, witness standardness, TRUC, sigop limits | Captures relay-policy boundaries that the node also exercises through functional tests. |
| Generated node policy provenance corpus | `tidecoin/tests/data/node_policy_provenance_corpus.json` plus `tidecoin/tests/node_policy_provenance.rs` | Pins node descriptor/policy source-file hashes, node commit, constants, descriptor script-size invariants, and stateless boundary cases generated from node unit/fuzz/functional-test semantics. |
| Generated synthetic monotonicity cases | `tidecoin_script_assets_generated.rs` plus metadata JSON | Expands script-asset coverage while pinning source fixture hashes and node commit. |
| Real-chain fixtures | testnet AuxPoW, header, retarget-window fixtures | Proves header/PoW/contextual behavior on chain-derived data without claiming UTXO validation. |
| Randomized node-diff cases | `tidecoin_random_consistency` | Continuously compares generated interpreter cases against the checked-out node. |
| Fuzz targets | `fuzz/fuzz_targets/**` | Exercises stateless library-owned surfaces for crashes/invariant violations. |

Rule:

- If the checked-out Tidecoin node advances in a consensus-sensitive way, update
  the node-backed corpus metadata and refresh any active docs that pin the node
  commit.
- Regenerate the two pinned provenance artifacts with these commands. The export
  occurs before the metadata assertion: a stale-metadata failure during export
  is expected, but the full test must pass after regeneration:
  ```bash
  python3 tidecoin/contrib/generate_node_policy_provenance_corpus.py \
    --node-repo /path/to/tidecoin

  mkdir -p /tmp/tidecoin_script_assets
  TIDECOIN_NODE_REPO=/path/to/tidecoin \
  TIDECOIN_SCRIPT_ASSETS_WRITE_GENERATED_JSON=/tmp/tidecoin_script_assets/generated.json \
  cargo test -p consensus --test tidecoin_script_assets_generated \
    tidecoin_generated_script_assets_monotonicity -- --nocapture

  python3 consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py \
    --json /tmp/tidecoin_script_assets/generated.json \
    --tx-valid /path/to/tidecoin/src/test/data/tx_valid_pq.json \
    --tx-invalid /path/to/tidecoin/src/test/data/tx_invalid_pq.json \
    --node-repo /path/to/tidecoin \
    --output consensus/tests/data/tidecoin_script_assets_generated_metadata.json
  ```

## Feature And No-Std Matrix

| Check | Required status | Notes |
| --- | --- | --- |
| `cargo check --workspace --no-default-features` | must pass or have a documented non-library blocker | Workspace-level smoke for accidental default-feature leakage. |
| `cargo check -p consensus --no-default-features` | must pass | Byte-oriented consensus wrapper is no-std capable. |
| `cargo check -p tidecoin-consensus-core --no-default-features` | must pass | Interpreter, sighash, witness planning, and PQ verification stay below high-level `tidecoin`. |
| `cargo check -p tidecoin-consensus-encoding --no-default-features` | must pass | Canonical codec stays no-std capable. |
| `cargo check -p tidecoin-primitives --no-default-features` | must pass | Canonical transaction/block/script/witness semantics stay alloc/no-std capable. |
| `cargo check -p tidecoin-p2p-messages --no-default-features` | must pass | P2P wire message layer remains no-std plus alloc. |
| `cargo check -p tidecoin-p2p-messages --no-default-features --features serde` | must pass | P2P alloc-only serde surface stays independent of `std`. |
| `cargo check -p tidecoin-p2p-messages --features serde` | must pass | P2P default feature plus serde combination stays clean. |
| `cargo check -p tidecoin --no-default-features` | must pass | High-level facade must not expose OS-RNG or node harness requirements without features. |
| Node-backed tests | required CI sets `TIDECOIN_NODE_REPO` and `TIDECOIN_NODE_PARITY_REQUIRED=1`, plus the product feature | Node parity helpers must not become mandatory runtime dependencies. |

## Public API Scope

Current APIs should describe the validation surface they actually own:

- `consensus` is a byte-oriented script/spend verifier, not a chainstate
  validator.
- `check_transaction_sanity` mirrors context-free `CheckTransaction`, not
  `CheckTxInputs`.
- `check_block_sanity` mirrors context-free `CheckBlock`, not `ConnectBlock`.
- `contextual_check_block_header` and `contextual_check_block` cover non-UTXO
  header/block context only.
- `check_standard_relay_prechecks` is a stateless subset of the node mempool
  precheck path, not full `MemPoolAccept`.
- Full node acceptance wording is reserved for future stateful crates.

## Checkpoint Gate

Build the standalone original-node oracle and export
`TIDECOIN_NODE_VALIDATION_ORACLE` as shown in the follow-up record above.
The protocol-library parity checkpoint requires:

- `TIDECOIN_NODE_PARITY_REQUIRED=1 TIDECOIN_NODE_REPO=/home/yaroslav/dev/tidecoin/tidecoin cargo test --workspace --all-targets`
- `TIDECOIN_NODE_PARITY_REQUIRED=1 TIDECOIN_NODE_REPO=/home/yaroslav/dev/tidecoin/tidecoin cargo test -p tidecoin --lib --tests --features tidecoin-node-validation`
- the node checkout matches the migration target; required parity jobs do not
  silently skip, and phases 1–4 have recorded passing evidence
- no-std/feature checks from the feature matrix above
- `cargo test -p tidecoin-fuzz --all-targets`
- `cargo clippy --workspace --all-targets`
- short fuzz smoke runs for stateless current-boundary targets. On stable
  toolchains this uses `cargo fuzz run <target> --sanitizer none ...` because
  sanitizer-backed libFuzzer builds require nightly `-Zsanitizer`.
- generated node-provenance metadata matching the checked-out Tidecoin node
- active docs pointing to this protocol-library scope, not to full node
  acceptance parity
