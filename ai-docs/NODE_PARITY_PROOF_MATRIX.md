# Node Parity Proof Matrix

Status: active checkpoint matrix.

This matrix maps Tidecoin node validation surfaces to the Rust proof artifacts
that exist today. The scope is protocol-library parity: stateless or
caller-context validation that can be owned by `rust-tidecoin` without a UTXO
database or mempool.

Full node acceptance parity is intentionally out of scope here. `ConnectBlock`,
`CheckTxInputs`, BIP30, coinbase maturity, UTXO-backed sequence locks, fee and
subsidy connect checks, `MemPoolAccept`, package topology, RBF/conflicts, and
ephemeral dust packages belong to future stateful crates.

## Policy Flags And Relay Prechecks

| Node surface | Rust owner | Proof artifact |
| --- | --- | --- |
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
| `script_ops.cpp`, `scriptnum_ops.cpp` | scriptnum unit matrices and runtime consistency | active test/property coverage |
| `script.cpp` | `tidecoin_script_policy` | active fuzz coverage |
| `tx_out.cpp` | `tidecoin_tx_out_policy` | active fuzz coverage |
| `transaction.cpp` stateless pieces | `tidecoin_transaction_policy` | active fuzz coverage |
| `block.cpp` context-free pieces | `tidecoin_block_sanity` | active fuzz coverage |
| `pow.cpp` | `tidecoin_pow` | active fuzz coverage |
| `coins_view.cpp`, `coinscache_sim.cpp`, `utxo_total_supply.cpp` | future `tidecoin-chain-validation` crate | intentionally out of current scope |
| package/mempool fuzz targets | future mempool-policy crate | intentionally out of current scope |

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
| Node-backed tests | gated by `TIDECOIN_NODE_REPO` and explicit features where applicable | Node parity helpers must not become mandatory runtime dependencies. |

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

The protocol-library parity checkpoint requires:

- `TIDECOIN_NODE_REPO=/home/yaroslav/dev/tidecoin/tidecoin cargo test --workspace --all-targets`
- no-std/feature checks from the feature matrix above
- `cargo test -p tidecoin-fuzz --all-targets`
- `cargo clippy --workspace --all-targets`
- short fuzz smoke runs for stateless current-boundary targets. On stable
  toolchains this uses `cargo fuzz run <target> --sanitizer none ...` because
  sanitizer-backed libFuzzer builds require nightly `-Zsanitizer`.
- generated node-provenance metadata matching the checked-out Tidecoin node
- active docs pointing to this protocol-library scope, not to full node
  acceptance parity
