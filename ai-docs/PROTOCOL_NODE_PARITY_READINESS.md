# Protocol Node Parity Readiness

Status: active protocol scope document.

This document is subordinate to
[README.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/README.md).

This document defines what "node parity" means for the current `rust-tidecoin`
protocol crates before a full UTXO chain-connect or mempool-validation crate
exists.

The detailed proof inventory is maintained in
[NODE_PARITY_PROOF_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_PARITY_PROOF_MATRIX.md).

## Current Claim

The current crates may claim **protocol-library parity** with the Tidecoin node
for the surfaces they own:

- consensus script execution for explicit flags
- Tidecoin PQ, witness-v1-512, and `OP_SHA512` interpreter behavior
- context-free transaction sanity
- context-free block sanity
- non-UTXO contextual block/header checks
- PoW/AuxPoW target and mining-hash behavior
- subsidy schedule
- stateless relay-policy prechecks
- standard script/output/witness policy helpers

They must not claim full node acceptance parity yet. Full node acceptance still
requires UTXO and mempool state.

## Policy Matrix

| Node surface | Rust owner | Proof status | Notes |
| --- | --- | --- | --- |
| `IsStandardTx` | `tidecoin::policy::is_standard_tx` | implemented, unit covered | Covers version range, standard output forms, data-carrier budget, bare multisig policy, tx weight, scriptSig size/push-only, dust-output count. |
| `AreInputsStandard` | `tidecoin::policy::are_inputs_standard` | implemented, unit covered | Requires caller-supplied spent outputs. Missing prevouts are rejected by this helper because it cannot silently assume UTXO state. |
| `IsWitnessStandard` | `tidecoin::policy::is_witness_standard` | implemented, boundary covered | Covers native and P2SH-wrapped P2WSH/P2WSH-512 stack count, item-size, and witnessScript-size limits. |
| `GetDustThreshold` / `IsDust` | `ScriptPubKeyExt::minimal_non_dust*`, `TxOutExt::minimal_non_dust*` | implemented, fuzz covered | Dust threshold ownership stays in policy/script helpers. `tidecoin_tx_out_policy` fuzz now exercises TxOut threshold paths directly. |
| `SpendsNonAnchorWitnessProg` | `tidecoin::policy::spends_non_anchor_witness_program` | implemented, unit covered | Mirrors the node's witness-v0-only classifier. It is P2P/mempool diagnostic policy, not consensus and not Taproot validation. |
| Pre-AuxPoW witness-v1 relay policy | `check_standard_relay_prechecks` | implemented, unit covered | Rejects witness-v1 outputs before `auxpow_start_height`, matching node stateless policy. |
| Standard script flags | `standard_policy_script_flags` | implemented, unit covered | Starts from node `STANDARD_SCRIPT_VERIFY_FLAGS`, then adds `PQ_STRICT`, `WITNESS_V1_512`, and `SHA512` at AuxPoW activation. |
| Stateless TRUC vsize | `check_standard_relay_prechecks` | implemented, unit and fuzz covered | Enforces version-3 sigop-adjusted vsize <= 10,000. |
| Generated node policy provenance corpus | `tidecoin/tests/node_policy_provenance.rs` | implemented | Pins node descriptor/policy constants, source hashes, PQ descriptor script-size invariants, and stateless boundary cases generated from node source, unit tests, fuzz invariants, and functional tests. |
| TRUC ancestor/descendant topology | future mempool-policy crate | not in current scope | Requires unconfirmed ancestor graph and package/mempool state. |
| Ephemeral dust package policy | future mempool-policy crate | not in current scope | Requires package fee and parent/child spend state. |
| Fee admission, conflicts, RBF, package limits | future mempool-policy crate | not in current scope | Must not be hidden behind stateless policy names. |

## Interpreter Boundary Matrix

| Node behavior | Rust proof | Status |
| --- | --- | --- |
| `OP_SHA512` acts as an upgradeable NOP until `SCRIPT_VERIFY_SHA512` is set. | `consensus/tests/tidecoin_unit_parity.rs::tidecoin_sha512_opcode_flag_boundary_matches_node` | implemented |
| `OP_SHA512` fails under `DISCOURAGE_UPGRADABLE_NOPS` when not enabled. | same test | implemented |
| `OP_CODESEPARATOR` in base scripts fails under `CONST_SCRIPTCODE`, including unexecuted branches. | `tidecoin_const_scriptcode_and_script_size_boundaries_match_node` | implemented |
| Script size limit is exactly 65,536 bytes; 65,537 fails. | `tidecoin_const_scriptcode_and_script_size_boundaries_match_node` and witness-v1-512 boundary tests | implemented |
| Push element limit is exactly 8,192 bytes; 8,193 fails. | `tidecoin_push_size_boundary_matches_node` | implemented |
| Witness-v0 `MINIMALIF` policy rejects non-minimal true values. | `consensus/tests/tidecoin_witness_unit_parity.rs::tidecoin_witness_minimalif_boundary_matches_node` | implemented |
| Witness-v1-512 dispatch, hashing, and script-size limits. | `tidecoin_witness_v1_512_script_size_boundary_matches_node`, `tidecoin_pq_multisig_parity`, Tidecoin script assets | implemented |
| PQ strict mode rejects legacy Falcon-512 where node rejects it. | `tidecoin_pq_multisig_parity`, node corpora | implemented |

The interpreter remains flag-driven. It must not learn about network params,
deployment state, minimum-chain-work, or assume-valid. Chain-context code derives
flags and passes them to `consensus-core`.

## Fuzz Surface Reconciliation

| Node fuzz target | Rust target | Status |
| --- | --- | --- |
| `script_interpreter.cpp`, stateless execution paths | `consensus_script_runtime`, consensus parity tests, `tidecoin_random_consistency` | implemented |
| `transaction.cpp`, stateless transaction pieces | `tidecoin_transaction_policy` | implemented |
| `primitives_transaction.cpp`, transaction codec/arbitrary shape | `tidecoin_arbitrary_transaction`, `tidecoin_deserialize_transaction` | implemented |
| `script.cpp`, script policy/classification pieces | `tidecoin_script_policy` | implemented |
| `script_interpreter.cpp`, script corpora/randomized runtime | consensus tests and `tidecoin_random_consistency` | implemented as tests plus continuous fuzz |
| `script_ops.cpp`, `scriptnum_ops.cpp` | `tidecoin_unit_parity`, `tidecoin_random_consistency` | implemented as tests/randomized parity |
| `tx_out.cpp` | `tidecoin_tx_out_policy` | implemented |
| `block.cpp`, context-free block pieces | `tidecoin_block_sanity` | implemented |
| `pow.cpp` | `tidecoin_pow` | implemented |
| `coins_view.cpp`, `coinscache_sim.cpp` | future chain-validation crate | out of current scope |
| `package_eval.cpp`, `tx_pool.cpp`, mempool/package targets | future mempool-policy crate | out of current scope |
| `utxo_total_supply.cpp` | future chain-validation crate | out of current scope |

The current fuzz claim is therefore "library-owned node fuzz surfaces are
represented." It is not "the Rust library fuzzes full node acceptance."

## Readiness Checklist

Current protocol crates can be treated as ready for a checkpoint when:

- `cargo test --workspace --all-targets` passes
- `cargo clippy --workspace --all-targets` passes
- node-backed tests pass with `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin`
- `cargo test -p tidecoin-fuzz --all-targets` passes
- active docs point to this scope document instead of implying full node
  `ConnectBlock` or mempool acceptance parity

Remaining work after that checkpoint belongs to new stateful crates:

- `tidecoin-chain-validation`: `ConnectBlock`, `CheckTxInputs`, BIP30, coinbase
  maturity, sequence locks, fees, block reward claim, chain-derived script flags
- `tidecoin-mempool-policy`: full `MemPoolAccept`, package policy, TRUC topology,
  ephemeral dust packages, fee admission, conflicts, RBF
