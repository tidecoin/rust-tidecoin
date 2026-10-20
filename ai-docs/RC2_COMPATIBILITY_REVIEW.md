# Tidecoin rc2 compatibility review

Status: reviewed baseline, 2026-10-20. See migration plan for current resolution status.

This assessment records the differences between Rust `v2` and the local Tidecoin
node's `v1.0.0rc2` tag. That reviewed Rust baseline could not claim parity with
that release. The implementation sequence and completion gates are maintained
in [RC2_MIGRATION_PLAN.md](RC2_MIGRATION_PLAN.md), under the authority of
[README.md](README.md).

Phase 2 resolved R01/R02/R03/R10 locally. Phase 3 implements R04–R08 with
source-derived and differential tests and resolves R14 through a pinned public
Git dependency on the corrected verifier. The migration plan owns resolution
status; the findings below preserve review evidence.

## Reviewed versions

| Reference | Commit | Date |
| --- | --- | --- |
| Rust `v2` | `9e9b74581b765ad53ad902e3c7c10ea78817d0a7` | 2026-04-30 |
| Previous node provenance baseline | `fe36ef8dde80f730f02fd1e64c80432d06b1c436` | 2026-04-21 |
| Node `v1.0.0rc2`, matching the reviewed local checkout | `7d653be5d24e73b49d101578afb33d8d7a889c1d` | 2026-10-20 |

The source comparison used the node checkout at
`/home/yaroslav/dev/tidecoin/tidecoin`. Node paths below are relative to that
checkout. This is a source and differential-test assessment, not a historical
chain replay or full node acceptance certification.

## Findings at the reviewed Rust commit

P1 findings block the rc2 protocol compatibility checkpoint. P2 findings concern
supporting API, test, or wallet capabilities; their phase gates still apply.
The table preserves the initial assessment. Phase 1 has since repaired the R09
signature/PoW oracle and R11 comparison/skip handling; see the
[implementation evidence and remaining oracle limits](RC2_MIGRATION_PLAN.md#phase-1-implementation-evidence-2026-10-20).
The phase-2/3 implementation evidence is in the migration plan. Phase 4 has
refreshed provenance and configured required CI; its hosted run remains pending.

| ID | Priority | Finding and evidence | Rust owner | Node reference |
| --- | --- | --- | --- | --- |
| R01 | P1 | Non-ANYONECANPAY witness-v1 hashes omit SHA-512 commitments to all spent amounts and locking scripts. The rc2 reference vector produces a different digest. | [sighash.rs](../consensus-core/src/sighash.rs), `p2wsh512_signature_hash` | `src/script/interpreter.cpp`, `SignatureHash512`; `src/test/sighash_tests.cpp`, `witness_v1_spent_output_commitments` |
| R02 | P1 | Witness-v1 SINGLE without a corresponding output returns `UINT512_ONE`. A signed SINGLE+ANYONECANPAY reproduction passes Rust and fails rc2. | [sighash.rs](../consensus-core/src/sighash.rs) | `src/script/interpreter.cpp`, `SignatureHash512` |
| R03 | P1 | Product transaction verification collects previous outputs but passes `None` to the engine. Existing precomputation has SHA-256 spent-output fields that do not supply the required v1 message. | [consensus_validation.rs](../tidecoin/src/consensus_validation.rs), [consensus_validation_tidecoin.rs](../tidecoin/src/consensus_validation_tidecoin.rs), [tx.rs](../consensus-core/src/tx.rs) | `src/script/interpreter.h`, `PrecomputedTransactionData` |
| R04 | P1 | Before activation, Rust accepts additional PQ schemes that rc2 rejects. Existing Falcon-1024/mixed-scheme tests and a focused ML-DSA case disagree with the node. | [interpreter.rs](../consensus-core/src/interpreter.rs), `verify_pq_signature_against_code` | `src/script/interpreter.cpp`, `CheckPostQuantumSignature` |
| R05 | P1 | Before activation, Rust treats 64-byte v1 programs as upgradeable witness programs rather than ordinary script. Reproductions disagree in both acceptance directions. V1 sigop accounting also lacks rule flags. | [witness.rs](../consensus-core/src/witness.rs), [interpreter.rs](../consensus-core/src/interpreter.rs), [transaction.rs](../tidecoin/src/blockdata/transaction.rs) | `src/script/interpreter.cpp`, `IsWitnessProgramForFlags`, `CountWitnessSigOps` |
| R06 | P1 | Active v1 lacks the six-defined-hash-byte check. An invalid-key CHECKSIG NOT case passes Rust but fails rc2 with SIG_HASHTYPE. Rust also rejects the new bit-16 relay flag as unknown. | [flags.rs](../consensus-core/src/flags.rs), [interpreter.rs](../consensus-core/src/interpreter.rs), [policy.rs](../tidecoin/src/policy.rs) | `src/script/interpreter.cpp`, `CheckSignatureHashType`; `src/validation.cpp`, `PolicyScriptChecks` |
| R07 | P1 | Witness-v0 consensus hashing normalizes the raw signature hash byte. An independently constructed signature ending in 0x41 passes rc2 consensus verification but fails Rust. This is an existing defect, not a change to v0 consensus in rc2. | [interpreter.rs](../consensus-core/src/interpreter.rs), `segwit_v0_signature_hash`; [sighash.rs](../consensus-core/src/sighash.rs) | `src/script/interpreter.cpp`, `SignatureHash`, `CheckPostQuantumSignature` |
| R08 | P1 | Ordinary preactivation headers with chain-ID bits are rejected by Rust. The full signed-version preactivation minimum is absent from contextual checks. Delayed/disabled regtest activation incorrectly selects Yespower for genesis. Chain-ID rejection and genesis selection were reproduced; the minimum-version gap was established by source comparison. | [pow.rs](../tidecoin/src/pow.rs), [block_validation.rs](../tidecoin/src/block_validation.rs), [params.rs](../tidecoin/src/network/params.rs) | `src/validation.cpp`, `ContextualCheckBlockHeader`; `src/pow.cpp`, `UseScryptPoW` |
| R09 | P1 | The C++ signature bridge supplies no spent outputs, so it cannot validate ordinary rc2 v1 signatures. Copied header validation retains obsolete rules. Passing comparisons against that copy are insufficient evidence. | [tidecoin_validation_bridge.cpp](../node-parity/c_src/tidecoin_validation_bridge.cpp), [harness.rs](../node-parity/src/harness.rs) | Node interpreter and validation functions above |
| R10 | P2 | Incomplete typed `SpentOutputs` can panic during precomputation rather than returning a validation error. Reproduced with an empty set and a transaction containing witness data. | [tx.rs](../consensus-core/src/tx.rs), `PrecomputedTransactionData::new` | Validate the caller-context contract before indexing |
| R11 | P2 | Generated monotonicity comparisons vary activation flags; node comparisons must hold PQ_STRICT, WITNESS_V1_512 and SHA512 fixed. Optional harness initialization can silently remove node comparison. | [tidecoin_script_assets_generated.rs](../consensus/tests/tidecoin_script_assets_generated.rs), [tidecoin_test_support.rs](../consensus/tests/tidecoin_test_support.rs) | `src/script/interpreter.h`; `src/test/script_tests.cpp`, `script_flag_comparisons_preserve_activation` |
| R12 | P2 | Main CI is configured around master and does not provision a node parity checkout. Provenance and active parity claims still refer to April. | [rust.yml](../.github/workflows/rust.yml), [NODE_PARITY_PROOF_MATRIX.md](NODE_PARITY_PROOF_MATRIX.md) | Pinned rc2 reference above |
| R13 | P2 | There is no full Rust PSBT API. The narrow PQHD descriptor parser lacks sh(wsh512(...)), which rc2 supports. | [psbt.md](../docs/psbt.md), [key_expression.rs](../tidecoin/src/key_expression.rs) | `doc/psbt.md`; `src/psbt.h`, `src/psbt.cpp`; `src/script/descriptor.cpp` |

Witness v1 must use strict signature verification even when its flag is tested
independently of PQ_STRICT; scheme eligibility remains a separate rule. Include
that independent-flag case when repairing R04/R06.

## Additional finding during phase 3

**R14 (P1): Falcon backend and profile selection differ from the node.**
Published `tide-fn-dsa-vrfy` 0.4.0 applies the legacy signer's 688-byte output
limit during verification and ignores the compressed decoder's consumed length.
The original node's legacy verifier requires exact consumption and uses its
legacy norm bound without that signer-size limit. The node's strict PQClean
verifier accepts extra zero padding only at 666 bytes (Falcon-512) or 1280 bytes
(Falcon-1024). Rust's preactivation script path also incorrectly tried the union
of strict and legacy acceptance instead of selecting the legacy profile.

The durable [rc2 rule tests](../consensus/tests/tidecoin_rc2_rules.rs) reproduce
both acceptance directions using synthetic 32/64-byte-message vectors: a
745-byte legacy-only signature passes the node and fails published Rust;
a short strict-valid signature with one appended zero passes published Rust
and fails the node. Fixed-length padding, excess norm and truncation provide
controls. References: node `src/pq/falcon512.c`,
`tidecoin_falcon512_verify_legacy`; `src/pq/falcon-{512,1024}/pqclean.c`,
`do_verify`; and `src/script/interpreter.cpp`, `CheckPostQuantumSignature`.
Git history traces both verifier defects to the fork's `cd909421` addition of
Falcon compatibility functions (2026-04-07). The original FN-DSA verifier enforced
a fixed signature length before decoding; the fork's variable-length Falcon
path omitted the corresponding profile-specific consumption checks. The legacy
signer-size restriction was also introduced in that fork addition. These findings
do not establish a defect in the original FN-DSA verification arithmetic.

This is a Rust compatibility defect, not a node-defect pause. The tested fix,
release commit and dependency adoption gate are recorded in the migration plan.

## Rule distinctions to preserve

- Legacy/v0 consensus verification retains historical raw hash-byte behavior.
  New signing and relay restrictions must not invalidate historical finals.
- Active v1 signature opcodes enforce the six defined bytes for every nonempty
  signature argument, including multisig arguments not reached by matching.
  Empty signatures retain their existing behavior.
- Non-ANYONECANPAY v1 commits to all spent amounts and scripts. ANYONECANPAY
  retains current-input commitments. NONE/SINGLE do not approve a fixed total fee.
- Mainnet AuxPoW remains disabled; testnet activation remains height 1000.
  Regtest supports delayed/disabled activation while preserving scrypt genesis.
- The node describes a coordinated testnet restart for the v1 message changes.
  Old testnet fixtures must retain their original rule-era provenance.
- AuxPoW proof failures may be replaceable without changing the block header.
  Future stateful validation must not permanently invalidate the header merely
  because one proof failed.

## Foundation retained

Keep canonical protocol types in `primitives`, script and sighash ownership in
`consensus-core`, the byte adapter in `consensus`, and product APIs in `tidecoin`.
`node-parity` remains development infrastructure.

The reviewed tests passed PQ key generation, cross-verification and PQHD
derivation cases. Many script, transaction, policy and header tests also passed.
Those results support retaining the architecture and cryptographic primitives;
they do not establish rc2 consensus parity.

Full chain connection, UTXO state, cluster mempool admission, reorg-driven
mempool revalidation and node database migration remain outside this migration.
Flag derivation and stateless policy helpers already owned by Rust are in scope.

## Recorded validation

These results describe the reviewed Rust commit, not completion of the plan.
Tests ran with `TIDECOIN_NODE_REPO=/home/yaroslav/dev/tidecoin/tidecoin` where
node comparison was required.

| Command or check | Recorded result |
| --- | --- |
| `cargo test -p tidecoin-consensus-core --lib --offline` | 32 passed |
| `cargo test -p consensus --tests --offline --no-fail-fast -- --nocapture` | 98 passed, 7 failed across 5 targets |
| `cargo test -p tidecoin --lib --tests --features tidecoin-node-validation --no-fail-fast` | 337 passed, 7 failed across 2 targets |
| `cargo check -p tidecoin-consensus-core -p consensus --no-default-features --offline` | Passed |
| Isolated review probes | 12 passed by asserting the reported defects and control cases |

Failing consensus targets:

- `tidecoin_fixture_hashes`: changed node fixture hashes.
- `tidecoin_node_parity`: script corpus mismatch.
- `tidecoin_pq_multisig_parity`: single/mixed scheme acceptance mismatch.
- `tidecoin_runtime_diff`: interpreter result mismatch.
- `tidecoin_script_assets_generated`: stale source-commit metadata.

The product crate had six library failures in script corpus, v1 preactivation,
and PQ single/mixed-scheme cases, plus one policy-provenance integration failure.

The original temporary probes and logs were written under
`/tmp/rust-tidecoin-rc2-review` and `/tmp/rust-tidecoin-rc2-*.log`.
Phase 1 promoted the signature, activation, hash-byte and genesis controls into
[node-oracle regressions](../consensus/tests/tidecoin_rc2_oracle.rs), with enabled
[pending Rust regressions](../consensus/tests/tidecoin_rc2_pending.rs) and the
remaining source-case references recorded in the migration plan. The temporary
probes are no longer the only evidence for those findings.
