# AI Docs Master Plan

This file is the active docs entrypoint for this repository.

The [repository compatibility principles](../AGENTS.md#compatibility-principles)
govern this work. This file controls planning precedence among active docs;
neither it nor other prose overrides the pinned C++ node's behavior.

## Agent Read Order

Read only what matches the task.

1. Read this file.
2. For rc2-sensitive work, read
   [RC2_COMPATIBILITY_REVIEW.md](RC2_COMPATIBILITY_REVIEW.md) and
   [RC2_MIGRATION_PLAN.md](RC2_MIGRATION_PLAN.md).
3. Then follow the relevant reference path:
   - Validation/parity work:
     - [VALIDATION_FIX_BACKLOG.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/VALIDATION_FIX_BACKLOG.md)
     - then one of:
       - [NODE_CONSENSUS_SETTINGS_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_CONSENSUS_SETTINGS_AUDIT.md)
       - [PROTOCOL_NODE_PARITY_READINESS.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/PROTOCOL_NODE_PARITY_READINESS.md)
       - [NODE_PARITY_PROOF_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_PARITY_PROOF_MATRIX.md)
       - [CONSENSUS_TEST_COVERAGE_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md) if the task is specifically about archived-proof reconciliation
   - Wallet/app ergonomics:
     - [WALLET_API_ROADMAP.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/WALLET_API_ROADMAP.md)
     - open [rust-tidecoin-vs-mobile-native-comparison.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/rust-tidecoin-vs-mobile-native-comparison.md) only if mobile compatibility matters
   - Public API cleanup:
     - [API_STABILIZATION_SURFACE_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/API_STABILIZATION_SURFACE_AUDIT.md)
     - [CI_FEATURE_MATRIX_INTEGRATION.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CI_FEATURE_MATRIX_INTEGRATION.md) if the task is specifically about CI coverage for feature combinations
   - Future stateful validation design:
     - [CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md)

Ignore `ai-docs/archived/` unless an active doc explicitly sends you there.

## Current State

- The local `v2` migration passes the bounded rc2 protocol-library checkpoint.
  The [proof matrix](NODE_PARITY_PROOF_MATRIX.md) names the tested surfaces;
  this is not a full-node or PSBT interoperability claim.
- The migration target is node commit
  `7d653be5d24e73b49d101578afb33d8d7a889c1d`. The pre-migration Rust baseline
  was `9e9b74581b765ad53ad902e3c7c10ea78817d0a7` on `v2`.
- It does not yet claim full node acceptance parity. UTXO-backed chain connect
  and mempool acceptance remain future crates.
- Public `tidecoin` validation now runs on the pure-Rust shared engine.
- `tidecoin-node-validation` and `node-parity` are dev/parity infrastructure,
  not the product validation path.
- The current work is the phased rc2 migration described below. A full Rust
  PSBT API is absent; wallet signing must build on the corrected consensus path.
- Phase 1 repaired the node oracle and established required-mode regression
  coverage. Phase 2 implemented complete spent-output propagation and rc2 v1
  hashing, with passing differential tests. Phase 3 rules pass with the corrected
  Falcon verifier pinned to a public Git commit, closing R14 for development.
  Phase 4 provenance and local checks pass; required CI is configured but its
  hosted execution is pending. A direct original-node contextual-header oracle
  now replaces the copied block/context/subsidy checks. The migration plan owns
  evidence and status.

Compatibility boundaries:

- Mainnet AuxPoW remains disabled; testnet activation remains height 1000.
- The node requires a coordinated testnet restart for the changed v1 messages.
  Existing fixtures must retain their original rule-era provenance.
- Consensus verification, relay policy, new signing, and PSBT finalization have
  different hash-type/data contracts. Do not collapse them into one flag set.

Node provenance rule:

- Active node-sensitive docs and generated parity/provenance artifacts must
  record the exact node commit they were checked against. Required rc2 parity
  uses the pinned migration target, not an unreviewed moving checkout.
- When node constants or consensus-sensitive behavior change, refresh the
  relevant parity/provenance docs alongside the code.

Provenance refresh commands (phase 4, after oracle and semantic repairs; changing
hashes alone does not resolve a compatibility failure):

- Generated node policy provenance corpus:
  ```bash
  python3 tidecoin/contrib/generate_node_policy_provenance_corpus.py \
    --node-repo /path/to/tidecoin
  cargo test -p tidecoin --test node_policy_provenance -- --nocapture
  ```
- Generated script-assets metadata:
  ```bash
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

  TIDECOIN_NODE_REPO=/path/to/tidecoin \
  cargo test -p consensus --test tidecoin_script_assets_generated -- --nocapture
  ```

## Priority Order

Use this priority order unless the user asks for a different slice.

0. Establish accurate documentation, reviewed evidence and phase gates.
1. Repair the node oracle and add durable rc2 regression coverage.
2. Implement validated spent-output context and rc2 witness-v1 hashing.
3. Reconcile activation, hash types, sigops and header rules.
4. Pass required parity CI, refresh provenance and document bounded compatibility.
5. Implement Tidecoin-native PSBT and wallet signing, then spend construction.

[RC2_MIGRATION_PLAN.md](RC2_MIGRATION_PLAN.md) owns phase status, dependencies
and acceptance gates. Keep documentation current with each implementation change.
Broader historical coverage and maintenance remain follow-up work.

Do not treat broad `consensus-core` export privatization as an immediate
priority. For the current internal-use posture, that is maintenance, not a
blocker.

## Active Docs

- [RC2_COMPATIBILITY_REVIEW.md](RC2_COMPATIBILITY_REVIEW.md)
  - Reviewed baseline, findings R01–R13 and recorded test results.
- [RC2_MIGRATION_PLAN.md](RC2_MIGRATION_PLAN.md)
  - Current implementation sequence and completion gates.
- [VALIDATION_FIX_BACKLOG.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/VALIDATION_FIX_BACKLOG.md)
  - Current validation/parity backlog.
- [NODE_CONSENSUS_SETTINGS_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_CONSENSUS_SETTINGS_AUDIT.md)
  - Node-vs-Rust settings and ownership reference.
- [PROTOCOL_NODE_PARITY_READINESS.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/PROTOCOL_NODE_PARITY_READINESS.md)
  - Scope and readiness gates; rc2 parity is currently unproven and blocked.
- [NODE_PARITY_PROOF_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_PARITY_PROOF_MATRIX.md)
  - Earlier proof inventory plus rc2 revalidation requirements.
- [CONSENSUS_TEST_COVERAGE_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md)
  - Archived-proof-class replacement matrix.
- [WALLET_API_ROADMAP.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/WALLET_API_ROADMAP.md)
  - Current wallet/API work plan.
- [API_STABILIZATION_SURFACE_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/API_STABILIZATION_SURFACE_AUDIT.md)
  - Current public-surface decisions and remaining rough edges.
- [CI_FEATURE_MATRIX_INTEGRATION.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CI_FEATURE_MATRIX_INTEGRATION.md)
  - Follow-up plan for adding CI feature-matrix coverage.
- [CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md)
  - Future stateful validation boundary.

## Archive Rule

Everything under [ai-docs/archived/](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived)
is historical reference only.
