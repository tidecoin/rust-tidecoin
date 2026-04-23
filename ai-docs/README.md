# AI Docs Master Plan

This file is the active docs entrypoint for this repository.

If an active doc disagrees with this file, this file wins.

## Agent Read Order

Read only what matches the task.

1. Read this file.
2. Then follow exactly one path:
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
     - [FEATURE_GATING_API_REDESIGN.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/FEATURE_GATING_API_REDESIGN.md) if the task is specifically about `pow` / `p2p` feature boundaries
     - [CI_FEATURE_MATRIX_INTEGRATION.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CI_FEATURE_MATRIX_INTEGRATION.md) if the task is specifically about CI coverage for feature combinations
   - Future stateful validation design:
     - [CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md)

Ignore `ai-docs/archived/` unless an active doc explicitly sends you there.

## Current State

- `rust-tidecoin` already has protocol-library parity for the surfaces it owns.
- It does not yet claim full node acceptance parity. UTXO-backed chain connect
  and mempool acceptance remain future crates.
- Public `tidecoin` validation now runs on the pure-Rust shared engine.
- `tidecoin-node-validation` and `node-parity` are dev/parity infrastructure,
  not the product validation path.
- The main remaining work is:
  - validation/parity coverage tails
  - wallet-facing spend construction
  - a small amount of public-surface cleanup

Recent protocol note:

- Regtest P2P magic is now distinct from testnet in the node and should be
  treated as exact, not collapsed.

Node provenance rule:

- Active node-sensitive docs and generated parity/provenance artifacts should
  either record the current Tidecoin node commit they were checked against or
  explicitly say they track the current local `TIDECOIN_NODE_REPO` checkout.
- When node constants or consensus-sensitive behavior change, refresh the
  relevant parity/provenance docs alongside the code.

Provenance refresh commands:

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

1. Validation/parity coverage tails:
   - deeper AuxPoW malformed-parent and malformed-commitment vectors
   - broader historical difficulty/retarget coverage
   - explicit proof-matrix reconciliation before deleting archived proof data
2. Wallet-facing spend construction:
   - build on existing addresses, scripts, weight, fee, PQ, and validation
     primitives
   - do not build a second consensus engine
3. Small maintenance cleanup:
   - hidden public network-conversion traits in address/WIF constructors
   - stale docs or metadata
   - historical cleanup in `consensus/` and parity docs

Do not treat broad `consensus-core` export privatization as an immediate
priority. For the current internal-use posture, that is maintenance, not a
blocker.

## Active Docs

- [VALIDATION_FIX_BACKLOG.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/VALIDATION_FIX_BACKLOG.md)
  - Current validation/parity backlog.
- [NODE_CONSENSUS_SETTINGS_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_CONSENSUS_SETTINGS_AUDIT.md)
  - Node-vs-Rust settings and ownership reference.
- [PROTOCOL_NODE_PARITY_READINESS.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/PROTOCOL_NODE_PARITY_READINESS.md)
  - What parity can be claimed now.
- [NODE_PARITY_PROOF_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_PARITY_PROOF_MATRIX.md)
  - Proof artifacts by node surface.
- [CONSENSUS_TEST_COVERAGE_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md)
  - Archived-proof-class replacement matrix.
- [WALLET_API_ROADMAP.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/WALLET_API_ROADMAP.md)
  - Current wallet/API work plan.
- [API_STABILIZATION_SURFACE_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/API_STABILIZATION_SURFACE_AUDIT.md)
  - Current public-surface decisions and remaining rough edges.
- [FEATURE_GATING_API_REDESIGN.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/FEATURE_GATING_API_REDESIGN.md)
  - Active design note for `pow` / `p2p` capability-boundary cleanup.
- [CI_FEATURE_MATRIX_INTEGRATION.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CI_FEATURE_MATRIX_INTEGRATION.md)
  - Follow-up plan for adding CI feature-matrix coverage.
- [CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md)
  - Future stateful validation boundary.

## Archive Rule

Everything under [ai-docs/archived/](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived)
is historical reference only.
