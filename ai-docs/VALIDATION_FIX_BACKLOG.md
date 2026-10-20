# Validation Fix Backlog

Status: active validation/parity backlog beneath
[README.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/README.md).

This file tracks remaining validation and parity work only. Wallet-facing API
work lives in
[WALLET_API_ROADMAP.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/WALLET_API_ROADMAP.md).

## Priority Rule

Do not reopen broad architecture cleanup by default.

The shared engine split is already in place:

- `consensus-core` owns the interpreter and shared typed verification facade
- `consensus` is the byte-oriented adapter
- `tidecoin` is the product-facing Rust API
- `node-parity` is dev/parity infrastructure

The local rc2 protocol-library checkpoint is validated; remaining work follows
the recorded scope and evidence. [RC2_MIGRATION_PLAN.md](RC2_MIGRATION_PLAN.md)
owns the implementation order and gates; the
[compatibility review](RC2_COMPATIBILITY_REVIEW.md) owns baseline evidence.

## Open

### 1. rc2 checkpoint follow-through

- Required node CI and current provenance are implemented; local workspace,
  product parity and feature gates are recorded in phase 4 of the migration plan.
  Hosted verification is in progress. Branch protection was inspected: `v2`
  is unprotected; naming a job required does not configure enforcement.
- The verifier uses pinned Git revision `522f179ae3fdbcf180854f17a41de520013e9ec6`.
  Registry publication is deferred and only blocks dependent crates.io releases.
- Preserve the documented oracle limits. Phase 5 PSBT/descriptor interoperability
  is the next implementation milestone, not an implied consequence of this gate.

Phase 2 completed R01/R02/R03/R10 locally: rc2 v1 hashing, SINGLE failure,
complete previous-output propagation and caller-context validation. Evidence
and API migration details live in the migration plan.

### 2. Chain-rule parity depth (follow-up)

Still needed:

- deeper AuxPoW malformed-parent and malformed-commitment vectors
- broader historical difficulty/retarget windows
- continued node-generated fixture provenance for PoW/header surfaces
- explicit rechecks when node rules or network constants change

Do not expand this into full chainstate or mempool validation. Those belong to
future stateful crates.

### 3. Shared node-parity proof-matrix reconciliation

Active Tidecoin parity now runs through:

- [`node-parity/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity)
- [`consensus/tests/tidecoin_node_parity.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs)
- [`tidecoin/src/consensus_validation_node.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)

Still needed:

- reconcile every archived Core-era proof class against a Tidecoin-native
  replacement in
  [CONSENSUS_TEST_COVERAGE_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md)
- keep `tidecoin` and `consensus` on the same shared node harness
- do not restore archived Core-diff tests unless they are rewritten as
  Tidecoin-node parity tests

### 4. `consensus/` historical cleanup (supporting)

The active `consensus` crate is already Tidecoin-native.

Remaining work is narrow:

- remove stale Bitcoin/Core-oriented docs and metadata when encountered
- keep archived proof files as historical reference only
- keep the standalone crate limited to byte-oriented validation responsibilities

This is maintenance, not the lead task.

### 5. `consensus-core` boundary maintenance (supporting)

This is no longer the main open architecture problem.

Still required:

- keep product validation on the shared pure-Rust engine
- keep the node bridge outside `consensus-core`
- avoid reintroducing duplicate validation/orchestration logic above the shared
  core
- avoid new `consensus -> tidecoin` layering mistakes

Do not treat aggressive export narrowing or semver-hardening as urgent while the
crate is still optimized for internal plumbing use.

## Current Replacement Standard

Validation changes should preserve these proof classes:

1. node-backed corpus parity
2. runtime differential behavior
3. targeted unit parity
4. randomized differential/property coverage
5. fixture provenance and reproducibility

Use
[NODE_PARITY_PROOF_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_PARITY_PROOF_MATRIX.md)
and
[CONSENSUS_TEST_COVERAGE_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md)
to decide whether a proof class is actually missing.

## Future-State Boundary

The following are explicitly out of scope for this file:

- UTXO-backed `ConnectBlock` parity
- `CheckTxInputs`
- BIP30/coinbase maturity/sequence-lock chainstate logic
- mempool/package policy
- RBF/conflicts/ephemeral dust package behavior

Those belong to
[CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md)
and future mempool-policy work.

## Recent Resolved Items

These are done and should not be reopened casually:

- shared typed verification facade moved into `consensus-core`
- product validation now always uses the pure-Rust shared engine
- `UnsupportedScript` removed from the live product validation path
- orphaned `node-parity/src/build_support.rs` removed
- regtest P2P magic ambiguity removed after the node-side split
