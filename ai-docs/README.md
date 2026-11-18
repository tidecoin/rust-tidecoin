# AI Docs Master Plan

This is the active documentation entrypoint. The [compatibility principles](../AGENTS.md#compatibility-principles) govern the work; prose never overrides the pinned C++ implementation.

## Target and read order

Read [RC3_MIGRATION_PLAN.md](RC3_MIGRATION_PLAN.md) for the active target, source review, implementation sequence, evidence and outstanding checks. The authority is Tidecoin `v1.0.0rc3`, `ffed4e92e60ff2de30361648a71cba64531f9077`. `node-parity/NODE_REVISION` enforces that revision in required tests. Work remains on `v2`.

The rc2 [review](RC2_COMPATIBILITY_REVIEW.md) and [plan](RC2_MIGRATION_PLAN.md) are historical baseline records. Their old status, wrapped-v1 and Falcon encoding descriptions must not override rc3 source or executable comparisons. Older audits below retain their original revision and are inventories, not independent current compatibility claims.

The [ordered compatibility follow-up](RC3_MIGRATION_PLAN.md#ordered-compatibility-follow-up)
records the next five work areas, their source references and completion criteria.

## Scope and priorities

1. Review original implementations and callers; preserve node behavior.
2. Implement shared Rust behavior and source-derived differential boundaries.
3. Pass the original-node gate, feature checks and CI; record evidence.
4. Build future PSBT, wallet signing and stateful validation on this foundation.

Product validation uses the pure Rust shared engine. `node-parity` and `tidecoin-node-validation` are test infrastructure. This library has no complete PSBT implementation, UTXO-backed chain connect, mempool acceptance or peer scheduler. Passing library tests does not establish those absent capabilities. Mainnet AuxPoW remains disabled; testnet activation remains height 1000.

Keep consensus, relay policy, new signing and PSBT-finalization contracts separate. Caller-supplied outputs do not authenticate outpoints. Documentation records implementation and evidence; original node code resolves disagreements.

## Evidence and follow-up inventories

- [NODE_PARITY_PROOF_MATRIX.md](NODE_PARITY_PROOF_MATRIX.md): tested surfaces, original-source oracle boundaries and limits.
- [VALIDATION_FIX_BACKLOG.md](VALIDATION_FIX_BACKLOG.md), [NODE_CONSENSUS_SETTINGS_AUDIT.md](NODE_CONSENSUS_SETTINGS_AUDIT.md), [PROTOCOL_NODE_PARITY_READINESS.md](PROTOCOL_NODE_PARITY_READINESS.md): earlier audit inventories; apply the current rc3 plan before relying on old findings.
- [WALLET_API_ROADMAP.md](WALLET_API_ROADMAP.md): future wallet/API work.
- [API_STABILIZATION_SURFACE_AUDIT.md](API_STABILIZATION_SURFACE_AUDIT.md) and [CI_FEATURE_MATRIX_INTEGRATION.md](CI_FEATURE_MATRIX_INTEGRATION.md): maintenance.
- [CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md](CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md): future stateful validation boundary, not a protocol authority.

Provenance must identify the checked-out revision. Regenerate script metadata with `consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py` and policy provenance with `tidecoin/contrib/generate_node_policy_provenance_corpus.py` only after reviewing source changes and running differential tests. Updating hashes alone is not compatibility evidence. The rc2 plan retains full regeneration commands.

Everything in `archived/` is historical reference only.
