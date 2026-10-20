# PSBT

PSBT is not exposed as a full live Rust API in this repository.

The planned API targets Tidecoin node `v1.0.0rc2`, commit
`7d653be5d24e73b49d101578afb33d8d7a889c1d`. It must compose existing Tidecoin
primitives and the corrected shared consensus engine.

Phase 5 of the [migration plan](../ai-docs/RC2_MIGRATION_PLAN.md) defines
format handling, previous-output integrity, signing consent, combining,
finalization, analysis, external-signing data requirements, PQHD origins and
native/wrapped witness-v1 support.

Phase 2 implemented spent-output-aware witness-v1 hashing and verification.
Use `SighashCache::new_with_spent_outputs` for non-ANYONECANPAY v1 signing;
complete-context verification is available through the product transaction API
and `verify_script_with_spent_outputs`. The [migration plan](../ai-docs/RC2_MIGRATION_PLAN.md#phase-2--transaction-context-and-signature-hashing)
records the API contract and differential evidence. Activation, hash-type and
policy reconciliation must still pass before the PSBT compatibility checkpoint.

Witness version 1 refers to Tidecoin's SHA-512 script/signature rules; it does
not mean a PSBT format version. Historical legacy/v0 verification, new signing,
relay admission and PSBT finalization must retain their distinct rules.
