# Supported versions

This repository is currently maintained as the Tidecoin Rust workspace.

## Node compatibility

The active `main` target is Tidecoin `v1.0.0rc4`
(`78aca4a6b656f43a1efe4b43cf884214219b6c09`), used by `tidecoin`
0.34.0-beta.2 and `tidecoin-node-parity` 0.2.1. The preceding
`tidecoin` 0.34.0-beta.1 release at `882df93` was validated against rc3.
The [migration plan](../ai-docs/RC4_MIGRATION_PLAN.md)
records original-source comparisons, check results and remaining limits.
Full-node acceptance and PSBT interoperability are not claimed.

### API migration

- Witness-v1 with a 64-byte program executes only natively after activation.
  The P2SH-wrapped form stays ordinary script; shorter v1 programs stay reserved.
- Relay flags include `VERIFY_FALCON_CANONICAL`; consensus flags do not. Use
  `spends_non_anchor_witness_program_with_flags` when selecting an explicit era.
- PQHD default descriptors now separate script families and main/test networks.
  Preserve existing descriptors: explicit supported old paths still derive the
  same keys; regenerating defaults is not a wallet migration.
- Legacy Falcon WIF exports carry the raw public key. Historical raw secret
  imports are accepted; inconsistent embedded key pairs are rejected.
- Header admission uses `is_oversized_auxpow_header` before duplicate shortcuts;
  it is separate from proof/context checks. `HeadersMessageSize` in the P2P crate
  tracks rc3 reply continuation by count and serialized size.

- Non-ANYONECANPAY witness-v1 signing/verification needs all spent `TxOut`s in
  input order. Supply `SpentOutputs` to the shared engine or the complete-context
  product API; current-output-only methods cannot establish those signatures.
- V1 sighash and precomputation now return errors for invalid caller context,
  missing data or SINGLE without a matching output. Handle these results;
  do not substitute a constant digest. Legacy/v0 verification retains its
  historical raw-hash-byte behavior.
- Callers resolve/authenticate outpoints and choose activation flags. Context
  count/current-output checks do not replace UTXO lookup. Rebuild context when
  input order or outpoints change.

Exact interfaces and migration details are in
[phase 2](../ai-docs/RC2_MIGRATION_PLAN.md#phase-2-transaction-context-and-signature-hashing).

## Active crates

The live crate graph is organized around these supported surfaces:

- `tidecoin`: high-level Tidecoin library and public ergonomics.
- `tidecoin-primitives`: canonical protocol, transaction, script, opcode, witness, and block types.
- `tidecoin-consensus-core`: reusable Tidecoin validation engine.
- `consensus`: standalone byte-oriented validation adapter over `tidecoin-consensus-core`.
- `tidecoin-consensus-encoding`: sans-I/O consensus codec primitives.
- `tidecoin-p2p-messages`: peer message layer built on lower shared crates.

## Maintenance policy

This branch maintains the Tidecoin crate line as the active API surface. Historical migration
artifacts may remain temporarily during migration, but they are not part of the intended
steady-state architecture and should be deleted once their Tidecoin-native replacement coverage is
accepted.

Dependency versions are tracked in the workspace manifests. Lockfiles are local generated build
artifacts for this library workspace; prefer committed `version` or pinned `git` dependencies for
reproducibility, and do not commit local developer overrides as external path dependencies.

Falcon verification, signing and key generation use the published
`tide-fn-dsa-{vrfy,sign,kgen}` 0.5.0 packages and their shared common crate.
Verification uses the explicit `TidecoinStrict` and `TidecoinLegacyFalcon512`
profiles; the Rust facade no longer normalizes historical signatures itself.
The legacy profile accepts historical negative zero/final bits while rejecting
norm equality at 43,533,782 and appended bytes, matching the pinned node.
Strict verification rejects padding and accepts valid signatures above the local
signing budgets. No local Falcon checkout or Git dependency is required.


PQ input estimates support `PqSignatureSize::LocalSigning` and `Maximum` through
`InputWeightPrediction`'s `_with_mode` helpers. Existing helpers retain maximum
mode. Choose local mode only when all corresponding signers enforce rc3's local
limits; this does not select consensus flags. For node-style fees, round the total
predicted weight to virtual bytes, then call `FeeRate::mul_by_vsize`. Dust now
rounds fees upward like rc3, and weight-based fee arithmetic preserves fractional
rates instead of truncating them before multiplication.

Rc4 changes wallet funding, explicit input-budget checks and GUI previews. The
library's complete-transaction weight predictions already account for count
widths, change and mixed witnesses; the rc4 plan records the new comparisons.
Wallet funding, parent-dependent construction limits and previews are not
implemented here. `TxInExt::segwit_weight` matches the node's input-budget
convention, including one empty witness-count byte for a legacy input; compare
budgets in WU before vsize rounding.
