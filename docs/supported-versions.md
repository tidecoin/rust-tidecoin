# Supported versions

This repository is currently maintained as the Tidecoin Rust workspace.

## Node compatibility

The local `v2` migration passes the protocol-library checkpoint against node
`v1.0.0rc2` (`7d653be5d24e73b49d101578afb33d8d7a889c1d`). This supersedes the
incompatible reviewed Rust baseline `9e9b74581b765ad53ad902e3c7c10ea78817d0a7`;
it is not a published Rust release. The [proof matrix](../ai-docs/NODE_PARITY_PROOF_MATRIX.md)
bounds the claim, and the [migration plan](../ai-docs/RC2_MIGRATION_PLAN.md)
records validation and remaining oracle limits. Hosted verification is in
progress for the pushed `v2` checkpoint. Full-node acceptance and PSBT interoperability are not claimed.

### API migration

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

The Falcon verifier is currently fetched from public Git revision
`522f179ae3fdbcf180854f17a41de520013e9ec6`, pinned in
`consensus-core/Cargo.toml`. No crates.io publishing credential or local checkout
is needed to build it. Publishing dependent crates to crates.io requires a
later registry release of the fixed verifier and a manifest update.
