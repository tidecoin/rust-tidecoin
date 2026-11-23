# Tidecoin repository roadmap

The active compatibility target is Tidecoin node `v1.0.0rc4`,
`78aca4a6b656f43a1efe4b43cf884214219b6c09`. The
[rc4 migration plan](../ai-docs/RC4_MIGRATION_PLAN.md) owns current evidence
and status.

The next work is the [ordered compatibility follow-up](../ai-docs/RC3_MIGRATION_PLAN.md#ordered-compatibility-follow-up).
It covers sighash mutation testing, expanded signed transactions, complex valid
scripts, combined block rules and decoding across public APIs. The plan records
scope and completion criteria for each step.

Future wallet and PSBT work is described in the
[wallet roadmap](../ai-docs/WALLET_API_ROADMAP.md). Stateful block connection is
described in the [chain-connect design](../ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md).

Current high-value architectural goals:

- keep canonical Tidecoin protocol/script/opcode ownership in `primitives`
- keep `consensus-core` as the single reusable validation engine
- keep `consensus` as the thin byte-oriented standalone adapter
- keep `tidecoin` as the public product wrapper over lower shared crates
- rebase crates like `p2p` onto lower shared crates instead of the top-level `tidecoin` crate
- archive or delete remaining historical Core-era material once it no longer carries engineering value

## RC cycle

The pinned node revision identifies the compatibility target. Rust release
readiness follows the migration's recorded validation and explicit API migration
documentation. Full chainstate and mempool acceptance require the future
stateful implementation and its own original-node comparisons.
