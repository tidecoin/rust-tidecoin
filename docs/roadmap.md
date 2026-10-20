# Tidecoin repository roadmap

The rc2 protocol-library checkpoint is validated locally; hosted CI remains
to be verified after publication of these changes. The next implementation
milestone is Tidecoin-native PSBT and wallet interoperability. See the
[migration evidence](../ai-docs/RC2_MIGRATION_PLAN.md).

The [migration plan](../ai-docs/RC2_MIGRATION_PLAN.md) defines this sequence:
documentation and contracts, node oracle/regressions, spent-output context and
v1 hashing, remaining consensus/policy boundaries, required CI and provenance,
then PSBT and wallet signing.

Current high-value architectural goals:

- keep canonical Tidecoin protocol/script/opcode ownership in `primitives`
- keep `consensus-core` as the single reusable validation engine
- keep `consensus` as the thin byte-oriented standalone adapter
- keep `tidecoin` as the public product wrapper over lower shared crates
- rebase crates like `p2p` onto lower shared crates instead of the top-level `tidecoin` crate
- archive or delete remaining historical Core-era material once it no longer carries engineering value

## RC cycle

The node's `v1.0.0rc2` version identifies the compatibility target, not the Rust
crate version. Rust release readiness requires the migration's recorded gates
and explicit API migration documentation. Full chainstate and mempool acceptance
remain outside the protocol-library claim.
