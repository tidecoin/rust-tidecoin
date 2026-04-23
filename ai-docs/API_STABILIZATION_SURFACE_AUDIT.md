# API Stabilization Surface Audit

Status: active supporting reference, not a first-line work driver.

Use this file only when the task is specifically about public API cleanup.

## Current Decisions

- The top-level `tidecoin` validation API is now pure Rust by default.
- `tidecoin-node-validation` is dev/parity-only and must stay out of normal
  product builds.
- The live product validation path no longer uses the old `UnsupportedScript`
  contract.
- `tidecoin::p2p::{Magic, NetworkExt}` is public, but `Network` or `Params`
  remain the primary high-level network identity in application code.

## Current Remaining Rough Edges

### Feature-gated capability cleanup

The `p2p` / `pow` capability-boundary cleanup is implemented in the library
surface.

Historical implementation detail lives in
[archived/FEATURE_GATING_API_REDESIGN.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived/FEATURE_GATING_API_REDESIGN.md).

The remaining active follow-up is CI matrix enforcement in
[CI_FEATURE_MATRIX_INTEGRATION.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CI_FEATURE_MATRIX_INTEGRATION.md).

### Hidden public network-conversion traits

These are the main active public-surface rough edge:

- [`tidecoin/src/crypto/key.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/crypto/key.rs)
- [`tidecoin/src/address/mod.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/address/mod.rs)

The constructors still leak hidden conversion traits through public signatures.
That should eventually be replaced with explicit exact-network parameters or
clear helper constructors.

### `NetworkKind` is intentionally coarse

[`network::NetworkKind`](/home/yaroslav/dev/tidecoin/rust-tidecoin/network/src/lib.rs)
means `Main` vs `Test`, not exact chain identity.

It is acceptable for legacy address/WIF-family classification, but it should not
be used for exact P2P constants like magic bytes or ports.

### `consensus-core` still exports low-level internals

This is acceptable for the current internal-use posture.

It is not the main current cleanup task unless the project decides to tighten
the crate as a third-party semver-facing public dependency.

## Current Priority

If API cleanup work is chosen, do it in this order:

1. finish the `pow` / `p2p` feature-gating cleanup in
   [CI_FEATURE_MATRIX_INTEGRATION.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CI_FEATURE_MATRIX_INTEGRATION.md)
2. remove hidden network-conversion traits from public constructor signatures
3. keep docs/examples pointing normal downstream code at `tidecoin::*`
4. leave broad `consensus-core` export narrowing for later unless external API
   hardening becomes a real release goal

## Non-Goals Right Now

Do not prioritize these by default:

- aggressive `consensus-core` privatization
- cleanup aimed mainly at hypothetical third-party consumers
- reopening completed validation-boundary refactors

## Historical Material

Detailed migration-era inventories and resolved audits live in
[ai-docs/archived/](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived).
