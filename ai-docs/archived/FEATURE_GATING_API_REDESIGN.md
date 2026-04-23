# Feature-Gating API Redesign

Status: archived implemented design note.

This file records the completed `pow` / `p2p` feature-boundary redesign for the
`tidecoin` crate.

Do not use this file as an active work driver. The only remaining active
follow-up from this redesign is CI matrix integration in
[CI_FEATURE_MATRIX_INTEGRATION.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CI_FEATURE_MATRIX_INTEGRATION.md).

## Scope

This redesign covered only the `tidecoin` crate surface.

It did not change:

- `primitives` wire ownership
- future UTXO-backed validation crates
- broad `consensus-core` public-surface tightening

## Completed

The library-side redesign is done.

Implemented results:

- `p2p` remains honestly feature-gated.
  - [tidecoin/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/lib.rs:134)
    removes `tidecoin::p2p` entirely when `p2p` is disabled.
- `HeaderExt` is now proof-free.
  - [tidecoin/src/blockdata/block.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/block.rs:46)
    keeps only always-available header math helpers.
- Proof validation moved into the `pow` layer.
  - [tidecoin/src/pow.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/pow.rs:150)
    owns the `HeaderPowExt` trait behind `feature = "pow"`.
- Contextual validation no longer silently weakens semantics.
  - [tidecoin/src/block_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/block_validation.rs:124)
    adds `ContextualHeaderError::PowUnavailable`.
  - [tidecoin/src/block_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/block_validation.rs:394)
    returns that error when proof checking is requested without `pow`.
- Feature-sensitive test compilation was fixed.
  - proof-only tests in `block.rs` and `pow.rs` are now gated correctly
  - non-`pow` contextual validation has explicit coverage

## Verified

The redesign was verified locally with:

```bash
cargo check -p tidecoin --lib
cargo check -p tidecoin --lib --no-default-features
cargo check -p tidecoin --lib --no-default-features --features std,pow
cargo check -p tidecoin --lib --no-default-features --features std,p2p
cargo test -p tidecoin --lib --no-run
cargo test -p tidecoin --lib --no-run --no-default-features
cargo test -p tidecoin --lib --no-run --no-default-features --features std,pow
```

## Historical Problems Solved

- `HeaderExt` previously mixed proof-free header math with proof-only
  validation.
- `HeaderExt::validate_pow(...)` previously existed in non-`pow` builds and
  fell back to a panic.
- contextual validation previously accepted `check_proof: true` but compiled the
  proof-check block away in non-`pow` builds.
- proof-only tests previously broke minimal-feature test compilation.

## Pending Follow-Up

Only CI integration remains active.

Pending:

- add the explicit `tidecoin` feature matrix to
  [.github/workflows/rust.yml](/home/yaroslav/dev/tidecoin/rust-tidecoin/.github/workflows/rust.yml)
- enforce the already-verified feature combinations in CI

Track that work in:

- [CI_FEATURE_MATRIX_INTEGRATION.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CI_FEATURE_MATRIX_INTEGRATION.md)

## Relationship To Other Docs

- Active public-surface tracking now lives in
  [API_STABILIZATION_SURFACE_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/API_STABILIZATION_SURFACE_AUDIT.md)
- Active CI follow-up lives in
  [CI_FEATURE_MATRIX_INTEGRATION.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CI_FEATURE_MATRIX_INTEGRATION.md)
