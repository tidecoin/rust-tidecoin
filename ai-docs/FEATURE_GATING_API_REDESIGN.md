# Feature-Gating API Redesign

Status: active design note.

Use this file when the task is specifically about `pow` / `p2p` feature
boundaries, capability-gated public API design, or follow-up implementation of
the current feature-gating cleanup.

## Scope

This document covers the `tidecoin` crate surface only.

It does not redefine:

- `primitives` wire ownership
- future UTXO-backed validation crates
- broad `consensus-core` public-surface tightening

## Current State

The crate currently has two new capability features in
[tidecoin/Cargo.toml](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/Cargo.toml:18):

- `p2p`
- `pow`

The current design quality is mixed:

- `p2p` is feature-gated honestly.
  - [tidecoin/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/lib.rs:132)
    removes `tidecoin::p2p` entirely when `p2p` is disabled.
- `pow` is only partially feature-gated honestly.
  - [tidecoin/src/pow.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/pow.rs:56)
    already keeps mining-hash and proof-validation functions behind
    `#[cfg(feature = "pow")]`.
  - But [tidecoin/src/blockdata/block.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/block.rs:48)
    still exposes `HeaderExt::validate_pow(...)` in all builds and falls back to
    a panic when `pow` is disabled.
  - And [tidecoin/src/block_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/block_validation.rs:40)
    still defaults `check_proof` to `true`, while
    [tidecoin/src/block_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/block_validation.rs:384)
    compiles the proof-check block away entirely in non-`pow` builds.

## Design Rule

Use capability ownership as the public API rule.

- If a build cannot perform a capability, proof-only APIs for that capability
  should not exist.
- Mixed-purpose APIs may remain available, but they must report that the
  requested capability is unavailable instead of silently weakening behavior.

`p2p` already follows this rule. `pow` should be brought to the same standard.

## Architectural Problems

### `HeaderExt` owns too much

[tidecoin/src/blockdata/block.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/block.rs:48)
currently mixes:

- proof-free header math
  - `target`
  - `difficulty`
  - `difficulty_float`
  - `work`
- proof-only behavior
  - `validate_pow`

That boundary is wrong.

`validate_pow` is not a general header capability. It depends on the `pow`
feature and should be owned by the `pow` layer.

### Silent semantic downgrade in contextual validation

[ContextualHeaderCheck::DEFAULT](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/block_validation.rs:40)
still means "perform proof checks", but the implementation currently changes
that meaning depending on features.

That is not acceptable for a validation API. Feature flags may change available
capabilities, but they should not silently reinterpret caller intent.

### Redundant error layering

[block::ValidationError](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/block.rs:271)
is only a local wrapper around `pow::PowValidationError`.

That duplication made sense only while `validate_pow` lived in the `block`
extension trait. Once proof validation moves to the `pow` layer, the wrapper no
longer adds value.

### Test surface does not enforce the intended boundary

The current feature split is not reflected cleanly in tests:

- `cargo check -p tidecoin --lib --no-default-features` passes
- but `cargo test -p tidecoin --lib --no-run --no-default-features` currently
  fails because proof-only tests in `block.rs` and `pow.rs` compile
  unconditionally

That means the project currently validates the library surface better than it
validates the test surface.

## Recommended End State

### `p2p`

Keep the current `p2p` model.

- `tidecoin::p2p` remains absent when `p2p` is disabled
- no runtime stubs
- no fallback no-op behavior

### `pow`

Keep `tidecoin::pow` always present, but split it by capability.

Always available:

- `Target`
- `Work`
- `derive_target`
- retarget / transition helpers
- `CompactTargetExt`
- algorithm-selection helpers that do not require hashing backends

Only available with `feature = "pow"`:

- `scrypt_pow_hash`
- `yespower_pow_hash`
- `mining_hash_for_height`
- `validate_pow_at_height`
- `validate_pow_at_height_against_target`
- `validate_pow_any`
- `validate_auxpow_context`
- proof-specific header extension trait

### Extension-trait split

Keep `HeaderExt` always available and proof-free.

`HeaderExt` should contain only:

- `target`
- `difficulty`
- `difficulty_float`
- `work`

Move `validate_pow` into a separate trait owned by the `pow` layer, for
example:

- `tidecoin::pow::HeaderPowExt`

That trait should exist only under `#[cfg(feature = "pow")]`.

### Mixed validation APIs

Keep contextual validation APIs available in all builds because they still do
useful non-PoW work.

But if the caller requests proof checking in a non-`pow` build, return an
explicit unavailable error.

Recommended shape:

- add `ContextualHeaderError::PowUnavailable`
- optionally add a corresponding block-level unavailable path if needed through
  `ContextualBlockError::Header(...)`

Do not:

- panic
- silently skip proof checks
- make the default feature-dependent

## Solutions

### 1. Move proof-specific header behavior into the `pow` layer

Solution:

- remove `validate_pow(...)` from `block::HeaderExt`
- add `#[cfg(feature = "pow")] pub trait HeaderPowExt`
- implement it for `Header` in `tidecoin::pow`

Justification:

- the trait then lives with the code and dependencies that own the capability
- non-`pow` builds no longer advertise a fake method
- the public surface matches the dependency graph

### 2. Keep `HeaderExt` stable across all builds

Solution:

- leave only proof-free methods in `HeaderExt`

Justification:

- this trait then becomes a stable, capability-independent header API
- downstream users who only need target/work math do not pay for `pow`

### 3. Remove the `block::ValidationError` wrapper if proof validation moves

Solution:

- return `pow::PowValidationError` directly from the new proof trait

Justification:

- one operation should have one canonical error type
- the error should be owned by the module that implements the behavior
- this reduces duplicate conversions and duplicate docs

### 4. Preserve caller intent in contextual validators

Solution:

- keep `ContextualHeaderCheck::DEFAULT.check_proof = true`
- branch on the feature inside the proof-check path
- return `PowUnavailable` when `check_proof` is requested without `pow`

Justification:

- the same call should keep the same meaning across builds
- only the availability of the requested capability should differ

### 5. Make wildcard ergonomics feature-aware

Solution:

- always export `HeaderExt` in `tidecoin::ext`
- export `pow::HeaderPowExt` only when `pow` is enabled

Justification:

- `ext::*` should reflect the same capability boundaries as direct imports
- downstream wildcard-import users should not see methods that do not exist

### 6. Bring tests under the same feature model

Solution:

- gate proof-only tests in `block.rs` and `pow.rs`
- keep proof-free tests always enabled
- add non-`pow` tests for explicit unavailable behavior in contextual
  validators

Justification:

- otherwise the feature split will regress again without detection

## Updated Todo List

1. Split `HeaderExt` and introduce a `pow`-owned proof trait.
   - Solution:
     move `validate_pow(...)` out of `block::HeaderExt` and into
     `tidecoin::pow::HeaderPowExt`.
   - Why:
     this is the cleanest ownership boundary and removes the current panic path.

2. Delete the current panic fallback in `HeaderExt::validate_pow(...)`.
   - Solution:
     remove the method from `HeaderExt` entirely rather than returning a stub.
   - Why:
     compile-time absence is the correct model for proof-only APIs.

3. Simplify proof-validation error ownership.
   - Solution:
     retire `block::ValidationError` if the new proof trait can return
     `PowValidationError` directly.
   - Why:
     avoid redundant wrappers and duplicated public surface.

4. Add `ContextualHeaderError::PowUnavailable`.
   - Solution:
     keep contextual validators available, but return explicit unavailable
     errors when `check_proof` is requested without `pow`.
   - Why:
     contextual validation is mixed-purpose and should not silently weaken.

5. Keep `ContextualHeaderCheck::DEFAULT.check_proof` as `true`.
   - Solution:
     do not make the default differ by feature.
   - Why:
     defaults should express caller intent, not local compilation details.

6. Update `tidecoin::ext` exports.
   - Solution:
     re-export `HeaderPowExt` only when `pow` is enabled.
   - Why:
     wildcard ergonomics must remain truthful.

7. Update crate-level feature docs.
   - Solution:
     fix stale `default` docs and document `pow` / `p2p` capability boundaries.
   - Why:
     current docs are wrong and hide the actual contract.

8. Add `doc(cfg)` annotations to proof-only APIs.
   - Solution:
     mark feature-gated traits and functions with docs.rs-visible cfg docs.
   - Why:
     docs built with all features otherwise misrepresent availability.

9. Repair test feature hygiene.
   - Solution:
     gate proof-only tests and add explicit non-`pow` behavior tests.
   - Why:
     the current `--no-default-features` test compile failure proves this is
     missing.

10. Treat the redesign as an intentional semver-facing API change.
    - Solution:
      add migration notes once implementation starts.
    - Why:
      moving `validate_pow` off the always-on trait is a real public API break.

## Non-Goals

Do not use this redesign to expand scope into:

- full UTXO-backed validation
- broad `consensus-core` privatization
- unrelated wallet/API cleanup
- further `p2p` redesign beyond preserving the current honest capability model

## Relationship To Other Docs

- This file refines the public-surface side of
  [API_STABILIZATION_SURFACE_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/API_STABILIZATION_SURFACE_AUDIT.md)
  for the specific `pow` / `p2p` feature-gating problem.
- CI follow-up and matrix integration are tracked separately in
  [CI_FEATURE_MATRIX_INTEGRATION.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CI_FEATURE_MATRIX_INTEGRATION.md).
