# CI Feature Matrix Integration

Status: active follow-up plan.

Use this file when the task is to add or refine CI coverage for feature-gated
crate surfaces, especially `tidecoin` `pow` / `p2p` capability boundaries.

## Why This Exists

The repository currently has no CI feature matrix for the `tidecoin` crate.

That is now a real gap because:

- `p2p` and `pow` are public capability features
- the library can compile in combinations that materially change the public API
- recent regressions were able to pass normal library checks while still
  breaking test compilation and feature-boundary semantics

Examples already observed:

- `cargo check -p tidecoin --lib --no-default-features` passes
- `cargo test -p tidecoin --lib --no-run --no-default-features` now passes
  locally after the feature-gating cleanup, but is not yet enforced in CI

Without a feature matrix, this class of regression is easy to reintroduce.

## Goal

Add a minimal but strict CI matrix that proves:

- each supported feature shape compiles
- proof-free builds do not accidentally depend on proof-only APIs
- proof-enabled builds retain their intended behavior
- tests themselves respect the same feature boundaries as the library

## Principles

1. Use a small matrix with strong signal.
2. Separate compile-surface checks from deeper test execution.
3. Make feature-boundary regressions fail fast.
4. Prefer explicit matrix entries over a single "all default" job.

## Required Matrix

At minimum, CI should run the following for `tidecoin`:

### Compile matrix

1. Default surface

```bash
cargo check -p tidecoin --lib
```

Why:

- proves the normal downstream product build still compiles

2. Minimal surface

```bash
cargo check -p tidecoin --lib --no-default-features
```

Why:

- proves proof-free / p2p-free downstream consumers still compile

3. `pow` without default extras

```bash
cargo check -p tidecoin --lib --no-default-features --features std,pow
```

Why:

- proves `pow` can be enabled independently of `p2p`

4. `p2p` without `pow`

```bash
cargo check -p tidecoin --lib --no-default-features --features std,p2p
```

Why:

- proves `p2p` can be enabled independently of `pow`

### Test-compile matrix

5. Minimal test surface

```bash
cargo test -p tidecoin --lib --no-run --no-default-features
```

Why:

- catches test modules that still reference proof-only APIs unconditionally

6. `pow` test surface

```bash
cargo test -p tidecoin --lib --no-run --no-default-features --features std,pow
```

Why:

- proves proof-enabled unit tests compile in the non-default `pow` shape

## Recommended Extra Coverage

These are not strictly required for the first CI patch, but they are good next
steps.

### Default test execution

```bash
cargo test -p tidecoin --lib
```

Why:

- keeps the normal test surface healthy

### Explicit `pow` test execution

```bash
cargo test -p tidecoin --lib --no-default-features --features std,pow
```

Why:

- ensures the split proof trait and proof APIs behave correctly outside the
  default feature set

### Clippy on at least one minimal feature shape

```bash
cargo clippy -p tidecoin --lib --no-default-features --features std,pow -- -D warnings
```

Why:

- catches cfg-dependent dead code and unused imports after the redesign

## Planned Assertions After The API Redesign

Once the feature-gating redesign is implemented, CI should indirectly enforce
these contracts:

- non-`pow` builds do not expose proof-only APIs
- proof-only tests are gated correctly
- contextual validators return explicit unavailable errors when proof checking
  is requested without `pow`
- `pow` builds still expose and compile proof-validation APIs

## Suggested CI Job Shape

One practical split:

- `tidecoin-default`
  - `cargo check -p tidecoin --lib`
  - `cargo test -p tidecoin --lib --no-run`
- `tidecoin-minimal`
  - `cargo check -p tidecoin --lib --no-default-features`
  - `cargo test -p tidecoin --lib --no-run --no-default-features`
- `tidecoin-pow`
  - `cargo check -p tidecoin --lib --no-default-features --features std,pow`
  - `cargo test -p tidecoin --lib --no-run --no-default-features --features std,pow`
- `tidecoin-p2p`
  - `cargo check -p tidecoin --lib --no-default-features --features std,p2p`

This is small enough to add now without turning CI into a slow exhaustive
feature-power-set search.

## Integration Notes

When implementing the CI workflow later:

- keep matrix entries explicit
- keep commands independent and easy to reproduce locally
- do not hide multiple feature combinations behind a single script without
  preserving the exact commands in the workflow definition
- fail the minimal job before deeper default jobs if possible, because minimal
  feature regressions are easiest to miss locally

## Follow-Up Work After CI Exists

1. Add crate-level policy for which feature combinations are officially
   supported.
2. Expand the matrix if new public capability features are added.
3. Add docs/tests around migration of `validate_pow` to the `pow`-owned proof
   trait once that redesign lands.

## Relationship To Other Docs

- Historical API redesign details live in
  [archived/FEATURE_GATING_API_REDESIGN.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived/FEATURE_GATING_API_REDESIGN.md).
- This file is intentionally CI-focused so it can be implemented later without
  reopening the broader architecture discussion.
