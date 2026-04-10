# Rust-Tidecoin Migration Handoff

This document captures the architectural conclusions and migration guidance discussed before moving the Tidecoin consensus work into the `rust-tidecoin` monorepo.

Related planning document:

- [pq-integration-plan.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/docs/pq-integration-plan.md)

## Original situation

The imported crate started as a Bitcoin-oriented pure-Rust consensus verifier.
At the time this handoff was written, it depended on upstream `rust-bitcoin`
via the `bitcoin` crate and used that dependency for much more than generic
data types.

At that point, the `bitcoin` crate was used for:

- transaction, script, witness, amount, outpoint, sequence, locktime, and serialization types
- script parser and builder machinery
- opcodes and instruction decoding
- sighash cache and segwit/taproot-related sighash helpers
- secp256k1 ECDSA and Schnorr signature logic
- Taproot/Tapscript types and constants
- a large portion of the current tests and benches

That meant the `bitcoin` dependency was both:

- a primitives dependency
- a Bitcoin consensus semantics dependency

For Tidecoin, the second role was the real problem.

Current status:
- this dependency migration has since been completed in the live crate
- this document remains useful as architectural rationale, not as a current
  status snapshot

## What changed in scope

The goal is not "rename Bitcoin consensus to Tidecoin consensus".

The goal is:

- remove Bitcoin-specific consensus assumptions
- replace them with Tidecoin consensus behavior
- use Rust Tidecoin crypto and validation logic
- treat the Tidecoin node as the external reference implementation

This includes:

- post-quantum signatures
- `PQ_STRICT`
- witness-v1-512
- `OP_SHA512`
- Tidecoin fixture corpora
- Tidecoin activation logic

It explicitly excludes continuing to use Bitcoin-only assumptions like:

- Taproot/Tapscript/Schnorr as the target model
- `bitcoinconsensus` as the reference crate
- Bitcoin Core activation schedules

## Important decision: no separate Tidecoin `bitcoinconsensus` reference crate

In Bitcoin-land, this crate currently tests a lot of behavior against the `bitcoinconsensus` crate and Bitcoin Core-shaped fixtures.

For Tidecoin, that is not the right model.

The consensus crate being built here is intended to become the Tidecoin consensus crate itself. Therefore:

- there is no separate Tidecoin analogue of `bitcoinconsensus` to use as a reference crate
- the Tidecoin node becomes the only external consensus reference implementation
- the differential/parity test surface must compare against the node, not another Rust crate

## Why depending on the top-level `tidecoin` crate is not the right fix

There was an early idea to replace the direct `bitcoin` dependency with a path dependency on:

- `/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin`

That top-level crate is named `tidecoin` and already exposes useful Tidecoin-native pieces:

- PQ crypto types
- Tidecoin consensus-validation logic
- Tidecoin script, transaction, sighash, and witness-v1-512 support

However, making this crate depend directly on the top-level `tidecoin` crate is not the right long-term structure if the work is also moving into `rust-tidecoin`, because it creates an architectural knot:

- `consensus` would depend on `tidecoin`
- the top-level `tidecoin` crate would likely need to depend on `consensus`
- that becomes a Cargo cycle

Even if that cycle is avoided temporarily, it still leaves the reusable validation core in the wrong layer.

## Core architectural conclusion

The reusable Tidecoin validation logic should not live only as an internal module of the top-level `tidecoin` crate.

Instead, the best structure is:

1. low-level Tidecoin crates provide primitives
2. a shared consensus/validation core crate provides Tidecoin consensus-critical logic
3. both the top-level `tidecoin` crate and any compatibility-facing consensus crate depend on that shared core

### Recommended dependency shape

Desired dependency graph:

- low-level crates:
  - `consensus_encoding`
  - `hashes`
  - `units`
  - `primitives`
  - PQ crypto crates and wrappers
- shared validation crate:
  - tentative name: `tidecoin-consensus-core`
- consumers:
  - top-level `tidecoin` crate
  - compatibility-oriented `consensus` crate, if it still exists

### What should live in the shared core crate

- verification flags and supported-flag checks
- script error types
- Tidecoin script interpreter/evaluator
- consensus-critical sighash logic
- witness-v0 and witness-v1-512 validation logic
- PQ public-key/signature verification glue
- transaction input verification helpers

### What should not live in the shared core crate

- wallet logic
- descriptor generation
- address encoding/decoding
- P2P or RPC code
- node runtime code
- mempool/policy code unless a piece is genuinely consensus-critical
- repo-specific test harness glue

## Strong recommendation: move the consensus work into the `rust-tidecoin` monorepo

Given the cycle risk, shared validation logic, and the fact that `rust-tidecoin` already owns the low-level crates, the cleanest structure is to move the Tidecoin consensus work into the `rust-tidecoin` monorepo.

Recommended approach:

- create a new crate in `~/dev/tidecoin/rust-tidecoin`
- use that crate for the reusable validation core
- make the top-level `tidecoin` crate depend on it
- either retire this current standalone repo or keep it only as a compatibility wrapper if needed

This is better than keeping the core logic split across repos.

## What the current standalone `consensus` repo should not do

The current repo should not:

- continue building Tidecoin consensus on upstream `rust-bitcoin` semantics
- depend on the top-level `tidecoin` crate in a way that creates a cycle
- keep Bitcoin-only test and fixture assumptions alive and "patch around them"

## Test-surface conclusion

The testing modes should be preserved, but the reference target and harness assumptions must change.

### Testing modes that should remain possible

- local unit tests
- JSON fixture/vector tests
- node-connected parity tests
- helper-binary/runtime diff tests where useful
- fixture integrity tests

### What changes

- no more `bitcoinconsensus` parity as the target
- no more Bitcoin Core as the target
- the Tidecoin node becomes the parity target
- Tidecoin fixtures replace Bitcoin fixtures
- Taproot/Tapscript/Schnorr-specific tests are removed
- PQ, witness-v1-512, and `OP_SHA512` coverage must be added

### Monorepo test preservation

Moving this work into `rust-tidecoin` does not mean losing the ability to run the same class of tests. It means:

- keep the test modes
- re-anchor them on Tidecoin behavior
- point node-backed tests at:
  - `~/dev/tidecoin/tidecoin`

A good target shape inside the monorepo would be a dedicated consensus crate test area with:

- local invariant/unit tests
- Tidecoin fixture/vector tests
- Tidecoin-node parity tests

## Practical import/dependency audit that must happen

Before implementation, do an import-by-import audit of what the current crate takes from upstream `bitcoin` and classify each import as:

- primitive/container
- script model
- sighash utility
- secp/signature logic
- Taproot-only logic
- test-helper only

For each import, decide whether the replacement is:

- a direct Tidecoin lower-crate replacement
- a wrapper over the new shared consensus core
- or deletion

This audit is necessary because the current `bitcoin` dependency is deeply embedded across:

- `src/`
- `tests/`
- `benches/`

## Best way to proceed after moving into `rust-tidecoin`

### Phase A: establish the crate boundary first

- decide the shared crate name and workspace location
- define exactly what belongs in that crate
- ensure it depends only on lower-level Tidecoin crates, not the top-level `tidecoin` crate

### Phase B: move validation logic down

- extract or port Tidecoin consensus-critical validation code into the shared crate
- move/port the relevant parts of:
  - script evaluation
  - sighash handling
  - witness-v1-512 logic
  - PQ verification glue

### Phase C: make the top-level `tidecoin` crate consume it

- replace internal consensus validation implementation with the shared crate
- keep any higher-level ergonomic wrappers in the `tidecoin` crate only if useful

### Phase D: rebuild the compatibility-facing consensus API

- either re-create the byte-oriented API in a wrapper crate
- or expose a stable public API directly from the shared crate if that is preferable

### Phase E: rebuild the test surface around Tidecoin

- delete Bitcoin-only tests first
- rewrite vector and parity harnesses around the Tidecoin node
- add PQ-specific coverage back in

## Explicit decisions already made in discussion

- The Tidecoin node is the reference implementation for parity testing.
- This work should not rely on a separate Tidecoin `bitcoinconsensus` analogue.
- The current `bitcoin` dependency is too deep and semantically wrong for the final Tidecoin architecture.
- A shared lower-level consensus core crate is the right long-term boundary.
- Moving the consensus work into the `rust-tidecoin` monorepo is likely the best overall structure.
- Test capability should be preserved, but the test surface must be redesigned for Tidecoin.

## Immediate recommended next action inside `rust-tidecoin`

Before touching implementation, create a small architecture note in the monorepo that answers:

1. What is the new shared crate called?
2. Which existing modules move into it?
3. Which public APIs are exposed from it?
4. Which existing top-level `tidecoin` modules become wrappers?
5. Which tests are deleted immediately?
6. Which tests are rewritten first to preserve confidence during the move?

Once that boundary is agreed, implementation can proceed without repeatedly re-litigating the architecture.
