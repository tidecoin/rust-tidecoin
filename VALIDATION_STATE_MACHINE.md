# Validation State Machine

This file is the authoritative state tracker for the multi-wave validation and fixing run.

## State Definitions

- `queued`: identified but not yet explored
- `exploring`: being validated by an agent or local pass
- `ready_to_fix`: validated issue, waiting for implementation
- `fixing`: implementation in progress
- `verifying`: fix landed, verification running
- `done`: validated and closed
- `blocked`: cannot progress without a confirmed external decision

## Global Goal

Bring the library to a state where:

- Tidecoin-specific requirements are validated against the Tidecoin node
- no required porting items are missing in the actual codebase
- code compiles across requested feature combinations
- tests pass
- no unused code remains
- no taproot support remains
- required features are covered by tests
- compatibility with Tidecoin node behavior is maximized and documented
- every `#[ignore]` block is inspected to determine whether it should be fixed, removed, or explicitly retained with a Tidecoin-specific justification
- git remote `origin` targets `git@github.com:tidecoin/rust-tidecoin.git`
- the validated result is pushed to branch `v2`

## Workstreams

| Workstream | State | Owner | Notes |
| --- | --- | --- | --- |
| Inventory and baseline verification | `done` | orchestrator | Current status established from local and subagent validation |
| Tidecoin node compatibility diff | `done` | orchestrator | Major Rust vs node deltas identified and tracked |
| All-features compilation | `done` | orchestrator | Tidecoin crate all-features compile/tests/examples now pass |
| Taproot removal | `done` | orchestrator + workers | Hidden taproot modules and key/consensus hooks are removed; `is_p2tr()` and dead taproot serde artifacts are gone; `OP_CHECKSIGADD` is retained only as a disabled node-compatibility opcode byte |
| Unused code and warnings | `done` | orchestrator | Strict clippy gate is clean |
| Test coverage migration | `done` | orchestrator + workers | PQ coverage landed; node-style key/address, WIF, genesis, policy, and doctest coverage expanded; no live `#[ignore]` tests remain |
| Final verification | `done` | orchestrator | Workspace compile/test/lint/doc gates are green after the latest ignore audit and taproot-surface cleanup |
| Regtest legacy compatibility | `done` | orchestrator + worker | Dedicated regtest legacy address/WIF prefixes now round-trip and are covered by node-backed tests |
| Repository remote and publish | `fixing` | orchestrator | `origin` now points at the Tidecoin repository; final validated state still needs to be pushed to branch `v2` |

## Phase Log

### Phase 0

- State: `exploring`
- Objective: build a concrete backlog from source validation and parallel agent findings
- Baseline confirmed:
  - `cargo check --workspace` passes
  - `cargo test --workspace` passes
  - `cargo check --workspace --all-features` passes with warnings
  - `cargo check -p tidecoin --all-features --tests --examples` fails on stale `Network::Bitcoin`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings` fails
  - taproot remains broadly present across code and docs

### Phase 1

- State: `fixing`
- Objective: clear compile blockers, reduce taproot exposure, and fill Tidecoin-specific test gaps
- Completed in this phase:
  - stale `Network::Bitcoin` references removed from examples/tests/embedded paths
  - strict `cargo clippy --workspace --all-targets --all-features -- -D warnings` now passes
  - PQ API coverage expanded across all five schemes, parse/serialize, `key_id`, and error boundaries
  - legacy base58 decoding widened to match Tidecoin node prefixes for mainnet/testnet/regtest
  - stale Bitcoin/Taproot wording removed from owned docs/examples/fuzz generator
  - Tidecoin crate no longer publicly exports the `taproot` module
  - P2TR constructor helpers removed from the public script surface
  - taproot-facing serde/API/tests removed from `bitcoin/tests/serde.rs` and `primitives/tests/api.rs`
  - additional taproot-only PSBT/witness/test vectors pruned from default validation

### Phase 2

- State: `verifying`
- Objective: prove the current tree is stable after the fixes
- Current verification snapshot:
  - `cargo check --workspace` passes
  - `cargo check -p tidecoin --all-features --tests --examples` passes
  - `cargo test --workspace` passes
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes

### Phase 3

- State: `fixing`
- Objective: remove dead internal taproot code, restore honest tracker state, and execute the next compatibility wave
- Completed in this phase:
  - deleted `bitcoin/src/crypto/taproot.rs`
  - removed `crypto::taproot` from `bitcoin/src/crypto/mod.rs`
  - removed the taproot serialized-signature `PushBytes` adapter from `bitcoin/src/blockdata/script/push_bytes.rs`
  - removed the disabled taproot-specific sighash types, errors, and entry points from `bitcoin/src/crypto/sighash.rs`
  - refreshed validation gates and re-confirmed:
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo clippy -p tidecoin --all-targets --all-features -- -D warnings`
    - `cargo check --workspace`
    - `cargo test --workspace`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Remaining open risks:
  - the compiled taproot/tapscript implementation cluster still exists in `bitcoin/src/taproot/**`, `bitcoin/src/consensus/encode.rs`, `bitcoin/src/crypto/key.rs`, `primitives/src/script/*`, `bitcoin/src/blockdata/opcodes.rs`, and `primitives/src/opcodes.rs`
  - Tidecoin node compatibility still needs deeper corpus-style address/key validation and a final ignored-test audit

### Phase 4

- State: `fixing`
- Objective: finish the Tidecoin-node compatibility pass and remove the last compiled taproot cluster
- Completed in this phase:
  - aligned regtest legacy base58 address formatting and parsing with dedicated Tidecoin node prefixes
  - aligned WIF parsing/encoding with dedicated regtest behavior and added node-backed WIF vectors
  - aligned `MAX_STANDARD_TX_WEIGHT` and `MAX_OP_RETURN_RELAY` with Tidecoin node policy and added regression coverage
  - added genesis and network-parameter sanity tests for Tidecoin mainnet/testnet/regtest
  - removed the dedicated `TapScriptTag` marker from `primitives/src/script/tag.rs` and collapsed `TapScript{,Buf}` onto the witness-script types in `primitives/src/script/mod.rs`
  - removed the last explicit `Taproot` wording from `primitives/src/script/mod.rs`
  - removed the hidden `bitcoin/src/taproot/**` implementation tree and deleted the dependent key-tweaking and consensus encoding hooks
  - deleted unreferenced taproot-only test fixtures from `bitcoin/tests/data/**`
  - vendored Tidecoin node `key_io_valid.json` and `key_io_invalid.json` into `bitcoin/tests/data/**`
  - added `bitcoin/tests/key_io_vectors.rs` to validate node address/WIF corpora directly against the Rust port
  - retargeted git remote `origin` to `git@github.com:tidecoin/rust-tidecoin.git`
  - refreshed verification gates and re-confirmed:
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo clippy -p tidecoin --all-targets --all-features -- -D warnings`
    - `cargo check --workspace`
    - `cargo test --workspace`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Remaining open risks:
  - repository publishing is still pending: the validated state must be pushed to `v2`

### Phase 5

- State: `done`
- Objective: close the ignore audit, remove the last live taproot-named API, and re-run full verification
- Completed in this phase:
  - confirmed there are no live Rust `#[ignore]` attributes anywhere in the repository
  - converted avoidable ignored doctests to `compile_fail` or compilable examples
  - removed the residual `is_p2tr()` script API and renamed the witness-v1 regression test accordingly
  - deleted unreferenced taproot-era serde blobs from `bitcoin/tests/data/serde/**`
  - reduced ignored doctests to three justified sketch/context cases:
    - `bitcoin/src/bip158.rs`
    - `bitcoin/src/crypto/sighash.rs`
    - `hashes/src/internal_macros.rs`
  - completed final verification successfully:
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo check --workspace`
    - `cargo test --workspace`
    - `cargo test --workspace -- --ignored --list`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Compatibility decisions recorded:
  - `OP_CHECKSIGADD` remains intentionally named and exported because the Tidecoin node still carries opcode `0xba` under that name while treating it as disabled; the Rust port keeps it only for raw script/opcode compatibility and classifies it as illegal
