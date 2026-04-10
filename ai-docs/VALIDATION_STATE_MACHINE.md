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
- no taproot execution/address/script support remains in the live Tidecoin API surface, while explicit rejection markers, disabled-opcode compatibility bytes, x-only secp utilities, and historical changelog references may remain intentionally present
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
| Consensus-core extraction and `consensus/` migration | `verifying` | orchestrator | `consensus-core` now owns the shared interpreter/typed tx/sighash/PQ/witness core, `consensus/` is a Tidecoin-native byte-oriented adapter over it, and the remaining work is cleanup of historical proof assets plus final boundary audit |
| Shared Tidecoin node-parity harness extraction | `verifying` | orchestrator | Shared crate now owns native bridge sources, native build wiring, raw FFI, script-error/fixture helpers, and `TidecoinNodeHarness`; both `tidecoin` and `consensus/` now consume it, `consensus/tests/tidecoin_node_parity.rs` covers Tidecoin script and tx corpora, and the next step is replacing the remaining Bitcoin-specific `core_diff_bridge` differential path |
| All-features compilation | `done` | orchestrator | Tidecoin crate targeted all-features compile/lint gates are currently green; keep tied to fresh command output rather than stale blanket claims |
| Taproot removal | `done` | orchestrator + workers | Hidden taproot modules and taproot script/address support are removed; `is_p2tr()` and dead taproot serde artifacts are gone; `OP_CHECKSIGADD` is retained only as a disabled node-compatibility opcode byte, while x-only secp utilities, explicit PSBT rejection markers, and historical changelog references remain intentionally present |
| Unused code and warnings | `verifying` | orchestrator | The I/O compatibility codec crate is being removed; canonical codecs now flow through `tidecoin-consensus-encoding`, with crate-specific facades only where they add domain semantics |
| Test coverage migration | `done` | orchestrator + workers | Imported node PQ corpora, direct witness-v1-512/runtime tails, PQ WIF behavior, and the remaining tracked node executable cases are now mirrored in Rust tests |
| PQ/Falcon runtime parity | `done` | orchestrator + explorers | The previously tracked library-scope PQ/Falcon runtime gaps are closed; remaining debt is direct node executable coverage, not missing runtime behavior; see `FALCON_PQ_GAP_REPORT.md` |
| Final verification | `done` | orchestrator | Final verification is tied to fresh command output: workspace check/test, Tidecoin all-features check, strict clippy, and `git diff --check` are green |
| Regtest legacy compatibility | `done` | orchestrator + worker | Dedicated regtest legacy address/WIF prefixes now round-trip and are covered by node-backed tests |
| Repository remote and publish | `done` | orchestrator | `origin` points at the Tidecoin repository and the validated tree is published at `origin/v2` (`d8bbe1e`) |

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
  - taproot-facing serde/API/tests removed from `tidecoin/tests/serde.rs` and `primitives/tests/api.rs`
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
  - deleted `tidecoin/src/crypto/taproot.rs`
  - removed `crypto::taproot` from `tidecoin/src/crypto/mod.rs`
  - removed the taproot serialized-signature `PushBytes` adapter from `tidecoin/src/blockdata/script/push_bytes.rs`
  - removed the disabled taproot-specific sighash types, errors, and entry points from `tidecoin/src/crypto/sighash.rs`
  - refreshed validation gates and re-confirmed:
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo clippy -p tidecoin --all-targets --all-features -- -D warnings`
    - `cargo check --workspace`
    - `cargo test --workspace`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Remaining open risks:
  - the old `tidecoin/src/consensus/**` codec compatibility namespace has been removed; any remaining Taproot/Tapscript audit should focus on real runtime/type surfaces such as `tidecoin/src/crypto/key.rs`, `primitives/src/script/*`, and `primitives/src/opcodes.rs`
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
  - removed the hidden `tidecoin/src/taproot/**` implementation tree and deleted the dependent key-tweaking and consensus encoding hooks
  - deleted unreferenced taproot-only test fixtures from `tidecoin/tests/data/**`
  - vendored Tidecoin node `key_io_valid.json` and `key_io_invalid.json` into `tidecoin/tests/data/**`
  - added `tidecoin/tests/key_io_vectors.rs` to validate node address/WIF corpora directly against the Rust port
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
  - deleted unreferenced taproot-era serde blobs from `tidecoin/tests/data/serde/**`
  - reduced ignored doctests to three justified sketch/context cases:
    - `tidecoin/src/bip158.rs`
    - `tidecoin/src/crypto/sighash.rs`
    - `hashes/src/internal_macros.rs`
  - completed final verification successfully:
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo check --workspace`
    - `cargo test --workspace`
    - `cargo test --workspace -- --ignored --list`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Compatibility decisions recorded:
  - `OP_CHECKSIGADD` remains intentionally named and exported because the Tidecoin node still carries opcode `0xba` under that name while treating it as disabled; the Rust port keeps it only for raw script/opcode compatibility and classifies it as illegal

### Phase 6

- State: `done`
- Objective: close the repository publish item and record the next validated Falcon/PQ compatibility backlog
- Completed in this phase:
  - re-verified publish state: local `HEAD`, `origin/v2`, and the remote branch tip all match `d8bbe1eddf4d27263bdfeb1e3d43f5541d4e6271`
  - executed a second multi-agent node-vs-Rust comparison focused on PQ crypto, PQHD, interpreter/runtime behavior, corpus coverage, and transport
  - recorded the validated missing-behavior inventory in `FALCON_PQ_GAP_REPORT.md`
  - promoted the missing Falcon/PQ runtime areas into explicit `ready_to_fix` backlog items instead of leaving them implied
- Remaining open risks:
  - real PQ crypto backend parity with `src/pq/pq_api.h` and `src/pq/pq_scheme.h` is still missing
  - interpreter/runtime support for `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and `SignatureHash512` is still missing
  - node PQ script/transaction/multisig/policy corpora are not yet migrated as executable Rust coverage
  - Tidecoin PQ transport parity with `src/bip324_pq.h` is still missing

### Phase 7

- State: `done`
- Objective: land the first executable Falcon/PQ parity slice inside the Rust library boundary
- Completed in this phase:
  - added `tidecoin/src/pqhd.rs` with node-mirrored PQHD v1 constants, `SeedId`, master/child/path derivation, path validation, leaf material derivation, and deterministic stream-block vectors
  - added `tidecoin/src/psbt/tidecoin.rs` with Tidecoin proprietary PSBT helpers for PQHD origin records on inputs and outputs
  - mirrored the node PQHD origin validation behavior in Rust tests, including identifier/subtype rejection, malformed-path rejection, roundtrip, and combine semantics
  - fixed a real PSBT parser compatibility bug by raising the proprietary keydata read cap in `tidecoin/src/psbt/raw.rs` so large PQ prefixed public keys are accepted
  - re-ran verification successfully:
    - `cargo test -p tidecoin --lib`
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo check --workspace`
    - `cargo test --workspace`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Remaining open risks:
  - real PQ crypto backend parity with deterministic keygen/sign/verify and ML-KEM is still missing
  - interpreter/runtime support for `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and `SignatureHash512` is still missing
  - node PQ script/transaction/multisig/policy corpora are not yet migrated as executable Rust coverage
  - Tidecoin PQ transport parity with `src/bip324_pq.h` is still missing

### Phase 8

- State: `done`
- Objective: close the next verified PQ runtime gap with node-backed backend behavior
- Completed in this phase:
  - added a small C compatibility bridge in `tidecoin/c_src/**` plus `tidecoin/build.rs` to reuse PQClean internals already present in the dependency graph
  - implemented `PqPublicKey::from_secret_key()` in `tidecoin/src/crypto/pq.rs` for Falcon-512, Falcon-1024, ML-DSA-44, ML-DSA-65, and ML-DSA-87
  - implemented explicit Falcon-512 legacy helpers in `tidecoin/src/crypto/pq.rs`:
    - `sign_msg32_legacy`
    - `sign_msg64_legacy`
    - `verify_msg32_legacy`
    - `verify_msg64_legacy`
    - `verify_msg32_allow_legacy`
    - `verify_msg64_allow_legacy`
  - added regression coverage for:
    - secret-to-public-key derivation across all five schemes
    - Falcon-512 legacy signature generation/verification for 32-byte and 64-byte messages
  - re-ran verification successfully:
    - `cargo test -p tidecoin --lib crypto::pq`
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo test --workspace`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Remaining open risks:
  - deterministic PQHD key generation from the derived stream material is still missing
  - prefixed/legacy PQ secret-key codec parity with node `DecodeSecretKey` / `EncodeSecretKey` is still missing
  - interpreter/runtime support for `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and PQ corpus execution is still missing
  - Tidecoin PQ transport parity with `src/bip324_pq.h` is still missing
  - the optional validation API still points at upstream `bitcoinconsensus`, not a Tidecoin-specific validation surface

### Phase 9

- State: `done`
- Objective: close the next two validated PQ parity gaps with node-backed deterministic keygen and secret-key codec behavior
- Completed in this phase:
  - implemented deterministic seed-based keypair generation for Falcon-512, Falcon-1024, ML-DSA-44, ML-DSA-65, and ML-DSA-87 via the local PQClean compatibility bridge in `tidecoin/c_src/**`
  - wired Tidecoin PQHD v1 stream-key retry generation in `tidecoin/src/pqhd.rs`, matching the node's deterministic `KeyGenFromSeed` flow and attempt budget
  - added exact node hash-vector coverage for deterministic PQHD key generation across all five schemes plus receive-vs-change domain separation tests
  - implemented prefixed secret-key parsing/serialization and legacy raw-secret decoding in `tidecoin/src/crypto/pq.rs`
  - enforced Falcon secret-key encoding bytes (`0x59` / `0x5A`) and added regression coverage for prefixed and legacy secret-key roundtrips
  - re-ran verification successfully:
    - `cargo test -p tidecoin --lib crypto::pq`
    - `cargo test -p tidecoin --lib pqhd::tests`
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo test --workspace`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Remaining open risks:
  - interpreter/runtime support for `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and PQ corpus execution is still missing
  - Tidecoin PQ transport parity with `src/bip324_pq.h` is still missing
  - the optional validation API still points at upstream `bitcoinconsensus`, not a Tidecoin-specific validation surface

### Phase 10

- State: `done`
- Objective: land the missing `pqhd(...)` key-expression and descriptor-string layer in the dedicated workspace crate
- Completed in this phase:
  - implemented `PqhdKeyExpression` parsing and formatting in `key_expression/src/lib.rs`
  - added deterministic public-key/keypair derivation from `pqhd(...)` expressions backed by `tidecoin::pqhd`
  - added node-style wallet descriptor string generation with Tidecoin scheme/height gating for `pkh(...)`, `sh(wpkh(...))`, `wpkh(...)`, and `wsh512(pk(...))`
  - added regression coverage ported from node descriptor and wallet behavior, including negative parsing cases and scheme-height policy checks
  - re-ran verification successfully:
    - `cargo test -p tidecoin-key-expression`
    - `cargo check --workspace`
    - `cargo test --workspace`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Remaining open risks:
  - interpreter/runtime support for `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and PQ corpus execution is still missing
  - Tidecoin PQ transport parity with `src/bip324_pq.h` is still missing
  - the optional validation API still points at upstream `bitcoinconsensus`, not a Tidecoin-specific validation surface

### Phase 11

- State: `done`
- Objective: close the stale non-PQ cleanup slice and re-validate the legacy P2P message claim
- Completed in this phase:
  - deleted the dead `tidecoin/tests/data/legacy_sighash.json` vector now that node-backed `sighash.json` is the active coverage source
  - deleted the unreferenced `tidecoin/tests/data/mainnet_block_*.raw` and `tidecoin/tests/data/testnet_block_*.raw` fixtures while keeping the still-used `node_block_413567.raw` fixture
  - corrected the remaining Tidecoin-facing `BTC/kB` / "today's Bitcoin network" wording in the dust-policy and sighash public docs
  - re-validated the stale P2P gap and confirmed:
    - `NetworkMessage` already decodes legacy `reject` traffic as `Unknown`
    - `message_network::Alert` must remain because Tidecoin node still sends the final alert to peers with protocol version `<= 70012`
  - re-ran verification successfully:
    - `cargo check --workspace`
    - `cargo test --workspace`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Remaining open risks:
  - interpreter/runtime support for `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and PQ corpus execution is still missing
  - Tidecoin PQ transport parity with `src/bip324_pq.h` is still missing
  - the optional validation API still points at upstream `bitcoinconsensus`, not a Tidecoin-specific validation surface

### Phase 12

- State: `done`
- Objective: close the remaining ML-KEM and Tidecoin v2 PQ transport library gaps with node-backed behavior and tests
- Completed in this phase:
  - added ML-KEM-512 helper types and operations in `tidecoin/src/crypto/pq.rs`:
    - random keypair generation
    - deterministic keypair generation from node-style 64-byte coins
    - encapsulate / deterministic encapsulate
    - decapsulate
  - added regression coverage for ML-KEM-512 roundtrip and deterministic behavior in `tidecoin/src/crypto/pq.rs`
  - added `p2p/src/bip324_pq.rs` implementing Tidecoin v2 PQ packet-cipher key derivation and packet encryption/decryption
  - mirrored node transport test coverage with Rust tests for:
    - FSChaCha20 vectors from `src/test/crypto_tests.cpp`
    - FSChaCha20Poly1305 vectors from `src/test/crypto_tests.cpp`
    - `bip324_pq` packet roundtrip and corruption handling from `src/test/bip324_pq_tests.cpp`
  - re-ran verification successfully:
    - `cargo test -p tidecoin --lib crypto::pq`
    - `cargo test -p tidecoin-p2p-messages bip324_pq`
    - `cargo check --workspace`
    - `cargo test --workspace`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Remaining open risks:
  - interpreter/runtime support for `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and PQ corpus execution is still missing

### Phase 13

- State: `done`
- Objective: stop the optional validation API from misrepresenting Tidecoin support while the local runtime remains unimplemented
- Completed in this phase:
  - added Tidecoin-only validation flag constants in `tidecoin/src/consensus_validation.rs` for:
    - `VERIFY_PQ_STRICT`
    - `VERIFY_WITNESS_V1_512`
    - `VERIFY_SHA512`
  - initially changed `tidecoin/src/consensus_validation.rs` so Tidecoin-only flags and `p2wsh512` outputs returned explicit unsupported errors instead of being forwarded to upstream `bitcoinconsensus`
- Remaining open risks:
  - interpreter/runtime support for `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, and PQ corpus execution is still missing

### Phase 19

- State: `done`
- Objective: remove the stale `bitcoinconsensus` validation surface from the live Tidecoin crate
- Completed in this phase:
  - removed the `bitcoinconsensus` dependency and feature from [tidecoin/Cargo.toml](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/Cargo.toml)
  - made [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs) Tidecoin-native only:
    - `ValidationError` is now the public wrapper error
    - public verification no longer dispatches to `bitcoinconsensus`
  - removed the stale `bitcoinconsensus`-gated tests from:
    - [tidecoin/src/blockdata/script/tests.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/script/tests.rs)
    - [tidecoin/src/blockdata/transaction.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/transaction.rs)
  - re-ran verification successfully:
    - `cargo check --workspace`
    - `cargo check -p tidecoin --features tidecoin-node-validation`
    - `cargo test -p tidecoin --lib consensus_validation -- --nocapture`
- Remaining open risks:
  - the imported [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) crate still contains upstream `bitcoinconsensus` and Bitcoin Core differential infrastructure, and remains a migration target rather than the live Tidecoin validation surface

### Phase 14

- State: `done`
- Objective: land the Tidecoin-native validation/runtime surface and close the remaining node PQ corpus gap
- Completed in this phase:
  - added the `tidecoin-node-validation` feature in `tidecoin/Cargo.toml`
  - extended `tidecoin/build.rs` to compile a local node-backed validation bridge from Tidecoin node sources
  - added `tidecoin/c_src/tidecoin_validation_bridge.cpp` and `tidecoin/c_src/randombytes_stub.c` to support the bridge build
  - split validation behavior in:
    - `tidecoin/src/consensus_validation.rs`
    - `tidecoin/src/consensus_validation_node.rs`
    - `tidecoin/src/consensus_validation_tidecoin.rs`
  - routed Tidecoin-only script cases through the node-backed validator while keeping ordinary Bitcoin-compatible scripts on the local fallback path
  - migrated and covered the node PQ execution corpora and tails with executable Rust tests for:
    - `script_tests_pq.json`
    - `tx_valid_pq.json`
    - `tx_invalid_pq.json`
    - `script_assets_test.json`
    - `OP_SHA512`
    - witness-v1-512 policy/runtime cases
    - mixed witness-v0/v1-512 behavior
    - PQ multisig mixed, negative, and limit cases
    - committed-hash mixed and failure cases
    - legacy base-signature verification
  - corrected the feature-matrix gating for the legacy pure-`bitcoinconsensus` tests so both validation configurations remain green
  - re-ran verification successfully:
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo test -p tidecoin --all-features --quiet`
    - `cargo test --workspace`
    - `cargo clippy -p tidecoin --all-features --all-targets -- -D warnings`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
    - `git diff --check`
- Remaining open risks:
  - no confirmed library-scope validation/runtime gaps remain from the tracked Tidecoin protocol port

### Phase 15

- State: `verifying`
- Objective: clean up stale fixture wiring and docs, then align the trackers with the real post-sweep executable-coverage state
- Completed in this phase:
  - fixed the stale `psbt_combined.hex` test wiring in `tidecoin/src/psbt/mod.rs` so the combine regression loads the dedicated combined fixture instead of re-reading `psbt2.hex`
  - removed the remaining confirmed Tidecoin-facing Bitcoin wording in:
    - `tidecoin/src/psbt/mod.rs`
    - `units/src/fee_rate/mod.rs`
    - `base58/README.md`
  - tightened tracker wording around taproot removal so it no longer reads as if explicit rejection markers or historical references must also disappear
  - re-audited the current Rust-vs-node coverage state and recorded that the imported PQ JSON corpora are present, while several direct node executable tests still remain unmigrated
  - re-opened the tracker backlog for the verified direct test tails instead of keeping the tracker at "none open"
  - re-ran targeted verification successfully:
    - `cargo test -p tidecoin combine_psbts -- --nocapture`
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo test -p tidecoin --lib psbt::`
    - `cargo test -p tidecoin-units`
    - `git diff --check`
- Remaining open risks:
  - direct executable coverage still trails the Tidecoin node in the specific suites listed in `VALIDATION_FIX_BACKLOG.md`

### Phase 16

- State: `done`
- Objective: close the reopened direct executable-coverage tails and finish the final verification sweep
- Completed in this phase:
  - fixed the partially landed PQ WIF surface in `tidecoin/src/crypto/key.rs`, re-exported it from `tidecoin/src/lib.rs`, and revalidated:
    - prefixed PQ base58 secret roundtrips across all five schemes
    - legacy Falcon-512 WIF roundtrip behavior
    - mismatched legacy public-key rejection
  - expanded Tidecoin policy parity coverage in `tidecoin/src/policy.rs` for:
    - `spends_witness_prog`
    - `test_IsStandard`
    - `max_standard_legacy_sigops`
    - PQ input-vsize formulas from `pq_txsize_tests.cpp`
  - added public-surface validation regressions in `tidecoin/src/consensus_validation.rs` for PQ legacy base-signature verification through:
    - `verify_script_with_flags`
    - `verify_transaction_with_flags`
    - `TransactionExt::verify_with_flags`
  - updated stale dust-threshold assertions in `tidecoin/src/blockdata/script/tests.rs` to the Tidecoin node’s PQ-aware values
  - closed the reopened executable-coverage backlog after revalidating the tracked direct tails against the current Rust suite
  - completed final verification successfully:
    - `cargo check --workspace`
    - `cargo test --workspace`
    - `cargo check -p tidecoin --all-features --tests --examples`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
    - `git diff --check`
- Remaining open risks:
  - no confirmed library-scope protocol or tracked executable-coverage gaps remain from this validation run

### Phase 17

- State: `done`
- Objective: resolve the final residual node-test tails discovered by the post-push multi-agent audit
- Completed in this phase:
  - fixed PQ bech32 namespace validation in `tidecoin/src/address/mod.rs` so PQ HRPs reject legacy segwit-v0 programs during parsing
  - added explicit PQ bech32 namespace/checksum regression coverage in `tidecoin/src/address/mod.rs`
  - added the exact node legacy-WIF BASE-sighash verification vector and the library-equivalent toolpath regression in `tidecoin/src/consensus_validation_node.rs`
  - expanded node-backed PQ multisig coverage in `tidecoin/src/consensus_validation_node.rs` for:
    - single-scheme direct and wrapped matrices across all five PQ schemes
    - single-scheme committed-hash direct and wrapped matrices across all five PQ schemes
    - `SCRIPT_VERIFY_PQ_STRICT` happy-path regressions
  - expanded policy parity coverage in `tidecoin/src/policy.rs` for:
    - oversized witness-script rejection
    - bare PQ multisig standardness rejection
    - worst-case `20-of-20` ML-DSA-87 standard-weight behavior
  - refreshed Tidecoin-facing key docs in `tidecoin/src/crypto/key.rs`
  - re-ran verification successfully:
    - `cargo test -p tidecoin address:: -- --nocapture`
    - `cargo test -p tidecoin policy::tests -- --nocapture`
    - `cargo test -p tidecoin --features tidecoin-node-validation --lib -- --nocapture`
- Remaining open risks:
  - no confirmed library-scope protocol or residual tracked node-test coverage gaps remain after the post-push audit

### Phase 18

- State: `done`
- Objective: documentation parity sweep, dead code removal, and planned test gap inventory
- Completed in this phase:
  - rewrote root `README.md` from Bitcoin to Tidecoin with AuxPoW/PQ/denomination sections and crate table
  - updated 9 sub-crate READMEs (addresses, hashes, primitives, consensus_encoding, network, p2p, units, io, internals, crypto) to reference Tidecoin
  - updated `CONTRIBUTING.md` with Tidecoin project name, repo URLs, maintainer list, and communication channels
  - updated `docs/README.md`, `docs/crates.md`, `docs/policy.md` to reference Tidecoin
  - removed dead Signet code: `SignetBlockScriptTag`, `SignetBlockScript`/`SignetBlockScriptBuf` types, `From<WitnessScriptBuf>` conversion, and test
  - removed empty `tidecoin/src/taproot/merkle_branch/` directory
  - removed deprecated `from_btc()`/`to_btc()`/`from_int_btc()` methods from `units/src/amount/unsigned.rs` and `units/src/amount/signed.rs`
  - updated test `from_int_btc` to `from_int_tdc` in `units/src/amount/tests.rs`
  - removed stub workspace crates `addresses/` and `crypto/` and dropped them from workspace members
  - removed `api/` directory and `contrib/check-for-api-changes.sh` script
  - removed API CI job from `.github/workflows/rust.yml`
  - recorded planned test gaps in `VALIDATION_FIX_BACKLOG.md`: script validation vectors, AuxPoW validation, subsidy schedule, difficulty retargeting edges, standalone PQ signature operations
  - re-ran verification successfully:
    - `cargo check --workspace`
    - `cargo test --workspace`
- Remaining open risks:
  - planned test gaps recorded in `VALIDATION_FIX_BACKLOG.md` are not yet implemented
