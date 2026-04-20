# API Stabilization Surface Audit

Status: active API-boundary audit, 2026-04-18.

This document inventories every migration-era compatibility surface and
temporary proof-harness surface found in the current workspace. It is meant to
answer a narrow stabilization question:

- what is product/API surface that downstream users may rely on
- what is internal test/dev/provenance machinery
- what historical material must not leak back into active public APIs
- what "legacy" behavior is real Tidecoin compatibility and must not be
  removed just because it has a legacy name

The audit was performed over the current workspace plus the Tidecoin node
checkout configured at:

- `/home/yaroslav/dev/tidecoin/rust-tidecoin`
- `/home/yaroslav/dev/tidecoin/tidecoin`

The local Tidecoin node checkout was clean during this audit and resolved to:

```text
ead72073edf746586e7f4df843ee2d00a014134f
```

## Classification Rules

### Product API

Product API is code that wallets, indexers, mobile clients, libraries, or
applications should be allowed to depend on without knowing the migration
history. Examples include addresses, network params, PQ keys, PQ WIF, PQHD,
descriptors, transaction/script helpers, validation helpers, policy helpers,
and PoW/header validation helpers.

### Migration-Era Compatibility Helper

A migration-era compatibility helper is a shim, name, file, or test helper that
exists because code was transplanted from an older architecture, from an
upstream Bitcoin/Core-oriented proof setup, or from an intermediate Tidecoin
porting stage.

These helpers may be useful internally, but they should not become stable
downstream API unless explicitly re-designed as product API.

### Temporary Proof Harness API

A temporary proof harness API exists to compare Rust behavior against the
Tidecoin C++ node, imported corpora, generated fixtures, or archived proof
classes. These APIs are valuable for correctness, but they are not wallet,
mobile, indexer, or app ergonomics.

The key rule: proof harnesses are allowed to know about `TIDECOIN_NODE_REPO`,
C++ bridge details, fixture files, node source hashes, and parity-only error
mapping. Product APIs should not.

### Real Legacy Protocol Compatibility

Some code uses the word "legacy" because Tidecoin itself has legacy consensus
or wallet behavior. That is not migration trash.

Real protocol compatibility must remain available when the node, historical
wallets, or the chain require it. It should be documented as compatibility
surface, not hidden as proof-harness plumbing.

## Executive Findings

1. The main live proof-harness surface is the
   [`node-parity/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity)
   crate. Its own crate docs state that it is internal test/dev
   infrastructure, not production consensus engine surface.
2. The highest remaining API-stabilization risk is the
   `tidecoin-node-validation` feature in
   [`tidecoin/Cargo.toml`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/Cargo.toml).
   The product validation route no longer depends on it, but the feature still
   exists in crate metadata and test configuration, so it must stay documented
   as dev/parity-only.
3. The migration-era compatibility aliases in
   [`consensus-core/src/error.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/error.rs)
   have now been removed from the live API surface.
4. Active proof coverage is now Tidecoin-node-based. The old
   Bitcoin/Core-oriented proof files are archived under
   [`consensus/tests/archived/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived)
   and documented as historical.
5. Real Tidecoin legacy behavior exists and must not be conflated with
   migration scaffolding. This includes legacy Falcon-512 signatures, legacy
   PQ WIF, legacy sighash behavior, and legacy script find-and-delete behavior.

## Full Inventory

### 1. `node-parity/` Crate

Paths:

- [`node-parity/Cargo.toml`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/Cargo.toml)
- [`node-parity/src/lib.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/lib.rs)
- [`node-parity/src/harness.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/harness.rs)
- [`node-parity/src/error.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/error.rs)
- [`node-parity/src/ffi.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/ffi.rs)
- [`node-parity/src/fixtures.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/fixtures.rs)
- [`node-parity/build.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/build.rs)
- [`node-parity/c_src/tidecoin_validation_bridge.cpp`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src/tidecoin_validation_bridge.cpp)
- [`node-parity/c_src/tidecoin_validation_stub.c`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src/tidecoin_validation_stub.c)
- [`node-parity/c_src/randombytes_stub.c`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src/randombytes_stub.c)

Classification:

- temporary proof harness API
- test/dev infrastructure
- not product API

Current role:

- builds a C/C++ bridge against a local Tidecoin node checkout when
  `TIDECOIN_NODE_REPO` is configured
- otherwise builds a stub bridge that returns failure codes
- exposes `TidecoinNodeHarness` for node-backed parity calls
- maps node script errors and bridge failures through `NodeParityError`
- provides fixture discovery helpers for `TIDECOIN_NODE_REPO/src/test/data`

Bridge surfaces currently covered:

- transaction sanity
- scrypt and yespower mining hashes
- header PoW and AuxPoW context checks
- context-free block checks
- UTXO-independent contextual block checks
- permitted difficulty transition checks
- block subsidy
- PQ input vsize formulas
- PQ key generation, signing, verification, and PQHD keygen
- ML-KEM deterministic keypair, encapsulation, and decapsulation checks
- script assembly parsing
- isolated script-case verification
- serialized transaction-input verification

Stabilization action:

- keep the crate clearly documented as internal test/dev infrastructure
- do not expose it as a recommended dependency for wallets or apps
- avoid making `node-parity` a default feature of any product crate
- keep all node checkout and C++ bridge knowledge out of wallet-facing APIs

Resolved cleanup note:

- the previously orphaned `node-parity/src/build_support.rs` helper has been
  removed from the live tree
- `node-parity/build.rs` is now the single active build integration surface for
  the node bridge

### 2. `tidecoin-node-validation` Feature

Paths:

- [`tidecoin/Cargo.toml`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/Cargo.toml)
- [`tidecoin/src/consensus_validation.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
- [`tidecoin/src/consensus_validation_node.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)
- [`tidecoin/src/consensus_validation_tidecoin.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)

Classification:

- proof-harness-backed feature
- formerly a public API risk
- not a normal downstream feature

Current role:

- `tidecoin-node-validation = ["std", "rand", "dep:node_parity"]`
- public verification APIs now always use the pure Rust
  `consensus-core`-backed implementation
- the feature remains for node-backed parity tests and dev-only adapters
- the old public routing helper has been removed from the product validation
  path

Resolved API issue:

- `tidecoin::consensus_validation` now publicly re-exports stable pure-Rust
  `consensus_core::{ScriptError, TidecoinValidationError}`
- the node-backed bridge no longer changes the public error type identity or
  product backend

Stabilization action:

- treat `tidecoin-node-validation` as a dev/parity feature, not a product
  feature
- document that downstream wallets/apps should not enable it for normal use
- keep the public validation error surface anchored on pure Rust types
- keep `consensus_validation_node` and `consensus_validation_tidecoin` private
  implementation details

Recommended target shape:

- public callers use stable functions such as
  `verify_script`, `verify_script_with_flags`, `verify_transaction`, and
  `verify_transaction_with_flags`
- internal parity tests may opt into node-backed verification
- the public error enum should not expose node bridge implementation details
  except as a clearly dev-only diagnostic path

### 3. Removed Migration Compatibility Constants

Path:

- [`consensus-core/src/error.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/error.rs)

Classification:

- migration-era compatibility helper
- removed from the live shared-core API

Former role:

- short-lived alias constants on `TidecoinValidationError` kept during the
  interpreter transplant

Resolved action:

- direct enum variants are now used everywhere in the live code
- the compatibility aliases no longer remain in the shared-core public surface
- no downstream workspace use was found before removal

### 4. `tidecoin` In-Source Node-Backed Tests

Paths:

- [`tidecoin/src/pow.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/pow.rs)
- [`tidecoin/src/block_validation.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/block_validation.rs)
- [`tidecoin/src/policy.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/policy.rs)
- [`tidecoin/src/blockdata/subsidy.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/subsidy.rs)
- [`tidecoin/src/crypto/pq.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/crypto/pq.rs)
- [`tidecoin/src/consensus_validation.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
- [`tidecoin/src/consensus_validation_node.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)

Classification:

- proof harness usage inside crate tests
- acceptable as tests
- not product API

Current proof areas:

- AuxPoW fixture validation and node bridge comparison
- real testnet header and retarget-window fixtures
- difficulty-transition parity
- yespower and scrypt PoW parity
- UTXO-independent contextual header/block checks
- PQ input vsize formulas
- subsidy schedule parity
- ML-KEM and PQ crypto node-backed checks
- public validation API behavior under node-backed feature
- PQ multisig, committed-hash, script-case, and legacy-WIF node-backed checks

Stabilization action:

- keep tests, but keep their helper APIs private
- do not present node-backed tests as runtime requirements
- where a test helper starts becoming reusable product code, move it behind a
  stable pure-Rust API first
- keep fixture provenance documented and pinned

### 5. `consensus/` Active Parity Tests

Paths:

- [`consensus/Cargo.toml`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/Cargo.toml)
- [`consensus/tests/tidecoin_test_support.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_test_support.rs)
- [`consensus/tests/tidecoin_node_parity.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs)
- [`consensus/tests/tidecoin_runtime_diff.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_runtime_diff.rs)
- [`consensus/tests/tidecoin_script_assets.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets.rs)
- [`consensus/tests/tidecoin_script_assets_generated.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets_generated.rs)
- [`consensus/tests/tidecoin_fixture_hashes.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_fixture_hashes.rs)
- [`consensus/tests/tidecoin_unit_parity.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_unit_parity.rs)
- [`consensus/tests/tidecoin_witness_unit_parity.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_witness_unit_parity.rs)
- [`consensus/tests/tidecoin_sigop_surface.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sigop_surface.rs)
- [`consensus/tests/tidecoin_pq_multisig_parity.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_pq_multisig_parity.rs)
- [`consensus/tests/tidecoin_sighash_vectors.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_vectors.rs)
- [`consensus/tests/tidecoin_random_consistency.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_random_consistency.rs)
- [`consensus/tests/script_parse_parity.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/script_parse_parity.rs)
- [`consensus/tests/script_asm.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/script_asm.rs)

Classification:

- active proof harness tests
- test-only support
- not product API

Current role:

- `consensus` depends on `node_parity` only as a dev-dependency
- `tidecoin_test_support.rs` centralizes fixture parsing, flag parsing, Rust /
  node error mapping, test UTXO construction, and node harness discovery
- active tests compare Rust consensus execution against Tidecoin node fixtures,
  generated assets, randomized cases, and targeted unit surfaces

Stabilization action:

- keep `node_parity` as a dev-dependency only
- do not move `tidecoin_test_support` helpers into library modules unless they
  are redesigned as stable public APIs
- rename "core" / "parity" wording in active test names only if it causes
  developer confusion; the files are test-only
- continue using these tests as proof, but do not require downstream users to
  understand them

Special note:

- `script_asm.rs` preserves a historical textual parser behavior that excludes
  `OP_CHECKSIGADD` from asm token parsing. This is test/parser compatibility,
  not a wallet-facing parser contract unless explicitly promoted later.

### 6. Generated and Provenance Artifacts

Paths:

- [`tidecoin/tests/node_policy_provenance.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/tests/node_policy_provenance.rs)
- [`tidecoin/tests/data/node_policy_provenance_corpus.json`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/tests/data/node_policy_provenance_corpus.json)
- [`tidecoin/contrib/generate_node_policy_provenance_corpus.py`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/contrib/generate_node_policy_provenance_corpus.py)
- [`consensus/tests/data/tidecoin_script_assets_generated_metadata.json`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/data/tidecoin_script_assets_generated_metadata.json)
- [`consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py)
- [`tidecoin/tests/data/auxpow_headers.json`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/tests/data/auxpow_headers.json)
- [`tidecoin/tests/data/testnet_real_headers.json`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/tests/data/testnet_real_headers.json)
- [`tidecoin/tests/data/testnet_retarget_windows.json`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/tests/data/testnet_retarget_windows.json)

Classification:

- active proof/provenance artifacts
- not product API

Current role:

- pin node source commit and source-file hashes
- pin generated corpus metadata
- capture node-derived policy, script, AuxPoW, header, and retarget cases
- prevent silent fixture drift

Stabilization action:

- keep, but document as test/provenance only
- do not expose fixture schemas as stable public formats
- keep generator scripts under `contrib/` or `scripts/`, not crate APIs
- require explicit regeneration when node source commit or fixture hashes change

### 7. Archived Bitcoin/Core-Era Proof Material

Paths:

- [`consensus/tests/archived/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived)
- [`consensus/tests/archived/data/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/data)
- [`consensus/docs/archived/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/docs/archived)
- [`ai-docs/archived/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived)

Classification:

- archived migration history
- historical proof reference only
- not active API

Current role:

- preserves coverage-class intent from the old Bitcoin/Core-diff suite
- documents why old Bitcoin/Taproot/`bitcoinconsensus` assumptions are not
  active Tidecoin acceptance criteria
- gives future audits a way to confirm that proof depth was replaced rather
  than silently discarded

Stabilization action:

- never restore archived files directly into active runtime
- if useful coverage remains, reintroduce it as Tidecoin-native/PQ-native tests
- eventually delete archived proof material only after the active
  Tidecoin-native matrix has enough replacement depth

### 8. `consensus` Product Surface That Is Not Proof Harness

Paths:

- [`consensus/src/lib.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
- [`consensus/src/types.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/types.rs)

Classification:

- product/library API
- not migration trash

Current role:

- byte-oriented Tidecoin consensus verification API
- thin adapter over `consensus-core`
- no runtime dependency on `node-parity`
- no active dependency on upstream `bitcoin` or `bitcoinconsensus`

Stabilization action:

- keep separate from `node-parity`
- stabilize its error and flag behavior as a pure-Rust API
- avoid adding node checkout, fixture, or bridge concepts to this crate

### 9. Real Tidecoin Legacy Compatibility

Paths:

- [`tidecoin/src/crypto/pq.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/crypto/pq.rs)
- [`tidecoin/src/crypto/key.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/crypto/key.rs)
- [`consensus-core/src/pq.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)
- [`consensus-core/src/sighash.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs)
- [`consensus-core/src/interpreter.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)

Classification:

- real protocol/wallet compatibility
- product API or consensus behavior
- not migration-era helper by default

Current examples:

- `PqSecretKey::decode_slice(..., allow_legacy)`
- `PqSignature::sign_msg32_legacy`
- `PqSignature::sign_msg64_legacy`
- `PqSignature::verify_msg32_legacy`
- `PqSignature::verify_msg64_legacy`
- `PqSignature::verify_msg32_allow_legacy`
- `PqSignature::verify_msg64_allow_legacy`
- `PqWifFormat::LegacyFalcon512`
- legacy signature hash support
- script find-and-delete behavior where consensus flags allow it

Stabilization action:

- keep these surfaces if they are needed for node, chain, or wallet
  compatibility
- document them as compatibility behavior
- avoid calling them "migration helpers"
- for new wallet APIs, prefer canonical strict/prefixed formats while still
  supporting required historical import/verification paths

### 10. False Positives Found During Search

These were found by broad keyword searches but should not be treated as
migration/proof-harness cases:

- [`io/src/bridge.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/io/src/bridge.rs):
  standard I/O adapter bridge, not node parity
- [`internals/src/array_vec.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/internals/src/array_vec.rs):
  `kani::proof` formal proof annotations, not Tidecoin-node proof harness
- [`internals/src/const_casts.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/internals/src/const_casts.rs):
  "const-compatible" conversion helpers, not migration compatibility helpers
- [`consensus_encoding/tests/api.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus_encoding/tests/api.rs)
  and [`io/tests/api.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/io/tests/api.rs):
  dyn-compatibility API tests, not migration compatibility shims
- [`fuzz/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/fuzz):
  active fuzz coverage, not temporary proof harness by itself

## Stabilization Recommendations

### Before Publishing API Expectations

1. Keep `tidecoin-node-validation` documented as a dev/parity-only feature,
   not a normal product feature.
2. Add explicit crate docs saying:
   - `node-parity` is not product API
   - `TIDECOIN_NODE_REPO` is test/provenance infrastructure
   - fixtures and generated metadata are not stable external formats
3. Keep real legacy Falcon/PQ WIF/sighash behavior as compatibility surface,
   not cleanup target.

### Public API Rule

Downstream users should be able to build Tidecoin software with:

- `tidecoin`
- `consensus`
- `consensus-core` only where low-level verification control is required
- stable lower crates such as `primitives`, `units`, `hashes`, and `encoding`

They should not need:

- `node-parity`
- `TIDECOIN_NODE_REPO`
- C++ bridge details
- archived Bitcoin/Core files
- fixture hash metadata
- generated corpus internals
- migration-era compatibility constants

### Documentation Rule

User-facing examples should use stable pure-Rust APIs. Node-backed examples
belong only in developer/provenance docs and test-running instructions.

## Audit Search Notes

The inventory was built by scanning for:

- `compat`, `compatibility`, `migration`, `transplant`, `shim`
- `proof`, `harness`, `parity`, `fixture`, `corpus`, `provenance`
- `bridge`, `node-validation`, `node_parity`, `TIDECOIN_NODE_REPO`
- `fallback`, `route`, `generated`, `archived`
- `legacy`, followed by manual classification into real protocol
  compatibility versus migration scaffolding

The broad search intentionally included false positives. The classification
above is the result of manually separating those false positives from real
stabilization risks.
