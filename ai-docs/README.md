# AI Docs Master Plan

This file is the single source of truth for active development planning in this
repository.

If another development note disagrees with this file, this file wins.

## Agent Read Order

Read only this set first:

1. This file.
2. [VALIDATION_FIX_BACKLOG.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/VALIDATION_FIX_BACKLOG.md)
3. One task-specific doc:
   - protocol/parity: [NODE_CONSENSUS_SETTINGS_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_CONSENSUS_SETTINGS_AUDIT.md),
     [PROTOCOL_NODE_PARITY_READINESS.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/PROTOCOL_NODE_PARITY_READINESS.md),
     [NODE_PARITY_PROOF_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_PARITY_PROOF_MATRIX.md)
   - wallet/API ergonomics: [WALLET_API_ROADMAP.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/WALLET_API_ROADMAP.md)
   - API surface cleanup: [API_STABILIZATION_SURFACE_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/API_STABILIZATION_SURFACE_AUDIT.md)

Open supporting refs only if the task needs them. Ignore `ai-docs/archived/`
unless an active doc explicitly sends you there.

## Current Situation

The repository has moved well past the original "port from rust-bitcoin" phase.
Most Tidecoin protocol-library work is already implemented and validated against
the Tidecoin node.

The main open problem is now coverage and boundary maintenance, not the original
extraction:

- the top-level [`tidecoin`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) crate owns public validation orchestration and key/signing ergonomics
- the standalone [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) crate is now a Tidecoin-native byte-oriented wrapper over the shared engine in [`consensus-core/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core)
- the shared Tidecoin consensus core owns the interpreter, typed transaction context, sighash, PQ verification facade, and witness execution planning
- the shared Tidecoin consensus core now also owns the reusable typed
  verification facade used by both the top-level `tidecoin` crate and the
  byte-oriented `consensus` crate
- the canonical Tidecoin script representation/parsing/building layer now lives in
  [`primitives/src/script/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/script)
  and is consumed by both [`consensus-core/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core)
  and the top-level [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) crate;
  the top-level `blockdata/script` layer is now a higher-level Tidecoin
  convenience layer instead of a second competing script implementation
- the canonical Tidecoin opcode layer now also lives in
  [`primitives/src/opcodes.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/opcodes.rs);
  [`tidecoin/src/blockdata/opcodes.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/opcodes.rs)
  is now only a public reexport layer, not a second opcode implementation
- the top-level pure-Rust fallback in
  [tidecoin/src/consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)
  is now a thin adapter over `consensus-core`
- the public
  [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
  facade now always uses the pure-Rust shared engine; the node bridge remains
  available only for explicit parity tests and dev-only adapters
- the historical reader/writer codec compatibility layer has been retired;
  the `tidecoin::consensus` codec namespace has been removed rather than
  preserved as a reexport layer, while canonical type codecs live with their
  owning lower crates and callers use
  [`consensus_encoding/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus_encoding)
  APIs directly
- the Tidecoin node-backed bridge/parity surface is shared between `tidecoin`
  and `consensus/` through
  [`node-parity/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity)
- chain-level coverage still has real gaps: node-generated AuxPoW fixtures and
  deeper historical difficulty vectors remain open; node-style target
  derivation, params/height-aware yespower/scrypt PoW validation, heightless
  `CheckProofOfWorkAny` parity, AuxPoW context rules, subsidy schedule, and
  difficulty transition envelopes now follow the node's active semantics with
  focused tests

For consensus/protocol development, that is the primary workstream now.

Priority rule for the next phase:

- for consensus/protocol work, first fill chain-rule coverage gaps against the
  Tidecoin node, especially node-generated AuxPoW fixtures, target-check APIs,
  and deeper historical difficulty-vector coverage
- for wallet-facing crate development, use
  [`WALLET_API_ROADMAP.md`](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/WALLET_API_ROADMAP.md)
  and build on the existing key, address, script, weight, fee, and validation
  primitives instead of duplicating them
- reconcile the archived proof-class matrix against the active Tidecoin-native
  tests before deleting historical consensus files
- keep auditing new wrapper code for real duplicate validation/protocol logic,
  but do not re-open completed `consensus-core` extraction decisions

Audit rule for that work:

- audit consensus-sensitive behavior against the actual Tidecoin core node checkout at `~/dev/tidecoin/tidecoin`
- treat the Tidecoin node as the primary source of truth
- treat the already-ported [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) crate as secondary internal evidence
- do not use upstream Bitcoin or `bitcoinconsensus` behavior as the acceptance standard
- BIP-labeled chain parameter names may stay only where they match active
  Tidecoin node consensus parameter names; they are node-parity identifiers,
  not upstream Bitcoin compatibility promises

Type-system rule for that work:

- semantic parity is not enough on its own
- the imported [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) crate must not keep live dependencies on upstream `bitcoin` transaction/script/sighash types and helpers
- the end state is Tidecoin-native runtime behavior on Tidecoin-native types, with shared lower crates used where practical

Current status note:

- the live `consensus` crate no longer depends on upstream `bitcoin::*` or `bitcoinconsensus`
- active fixture parity is Tidecoin-node-based
- the live interpreter/typed tx engine now lives in `consensus-core`, not in `consensus/src/`
- the shared typed verification facade now also lives in `consensus-core`, so
  both public validation adapters execute the same engine pipeline
- the completed top-level validation audit and adapter refactor are captured in
  [TIDECOIN_VALIDATION_CORE_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived/TIDECOIN_VALIDATION_CORE_AUDIT.md)
- the current node-vs-Rust consensus/settings gap audit is captured in
  [NODE_CONSENSUS_SETTINGS_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_CONSENSUS_SETTINGS_AUDIT.md)
- the current definition of protocol-crate node parity, and the boundary between
  "ready now" and future UTXO/mempool crates, is captured in
  [PROTOCOL_NODE_PARITY_READINESS.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/PROTOCOL_NODE_PARITY_READINESS.md)
- the executable proof matrix that maps node validation surfaces to Rust tests
  and fuzz targets is captured in
  [NODE_PARITY_PROOF_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_PARITY_PROOF_MATRIX.md)
- archived Bitcoin/Core-era materials remain only as historical reference

Current API cleanup note:

- the main remaining public-surface rough edge is hidden-but-public network
  conversion traits leaking through constructor signatures in
  `tidecoin/src/crypto/key.rs` and `tidecoin/src/address/mod.rs`
- `consensus-core` still exports more low-level engine internals than the
  current internal-use posture strictly needs, but this is not an immediate
  correctness problem
- product validation now cleanly distinguishes malformed serialized
  transactions from engine-level verification failures; `UnsupportedScript` has
  been removed from the live shared-core contract
- remaining validation-error work is documentation quality and boundary
  clarity, not another structural refactor

## Master Status

### Done

- The main crate directory was renamed from `bitcoin/` to [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin), and the workspace/path references were updated.
- The first `tidecoin-consensus-core` extraction slice is in place:
  - [`consensus-core/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core) exists in the workspace
  - shared validation flags live there now
  - the pure-Rust validation error types live there now
  - the verification-only PQ facade lives there now
  - shared witness-program parsing now lives there too
  - shared witness-program version/length/flag classification now lives there too
  - shared witness execution planning now lives there too
  - the shared script interpreter now lives there too in
    [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  - the shared typed transaction context/precompute layer now lives there too in
    [consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
- The Tidecoin script-layer ownership is now explicit and enforced:
  - canonical instruction parsing, push-bytes handling, script-buffer mutation,
    and lower builder logic live in
    [primitives/src/script/](/home/yaroslav/dev/tidecoin/rust-tidecoin/primitives/src/script)
  - [tidecoin/src/blockdata/script/](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/blockdata/script)
    now wraps that lower layer for Tidecoin-specific conveniences such as key,
    locktime, policy, and witness-program ergonomics
  - the duplicated top-level instruction and push-bytes implementation files
    were removed
- A verification-only sighash subset now lives in
  [consensus-core/src/sighash.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/sighash.rs)
  and the pure-Rust Tidecoin validator uses it.
- Tidecoin-specific PQ crypto surface is implemented and node-checked.
- Tidecoin-specific validation/runtime behavior exists in:
  - [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
  - [tidecoin/src/consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)
  - [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)
- The top-level pure-Rust Tidecoin fallback no longer owns a second
  interpreter:
  - [tidecoin/src/consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)
    is now a thin adapter over:
    - [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
    - [consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
  - duplicate top-level interpreter helpers were deleted
- The top-level reader/writer consensus codec implementation and the temporary
  I/O compatibility crate were removed as competing implementations:
  - the old `tidecoin::consensus` codec namespace was deleted instead of being
    kept as an API-compatibility reexport
  - P2P message framing now uses
    [p2p/src/message.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/p2p/src/message.rs)
    and the shared codec traits directly, instead of a parallel reader/writer
    implementation
  - known P2P framing polish remains: V1 currently performs one no-allocation
    planning pass to compute payload length/checksum and a second pass to emit
    the payload, because the frame header commits to payload metadata before
    the payload bytes; this is not duplicate transaction/block codec logic
  - raw transaction deserialization remains non-semantic: duplicate-input and
    missing-output rejection belongs in validation, not in byte decoding
- The top-level [`tidecoin`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) crate no longer depends on or routes through `bitcoinconsensus`.
  - its public validation surface is now Tidecoin-native only
- The first `consensus/` runtime conversion slice is in place:
  - [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs) now exposes Tidecoin-shaped public flags and default verification behavior
  - the public flag surface now includes `PQ_STRICT`, `WITNESS_V1_512`, and `SHA512`
  - default verification no longer enables Taproot
  - `height_to_flags(...)` is no longer Bitcoin-height-based and now has an auxpow-aware helper
  - the mature interpreter and typed tx/precompute engine were moved wholesale into:
    - [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
    - [consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
  - [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs) is now the thin byte-oriented wrapper over that engine
  - the old local engine files `consensus/src/script.rs` and `consensus/src/tx.rs` have been removed
  - the shared engine now uses Tidecoin witness-v1-512 semantics, `consensus_core::SighashCache`, Tidecoin-native transaction/witness/amount types, and the shared PQ verification facade
  - active `consensus` runtime, tests, and manifests no longer depend on upstream `bitcoin::*` or `bitcoinconsensus`; the remaining Bitcoin-era proof files are archived only
  - legacy Bitcoin-only validation flags removed from the live `consensus` surface:
    - `VERIFY_DERSIG`
    - `VERIFY_LOW_S`
    - `VERIFY_STRICTENC`
  - `OP_CHECKSIGADD` is now rejected again as a disabled opcode in the Tidecoin witness-v1-512 path
  - the shared interpreter in `consensus-core` now consumes `consensus_core::{PqPublicKey, PqSignature}` instead of depending directly on the top-level `tidecoin` crate
  - fake Bitcoin-only public/runtime flags removed from `consensus`:
    - `VERIFY_TAPROOT`
    - `VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`
    - `VERIFY_DISCOURAGE_OP_SUCCESS`
    - `VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE`
    - `VERIFY_WITNESS_PUBKEYTYPE`
  - the largest Taproot/Tapscript-heavy unit block in [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs) has been replaced with Tidecoin witness-v1-512 coverage
  - current validation:
    - `cargo test -p tidecoin-consensus-core --lib -- --nocapture`
    - `cargo check -p consensus`
    - `cargo check -p consensus --tests`
    - `cargo test -p consensus --lib -- --nocapture`
    - `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin cargo test -p consensus --test tidecoin_node_parity -- --nocapture`
    - `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin cargo test -p consensus --test tidecoin_runtime_diff -- --nocapture`
    - `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin cargo test -p consensus --test tidecoin_script_assets -- --nocapture`
    - `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin cargo test -p consensus --test tidecoin_fixture_hashes -- --nocapture`
    - `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin cargo test -p consensus --test tidecoin_unit_parity -- --nocapture`
    - `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin cargo test -p consensus --test tidecoin_sigop_surface -- --nocapture`
    - `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin cargo test -p consensus --test tidecoin_witness_unit_parity -- --nocapture`
    - `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin cargo test -p consensus --test tidecoin_sighash_vectors -- --nocapture`
    - `cargo test -p consensus --test tidecoin_sighash_cache_randomized -- --nocapture`
    - `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin cargo test -p consensus --test tidecoin_sighash_vectors --test tidecoin_sighash_cache_randomized -- --nocapture`
    - `TIDECOIN_NODE_REPO=~/dev/tidecoin/tidecoin cargo test -p consensus --test tidecoin_pq_multisig_parity -- --nocapture`
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now also has a Tidecoin-native PQ multisig parity suite in
    [consensus/tests/tidecoin_pq_multisig_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_pq_multisig_parity.rs),
    covering:
    - single-scheme PQ multisig matrix parity
    - mixed-scheme direct and wrapped parity
    - negative ordering / outsider / wrong-sighash cases
    - `NULLDUMMY`, `NULLFAIL`, push-size, and pubkey-count edges
    - strict-mode positive Falcon512 coverage
  - a small set of removed Bitcoin/ECDSA-era unit surfaces is now explicitly deferred for PQ-native replacement:
    - witness-v0 code-separator sighash coverage
    - witness-v0 raw hashtype coverage
    - explicit witness amount authority coverage
    - legacy code-separator signature coverage
    - the old Bitcoin-only multisig intermediate-mismatch edge case
- The node-backed bridge ownership is now explicit:
  - keep the Tidecoin bridge semantics and Tidecoin-node truth
  - keep the bridge in the shared internal parity harness
  - keep that parity harness outside `tidecoin-consensus-core`
- The shared node-parity extraction is in place:
  - [`node-parity/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity) exists in the workspace
  - shared `ScriptError` mapping lives there now
  - raw bridge FFI declarations live there now
  - shared Tidecoin node fixture-path helpers live there now
  - the native Tidecoin node bridge is now built by [node-parity/build.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/build.rs), so any consumer of `node-parity` links the same shim
  - native bridge sources now live in [node-parity/c_src/](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src)
  - a first byte-oriented [TidecoinNodeHarness](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/src/harness.rs) exists
  - [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs) is now an adapter over that harness for:
    - transaction-input verification
    - transaction sanity checks
    - script-ASM parsing
    - isolated script-case verification
    - PQ/PQHD parity helper calls used by the node-backed tests
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now has shared-harness Tidecoin parity coverage in
    [consensus/tests/tidecoin_node_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_node_parity.rs)
    covering:
    - `script_tests_pq.json`
    - `tx_valid_pq.json`
    - `tx_invalid_pq.json`
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now also has a Tidecoin-native runtime diff/error suite in
    [consensus/tests/tidecoin_runtime_diff.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_runtime_diff.rs)
    covering:
    - script corpus accept/reject parity
    - script-error parity
    - tx corpus accept/reject parity
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now has a Tidecoin-native `script_assets` replacement in
    [consensus/tests/tidecoin_script_assets.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets.rs),
    replaying the Tidecoin node `script_assets_test.json` corpus with the same
    subset/superset monotonicity rules the node uses
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now also has a Tidecoin-native generated large-corpus/provenance replacement in
    [consensus/tests/tidecoin_script_assets_generated.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets_generated.rs),
    deriving a larger script-assets corpus from the active node
    `tx_valid_pq.json` and `tx_invalid_pq.json`, pinning it with
    [consensus/tests/data/tidecoin_script_assets_generated_metadata.json](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/data/tidecoin_script_assets_generated_metadata.json),
    and generating that metadata through
    [consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/scripts/generate_tidecoin_script_assets_generated_metadata.py)
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now has a Tidecoin-native fixture integrity gate in
    [consensus/tests/tidecoin_fixture_hashes.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_fixture_hashes.rs),
    pinning the active node corpora:
    - `script_tests_pq.json`
    - `tx_valid_pq.json`
    - `tx_invalid_pq.json`
    - `script_assets_test.json`
    - `sighash.json`
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now has a Tidecoin-native unit parity suite in
    [consensus/tests/tidecoin_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_unit_parity.rs),
    covering:
    - `ScriptNum` creation/operator matrices
    - P2SH detection
    - P2SH no-recurse and switchover behavior
    - Tidecoin-node parity for the runtime cases when the node checkout is available
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now has a Tidecoin-native sigop surface suite in
    [consensus/tests/tidecoin_sigop_surface.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sigop_surface.rs),
    covering:
    - native P2WPKH witness toggles
    - native P2WSH witness toggles
    - P2SH-P2WSH witness toggles
    - Tidecoin-node parity for those runtime cases
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now has a Tidecoin-native witness unit parity suite in
    [consensus/tests/tidecoin_witness_unit_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_witness_unit_parity.rs),
    covering:
    - wrapped-witness detection surface
    - wrong-length / empty / mismatch witness cases
    - witness malleation / unexpected-witness cases
    - Tidecoin-node parity for those runtime cases
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now has a Tidecoin-native sighash vector runner in
    [consensus/tests/tidecoin_sighash_vectors.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_vectors.rs),
    replaying the active node `sighash.json` corpus on lower Tidecoin types and
    the lowered `consensus_core::SighashCache`
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now also has a Tidecoin-native deep sighash suite in
    [consensus/tests/tidecoin_sighash_cache_randomized.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_sighash_cache_randomized.rs),
    covering:
    - randomized legacy sighash equivalence on lowered Tidecoin transaction/script types
    - cache-vs-no-cache parity for BASE and witness-v0 sighash computation
  - [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) now also has a Tidecoin-native randomized differential suite in
    [consensus/tests/tidecoin_random_consistency.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_random_consistency.rs),
    covering:
    - deterministic random legacy/P2SH/witness-v0/witness-v1-512 script shapes
    - Tidecoin-node accept/reject and script-error parity
    - Tidecoin-only flags and opcode surface, with no Bitcoin/Taproot assumptions
  - [`consensus/tests/tidecoin_runtime_diff.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_runtime_diff.rs)
    now also reports exercised:
    - Tidecoin flag tokens
    - normalized flag bits
    - flag combinations
    - Rust/node error-class distributions
- shared Tidecoin fixture/token/error support for the active parity tests now
  lives in [consensus/tests/tidecoin_test_support.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_test_support.rs)
- PQ/Falcon runtime parity work tracked in this repo is effectively closed.
- The old port-validation prompt is archived.

### Open

- Keep lowering any still-reusable validation/runtime helpers from the
  top-level [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin)
  crate into [`consensus-core/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core)
  where they are truly shared engine responsibilities.
- Simplify the remaining wrapper/error seams in the top-level validation path,
  especially around public fallback-error mapping and node-backed error
  adaptation.
- Delete the archived Bitcoin/Core-era materials later; they are temporary
  migration reference only and not part of the intended steady-state repo.
- Reconcile the archived `consensus` proof classes against Tidecoin/PQ-native
  replacements before deleting the historical files.
- Keep the Tidecoin node as the only external parity target.
- Keep explicitly archived Bitcoin/Core-diff tests archived unless they are
  being rewritten as Tidecoin-native parity coverage.
- Preserve the archived suite's proof depth by replacing its coverage classes,
  not by accepting a smaller Tidecoin test surface.
- Keep expanding the proof surface until the archived depth is matched,
  especially any remaining stale fixture debt and any still-useful targeted cases.
- Add chain-level parity coverage that remains open below the script
  interpreter: AuxPoW validation, yespower mining hash, target-check APIs, and
  broader difficulty retargeting vectors.
- Keep the fuzz surface aligned with the Tidecoin node fuzz targets. Current
  Rust cargo-fuzz coverage includes stateless transaction/policy, script-policy,
  consensus script runtime, txout policy, block-sanity, and PoW targets;
  UTXO-backed `coins_view` and package-policy fuzz belong to the future
  chain-connect/mempool validation crate.

## Master Plan

### Phase 1: Rename `bitcoin/` To `tidecoin/`

Goal:
- align the repository layout with the actual Tidecoin identity of the main crate before deeper architecture work continues

Checklist:
- [x] Rename `bitcoin/` to `tidecoin/`.
- [x] Update root workspace members.
- [x] Update local path dependencies.
- [x] Update docs and scripts that reference `bitcoin/`.
- [x] Re-run workspace validation after the rename.

### Phase 2: Establish The Shared Core Boundary

Goal:
- define the new `tidecoin-consensus-core` crate before more migration work happens

Checklist:
- [x] Decide the crate name and workspace location.
- [x] Define what belongs in the shared core.
- [x] Define what must stay out of the shared core.
- [x] Confirm the dependency direction:
  - low-level Tidecoin crates -> `tidecoin-consensus-core`
  - top-level `tidecoin` crate -> `tidecoin-consensus-core`
  - compatibility-facing `consensus` crate -> `tidecoin-consensus-core`
- [x] Confirm the Tidecoin node remains the only external parity reference.
- [x] Lower the consensus sighash engine into `tidecoin-consensus-core`.
- [x] Lower witness-program consensus classification and execution planning
  into `tidecoin-consensus-core`.
- [x] Lower PQ verification into `tidecoin-consensus-core`.
- [ ] Continue auditing only real remaining facade leakage from the top-level
  crate; signing/keygen/key I/O and user-facing helpers stay high-level unless
  the Tidecoin node requires them for consensus validation.

The shared core should contain:
- verification flags and supported-flag checks
- script error types
- script interpreter / evaluator
- consensus-critical sighash logic
- witness-v0 and witness-v1-512 validation logic
- `OP_SHA512`
- PQ verification glue
- transaction input verification helpers

The shared core should not contain:
- wallet logic
- descriptors
- address encoding/decoding
- P2P or RPC code
- node runtime code
- repo-specific test harness glue
- native Tidecoin-node bridge build/FFI code

### Phase 3: Extract The Shared Node-Parity Harness

Goal:
- move Tidecoin node-backed parity infrastructure into a shared internal support layer that both `tidecoin` and `consensus/` tests can reuse

Checklist:
- [x] Freeze the scope:
  - test/dev support only
  - not part of `tidecoin-consensus-core`
  - not a public end-user API
- [x] Create the shared harness crate.
- [x] Move native bridge sources into [`node-parity/c_src/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/node-parity/c_src).
- [x] Move node build wiring into the shared parity crate.
- [x] Move raw FFI declarations out of
  [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs).
- [x] Move shared error mapping and fixture helpers out of
  [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs).
- [x] Introduce a first reusable harness API for:
  - script/input verification
  - script-ASM parsing
  - transaction sanity checks
  - PQ deterministic parity helpers
- [x] Rewire the first existing Tidecoin node-backed test helpers to use the shared harness.
- [x] Finish migrating the remaining Tidecoin node-backed helper surface to the shared harness.
- [x] Make the first `consensus/` test consume the shared Tidecoin node-parity harness.
- [x] Cover the first Tidecoin script and transaction corpora in `consensus/` via the shared harness.
- [x] Replace the Bitcoin-specific `core_diff_bridge` path in `consensus/` with the shared Tidecoin harness.
  - done: active `consensus/` parity tests use the shared Tidecoin harness, and
    the explicitly Bitcoin/Core-diff integration files were moved to
    [consensus/tests/archived/](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived)
    after the live runtime stopped supporting their flag/error model
  - open: reconcile archived proof classes against the Tidecoin-native coverage
    matrix before deleting the historical reference files

### Phase 4: Extract From The Current Top-Level Crate

Goal:
- move consensus-critical logic out of the current top-level crate internals into the shared core

Checklist:
- [x] Audit [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs).
- [x] Audit [tidecoin/src/consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs).
- [x] Audit [tidecoin/src/consensus_validation_node.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs).
- [x] Decide which parts are:
  - shared-core logic
  - top-level ergonomic wrappers
  - node-bridge-specific code
- [~] Move shared logic into the new core crate.
  - done: the duplicate pure-Rust fallback interpreter was removed from
    [tidecoin/src/consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)
    and replaced with a thin adapter over `consensus-core`
  - open: continue reviewing only new or still-unclear wrapper/error seams;
    do not replay the already-completed interpreter extraction
- [x] Rewire the top-level crate to depend on the shared core.

### Phase 5: Rebase The Imported `consensus/` Crate

Goal:
- stop treating the imported `consensus/` crate as an independent Bitcoin-style interpreter project

Execution rule:
- runtime/API migration in [`consensus/src/lib.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs) comes first
- broad retirement of `consensus/tests/core_diff_bridge.rs` consumers has been
  completed for the active test surface; the remaining task is coverage-matrix
  reconciliation against the archived proof material

Checklist:
- [x] Audit `consensus/src/lib.rs` for Bitcoin/Taproot/`bitcoinconsensus` assumptions and classify each as `delete`, `rewrite`, or `replace via consensus-core`.
- [x] Apply the first public-runtime conversion slice in `consensus/src/lib.rs`.
- [x] Apply the first transaction-precompute conversion slice and complete the engine move into `consensus-core`.
- [x] Produce the first runtime audit map for `consensus/src/lib.rs` and the shared engine boundary against the Tidecoin node.
- [x] Remove the assumption that `consensus/` should depend directly on the top-level `tidecoin` crate.
- [x] Remove the temporary direct `tidecoin` dependency previously used for PQ verification types by lowering that facade into shared core.
- [x] Make `consensus/` depend on `tidecoin-consensus-core`.
- [x] Remove upstream `bitcoin` runtime types/helpers from `consensus/src/**` by migrating onto lower Tidecoin-native shared crates:
  - done for the active runtime/test surface
  - archived historical files remain reference-only and are outside the active runtime surface
- [x] Make the first `consensus/` test depend on the shared Tidecoin node-parity harness.
- [~] Migrate the rest of `consensus/` differential tests onto the shared Tidecoin node-parity harness.
  - done: shared script/tx corpus parity, runtime diff/error suite, PQ multisig parity, script-assets replay, generated large-corpus/provenance, and fixture pinning
  - open: archived proof materials are temporary and should be deleted later
- [x] Remove the old `tidecoin::consensus` codec compatibility API; codec callers now use
  `tidecoin-consensus-encoding` names directly, and serde callers use the lower-level
  `primitives::serde_as_consensus` adapter directly.
- [x] Replace Bitcoin-only public flags and behavior with Tidecoin semantics.
- [x] Replace the active witness-v1 runtime path with Tidecoin witness-v1-512 program semantics.
- [x] Remove the largest Taproot/Tapscript fixture block from `consensus/src/lib.rs` and replace it with Tidecoin witness-v1-512 tests.
- [x] Remove the remaining Taproot/Tapscript/Schnorr placeholder flags and compatibility shims from runtime code.
  - done: fake Taproot/public-key-type flag bits removed
  - done: temporary ECDSA fallback removed from the active interpreter
  - open: archived historical materials are temporary and should be deleted later

### Phase 6: Replace The Bitcoin-Shaped Test Surface

Goal:
- re-anchor the imported `consensus/` crate on Tidecoin semantics and Tidecoin node parity

Checklist:
- [x] Remove or rewrite Bitcoin Core / `bitcoinconsensus` differential tests from the active test surface.
- [x] Archive the explicitly Bitcoin/Core-diff integration suite that no longer
  matches the live runtime:
  - `core_bip341_wallet_vectors.rs`
  - `core_fixture_hashes.rs`
  - `core_cpp_runtime_diff.rs`
  - `core_diff_bridge.rs`
  - `core_multisig_unit_parity.rs`
  - `core_script_p2sh_unit_parity.rs`
  - `core_script_segwit_detection_parity.rs`
  - `core_scriptnum_unit_parity.rs`
  - `core_sighash_cache_parity.rs`
  - `core_sighash_randomized.rs`
  - `core_sighash_vectors.rs`
  - `core_sigop_surface.rs`
  - `core_tx_vectors.rs`
  - `core_witness_unit_parity.rs`
  - `random_consistency.rs`
  - `script_assets.rs`
  - `script_vectors.rs`
  - `verification_bench.rs`
  - `core_cpp_helper/`
- [ ] Rebuild the archived proof classes with Tidecoin-native replacements as
  tracked in
  [ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md).
  - done: first runtime diff/error replacement landed in
    [consensus/tests/tidecoin_runtime_diff.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_runtime_diff.rs)
  - done: first `script_assets` replacement landed in
    [consensus/tests/tidecoin_script_assets.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets.rs)
  - done: PQ multisig replacement landed in
    [consensus/tests/tidecoin_pq_multisig_parity.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_pq_multisig_parity.rs)
- [x] Remove or rewrite Taproot-specific fixtures and tests from the active test surface.
- [x] Import Tidecoin node fixtures:
  - [x] `script_tests_pq.json`
  - [x] `tx_valid_pq.json`
  - [x] `tx_invalid_pq.json`
  - [x] direct node-backed use of `script_assets_test.json`
  - [x] Tidecoin-native generated large-corpus/provenance replacement derived from `tx_valid_pq.json` and `tx_invalid_pq.json`
  - [x] active `sighash.json` replay through lowered Tidecoin types
  - [x] archive the stale vendored
    [consensus/tests/archived/data/script_assets_test.json](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/data/script_assets_test.json)
  - [x] archive the old Core-era roadmap at
    [consensus/docs/archived/integration-roadmap.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/docs/archived/integration-roadmap.md)
  - [x] archive the remaining Core-era corpora under
    [consensus/tests/archived/data](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/data),
    leaving only active Tidecoin-generated metadata in `consensus/tests/data`
- [x] Rewrite token/flag parsing around:
  - `PQ_STRICT`
  - `WITNESS_V1_512`
  - `SHA512`
- [ ] Keep only local invariant tests that still make sense under Tidecoin semantics.

### Phase 7: Finish The Remaining Lower-Level Coverage

Goal:
- cover chain-rule areas that remain under-tested once the shared core exists

Checklist:
- [~] AuxPoW validation vectors
  - current state: wire structures/codecs stay in `primitives`
  - current state: `tidecoin::pow::validate_auxpow_context` covers the
    node-shaped pure-header context rules, including flag/payload consistency,
    activation, strict chain ID, merge-mining commitment shape, deterministic
    chain index, and parent scrypt PoW verification
  - current state: the node-parity bridge now exposes a focused
    `HasValidProofOfWork`-style header PoW path without linking full
    `validation.cpp`
  - current state: `tidecoin/tests/data/auxpow_headers.json` contains
    node-generated regtest AuxPoW fixtures for the Rust validator and the
    node-parity header PoW bridge, covering valid AuxPoW, parent PoW failure,
    wrong chain ID, parent chain ID collision, wrong chain index, invalid
    transaction merkle branch, invalid chain merkle branch, missing chain merkle
    root, missing and duplicated merged-mining headers, misplaced merged-mining
    header, merkle-size mismatch, missing size/nonce metadata, testnet
    activation acceptance, pre-activation rejection, and missing payload decode
    rejection
  - current state: `tidecoin/tests/data/testnet_retarget_windows.json` now
    includes active-chain RPC testnet headers for genesis-to-activation legacy
    min-difficulty walk-back, activation, the first local AuxPoW payload, an
    early post-AuxPoW span, and later AuxPoW spans through height 16120;
    mainnet AuxPoW vectors do not apply while mainnet AuxPoW activation is
    disabled
  - remaining gap: add any remaining historical real-chain edge fixtures if
    they are discovered in node data
- [~] yespower/scrypt PoW-hash selection and target-check vectors
  - current state: `validate_pow_at_height` now mirrors the node-shaped
    pure-header check by deriving target validity from `nBits`, selecting the
    height-dependent Tidecoin mining hash, and checking that hash against the
    header target
  - current state: `HeaderExt::validate_pow` remains the expected-target facade
    for callers that have also computed the contextual difficulty target
  - current state: the node-parity bridge now exposes node yespower and scrypt
    pure-header hash oracles, and tests pin both hash classes plus the
    pure-header validation entry point, height-aware `CheckProofOfWork`
    pass/fail cases, heightless `CheckProofOfWorkAny` pass/fail cases, and
    AuxPoW parent proof path against node-shaped C++ bridge data
  - current state: real testnet retarget windows now cover genesis-to-activation
    legacy min-difficulty walk-back, activation, first local AuxPoW payload, and
    active-chain post-AuxPoW header spans through height 16120
  - remaining gap: broader historical target-check vectors outside the active
    chain fixture set are still open
- [x] Subsidy/reward schedule tests
  - current state: `tidecoin::subsidy::block_subsidy` implements the node's
    doubling-interval quartering schedule, and Rust tests mirror the node's
    transition-boundary checks plus the pinned total subsidy through height
    `14_000_000`
  - current state: node-bridge subsidy coverage walks every representable
    transition boundary for mainnet, testnet, and regtest
  - scope boundary: coinbase reward-claim validation remains deferred with
    UTXO/chain-connect work because the node check depends on transaction fees
  - design handoff: future chain-connect ownership is specified in
    [CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md)
- [~] Difficulty retargeting edge-case tests
  - current state: `tidecoin::pow::next_target_after` now switches at
    `auxpow_start_height`, uses the node legacy overflow-guarded scaling path,
    pins the first mainnet historical retarget, and implements the post-AuxPoW
    averaging-window algorithm
  - current state: `tidecoin::pow::permitted_difficulty_transition` now ports
    the node transition-envelope rule, with focused node-bridge comparison for
    mainnet legacy bounds and synthetic post-AuxPoW coverage
  - current state: real testnet windows now verify observed `nBits` against
    `next_target_after` from genesis through activation and over a post-AuxPoW
    span through height 16120, including testnet legacy min-difficulty
    walk-back context
  - remaining gap: broader historical/node-vector coverage outside the active
    chain fixture set
- [~] Contextual header and non-UTXO block validation
  - current state: `tidecoin::block_validation::contextual_check_block_header`
    validates previous-hash linkage, exact next `nBits`, previous MTP,
    BIP94 timewarp bounds, optional future-time bounds, buried version gates,
    post-AuxPoW base-version validity, and selected PoW/AuxPoW proof
  - current state: `tidecoin::block_validation::contextual_check_block`
    validates context-free block sanity plus transaction finality, BIP34
    coinbase height, pre-activation witness rejection, witness commitment
    validation, and full witness-inclusive block weight over the same
    previous-header/history callback
  - current state: focused node-bridge parity tests cover the new finality,
    BIP34 coinbase-height, pre-activation witness, witness commitment, full
    weight, and larger 65-transaction contextual block cases
  - current state: real testnet fixture windows now exercise the contextual
    header path contiguously across genesis-to-activation, activation, first
    local AuxPoW payload, and active-chain post-AuxPoW spans through height
    16120
  - deferred separate-crate scope: UTXO-dependent chain-connect validation,
    including BIP30/BIP34Hash handling, sequence locks, spend availability,
    fee/value checks, versionbits state, minimum-chain-work policy, and
    assume-valid policy.
    The proposed crate boundary and API draft are in
    [CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md).
    This requires chainstate/database ownership and is intentionally not folded
    into the current protocol-library crate.
- [x] Standalone PQ signature operation tests where still useful below the node-backed layer
- [ ] Keep the `hashes/embedded` smoke test supported at a limited level:
  target-specific `thumbv7m-none-eabi` check documented, no host-target check,
  and no broad embedded matrix until intentionally scheduled.

## Supporting Documents

These files are supporting references, not co-equal sources of truth.

### Active Planning

- [ai-docs/VALIDATION_FIX_BACKLOG.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/VALIDATION_FIX_BACKLOG.md)
  - Active implementation backlog beneath this master plan.

- [ai-docs/WALLET_API_ROADMAP.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/WALLET_API_ROADMAP.md)
  - Active roadmap for wallet-facing crate APIs: transaction building, signing
    ergonomics, fee/change handling, and mobile/wallet integration gaps.

### Active Protocol References

- [ai-docs/NODE_CONSENSUS_SETTINGS_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_CONSENSUS_SETTINGS_AUDIT.md)
  - Current node-vs-Rust consensus/settings audit and chain-rule coverage map.

- [ai-docs/PROTOCOL_NODE_PARITY_READINESS.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/PROTOCOL_NODE_PARITY_READINESS.md)
  - Defines the current protocol-library parity claim and the boundary before
    future UTXO/mempool crates.

- [ai-docs/NODE_PARITY_PROOF_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/NODE_PARITY_PROOF_MATRIX.md)
  - Maps node validation surfaces to active Rust tests, fuzz targets, and
    generated provenance corpora.

- [ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md)
  - Active design note for the future UTXO-backed chain-validation crate.

### Optional Supporting Refs

- [ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CONSENSUS_TEST_COVERAGE_MATRIX.md)
  - Open only when reconciling archived proof classes against active tests.

- [ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md)
  - Open only for future UTXO-backed chain-validation work.

- [ai-docs/rust-tidecoin-vs-mobile-native-comparison.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/rust-tidecoin-vs-mobile-native-comparison.md)
  - Open only for wallet/mobile compatibility work.

- [consensus/docs/pq-integration-plan.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/docs/pq-integration-plan.md)
  - Open only for lower-level consensus crate integration work.

Everything else under [ai-docs/archived/](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived)
is historical evidence, not an active checklist.

- [ai-docs/rust-tidecoin-vs-mobile-native-comparison.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/rust-tidecoin-vs-mobile-native-comparison.md)
  - Wallet/mobile comparison reference. Use `WALLET_API_ROADMAP.md` for the
    active wallet/API backlog.

### Archived

- [consensus/docs/archived/rust-tidecoin-migration-handoff.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/docs/archived/rust-tidecoin-migration-handoff.md)
  - Historical consensus migration handoff. Do not use as the current architecture description.

- [ai-docs/archived/PORTING_VALIDATION_PROMPT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/archived/PORTING_VALIDATION_PROMPT.md)
  - Historical only. Do not use as a current checklist.

## Working Rule

When deciding what to do next:

1. Use this file first.
2. Use `VALIDATION_FIX_BACKLOG.md` for active protocol/validation tasks.
3. Use `WALLET_API_ROADMAP.md` for wallet-facing API and transaction-builder
   tasks.
4. Use `pq-integration-plan.md` for current consensus architecture detail.
5. Treat historical docs as supporting evidence unless this file explicitly
   reactivates them.
