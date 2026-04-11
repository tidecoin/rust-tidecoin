# Consensus Runtime Audit

This note records the first explicit audit of the imported
[`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus) runtime
surface against the actual Tidecoin core node at `~/dev/tidecoin/tidecoin`.

It is not an abstract cleanup note. It is the concrete migration map for:

- [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
- the shared engine now living in:
  - [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  - [consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)

Historical note:

- the original audit targeted `consensus/src/script.rs` and `consensus/src/tx.rs`
- that large refactor is now landed, and those local engine files have been removed
- the live engine/wrapper boundary is now `consensus-core` engine plus `consensus/src/lib.rs` byte wrapper

## Audit Standard

Primary source of truth:

- `~/dev/tidecoin/tidecoin`

Supporting internal evidence:

- [tidecoin/src/consensus_validation.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
- [tidecoin/src/consensus_validation_tidecoin.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_tidecoin.rs)
- [tidecoin/src/crypto/pq.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/crypto/pq.rs)

Not valid as the acceptance target:

- upstream Bitcoin behavior
- `bitcoinconsensus`

Not an acceptable final implementation shape either:

- upstream `bitcoin` transaction/script/sighash types remaining as the core runtime model inside [`consensus/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus)

## Tidecoin Node Reality

The Tidecoin node does not model Taproot/Tapscript as the target runtime.

Node facts verified from:

- [interpreter.h](/home/yaroslav/dev/tidecoin/tidecoin/src/script/interpreter.h)
- [interpreter.cpp](/home/yaroslav/dev/tidecoin/tidecoin/src/script/interpreter.cpp)
- [validation.cpp](/home/yaroslav/dev/tidecoin/tidecoin/src/validation.cpp)

Runtime facts:

- active post-auxpow consensus flags are:
  - `SCRIPT_VERIFY_PQ_STRICT`
  - `SCRIPT_VERIFY_WITNESS_V1_512`
  - `SCRIPT_VERIFY_SHA512`
- active script versions are:
  - `BASE`
  - `WITNESS_V0`
  - `WITNESS_V1_512`
- Tidecoin uses post-quantum signature verification with legacy Falcon gating via
  `allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT)`
- Tidecoin executes `OP_SHA512` only when `SCRIPT_VERIFY_SHA512` is active
- Tidecoin has witness-v1-512 execution, not Taproot/Tapscript execution

## File Audit

### `consensus/src/lib.rs`

Current status:

- describes itself as a Tidecoin-native byte-oriented validation adapter over
  `tidecoin-consensus-core`
- exposes Tidecoin-shaped public flags and defaults
- uses Tidecoin auxpow-aware activation helpers instead of Bitcoin height logic
- keeps Bitcoin/Core-era proof material only under archived historical paths

Retired non-Tidecoin surfaces:

- `VERIFY_WITNESS_PUBKEYTYPE`
- `VERIFY_TAPROOT`
- `VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`
- `VERIFY_DISCOURAGE_OP_SUCCESS`
- `VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE`
- `VERIFY_ALL_TIDECOIN`
- `height_to_flags(...)` using Bitcoin activation heights
- default `verify(...)` and `verify_with_details(...)` paths that enable
  `VERIFY_TAPROOT` when `spent_outputs` are present
- Taproot-specific public error messages:
  - `ERR_SPENT_OUTPUTS_REQUIRED`
  - `ERR_SPENT_OUTPUTS_MISMATCH`

Assessment:

- this file must be rewritten, not incrementally adjusted
- final target is not just Tidecoin semantics on Bitcoin types
- it must stop using upstream `bitcoin::Transaction` / script / witness / codec helpers as the runtime model

### `consensus-core/src/interpreter.rs`

Current status:

- no longer uses secp256k1 or ECDSA as a consensus primitive
- no longer carries the temporary non-PQ fallback path
- now runs Base / `WITNESS_V0` / `WITNESS_V1_512` checks through the Tidecoin PQ verification facade
- now uses lower Tidecoin transaction / witness / amount types together with
  `consensus_core::SighashCache`
- still carries some Bitcoin-shaped script-model/test history outside the active runtime

Confirmed non-Tidecoin surfaces:

- upstream `bitcoin` script parser/builder/opcode types as the active script-model dependency
- Bitcoin-shaped helper/tests still embedded in the file's test module

Assessment:

- the transaction/sighash side is now on the lower Tidecoin stack
- the remaining runtime migration is mainly the script-model dependency and
  residual Bitcoin-shaped helper/test surface
- this file should continue moving toward shared-core execution logic rather
  than growing more custom compatibility code

### `consensus-core/src/tx.rs`

Current status:

- parses transactions with `tidecoin-consensus-encoding`
- stores `tidecoin-primitives::Transaction` / `TxOut`
- hashes precompute material through the lower Tidecoin encoding/I/O stack
- uses witness-v0 / witness-v1 readiness terminology and Tidecoin witness-v1
  program detection

Confirmed non-Tidecoin surfaces:

- no active Taproot runtime surface remains in this file
- residual debt is limited to comment wording and any future duplication with
  shared-core precompute helpers

Assessment:

- the first real type migration slice is done here
- this file is now substantially aligned with the lower Tidecoin stack
- the next cleanup is deduplication with shared-core helpers, not a fresh
  Taproot-removal rewrite

## Conversion Map

Current implementation status:

- the first public-runtime slice is already applied in
  [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
- public flags/defaults/errors are now Tidecoin-shaped
- the first transaction-precompute slice is already applied in
  [consensus-core/src/tx.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/tx.rs)
- the shared tx engine now uses witness-v0 / witness-v1 readiness terminology instead of
  BIP143/BIP341 terminology
- the shared tx engine now parses and stores Tidecoin-native lower transaction types instead
  of upstream `bitcoin::Transaction`
- the active `script.rs` error surface no longer exposes explicit
  `Schnorr*` / `TaprootWrongControlSize` / `Tapscript*` names for the active
  witness-v1 path
- instead, the active witness-v1 path now maps onto the
  Tidecoin node’s generic script-error vocabulary wherever possible
- the production interpreter now uses `SigVersion::WitnessV1_512` instead of
  `SigVersion::Taproot`, and the main v1 execution helpers in
  [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  have been renamed away from `taproot_*` names
- the active witness-v1 wrapper in
  [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  now follows the Tidecoin node model directly:
  - `VERIFY_WITNESS_V1_512` gates execution
  - version 1 requires a 64-byte witness program
  - the last witness item is the executed script
  - `sha512(script)` must match the committed witness program
- the live interpreter now relies on the shared witness parser/classifier in
  [consensus-core/src/witness.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/witness.rs)
  for Tidecoin-aware 64-byte v1 program handling
- active Base / `WITNESS_V0` / `WITNESS_V1_512` signature verification now
  prefers Tidecoin PQ pubkeys and the shared PQ verification facade
- the temporary ECDSA fallback has been removed from the active runtime, so
  non-PQ pubkeys now simply fail verification like they should under Tidecoin
- `OP_CHECKSIGADD` is now disabled again in the active witness-v1-512 path
- the large Taproot/Tapscript test block in
  [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
  has been removed and replaced with Tidecoin witness-v1-512 tests
- the full `consensus` library test target is green after that first slice
- node-backed parity still passes for `script_tests_pq.json`, `tx_valid_pq.json`,
  and `tx_invalid_pq.json` after this slice
- the explicitly Bitcoin/Core-diff integration tests that still depended on
  removed flags/errors have been archived under
  [consensus/tests/archived/](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived)
  instead of being kept in Cargo's active `tests/` set
- the remaining runtime debt is now mostly architectural rather than semantic:
  - further lowering shared validation logic out of the top-level
    [tidecoin/](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin) crate into
    [consensus-core/](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core)
  - the old `tidecoin::consensus` codec compatibility API has been removed;
    remaining byte-oriented decisions belong to the standalone validation contract
  - deciding whether the archived Core-era proof materials should remain in-repo

Recent boundary fix:

- the verification-only PQ facade now lives in
  [consensus-core/src/pq.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/pq.rs)
- [consensus-core/src/interpreter.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/interpreter.rs)
  now consumes `consensus_core::{PqPublicKey, PqSignature}` instead of
  depending directly on the top-level [`tidecoin/`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin)
  crate
- that removes the temporary `consensus -> tidecoin` runtime dependency that
  existed only for PQ verification
- the active shared interpreter now also uses `consensus_core::SighashCache` and lower
  Tidecoin transaction/witness/amount types instead of upstream Bitcoin
  transaction+sighash runtime primitives

Recent flag cleanup:

- `consensus/src/lib.rs` and the shared interpreter no longer expose or
  accept the fake Bitcoin-only flag bits that do not exist in the Tidecoin
  node:
  - `VERIFY_TAPROOT`
  - `VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`
  - `VERIFY_DISCOURAGE_OP_SUCCESS`
  - `VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE`
  - `VERIFY_WITNESS_PUBKEYTYPE`
- the corresponding placeholder tests and branches were deleted

### Delete

These should be removed from `consensus/` rather than translated.

#### Public/runtime surface

- `VERIFY_WITNESS_PUBKEYTYPE`
- `VERIFY_TAPROOT`
- `VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`
- `VERIFY_DISCOURAGE_OP_SUCCESS`
- `VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE`
- `VERIFY_ALL_TIDECOIN`
- Bitcoin activation heights in `height_to_flags(...)`
- Taproot-specific spent-output requirements/messages

#### Interpreter/runtime internals

- secp256k1 verification context plumbing
- ECDSA consensus verification path
- Schnorr consensus verification path
- Taproot control-block parsing
- annex handling
- tapscript validation-weight logic
- tapscript `CHECKSIGADD` handling
- Taproot/Tapscript-specific `ScriptError` variants
- Taproot-specific tx precompute fields

#### Tests

- `bitcoinconsensus` parity tests
- Taproot/Tapscript/Schnorr/secp tests in
  [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
- Bitcoin activation-height tests tied to the old `height_to_flags(...)`
- the archived Bitcoin/Core-diff integration suite in
  [consensus/tests/archived/](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived)

### Rewrite

These still exist conceptually in Tidecoin, but with different semantics.

#### Flags

Keep and map to Tidecoin semantics:

- `VERIFY_P2SH`
- `VERIFY_NULLDUMMY`
- `VERIFY_SIGPUSHONLY`
- `VERIFY_MINIMALDATA`
- `VERIFY_DISCOURAGE_UPGRADABLE_NOPS`
- `VERIFY_CLEANSTACK`
- `VERIFY_CHECKLOCKTIMEVERIFY`
- `VERIFY_CHECKSEQUENCEVERIFY`
- `VERIFY_WITNESS`
- `VERIFY_MINIMALIF`
- `VERIFY_NULLFAIL`
- `VERIFY_CONST_SCRIPTCODE`

Add Tidecoin-native flags:

- `VERIFY_PQ_STRICT`
- `VERIFY_WITNESS_V1_512`
- `VERIFY_SHA512`

### Deferred Test Replacements

The ECDSA-only `consensus` unit tests that were removed as part of the runtime
cleanup still need Tidecoin-native replacements. They are intentionally deferred
until PQ-native signing helpers or shared node-backed fixtures are used in the
lib-test surface.

Replace later with Tidecoin/PQ coverage:

- witness-v0 code-separator sighash behavior
- witness-v0 raw hashtype behavior
- explicit witness amount authority
- legacy code-separator signature behavior
- the old Bitcoin-only multisig intermediate-mismatch edge case, if it still
  maps to a meaningful Tidecoin rule
- any reusable surface formerly covered only by the archived Bitcoin/Core-diff
  integration files, but only after it is restated as Tidecoin node parity

#### Activation helpers

- rewrite `height_to_flags(...)` around Tidecoin auxpow activation logic
- default verification helpers must stop assuming Taproot and instead use
  Tidecoin’s default flag bundle

#### Public errors

- reword errors to Tidecoin semantics
- spent-output mismatches must refer to the actual Tidecoin verification model,
  not Taproot

#### Transaction precompute

- rewrite precompute support for Tidecoin:
  - legacy/base
  - witness-v0
  - witness-v1-512
- remove Taproot-specific readiness tracking

### Replace Via `tidecoin-consensus-core`

These should not be hand-maintained separately inside `consensus/`.

- supported-flag validation
- `ScriptError`
- interpreter stack machine
- opcode execution
- script/witness dispatch
- locktime and sequence checks
- consensus-critical sighash logic
- witness-v1-512 handling
- `OP_SHA512`
- PQ verification glue:
  - Falcon strict
  - Falcon legacy-accepting mode
  - ML-DSA

## Immediate Implementation Order

1. Rewrite [consensus/src/lib.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs) public flags and public defaults to Tidecoin semantics.
2. Delete Taproot/Tapscript/ECDSA/Schnorr public tests embedded in that file.
3. Move the mature interpreter and typed tx/precompute layer into shared core.
4. Keep `consensus` as the byte-oriented wrapper over that engine.
5. Keep the old Bitcoin differential test harnesses archived while the
   Tidecoin-native replacement matrix is reconciled.

## Exit Criteria For The First Runtime Pass

- `consensus/src/lib.rs` no longer exports Taproot, DER/low-S, or Bitcoin-only
  policy flags
- the default verification surface no longer models Taproot or
  `bitcoinconsensus`
- the shared interpreter no longer depends on secp/Schnorr/Taproot runtime
  semantics
- the shared tx layer no longer contains Taproot precompute logic
- the remaining test suite no longer treats Bitcoin or `bitcoinconsensus` as the
  runtime reference model
