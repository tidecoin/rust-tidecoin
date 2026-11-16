# rc3 compatibility migration

Status: local protocol-library gate passes (2026-11-16); hosted CI pending.
This is a bounded compatibility checkpoint, not full-node or PSBT parity.

## Authority and baseline

The target is the clean local Tidecoin `v1.0.0rc3` tag,
`ffed4e92e60ff2de30361648a71cba64531f9077`, in
`/home/yaroslav/dev/tidecoin/tidecoin`. Compare against the previous pinned rc2
node `7d653be5d24e73b49d101578afb33d8d7a889c1d`. Rust starts from `v2`
`b966a55af15ecd9604e06c0247f4da96a7c767d4`, with unfinished test-only feature
and cross-runner fixes preserved. The rc2 migration plan is historical evidence.

The node implementation and callers remain authoritative. Review notes in
`/home/yaroslav/dev/tidecoin/ai-docs-tidecoin` guide source inspection, especially
`plans/2026-10-23-rc3-fix-register.md` and
`plans/2026-10-28-deep-dive-implementation-register.md`. Their dated intermediate
states are not substituted for the final tagged source.

## Implementation and verification order

| Area | Original node references | Rust work and evidence required | Status |
|---|---|---|---|
| Oracle | validation.cpp, script/interpreter.cpp, pq wrappers | Pin rc3; rebuild original-source bridges and validation executable; refresh provenance only after review | Complete locally |
| Witness interpretation | IsWitnessProgramForFlags, VerifyWitnessProgram, CountWitnessSigOps, IsWitnessStandard | Native-only 64-byte v1; wrapped extension stays ordinary script; short v1 stays reserved; execution, sigops and policy boundary comparisons | Complete locally |
| Falcon legacy and relay | pq/falcon512.c, CheckFalconSignatureEncoding, PolicyScriptChecks | Accept historical negative zero/final bits only in legacy verification; exact consumption; separate canonical relay flag/error and error ordering | Complete locally |
| PQ keys and signing | IsValidPubKey, SignFalcon, kem.cpp, key_io.cpp, pubkey.cpp | Full Falcon key validation at non-consensus boundaries; local signing size bound; historical WIF identity validation; message verification and ML-KEM rejection controls | Complete locally |
| PQHD | pqhd_params.h, ValidateV1LeafPath, descriptor.cpp | Script-family purposes and network coin types; explicit path compatibility and independent node derivation vectors | Complete locally |
| Header and policy APIs | IsOversizedAuxPowHeader, headerssync.cpp, policy.cpp, net_processing.cpp | Individual AuxPoW size limit, era-specific transition screening, witness classification; map serving limits to exposed Rust message APIs | Complete locally |
| Signing/PSBT inventory | psbt.cpp, psbt.h, script/sign.cpp | Map selected-era eligibility, finals/UTXO validation and inactive partial handling to existing Rust surfaces; record absent PSBT APIs without claiming interoperability | Complete locally |
| Integration | node script assets, feature matrix, CI | Source-derived negative cases, full original-node differential gate, no-std, stable/MSRV, cross tests, docs and CI | Local checks pass; hosted CI pending |

This is a protocol-library migration, not an implementation of node chainstate,
wallet database, RPC server, peer scheduling or absent PSBT machinery. Changes
in those callers must still be inspected for effects on exposed Rust contracts.
Do not infer full-node or PSBT compatibility from the library gate. Preserve
mainnet activation settings and the node's deferred design decisions.

## Findings and evidence

The full workspace gate passed **1,803 tests across 106 test targets**, and the
product gate with the required original node passed **364 tests across 8 test
targets**. Both exited successfully with no ignored tests. Optional parity tests
run in required mode here; normal builds without an oracle may skip them.

### Implemented changes and independent evidence

- **Witness:** reviewed original `IsWitnessProgramForFlags`, execution,
  `CountWitnessSigOps`, signing callers and `IsWitnessStandard`. Native-only
  64-byte v1 recognition is shared; wrapped v1 remains ordinary script and
  shorter v1 programs remain reserved. Existing signed context matrices were
  updated, preserving all six hash modes, mutation/cache and missing-output
  controls. New policy tests call original C++ policy functions with a coin view.
- **Falcon:** original rc3 decoders and classifier establish historical negative
  zero/final-bit acceptance, exact consumption and strict padding rejection.
  The shared facade clears only equivalent legacy encoding bits before invoking
  the published 0.4.1 legacy arithmetic verifier; strict mode checks canonical
  exact-length encoding first. Node-generated signatures are mutated at zero
  coefficients and every possible unused tail value, plus overflow, truncation,
  header and trailing-byte controls. Original crypto and classification verdicts
  are compared. CHECKSIG/MULTISIG tests cover hash-type precedence, unreached
  arguments and the relay-only flag's interaction with PQ_STRICT.
- **Keys/signing:** full Falcon public-key validation is exposed separately from
  structural consensus parsing. Original `IsValidPubKey` confirms header and
  coefficient boundaries. New signatures obey the node's local 666/1280-byte
  bounds without truncation or padding; external verification keeps its own
  bounds. Existing bidirectional C++ signing/key-generation tests pass. Original
  ML-KEM encapsulation confirms Rust already rejects coefficients >=3329 while
  accepting arbitrary seed bytes; no alternate cryptographic implementation was
  needed. Signed-message compatibility is available through existing
  `verify_msg*_allow_legacy`; the library has no node message-recovery envelope API.
- **WIF:** reviewed `DecodeSecret`, `EncodeSecretLegacy`, `CKey` validation and
  public-key derivation. Legacy exports now carry raw public-key bytes. Tests
  compare original import and both export forms on all three networks, including
  raw keys with/without the marker, wrong embedded identities, wrong tags,
  obsolete prefixed embedded keys and invalid prefixed-key trailers.
- **PQHD:** supported explicit purposes/coin types follow original path validation.
  New defaults separate the four script families and main/test networks. Existing
  explicit generic paths are preserved. A matrix of 776 paths covers accepted and
  unsupported purposes/coins/schemes, hardened bits, change and path length;
  accepted paths compare stream keys directly with original C++ KDF functions.
  Default descriptor tests include network, family, internal/external and inactive
  v1 cases. Existing deterministic key-generation vectors remain unchanged.
- **Headers/P2P:** the complete AuxPoW header cap is derived from the shared
  6,000,000 weight limit: 1,500,000 bytes. Original admission tests cover cap-1,
  cap and cap+1, cleared flags and proof-checked headers with omitted payloads.
  `HeadersMessageSize` matches the original list-count/zero-transaction-count
  accounting and continuation thresholds, including CompactSize transitions.
  P2P payload cap is corrected from 5 MB to the node's 8 MB; v2 allows the original
  13-byte command overhead and enforces the cap for slice and incremental input.
  `headerssync.cpp`'s preactivation fix belongs to its state machine; Rust already
  selects the correct era in its transition primitive, whose existing original
  comparisons pass. Peer scheduling, proof-read failure handling and inv fallback
  have no equivalent stateful Rust component.

### Caller review and scope limits

`script/sign.cpp` now filters new and cached signatures by the selected era
before satisfaction, rejects wrapped v1, and sizes actual redeem-script pushes.
Rust provides raw signing, explicit-context sighashes and validation; it has no
signature creator/satisfaction cache. Do not infer signing eligibility from raw
cryptographic signing success. `InputWeightPrediction` retains conservative
external-signature estimates; its push-length helper already handles PUSHDATA
boundaries. The local signer bound is a distinct scheme property.

Reviewed `PSBTInputHasSigningUTXO`, partial classification, declaration/signing,
final verification and unnecessary-transaction removal in `psbt.cpp`/`psbt.h`.
Future PSBT implementation must preserve the original distinction between
invalid, excluded and unknown partials, full previous transactions for legacy
finals, exact wrapped-v0 final pushes, native-only v1 and immutable selected-era
context. These are source references for future implementation, not an alternate
PSBT specification. No complete Rust PSBT/signing-provider surface exists to
upgrade in this checkpoint. Wallet persistence, RPC concurrency and deferred node
design choices are likewise outside the protocol-library implementation.

No clear node logic defect with a concrete funds-at-risk path was found. Rust
parity failures were fixed against original source; no node behavior was silently
compensated for or redesigned.

### Validation results

- Required workspace and product gates above: pass against the rc3 pin.
- Stable workspace no-default-features and independent no-std checks on MSRV
  1.94.1: pass, including product/P2P serde without default features.
- Stable Clippy passes with existing advisory warnings. The pinned nightly
  all-targets/all-features Clippy gate also passes with `-D warnings` after
  simplifying the Falcon rejection predicate and removing one test-only clone.
- Script-runtime fuzz smoke: 5,000 runs with stable libFuzzer, no sanitizer; pass.
  This is bounded smoke coverage, not a fuzzing/security certification.
- Regenerated policy provenance (33 cases) and script metadata (30 cases) exactly
  match the committed artifacts. Existing fixture/source hash gates pass.
- Formatting, diff whitespace, actionlint and shell syntax checks: pass.
- Workspace documentation builds; product doctests pass (15 passed, one
  pre-existing ignored example). Product and P2P no-std builds also pass on
  `thumbv7m-none-eabi`.
- AArch64 cross-runner configuration regression: all five tests pass under QEMU.
  Hosted full cross/feature jobs remain the integration gate.

The retained CI fixes correct child-test execution through Cargo's cross runner,
assert that configuration-rejection tests actually entered the child, repair a
no-std test import, and gate proof-only oracle tests. Docker context excludes build
artifacts. Miri's unsafe-code screening now checks each crate's manifest instead
of repeatedly checking the entire workspace. None of these changes weakens the
required native oracle gate.

## Validation commands

```sh
export TIDECOIN_NODE_REPO=/path/to/tidecoin
export TIDECOIN_NODE_PARITY_REQUIRED=1
cmake -S node-parity/validation-oracle -B target/node-oracle \
  -DTIDECOIN_NODE_REPO="$TIDECOIN_NODE_REPO" -DCMAKE_BUILD_TYPE=Release
cmake --build target/node-oracle --target tidecoin-validation-oracle -j 2
export TIDECOIN_NODE_VALIDATION_ORACLE="$PWD/target/node-oracle/tidecoin-validation-oracle"
cargo +1.99.1 test --workspace --all-targets
cargo +1.99.1 test -p tidecoin --lib --tests --features tidecoin-node-validation
cargo +1.99.1 clippy --workspace --all-targets
cargo +1.99.1 check --workspace --no-default-features
cargo +1.99.1 fmt --all -- --check
```

The standalone oracle includes complete unmodified `validation.cpp`; added
adapters call original key, policy, KDF and header-size functions. It is not a
copy of those rules. Historical `rc2` test filenames preserve provenance while
running against the active pin. External node/docs checkouts were not modified.

### Hosted validation

Initial rc3 run: [43851939268](https://github.com/tidecoin/rust-tidecoin/actions/runs/43851939268)
at `740b2ba`. Its lint failure was reproduced with the exact nightly command
and fixed without changing the rules. The follow-up commit re-runs hosted gates;
final results are not inferred from local passes or from unfinished jobs.
