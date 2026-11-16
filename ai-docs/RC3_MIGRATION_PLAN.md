# rc3 compatibility migration

Status: initial rc3 checkpoint passed local and main hosted CI (2026-11-16).
The signing/fee follow-up below passes local gates; its hosted CI is pending.
Initial Miri status is recorded with its run link below.
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
| Integration | node script assets, feature matrix, CI | Source-derived negative cases, full original-node differential gate, no-std, stable/MSRV, cross tests, docs and CI | Local checks and main hosted CI pass; separate Miri pending |

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

The rc3 F12/F13 transport changes were also traced through `net.cpp` and
`crypto/hkdf_sha256_32.cpp`. Rust's `pq_v2_transport` is a packet cipher, not the
node handshake/session state machine. Its key schedule and packet vectors remain
unchanged. It borrows the shared secret; the caller owns that buffer's lifetime.
Existing Rust erasure helpers are not proof that every compiler-created temporary
is erased, and wire parity does not establish identical memory-cleanup guarantees.

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
  Hosted full AArch64/s390x and feature jobs also pass.

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
and fixed without changing the rules.

The final code commit `a479c9085ef13e8518ff5b18373cd509eed53363` passed
[main CI run 43852925990](https://github.com/tidecoin/rust-tidecoin/actions/runs/43852925990).
This includes required original-node rc3 parity, stable/MSRV/nightly tests,
AArch64/s390x, 32-bit, WASM, embedded, ASAN, lint, formatting, documentation,
prerelease, bench, repository policy and Kani code generation. The mutation job
was skipped by the workflow's existing push-event condition; this is not a
mutation-testing result.

[Miri run 43852926078](https://github.com/tidecoin/rust-tidecoin/actions/runs/43852926078)
is still executing at the time of this record. No Miri pass is claimed. The final
documentation checkpoint changes only prose and a test module's introductory
comment; executable code remains identical to the successfully tested commit.


### Signing and fee-estimation follow-up (2026-11-16)

The earlier statement about conservative predictions was incomplete: the node's
`script/sign.cpp` exposes both `DUMMY_SIGNATURE_CREATOR` (local signing bound)
and `DUMMY_MAXIMUM_SIGNATURE_CREATOR`. Rust now exposes this choice through
`PqSignatureSize::{LocalSigning, Maximum}` and all four existing PQ input
prediction families' `_with_mode` methods. Existing helpers retain maximum mode.
The unknown-key dummy size uses the largest known scheme in either mode, matching
the original creator. These modes are estimates, not verification acceptance rules.

For a mixed transaction, choose the mode separately for each input, aggregate
with `predict_weight`, then round the total weight to virtual bytes. Apply
`FeeRate::mul_by_vsize` to that total (or the policy-adjusted virtual size when
applicable). Do not round each input separately. Local mode requires every
contributing signer to obey the rc3 bound. Finalized transactions use actual
serialized weight. Dust policy continues to use its original maximum-size proxies.

This follow-up found and repaired two Rust arithmetic discrepancies missed by the
initial checkpoint: dust thresholds rounded down instead of following original
`CFeeRate::GetFee` upward rounding; `FeeRate::mul_by_weight` prematurely rounded
the rate down to integer sat/kwu. Multiplication now preserves the represented
rate with a wide intermediate, rounds once, and checks `Amount::MAX_MONEY`.
`mul_by_weight` still prices exact weight; the new `mul_by_vsize` prices integer
virtual bytes. Negative node fee rates are outside Rust's unsigned `FeeRate` API.

`rc3_fee_estimation.rs` calls original dummy creators, C++ transaction serialization,
`GetVirtualTransactionSize`, `CFeeRate::GetFee`, `GetDustThreshold` and `CScript`
push serialization. It compares 2,410 sizing cases across all five schemes and
both modes, including unknown-key fallback, native/wrapped v0, native witness
script forms, count/length CompactSize boundaries and fractional fee rates.
Another 170 cases cover fee, dust and PUSHDATA boundaries. Witness-v1 size tests
do not authorize wrapped v1 or bypass activation/signing eligibility.

The actual registry dependencies reviewed are `tide-fn-dsa-sign 0.4.0` (scalar
and AVX2 paths) and `fips204 0.4.6`, compared with node `pq_api.h`, Falcon wrappers
and ML-DSA signing. No new randomness algorithm or nonce construction is introduced.
Default signing uses `OsRng`; caller RNGs must be cryptographically secure and
advance across calls. The shared bounded Falcon retry helper never resets the RNG,
never truncates a valid signature, and returns an error after 10,000 completed
attempts fail the local bound. Backend-internal sampling retries are separate.
Tests force a completed retry through the real signer, inspect nonce freshness,
exercise empty/oversized/error attempts and exhaustion, and check repeated
Falcon/ML-DSA signatures against original C++ with wrong-message controls.

Entropy failures produce no signature: ML-DSA propagates an error; the current
Falcon dependency uses infallible RNG calls and can panic. This behavior is now
documented and tested, not described as uniformly returning `PqError`. Debug
cryptography tests use the existing 32 MiB stack convention. These checks do not
prove constant-time behavior or complete erasure of compiler-created temporaries.

Validation: required original-node workspace gate **1,808 passed / 107 targets**;
product gate **371 passed / 9 targets**, no failures or ignored tests. Pinned
nightly all-features/all-targets Clippy with `-D warnings`, MSRV 1.94.1 no-default
product check, formatting and public documentation builds pass. Hosted results
for this follow-up must be checked separately from the initial rc3 run above.

### Script, witness and decoding review (2026-11-16)

This review extended original-C++ comparison beyond the initial checkpoint to
interpreter state, witness recognition, sighash context, wire decoding and limit
combinations. It found the following Rust discrepancies. All were fixed in Rust.
None is a node defect.

| Finding | Effect before the fix | Fix and regression |
| --- | --- | --- |
| `Interpreter::verify()` kept its stack between calls | Reusing one low-level interpreter could accept a script that a fresh verification rejects. The higher-level verification functions create fresh interpreters. | All execution state is reset before any early return. Transaction-bound sighash caches are kept. `original_node_execution_boundaries_and_reuse` |
| Witness v1 always enforced `MINIMALIF` | Rust rejected v1 spends that rc3 accepts when `MINIMALIF` is not set. That flag is standard but not mandatory. | Flag-controlled for v0 and v1, as in the original `EvalScript`. `minimalif_and_competing_opcode_errors_follow_original_flags` |
| Witness program recognition accepted other lengths and versions | Rust classified some ordinary scripts as witness programs. | Recognition is limited to 2–40 bytes plus exactly 64-byte v1, as in `CScript::IsWitnessProgram`. `witness_program_recognition_matches_original_execution` |
| The policy helper rejected malformed v0 program lengths | Policy verdict differed. Original `IsWitnessStandard` leaves this to consensus. | Only P2WSH gets v0 stack limits. `rc3_witness_context.rs` |
| Legacy multisig scriptCode preparation rejected a malformed script end | Wrong error (generic instead of `BAD_OPCODE`). | The malformed end is kept, as in original `FindAndDelete`. `malformed_legacy_multisig_tail_preserves_original_error_order` (crash-61efecbb) |
| Disabled/invalid opcode checks ran before the opcode-count limit | Wrong error when both apply. | Order follows original `EvalScript`. Same MINIMALIF/opcode test. |
| `PICK`, `ROLL`, binary numeric opcodes and `WITHIN` decoded operands before checking stack depth | `UNKNOWN_ERROR` instead of `INVALID_STACK_OPERATION`. | Depth is checked first. `numeric_opcode_depth_precedes_scriptnum_errors` (crash-8e940121) |
| The legacy `FindAndDelete` search pattern used minimal push encoding | For a 1-byte signature 1–16 or `0x81`, Rust searched for `OP_1`…`OP_16`/`OP_1NEGATE` instead of `CScript() << vchSig` (`01 xx`). It removed the wrong bytes and reported `SIG_FINDANDDELETE` incorrectly. Under standard flags both reject with different errors. Consensus outcome is unchanged because such a signature cannot verify. With `CONST_SCRIPTCODE` but not `NULLFAIL`, Rust rejected spends rc3 accepts. | Length-prefixed push, as in the original `AppendDataSize`. `legacy_signature_removal_uses_explicit_push_encoding` (crash-bf928ece) and `signature_pattern_uses_explicit_push_encoding` |

The P2SH-witness check that the scriptSig is exactly one push of the redeem
script uses the same helper. It also matches the original
`CScript() << vector`. Its input is always a witness program of at least 4 bytes,
so its result is unchanged.

**Comparison infrastructure.** `fuzz/src/differential.rs` runs each case through
original C++ `VerifyScript` and through Rust in three ways: fresh typed
verification, the byte API, and three repeated calls on one interpreter. It
compares exact script errors, not only acceptance. Harness or context failures
stop the run instead of counting as script rejection. Wire decoding and
transaction sanity are compared separately from script execution, because C++
can run scripts on a transaction that fails sanity checks, while the Rust byte
API rejects it while decoding. The cases cover:

- mixed legacy/v0/v1 signed transactions
- mutated amounts, scripts, outpoints, sequences, signatures and hash modes
- cached versus fresh v1 hashes
- complete versus missing spent-output context
- compact inputs expanded to large script, stack and element sizes

`fuzz/tests/node_oracle.rs` holds the deterministic matrices and the minimized
regressions. It runs in the required node-parity CI job. `consensus_node_differential`
is the fuzz target. `fuzz/seed-node-corpus.py` writes 1,406 seeds, including the
four original inputs that exposed the mismatches. `node-differential.yml` runs
the target with AddressSanitizer in both Rust and C++: 50,000 runs on push and
pull request, and 30 minutes on schedule or manual dispatch.

**Results.**

- The deterministic matrices found the other four findings in the table.
- Four ASan fuzz campaigns found the four findings with crash IDs, one per
  campaign. Each was minimized into a regression and fixed, and the saved
  inputs now replay cleanly.
- After the last fix, a 50,000-run campaign (seed 5) found no mismatch.
- Four parallel 30-minute ASan campaigns (seeds 11–14) completed 4,902,283
  runs with no mismatch. Coverage leveled off at 7,039–7,044 edges and about
  2,000 corpus entries.
- Required original-node workspace gate: **1,811 passed / 109 targets**.
- Product gate: **372 passed / 9 targets**.
- `node_oracle`: 8 passed. No failures or ignored tests.
- The oracle executable was rebuilt from the pinned rc3 checkout for these runs.
- Pinned nightly all-features/all-targets Clippy with `-D warnings`,
  no-default-features workspace check, MSRV 1.94.1 no-default checks and
  formatting pass.

**Limits.** Fuzzing samples inputs; a clean campaign does not prove that no
mismatch remains. The comparison covers script verification with
caller-supplied spent outputs. It does not cover UTXO-backed checks, mempool or
package policy. Miri and constant-time properties are outside this review.
