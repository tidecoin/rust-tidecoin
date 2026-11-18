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

After updating the oracle source, rerun the CMake build in the directory that
supplies `TIDECOIN_NODE_VALIDATION_ORACLE`. Cargo uses that executable as built.

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
is still executing at the time of this record. No Miri pass is claimed.
Follow-up (2026-11-17): no Miri run on `v2` has completed; runs failed or were
cancelled, most at the six-hour job limit. The screening in `contrib/test-miri.sh`
put `-F unsafe-code` in `RUSTFLAGS`, which also applied it to workspace
dependencies such as `internals`, so every crate depending on them ran under Miri,
including the post-quantum signing tests of `tidecoin`, `consensus-core` and
`consensus`. The screening now forbids unsafe code in the checked crate's library
only (normal and `cfg(test)` builds), selecting `hashes`, `internals`, `io`,
`primitives` and `p2p` (`consensus` no longer contains unsafe code; see
"Borrowed outputs and typed erasure" below). The Miri workflow is now started manually
instead of on every push. The final
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
| Witness stacks deeper than 1,000 items were rejected before execution | `STACK_SIZE` instead of the original error, for example `CLEANSTACK` with an empty witness script. Original `ExecuteWitnessScript` checks only element sizes before `EvalScript`, which checks depth after each opcode. Both reject: the 201-operation limit cannot reduce such a stack to one item. | `ScriptStack::from_items` checks element sizes only. `witness_stack_depth_is_checked_only_by_execution` |

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
  2,000 corpus entries. These runs compared verdicts and errors only; they
  predate the full-stack comparison below.
- With the full-stack comparison, four parallel 30-minute ASan campaigns
  (seeds 21–24, 2026-11-17) completed 2,558,595 runs with no mismatch and no
  sanitizer error. Each case now also runs three `EvalScript` comparisons, so
  throughput is about half. Coverage reached 7,162–7,181 edges and about 2,250
  corpus entries.
- Required original-node workspace gate: **1,811 passed / 109 targets**.
- Product gate: **372 passed / 9 targets**.
- `node_oracle`: 16 passed (8 at the first checkpoint). No failures or ignored tests.
- The oracle executable was rebuilt from the pinned rc3 checkout for these runs.
- Pinned nightly all-features/all-targets Clippy with `-D warnings`,
  no-default-features workspace check, MSRV 1.94.1 no-default checks and
  formatting pass.

**Mutation testing (2026-11-17).** cargo-mutants 27.1.0 changed
`consensus-core/src/interpreter.rs` one operator or return value at a time and
ran the comparison suite against each change. A surviving change marks behavior
that no test pins down.

- The first run compared verdicts only and missed 358 of 804 changes. Many
  survivors left a wrong value on the stack under a true top element.
- `tidecoin_node_eval_script` was added to the bridge. It runs original
  `EvalScript` on a given script, starting stack and sigversion.
  `compare_eval` now checks the complete resulting stack, or the exact error,
  under BASE, WITNESS_V0 and WITNESS_V1_512. `opcode_results_match_original_eval_script`
  runs all 256 opcodes over stacks of chosen values, distinct items and every
  depth up to 7. With this, the 778 changes gave 595 caught, 157 missed,
  19 unviable (the change does not compile) and 7 timeouts (the change made
  the suite hang; counted separately from assertion failures).
- 76 changes survived both this suite and the regular unit tests. Targeted
  comparisons were added for them:
  - `lock_time_and_sequence_boundaries_match_original_node`: CLTV/CSV across
    lock time, sequence and version boundaries
  - `push_encodings_and_signature_removal_match_original_node`: MINIMALDATA over
    every push form, and FindAndDelete over PUSHDATA1/2/4 and truncated scripts
  - `instruction_boundaries_match_original_node`: PUSHDATA payloads holding the
    signature pattern, so that a length or offset mistake would shift the
    instruction walk; it also exercises the P2SH and SIGPUSHONLY push-only checks
  - `multisig_counts_and_operation_limit_match_original_node` and
    `signed_multisig_matches_original_node`: valid and invalid m-of-n
  - `script_code_follows_code_separator_and_executing_script`: signed spends
    whose two signature checks use different script codes
  - `witness_stack_depth_is_checked_only_by_execution`, which found the
    discrepancy in the last table row

  Rerunning the affected changes confirmed these tests catch them. Two unit
  tests cover Rust-only behavior: a missing amount is rejected only for witness
  spends, and accurate multisig sigop counts.
- The remaining survivors were reviewed one by one and cannot change a result:
  - flag masks whose bits do not overlap (`|` and `^` are equal)
  - the script-code cache always refreshing
  - boundaries that execution cannot reach: a code separator at the script
    end, a direct push over 8,192 bytes, `PUSHDATA4` data over 65,535 bytes,
    FindAndDelete on a script no longer than the pattern
  - `OP_MIN`, `OP_MAX`, `OP_ABS` at equal or zero operands
  - a multisig key-depth check whose failure the next pop reports identically
  - the redundant final stack check and the P2SH stack copy in `verify`
  - error bookkeeping for internal failures that execution cannot produce
  - the interpreter's sigop total, which verification never exposes
  - minimal-push enforcement in a test-only instruction walker

**Limits.** Fuzzing samples inputs; a clean campaign does not prove that no
mismatch remains. The comparison covers script verification with
caller-supplied spent outputs. It does not cover UTXO-backed checks, mempool or
package policy. Miri and constant-time properties are outside this review.

**Remaining follow-up.** The interpreter-focused work above is complete. Still open:

| Area | Remaining work |
| --- | --- |
| Broader script combinations | Structured, valid multi-operation scripts with nested branches, alternate-stack use and several signature checks. The arbitrary-script generator stops at 2,048 bytes; larger boundaries use fixed patterns. |
| Complete signed transactions | The [mixed-input comparison](#mixed-input-signed-transactions-2026-11-18) covers three-input single-key spends; [signed shapes](#signed-shapes-input-counts-script-mixes-and-error-order-2026-11-18) add 1, 2 and 4 inputs, SINGLE without a matching output, and multisig with a branched witness script in one transaction. Mixed PQ schemes within these shapes, larger multisig and further script forms remain open. |
| Block comparisons | Generated combinations of witness commitments, coinbase data, merkle structure, weight, sigops and contextual boundaries against the original-node block oracle. |
| Decoder and API combinations | Incremental and chunked decoding and every public entry point. The transaction comparison currently decodes complete byte slices. |
| Mutation testing outside the interpreter | Sighash and context handling, witness recognition, transaction decoding, block checks and fee arithmetic. |

### Borrowed outputs and typed erasure (2026-11-17)

Two Rust API defects were corrected without changing node validation rules:

- `consensus::Utxo<'a>` borrows `&'a [u8]` instead of exposing a raw pointer
  and independent length. All active callers now borrow their script storage.
  Amount, output-count and current-input consistency checks remain in place.
  The consensus adapter now forbids unsafe code. A compile-fail example checks
  the lifetime contract; runtime cases cover subslices, empty scripts, amounts,
  context counts, copying into interpreter-owned storage and all four entry points.
- Removed arbitrary-object zeroing from `hashes`. HMAC erasure requires
  `T: zeroize::Zeroize`, and all built-in engines clear their typed state fields.
  HKDF stores the PRK as a byte array and erases that array on request and drop,
  rather than overwriting the representation of a caller-defined hash type.
  Custom-engine regressions use nonzero fields and owned allocations. Explicit
  erasure still does not guarantee removal of compiler-created copies.

These are source-level API changes; migration details are in the consensus and
hashes changelogs. Archived migration fixtures retain their historical APIs.

Validation with the required pinned rc3 node and standalone validation oracle:
`cargo +1.99.1 test --workspace --all-targets --all-features` passed **1,892 tests
across 111 test targets**, with no failures or ignored tests, including the 16
original-node differential matrices. Pinned-nightly Miri passed the three erasure
regressions and the borrowed-output regression. The affected crates' doctests
passed (9 passed, one existing ignored example), including both compile-fail
contracts. All-feature workspace Clippy with `-D warnings`, MSRV 1.94.1
no-default-feature checks for both affected crates, and formatting passed.


### Checked conversions and local unsafe-code restrictions (2026-11-17)

- P2P command decoding now uses checked UTF-8 conversion after its existing
  ASCII check; null-padding and embedded-null handling remain unchanged.
- `internals::slice` uses safe `as_chunks` / `as_chunks_mut`, available on the
  project's MSRV. Both zero-sized-chunk compile-fail contracts remain intact.
- SipHash uses checked slice/index reads. Its existing 64 reference vectors now
  also cover all 2,080 two-part input splits, including empty intermediate writes.
- Added `forbid(unsafe_code)` to the P2P, base58, chacha20_poly1305,
  consensus-core, consensus_encoding, network and units library roots. Together
  with consensus, eight library roots now carry the restriction. It is also
  applied locally to the slice and SipHash modules.

The restriction is local, not a claim about dependencies. Expanded all-feature
code for the eight libraries was inspected: remaining generated low-level code
comes from compiler derives and standard allocation macros. External wrapper
macros still emit pointer casts in `tidecoin`, `io` and `primitives`, so those
libraries are not classified as free of such operations. A compiler control
confirmed that `tidecoin` can pass `-F unsafe-code` despite casts from external
macros; lint success alone is therefore insufficient evidence. CPU intrinsics,
ArrayVec, wrapper conversions, volatile comparison and original-node FFI remain
separate review boundaries.

Validation: the required rc3 all-target/all-feature workspace run passed
**1,892 tests / 111 targets**, including all 16 original-node comparison tests.
Pinned-nightly Clippy with `-D warnings`, MSRV 1.94.1 no-default checks for the
changed libraries, formatting, and the internals doctests pass. Miri passed
SipHash's reference-vector and split-input test. The benchmark package's stale
chacha20 dependency name was corrected and an unused benchmark import removed;
all benchmark targets now compile. The repository SipHash Criterion benchmark
ran before and after checked indexing (10 samples, one-second warm-up and
measurement per case). No statistically significant slowdown was reported in
its four cases; these short local measurements do not establish a general
performance improvement. No hashing or node validation rules changed.


### Stable lint baseline (2026-11-17)

Clippy now uses the same pinned stable Rust 1.99.1 as normal CI and formatting.
The required node-parity job runs `cargo clippy --workspace --all-targets
--all-features -- -D warnings`; the duplicate maintainer-tool nightly lint task
was removed from the workflow matrix. The MSRV stays 1.94.1 and the specialized
nightly toolchain stays pinned separately. Local commands must name `+1.99.1`
when matching this lint gate; the machine's unqualified stable alias was 1.94.1
at this checkpoint.

The 19 pre-existing default-feature warning locations and one additional
all-feature node-test location were fixed. Fixed-size block loops use
`as_chunks`/`as_chunks_mut` with the same handling of full blocks and remainders,
including the conditional SHA-256 paths. Amount formatting now initializes its
trailing-zero count from the match expression without changing arithmetic.
Other changes remove redundant formatting borrows, a single-item loop and an
explicit error-forwarding match. No lint suppressions or rule changes were added.

Validation: stable 1.99.1 strict Clippy passes with default features and with all
features. The pinned-node all-target/all-feature workspace run passes **1,892
tests / 111 targets**, including all 16 original-node matrices. Default-feature
hash, ChaCha and units tests/doctests pass (644 passed, one existing ignored
example), covering formatting, block loops and partial-block processing.
Rust 1.94.1 checks the entire workspace with all targets and all features.
Formatting, whitespace checks and actionlint for the modified CI workflow pass.


### Safe address conversions and borrowed coinbase views (2026-11-17)

The two `transparent_newtype!` reference casts in `tidecoin` were removed.
Callers of the removed `Address::as_unchecked()` use `to_unchecked()`; callers
of `assume_checked_ref()` use `assume_checked()` on the Copy address. `BlockCheckedExt::coinbase()` returns
`CoinbaseRef<'_>`, which stores the transaction reference directly. Owned Coinbase
methods forward through `as_coinbase_ref()`, keeping the logic in one
implementation without overlapping the standard `AsRef::as_ref` name.
Tests check address/script preservation, transaction/input reference identity,
owned/view results and rejection of a view that outlives its transaction. These
are Rust API changes; node validation rules and wire formats are unchanged.
The public changelog records the API migration.

`tidecoin` now forbids unsafe code. The earlier lint-based Miri screening was
insufficient because external macro expansions escape that lint. The new
`contrib/check-expanded-safety.py` checks the pinned nightly's expanded AST,
including dependency macros. Compiler-generated unsafe blocks are identified
by rustc's `CompilerGenerated` marker; built-in `TrivialClone` implementations
require a compiler dummy keyword span and the exact generated trait path.
Handwritten lookalikes, including `automatically_derived` annotations, are not
excluded. Five compiler-backed regression tests cover built-in derives,
unsafe blocks/functions/traits/impls/extern declarations/attributes, external
macros despite `forbid`, cfg(test)-only code and unsupported output formats.
The pinned compiler's format and exceptions must be reviewed on nightly updates.

The explicit exemption list covers base58, ChaCha, consensus, consensus-core,
encoding, fuzz, network, P2P, tidecoin and units. The checker expands each library
with default, no-default and all features, and its unit/integration tests with
all features. It runs in normal CI and before Miri skips these crates. Miri's
preflight passes its target and CPU feature settings to the checker. Dependencies,
other feature combinations/targets, doctest bodies and fuzz binary targets are
outside the expansion claim. Node-parity retains its separate C++ FFI exemption;
hashes, internals, io and primitives remain selected for Miri.

Validation: all listed expansion checks and the five checker regression tests
pass. With the required pinned rc3 oracle, `cargo +1.99.1 test -p tidecoin
--all-features` passes 351 unit tests, 24 integration tests and 16 doctests
(one existing ignored doctest). Strict all-target/all-feature workspace Clippy
passes; Rust 1.94.1 checks all tidecoin targets/features. Formatting, workflow
validation and shell syntax checks pass.
The focused `coinbase_assume_methods` Miri test passes (6.88 seconds of test
execution); the full tidecoin Miri suite was not run. The explicit-target
expansion path also passes for base58 on x86_64-unknown-linux-gnu.

### Signature hash comparison (2026-11-18)

Legacy and witness-v0 digests were previously compared with the node only
through signature verification on fixed transactions, plus the node's
`sighash.json` vectors after test-side separator removal. The bridge now exposes
original `SignatureHash` (`tidecoin_node_signature_hashes`). Each query for one
input is computed with a shared `SigHashCache` and precomputed data, as a script
checker does, and again without caches; a disagreement between the node's own
paths is reported as an oracle failure. `compare_random_sighashes` (fuzz kind 4)
generates 1–5 inputs, 0–5 outputs, boundary versions, lock times, sequences and
prevout indexes, uncommitted witnesses, spent outputs and up to six queries per
input. Script code favors `OP_CODESEPARATOR` and truncated pushes. Legacy and v0
queries use raw hash types (bytes and 32-bit values). Witness v1 rejects undefined
hash types before hashing, so v1 queries map each value to one of the six defined
modes. Rust reuses one cache per version across the queries.

The comparison found one Rust discrepancy. `SighashCache::legacy_signature_hash`
serialized script code unchanged, while node `SignatureHash` serializes it with
`SerializeScriptCode`: `OP_CODESEPARATOR` at instruction boundaries is removed,
and at a malformed push the written bytes stop where `GetScriptOp` stops while
the length prefix still counts the whole script minus removed separators. The
interpreter already removed separators, so well-formed scripts were unaffected.
A signer passing raw script code with separators through the public API would
have produced signatures the node rejects. For script code ending in a malformed
push the spend is invalid either way, but a signature valid for the node digest
now passes an earlier signature check and reaches `BAD_OPCODE`, as in the node.
The Rust serializer now reproduces the node's. This is a Rust defect, not a node
defect.

The `sighash.json` test now passes the node's raw scripts. New node comparisons
cover 4,000 generated transactions, fixed separator and malformed-tail scripts
(also pinned byte-for-byte by a `consensus-core` unit test), and signed bare and
P2SH spends with a signature check before a truncated push, which return
`BAD_OPCODE` from both implementations. That signed regression fails with the
previous serializer.

The first fuzz campaign (seed 31) stopped after 330,809 runs on a harness defect,
not a digest mismatch: comparison bridges decoded transactions with the RPC hex
heuristics, which can reread a witness encoding as a different zero-input
legacy transaction. Script evaluation, input verification, witness sigop
counting and both digest bridges now decode Rust's encoding exactly; the typed
`CheckTransaction` comparison uses exact wire status. Fixture and edge tests that
need the RPC decoder (zero-input transactions) keep it. The input is a seed and an
exact replay test, which fails with the previous decoder.

Kind 4 uses first byte `0x04`, which previously selected kind 0; 458 of 18,122
entries in the saved corpus started with it. Campaign 3 used a merged corpus
with those entries rewritten to `0x00` plus 3,596 new entries (21,718 files).

| Campaign | Corpus | Runs | Result |
| --- | --- | --- | --- |
| Seed 31 (stopped) | Fresh seeds | 330,809 | Bridge decoding defect, fixed |
| Seed 32 (stopped for restart) | Campaign 1 corpus | 182,491 | No mismatch or sanitizer error |
| Seed 33, 25 minutes | Merged, 21,718 files | 1,080,687 | No mismatch or sanitizer error; coverage 7,681 |

Validation with the required pinned rc3 node and oracle: `cargo +1.99.1 test
--workspace --all-targets --all-features` passes 1,897 tests, with no failures or
ignored tests; workspace doctests pass 83 with two ignored. Strict all-feature
workspace Clippy, formatting, Rust 1.94.1 all-target checks and the
`consensus-core` no-default-feature build pass.

Limits: this is digest-level coverage of one input per generated transaction.
The mixed-input follow-up below checks signatures across all three inputs in
single-key layouts. Mutation testing of `sighash.rs` remains open.

### Mixed-input signed transactions (2026-11-18)

The required node suite compares whole three-input spends against pinned rc3.
Each executed signing script pushes one fixed public key and runs `OP_CHECKSIG`.
The first post-activation layout covers all 216 independent assignments of the
six hash modes to legacy, witness-v0 and native witness-v1 inputs. Five more
layouts cover six assignments each. Across the post-activation layouts all five
PQ schemes sign in each script version, with both bare/P2SH and native/wrapped
v0 forms. Testnet heights 999 and 1000 select the flags on either side of the
AuxPoW transition. The historical layout uses Falcon-512 legacy signing and
wrapped v0. Each key and signing RNG here belongs to the reproducible test corpus.

Each positive must pass the original verifier at every input. Paired edits change
a previous amount and an output, move an input with its previous output and change
a sequence, change an outpoint and append an output, or remove both witness
signatures. Tests pin which inputs succeed, the exact errors, and the change in
outcomes when the same bytes are verified across activation. The product
transaction verifier shares its cache across inputs and must return the first
original-node error in input order. The existing kind-3 fuzzer retains its
original comparison and can also select independent modes, paired edits and an
era switch. Its seed generator supplies 24 entries for this path.

Across 180 cases and six fee rates, the standalone oracle decodes the signed
bytes with witness. The tests compare Rust `weight()`, `vsize()` and
`FeeRate::mul_by_vsize` with the node's `GetTransactionWeight`,
`GetVirtualTransactionSize` and `CFeeRate::GetFee`, respectively.
For the fee actually paid, the test itself sums the supplied previous output
amounts and subtracts the transaction's output total. It checks this fixture
calculation against `Consensus::CheckTxInputs` using the same synthetic
non-coinbase coins. Rust UTXO lookup, chainstate and relay admission remain
outside this comparison.

The required rc3 all-target/all-feature workspace run passed 1,899 tests
with zero failures or ignored tests. Strict workspace Clippy, formatting,
MSRV 1.94.1 checks on the fuzz package and its expanded-code check passed.
The final ASan differential smoke run (seed 44) completed 19,986 runs in
101 seconds without a mismatch or sanitizer error. That count includes all
driver modes reached from the corpus.

A 25-minute ASan campaign against the pinned rc3 node (seed 45) then started from
24,529 entries: the saved digest-campaign corpus plus the current seed script,
of which 24 reach the mixed path. It completed 591,203 runs (including the initial
corpus pass) with no mismatch or sanitizer error, ending at 2,900 corpus entries
and coverage 12,524. The driver's opt-in counters (`TIDECOIN_FUZZ_MODE_STATS`)
print completed runs per mode every 256 runs, because libFuzzer reports only the
total. The last report, 99 runs before the end, recorded:

| Kind | Path | Completed runs |
| --- | --- | --- |
| 0 | Generated scripts | 405,925 |
| 1 | Wire decoding | 62,396 |
| 2 | Fixed-shape v1 digests | 14,676 |
| 3 | Signed templates | 63,725 |
| 4 | Generated-transaction digests | 44,382 |
| 3 + `MX` | Mixed signed transactions | 11,277 |

Mixed runs are a subset of kind 3 and each verifies two complete transactions.
They received about 2% of runs from this corpus, which is dominated by older
script-execution entries; a corpus seeded mainly with mixed entries would focus
a later campaign.

### Signed shapes: input counts, script mixes and error order (2026-11-18)

The mixed-input layouts always have three single-key inputs, so longer runs of
that generator repeat the same shapes. `fuzz/src/differential/mixed/shapes.rs`
adds signed transactions of other shapes. Each signature is made over a digest
from rc3 (`SignatureHash` or `SignatureHash512`), so a matching error in Rust
digest and verification code cannot make a positive case pass. Keys are
Falcon-512 test keys; the signing RNG is seeded from the digest.

**SIGHASH_SINGLE without a matching output.** Transactions have one, two or four
inputs. Earlier inputs are legacy and sign NONE; the last input is legacy, v0 or
v1 and signs SINGLE, with and without an output at its index (a one-input case
keeps its output to pass transaction sanity). Rc3 treats the missing output
three ways, and the fixtures use each: legacy signs the constant-one digest
(asserted from the node), v0 signs a digest with a zero output hash, and v1 has
no digest (both implementations decline, asserted), so its signature is the one
made while the output existed. Only the v1 input fails, with `EVAL_FALSE`; every
other input passes in both implementations.

**Script types in one transaction.** Four inputs: legacy single-key, v0 2-of-2
`CHECKMULTISIG`, v1 `IF <A> ELSE <B> ENDIF CHECKSIG`, and v0 single-key, with the
multisig and branch inputs in both orders and each branch taken. Each order has
its own valid signatures. These cases use the post-activation flags plus
`VERIFY_MINIMALIF`, which makes a non-minimal branch selector an error.
The unedited transaction passes at every input. Edits change one witness item
each: a non-empty multisig dummy (`SIG_NULLDUMMY`), a non-minimal IF selector
(`MINIMALIF`), an empty first multisig signature, or the opposite branch
(`EVAL_FALSE`), alone and combined (48 cases).

**Error order.** Twenty of those cases fail two inputs with different errors
(`SIG_NULLDUMMY` or `EVAL_FALSE` against `MINIMALIF` or `EVAL_FALSE`), in both
input orders. Each input is compared with rc3, and the Rust whole-transaction
verifier must return the first failing input's error in input order.

Pinned expectations were checked to be live: expecting the v1 SINGLE input to
pass, expecting a different multisig error, or making the whole-transaction
check take the last failure instead of the first each fails the suite.

The kind-3 fuzz driver gains an `SH` path beside `MX`. It rebuilds one pinned
shape, checks its expectation, then applies up to two unpinned edits (amount,
witness or scriptSig bit, sequence, lock time, input swap with its previous
output, removed or duplicated output, pre-activation flags) and compares the
result with rc3. The seed script adds 82 entries: every pinned case and 16 with
edits. Each edit takes five bytes; byte offsets use two of them, so a bit edit
reaches every byte of a Falcon-512 signature or a script containing a large
public key (the first version used one byte and reached only the first 256). The
pre-activation edit keeps the fixtures' extra `VERIFY_MINIMALIF` flag.

A 90-second ASan run from the seeds (seed 46) completed 18,511 runs with no
mismatch or sanitizer error. The last counter report at run 18,432 recorded
891 completed `SH` runs.

After the offset change, a 25-minute ASan campaign against the pinned rc3 node
(seed 47) started from only the 82 `SH` seeds. It completed 297,283 runs with no
mismatch or sanitizer error, ending at 2,397 corpus files and coverage 12,890.
The last counter report, 67 runs before the end, recorded 10,709 `SH` runs and
8,775 mixed runs; the rest were kinds 0–4 (136,886 / 14,205 / 10,925 / 87,251
including both signed paths / 47,949). Mutations of the first byte move inputs
to the faster driver kinds, so a seed-only corpus does not keep the campaign on
this path.

The driver therefore has a focus option. With `TIDECOIN_FUZZ_SIGNED_ONLY` set,
the first byte chooses the mixed (even) or signed-shape (odd) path and the rest
is that path's input, so mutations stay on the signed paths;
`seed-node-corpus.py DIR --signed-only` writes the 24 `MX` and 82 `SH` seeds in
that layout. Replay focused corpus entries and reproductions with
`TIDECOIN_FUZZ_SIGNED_ONLY=1`. The option is enabled by the variable's presence,
including a value of `0`; unset it for the general driver. Keep focused corpora
and reproductions in their own directories and record the mode alongside them.
The seed script writes into its destination without clearing existing entries,
so use a fresh directory when creating a focused starting corpus.

A focused 25-minute ASan campaign against the pinned rc3 node
(seed 48) started from those 106 seeds and completed 97,436 runs with no
mismatch or sanitizer error, ending at 348 active corpus entries, 433 saved
corpus files and coverage 11,081.
Every run took a signed path: the last counter report, 156 runs before the end,
recorded 55,462 `SH` and 41,818 mixed runs, about five times each of the
unfocused campaign above. The workspace still passes 1,901 tests with the
pinned node after the option was added.

Validation: with the pinned rc3 node and oracle, the workspace passes 1,901
tests with no failures or ignored tests. Strict workspace Clippy, formatting,
MSRV 1.94.1 and the fuzz expanded-code check pass.
