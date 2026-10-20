# Tidecoin rc2 migration plan

Status: phases 1–4 validated locally. Required rc2 CI is configured; hosted
execution and branch protection remain unverified. Phase 5 is next.
The corrected Falcon verifier uses a pinned public Git revision.

This is the implementation plan for bringing Rust `v2` into agreement with
Tidecoin `v1.0.0rc2`, followed by a Tidecoin-native PSBT product layer.
It is subordinate to [README.md](README.md). Findings and baseline test results
are recorded in [RC2_COMPATIBILITY_REVIEW.md](RC2_COMPATIBILITY_REVIEW.md).

Target node commit: `7d653be5d24e73b49d101578afb33d8d7a889c1d`.
Reviewed Rust implementation: `9e9b74581b765ad53ad902e3c7c10ea78817d0a7`.
Do not substitute a moving node branch without reviewing the delta and updating
this target explicitly.

The [repository compatibility principles](../AGENTS.md#compatibility-principles)
apply to every phase. The pinned C++ node is the behavioral authority; this plan
organizes implementation and evidence, not a separate protocol specification.
The long-term objective is a compatible foundation for a pure Rust node.
Node design review interrupts this migration only for a clear node logic defect
that could put funds at risk, using the reporting procedure in those principles.

## Phase status and dependencies

| Phase | Deliverable | Depends on | Status |
| --- | --- | --- | --- |
| 0 | Correct readiness documentation, record evidence, define migration gates | Reviewed baseline | Complete for planning; code compatibility remains open |
| 1 | Repair the node oracle and establish rc2 regression cases | 0 | Complete locally; evidence and oracle limits below |
| 2 | Implement spent-output context and rc2 v1 signature hashing | 1 | Complete locally; API contract and evidence below |
| 3 | Reconcile activation, hash types, sigops and header rules | 1 and the relevant phase-2 interfaces | Complete locally with pinned Git verifier; evidence below |
| 4 | Pass required parity CI, refresh provenance and publish a bounded compatibility claim | 2, 3 | Local gate passed; CI configured, hosted run pending |
| 5 | Implement PSBT and wallet signing workflows | Phase-4 compatibility checkpoint; API design may start earlier | Planned |

Completion requires recorded evidence. A passing local unit suite, a changed
fixture hash, or completion of a document does not close a consensus finding.

## Phase 0 — Documentation and contracts

- Record exact reviewed versions, findings R01–R13 and known test failures.
- Withdraw the unqualified current protocol-parity claim.
- Make this plan the implementation sequence in active validation/wallet docs.
- Keep older proof inventories as explicitly dated references.
- Separate consensus verification, relay policy, signing policy and PSBT state.
- Reference the repository compatibility principles and authoritative node
  behavior; do not add an independent normative specification or reopen the
  node's design review as a prerequisite to porting.

Gate: documentation entrypoints agree on the target, incomplete compatibility
status, implementation order and stateful exclusions. This gate authorizes no
claim that the implementation is rc2-ready.

## Phase 1 — Node oracle and regression baseline

Addresses R09, R11, R12 and supplies proof for R01–R08/R10.

1. Extend the shared C++ bridge, FFI and Rust harness to accept ordered spent
   outputs and initialize node precomputation correctly. Preserve the ability
   to test absent data and ANYONECANPAY without fabricating foreign outputs.
2. Audit copied bridge validation against the pinned node. Prefer direct node
   functions when practical; document copied behavior and add independently
   generated vectors where direct linkage is impractical.
3. Add a required parity mode that fails on missing/invalid node configuration.
   Keep optional local tests explicit about what they skip.
4. Hold activation flags fixed in monotonicity tests. Audit all analogous
   comparison helpers, not only the generated script-assets suite.
5. Promote review probes into durable tests, including the independent rc2
   sighash vector. Preserve the old failing baseline until behavior is repaired.

Gate: the harness can verify a known-valid rc2 non-ANYONECANPAY v1 spend with
complete previous outputs and reject the relevant missing/mutated data.
Each consensus finding has a regression case or a documented independent
source vector. Tests can distinguish a Rust defect from an oracle defect.

During migration, targeted expected failures may be recorded explicitly.
They must not be hidden by silently skipped node tests or weakened assertions,
and none may remain at the phase-4 checkpoint.

### Phase-1 implementation evidence (2026-10-20)

- The shared bridge accepts all spent outputs in input order. It calls node
  `PrecomputedTransactionData::Init` and `SignatureHash512` directly. Script
  fixtures supply their real credit output, matching node `DoTest`; empty
  context remains available for missing-data and ANYONECANPAY tests. Partial
  context is a bridge error, not a script-validation verdict.
- [tidecoin_rc2_oracle.rs](../consensus/tests/tidecoin_rc2_oracle.rs) has seven
  passing node-backed regressions: the independent rc2 digest vector, signed
  verification in all six modes, foreign amount/script mutations and reordering,
  absent/partial context, SINGLE out of range, activation/hash-byte errors,
  ML-DSA activation, raw v0 hash bytes versus policy, and regtest scrypt genesis.
- [tidecoin_rc2_pending.rs](../consensus/tests/tidecoin_rc2_pending.rs) asserts
  required Rust behavior for R02 and R10. Both failed at the phase-1 checkpoint
  and now pass after phase 2. Existing mismatches and provenance failures remain
  enabled; no metadata was refreshed to conceal them.
- All active monotonicity adapters keep PQ_STRICT, WITNESS_V1_512 and SHA512
  fixed. The shared helper tests all eight activation states.
- `TIDECOIN_NODE_PARITY_REQUIRED=1` rejects absent node configuration at build
  time and makes optional harness entrypoints fail instead of skip at runtime.
  A required build cannot be downgraded by removing the runtime switch.
  Configured runs check the compiled checkout path/revision and clean `src`.
  [NODE_REVISION](../node-parity/NODE_REVISION) pins the compiled reference;
  Cargo watches node headers/sources and Git metadata. Runtime source identity
  is checked once per process; do not change the node checkout during a run.
  Optional unconfigured runs report a skip. Stub and required-mode subprocess
  checks passed; a required build without the checkout failed as intended.

Run the oracle and configuration gates with:

```sh
TIDECOIN_NODE_REPO=/path/to/tidecoin TIDECOIN_NODE_PARITY_REQUIRED=1 \
  cargo test -p tidecoin-node-parity --offline
TIDECOIN_NODE_REPO=/path/to/tidecoin TIDECOIN_NODE_PARITY_REQUIRED=1 \
  cargo test -p consensus --test tidecoin_rc2_oracle --offline
```

The phase-1 checkpoint required-mode run of `tidecoin-node-parity` and `consensus` recorded
110 passes, 8 failures, no ignored tests. Six failures are the remaining
activation/hash and stale-provenance baseline; two are the new R02/R10
regressions. The product suite recorded 338 passes, 6 failures, no ignored tests.
The P2P unit/source suite added 109 passes. The final combined run therefore
recorded **557 passes, 14 failures, no ignored tests**. Both node script-corpus
round trips now pass. These are migration results, not an rc2 compatibility claim.

### Oracle scope and source references

The bridge now links node `pow.cpp` for proof targets, algorithm selection and
permitted difficulty transitions, eliminating its copies of those calculations.
Script verification, signature hashing, PQ operations, transaction sanity and
Merkle hashing also call the node implementation.

The final integration link exposed colliding C symbols between the node and
`rust-yespower`. The bridge now prefixes the node's Yespower and supporting
SHA-256/HMAC/PBKDF2 symbols at compilation, leaving node source unchanged.
This prevents link-order substitution as well as duplicate-symbol failures.
Archive inspection found no shared defined symbols between those C backends;
the combined product/oracle build and existing PoW parity tests passed.

The subsequent Yespower dependency update adopts published `rust-yespower`
0.3.0 and its owned context through `pow::YespowerHasher`. The one-shot
`yespower_pow_hash` also uses that context and releases its memory after each
call; workers can retain a hasher to reuse scratch memory. The crate's vendored
algorithm is unchanged from 0.2.0, and its owned wrapper uses the pinned node's
yespower 1.0 / N=2048 / r=8 / no-personalization parameters. All 136 PoW tests
passed, including reused-context and concurrent-worker comparisons against the
isolated node backend. The `no_std` + `pow` build and the published crate's
ASan/UBSan native allocation, failure and cleanup tests also passed. These
checks do not close the remaining activation/header findings.

At the phase-1 checkpoint, some boolean adapters remained copies because their node functions live in
`validation.cpp` with chain-state dependencies: `CheckAuxPowContextBridge`,
`CheckBlockBridge`, `CheckWitnessMalleationBridge`, `IsFinalTxBridge`,
`ContextualCheckBlockBridge` and `BlockSubsidyBridge`. Their acceptance paths
were compared with the matching rc2 functions; network constants come from
`src/kernel/chainparams.cpp`. These adapters do **not** prove equivalence of
validation-state categories, caches, header invalidation or chain connection.
Header proof validation does not run `ContextualCheckBlockHeader`. Its former
ordinary-chain-ID-bit rejection has been removed from this proof adapter,
matching the node's separation of proof and contextual checks. The original-node
validation follow-up below removes these copies and adds the missing direct oracle.

Remaining source-derived cases for phase 2/3 are anchored to the pinned node:

| Findings | Durable reference / next differential test |
| --- | --- |
| R01–R03 | Oracle digest/complete-context spends above; propagate that context through Rust signing and transaction verification |
| R04 | Oracle ML-DSA test and existing failing Falcon-1024/mixed-scheme suites; node `test/functional/feature_pq_scheme_activation.py` |
| R05 | Oracle activation cases; node `src/test/script_tests.cpp`, `script_witness_v1_512_activation` and `script_witness_v1_512_sigop_activation` |
| R06–R07 | Oracle hash-byte controls; node `witness_v1_hash_types_are_script_errors` (including unmatched multisig arguments) and `legacy_v0_hash_type_controls` |
| R08 | Oracle genesis case; node `src/test/pow_tests.cpp`, `regtest_auxpow_activation_override` and `regtest_auxpow_override_pow_and_difficulty_boundary`; node `test/functional/feature_header_version_activation.py` supplies full-header acceptance vectors |
| R10 | Enabled Rust malformed-context regression above; replace indexing failure with an explicit caller-context error in phase 2 |

The header functional vectors reject signed versions `4`, `0x1fe00004` and
`-0x7ffffffc` before activation while accepting ordinary versions `0x20010004`,
`0x20080004`, `0x201f0004`; at activation the ordinary chain-ID-bit restriction
applies. These are references to the node's executable cases, not a second
specification or a claim that the Rust header migration is finished.

## Phase 2 — Transaction context and signature hashing

Addresses R01, R02, R03 and R10.

1. Introduce validated transaction-wide previous-output context. Check count,
   input order contract, and agreement with separately supplied current-input
   amount/script data. Return errors rather than indexing malformed collections.
2. Compute SHA-512 spent-amount and spent-script commitments with the exact node
   serialization and field order. Use one authoritative precomputation path.
3. Make missing data fail closed for non-ANYONECANPAY v1. Preserve the smaller
   current-input data requirement for ANYONECANPAY.
4. Reject v1 SINGLE when its output is absent, including ANYONECANPAY.
   Preserve legacy/v0 consensus behavior.
5. Thread the context through `consensus`, public `tidecoin` validation and
   typed/byte APIs. Reuse transaction decoding and caches across inputs.
6. Document the API migration: old single-input APIs cannot silently compute
   the old v1 message when their arguments are insufficient.

Gate: cross-language digest and signature tests cover all six modes, multiple
inputs, native and wrapped v1, current/foreign amount and script mutations,
missing/wrong-sized context, and SINGLE output boundaries. ANYONECANPAY and
legacy/v0 controls demonstrate that unrelated commitments have not changed.

Implemented locally on 2026-10-20. This closes R01/R02/R03/R10 for the phase-2
scope; R04–R08 and the compatibility checkpoint remain open.

API decisions:

- `SpentOutputs` owns one `TxOut` per input in input order. The caller resolves
  actual outpoints; `TxOut` alone cannot prove that association. `None` means
  unavailable context; a supplied partial/extra set is a caller error.
- `SighashCache::new_with_spent_outputs` binds and validates the complete set.
  `new` remains available for legacy/v0 and v1 ANYONECANPAY. V1 signing returns
  `WitnessV1SighashError` for missing context, SINGLE without an output, invalid
  input indices or inconsistent current amounts. The script-code argument is
  the executed witness script, not the locking script.
- `PrecomputedTransactionData::new` and `TransactionContext::build_precomputed`
  now return `Result`. SHA-512 spent commitments replace the unused SHA-256
  fields. The interpreter uses the same v1 precomputation as the signer;
  transaction-hash readiness is separate from spent-output readiness.
- Typed and byte verification reject wrong counts and disagreement with the
  supplied current amount/locking script before execution. Those are Rust
  caller-contract checks, not additional node consensus rules. Missing digest
  during signature checking produces false, as in node `CheckPostQuantumSignature`;
  it is not an unconditional script abort. CHECKSIG NOT and NULLFAIL controls
  cover that distinction.
- `verify_transaction_inputs` shares one owned context and lazy cache across
  inputs. Product transaction verification resolves each outpoint once and
  calls it directly, eliminating repeated serialization/decoding. It explicitly
  retains the context-free sanity checks previously supplied by the decoder;
  a regression covers missing outputs, duplicate inputs and empty inputs.
  `tidecoin::consensus_validation::verify_script_with_spent_outputs` provides
  serialized single-input verification with complete context. Existing
  current-output-only methods cannot verify non-ACP v1 signatures.
- Mutable transaction access invalidates computed hashes. Callers changing
  input outpoints or order must construct a new cache with the matching outputs.
  Verification takes immutable transactions; caller state is not mutated.

Authoritative code reviewed: pinned `src/script/interpreter.cpp`,
`PrecomputedTransactionData::Init`, `SignatureHash512` and
`CheckPostQuantumSignature`; `src/script/sign.cpp::SignTransaction` and
`src/psbt.cpp::PrecomputePSBTData`. No node implementation was changed.

Executable evidence:

- `consensus/tests/tidecoin_rc2_context.rs`: all six modes and both input indices;
  repeated cache use; spent-script CompactSize boundaries 252/253 and
  65535/65536; native/wrapped signatures using Rust and node digests; current
  and foreign amount/script changes; missing and malformed context through
  typed/byte facades; SINGLE boundaries; legacy/v0 controls; cache invalidation.
- `consensus/tests/tidecoin_rc2_pending.rs`: both original phase-1 regressions
  now pass, including an explicit malformed-context error assertion.
- `tidecoin/tests/rc2_spent_output_context.rs`: product transaction and serialized
  APIs verify mixed native/wrapped multi-input spends against C++; prevout
  lookup order/count, missing UTXOs and changed amounts are checked.
- Node tests use `TIDECOIN_NODE_PARITY_REQUIRED=1` and the pinned checkout.
  The six context tests, two original regressions, product regression and seven
  phase-1 oracle tests pass. No-std checks pass for core, byte and product crates.

Final required-mode verification:

```sh
TIDECOIN_NODE_REPO=/path/to/tidecoin TIDECOIN_NODE_PARITY_REQUIRED=1 \
  cargo test -p tidecoin-consensus-core -p consensus -p tidecoin-node-parity \
  -p tidecoin --features tidecoin/tidecoin-node-validation --offline --no-fail-fast
cargo check -p tidecoin-consensus-core -p consensus -p tidecoin \
  --no-default-features --offline
```

The four-crate test run recorded **506 passed, 12 failed, 1 ignored**. The ignored
compact-filter documentation example predates this work; no migration test is
ignored. The twelve failures are eight existing activation/hash-type/script
cases and four stale-provenance checks across six targets: consensus fixture
hashes, PQ multisig parity, runtime diff, generated script assets, product lib,
and product policy provenance. Both original phase-2 failures now pass. This
run includes core and documentation tests, and excludes the separate P2P suite,
so its total is not directly comparable with the phase-1 combined total.
No-std and formatting/diff checks pass. Local logs:
`/tmp/rc2-phase2-final-suite.log`, `/tmp/rc2-phase2-final-nostd.log`.

The known phase-3/4 failures remain enabled; phase-2 success does not establish
full rc2 parity.

## Phase 3 — Consensus and policy boundaries

Addresses R04–R08 and consumers of phase-2 APIs.

- Gate Falcon-1024 and ML-DSA authorization on PQ_STRICT. Keep witness-v1
  cryptographic verification strict independently of that flag.
- Use flag-aware v1 execution recognition for native and P2SH-wrapped inputs.
  Retain structural address/script classification independently of activation.
- Add flag-aware sigop accounting and update policy/weight consumers.
- Enforce defined nonempty v1 hash bytes before signature matching, including
  every argument of an executed multisig opcode.
- Add bit-16 DEFINED_HASHTYPE support and apply it to relay policy without
  accidentally adding it to legacy/v0 consensus or existing-final verification.
- Preserve raw hash-type bytes in legacy/v0 consensus sighash calculation.
  Keep typed signing-mode validation separate.
- Fix ordinary-header chain-ID handling, the full signed-version preactivation
  minimum, and regtest genesis PoW under delayed/disabled activation.
- Review proof-error semantics exposed to callers so replaceable AuxPoW proof
  failure is not presented as permanent header invalidity.

Gate: differential tests cover before/at/after activation, independently selected
activation flags, disabled activation, native/wrapped scripts, empty signatures,
all six defined bytes, undefined bytes, unreachable multisig arguments and
legacy/v0 historical controls. Header tests include explicit heightless versus
height-known contracts and regtest height zero.

### Phase-3 implementation evidence (2026-10-20)

R04–R08 have local implementations and source-derived tests. R14 is resolved
by adopting the corrected verifier as a pinned Git dependency. The phase-3
checks pass through the normal manifest, without local overrides. No node
change or funds-risk defect was found.

- The interpreter gates scheme eligibility on PQ_STRICT, selects the node's
  legacy Falcon profile for legacy/v0 execution before that flag, and always
  uses strict verification for active v1. A union of strict and legacy profile
  acceptance is not the node's preactivation rule: their padding rules differ.
- Flag-aware witness recognition is shared by execution and sigop counting.
  Structural classification remains independent. `total_sigop_cost_with_flags`
  accepts candidate flags; its older convenience wrapper assumes active rules.
  Relay prechecks now use candidate flags. Coinbase and non-push-only P2SH
  counting follow the node's guards.
- `VERIFY_DEFINED_HASHTYPE` is bit 16. Relay flag selection adds it;
  `STANDARD_SCRIPT_VERIFY_FLAGS` does not. Active v1 always checks nonempty
  signature hash bytes, including unmatched multisig arguments. FindAndDelete,
  NULLFAIL and NULLDUMMY ordering follows the original interpreter.
  `p2wsh_signature_hash_raw` preserves the complete raw v0 hash-type word;
  typed signing remains restricted to the six defined modes.
- Contextual header checks enforce the complete signed preactivation version
  minimum and the postactivation ordinary chain-ID rule. Proof checking no
  longer rejects those ordinary bits. `Params::pow_genesis_scrypt` preserves
  regtest's genesis algorithm under delayed/disabled activation.
  `AuxPowValidationError::is_replaceable_proof` exposes the node's proof-error
  category; it does not guarantee that a valid replacement exists.

[tidecoin_rc2_rules.rs](../consensus/tests/tidecoin_rc2_rules.rs) contains eight
passing differential tests with the corrected backend: every raw hash byte in
legacy/v0 and v1 error checks; all five schemes; independent activation flags;
native/wrapped witness; empty/unmatched signatures; error precedence; ordinary
zero/negative-zero evaluation; unknown witness versions; and Falcon norm/length/
padding boundaries for both digest widths and Falcon degrees.

[rc2_spent_output_context.rs](../tidecoin/tests/rc2_spent_output_context.rs) adds
original-node `CountWitnessSigOps` comparisons and `UseScryptPoW` comparisons
across networks and activation overrides. Header-version tests use explicit
vectors from `feature_header_version_activation.py` and the original
`ContextualCheckBlockHeader` source. They do **not** execute that original
contextual function through the phase-3 bridge. The follow-up below adds direct
execution. Phase-3 proof-error category checks were also source-derived; full validation-state/cache equivalence remains outside this
oracle. Existing positive mixed-scheme fixtures now select the activation flag
required by their original-node callers; new matrices test rejection before it.

R14 is adopted through a direct Git dependency in `consensus-core/Cargo.toml`:
`tide-fn-dsa-vrfy` 0.4.1 at
[`522f179ae3fdbcf180854f17a41de520013e9ec6`](https://github.com/tidecoin/tide-fn-dsa/commit/522f179ae3fdbcf180854f17a41de520013e9ec6).
The full commit pin fixes the source for downstream builds as well as this
workspace; no local path or workspace-only patch is needed. The verifier's
common crate is taken from that same revision. Its common source matches
published 0.4.0; signing and key-generation dependencies remain on 0.4.0.

The fix removes the legacy signer-size restriction and enforces profile-specific
compressed-body consumption in scalar and AVX2 verification. It was prepared
from `30e5695f4c5718b1625d8f4227bed1ff0e872692` in the isolated
`/home/yaroslav/dev/tidecoin/tide-fn-dsa-rc2-parity` checkout. The original
checkout's 39 formatting-only changes were preserved. Both verifier defects
originated in the fork's earlier `cd909421` Falcon compatibility additions.

The commit is available on the public release branch. crates.io publication
remains deferred because the available account lacks crate ownership; it is
not required for Git-based development, CI or downstream use. Before publishing
the dependent Rust crates to crates.io, publish the fixed verifier there and
replace the Git dependency with an appropriate registry version requirement.

The synthetic vectors and their independent Python generator live in
[tests/data](../consensus/tests/data/generate_rc2_falcon512_legacy_boundary.py).
They use chosen test keys, not production signing keys. The original node
accepts a 745-byte legacy-only signature that published Rust rejects, and
rejects arbitrary zero padding that published Rust accepts. Excess-norm,
truncation and padding controls remain enabled. The fixed package passes its
four unit tests and documentation example in normal and `no_avx2` builds,
including direct scalar/AVX2 checks, and `cargo package` verification against
published `tide-fn-dsa-comm` 0.4.0.

Validation uses the normal manifest, without dependency overrides. Fetch the
public Git revision once; subsequent checks can run offline:

```sh
cargo fetch
TIDECOIN_NODE_REPO=/path/to/pinned-node TIDECOIN_NODE_PARITY_REQUIRED=1 \
  cargo test -p tidecoin-consensus-core -p consensus -p tidecoin-node-parity \
  -p tidecoin --features tidecoin/tidecoin-node-validation --offline --no-fail-fast
cargo check -p tidecoin-consensus-core -p consensus -p tidecoin \
  --no-default-features --features tidecoin/pow --offline
```

The four-crate run using the public Git dependency records **526 passed,
4 failed, 1 ignored**. All four failures
are unchanged provenance gates: fixture hashes, generated script-assets metadata
and monotonicity, and product policy provenance. The ignored compact-filter
documentation example predates this work. No-std including `pow` also passes.
All eight new rule tests now pass, including both Falcon regressions. The
pre-adoption run with registry 0.4.0 recorded **6 passed, 2 failed**, preserving
proof of both R14 discrepancies; no test was skipped or weakened.
Current logs: `/tmp/rc2-phase3-final-suite-git.log`,
`/tmp/rc2-phase3-nostd-git.log`. Historical failure log:
`/tmp/rc2-phase3-rules-published.log`.

Phase 4 follows below. The Git pin removes registry publication as a prerequisite
for development and CI; registry release remains separate.

## Phase 4 — Compatibility checkpoint and release evidence

Addresses R11/R12 and closes the protocol subset of R01–R10.

1. Provision the exact node revision in required CI; enable both consensus
   tests and the product's `tidecoin-node-validation` feature.
2. Correct branch triggers and base-branch assumptions for the repository's
   maintained `v2`/`main` branches.
3. Regenerate provenance only after semantic fixes and oracle repairs pass.
   Explain changed vectors and preserve historical rule-era fixtures separately.
4. Update the proof matrix with rc2 test names, source commits and coverage
   limits. Update public compatibility, API migration and release documentation.
5. Record each command, environment, result and any remaining exclusion.

Required checks:

```sh
export TIDECOIN_NODE_REPO=/path/to/tidecoin-at-the-pinned-commit
cargo test --workspace --all-targets
cargo test -p tidecoin --lib --tests --features tidecoin-node-validation
cargo clippy --workspace --all-targets
cargo test -p tidecoin-fuzz --all-targets
```

Also run the feature/no-std matrix in
[NODE_PARITY_PROOF_MATRIX.md](NODE_PARITY_PROOF_MATRIX.md), focused new
regressions and bounded fuzz smoke runs for the changed surfaces. Build the
node oracle after source/header changes; no stale compiled bridge may satisfy
the gate. Workspace testing alone does not enable the product parity feature.

Gate: no unresolved consensus mismatch, no unexpected skip in required parity
jobs, current provenance, and passing required checks. The resulting claim is
protocol-library compatibility for the named surfaces and node revision, not
full chain/mempool acceptance. PSBT remains incomplete until phase 5 passes.

## Phase 4 implementation evidence (2026-10-20)

Local checkpoint passed on `v2` with Rust/Cargo 1.94.1 and the normal manifest
(including the public verifier Git pin). The C++ checkout was clean at
`7d653be5d24e73b49d101578afb33d8d7a889c1d`. The oracle was rebuilt in a new
`target/rc2-clean` directory before the workspace gate; later lint/generator
fixes were recompiled and rechecked there. No local dependency patches were used.

For the node-backed commands below:

```sh
export TIDECOIN_NODE_REPO=/home/yaroslav/dev/tidecoin/tidecoin
export TIDECOIN_NODE_PARITY_REQUIRED=1
# Clean-build workspace gate used this directory:
CARGO_TARGET_DIR="$PWD/target/rc2-clean" cargo test --workspace --all-targets --offline --no-fail-fast
cargo test -p tidecoin --lib --tests --features tidecoin-node-validation --offline
cargo clippy --workspace --all-targets --offline
cargo test -p tidecoin-fuzz --all-targets --offline
```

| Check | Result |
| --- | --- |
| Workspace/all targets, freshly built node oracle | 1,794 passed, 0 failed, 0 ignored across 98 test groups |
| Product library/integration tests with node feature | 351 passed, 0 failed, 0 ignored; overlaps workspace tests |
| Workspace Clippy | Passed without warnings |
| All nine feature/no-std commands in the proof matrix | Passed, including isolated library checks and P2P serde with/without defaults |
| `cargo test -p tidecoin-fuzz --all-targets` | Passed; builds test harnesses, not a libFuzzer campaign |
| New arbitrary-header regression and no-default `arbitrary` primitives build | Passed |
| Six stable libFuzzer smoke runs | Passed after the generator correction below; 15-second budgets, sanitizer disabled |
| Changed workflows | actionlint 1.7.7 passed for rust, Miri and shellcheck workflows; YAML parsed |
| `git diff --check` | Passed |

Fuzz invocation: `cargo fuzz run <target> --sanitizer none -- -max_total_time=15
-max_len=4096` (cargo-fuzz 0.13.1). Targets and completed iterations:
`consensus_script_runtime` 815,632; `tidecoin_script_policy` 3,022,647;
`tidecoin_tx_out_policy` 3,689,038; `tidecoin_transaction_policy` 901,491;
`tidecoin_block_sanity` 465,051 after correction; `tidecoin_pow` 6,066.
These are bounded crash/invariant smoke runs, not differential or exhaustive proofs.
The consensus target now exercises complete spent-output context as well as absence.

The first block-sanity run found an `Arbitrary<Header>` defect: random version
bits could signal AuxPoW while the generator always supplied no payload. An
encoded malformed block could then decode with transaction bytes misread as the
payload, violating the target's round-trip assertion. Original node
`src/primitives/block.h` explicitly rejects serialization with the flag set and
payload absent. The generator now clears only that flag when generating no
payload; all other version bits remain random. The focused header regression,
the original crashing input, and the rerun pass. This changes fuzz input
construction, not consensus acceptance or production serialization.

Provenance was regenerated with the existing generators after reviewing the
node delta. The proof matrix records changed script vectors, the unchanged
30-case monotonicity and 33-case stateless policy corpora, six changed policy
source hashes, and preserved historical chain fixtures. No expectations were
weakened to satisfy new hashes. The export's initial stale-metadata failure was
expected; both integrity and monotonicity tests pass after regeneration.

CI now provisions `node-parity/NODE_REVISION` on a fresh runner and sets required
mode for workspace and product tests, Clippy and feature checks. Push triggers
cover `v2`/`main`; prerelease and PR mutation comparisons use the actual base
branch rather than `master`. The pinned maintainer-tool source was checked to
confirm its `prerelease --baseline` option. Miri/shellcheck branch filters were
updated too. **Hosted CI execution and branch protection have not been verified**;
no push or repository-settings change was made in this phase.

Evidence logs are local `/tmp/rc2-phase4-{workspace,product,clippy,fuzz-tests}.log`,
`/tmp/rc2-phase4-matrix.json`, `/tmp/rc2-phase4-matrix-*.log`, and
`/tmp/rc2-phase4-fuzz-*.log`; workflow validation is
`/tmp/rc2-phase4-actionlint.log`. The initial fuzz failure remains in
`/tmp/rc2-phase4-fuzz-tidecoin_block_sanity.log`; the successful replay and rerun
are `...-fuzz-replay.log` and `...-fuzz-tidecoin_block_sanity-fixed.log`.

The bounded claim covers the named protocol-library surfaces, with the phase-1
copied-bridge and header-oracle limitations retained at that checkpoint; the
follow-up below supersedes those two limitations. It does not establish
stateful node acceptance, full descriptor/PSBT interoperability, original node
functional-suite execution, long sanitizer campaigns or all CI architectures.
Actual spent-output association remains caller-owned. Registry publication is
still deferred; it is not required for Git-based development/CI.

## Original-node validation follow-up (2026-10-20)

The standalone `node-parity/validation-oracle` executable compiles the complete,
unmodified original `src/validation.cpp` and links the node libraries. Including
that translation unit gives access to its static contextual checks without
copying their bodies. Script, signature-hash and crypto comparisons retain the
existing original-source bridge. No node source changes were made.

| Former copied check | Original function now executed |
| --- | --- |
| Header proof and AuxPoW context | `CheckBlockHeader`, including its original proof helpers |
| Context-free block checks | `CheckBlock` |
| Witness malleation/commitment | `CheckWitnessMalleation`, called by `ContextualCheckBlock` |
| Transaction finality | `IsFinalTx`, called by `ContextualCheckBlock` |
| Contextual block checks | `ContextualCheckBlock` |
| Subsidy | `GetBlockSubsidy` |
| Previously absent contextual-header oracle | `ContextualCheckBlockHeader` |

The copied rule implementations and their obsolete C exports were removed.
Remaining lightweight PoW bridge calls still construct network parameter inputs;
the new executable also compares 20 unmodified original network defaults against
Rust on mainnet, testnet and regtest. Controlled activation/retarget overrides
are used separately for boundary cases.

`rc2_original_validation.rs` exercises 360 contextual-header cases covering
activation, signed/base versions, chain-ID bits, MTP/future time, BIP94 timewarp,
legacy and post-activation retargets, minimum difficulty and buried deployments.
Seven AuxPoW cases compare acceptance, reject reason and replaceable-proof
category, including malformed commitments and invalid parent work. Existing
block, witness, finality and subsidy suites now execute the original functions.

The client checks the executable's node revision and `validation.cpp` SHA-256
against the pinned clean checkout. Missing binaries, stale identities, malformed
responses and subprocess failures are infrastructure errors, never rejection
verdicts. Decode rejection is distinct from validation rejection. Configuration
regressions cover absent binaries, wrong revisions and wrong source hashes.

Build and run from the repository root (CMake >= 3.22, a C++20 compiler, Boost,
libevent and pkg-config are required):

```sh
export TIDECOIN_NODE_REPO=/path/to/clean/tidecoin
export TIDECOIN_NODE_PARITY_REQUIRED=1
cmake -S node-parity/validation-oracle -B target/node-oracle \
  -DTIDECOIN_NODE_REPO="$TIDECOIN_NODE_REPO" -DCMAKE_BUILD_TYPE=Release
cmake --build target/node-oracle --target tidecoin-validation-oracle -j 2
export TIDECOIN_NODE_VALIDATION_ORACLE="$PWD/target/node-oracle/tidecoin-validation-oracle"
cargo +1.99.1 test --workspace --all-targets
cargo +1.99.1 test -p tidecoin --lib --tests --features tidecoin-node-validation
cargo +1.99.1 clippy --workspace --all-targets --features tidecoin/tidecoin-node-validation
cargo +1.99.1 fmt --all -- --check
```

The existing explicit-flags block adapter supplies activation choices and an MTP
cutoff to actual node deployments; its domain is height >= 1 and a `u32` cutoff.
The contextual-header adapter constructs connected `CBlockIndex` history from
caller-supplied headers. It does not establish that the supplied history was
itself accepted. Checks use fresh caches and temporary test directories. This
is direct function-level parity, not `AcceptBlockHeader` cache/invalidation,
UTXO chain connection, reorg or full-node acceptance parity.

CI builds this executable from the pinned node checkout. The stable tooling pin
is now 1.99.1; package MSRVs remain unchanged, with the product at 1.94.1.
Formatting invokes stable Cargo directly because the pinned maintainer wrapper
hardcodes nightly for `fmt`. Nightly remains for forward-compatibility tests,
specialized checks and inherited maintainer-tool audits. The stable node gate
runs its own Clippy checks. This does not add a nightly requirement for users.

Local verification passed on Rust 1.94.1 and 1.99.1: 1,796 workspace tests
plus four successful configuration-child invocations; 356 product tests with
`tidecoin-node-validation` (overlapping the workspace suite); no failures or
ignored tests. All nine no-std/feature checks pass on 1.99.1, as do stable format
and workflow syntax checks. Stable 1.99.1 Clippy completes successfully with
new style/unused-import warnings in existing code; this is not a warning-free
lint claim. The removed Clippy lint `from_iter_instead_of_collect` was deleted
from workspace configuration. Logs: `/tmp/rc2-direct-{workspace,product}.log`,
`/tmp/rc2-stable-{workspace,product,clippy,format}.log` and
`/tmp/rc2-stable-matrix.json`. The checkpoint was pushed to `v2` as
`163e20db122dd1883ffe638718c49647797769b7`.

The [first hosted run](https://github.com/tidecoin/rust-tidecoin/actions/runs/39493025017)
passed stable formatting, policy, ASan and 32-bit tests. It exposed inherited
maintainer jobs expecting the absent `Cargo-recent.lock`, an unnecessary
unauthenticated fetch after checkout, and a missing explicit `hex` feature in
the new oracle client's hash dependency. Follow-up fixes generate a runner-local
lockfile, use the pinned wrapper's `--lock-file existing` option, reuse already
fetched branch refs, and declare the dependency feature. Strict local stable
builds and API docs pass after fixing duplicate test imports, broken doc links
and the existing cpufeatures deprecation annotation. The pinned nightly all-feature
Clippy pass preserves opcode-arm structure with narrowly scoped style exceptions.

Branch protection was inspected: `v2` is unprotected and has no enforced status
checks. The job name does not configure this setting. Hosted node parity and the
corrected workflow are still being verified; no all-CI-green claim is made yet.

The second hosted run also passed Kani code generation after the explicit hash
feature fix. Its isolated no-std tests exposed a missing test-only `ToString`
import; docs.rs exposed the missing `doc_cfg` declaration. Both were repaired.
All 15 crates subsequently passed isolated no-default-feature Clippy locally,
and the docs.rs build passed. These fixes do not change runtime consensus rules.

## Phase 5 — PSBT and wallet product layer

Addresses R13. Design may proceed during earlier phases; shipping signing
depends on the phase-4 consensus checkpoint.

Use existing transaction, script, PQ, PQHD, fee and weight primitives. Do not
restore removed upstream signing infrastructure or introduce another verifier.
Decide the PSBT module/crate boundary, supported versions/templates and
resource limits before implementing the parser.

Implement in reviewable slices:

1. **Format and data integrity:** BIP174-style container, PQ public keys,
   unknown/proprietary record preservation, duplicate/conflicting key handling,
   previous-transaction/outpoint checks and consistent dual UTXO records.
2. **Public updates and combine:** distinguish absent declarations from explicit
   ALL, preserve foreign-input modes, reject conflicts, and make explicit public
   declaration updates atomic.
3. **Signing and finalization:** explicit consent for nondefault modes on owned
   inputs, phase-2 spent-output context, defined signing modes and refusal of new
   SINGLE signatures without a corresponding output. Verify existing finals
   under consensus rules rather than imposing new-signature restrictions.
4. **External signing data contract:** require full previous transactions for
   unfinished legacy targets before contacting a signer and validate returned
   changes. Keep foreign-input fee evidence distinct from target signability.
5. **Analysis and extraction:** distinguish per-input issues, missing solving
   data and next roles; preserve independently computable fees and omit
   unresolved size/fee-rate estimates. Verify finals before extraction.
6. **PQHD, descriptors and cleanup:** support Tidecoin origin records and
   native/wrapped wsh512. Preserve seed-ID storage encoding. Make any full-tx
   cleanup conditional on the node's transaction-wide eligibility checks;
   cleanup must not be advertised as fee authentication.
7. **Spend construction:** compose recipients, inputs, fees and change around
   these validated signing/PSBT contracts.

Node contract references: `doc/psbt.md`, `doc/external-signer.md`,
`src/psbt.{h,cpp}`, `src/script/sign.{h,cpp}` and
`src/script/descriptor.cpp` at the pinned revision.

Gate: node-to-Rust and Rust-to-node round trips, combine/sign/finalize/extract
interoperability and negative tests for consent, UTXO conflicts, missing data,
unknown fields and wrong scripts. Include multiple owners, mixed input types,
all six modes, all supported schemes, verified historical legacy/v0 finals,
signatureless finals and cleanup eligibility. Use the node's
`rpc_psbt_witness_v1.py`, `rpc_psbt_signing_policy.py`, `rpc_psbt_complete.py`,
`wallet_pqhd_psbt.py` and multisig PSBT suites as behavioral references.

## Maintenance rules

- Update finding status and evidence as each phase lands; do not relabel this
  baseline assessment as a later successful test run.
- Keep documentation alongside semantic/API changes, not only at phase 4.
- Do not change node rules, network activation heights or existing provenance
  merely to make Rust tests pass.
- Keep full chainstate, cluster mempool, RPC broadcasting and node database
  migration outside this plan.
- Record implementation commits with the repository-required assistance trailer.
