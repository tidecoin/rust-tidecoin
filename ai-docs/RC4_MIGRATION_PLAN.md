# rc4 compatibility migration

Status: implementation and local validation complete. Release versions prepared;
hosted CI and publication are pending at this checkpoint.

## Authority and scope

The compatibility target is the signed Tidecoin `v1.0.0rc4` tag,
`78aca4a6b656f43a1efe4b43cf884214219b6c09`. The previous target was rc3,
`ffed4e92e60ff2de30361648a71cba64531f9077`. Rust starts from `ec7575f`,
after the published `v0.34.0-beta.1` release at `882df93`.
`node-parity/NODE_REVISION` enforces the new target. The C++ source remains the
behavioral authority under [AGENTS.md](../AGENTS.md).

The complete rc3-to-rc4 diff has three commits and 28 changed files:
`b91db7aab4` (wallet fees/weights/preview), `822eedd25e` (CMake includes),
and `78aca4a6b6` (release metadata/documentation). No changes occur in consensus,
script execution, signature hashing, PQ verification/signing, PQHD derivation,
transaction serialization, mempool policy constants or activation settings.
Mainnet AuxPoW remains disabled; testnet activation remains at height 1,000.

## Source review and Rust disposition

| rc4 change and original source | Rust disposition |
| --- | --- |
| `wallet/spend.cpp`: `CreateTransactionInternal` counts selected inputs with CompactSize, charges change's marginal output-count growth, reconciles change and retries selection when the input-count width grows. Recipients change only when fee subtraction was requested. | Rust has no wallet funding/coin-selection/reselection implementation. Existing `predict_weight` already counts both complete vectors and their CompactSize widths. Add combined count/change/mixed-input regressions against original node serialization; do not reproduce wallet selection in a new rule set. |
| `GetTransactionWeightLimit`, its final selected-parent call, and the pre/post-sign weight checks enforce requested/default limits and version-3 unconfirmed-parent limits on complete maximum signed weight. | Rust exposes transaction/policy sizing, not wallet construction with authenticated parent/mempool state or a caller weight budget. Keep the existing policy constants and validation behavior. A sizing result does not enforce these wallet constraints. |
| `CalculateMaximumSignedInputWeight` and `FetchSelectedInputs` compare explicit input budgets in WU before vsize rounding. The budget convention includes an empty witness count even for legacy inputs. | Existing `TxInExt::segwit_weight` uses this convention; `legacy_weight` and a non-witness `InputWeightPrediction::total_weight` intentionally do not. Document the distinction and compare exact input WU to original `GetTransactionInputWeight`, including equal-vsize/different-WU examples. Rust has no explicit-input-budget validator to port. |
| `PreviewTransaction`, `GetChangeScriptForPreview`, wallet interfaces and Qt coin control now use actual scripts, per-recipient subtraction and ancestor fees; unavailable estimates stay unavailable. | No Rust wallet database, GUI preview, change reservation or ancestor-fee lookup exists. Preserve these as future wallet requirements rather than claiming preview parity. The new C++ helper reads cached descriptor output; it does not change PQHD or key derivation. |
| `src/CMakeLists.txt` moves includes to `core_interface`. | Reconfigure and rebuild the original-source oracle against rc4; its existing target links `core_interface`. |
| Release metadata, manuals, Qt/wallet tests and `wallet_fee_accounting.py`. | Review as caller/regression evidence. The original node functional scenarios inform library arithmetic tests; passing those does not establish wallet funding or PSBT parity. |

No production Rust behavior mismatch has been established by this source review.
The upgrade updates the enforced node target and adds source-derived evidence.
The existing local/external signature-size distinction and fee-rate arithmetic
remain unchanged. Synthetic maximum signatures are sizing fixtures, not valid
signatures or evidence of script acceptance.

## Implementation and validation

1. Add original-node transaction/input-weight comparisons for complete mixed
   legacy/v0/native-v1 shapes, all PQ schemes, local/external signature sizes,
   input/output counts around 252/253, and adding/removing change.
2. Pin rc4, rebuild both original-source bridges and the standalone oracle.
3. Run focused new regressions and the full original-node workspace suite,
   including existing signing, Falcon bounds, WIF, PQHD, script, witness and
   sighash checks. Validate MSRV, features, strict Clippy and formatting.
4. Refresh fixture provenance only after confirming source/data are unchanged
   and the original-node comparisons pass. Record actual results below.

No new scheduled campaigns are added. The five broader investigation areas in
[the rc3 follow-up](RC3_MIGRATION_PLAN.md#ordered-compatibility-follow-up) remain
open unless separately completed; changing the node pin does not close them.

## Evidence

The local node worktree is clean at the rc4 tag, and `git verify-tag v1.0.0rc4`
passed. The standalone oracle was reconfigured and rebuilt successfully with the
rc4 CMake sources. Focused tests passed (2 tests, 901 original-node requests).
The full original-node workspace suite passed (1,907 tests, 0 failed/ignored),
including the existing Falcon boundary, repeated normal/legacy signing, WIF,
PQHD, ML-KEM, script, witness, sighash, wire, block/context and policy comparisons.
No production Rust behavior change was required. Validation uses the existing
local dependency resolution; this is not a new dependency upgrade.

| Local check | Result |
| --- | --- |
| Original-source rc4 oracle configure/build | Passed. |
| Focused rc4 sizing/input-weight tests | 2 passed; 901 oracle requests. |
| Workspace, all features/all targets, required node mode | 1,907 passed; 0 failed; 0 ignored. |
| Strict Clippy, default and all features/all targets, Rust 1.99.1 | Passed. |
| MSRV 1.94.1, workspace/all features/all targets | Passed. |
| Workspace without default features | Passed. |
| Core without default features, MSRV 1.94.1 | 40 tests passed. |
| Workspace all-feature doctests | 83 passed; 0 failed; 2 ignored. |
| Expanded-code screening, pinned nightly | Passed. |
| Formatting and diff whitespace | Passed. |
| Release dry run, tidecoin 0.34.0-beta.2 and node-parity 0.2.1, all features | Passed using registry dependencies for the other workspace crates. |

Hosted CI has not run on this release checkpoint. No new long fuzz campaign,
Miri run, native non-Linux run or wallet functional run is claimed here. The
original node's changed wallet behavior was reviewed at source and mapped to
Rust's implemented surface; its funding engine and Qt UI are not implemented
or tested through this library's oracle.

The count/change matrix has 900 requests: five PQ schemes, two size modes, three
layouts (legacy-only, witness-only and mixed), five input/output count pairs,
change present/absent and three fee rates. Mixed inputs rotate all five schemes,
include wrapped-v0 and witness-script satisfactions, and use per-input size modes.
Both iterator and slice prediction APIs agree with serialized Rust weight and
the node's original weight/vsize functions. Every input's SegWit weight agrees
with `GetTransactionInputWeight`. The separate test pins 173/174/175/176 WU,
which all round to 44 vbytes, and the legacy 164-WU versus budget 165-WU distinction.
These examples do not exercise the node wallet's explicit-budget validator.

All fourteen policy-provenance source files and both PQ script-vector files are
byte-identical between rc3 and rc4. The existing generators were rerun; both
tracked provenance files changed only their source revision. The generated
30-case script corpus retains SHA-256
`9bfbfe565a9ec22a8be72cc577e877164251a2b2789451da705d4c1387d1f637`;
the 33-case policy corpus retains SHA-256
`5b26286e5e17300c337a07d165c48d11ef94dc965d0fb68bfc8deb05ee3ef775`.
The full suite checks the regenerated provenance and comparisons.

## Validation commands

From the Rust workspace root, with the clean rc4 node checkout:

```sh
export TIDECOIN_NODE_REPO=/home/yaroslav/dev/tidecoin/tidecoin
export TIDECOIN_NODE_PARITY_REQUIRED=1
export TIDECOIN_NODE_VALIDATION_ORACLE="$PWD/target/node-oracle/tidecoin-validation-oracle"
cmake -S node-parity/validation-oracle -B target/node-oracle \
  -DTIDECOIN_NODE_REPO="$TIDECOIN_NODE_REPO" -DCMAKE_BUILD_TYPE=Release
cmake --build target/node-oracle --target tidecoin-validation-oracle -j 2
cargo +1.99.1 test -p tidecoin --features tidecoin-node-validation --test rc4_fee_accounting
cargo +1.99.1 test --workspace --all-features --all-targets
cargo +1.99.1 clippy --workspace --all-targets --all-features -- -D warnings
cargo +1.99.1 clippy --workspace --all-targets -- -D warnings
cargo +1.94.1 check --workspace --all-targets --all-features
cargo +1.99.1 check --workspace --no-default-features
cargo +1.94.1 test -p tidecoin-consensus-core --no-default-features --lib
cargo +1.99.1 test --workspace --all-features --doc
python3 contrib/check-expanded-safety.py
cargo +1.99.1 fmt --all --check
```

## Rust release versions

This checkpoint prepares `tidecoin` **0.34.0-beta.2** and
`tidecoin-node-parity` **0.2.1**. The product's optional node-parity dependency
requires 0.2.1 so rc4 test builds cannot silently resolve the old rc3 pin.
Other crate versions and external dependency requirements are unchanged.
The public API and production behavior remain compatible with beta.1.

Publication order is node-parity, then tidecoin. Validate the two packages
together before upload, using the other eleven already-published workspace
packages from crates.io. After upload, compare downloaded archive checksums and
source commit information, and build a separate registry-only consumer on the
MSRV. The release process commits and pushes this checkpoint, checks hosted CI,
and publishes only these two new versions; it does not republish unchanged crates.
