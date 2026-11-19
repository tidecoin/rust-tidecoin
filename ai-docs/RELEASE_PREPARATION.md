# Release preparation (2026-11-19)

Status: version/dependency updates and local package/compatibility validation
complete. Registry publication and release tagging remain pending.
The prior standalone `consensus` decision remains: `publish = false`.

## Baseline and version choices

Compared the latest crates.io archives with the working tree based on `7639439`.
Downloaded archives were checked against registry SHA-256 checksums. All thirteen
published workspace packages have changes or require updated dependencies.
The published versions below are the April 30, 2026 releases, not the current rc3
implementation. The node remains pinned to
`ffed4e92e60ff2de30361648a71cba64531f9077`.

For 0.x packages, changes to the minor number mark incompatible updates. Patch
bumps retain existing API contracts and carry compatible additions/fixes. Public
re-exports and types from incompatible dependencies require downstream bumps,
even if a crate's own source did not change (notably `tidecoin-io`). The top-level
crate remains a prerelease; this preparation does not declare a stable API.

| Package | Published | Prepared | Reason |
| --- | --- | --- | --- |
| `tidecoin-internals` | `0.5.0` | `0.5.1` | Replace unsafe slice chunking with safe equivalents; public signatures are unchanged. |
| `tidecoin-consensus-encoding` | `0.1.0` | `0.1.1` | Enforce the unsafe-code restriction and require the updated internal helpers; encoding APIs are unchanged. |
| `tidecoin_hashes` | `0.20.0` | `0.21.0` | Breaking: custom HMAC engines must implement Zeroize for erasure. Include typed erasure and safe SipHash reads. |
| `tidecoin-units` | `0.3.0` | `0.3.1` | Fix fractional fee-rate multiplication and add node-compatible integer-vsize fee calculation; existing types and signatures remain compatible. |
| `tidecoin-network-kind` | `0.1.0` | `0.1.1` | Enforce the unsafe-code restriction and require the updated internal helpers; network types are unchanged. |
| `tidecoin-io` | `0.5.0` | `0.6.0` | Breaking dependency update: the public hashes re-export and hash I/O interfaces use tidecoin_hashes 0.21. |
| `tidecoin-base58ck` | `0.4.0` | `0.4.1` | Require the updated hash and internal implementations and enforce the unsafe-code restriction; the Base58 API is unchanged. |
| `tidecoin-primitives` | `0.102.0` | `0.103.0` | Breaking dependency update: public hash types use tidecoin_hashes 0.21. Include rc3 witness recognition and signature-size estimation modes. |
| `tidecoin-chacha20-poly1305` | `0.1.2` | `0.1.3` | Use safe chunk iteration and enforce the unsafe-code restriction; public APIs are unchanged. |
| `tidecoin-consensus-core` | `0.1.0` | `0.2.0` | Breaking: fallible spent-output/precompute APIs and updated public dependency types. Include rc3 witness rules, sighash/interpreter fixes and Falcon 0.5.0 verification. |
| `tidecoin-node-parity` | `0.1.0` | `0.2.0` | Breaking: expanded public error enums and original-node comparison interfaces. Pin rc3 and package the current oracle support. |
| `tidecoin-p2p-messages` | `0.1.0` | `0.2.0` | Breaking dependency update: public primitives and hash/I/O types move to the new versions. Include rc3 message limits and safe command decoding. |
| `tidecoin` | `0.33.0-beta` | `0.34.0-beta.1` | Breaking prerelease: updated public dependencies, owned Address conversions, CoinbaseRef, spent-output validation and rc3 signing/policy/PQHD integration. Includes Falcon 0.5.0. |

`consensus` and `tidecoin-fuzz` remain workspace-only. Falcon's separate 0.5.0
registry packages are already published and are not changed here. External dependency requirements are unchanged. Validation also uses a fresh
registry resolution, since downstream users do not inherit this repository's
ignored Cargo.lock.

## Validation and publication order

1. Verify every local dependency constraint, including target/dev dependencies,
   resolves to its intended workspace version. Published packages must not refer
   to either workspace-only package.
2. Package all thirteen together with Cargo's multi-package verification, so
   verification uses the prepared dependencies despite their not being published
   yet. Check normalized manifests, archive contents and extracted builds.
3. Run the workspace suite against the pinned node, MSRV, pinned stable Clippy,
   default/no-default/all-feature checks, doctests and expanded-code checks.
4. Record results here. Before upload, use a clean reviewed commit and regenerate
   packages. Publish dependencies before their consumers, then verify registry
   archives against the prepared sources. Publication is a separate action.

Dependency order (independent entries within a group may be reordered):

- internals; chacha20-poly1305
- consensus-encoding; network-kind
- hashes; units
- io; base58ck; primitives; node-parity
- consensus-core; p2p-messages
- tidecoin

No independent protocol specification or consensus-rule change is introduced by
this version preparation. Historical test names and evidence retain their
original release/version references.

## Package contents and test scope

Extracted-archive testing found that `tidecoin` and `tidecoin-p2p-messages`
excluded the entire `tests` directory even though library unit tests include
files from `tests/data`. Their manifests now exclude only integration-test Rust
sources and retain the data and provenance files. This fixes package test
compilation without changing runtime behavior.

Archive checks inspect the normalized manifests: internal version requirements
must match the release set; no path/Git overrides or workspace-only dependencies
may remain. The Falcon regression fixture and pinned node revision are included.
The archive test workspace substitutes only these thirteen prepared packages for
crates.io packages; external dependencies, including Falcon 0.5.0, come from the
registry. Its 1,293 library tests run without the optional original-node setup.
The separate original source-workspace run requires the pinned node and exercises
the node comparisons; archive unit-test totals alone do not establish parity.

Validation is local. Hosted CI for these version and packaging changes has not
run. Package archives created with `--allow-dirty` are preparation artifacts;
regenerate them from the reviewed clean commit before publication. No release
tag or registry upload is part of this preparation.

## Local validation results

Both the existing local lockfile and a fresh registry resolution pass the
workspace gates below. The fresh resolution was generated with Cargo 1.99.1;
notably, the existing ML-KEM requirement now resolves to 0.3.4 instead of
0.3.0-rc.2. All four resolved Falcon packages remain at 0.5.0 without old/new
version duplicates. Cargo.lock remains ignored, as before.

| Check | Result |
| --- | --- |
| Multi-package archive builds | All thirteen passed with default features and with all features. Final archives include current changelogs and required data. |
| Normalized archive manifests and contents | All thirteen passed dependency/version checks; no path/Git overrides or workspace-only dependencies; Falcon fixture and node revision retained. |
| Workspace, all features/all targets, original-node comparisons required | 1,905 passed; 0 failed; 0 ignored, including the Falcon/PQHD/WIF comparisons. |
| Workspace doctests, all features | 83 passed; 0 failed; 2 ignored. |
| Extracted release archives, library tests, all features | 1,293 passed; 0 failed; 0 ignored across all thirteen packages; optional node setup absent as described above. |
| Rust 1.94.1 MSRV, workspace/all features/all targets | Passed with both dependency resolutions. |
| Consensus core without default features, Rust 1.94.1 | 40 library tests passed with both dependency resolutions. |
| Workspace without default features | Passed with both dependency resolutions. |
| Rust 1.99.1 strict Clippy, default and all features/all targets | Passed with both dependency resolutions. |
| Expanded-code safety screening, pinned nightly | Passed with both dependency resolutions. |
| Formatting and diff whitespace checks | Passed. |
| Excluded benchmark package, all targets | Passed. |

Representative reproduction commands (from the repository root):

```sh
# Original-node environment for workspace comparisons:
export TIDECOIN_NODE_REPO=/path/to/pinned/tidecoin
export TIDECOIN_NODE_PARITY_REQUIRED=1
export TIDECOIN_NODE_VALIDATION_ORACLE="$PWD/target/node-oracle/tidecoin-validation-oracle"
cargo +1.99.1 test --workspace --all-features --all-targets --locked
cargo +1.94.1 check --workspace --all-features --all-targets --locked
cargo +1.99.1 clippy --workspace --all-features --all-targets --locked -- -D warnings
cargo +1.99.1 test --workspace --all-features --doc --locked
cargo +1.94.1 test -p tidecoin-consensus-core --no-default-features --lib --locked
python3 contrib/check-expanded-safety.py

# Multi-package verification resolves the unpublished versions together.
# Use portable archive builds without the optional original-node setup.
unset TIDECOIN_NODE_REPO TIDECOIN_NODE_PARITY_REQUIRED TIDECOIN_NODE_VALIDATION_ORACLE
cargo +1.99.1 package --workspace --exclude consensus --exclude tidecoin-fuzz --allow-dirty --all-features
```

For a fresh-resolution run, regenerate the ignored lockfile first with
`cargo +1.99.1 generate-lockfile`. The oracle must already be rebuilt against the
pinned revision using the instructions in `node-parity/README.md`.
