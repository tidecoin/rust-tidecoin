## Archived Bitcoin/Core-Diff Tests

These files are historical Bitcoin/Core-diff test surfaces that no longer match
the active Tidecoin migration target for `consensus/`.

They were archived after the live `consensus` runtime stopped exposing
Bitcoin-only flags and ECDSA/Taproot semantics such as:

- `VERIFY_STRICTENC`
- `VERIFY_DERSIG`
- `VERIFY_LOW_S`
- `VERIFY_TAPROOT`
- Taproot/Tapscript/Schnorr-specific `ScriptError` variants

They now also include the last active Bitcoin-era parity residue that still
depended on upstream `bitcoin::*`, `bitcoinconsensus`, or Core-specific fixture
corpora:

- `core_fixture_hashes.rs`
- `core_script_p2sh_unit_parity.rs`
- `core_script_segwit_detection_parity.rs`
- `core_scriptnum_unit_parity.rs`
- `core_sighash_cache_parity.rs`
- `core_sighash_randomized.rs`
- `core_sighash_vectors.rs`
- `core_sigop_surface.rs`
- `core_witness_unit_parity.rs`
- `verification_bench.rs`

The active replacement direction is:

- Tidecoin-native runtime behavior in `consensus/src/**`
- Tidecoin node parity through `tests/tidecoin_node_parity.rs`
- shared bridge/harness infrastructure in `node-parity/`

If useful coverage from an archived test still matters, reintroduce it only as
a Tidecoin-native/PQ-native test, not by restoring the old Bitcoin/Core-diff
assumptions.
