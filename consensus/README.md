# consensus

Pure-Rust Tidecoin consensus verification crate.

## Status

- Legacy, P2SH, witness-v0, and Tidecoin witness-v1-512 validation are implemented.
- Tidecoin node parity checks are available and are the acceptance authority.
- Tidecoin-native script-assets proof coverage now includes:
  - direct node `script_assets_test.json` replay
  - generated large-corpus monotonicity derived from `tx_valid_pq.json` and `tx_invalid_pq.json`
  - pinned generated-corpus provenance metadata

## API

Main entrypoints in `src/lib.rs`:

- `verify`
- `verify_with_flags`
- `verify_with_details`
- `verify_with_flags_detailed`

## Feature Flags

- `std` (default)

## Quick Start

```bash
cargo test
```

Fixture integrity check:

```bash
cargo test -p consensus --test tidecoin_fixture_hashes
```

Active Tidecoin runtime differential:

```bash
TIDECOIN_NODE_REPO=/path/to/tidecoin \
cargo test -p consensus --test tidecoin_runtime_diff -- --nocapture
```

Direct Tidecoin `script_assets_test.json` replay:

```bash
TIDECOIN_NODE_REPO=/path/to/tidecoin \
cargo test -p consensus --test tidecoin_script_assets -- --nocapture
```

Generated Tidecoin large-corpus/provenance workflow:

```bash
mkdir -p /tmp/tidecoin_script_assets
TIDECOIN_NODE_REPO=/path/to/tidecoin \
TIDECOIN_SCRIPT_ASSETS_WRITE_GENERATED_JSON=/tmp/tidecoin_script_assets/generated.json \
cargo test -p consensus --test tidecoin_script_assets_generated tidecoin_generated_script_assets_monotonicity -- --nocapture

python3 scripts/generate_tidecoin_script_assets_generated_metadata.py \
  --json /tmp/tidecoin_script_assets/generated.json \
  --tx-valid /path/to/tidecoin/src/test/data/tx_valid_pq.json \
  --tx-invalid /path/to/tidecoin/src/test/data/tx_invalid_pq.json \
  --node-repo /path/to/tidecoin \
  --output tests/data/tidecoin_script_assets_generated_metadata.json
```

## Benchmarks

```bash
cargo bench --bench verification
```

## Project Layout

- `src/lib.rs`: byte-oriented public API and wrapper flow
- `../consensus-core/src/interpreter.rs`: shared Tidecoin script interpreter/engine
- `../consensus-core/src/tx.rs`: shared typed transaction context and precompute helpers
- `tests/`: vectors, corpus checks, and differential suites

## Documentation

- `docs/github-ci.md`: active Tidecoin fixture/provenance workflow
- `docs/pq-integration-plan.md`: active architectural and cleanup checklist
- `docs/archived/integration-roadmap.md`: historical Bitcoin/Core-oriented roadmap

## Notes

- Amount semantics follow the active Tidecoin runtime: explicit `amount` is authoritative for checksig/sighash.
- Historical Bitcoin/Core-diff materials still exist in archived docs/tests, but are not the active Tidecoin parity workflow.
- Historical Core-era corpora and metadata now live under [tests/archived/data](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/archived/data).
