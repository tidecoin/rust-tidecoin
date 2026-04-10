Historical Core-era script-assets artifacts.

These files were part of the earlier Bitcoin/Core-oriented proof workflow:
- curated `script_assets_test.json`
- generated-corpus metadata
- upstream minimizer corpus and metadata
- `script_tests.json`
- `tx_valid.json`
- `tx_invalid.json`
- `bip341_wallet_vectors.json`
- `sighash.json`

They are archived for reference only.

Active Tidecoin parity/provenance now uses:
- direct Tidecoin node fixtures from `TIDECOIN_NODE_REPO/src/test/data`
- [tidecoin_script_assets.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets.rs)
- [tidecoin_script_assets_generated.rs](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/tidecoin_script_assets_generated.rs)
- [tidecoin_script_assets_generated_metadata.json](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/tests/data/tidecoin_script_assets_generated_metadata.json)
