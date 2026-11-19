# Changelog

All notable Tidecoin-specific changes for the standalone consensus adapter are documented here.

## Unreleased

- Marked the adapter as workspace-only with `publish = false` and removed the
  documentation URL pointing to the unrelated crates.io package. Workspace
  verification tests and fuzz targets continue to use the local adapter.
- Changed `Utxo` to `Utxo<'a>` with a borrowed `script_pubkey: &'a [u8]`.
  Removed the raw pointer, separate length and C representation. Verification
  remains safe to call; callers now borrow scripts directly. Amount and ordered
  spent-output checks retain their existing behavior.
- Reworked the crate as a standalone adapter over `tidecoin-consensus-core`.
- Preserved byte-oriented entry points only where they serve the active Tidecoin validation boundary.
- Replaced inherited differential assumptions with Tidecoin fixture and node-parity workflows.
- Delegated transaction decoding and script execution to the shared lower-level crates.
- Set the crate MSRV to Rust 1.94.1.
