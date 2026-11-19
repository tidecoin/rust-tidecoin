# Changelog

All notable Tidecoin-specific changes for the public Tidecoin crate are documented here.

## Unreleased

- Upgrade Falcon signing/key generation to published 0.5.0 packages, alongside
  the shared verifier fix for the legacy norm boundary. Normal signing explicitly
  selects `TidecoinStrict`; preserve local output budgets, advancing RNG retries,
  actual-length serialization, deterministic keys and PQHD derivation.
- Direct strict Falcon verification reports `BackendFailure` for an invalid key
  encoding even if the signature is also malformed; the shared-core changelog
  records this error-precedence clarification.

- Removed `Address::as_unchecked()`; use `to_unchecked()` instead. Removed
  `Address<NetworkUnchecked>::assume_checked_ref()`; use `assume_checked()`
  instead. Addresses are `Copy`; these value conversions do not change
  network-validation rules.
- `BlockCheckedExt::coinbase()` now returns `CoinbaseRef<'_>` instead of
  `&Coinbase`. Use `CoinbaseRef::assume_coinbase(&tx)` in place of
  `Coinbase::assume_coinbase_ref(&tx)`. The view borrows without cloning, and
  `Coinbase::as_coinbase_ref()` exposes the same view from an owned coinbase.
- Forbid unsafe code in this crate; CI also checks expanded dependency macros.

- Reoriented the crate around Tidecoin-native transaction, block, script, address, network, and post-quantum key surfaces.
- Routed consensus validation through the shared Tidecoin consensus runtime and node-parity harness instead of inherited validation dependencies.
- Delegated protocol primitives and consensus serialization to the lower-level `tidecoin-primitives` and `tidecoin-consensus-encoding` crates.
- Removed inherited signing and validation surfaces that do not describe Tidecoin consensus.
- Set the crate MSRV to Rust 1.94.1.
