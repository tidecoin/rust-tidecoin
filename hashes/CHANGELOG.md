# Changelog

All notable Tidecoin-specific changes for hashes are documented here.

## Unreleased

- Replaced SipHash unchecked byte reads with checked slices and indexing. The
  SipHash module forbids unsafe code; reference vectors also cover every two-part input split.
- Replaced arbitrary-object byte zeroing with typed `zeroize` operations.
  `HmacEngine::non_secure_erase` now requires its engine to implement `Zeroize`;
  all built-in engines implement it by clearing their state fields. Custom
  engines must supply their own implementation. HKDF stores and clears the PRK
  as bytes, so erasure and drop never overwrite a custom hash object's layout.
  This does not guarantee removal of compiler-created copies.
- Reoriented the hash utility crate for Tidecoin workspace ownership.
- Kept hash newtypes, hex formatting, and encoding integrations available to primitives, p2p, and consensus layers.
- Preserved the low-level no-std boundary so hashing remains independent from protocol validation.
- Set the crate MSRV to Rust 1.94.1.
