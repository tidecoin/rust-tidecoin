# Changelog

All notable Tidecoin-specific changes for the shared consensus engine are documented here.

## Unreleased

- `SighashCache::legacy_signature_hash` now serializes script code like node
  `SignatureHash`: `OP_CODESEPARATOR` at instruction boundaries is removed, and
  at a malformed push the written bytes stop where node `GetScriptOp` stops.
  Callers may pass script code with or without separators. Previously raw script
  code containing separators produced a digest the node never computes, so a
  signer passing it would create signatures the node rejects.
  Interpreter results change only for script code that ends in a malformed push.
  Such a spend is invalid either way, but a signature valid for the node digest
  now passes an earlier signature check, so execution reaches `BAD_OPCODE` as in
  the node instead of reporting a signature failure first. The interpreter
  already removed separators, so well-formed scripts are unaffected.
- Added the shared Tidecoin consensus engine crate used by both public adapters and tests.
- Moved Tidecoin script, witness, flag, error, and verification semantics into the lower-level consensus runtime.
- Added the post-quantum verification facade required by Tidecoin witness validation.
- Kept consensus execution independent from high-level crate API compatibility concerns.
- Set the crate MSRV to Rust 1.94.1.
