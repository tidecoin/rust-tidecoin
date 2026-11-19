# Changelog

All notable Tidecoin-specific changes for the shared consensus engine are documented here.

## Unreleased — 0.2.0

- Breaking: fallible spent-output/precompute APIs and updated public dependency types. Include rc3 witness rules, sighash/interpreter fixes and Falcon 0.5.0 verification.

- Adopt published `tide-fn-dsa-vrfy` 0.5.0. Legacy Falcon-512 now rejects norm
  equality at 43,533,782, matching rc3. Delegate historical decoding and format
  classification to the backend and use `TidecoinStrict` for strict verification.
  Remove the duplicate encoding normalizer; retain exact consumption and allow
  valid signatures above local signing budgets.
- Falcon verification now decodes the public key before checking signature
  encoding. If both are malformed, direct strict verification returns
  `BackendFailure` instead of `VerificationFailed`. Explicit legacy verification
  already used that ordering. Script acceptance/error mapping is unchanged
  except rejection of the previously accepted legacy norm-equality case.

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

## 0.1.0 — published 2026-04-30

- Added the shared Tidecoin consensus engine crate used by both public adapters and tests.
- Moved Tidecoin script, witness, flag, error, and verification semantics into the lower-level consensus runtime.
- Added the post-quantum verification facade required by Tidecoin witness validation.
- Kept consensus execution independent from high-level crate API compatibility concerns.
- Set the crate MSRV to Rust 1.94.1.
