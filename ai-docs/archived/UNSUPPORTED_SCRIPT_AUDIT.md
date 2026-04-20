# `UnsupportedScript` Audit

Status: archived historical root-cause record.

This document records the audit that led to the removal of
`consensus_core::TidecoinValidationError::UnsupportedScript` from the live
shared-core contract.

The described stale variant has been removed from the live code, and malformed
serialized transaction bytes now surface as
`ValidationError::MalformedTransaction`.

Use this document only as historical evidence for why that cleanup happened.
It is not an active planning or implementation checklist.

## Original Question

Is `consensus_core::TidecoinValidationError::UnsupportedScript` still a real
runtime error in the current `rust-tidecoin` codebase? If so, where can it
happen? If not, where does it still survive?

## Short Answer

Before the direct cleanup, `UnsupportedScript` was **not** a live pure-Rust
consensus-engine outcome.

I could not find any construction site for
`TidecoinValidationError::UnsupportedScript` inside the shared pure-Rust
verification path.

It survived in three places:

1. as a variant definition in
   [`consensus-core/src/error.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus-core/src/error.rs)
2. as a **misclassification** of transaction decode failure in
   [`tidecoin/src/consensus_validation.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation.rs)
3. as dead or vestigial mapping arms in adapter code that mirrored the shared
   enum shape:
   - [`consensus/src/lib.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/consensus/src/lib.rs)
   - [`tidecoin/src/consensus_validation_node.rs`](/home/yaroslav/dev/tidecoin/rust-tidecoin/tidecoin/src/consensus_validation_node.rs)

Before cleanup, the public product-facing runtime case was:

- malformed serialized transaction bytes in `verify_script_with_flags(...)`
  could incorrectly surface as `UnsupportedScript`

That was not a real “unsupported script family” outcome. It was a wrong bucket.

## Historical Conclusion

`UnsupportedScript` was historical residue, not a real live pure-Rust engine
contract. The cleanup that followed:

1. removed the stale variant from the live shared-core contract
2. removed the stale adapter/dev mirror arms
3. introduced `ValidationError::MalformedTransaction` for malformed serialized
   transaction input
