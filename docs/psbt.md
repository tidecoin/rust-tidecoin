# PSBT

A complete Rust PSBT API remains future work. Its target is Tidecoin node
`v1.0.0rc3`, commit `ffed4e92e60ff2de30361648a71cba64531f9077`.

The [wallet roadmap](../ai-docs/WALLET_API_ROADMAP.md) records planned format
handling, previous-output integrity, signing consent, combining, finalization,
analysis, external-signing data requirements and PQHD origins. The
[rc3 migration plan](../ai-docs/RC3_MIGRATION_PLAN.md) owns source-review evidence
and current priorities.

Rc3 uses native-only witness-v1 signing and top-level `wsh512(...)`
descriptors. Future PSBT APIs must preserve selected-era eligibility, complete
non-ANYONECANPAY v1 context, full previous transactions for legacy finals,
exact wrapped-v0 final pushes and classification of invalid, excluded and
unknown partials. Review the pinned `psbt.cpp`, `script/sign.cpp` and
`script/descriptor.cpp` callers for each implementation slice.

Use `SighashCache::new_with_spent_outputs` for non-ANYONECANPAY v1 signing.
Complete-context verification is available through the product transaction API
and `verify_script_with_spent_outputs`. These existing primitives form the
foundation for future PSBT interoperability tests.

Witness version 1 identifies Tidecoin's SHA-512 script/signature rules.
Historical legacy/v0 verification, new signing, relay admission and PSBT
finalization retain their respective node contracts.
