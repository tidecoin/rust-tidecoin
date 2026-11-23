# Wallet API Roadmap

Status: future wallet-facing work under the pinned rc4 compatibility target.

This document tracks Rust crate work that is useful to wallets, mobile clients,
and application developers. It is separate from the consensus and node-parity
docs because wallet ergonomics should compose existing protocol primitives
instead of changing consensus boundaries.

The [rc4 migration plan](RC4_MIGRATION_PLAN.md) owns the target, dependencies,
evidence and current implementation priorities. The linked ordered compatibility
follow-up precedes this wallet work. Review rc4 signing and PSBT callers before
implementing each API slice.

## Current Foundation

The crate already has most low-level pieces needed by a wallet:

- raw transaction, input, output, amount, locktime, sequence, and witness types
- address parsing and `Address::script_pubkey()`
- dust and minimal-output helpers through script and transaction extension APIs
- transaction weight, vsize, and effective-value helpers
- PQ spend weight prediction through `InputWeightPrediction`
- PQ secret/public key types, signing, verification, WIF, and PQHD derivation
- `pqhd(...)` descriptor/key-expression parsing and deterministic key derivation
- public script and transaction verification APIs for validating built spends

Compose these primitives and retain their original-node comparisons when
adding wallet-facing behavior.

## Priority 1: PSBT and signing contracts

The full Rust PSBT API remains future work. The planned implementation includes
the following areas.

- PSBT parsing/serialization, unknown fields and PQHD origin metadata
- consistent previous-output records and authenticated script commitments
- public declarations, combine semantics and explicit signing consent
- native v1 signing with complete non-ANYONECANPAY context
- native/wrapped v0 finalization matching rc4 script commitments
- legacy external-signing data requirements
- final verification, extraction, per-input analysis and conditional cleanup
- top-level `wsh512(...)` descriptors and rejection of wrapped v1 signing
- invalid, excluded and unknown partials under an immutable selected-era context

Keep historical legacy/v0 consensus validity distinct from new-signature and
relay policy. Node fixtures and round trips are required for these contracts.

## Priority 2: Spend Construction Layer

Goal:

- provide a public API that assembles spendable Tidecoin transactions from UTXOs,
  recipients, change policy, fee policy, and supported signing templates

This is the corrected form of the earlier "wallet-facing transaction builder"
idea. The crate already has transaction-building ingredients; the missing piece
is the user-facing composition layer.

The rc4 source review adds construction requirements from `wallet/spend.cpp`:
complete CompactSize count accounting including change; fee reconciliation
without changing recipients unless subtraction was requested; exact-WU input
budget comparisons; and assembled maximum-weight checks using the final parent
context. A preview must use actual scripts, ancestor fees and available solving
data without reserving change or modifying wallet state. See the
[rc4 source dispositions](RC4_MIGRATION_PLAN.md#source-review-and-rust-disposition).
These remain future wallet work, not capabilities of the sizing primitives.

Initial scope:

- `Recipient` or `Destination` accepting `Address` or `ScriptPubKeyBuf` plus
  `Amount`
- `SpendInput` carrying `OutPoint`, previous `TxOut`, sequence, and optional
  descriptor/key metadata
- fee-rate and change-policy types that use the existing dust and weight helpers
- builder output that exposes the unsigned transaction, selected fee, change
  output, and weight estimate
- signing support for a small first set of Tidecoin spend templates
- verification tests using the existing public validation APIs and node-backed
  parity fixtures where possible

Out of scope for the first slice:

- UTXO database ownership
- mempool/package policy
- full coin selection optimization
- RPC broadcasting
- chain-connect validation

## Priority 3: Signing Ergonomics

Goal:

- make common Tidecoin/PQ spend templates signable without callers manually
  assembling scriptSig or witness stacks

Candidate first templates:

- PQ legacy/base P2PKH-style spend if that remains required by current wallet
  compatibility
- PQ witness-v0 P2WPKH or nested P2SH-P2WPKH where current wallets depend on it
- PQ witness-v1-512 script spend for new PQ-native addresses

Signing should reuse consensus-core sighash behavior and existing PQ key APIs.
It must not create a second consensus verifier.

## Priority 4: Wallet/Mobile Compatibility

Goal:

- expose the crate capabilities that mobile and wallet clients need without
  leaking node-only concepts into wallet code

Useful surfaces:

- canonical PQ WIF import/export, preferring prefixed PQ WIF for new wallets
- scheme-aware fee and dust estimation
- P2WSH512/PQ address parsing and construction helpers
- PQHD descriptor generation and derivation helpers
- clear network validation for standard and PQ HRP namespaces

Reference:

- [`rust-tidecoin-vs-mobile-native-comparison.md`](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/rust-tidecoin-vs-mobile-native-comparison.md)

## Acceptance Standard

Wallet-facing APIs are ready only when:

- relevant rc4 PSBT/signing interoperability cases pass against the pinned node
- they compose existing transaction/script/address/PQ primitives instead of
  duplicating them
- fee and dust behavior is tied to existing policy helpers
- produced transactions verify through the public Tidecoin validation surface
- node-backed parity is required for consensus-sensitive signing behavior
- documentation is explicit about what is wallet convenience, what is relay
  policy, and what is consensus validation
