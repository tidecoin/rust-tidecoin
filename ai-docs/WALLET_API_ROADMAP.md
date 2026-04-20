# Wallet API Roadmap

Status: active wallet-facing API roadmap.

This document tracks Rust crate work that is useful to wallets, mobile clients,
and application developers. It is separate from the consensus and node-parity
docs because wallet ergonomics should compose existing protocol primitives
instead of changing consensus boundaries.

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

That means the next wallet-facing work should not rebuild primitives. It should
wrap the existing pieces into stable, ergonomic APIs.

## Priority 1: Spend Construction Layer

Goal:

- provide a public API that assembles spendable Tidecoin transactions from UTXOs,
  recipients, change policy, fee policy, and supported signing templates

This is the corrected form of the earlier "wallet-facing transaction builder"
idea. The crate already has transaction-building ingredients; the missing piece
is the user-facing composition layer.

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

## Priority 2: Signing Ergonomics

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

## Priority 3: Wallet/Mobile Compatibility

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

- they compose existing transaction/script/address/PQ primitives instead of
  duplicating them
- fee and dust behavior is tied to existing policy helpers
- produced transactions verify through the public Tidecoin validation surface
- node-backed parity is used for consensus-sensitive signing behavior where
  practical
- documentation is explicit about what is wallet convenience, what is relay
  policy, and what is consensus validation
