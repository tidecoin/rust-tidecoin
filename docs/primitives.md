# primitives 1.0.0

Design considerations and TODOs for the `tidecoin-primitives 1.0.0` release.

## Current ownership rule

`primitives` is the canonical home for:

- Tidecoin transaction, block, and witness data structures
- the canonical Tidecoin script representation
- the canonical Tidecoin opcode definitions
- reusable hash wrapper types used across higher layers

Higher layers should consume or reexport this model, not keep parallel implementations.

## Remaining public API consideration

One continuing concern is keeping `hashes` from leaking too broadly through the public API. Hash
wrapper types are useful, but their public shape should remain stable and intentional.

Usage of `hash_newtype` outside of `primitives` should stay intentionally narrow:

- `bip158::{FilterHash, FilterHeader}`
- `crypto::key::{PubkeyHash, WPubkeyHash}`
- `crypto::sighash::{LegacySighash, SegwitV0Sighash}`
