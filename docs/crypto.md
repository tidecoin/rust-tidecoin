# Tidecoin crypto

The active Tidecoin crypto stack is post-quantum-first.

## Current ownership

- `tidecoin::crypto::pq`: PQ signature and KEM types and operations
- `tidecoin::crypto::key`: top-level Tidecoin key-adjacent wrappers used by the public crate
- `consensus-core::pq`: verification-only PQ facade for the consensus engine

## Current public key surface

The live top-level key API is intentionally narrow:

- `PubkeyHash`
- `WPubkeyHash`
- `PqWifKey`
- `PqWifFormat`
- WIF parse/validation errors

The removed legacy key/signing surface is not part of the live Tidecoin crate.

## Design rule

Reusable consensus-facing verification belongs below the top-level crate:

- protocol/script/opcode model: `primitives`
- validation engine: `consensus-core`
- standalone byte-oriented API: `consensus`
- product ergonomics and reexports: `tidecoin`

If crypto is split further later, it should preserve that same ownership rule rather than creating a
parallel second key or verification stack.
