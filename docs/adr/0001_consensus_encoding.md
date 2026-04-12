# `consensus_encoding` crate for sans-I/O codecs

- Status: accepted
- Date: 2025-09-06
- Current scope: `consensus_encoding`, `primitives`, `units`, `p2p`, `tidecoin`

## Context

Tidecoin consensus data must be encoded consistently across network, disk, hashing, and test
surfaces. The old reader/writer compatibility API tied core codecs to I/O error handling and forced
the workspace to maintain a second codec surface. This branch does not preserve API compatibility
when the compatibility layer works against a clean Tidecoin-native architecture.

The workspace therefore uses a sans-I/O codec layer:

- `tidecoin-consensus-encoding` owns the low-level encoder/decoder traits and composition helpers.
- `tidecoin-primitives` implements canonical protocol type codecs.
- Higher crates consume these layers rather than duplicating codec logic.

## Decision

Keep `tidecoin-consensus-encoding` as the only canonical codec substrate and remove the former
I/O compatibility layer.

This preserves:

- no-std compatibility for core codecs
- I/O-independent encoding and decoding state machines
- clean dependency direction for `primitives`, `consensus-core`, `p2p`, `consensus`, and `tidecoin`
- one codec implementation for each protocol surface instead of parallel reader/writer and
  sans-I/O implementations

## Boundary

- `consensus_encoding`: codec traits, encoder/decoder composition, byte/slice/vector callers.
- `primitives`: canonical Tidecoin protocol/script/opcode/transaction/block types and their sans-I/O codecs.
- `tidecoin`: high-level crate; it does not expose a `tidecoin::consensus` codec compatibility
  namespace. Callers use `encoding`/`tidecoin-consensus-encoding` APIs directly, while serde users
  use `primitives::serde_as_consensus`.
- `p2p`: message codecs; V1 network framing uses one no-allocation frame-planning pass for
  checksum/length and one emission pass because the header commits to payload metadata before the
  payload bytes. Payload type codecs use `consensus_encoding`.

This P2P V1 double walk is frame-layer metadata work, not a second payload codec. It is acceptable
current architecture because it avoids buffering payloads and keeps transaction/block/script/witness
serialization under the canonical codec layer. A future one-pass streaming frame builder is a
performance and implementation-polish target, not a consensus or codec-ownership blocker.

## API Sketch

```rust
pub trait Encodable {
    type Encoder<'e>: Encoder
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_>;
}

pub trait Encoder {
    fn current_chunk(&self) -> &[u8];
    fn advance(&mut self) -> bool;
}

pub trait Decodable {
    type Decoder: Decoder<Output = Self>;
    fn decoder() -> Self::Decoder;
}

pub trait Decoder: Sized {
    type Output;
    type Error;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error>;
    fn end(self) -> Result<Self::Output, Self::Error>;
    fn read_limit(&self) -> usize;
}
```

## Notes

The active design target is Tidecoin. Historical migration wording should not be treated as current
architecture.
