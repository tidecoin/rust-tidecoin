# PSBT

PSBT is not exposed as a full live Rust API in this repository.

The Tidecoin node has PSBT support, and this repository keeps only the lower-level primitives that
are needed by active Tidecoin code. If a full Rust PSBT API is introduced here, it should be designed
from current Tidecoin requirements rather than by reviving removed signing infrastructure.
