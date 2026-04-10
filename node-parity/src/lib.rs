// SPDX-License-Identifier: CC0-1.0

//! Shared Tidecoin node-backed parity harness support.
//!
//! This crate is intentionally `std`-only and is meant for internal test/dev
//! infrastructure, not for the pure-Rust production consensus engine.

#![warn(missing_docs)]

/// Shared Tidecoin-node script error types and mappings.
pub mod error;
/// Raw FFI declarations for the Tidecoin node parity bridge.
pub mod ffi;
/// Shared Tidecoin-node fixture discovery helpers.
pub mod fixtures;
/// Shared byte-oriented harness for Tidecoin node-backed parity calls.
pub mod harness;

pub use crate::error::NodeParityError;
pub use crate::error::ScriptError;
pub use crate::harness::TidecoinNodeHarness;
