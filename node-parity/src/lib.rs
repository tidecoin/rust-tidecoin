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
/// Process adapter for original node validation functions and detailed verdicts.
pub mod validation;

pub use crate::error::NodeParityError;
pub use crate::error::ScriptError;
pub use crate::harness::{SpentOutput, TidecoinNodeHarness};

/// Node activation flags, which must stay fixed when comparing script restrictions.
/// See the pinned node's `src/test/util/script.cpp::ScriptFlagsForComparison`.
pub const SCRIPT_ACTIVATION_FLAGS: u32 = (1 << 13) | (1 << 14) | (1 << 15);

/// Remove restrictions from a passing case or add them to a failing case,
/// preserving its activation state exactly as the node's test helper does.
pub fn script_flags_for_comparison(flags: u32, changes: u32, success: bool) -> u32 {
    let changes = changes & !SCRIPT_ACTIVATION_FLAGS;
    if success {
        flags & !changes
    } else {
        flags | changes
    }
}

/// Whether two flag sets describe the same activation state.
pub fn same_script_activation(left: u32, right: u32) -> bool {
    (left ^ right) & SCRIPT_ACTIVATION_FLAGS == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparisons_preserve_all_eight_activation_states() {
        for state in 0..8 {
            let flags = (state << 13) | 1;
            for success in [false, true] {
                let compared = script_flags_for_comparison(flags, u32::MAX, success);
                assert!(same_script_activation(flags, compared));
                assert_eq!(
                    compared & !SCRIPT_ACTIVATION_FLAGS,
                    if success { 0 } else { !SCRIPT_ACTIVATION_FLAGS }
                );
            }
        }
    }
}
