// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(feature = "tidecoin-node-validation", allow(dead_code))]

use consensus_core::{Interpreter, ScriptFlags, SpendContext, TransactionContext};

use crate::amount::Amount;
use crate::script::ScriptPubKey;
use crate::transaction::Transaction;
/// Shared core script error for the pure-Rust fallback path.
pub type ScriptError = consensus_core::ScriptError;
/// Shared core validation error for the pure-Rust fallback path.
pub type TidecoinValidationError = consensus_core::TidecoinValidationError;
pub use consensus_core::{VERIFY_CLEANSTACK, VERIFY_P2SH, VERIFY_WITNESS};

pub(crate) fn verify_script_input(
    script_pubkey: &ScriptPubKey,
    index: usize,
    amount: Amount,
    tx: &Transaction,
    flags: u32,
) -> Result<(), TidecoinValidationError> {
    let mut flags = flags;
    if flags & VERIFY_CLEANSTACK != 0 {
        flags |= VERIFY_P2SH | VERIFY_WITNESS;
    }

    let flags = ScriptFlags::from_bits(flags)?;
    let tx_ctx = TransactionContext::new(tx);
    let spend = SpendContext::new(script_pubkey.as_bytes(), None, amount.to_sat(), true);
    let mut interpreter = Interpreter::new(&tx_ctx, index, spend, flags)?;

    match interpreter.verify() {
        Ok(()) => Ok(()),
        Err(TidecoinValidationError::Script(_)) => {
            Err(TidecoinValidationError::Script(interpreter.last_script_error()))
        }
        Err(err) => Err(err),
    }
}
