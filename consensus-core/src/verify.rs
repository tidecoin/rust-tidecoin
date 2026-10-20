//! Shared typed verification facade over the Tidecoin interpreter.

use crate::{
    Interpreter, ScriptError, ScriptFlags, SpendContext, TidecoinValidationError,
    TransactionContext, VERIFY_CLEANSTACK, VERIFY_P2SH, VERIFY_WITNESS,
};
use primitives::Transaction;

/// Detailed failure information for a typed verification call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationFailure {
    /// High-level verification error.
    pub error: TidecoinValidationError,
    /// Final interpreter script error.
    pub script_error: ScriptError,
}

/// Verifies a single typed spend and returns the shared-core validation error.
pub fn verify_script_input(
    tx: &Transaction,
    input_index: usize,
    spend: SpendContext<'_>,
    flags: u32,
) -> Result<(), TidecoinValidationError> {
    verify_script_input_detailed(tx, input_index, spend, flags).map_err(|failure| failure.error)
}

/// Validates raw verification bits against the shared Tidecoin engine contract.
pub fn validate_verification_flags(flags: u32) -> Result<(), TidecoinValidationError> {
    let _ = ScriptFlags::from_bits(normalize_flags(flags))?;
    Ok(())
}

/// Same as [`verify_script_input`] but also reports the final interpreter script error.
pub fn verify_script_input_detailed(
    tx: &Transaction,
    input_index: usize,
    spend: SpendContext<'_>,
    flags: u32,
) -> Result<(), VerificationFailure> {
    let flags = ScriptFlags::from_bits(normalize_flags(flags)).map_err(simple_failure)?;
    let tx_ctx = TransactionContext::new(tx);
    let mut interpreter =
        Interpreter::new(&tx_ctx, input_index, spend, flags).map_err(simple_failure)?;

    interpreter.verify().map_err(|err| {
        let script_error = interpreter.last_script_error();
        VerificationFailure { error: normalize_script_error(err, script_error), script_error }
    })
}

fn normalize_flags(mut flags: u32) -> u32 {
    if flags & VERIFY_CLEANSTACK != 0 {
        flags |= VERIFY_P2SH | VERIFY_WITNESS;
    }
    flags
}

fn simple_failure(error: TidecoinValidationError) -> VerificationFailure {
    VerificationFailure { error, script_error: ScriptError::Ok }
}

fn normalize_script_error(
    error: TidecoinValidationError,
    script_error: ScriptError,
) -> TidecoinValidationError {
    match error {
        TidecoinValidationError::Script(_) => TidecoinValidationError::Script(script_error),
        other => other,
    }
}

/// Verifies every input using complete previous outputs in input order.
///
/// Transaction decoding is the caller's responsibility. One sighash cache and
/// one owned previous-output set are shared across all input verifications.
/// This checks scripts, not transaction-level value or block consensus rules.
pub fn verify_transaction_inputs(
    tx: &Transaction,
    spent_outputs: crate::SpentOutputs,
    flags: u32,
) -> Result<(), TidecoinValidationError> {
    let flags = ScriptFlags::from_bits(normalize_flags(flags))?;
    let tx_ctx = TransactionContext::new(tx);
    let mut cache = crate::SighashCache::new_with_spent_outputs(tx, spent_outputs)?;
    for index in 0..tx.inputs.len() {
        // Only the current output is cloned; the full context/cache moves between
        // interpreters and retains the hashes computed for preceding inputs.
        let output = cache.spent_outputs().expect("complete context").txouts()[index].clone();
        let spend =
            SpendContext::new(output.script_pubkey.as_bytes(), None, output.amount.to_sat(), true);
        let mut interpreter = Interpreter::with_cache(&tx_ctx, index, spend, flags, cache)?;
        interpreter
            .verify()
            .map_err(|err| normalize_script_error(err, interpreter.last_script_error()))?;
        cache = interpreter.into_sighash_cache();
    }
    Ok(())
}
