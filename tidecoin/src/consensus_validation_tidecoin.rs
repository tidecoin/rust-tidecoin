// SPDX-License-Identifier: CC0-1.0

use consensus_core::SpendContext;

use crate::amount::Amount;
use crate::script::ScriptPubKey;
use crate::transaction::Transaction;

type TidecoinValidationError = consensus_core::TidecoinValidationError;

pub(crate) fn verify_script_input(
    script_pubkey: &ScriptPubKey,
    index: usize,
    amount: Amount,
    tx: &Transaction,
    flags: u32,
) -> Result<(), TidecoinValidationError> {
    let spend = SpendContext::new(script_pubkey.as_bytes(), None, amount.to_sat(), true);
    consensus_core::verify_script_input(tx, index, spend, flags)
}
