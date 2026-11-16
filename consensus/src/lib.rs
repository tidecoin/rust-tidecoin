#![cfg_attr(not(feature = "std"), no_std)]
//! Tidecoin byte-oriented consensus verification API.
//!
//! The active runtime and proof surface are Tidecoin-native and audited against
//! the Tidecoin core node. Historical migration material now lives only in archived docs and tests.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

pub mod types;

pub use consensus_core::ScriptError;

use consensus_core as core_flags;
use consensus_core::{SpendContext, SpentOutputs};
use core::fmt;
use primitives::{Amount, ScriptPubKeyBuf, Transaction, TxOut};

use crate::types::{c_int64, c_uchar, c_uint};

/// Do not enable any verification.
pub const VERIFY_NONE: c_uint = core_flags::VERIFY_NONE as c_uint;
/// Evaluate pay-to-script-hash subscripts.
pub const VERIFY_P2SH: c_uint = core_flags::VERIFY_P2SH as c_uint;
/// Enforce NULLDUMMY for multisig stack dummies.
pub const VERIFY_NULLDUMMY: c_uint = core_flags::VERIFY_NULLDUMMY as c_uint;
/// Require scriptSig to be push only.
pub const VERIFY_SIGPUSHONLY: c_uint = core_flags::VERIFY_SIGPUSHONLY as c_uint;
/// Require minimal data encodings.
pub const VERIFY_MINIMALDATA: c_uint = core_flags::VERIFY_MINIMALDATA as c_uint;
/// Discourage use of upgradable NOP opcodes.
pub const VERIFY_DISCOURAGE_UPGRADABLE_NOPS: c_uint =
    core_flags::VERIFY_DISCOURAGE_UPGRADABLE_NOPS as c_uint;
/// Discourage unknown witness program versions.
pub const VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: c_uint =
    core_flags::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM as c_uint;
/// Require a clean stack after evaluation.
pub const VERIFY_CLEANSTACK: c_uint = core_flags::VERIFY_CLEANSTACK as c_uint;
/// Enable CHECKLOCKTIMEVERIFY.
pub const VERIFY_CHECKLOCKTIMEVERIFY: c_uint = core_flags::VERIFY_CHECKLOCKTIMEVERIFY as c_uint;
/// Enable CHECKSEQUENCEVERIFY.
pub const VERIFY_CHECKSEQUENCEVERIFY: c_uint = core_flags::VERIFY_CHECKSEQUENCEVERIFY as c_uint;
/// Enable Tidecoin witness validation.
pub const VERIFY_WITNESS: c_uint = core_flags::VERIFY_WITNESS as c_uint;
/// Require minimal encodings for IF/NOTIF.
pub const VERIFY_MINIMALIF: c_uint = core_flags::VERIFY_MINIMALIF as c_uint;
/// Enforce NULLFAIL behavior.
pub const VERIFY_NULLFAIL: c_uint = core_flags::VERIFY_NULLFAIL as c_uint;
/// Forbid legacy Falcon-512 signatures after auxpow activation.
pub const VERIFY_PQ_STRICT: c_uint = core_flags::VERIFY_PQ_STRICT as c_uint;
/// Enable Tidecoin witness-v1-512 validation.
pub const VERIFY_WITNESS_V1_512: c_uint = core_flags::VERIFY_WITNESS_V1_512 as c_uint;
/// Enable Tidecoin `OP_SHA512`.
pub const VERIFY_SHA512: c_uint = core_flags::VERIFY_SHA512 as c_uint;
/// Make OP_CODESEPARATOR and signature find-and-delete fail in legacy scripts.
pub const VERIFY_CONST_SCRIPTCODE: c_uint = core_flags::VERIFY_CONST_SCRIPTCODE as c_uint;
/// Require defined signature hash bytes (relay-only for legacy/v0).
pub const VERIFY_DEFINED_HASHTYPE: c_uint = core_flags::VERIFY_DEFINED_HASHTYPE as c_uint;
/// Relay-only canonical Falcon encoding restriction.
pub const VERIFY_FALCON_CANONICAL: c_uint = core_flags::VERIFY_FALCON_CANONICAL as c_uint;

/// Tidecoin default verification flags after auxpow-era features are enabled.
pub const VERIFY_ALL_TIDECOIN: c_uint = core_flags::VERIFY_ALL_TIDECOIN as c_uint;

/// Computes Tidecoin verification flags without assuming an auxpow activation height.
///
/// Base Tidecoin flags are always returned. Post-auxpow flags require an
/// explicit auxpow activation height and should be computed with
/// [`height_to_flags_with_auxpow_start_height`].
pub fn height_to_flags(height: u32) -> u32 {
    height_to_flags_with_auxpow_start_height(height, None)
}

/// Computes Tidecoin verification flags for a specific auxpow activation height.
pub fn height_to_flags_with_auxpow_start_height(
    height: u32,
    auxpow_start_height: Option<u32>,
) -> u32 {
    let mut flags = VERIFY_P2SH
        | VERIFY_NULLDUMMY
        | VERIFY_CHECKLOCKTIMEVERIFY
        | VERIFY_CHECKSEQUENCEVERIFY
        | VERIFY_WITNESS;

    if auxpow_start_height.is_some_and(|start| height >= start) {
        flags |= VERIFY_PQ_STRICT | VERIFY_WITNESS_V1_512 | VERIFY_SHA512;
    }

    flags
}

/// Detailed failure information returned by the diagnostic verification APIs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ScriptFailure {
    /// High-level error code for the byte-oriented verification API.
    pub error: Error,
    /// Detailed interpreter error for the Tidecoin validation engine.
    pub script_error: ScriptError,
}

/// Verifies a single spend (input) of a serialized transaction.
pub fn verify(
    spent_output: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
) -> Result<(), Error> {
    let flags = VERIFY_ALL_TIDECOIN;

    verify_with_flags(spent_output, amount, spending_transaction, spent_outputs, input_index, flags)
}

/// Same as [`verify`] but also reports the interpreter's `ScriptError`.
pub fn verify_with_details(
    spent_output: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
) -> Result<(), ScriptFailure> {
    let flags = VERIFY_ALL_TIDECOIN;

    perform_verification(
        spent_output,
        amount,
        spending_transaction,
        spent_outputs,
        input_index,
        flags,
    )
}

/// Same as [`verify`] but with explicit script verification flags.
pub fn verify_with_flags(
    spent_output_script: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
    flags: u32,
) -> Result<(), Error> {
    perform_verification(
        spent_output_script,
        amount,
        spending_transaction,
        spent_outputs,
        input_index,
        flags,
    )
    .map_err(|failure| failure.error)
}

/// Same as [`verify_with_flags`] but also reports the interpreter's `ScriptError`.
pub fn verify_with_flags_detailed(
    spent_output_script: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
    flags: u32,
) -> Result<(), ScriptFailure> {
    perform_verification(
        spent_output_script,
        amount,
        spending_transaction,
        spent_outputs,
        input_index,
        flags,
    )
}

fn perform_verification(
    spent_output_script: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
    flags: u32,
) -> Result<(), ScriptFailure> {
    consensus_core::validate_verification_flags(flags).map_err(|err| ScriptFailure {
        error: map_validation_error(&err),
        script_error: ScriptError::Ok,
    })?;

    let tx = parse_transaction(spending_transaction)
        .map_err(|err| ScriptFailure { error: err, script_error: ScriptError::Ok })?;
    if input_index >= tx.inputs.len() {
        return Err(ScriptFailure { error: Error::ERR_TX_INDEX, script_error: ScriptError::Ok });
    }
    let spent_outputs = spent_outputs
        .map(|raw| decode_spent_outputs(tx.inputs.len(), raw))
        .transpose()
        .map_err(|err| ScriptFailure { error: err, script_error: ScriptError::Ok })?;
    let explicit_amount_known = true;
    let has_amount = explicit_amount_known;
    let spend_context = SpendContext::new(spent_output_script, spent_outputs, amount, has_amount);
    consensus_core::verify_script_input_detailed(&tx, input_index, spend_context, flags).map_err(
        |failure| ScriptFailure {
            error: map_validation_error(&failure.error),
            script_error: failure.script_error,
        },
    )
}

fn parse_transaction(tx_bytes: &[u8]) -> Result<Transaction, Error> {
    let mut remaining = tx_bytes;
    let tx: Transaction = encoding::decode_from_slice_unbounded(&mut remaining)
        .map_err(|_| Error::ERR_TX_DESERIALIZE)?;
    if !remaining.is_empty() {
        return Err(Error::ERR_TX_SIZE_MISMATCH);
    }
    Ok(tx)
}

fn decode_spent_outputs(expected: usize, raw: &[Utxo]) -> Result<SpentOutputs, Error> {
    use core::slice;

    if raw.len() != expected {
        return Err(Error::ERR_SPENT_OUTPUTS_MISMATCH);
    }

    let mut txouts = Vec::with_capacity(raw.len());
    for utxo in raw {
        if utxo.value < 0 {
            return Err(Error::ERR_AMOUNT_REQUIRED);
        }

        if utxo.script_pubkey_len == 0 && utxo.script_pubkey.is_null() {
            txouts.push(TxOut {
                amount: Amount::from_sat(utxo.value as u64)
                    .map_err(|_| Error::ERR_AMOUNT_REQUIRED)?,
                script_pubkey: ScriptPubKeyBuf::new(),
            });
            continue;
        }

        if utxo.script_pubkey.is_null() {
            return Err(Error::ERR_TX_DESERIALIZE);
        }

        let script_bytes =
            unsafe { slice::from_raw_parts(utxo.script_pubkey, utxo.script_pubkey_len as usize) };
        txouts.push(TxOut {
            amount: Amount::from_sat(utxo.value as u64).map_err(|_| Error::ERR_AMOUNT_REQUIRED)?,
            script_pubkey: ScriptPubKeyBuf::from_bytes(script_bytes.to_vec()),
        });
    }

    Ok(SpentOutputs::from_txouts(txouts))
}

fn map_validation_error(error: &consensus_core::TidecoinValidationError) -> Error {
    match error {
        consensus_core::TidecoinValidationError::Script(_) => Error::ERR_SCRIPT,
        consensus_core::TidecoinValidationError::InvalidInputIndex { .. } => Error::ERR_TX_INDEX,
        consensus_core::TidecoinValidationError::InvalidFlags => Error::ERR_INVALID_FLAGS,
        consensus_core::TidecoinValidationError::AmountRequired => Error::ERR_AMOUNT_REQUIRED,
        consensus_core::TidecoinValidationError::SpentOutputs(_) => {
            Error::ERR_SPENT_OUTPUTS_MISMATCH
        }
        consensus_core::TidecoinValidationError::MissingSpentOutput(_) => {
            Error::ERR_SPENT_OUTPUTS_REQUIRED
        }
    }
}

/// UTXO struct for the byte-oriented verification API.
#[repr(C)]
pub struct Utxo {
    /// Pointer to the scriptPubkey bytes.
    pub script_pubkey: *const c_uchar,
    /// The length of the scriptPubkey.
    pub script_pubkey_len: c_uint,
    /// The value in sats.
    pub value: c_int64,
}

/// Errors returned by the consensus verifier.
///
/// Verification errors for the byte-oriented API.
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum Error {
    /// Generic script verification failure for the byte-oriented verification API.
    ERR_SCRIPT = 0,
    /// An invalid index for `txTo`.
    ERR_TX_INDEX,
    /// `txToLen` did not match with the size of `txTo`.
    ERR_TX_SIZE_MISMATCH,
    /// An error deserializing `txTo`.
    ERR_TX_DESERIALIZE,
    /// Input amount is required if WITNESS is used.
    ERR_AMOUNT_REQUIRED,
    /// Script verification `flags` are invalid.
    ERR_INVALID_FLAGS,
    /// Previous outputs are required by the selected verification mode.
    ERR_SPENT_OUTPUTS_REQUIRED,
    /// Provided previous outputs do not match the transaction being verified.
    ERR_SPENT_OUTPUTS_MISMATCH,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        let description = match *self {
            ERR_SCRIPT => "script verification failed",
            ERR_TX_INDEX => "an invalid index for txTo",
            ERR_TX_SIZE_MISMATCH => "txToLen did not match with the size of txTo",
            ERR_TX_DESERIALIZE => "an error deserializing txTo",
            ERR_AMOUNT_REQUIRED => "input amount is required if witness verification is used",
            ERR_INVALID_FLAGS => "script verification flags are invalid",
            ERR_SPENT_OUTPUTS_REQUIRED => {
                "previous outputs are required by the selected verification mode"
            }
            ERR_SPENT_OUTPUTS_MISMATCH => {
                "provided previous outputs do not match the transaction inputs"
            }
        };

        f.write_str(description)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Utxo;
    #[cfg(not(feature = "std"))]
    use alloc::string::ToString;
    #[cfg(not(feature = "std"))]
    use alloc::vec;
    use encoding::encode_to_vec;
    use hashes::{hash160, sha256, sha512};
    use primitives::{
        absolute::LockTime,
        opcodes::all,
        script::{
            Builder as BuilderT, PushBytesBuf, ScriptBuf as PrimitiveScriptBuf, ScriptHash,
            ScriptPubKeyBuf, ScriptSigBuf,
        },
        Amount, OutPoint, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
    };
    #[cfg(feature = "std")]
    use std::vec;

    type Builder = BuilderT<()>;
    type ScriptBuf = PrimitiveScriptBuf<()>;

    fn sat(value: u64) -> Amount {
        Amount::from_sat(value).expect("test amount in range")
    }

    fn dummy_outpoint() -> OutPoint {
        OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 }
    }

    fn p2sh_script_pubkey(redeem_script: &ScriptBuf) -> ScriptBuf {
        let script_hash = ScriptHash::from_byte_array(
            hash160::Hash::hash(redeem_script.as_bytes()).to_byte_array(),
        );
        Builder::new()
            .push_opcode(all::OP_HASH160)
            .push_slice(PushBytesBuf::try_from(script_hash.to_byte_array().to_vec()).unwrap())
            .push_opcode(all::OP_EQUAL)
            .into_script()
    }
    #[test]
    fn height_flag_schedule_matches_tidecoin_auxpow_gate() {
        let base = VERIFY_P2SH
            | VERIFY_NULLDUMMY
            | VERIFY_CHECKLOCKTIMEVERIFY
            | VERIFY_CHECKSEQUENCEVERIFY
            | VERIFY_WITNESS;

        assert_eq!(height_to_flags(0), base);
        assert_eq!(height_to_flags_with_auxpow_start_height(999, Some(1_000)), base);
        assert_eq!(
            height_to_flags_with_auxpow_start_height(1_000, Some(1_000)),
            base | VERIFY_PQ_STRICT | VERIFY_WITNESS_V1_512 | VERIFY_SHA512
        );
        assert_eq!(height_to_flags_with_auxpow_start_height(1_000_000, None), base);
    }

    #[test]
    fn verify_with_flags_rejects_unknown_bits_before_tx_deserialize() {
        let invalid_flags = VERIFY_P2SH | (1u32 << 31);

        let err =
            verify_with_flags(&[], 0, &[], None, 0, invalid_flags).expect_err("invalid flags");
        assert_eq!(err, Error::ERR_INVALID_FLAGS);

        let failure = verify_with_flags_detailed(&[], 0, &[], None, 0, invalid_flags)
            .expect_err("invalid flags");
        assert_eq!(failure.error, Error::ERR_INVALID_FLAGS);
        assert_eq!(failure.script_error, ScriptError::Ok);
    }

    #[test]
    fn err_script_display_reports_verification_failure() {
        assert_eq!(Error::ERR_SCRIPT.to_string(), "script verification failed");
    }

    #[test]
    fn verify_with_flags_rejects_unknown_bits_before_tx_index_check() {
        let invalid_flags = VERIFY_WITNESS | (1u32 << 31);
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };
        let tx_bytes = encode_to_vec(&tx);

        let failure = verify_with_flags_detailed(&[], 0, &tx_bytes, None, 7, invalid_flags)
            .expect_err("invalid flags");
        assert_eq!(failure.error, Error::ERR_INVALID_FLAGS);
        assert_eq!(failure.script_error, ScriptError::Ok);
    }

    #[test]
    fn verify_simple_p2sh_redeem_script() {
        let redeem_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let script_sig = push_data_script(redeem_script.as_bytes());
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::from(script_sig.into_bytes()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let spent_script = p2sh_script_pubkey(&redeem_script);
        let tx_bytes = encode_to_vec(&tx);
        verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_P2SH)
            .expect("p2sh redeem should validate");
    }

    #[test]
    fn verify_p2sh_p2wsh_trivial_witness() {
        let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let witness_script_bytes = witness_script.as_bytes().to_vec();
        let redeem_hash = sha256::Hash::hash(&witness_script_bytes);
        let redeem_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(redeem_hash.to_byte_array().to_vec()).unwrap())
            .into_script();
        let script_sig = push_data_script(redeem_script.as_bytes());
        let witness = Witness::from(vec![witness_script_bytes.clone()]);

        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::from(script_sig.into_bytes()),
                sequence: Sequence::MAX,
                witness,
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let spent_script = p2sh_script_pubkey(&redeem_script);
        let tx_bytes = encode_to_vec(&tx);
        verify_with_flags(
            spent_script.as_bytes(),
            5_000,
            &tx_bytes,
            None,
            0,
            VERIFY_P2SH | VERIFY_WITNESS,
        )
        .expect("p2sh-p2wsh witness spend should validate");
    }

    #[test]
    fn verify_script_conditions_then_branch() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_IF)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_ELSE)
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_ENDIF)
            .into_script();
        run_simple_script(script_sig, spent_script).expect("then branch executes");
    }

    #[test]
    fn verify_script_conditions_else_branch() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHBYTES_0).into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_IF)
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_ELSE)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_ENDIF)
            .into_script();
        run_simple_script(script_sig, spent_script).expect("else branch executes");
    }

    #[test]
    fn verify_script_unbalanced_conditional_fails() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script =
            Builder::new().push_opcode(all::OP_IF).push_opcode(all::OP_PUSHNUM_1).into_script();
        run_simple_script(script_sig, spent_script).expect_err("missing endif should fail");
    }

    #[test]
    fn verify_altstack_roundtrip() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_TOALTSTACK)
            .push_opcode(all::OP_FROMALTSTACK)
            .push_opcode(all::OP_DEPTH)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_EQUAL)
            .into_script();
        run_simple_script(script_sig, spent_script).expect("altstack operations succeed");
    }

    #[test]
    fn verify_rot_and_swap_ops() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_PUSHNUM_3)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_ROT)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_PUSHNUM_3)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_EQUAL)
            .into_script();
        run_simple_script(script_sig, spent_script).expect("rot/swap maintain order");
    }

    #[test]
    fn verify_pick_and_roll_ops() {
        let pick_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_PUSHNUM_3)
            .into_script();
        let pick_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PICK)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        run_simple_script(pick_sig, pick_script).expect("op_pick duplicates value");

        let roll_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_PUSHNUM_3)
            .push_opcode(all::OP_PUSHNUM_4)
            .into_script();
        let roll_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_3)
            .push_opcode(all::OP_ROLL)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        run_simple_script(roll_sig, roll_script).expect("op_roll moves element to top");
    }

    #[test]
    fn verify_arithmetic_and_within() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_PUSHNUM_3)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_ADD)
            .push_opcode(all::OP_DUP)
            .push_opcode(all::OP_PUSHNUM_5)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_6)
            .push_opcode(all::OP_WITHIN)
            .into_script();
        run_simple_script(script_sig, spent_script).expect("arithmetic and within succeed");
    }

    #[test]
    fn verify_sigpushonly_flag() {
        let script_sig =
            Builder::new().push_opcode(all::OP_PUSHNUM_1).push_opcode(all::OP_DUP).into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_ADD)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_EQUAL)
            .into_script();

        run_simple_script(script_sig.clone(), spent_script.clone()).expect("non push-only allowed");

        run_script_with_ctx_flags(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_SIGPUSHONLY,
        )
        .expect_err("sigpushonly flag rejects non push-only scriptSig");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_SIGPUSHONLY,
        )
        .expect_err("sigpushonly failure reason");
        assert_eq!(failure.script_error, ScriptError::SigPushOnly);
    }

    #[test]
    fn verify_sigpushonly_precedes_bad_opcode_for_malformed_pushdata() {
        let script_sig = ScriptBuf::from_bytes(vec![all::OP_PUSHDATA1.to_u8(), 0x01]);
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_SIGPUSHONLY,
        )
        .expect_err("sigpushonly must be checked before script execution");
        assert_eq!(failure.script_error, ScriptError::SigPushOnly);
    }

    #[test]
    fn verify_discourage_upgradable_nops_flag() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script =
            Builder::new().push_opcode(all::OP_NOP5).push_opcode(all::OP_PUSHNUM_1).into_script();

        run_simple_script(script_sig.clone(), spent_script.clone()).expect("nop allowed");

        run_script_with_ctx_flags(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
        )
        .expect_err("discourage upgradable nops flag rejects reserved nop use");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
        )
        .expect_err("discourage nops detail");
        assert_eq!(failure.script_error, ScriptError::DiscourageUpgradableNops);
    }

    #[test]
    fn verify_checksig_opcount_limit() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(vec![0x42]).unwrap())
            .into_script();

        let mut spent_builder =
            Builder::new().push_opcode(all::OP_TOALTSTACK).push_opcode(all::OP_TOALTSTACK);
        for _ in 0..35 {
            spent_builder = spent_builder
                .push_opcode(all::OP_FROMALTSTACK)
                .push_opcode(all::OP_FROMALTSTACK)
                .push_opcode(all::OP_2DUP)
                .push_opcode(all::OP_TOALTSTACK)
                .push_opcode(all::OP_TOALTSTACK)
                .push_opcode(all::OP_CHECKSIG)
                .push_opcode(all::OP_DROP);
        }
        let spent_script = spent_builder.push_opcode(all::OP_PUSHNUM_1).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("too many checksigs should exceed opcount budget");
        assert_eq!(failure.script_error, ScriptError::OpCount);
    }

    #[test]
    fn verify_minimalif_flag() {
        let condition = vec![2u8];
        let script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(condition.clone()).unwrap())
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_IF)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_ENDIF)
            .into_script();

        run_simple_script(script_sig.clone(), spent_script.clone()).expect("non minimal true ok");

        run_script_with_ctx_flags(
            script_sig,
            spent_script.clone(),
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_MINIMALIF,
        )
        .expect("MINIMALIF does not apply to legacy scripts");

        let witness_script = spent_script;
        let program = sha256::Hash::hash(witness_script.as_bytes());
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let witness = Witness::from(vec![condition, witness_script.as_bytes().to_vec()]);
        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            witness,
            sat(50_000),
            VERIFY_WITNESS | VERIFY_MINIMALIF,
        )
        .expect_err("non-minimal truthy witness branch rejected by MINIMALIF");
        assert_eq!(failure.script_error, ScriptError::MinimalIf);
    }

    #[test]
    fn verify_cleanstack_flag() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();

        run_simple_script(script_sig.clone(), spent_script.clone()).expect("extra stack elem ok");

        run_script_with_ctx_flags(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_CLEANSTACK,
        )
        .expect_err("cleanstack requires exactly one item");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_CLEANSTACK,
        )
        .expect_err("cleanstack detail");
        assert_eq!(failure.script_error, ScriptError::CleanStack);
    }

    #[test]
    fn verify_multisig_passes() {
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();

        let script_sig = Builder::new().push_opcode(all::OP_PUSHBYTES_0).into_script();

        let mut tx = multisig_test_transaction();
        tx.inputs[0].script_sig = ScriptSigBuf::from(script_sig.into_bytes());
        let tx_bytes = encode_to_vec(&tx);

        verify(spent_script.as_bytes(), 0, &tx_bytes, None, 0)
            .expect("0-of-0 multisig should validate");
    }

    #[test]
    fn verify_multisig_null_dummy_enforced() {
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();

        let mut tx = multisig_test_transaction();
        let good_script_sig = Builder::new().push_opcode(all::OP_PUSHBYTES_0).into_script();
        tx.inputs[0].script_sig = ScriptSigBuf::from(good_script_sig.into_bytes());
        let tx_bytes = encode_to_vec(&tx);
        verify(spent_script.as_bytes(), 0, &tx_bytes, None, 0)
            .expect("zero dummy should satisfy NULLDUMMY");

        let mut tx_bad = tx.clone();
        let bad_script_sig =
            Builder::new().push_slice(PushBytesBuf::try_from(vec![1]).unwrap()).into_script();
        tx_bad.inputs[0].script_sig = ScriptSigBuf::from(bad_script_sig.into_bytes());
        let tx_bad_bytes = encode_to_vec(&tx_bad);

        verify_with_flags(spent_script.as_bytes(), 0, &tx_bad_bytes, None, 0, VERIFY_ALL_TIDECOIN)
            .expect_err("non-zero dummy should fail under NULLDUMMY");

        let failure = verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bad_bytes,
            None,
            0,
            VERIFY_ALL_TIDECOIN,
        )
        .expect_err("nulldummy detail");
        assert_eq!(failure.script_error, ScriptError::SigNullDummy);

        let relaxed_flags = VERIFY_ALL_TIDECOIN & !VERIFY_NULLDUMMY;
        verify_with_flags(spent_script.as_bytes(), 0, &tx_bad_bytes, None, 0, relaxed_flags)
            .expect("non-zero dummy passes when NULLDUMMY disabled");
    }

    #[test]
    fn verify_stack_size_limit_enforced() {
        let mut sig_builder = Builder::new();
        for _ in 0..=1000 {
            sig_builder = sig_builder.push_opcode(all::OP_PUSHNUM_1);
        }
        let script_sig = sig_builder.into_script();
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("stack overflows after too many pushes");
        assert_eq!(failure.script_error, ScriptError::StackSize);
    }

    #[test]
    fn verify_sig_count_error() {
        let mut script_sig = Builder::new().push_opcode(all::OP_PUSHBYTES_0);
        for _ in 0..2 {
            script_sig = script_sig.push_slice(PushBytesBuf::try_from(vec![0x01]).unwrap());
        }
        let script_sig = script_sig.into_script();

        let spent_script = Builder::new()
            .push_int(2)
            .expect("small multisig key count")
            .push_slice(PushBytesBuf::try_from(vec![0x02]).unwrap())
            .push_int(1)
            .expect("small multisig sig count")
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("n_sigs larger than n_keys rejected");
        assert_eq!(failure.script_error, ScriptError::SigCount);
    }

    #[test]
    fn verify_pubkey_count_error() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHBYTES_0).into_script();
        let mut spent_builder = Builder::new().push_int(0).expect("zero is valid scriptint");
        for _ in 0..21 {
            spent_builder = spent_builder.push_slice(PushBytesBuf::try_from(vec![0x03]).unwrap());
        }
        let spent_script = spent_builder
            .push_int(21)
            .expect("small pubkey count")
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("too many pubkeys cause PubkeyCount failure");
        assert_eq!(failure.script_error, ScriptError::PubkeyCount);
    }

    #[test]
    fn verify_nullfail_flag() {
        let spent_script = Builder::new()
            .push_slice(PushBytesBuf::try_from(vec![0x99]).unwrap())
            .push_opcode(all::OP_CHECKSIG)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();

        let mut tx = multisig_test_transaction();
        let script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(vec![0x01, 0x01]).unwrap())
            .into_script();
        tx.inputs[0].script_sig = ScriptSigBuf::from(script_sig.into_bytes());
        let tx_bytes = encode_to_vec(&tx);

        verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_NONE)
            .expect("script succeeds when invalid signature is dropped");

        verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_NULLFAIL)
            .expect_err("nullfail forbids ignoring failing signatures");

        let failure = verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_NULLFAIL,
        )
        .expect_err("nullfail detail");
        assert_eq!(failure.script_error, ScriptError::NullFail);
    }

    #[test]
    fn verify_nullfail_multisig_exhaustion() {
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(vec![0x99]).unwrap())
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_CHECKMULTISIG)
            .push_opcode(all::OP_NOT)
            .into_script();

        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(vec![0x01, 0x01]).unwrap())
            .into_script();

        let mut tx = multisig_test_transaction();
        tx.inputs[0].script_sig = ScriptSigBuf::from(script_sig.into_bytes());
        let tx_bytes = encode_to_vec(&tx);

        verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_NONE)
            .expect("CHECKMULTISIG failure is masked by NOT when NULLFAIL disabled");

        let failure = verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_NULLFAIL,
        )
        .expect_err("NULLFAIL should trigger when failing non-empty multisig signatures remain");
        assert_eq!(failure.script_error, ScriptError::NullFail);
    }

    #[test]
    fn verify_op_return_sets_script_error() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script = Builder::new().push_opcode(all::OP_RETURN).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("op_return halts execution");
        assert_eq!(failure.script_error, ScriptError::OpReturn);
    }

    #[test]
    fn verify_op_verify_sets_script_error() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHBYTES_0).into_script();
        let spent_script = Builder::new().push_opcode(all::OP_VERIFY).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("op_verify fails");
        assert_eq!(failure.script_error, ScriptError::Verify);
    }

    #[test]
    fn verify_equalverify_sets_script_error() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_2)
            .into_script();
        let spent_script = Builder::new().push_opcode(all::OP_EQUALVERIFY).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("equalverify fails");
        assert_eq!(failure.script_error, ScriptError::EqualVerify);
    }

    #[test]
    fn verify_numequalverify_sets_script_error() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_2)
            .into_script();
        let spent_script = Builder::new().push_opcode(all::OP_NUMEQUALVERIFY).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("numequalverify fails");
        assert_eq!(failure.script_error, ScriptError::NumEqualVerify);
    }

    #[test]
    fn verify_checksigverify_sets_script_error() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(vec![0x99]).unwrap())
            .into_script();
        let spent_script = Builder::new().push_opcode(all::OP_CHECKSIGVERIFY).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("checksigverify detects invalid signature");
        assert_eq!(failure.script_error, ScriptError::CheckSigVerify);
    }

    #[test]
    fn verify_checkmultisigverify_sets_script_error() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_PUSHBYTES_0)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(vec![0x99]).unwrap())
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_CHECKMULTISIGVERIFY)
            .into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("checkmultisigverify fails with empty signature");
        assert_eq!(failure.script_error, ScriptError::CheckMultiSigVerify);
    }

    #[test]
    fn verify_disabled_opcode_sets_script_error() {
        let script_sig = Builder::new().into_script();
        let spent_script = Builder::new().push_opcode(all::OP_CAT).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("disabled opcode should fail");
        assert_eq!(failure.script_error, ScriptError::DisabledOpcode);
    }

    #[test]
    fn verify_reserved_opcode_sets_script_error() {
        let script_sig = Builder::new().into_script();
        let spent_script = Builder::new().push_opcode(all::OP_VERIF).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("reserved opcode should fail");
        assert_eq!(failure.script_error, ScriptError::BadOpcode);
    }

    #[test]
    fn verify_witness_program_wrong_length() {
        let script_sig = Builder::new().into_script();
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            // Use a non-zero program so EvalFalse does not short-circuit before witness checks.
            .push_slice(PushBytesBuf::try_from(vec![1u8; 5]).unwrap())
            .into_script();

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            Witness::new(),
            sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("invalid witness length fails");
        assert_eq!(failure.script_error, ScriptError::WitnessProgramWrongLength);
    }

    #[test]
    fn verify_witness_program_witness_empty() {
        let script_sig = Builder::new().into_script();
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            // Use a non-zero program so EvalFalse does not short-circuit before witness checks.
            .push_slice(PushBytesBuf::try_from(vec![1u8; 32]).unwrap())
            .into_script();

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            Witness::new(),
            sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("missing witness stack fails");
        assert_eq!(failure.script_error, ScriptError::WitnessProgramWitnessEmpty);
    }

    #[test]
    fn verify_witness_program_mismatch_p2wsh() {
        let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let program = sha256::Hash::hash(witness_script.as_bytes());
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let wrong_script = Builder::new().push_opcode(all::OP_PUSHNUM_2).into_script();
        let witness = Witness::from(vec![wrong_script.as_bytes().to_vec()]);

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            witness,
            sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("p2wsh hash mismatch fails");
        assert_eq!(failure.script_error, ScriptError::WitnessProgramMismatch);
    }

    #[test]
    fn verify_witness_program_mismatch_p2wpkh() {
        let program = vec![0x11u8; 20];
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program).unwrap())
            .into_script();
        let witness = Witness::from(vec![vec![0x01]]);

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            witness,
            sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("p2wpkh requires two witness items");
        assert_eq!(failure.script_error, ScriptError::WitnessProgramMismatch);
    }

    #[test]
    fn verify_p2wsh_cleanstack_enforced() {
        let witness_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        let program = sha256::Hash::hash(witness_script.as_bytes());
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let witness = Witness::from(vec![witness_script.as_bytes().to_vec()]);

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            witness,
            sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("witness scripts must leave exactly one stack item");
        assert_eq!(failure.script_error, ScriptError::CleanStack);
    }

    #[test]
    fn verify_p2sh_p2wsh_cleanstack_enforced() {
        let witness_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        let program = sha256::Hash::hash(witness_script.as_bytes());
        let redeem_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let redeem_bytes = redeem_script.as_bytes().to_vec();
        let script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(redeem_bytes.clone()).unwrap())
            .into_script();
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_HASH160)
            .push_slice(
                PushBytesBuf::try_from(hash160::Hash::hash(&redeem_bytes).to_byte_array().to_vec())
                    .unwrap(),
            )
            .push_opcode(all::OP_EQUAL)
            .into_script();
        let witness = Witness::from(vec![witness_script.as_bytes().to_vec()]);

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            witness,
            sat(50_000),
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .expect_err("p2sh-wrapped witnesses must also leave a clean stack");
        assert_eq!(failure.script_error, ScriptError::CleanStack);
    }

    #[test]
    fn verify_witness_malleated_p2sh() {
        let inner_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let program = sha256::Hash::hash(inner_script.as_bytes());
        let redeem_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let script_pubkey = p2sh_script_pubkey(&redeem_script);
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(redeem_script.as_bytes().to_vec()).unwrap())
            .into_script();
        let witness = Witness::from(vec![inner_script.as_bytes().to_vec()]);

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            witness,
            sat(50_000),
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .expect_err("non-canonical redeem push fails after P2SH witness detection");
        assert_eq!(failure.script_error, ScriptError::WitnessMalleatedP2SH);
    }

    #[test]
    fn verify_p2sh_non_witness_program_with_witness_is_unexpected() {
        let redeem_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let script_pubkey = p2sh_script_pubkey(&redeem_script);
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(redeem_script.as_bytes().to_vec()).unwrap())
            .into_script();
        let witness = Witness::from(vec![vec![0x01]]);

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            witness,
            sat(50_000),
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .expect_err("non-witness P2SH spends must report unexpected witness data");
        assert_eq!(failure.script_error, ScriptError::WitnessUnexpected);
    }

    #[test]
    fn verify_unknown_witness_program_does_not_bypass_eval_false() {
        // Preserve the interpreter rule that unknown witness versions cannot
        // bypass an already-false base-script result.
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHNUM_16)
            .push_slice(PushBytesBuf::try_from(vec![0x00, 0x00]).unwrap())
            .into_script();

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            Witness::from(vec![vec![0x01]]),
            sat(2_000),
            VERIFY_P2SH | VERIFY_WITNESS,
        )
        .expect_err("EvalFalse must be enforced before unknown-version witness handling");
        assert_eq!(failure.script_error, ScriptError::EvalFalse);
    }

    #[test]
    fn verify_witness_malleated_bare() {
        let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let program = sha256::Hash::hash(witness_script.as_bytes());
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            Witness::from(vec![witness_script.as_bytes().to_vec()]),
            sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("bare witness with scriptSig fails");
        assert_eq!(failure.script_error, ScriptError::WitnessMalleated);
    }

    #[test]
    fn verify_witness_unexpected_rejected() {
        let script_pubkey = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let witness = Witness::from(vec![vec![0x01]]);

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            witness,
            sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("unexpected witness data fails");
        assert_eq!(failure.script_error, ScriptError::WitnessUnexpected);
    }

    #[test]
    fn spent_output_script_must_match() {
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let wrong_script = Builder::new().push_opcode(all::OP_PUSHNUM_2).into_script();
        let tx = multisig_test_transaction();
        let tx_bytes = encode_to_vec(&tx);

        let (storage, utxo) = make_utxo(&wrong_script, 0);
        let utxos = [utxo];
        let err =
            verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, Some(&utxos), 0, VERIFY_NONE)
                .expect_err("mismatched spent output should fail");
        assert_eq!(err, Error::ERR_SPENT_OUTPUTS_MISMATCH);
        drop(storage);
    }

    #[test]
    fn p2sh_wrapped_v1_program_treated_as_reserved_witness() {
        let redeem = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(vec![0x11; 32]).unwrap())
            .into_script();
        let spent_script = p2sh_script_pubkey(&redeem);
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::from(push_data_script(redeem.as_bytes()).into_bytes()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };
        let tx_bytes = encode_to_vec(&tx);
        let (storage, utxo) = make_utxo(&spent_script, 0);
        let utxos = [utxo];

        verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            Some(&utxos),
            0,
            VERIFY_P2SH | VERIFY_WITNESS,
        )
        .expect("P2SH-wrapped v1/32 remains reserved and succeeds without discourage flag");

        let failure = verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            Some(&utxos),
            0,
            VERIFY_P2SH | VERIFY_WITNESS | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        )
        .expect_err("reserved witness version should fail when discouraged");
        assert_eq!(failure.script_error, ScriptError::DiscourageUpgradableWitnessProgram);
        drop(storage);
    }

    #[test]
    fn witness_v1_512_discouraged_without_feature_flag() {
        let script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let (spent_script, witness) = witness_v1_512_fixture(script, Vec::new());
        run_witness_script_with_ctx(
            Builder::new().into_script(),
            spent_script,
            witness,
            sat(50_000),
            VERIFY_WITNESS | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        )
        .expect_err("tidecoin v1 programs are discouraged when the feature flag is absent");
    }

    #[test]
    fn p2sh_anchor_fails_when_upgradable_witness_is_discouraged() {
        let anchor_program = PushBytesBuf::try_from(vec![0x4e, 0x73]).unwrap();
        let anchor =
            Builder::new().push_opcode(all::OP_PUSHNUM_1).push_slice(anchor_program).into_script();
        let spent_script = p2sh_script_pubkey(&anchor);
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::from(push_data_script(anchor.as_bytes()).into_bytes()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };
        let tx_bytes = encode_to_vec(&tx);
        let failure = verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_P2SH | VERIFY_WITNESS | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        )
        .expect_err("nested pay-to-anchor should be treated as reserved witness program");
        assert_eq!(failure.script_error, ScriptError::DiscourageUpgradableWitnessProgram);
    }

    #[test]
    fn witness_v1_512_disabled_is_ordinary_script_with_unexpected_witness() {
        let script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let (spent_script, witness) = witness_v1_512_fixture(script, Vec::new());
        for flags in [VERIFY_WITNESS, VERIFY_WITNESS | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM]
        {
            let failure = run_witness_script_with_ctx(
                Builder::new().into_script(),
                spent_script.clone(),
                witness.clone(),
                sat(50_000),
                flags,
            )
            .unwrap_err();
            assert_eq!(failure.script_error, ScriptError::WitnessUnexpected);
        }
    }

    #[test]
    fn short_witness_v1_remains_reserved_when_extension_enabled() {
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(vec![0x11; 32]).unwrap())
            .into_script();

        run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            Witness::new(),
            sat(50_000),
            VERIFY_WITNESS | VERIFY_WITNESS_V1_512,
        )
        .expect("short v1 is reserved even when native v1-512 activates");
    }

    #[test]
    fn witness_v1_512_empty_witness_is_rejected() {
        let script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let hash = sha512::Hash::hash(script.as_bytes());
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(hash.to_byte_array().to_vec()).unwrap())
            .into_script();

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            Witness::new(),
            sat(50_000),
            VERIFY_WITNESS | VERIFY_WITNESS_V1_512,
        )
        .expect_err("enabled witness-v1-512 requires a witness stack");
        assert_eq!(failure.script_error, ScriptError::WitnessProgramWitnessEmpty);
    }

    #[test]
    fn witness_v1_512_sha512_commitment_mismatch_fails() {
        let expected = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let wrong = Builder::new().push_opcode(all::OP_PUSHNUM_2).into_script();
        let hash = sha512::Hash::hash(expected.as_bytes());
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(hash.to_byte_array().to_vec()).unwrap())
            .into_script();

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            Witness::from(vec![wrong.as_bytes().to_vec()]),
            sat(50_000),
            VERIFY_WITNESS | VERIFY_WITNESS_V1_512,
        )
        .expect_err("witness-v1-512 commits to sha512(script)");
        assert_eq!(failure.script_error, ScriptError::WitnessProgramMismatch);
    }

    #[test]
    fn witness_v1_512_trivial_script_succeeds() {
        let script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let (spent_script, witness) = witness_v1_512_fixture(script, Vec::new());

        run_witness_script_with_ctx(
            Builder::new().into_script(),
            spent_script,
            witness,
            sat(50_000),
            VERIFY_WITNESS | VERIFY_WITNESS_V1_512 | VERIFY_CLEANSTACK,
        )
        .expect("basic tidecoin witness-v1-512 script should execute");
    }

    #[test]
    fn witness_v1_512_checksigadd_is_bad_opcode() {
        let script = Builder::new()
            .push_int(0)
            .expect("zero is valid scriptint")
            .push_opcode(all::OP_SWAP)
            .push_opcode(all::OP_CHECKSIGADD)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_EQUAL)
            .into_script();
        let (spent_script, witness) = witness_v1_512_fixture(script, vec![Vec::new(), Vec::new()]);

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            spent_script,
            witness,
            sat(50_000),
            VERIFY_WITNESS | VERIFY_WITNESS_V1_512,
        )
        .expect_err("tidecoin witness-v1-512 does not support CHECKSIGADD");
        assert_eq!(failure.script_error, ScriptError::BadOpcode);
    }

    fn witness_v1_512_fixture(
        script: ScriptBuf,
        mut stack_items: Vec<Vec<u8>>,
    ) -> (ScriptBuf, Witness) {
        let program_hash = sha512::Hash::hash(script.as_bytes());
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(program_hash.to_byte_array().to_vec()).unwrap())
            .into_script();
        stack_items.push(script.as_bytes().to_vec());
        (spent_script, Witness::from(stack_items))
    }

    #[test]
    fn verify_checklocktimeverify_passes_and_fails() {
        let lock_height = 1000i64;
        let script_sig = Builder::new().into_script();
        let spent_script = Builder::new()
            .push_int(lock_height.try_into().unwrap())
            .expect("lock height fits scriptint")
            .push_opcode(all::OP_CLTV)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();

        run_script_with_ctx(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::from_height((lock_height as u32) + 1).unwrap(),
            Sequence::ZERO,
        )
        .expect("locktime met");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::from_height((lock_height as u32) - 1).unwrap(),
            Sequence::ZERO,
            VERIFY_ALL_TIDECOIN,
        )
        .expect_err("locktime unmet");
        assert_eq!(failure.script_error, ScriptError::UnsatisfiedLockTime);

        let negative_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_NEG1)
            .push_opcode(all::OP_CLTV)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        let negative = run_script_with_ctx_flags_detailed(
            Builder::new().into_script(),
            negative_script,
            LockTime::from_height(lock_height as u32).unwrap(),
            Sequence::ZERO,
            VERIFY_ALL_TIDECOIN,
        )
        .expect_err("negative locktime rejected");
        assert_eq!(negative.script_error, ScriptError::NegativeLockTime);
    }

    #[test]
    fn verify_checksequenceverify_passes_and_fails() {
        let relative = 5i64;
        let script_sig = Builder::new().into_script();
        let spent_script = Builder::new()
            .push_int(relative.try_into().unwrap())
            .expect("relative locktime fits scriptint")
            .push_opcode(all::OP_CSV)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();

        run_script_with_ctx(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence(relative as u32),
        )
        .expect("csv satisfied");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence((relative - 1) as u32),
            VERIFY_ALL_TIDECOIN,
        )
        .expect_err("csv unmet");
        assert_eq!(failure.script_error, ScriptError::UnsatisfiedLockTime);

        let negative_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_NEG1)
            .push_opcode(all::OP_CSV)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        let negative = run_script_with_ctx_flags_detailed(
            Builder::new().into_script(),
            negative_script,
            LockTime::ZERO,
            Sequence::ZERO,
            VERIFY_ALL_TIDECOIN,
        )
        .expect_err("negative relative locktime rejected");
        assert_eq!(negative.script_error, ScriptError::NegativeLockTime);
    }

    #[test]
    fn verify_checksequenceverify_requires_version_two() {
        let script_sig = Builder::new().into_script();
        let spent_script = Builder::new()
            .push_int(1)
            .expect("small relative locktime")
            .push_opcode(all::OP_CSV)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();

        let failure = run_script_with_ctx_version_flags_detailed(
            TransactionVersion::ONE,
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence(1),
            VERIFY_CHECKSEQUENCEVERIFY,
        )
        .expect_err("csv must fail for tx version < 2");
        assert_eq!(failure.script_error, ScriptError::UnsatisfiedLockTime);

        run_script_with_ctx_version_flags_detailed(
            TransactionVersion::TWO,
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence(1),
            VERIFY_CHECKSEQUENCEVERIFY,
        )
        .expect("csv should pass once transaction version is >= 2");

        run_script_with_ctx_version_flags_detailed(
            TransactionVersion::maybe_non_standard(u32::MAX),
            Builder::new().into_script(),
            Builder::new()
                .push_int(1)
                .expect("small relative locktime")
                .push_opcode(all::OP_CSV)
                .push_opcode(all::OP_DROP)
                .push_opcode(all::OP_PUSHNUM_1)
                .into_script(),
            LockTime::ZERO,
            Sequence(1),
            VERIFY_CHECKSEQUENCEVERIFY,
        )
        .expect("csv version gate uses uint32 semantics (negative values are >= 2)");
    }

    #[test]
    fn verify_checksequenceverify_masks_operands_larger_than_u32() {
        let script_sig = Builder::new().into_script();
        let sequence_bytes = PushBytesBuf::try_from(vec![0x00, 0x00, 0x00, 0x80, 0x01]).unwrap();
        let spent_script = Builder::new()
            .push_slice(sequence_bytes)
            .push_opcode(all::OP_CSV)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();

        run_script_with_ctx_version_flags_detailed(
            TransactionVersion::TWO,
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::ZERO,
            VERIFY_CHECKSEQUENCEVERIFY,
        )
        .expect("csv should mask large operands instead of rejecting >u32");
    }

    #[test]
    fn const_scriptcode_rejects_op_codeseparator_even_unexecuted() {
        let script_sig = Builder::new().into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_IF)
            .push_opcode(all::OP_CODESEPARATOR)
            .push_opcode(all::OP_ENDIF)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();

        run_script_with_ctx_flags(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect("without CONST_SCRIPTCODE, unexecuted OP_CODESEPARATOR is permitted");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_CONST_SCRIPTCODE,
        )
        .expect_err("CONST_SCRIPTCODE rejects OP_CODESEPARATOR in legacy scripts");
        assert_eq!(failure.script_error, ScriptError::OpCodeSeparator);
    }

    #[test]
    fn const_scriptcode_rejects_signature_find_and_delete() {
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(vec![0x99]).unwrap())
            .push_opcode(all::OP_CHECKSIG)
            .into_script();

        let failure = run_script_with_ctx_flags_detailed(
            Builder::new().into_script(),
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_CONST_SCRIPTCODE,
        )
        .expect_err("CONST_SCRIPTCODE rejects legacy find-and-delete mutations");
        assert_eq!(failure.script_error, ScriptError::SigFindAndDelete);
    }

    #[test]
    fn pushdata_variants_match_direct_push_semantics() {
        let direct = vec![0x01, 0x5a];
        let pushdata1 = vec![all::OP_PUSHDATA1.to_u8(), 0x01, 0x5a];
        let pushdata2 = vec![all::OP_PUSHDATA2.to_u8(), 0x01, 0x00, 0x5a];
        let pushdata4 = vec![all::OP_PUSHDATA4.to_u8(), 0x01, 0x00, 0x00, 0x00, 0x5a];

        for variant in [direct, pushdata1, pushdata2, pushdata4] {
            let mut script = variant;
            script.extend_from_slice(&[0x01, 0x5a, all::OP_EQUAL.to_u8()]);

            run_script_with_ctx_flags_detailed(
                ScriptBuf::new(),
                ScriptBuf::from_bytes(script),
                LockTime::ZERO,
                Sequence::MAX,
                VERIFY_NONE,
            )
            .expect("all pushdata forms must produce identical stack values");
        }
    }

    #[test]
    fn truncated_pushdata_scripts_fail_with_bad_opcode() {
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        for truncated in [
            vec![all::OP_PUSHDATA1.to_u8(), 0x01],
            vec![all::OP_PUSHDATA2.to_u8(), 0x01, 0x00],
            vec![all::OP_PUSHDATA4.to_u8(), 0x01, 0x00, 0x00, 0x00],
        ] {
            let failure = run_script_with_ctx_flags_detailed(
                ScriptBuf::from_bytes(truncated),
                spent_script.clone(),
                LockTime::ZERO,
                Sequence::MAX,
                VERIFY_NONE,
            )
            .expect_err("truncated pushdata opcode should fail");
            assert_eq!(failure.script_error, ScriptError::BadOpcode);
        }
    }

    #[test]
    fn truncated_oversized_pushdata_reports_bad_opcode_before_pushsize() {
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        for truncated in [
            vec![all::OP_PUSHDATA2.to_u8(), 0x09, 0x02],
            vec![all::OP_PUSHDATA4.to_u8(), 0x09, 0x02, 0x00, 0x00],
        ] {
            let failure = run_script_with_ctx_flags_detailed(
                ScriptBuf::from_bytes(truncated),
                spent_script.clone(),
                LockTime::ZERO,
                Sequence::MAX,
                VERIFY_NONE,
            )
            .expect_err("truncated oversized pushdata must fail as bad opcode");
            assert_eq!(failure.script_error, ScriptError::BadOpcode);
        }
    }

    #[test]
    fn cltv_truncated_script_fails_with_invalid_stack_operation() {
        let failure = run_script_with_ctx_flags_detailed(
            ScriptBuf::new(),
            Builder::new().push_opcode(all::OP_CLTV).into_script(),
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_CHECKLOCKTIMEVERIFY,
        )
        .expect_err("OP_CHECKLOCKTIMEVERIFY requires an argument");
        assert_eq!(failure.script_error, ScriptError::InvalidStackOperation);
    }

    #[test]
    fn witness_only_does_not_imply_p2sh() {
        let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let witness_script_bytes = witness_script.as_bytes().to_vec();
        let redeem_hash = sha256::Hash::hash(&witness_script_bytes);
        let redeem_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(redeem_hash.to_byte_array().to_vec()).unwrap())
            .into_script();
        let script_sig = push_data_script(redeem_script.as_bytes());
        let witness = Witness::from(vec![witness_script_bytes]);
        let spent_script = p2sh_script_pubkey(&redeem_script);
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::from(script_sig.into_bytes()),
                sequence: Sequence::MAX,
                witness,
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };
        let tx_bytes = encode_to_vec(&tx);
        let failure = verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_WITNESS,
        )
        .expect_err("WITNESS-only should not behave like P2SH+WITNESS");
        assert_eq!(failure.script_error, ScriptError::WitnessUnexpected);
    }

    #[test]
    fn cleanstack_is_reported_before_witness_unexpected() {
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from(vec![vec![0x01]]),
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };
        let tx_bytes = encode_to_vec(&tx);
        let failure = verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_P2SH | VERIFY_WITNESS | VERIFY_CLEANSTACK,
        )
        .expect_err("clean stack must fail before witness-unexpected diagnostics");
        assert_eq!(failure.script_error, ScriptError::CleanStack);
    }

    #[test]
    fn verify_script_size_limit_enforced() {
        let script_sig = Builder::new().into_script();
        let oversized = vec![all::OP_NOP.to_u8(); 65_537];
        let spent_script = ScriptBuf::from_bytes(oversized);
        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("scripts larger than 64 KiB rejected");
        assert_eq!(failure.script_error, ScriptError::ScriptSize);
    }

    #[test]
    fn verify_push_size_limit_enforced() {
        let script_sig = Builder::new().into_script();
        let mut script_bytes = Vec::new();
        script_bytes.push(all::OP_PUSHDATA2.to_u8());
        let push_len: u16 = 8193;
        script_bytes.push((push_len & 0xff) as u8);
        script_bytes.push((push_len >> 8) as u8);
        script_bytes.extend(vec![0u8; push_len as usize]);
        let spent_script = ScriptBuf::from_bytes(script_bytes);

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("pushes over the Tidecoin 8192-byte limit are rejected");
        assert_eq!(failure.script_error, ScriptError::PushSize);
    }

    #[test]
    fn verify_opcode_count_limit_enforced() {
        let script_sig = Builder::new().into_script();
        let mut script_bytes = Vec::new();
        script_bytes.extend(vec![all::OP_NOP.to_u8(); 202]);
        let spent_script = ScriptBuf::from_bytes(script_bytes);

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("scripts exceeding opcount limit rejected");
        assert_eq!(failure.script_error, ScriptError::OpCount);
    }

    fn push_data_script(data: &[u8]) -> ScriptBuf {
        let push = PushBytesBuf::try_from(data.to_vec()).unwrap();
        Builder::new().push_slice(push).into_script()
    }

    fn run_simple_script(script_sig: ScriptBuf, script_pubkey: ScriptBuf) -> Result<(), Error> {
        run_script_with_ctx_flags(
            script_sig,
            script_pubkey,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
    }

    fn run_script_with_ctx(
        script_sig: ScriptBuf,
        script_pubkey: ScriptBuf,
        lock_time: LockTime,
        sequence: Sequence,
    ) -> Result<(), Error> {
        run_script_with_ctx_flags(
            script_sig,
            script_pubkey,
            lock_time,
            sequence,
            VERIFY_ALL_TIDECOIN,
        )
    }

    fn run_script_with_ctx_flags(
        script_sig: ScriptBuf,
        script_pubkey: ScriptBuf,
        lock_time: LockTime,
        sequence: Sequence,
        flags: u32,
    ) -> Result<(), Error> {
        run_script_with_ctx_flags_detailed(script_sig, script_pubkey, lock_time, sequence, flags)
            .map_err(|failure| failure.error)
    }

    fn run_script_with_ctx_flags_detailed(
        script_sig: ScriptBuf,
        script_pubkey: ScriptBuf,
        lock_time: LockTime,
        sequence: Sequence,
        flags: u32,
    ) -> Result<(), ScriptFailure> {
        run_script_with_ctx_version_flags_detailed(
            TransactionVersion::TWO,
            script_sig,
            script_pubkey,
            lock_time,
            sequence,
            flags,
        )
    }

    fn run_script_with_ctx_version_flags_detailed(
        version: TransactionVersion,
        script_sig: ScriptBuf,
        script_pubkey: ScriptBuf,
        lock_time: LockTime,
        sequence: Sequence,
        flags: u32,
    ) -> Result<(), ScriptFailure> {
        let tx = Transaction {
            version,
            lock_time,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::from(script_sig.into_bytes()),
                sequence,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let tx_bytes = encode_to_vec(&tx);
        verify_with_flags_detailed(script_pubkey.as_bytes(), 0, &tx_bytes, None, 0, flags)
    }

    fn run_witness_script_with_ctx(
        script_sig: ScriptBuf,
        script_pubkey: ScriptBuf,
        witness: Witness,
        amount: Amount,
        flags: u32,
    ) -> Result<(), ScriptFailure> {
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::from(script_sig.into_bytes()),
                sequence: Sequence::MAX,
                witness,
            }],
            outputs: vec![TxOut { amount, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let tx_bytes = encode_to_vec(&tx);
        verify_with_flags_detailed(
            script_pubkey.as_bytes(),
            amount.to_sat(),
            &tx_bytes,
            None,
            0,
            flags,
        )
    }

    fn multisig_test_transaction() -> Transaction {
        Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        }
    }

    fn make_utxo(script: &ScriptBuf, value: u64) -> (Vec<u8>, Utxo) {
        let bytes = script.as_bytes().to_vec();
        let utxo = Utxo {
            script_pubkey: bytes.as_ptr(),
            script_pubkey_len: bytes.len() as u32,
            value: value as i64,
        };
        (bytes, utxo)
    }
}
