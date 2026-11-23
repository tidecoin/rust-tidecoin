// SPDX-License-Identifier: CC0-1.0

//! Tidecoin transactions.
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::CompactSizeEncoder;
use internals::{const_casts, write_err, ToU64};

use super::Weight;
use crate::crypto::pq::{PqScheme, PqSignatureSize};
#[cfg(test)]
use crate::locktime::absolute;
use crate::locktime::absolute::{Height, MedianTimePast};
use crate::prelude::Borrow;
#[cfg(feature = "arbitrary")]
use crate::prelude::Vec;
use crate::script::{
    RedeemScript, ScriptExt as _, ScriptPubKey, ScriptPubKeyBuf, ScriptPubKeyExt as _,
    WitnessScript,
};
use crate::witness::Witness;
#[cfg(doc)]
use crate::TxSighashType;
use crate::{internal_macros, Amount, FeeRate, Sequence, SignedAmount};

#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(no_inline)]
pub use primitives::transaction::{
    BlockHashDecoderError, OutPointDecoderError, ParseTransactionError, ParseOutPointError,
    TransactionDecoderError, TransactionSanityError, TxInDecoderError, TxOutDecoderError,
    VersionDecoderError,
};
#[doc(inline)]
pub use primitives::transaction::{
    check_transaction_sanity, BlockHashDecoder, Ntxid, OutPoint, OutPointDecoder, OutPointEncoder,
    Transaction, TransactionDecoder, TransactionEncoder, TxIn, TxInDecoder, TxInEncoder, TxOut,
    TxOutDecoder, TxOutEncoder, Txid, Version, VersionDecoder, VersionEncoder, WitnessesEncoder,
    Wtxid,
};

/// Returns the input base weight.
///
/// Base weight excludes the witness and script.
// We need to use this const here but do not want to make it public in `primitives::TxIn`.
const TX_IN_BASE_WEIGHT: Weight =
    Weight::from_vb_unchecked(OutPoint::SIZE as u64 + Sequence::SIZE as u64);

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`TxIn`] type.
    pub trait TxInExt impl for TxIn {
        /// Returns true if this input enables the [`absolute::LockTime`](crate::absolute::LockTime) (aka `nLockTime`) of its
        /// [`Transaction`].
        ///
        /// `nLockTime` is enabled if *any* input enables it. See [`Transaction::is_lock_time_enabled`]
        ///  to check the overall state. If none of the inputs enables it, the lock time value is simply
        ///  ignored. If this returns false and OP_CHECKLOCKTIMEVERIFY is used in the redeem script with
        ///  this input then the script execution will fail.
        fn enables_lock_time(&self) -> bool { self.sequence != Sequence::MAX }

        /// The weight of the TxIn when it's included in a legacy transaction (i.e., a transaction
        /// having only legacy inputs).
        ///
        /// The witness weight is ignored here even when the witness is non-empty.
        /// If you want the witness to be taken into account, use `TxIn::segwit_weight` instead.
        ///
        /// Keep in mind that when adding a TxIn to a transaction, the total weight of the transaction
        /// might increase more than `TxIn::legacy_weight`. This happens when the new input added causes
        /// the input length `CompactSize` to increase its encoding length.
        ///
        /// # Panics
        ///
        /// If the conversion overflows.
        fn legacy_weight(&self) -> Weight {
            Weight::from_vb(self.base_size().to_u64()).unwrap()
        }

        /// The weight of the TxIn when it's included in a SegWit transaction (i.e., a transaction
        /// having at least one SegWit input).
        ///
        /// This always takes into account the witness, even when empty (in which
        /// case 1WU for the witness length `00` is included).
        /// This matches the node's `GetTransactionInputWeight` convention, also
        /// used for explicit wallet input-weight budgets in rc4. Compare such
        /// budgets in weight units before rounding to virtual bytes.
        ///
        /// Keep in mind that when adding a TxIn to a transaction, the total weight of the transaction
        /// might increase more than `TxIn::segwit_weight`. This happens when:
        /// - the new input added causes the input length `CompactSize` to increase its encoding length
        /// - the new input is the first segwit input added - this will add an additional 2WU to the
        ///   transaction weight to take into account the SegWit marker
        ///
        /// # Panics
        ///
        /// If the conversion overflows.
        fn segwit_weight(&self) -> Weight {
            Weight::from_vb(self.base_size().to_u64())
            .and_then(|w| w.checked_add(Weight::from_wu(self.witness.size().to_u64()))).unwrap()
        }

        /// Returns the base size of this input.
        ///
        /// Base size excludes the witness data (see [`Self::total_size`]).
        ///
        /// # Panics
        ///
        /// If the size calculation overflows.
        fn base_size(&self) -> usize {
            TxIn::base_size(self)
        }

        /// Returns the total number of bytes that this input contributes to a transaction.
        ///
        /// Total size includes the witness data (for base size see [`Self::base_size`]).
        ///
        /// # Panics
        ///
        /// If the size calculation overflows.
        fn total_size(&self) -> usize { TxIn::total_size(self) }
    }
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`TxOut`] type.
    pub trait TxOutExt impl for TxOut {
        /// The weight of this output.
        ///
        /// Keep in mind that when adding a [`TxOut`] to a [`Transaction`] the total weight of the
        /// transaction might increase more than `TxOut::weight`. This happens when the new output added
        /// causes the output length `CompactSize` to increase its encoding length.
        ///
        /// # Panics
        ///
        /// If output size * 4 overflows, this should never happen under normal conditions. Use
        /// `Weight::from_vb_checked(self.size() as u64)` if you are concerned.
        fn weight(&self) -> Weight {
            TxOut::weight(self)
        }

        /// Returns the total number of bytes that this output contributes to a transaction.
        ///
        /// There is no difference between base size vs total size for outputs.
        fn size(&self) -> usize { TxOut::size(self) }

        /// Constructs a new `TxOut` with given script and the smallest possible `value` that is **not** dust
        /// per current node policy.
        ///
        /// Dust depends on the `-dustrelayfee` value of the Tidecoin node you are broadcasting to.
        /// This function uses the default value of 0.00003 TDC/kB (3 tidoshi/vByte).
        ///
        /// To use a custom value, use [`minimal_non_dust_custom`].
        ///
        /// [`minimal_non_dust_custom`]: TxOut::minimal_non_dust_custom
        fn minimal_non_dust(script_pubkey: ScriptPubKeyBuf) -> Self {
            TxOut { amount: script_pubkey.minimal_non_dust(), script_pubkey }
        }

        /// Constructs a new `TxOut` with given script and the smallest possible `amount` that is **not** dust
        /// per current node policy.
        ///
        /// Dust depends on the `-dustrelayfee` value of the Tidecoin node you are broadcasting to.
        /// This function lets you set the fee rate used in dust calculation.
        ///
        /// The current default value in Tidecoin node policy is 3 tidoshi/vByte.
        ///
        /// To use the default Tidecoin node value, use [`minimal_non_dust`].
        ///
        /// [`minimal_non_dust`]: TxOut::minimal_non_dust
        fn minimal_non_dust_custom(script_pubkey: ScriptPubKeyBuf, dust_relay_fee: FeeRate) -> Option<Self>
        where
            Self: Sized
        {
            Some(TxOut { amount: script_pubkey.minimal_non_dust_custom(dust_relay_fee)?, script_pubkey })
        }
    }
}

/// Extension functionality for the [`Transaction`] type.
pub trait TransactionExt: sealed::Sealed {
    /// Returns the Tidecoin consensus weight of this transaction.
    ///
    /// > Transaction weight is defined as Base transaction size * 3 + Total transaction size (ie.
    /// > the same method as calculating Block weight from Base size and Total size).
    ///
    /// For transactions with an empty witness, this is simply the consensus-serialized size times
    /// four. For transactions with a witness, this is the non-witness consensus-serialized size
    /// multiplied by three plus the with-witness consensus-serialized size.
    ///
    /// For transactions with no inputs, this function will return a value 2 less than the actual
    /// weight of the serialized transaction. The reason is that zero-input transactions, post-SegWit,
    /// cannot be unambiguously serialized; we make a choice that adds two extra bytes. For more
    /// details see the [`Transaction`] serialization notes.
    /// which uses a "input count" of `0x00` as a `marker` for a SegWit-encoded transaction.
    ///
    /// If you need to model 0-input unsigned transactions, use a transaction-construction format
    /// that stores unsigned transactions without witness serialization. The live Rust API does not
    /// expose a full PSBT implementation.
    fn weight(&self) -> Weight;

    /// Returns the base transaction size.
    ///
    /// > Base transaction size is the size of the transaction serialized with the witness data stripped.
    ///
    /// # Panics
    ///
    /// If the size calculation overflows.
    fn base_size(&self) -> usize;

    /// Returns the total transaction size.
    ///
    /// > Total transaction size is the transaction size in bytes serialized with witness data,
    /// > including base data and witness data.
    ///
    /// # Panics
    ///
    /// If the size calculation overflows.
    fn total_size(&self) -> usize;

    /// Returns the "virtual size" (vsize) of this transaction.
    ///
    /// Will be `ceil(weight / 4.0)`. This is the virtual-size convention used
    /// by this library. A standardness-rule-correct version is available in the
    /// [`policy`] module.
    ///
    /// > Virtual transaction size is defined as Transaction weight / 4 (rounded up to the next integer).
    ///
    /// [`policy`]: crate::policy
    fn vsize(&self) -> usize;

    /// Returns `true` if the transaction itself signaled replaceability.
    ///
    /// # Warning
    ///
    /// **Incorrectly relying on RBF may lead to monetary loss!**
    ///
    /// This **does not** cover the case where a transaction becomes replaceable due to ancestors
    /// being RBF. Please note that transactions **may be replaced** even if they **do not** include
    /// the RBF signal.
    fn is_explicitly_rbf(&self) -> bool;

    /// Returns true if this [`Transaction`]'s absolute timelock is satisfied at `height`/`time`.
    ///
    /// # Returns
    ///
    /// By definition if the lock time is not enabled the transaction's absolute timelock is
    /// considered to be satisfied i.e., there are no timelock constraints restricting this
    /// transaction from being mined immediately.
    fn is_absolute_timelock_satisfied(&self, height: Height, time: MedianTimePast) -> bool;

    /// Returns `true` if this transaction's `nLockTime` is enabled.
    fn is_lock_time_enabled(&self) -> bool;

    /// Returns an iterator over lengths of `script_pubkey`s in the outputs.
    ///
    /// This is useful in combination with [`predict_weight`] if you have the transaction already
    /// constructed with a dummy value in the fee output which you'll adjust after calculating the
    /// weight.
    fn script_pubkey_lens(&self) -> TxOutToScriptPubkeyLengthIter<'_>;

    /// Counts the total number of sigops.
    ///
    /// This value is for the script forms recognized by Tidecoin's transaction
    /// and witness rules, including active v1-512. For historical/candidate rules
    /// use [`Self::total_sigop_cost_with_flags`].
    ///
    /// The `spent` parameter is a closure/function that looks up the output being spent by each input
    /// It takes in an [`OutPoint`] and returns a [`TxOut`]. If you can't provide this, a placeholder of
    /// `|_| None` can be used. Without access to the previous [`TxOut`], any sigops in a redeemScript (P2SH)
    /// as well as any SegWit sigops will not be counted for that input.
    fn total_sigop_cost<S>(&self, spent: S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>;

    /// Counts sigop cost under explicit candidate verification flags.
    /// Unlike [`Self::total_sigop_cost`], this can represent preactivation rules.
    /// Missing previous outputs contribute no P2SH/witness count.
    fn total_sigop_cost_with_flags<S>(&self, spent: S, flags: u32) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>;

    /// Returns a reference to the input at `input_index` if it exists.
    fn tx_in(&self, input_index: usize) -> Result<&TxIn, InputsIndexError>;

    /// Returns a reference to the output at `output_index` if it exists.
    fn tx_out(&self, output_index: usize) -> Result<&TxOut, OutputsIndexError>;
}

impl TransactionExt for Transaction {
    #[inline]
    fn weight(&self) -> Weight {
        let tx: &Self = self;
        tx.weight()
    }

    fn base_size(&self) -> usize {
        let tx: &Self = self;
        tx.base_size()
    }

    #[inline]
    fn total_size(&self) -> usize {
        let tx: &Self = self;
        tx.total_size()
    }

    #[inline]
    fn vsize(&self) -> usize {
        let tx: &Self = self;
        tx.vsize()
    }

    fn is_explicitly_rbf(&self) -> bool {
        self.inputs.iter().any(|input| input.sequence.is_rbf())
    }

    fn is_absolute_timelock_satisfied(&self, height: Height, time: MedianTimePast) -> bool {
        if !self.is_lock_time_enabled() {
            return true;
        }
        self.lock_time.is_satisfied_by(height, time)
    }

    fn is_lock_time_enabled(&self) -> bool {
        self.inputs.iter().any(|i| i.enables_lock_time())
    }

    fn script_pubkey_lens(&self) -> TxOutToScriptPubkeyLengthIter<'_> {
        TxOutToScriptPubkeyLengthIter { inner: self.outputs.iter() }
    }

    fn total_sigop_cost<S>(&self, spent: S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        self.total_sigop_cost_with_flags(spent, consensus_core::VERIFY_ALL_TIDECOIN)
    }

    fn total_sigop_cost_with_flags<S>(&self, mut spent: S, flags: u32) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        let mut cost = self.count_p2pk_p2pkh_sigops().saturating_mul(4);
        if self.is_coinbase() {
            return cost;
        }
        if flags & consensus_core::VERIFY_P2SH != 0 {
            cost = cost.saturating_add(self.count_p2sh_sigops(&mut spent).saturating_mul(4));
        }
        if flags & consensus_core::VERIFY_WITNESS != 0 {
            cost = cost.saturating_add(self.count_witness_sigops(spent, flags));
        }
        cost
    }

    #[inline]
    fn tx_in(&self, input_index: usize) -> Result<&TxIn, InputsIndexError> {
        self.inputs
            .get(input_index)
            .ok_or(IndexOutOfBoundsError { index: input_index, length: self.inputs.len() }.into())
    }

    #[inline]
    fn tx_out(&self, output_index: usize) -> Result<&TxOut, OutputsIndexError> {
        self.outputs
            .get(output_index)
            .ok_or(IndexOutOfBoundsError { index: output_index, length: self.outputs.len() }.into())
    }
}

/// Iterates over transaction outputs and for each output yields the length of the scriptPubkey.
// This exists to hardcode the type of the closure created by `map`.
pub struct TxOutToScriptPubkeyLengthIter<'a> {
    inner: core::slice::Iter<'a, TxOut>,
}

impl Iterator for TxOutToScriptPubkeyLengthIter<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        self.inner.next().map(|txout| txout.script_pubkey.len())
    }
}

trait TransactionExtPriv {
    /// Gets the sigop count.
    ///
    /// Counts sigops for this transaction's input scriptSigs and output scriptPubkeys i.e., doesn't
    /// count sigops in the redeemScript for p2sh or the sigops in the witness (use
    /// `count_p2sh_sigops` and `count_witness_sigops` respectively).
    fn count_p2pk_p2pkh_sigops(&self) -> usize;

    /// Does not include wrapped SegWit (see `count_witness_sigops`).
    fn count_p2sh_sigops<S>(&self, spent: S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>;

    /// Includes wrapped SegWit and returns 0 for unsupported witness-v1 forms.
    fn count_witness_sigops<S>(&self, spent: S, flags: u32) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>;
}

impl TransactionExtPriv for Transaction {
    /// Gets the sigop count.
    fn count_p2pk_p2pkh_sigops(&self) -> usize {
        let mut count: usize = 0;
        for input in &self.inputs {
            // 0 for p2wpkh, p2wsh, and p2sh (including wrapped SegWit).
            count = count.saturating_add(input.script_sig.count_sigops_legacy());
        }
        for output in &self.outputs {
            count = count.saturating_add(output.script_pubkey.count_sigops_legacy());
        }
        count
    }

    /// Does not include wrapped SegWit (see `count_witness_sigops`).
    fn count_p2sh_sigops<S>(&self, mut spent: S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        fn count_sigops(prevout: &TxOut, input: &TxIn) -> usize {
            let mut count: usize = 0;
            if prevout.script_pubkey.is_p2sh() && input.script_sig.is_push_only() {
                if let Some(redeem) = input.script_sig.last_pushdata() {
                    count = count
                        .saturating_add(RedeemScript::from_bytes(redeem.as_bytes()).count_sigops());
                }
            }
            count
        }

        let mut count: usize = 0;
        for input in &self.inputs {
            if let Some(prevout) = spent(&input.previous_output) {
                count = count.saturating_add(count_sigops(&prevout, input));
            }
        }
        count
    }

    /// Includes wrapped SegWit and returns 0 for unsupported witness-v1 forms.
    fn count_witness_sigops<S>(&self, mut spent: S, flags: u32) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        fn count_sigops_with_witness_program(
            witness: &Witness,
            witness_program: &ScriptPubKey,
            flags: u32,
        ) -> usize {
            if consensus_core::WitnessProgram::parse_for_flags(witness_program.as_bytes(), flags)
                .is_none()
            {
                return 0;
            }
            if witness_program.is_p2wpkh() {
                1
            } else if witness_program.is_p2wsh() || witness_program.is_p2wsh512() {
                // Treat the last item of the witness as the witnessScript
                witness.last().map(WitnessScript::from_bytes).map(|s| s.count_sigops()).unwrap_or(0)
            } else {
                0
            }
        }

        fn count_sigops(prevout: TxOut, input: &TxIn, flags: u32) -> usize {
            let script_sig = &input.script_sig;
            let witness = &input.witness;

            let witness_program = if prevout.script_pubkey.is_witness_program() {
                &prevout.script_pubkey
            } else if flags & consensus_core::VERIFY_P2SH != 0
                && prevout.script_pubkey.is_p2sh()
                && script_sig.is_push_only()
            {
                // If prevout is P2SH and scriptSig is push only
                // then we wrap the last push (redeemScript) in a Script; we use a ScriptPubKey to keep our types
                // consistent although strictly speaking it should
                // be a RedeemScript.
                if let Some(push_bytes) = script_sig.last_pushdata() {
                    ScriptPubKey::from_bytes(push_bytes.as_bytes())
                } else {
                    return 0;
                }
            } else {
                return 0;
            };

            // This will return 0 if the redeemScript wasn't a witness program
            if prevout.script_pubkey.is_p2sh() && witness_program.is_p2wsh512() {
                return 0;
            }
            count_sigops_with_witness_program(witness, witness_program, flags)
        }

        let mut count: usize = 0;
        for input in &self.inputs {
            if let Some(prevout) = spent(&input.previous_output) {
                count = count.saturating_add(count_sigops(prevout, input, flags));
            }
        }
        count
    }
}

/// Error attempting to do an out of bounds access on the transaction inputs vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputsIndexError(pub IndexOutOfBoundsError);

impl fmt::Display for InputsIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "invalid input index"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputsIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<IndexOutOfBoundsError> for InputsIndexError {
    fn from(e: IndexOutOfBoundsError) -> Self {
        Self(e)
    }
}

/// Error attempting to do an out of bounds access on the transaction outputs vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputsIndexError(pub IndexOutOfBoundsError);

impl fmt::Display for OutputsIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "invalid output index"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutputsIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<IndexOutOfBoundsError> for OutputsIndexError {
    fn from(e: IndexOutOfBoundsError) -> Self {
        Self(e)
    }
}

/// Error attempting to do an out of bounds access on a vector.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IndexOutOfBoundsError {
    /// Attempted index access.
    pub index: usize,
    /// Length of the vector where access was attempted.
    pub length: usize,
}

impl fmt::Display for IndexOutOfBoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "index {} is out-of-bounds for vector with length {}", self.index, self.length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IndexOutOfBoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Computes the value of an output accounting for the cost of spending it.
///
/// The effective value is the value of an output value minus the amount to spend it. That is, the
/// effective_value can be calculated as: value - (fee_rate * weight).
///
/// Note: the effective value of a [`Transaction`] may increase less than the effective value of
/// a [`TxOut`] when adding another [`TxOut`] to the transaction. This happens when the new
/// [`TxOut`] added causes the output length `CompactSize` to increase its encoding length.
///
/// # Parameters
///
/// * `fee_rate` - the fee rate of the transaction being created.
/// * `input_weight_prediction` - the predicted input weight.
/// * `value` - the value of the output we are spending.
pub fn effective_value(
    fee_rate: FeeRate,
    input_weight_prediction: InputWeightPrediction,
    value: Amount,
) -> SignedAmount {
    let weight = input_weight_prediction.total_weight();
    let fee = fee_rate.to_fee(weight);

    value.signed_sub(fee)
}

/// Predicts the weight of a to-be-constructed transaction.
///
/// This function computes the weight of a transaction which is not fully known. All that is needed
/// is the lengths of scripts and witness elements.
///
/// # Parameters
///
/// * `inputs` - an iterator which returns `InputWeightPrediction` for each input of the
///   to-be-constructed transaction.
/// * `output_script_lens` - an iterator which returns the length of `script_pubkey` of each output
///   of the to-be-constructed transaction.
///
/// Note that lengths of the scripts and witness elements must be non-serialized, IOW *without* the
/// length prefix. The length is computed and added inside the function for convenience.
///
/// If you have the transaction already constructed (except for signatures) with a dummy value for
/// fee output you can use the return value of [`Transaction::script_pubkey_lens`] method directly
/// as the second argument.
///
/// Include every prospective output, including change. Adding or removing change
/// can change the encoded output-count width as well as the output bytes. The
/// input and output counts are computed from the complete iterators.
///
/// This function calculates weight only. It does not select coins, adjust change
/// or recipient amounts, add ancestor fees, or enforce wallet transaction-weight
/// limits. Those require the caller's funding and chain context.
///
/// # Usage
///
/// When signing a transaction one doesn't know the signature before knowing the transaction fee and
/// the transaction fee is not known before knowing the transaction size which is not known before
/// knowing the signature. This apparent dependency cycle can be broken by knowing the length of the
/// signature without knowing the contents of the signature, for example when a signature scheme
/// has a fixed serialized size.
///
/// Additionally, some protocols may require calculating the amounts before knowing various parts
/// of the transaction (assuming their length is known).
///
/// # Notes on integer overflow
///
/// Overflows are intentionally not checked because one of the following holds:
///
/// * The transaction is valid (obeys the block size limit) and the code feeds correct values to
///   this function - no overflow can happen.
/// * The transaction will be so large it doesn't fit in the memory - overflow will happen but
///   then the transaction will fail to construct and even if one serialized it on disk directly
///   it'd be invalid anyway so overflow doesn't matter.
/// * The values fed into this function are inconsistent with the actual lengths the transaction
///   will have - the code is already broken and checking overflows doesn't help. Unfortunately
///   this probably cannot be avoided.
pub fn predict_weight<I, O>(inputs: I, output_script_lens: O) -> Weight
where
    I: IntoIterator<Item = InputWeightPrediction>,
    O: IntoIterator<Item = usize>,
{
    let (input_count, input_weight, inputs_with_witnesses) =
        inputs.into_iter().fold((0, 0, 0), |(count, weight, with_witnesses), prediction| {
            (
                count + 1,
                weight + prediction.total_weight().to_wu() as usize,
                with_witnesses + (prediction.witness_size > 0) as usize,
            )
        });

    let (output_count, output_scripts_size) =
        output_script_lens.into_iter().fold((0, 0), |(count, scripts_size), script_len| {
            (count + 1, scripts_size + script_len + CompactSizeEncoder::encoded_size(script_len))
        });

    predict_weight_internal(
        input_count,
        input_weight,
        inputs_with_witnesses,
        output_count,
        output_scripts_size,
    )
}

const fn predict_weight_internal(
    input_count: usize,
    input_weight: usize,
    inputs_with_witnesses: usize,
    output_count: usize,
    output_scripts_size: usize,
) -> Weight {
    // The value field of a TxOut is 8 bytes.
    let output_size = 8 * output_count + output_scripts_size;
    let non_input_size = 4 // version
        + CompactSizeEncoder::encoded_size(input_count) // Can't use ToU64 in const context.
        + CompactSizeEncoder::encoded_size(output_count)
        + output_size
        + 4; // locktime
    let weight = if inputs_with_witnesses == 0 {
        non_input_size * 4 + input_weight
    } else {
        non_input_size * 4 + input_weight + input_count - inputs_with_witnesses + 2
    };
    Weight::from_wu(weight as u64)
}

/// Predicts the weight of a to-be-constructed transaction in const context.
///
/// This is a `const` version of [`predict_weight`] which only allows slices due to current Rust
/// limitations around `const fn`. Because of these limitations it may be less efficient than
/// `predict_weight` and thus is intended to be only used in `const` context.
///
/// Please see the documentation of `predict_weight` to learn more about this function.
pub const fn predict_weight_from_slices(
    inputs: &[InputWeightPrediction],
    output_script_lens: &[usize],
) -> Weight {
    let mut input_weight = 0;
    let mut inputs_with_witnesses = 0;

    // for loops not supported in const fn
    let mut i = 0;
    while i < inputs.len() {
        let prediction = inputs[i];
        input_weight += prediction.total_weight().to_wu() as usize;
        inputs_with_witnesses += (prediction.witness_size > 0) as usize;
        i += 1;
    }

    let mut output_scripts_size = 0;

    i = 0;
    while i < output_script_lens.len() {
        let script_len = output_script_lens[i];
        output_scripts_size += script_len + CompactSizeEncoder::encoded_size(script_len);
        i += 1;
    }

    predict_weight_internal(
        inputs.len(),
        input_weight,
        inputs_with_witnesses,
        output_script_lens.len(),
        output_scripts_size,
    )
}

/// Weight prediction of an individual input.
///
/// This helper type collects information about an input to be used in [`predict_weight`] function.
/// It can only be created using the [`new`](InputWeightPrediction::new) function or using other
/// associated constants/methods.
///
/// PQ helpers without a mode retain maximum-size estimates. Use their `_with_mode`
/// variants with [`PqSignatureSize::LocalSigning`] only for signers that guarantee
/// the rc3 local bounds; use [`PqSignatureSize::Maximum`] otherwise. For mixed
/// inputs, choose a mode per input. This predicts size, not signing eligibility.
///
/// Aggregate inputs and outputs with [`predict_weight`] before rounding to virtual
/// bytes. For the node's nonnegative fee-rate calculation use
/// `fee_rate.mul_by_vsize(weight.to_vbytes_ceil())`; do not round each input's
/// virtual size separately. Relay sigop adjustments, when applicable, use
/// [`crate::policy::get_virtual_tx_size`]. A completed transaction should use its
/// actual serialized weight instead of a dummy-signature prediction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputWeightPrediction {
    script_size: u32,
    witness_size: u32,
}

impl InputWeightPrediction {
    /// Largest known PQ P2WPKH spend proxy used by Tidecoin node policy.
    pub const MAX_KNOWN_PQ_P2WPKH: Self = Self::pq_p2wpkh(PqScheme::MlDsa87);

    /// Largest known PQ P2SH-P2WPKH spend proxy used by Tidecoin node policy.
    pub const MAX_KNOWN_PQ_NESTED_P2WPKH: Self = Self::pq_nested_p2wpkh(PqScheme::MlDsa87);

    /// Largest known non-witness PQ key-spend scriptSig proxy used by Tidecoin node policy.
    pub const MAX_KNOWN_PQ_NON_WITNESS_KEY_SPEND: Self =
        Self::pq_non_witness_key_spend(PqScheme::MlDsa87);

    /// Largest known PQ witness-script key-spend proxy used by Tidecoin node policy.
    pub const MAX_KNOWN_PQ_WITNESS_SCRIPT_KEY_SPEND: Self =
        Self::pq_witness_script_key_spend(PqScheme::MlDsa87);

    /// Tidecoin node dust-policy non-witness input script-size proxy for the largest known PQ
    /// scheme.
    ///
    /// This is a relay-policy estimate, not canonical transaction encoding size. It mirrors the
    /// Tidecoin node's dust threshold calculation, which uses a one-byte script length component in
    /// the non-witness spend proxy.
    pub const MAX_KNOWN_PQ_NON_WITNESS_DUST_SCRIPT_SIG_SIZE: usize =
        Self::pq_non_witness_dust_script_sig_size(PqScheme::MlDsa87);

    const fn saturate_to_u32(x: usize) -> u32 {
        if x > u32::MAX as usize {
            u32::MAX
        } else {
            x as u32 //cast ok, condition prevents larger than u32::MAX.
        }
    }

    const fn compact_size_len_u32(value: usize) -> u32 {
        Self::saturate_to_u32(CompactSizeEncoder::encoded_size(value))
    }

    /// Serialized script length for a canonical push of `payload_size` bytes.
    pub const fn script_push_len(payload_size: usize) -> usize {
        if payload_size < 0x4c {
            1 + payload_size
        } else if payload_size <= u8::MAX as usize {
            2 + payload_size
        } else if payload_size <= u16::MAX as usize {
            3 + payload_size
        } else {
            5 + payload_size
        }
    }

    const fn pq_p2wpkh_for_sizes(sig_len: usize, pubkey_len: usize) -> Self {
        Self::from_slice(0, &[sig_len, pubkey_len])
    }

    const fn pq_nested_p2wpkh_for_sizes(sig_len: usize, pubkey_len: usize) -> Self {
        // 0x00 0x14 <20-byte keyhash>, pushed as the redeem script.
        Self::from_slice(Self::script_push_len(22), &[sig_len, pubkey_len])
    }

    const fn pq_script_sig_len(sig_len: usize, pubkey_len: usize) -> usize {
        CompactSizeEncoder::encoded_size(sig_len)
            + sig_len
            + CompactSizeEncoder::encoded_size(pubkey_len)
            + pubkey_len
    }

    /// Maximum-size prediction for a native PQ P2WPKH spend.
    /// See [`Self::pq_p2wpkh_with_mode`] for the smaller local-signing bound.
    pub const fn pq_p2wpkh(scheme: PqScheme) -> Self {
        Self::pq_p2wpkh_with_mode(scheme, PqSignatureSize::Maximum)
    }

    /// Native PQ P2WPKH prediction using the selected node dummy-signature mode.
    pub const fn pq_p2wpkh_with_mode(scheme: PqScheme, mode: PqSignatureSize) -> Self {
        Self::pq_p2wpkh_for_sizes(
            mode.signature_len_in_script(Some(scheme)),
            scheme.prefixed_pubkey_len(),
        )
    }

    /// Maximum-size prediction for a P2SH-wrapped PQ P2WPKH spend.
    /// See [`Self::pq_nested_p2wpkh_with_mode`] for the local-signing bound.
    pub const fn pq_nested_p2wpkh(scheme: PqScheme) -> Self {
        Self::pq_nested_p2wpkh_with_mode(scheme, PqSignatureSize::Maximum)
    }

    /// Wrapped PQ P2WPKH prediction using the selected node dummy-signature mode.
    pub const fn pq_nested_p2wpkh_with_mode(scheme: PqScheme, mode: PqSignatureSize) -> Self {
        Self::pq_nested_p2wpkh_for_sizes(
            mode.signature_len_in_script(Some(scheme)),
            scheme.prefixed_pubkey_len(),
        )
    }

    /// Input prediction for a native P2WPKH spend with explicit PQ signature
    /// and public-key sizes.
    pub const fn pq_p2wpkh_with_sizes(sig_len: usize, pubkey_len: usize) -> Self {
        Self::pq_p2wpkh_for_sizes(sig_len, pubkey_len)
    }

    /// Input prediction for a P2SH-wrapped P2WPKH spend with explicit PQ
    /// signature and public-key sizes.
    pub const fn pq_nested_p2wpkh_with_sizes(sig_len: usize, pubkey_len: usize) -> Self {
        Self::pq_nested_p2wpkh_for_sizes(sig_len, pubkey_len)
    }

    /// Input prediction for a non-witness PQ key spend.
    ///
    /// Tidecoin node dust policy uses this as the conservative non-witness spend proxy for
    /// P2PK, P2PKH, P2SH, and other non-witness script forms.
    pub const fn pq_non_witness_key_spend(scheme: PqScheme) -> Self {
        Self::pq_non_witness_key_spend_with_mode(scheme, PqSignatureSize::Maximum)
    }

    /// PQ P2PKH prediction using the selected node dummy-signature mode.
    /// This is a signature-and-public-key spend, not arbitrary P2SH satisfaction.
    pub const fn pq_non_witness_key_spend_with_mode(
        scheme: PqScheme,
        mode: PqSignatureSize,
    ) -> Self {
        Self::from_slice(
            Self::script_push_len(mode.signature_len_in_script(Some(scheme)))
                + Self::script_push_len(scheme.prefixed_pubkey_len()),
            &[],
        )
    }

    /// Tidecoin node dust-policy non-witness input script-size proxy for `scheme`.
    ///
    /// Use this only for node relay-policy dust estimation. Canonical transaction weight and size
    /// calculations should use [`InputWeightPrediction::pq_non_witness_key_spend`] instead.
    pub const fn pq_non_witness_dust_script_sig_size(scheme: PqScheme) -> usize {
        1 + Self::pq_script_sig_len(scheme.max_sig_len_in_script(), scheme.prefixed_pubkey_len())
    }

    /// Input prediction for a P2WSH/P2WSH-512 PQ witness-script key spend.
    ///
    /// The witness script is `<prefixed-pq-pubkey> OP_CHECKSIG`, matching the Tidecoin node policy
    /// proxy for standard script-hash witness outputs.
    pub const fn pq_witness_script_key_spend(scheme: PqScheme) -> Self {
        Self::pq_witness_script_key_spend_with_mode(scheme, PqSignatureSize::Maximum)
    }

    /// Native P2WSH/P2WSH-512 key-spend prediction using the selected dummy mode.
    /// Estimates size only; witness-v1 still requires the active native context.
    pub const fn pq_witness_script_key_spend_with_mode(
        scheme: PqScheme,
        mode: PqSignatureSize,
    ) -> Self {
        let witness_script_len = Self::script_push_len(scheme.prefixed_pubkey_len()) + 1;
        Self::from_slice(0, &[mode.signature_len_in_script(Some(scheme)), witness_script_len])
    }

    /// Computes the prediction for a single input.
    pub fn new<T>(input_script_len: usize, witness_element_lengths: T) -> Self
    where
        T: IntoIterator,
        T::Item: Borrow<usize>,
    {
        let (count, total_size) = witness_element_lengths.into_iter().fold(
            (0usize, 0u32),
            |(count, total_size), elem_len| {
                let elem_len = *elem_len.borrow();
                let elem_size = Self::saturate_to_u32(elem_len)
                    .saturating_add(Self::compact_size_len_u32(elem_len));
                (count + 1, total_size.saturating_add(elem_size))
            },
        );
        let witness_size =
            if count > 0 { total_size + Self::compact_size_len_u32(count) } else { 0 };
        let script_size =
            Self::saturate_to_u32(input_script_len) + Self::compact_size_len_u32(input_script_len);

        Self { script_size, witness_size }
    }

    /// Computes the prediction for a single input in `const` context.
    ///
    /// This is a `const` version of [`new`](Self::new) which only allows slices due to current Rust
    /// limitations around `const fn`. Because of these limitations it may be less efficient than
    /// `new` and thus is intended to be only used in `const` context.
    pub const fn from_slice(input_script_len: usize, witness_element_lengths: &[usize]) -> Self {
        let mut i = 0;
        let mut total_size: u32 = 0;
        // for loops not supported in const fn
        while i < witness_element_lengths.len() {
            let elem_len = witness_element_lengths[i];
            let elem_size = Self::saturate_to_u32(elem_len)
                .saturating_add(Self::compact_size_len_u32(elem_len));
            total_size = total_size.saturating_add(elem_size);
            i += 1;
        }
        let witness_size = if !witness_element_lengths.is_empty() {
            total_size.saturating_add(Self::compact_size_len_u32(witness_element_lengths.len()))
        } else {
            0
        };
        let script_size = Self::saturate_to_u32(input_script_len)
            .saturating_add(Self::compact_size_len_u32(input_script_len));

        Self { script_size, witness_size }
    }

    /// Encoded scriptSig byte count, including the CompactSize script length prefix.
    pub const fn script_sig_size(&self) -> usize {
        self.script_size as usize
    }

    /// Encoded witness stack byte count, including the CompactSize stack count and element length
    /// prefixes. This excludes the transaction-level witness marker and flag bytes.
    pub const fn witness_stack_size(&self) -> usize {
        self.witness_size as usize
    }

    /// Computes the signature, prevout (txid, index), and sequence weights of this weight
    /// prediction.
    ///
    /// A non-witness prediction excludes the empty witness-stack byte. When a
    /// transaction mixes legacy and witness inputs, [`predict_weight`] adds that
    /// byte for each legacy input. This differs from the node's explicit wallet
    /// input-weight budget convention, which always includes it.
    ///
    /// This function's internal arithmetic saturates at u32::MAX, so the return value of this
    /// function may be inaccurate for extremely large witness predictions.
    ///
    /// See also [`InputWeightPrediction::witness_weight`]
    pub const fn total_weight(&self) -> Weight {
        // `impl const Trait` is currently unavailable: rust/issues/67792
        // Convert to u64s because we can't use `Add` in const context.
        let weight = TX_IN_BASE_WEIGHT.to_wu() + Self::witness_weight(self).to_wu();
        Weight::from_wu(weight)
    }

    /// Computes the **signature weight** added to a transaction by an input with this weight prediction,
    /// not counting the prevout (txid, index), sequence, potential witness flag bytes or the witness count.
    ///
    /// This function's internal arithmetic saturates at u32::MAX, so the return value of this
    /// function may be inaccurate for extremely large witness predictions.
    ///
    /// See also [`InputWeightPrediction::total_weight`]
    pub const fn witness_weight(&self) -> Weight {
        let wu = self.script_size * 4 + self.witness_size;
        let wu = const_casts::u32_to_u64(wu);
        Weight::from_wu(wu)
    }
}

/// An owned wrapper for the coinbase transaction of a block.
///
/// This type distinguishes coinbase transactions from regular ones at the type level.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Coinbase(Transaction);

/// A borrowed view of a coinbase transaction, without copying its inputs or outputs.
///
/// The view cannot outlive its transaction:
/// ```compile_fail
/// use tidecoin::transaction::{CoinbaseRef, Transaction};
/// fn invalid_view(tx: Transaction) -> CoinbaseRef<'static> {
///     CoinbaseRef::assume_coinbase(&tx)
/// }
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct CoinbaseRef<'a>(&'a Transaction);

impl Coinbase {
    /// Wraps a transaction without checking whether it is a valid coinbase.
    ///
    /// The caller must ensure that it is a valid coinbase transaction.
    pub fn assume_coinbase(tx: Transaction) -> Self {
        Self(tx)
    }

    /// Borrows this coinbase without copying the transaction.
    pub const fn as_coinbase_ref(&self) -> CoinbaseRef<'_> {
        CoinbaseRef::assume_coinbase(&self.0)
    }

    /// Returns the first input. Panics if the assumed coinbase has no inputs.
    pub fn first_input(&self) -> &TxIn {
        self.as_coinbase_ref().first_input()
    }

    /// Returns the underlying transaction, whose input contains a dummy prevout.
    #[doc(alias = "as_inner")]
    pub fn as_transaction(&self) -> &Transaction {
        self.as_coinbase_ref().as_transaction()
    }

    /// Returns the underlying transaction, whose input contains a dummy prevout.
    #[doc(alias = "into_inner")]
    pub fn into_transaction(self) -> Transaction {
        self.0
    }

    /// Computes the [`Txid`] of this coinbase transaction.
    pub fn compute_txid(&self) -> Txid {
        self.as_coinbase_ref().compute_txid()
    }

    /// Returns [`Wtxid::COINBASE`], as required for coinbase transactions.
    #[doc(alias = "compute_wtxid")]
    pub const fn wtxid(&self) -> Wtxid {
        self.as_coinbase_ref().wtxid()
    }
}

impl<'a> CoinbaseRef<'a> {
    /// Borrows a transaction without checking whether it is a valid coinbase.
    ///
    /// The caller must ensure that it is a valid coinbase transaction.
    pub const fn assume_coinbase(tx: &'a Transaction) -> Self {
        Self(tx)
    }

    /// Returns the first input. Panics if the assumed coinbase has no inputs.
    pub fn first_input(self) -> &'a TxIn {
        &self.0.inputs[0]
    }

    /// Returns the underlying transaction, whose input contains a dummy prevout.
    #[doc(alias = "as_inner")]
    pub const fn as_transaction(self) -> &'a Transaction {
        self.0
    }

    /// Computes the [`Txid`] of this coinbase transaction.
    pub fn compute_txid(self) -> Txid {
        self.0.compute_txid()
    }

    /// Returns [`Wtxid::COINBASE`], as required for coinbase transactions.
    #[doc(alias = "compute_wtxid")]
    pub const fn wtxid(self) -> Wtxid {
        Wtxid::COINBASE
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Transaction {}
    impl Sealed for super::Txid {}
    impl Sealed for super::Wtxid {}
    impl Sealed for super::OutPoint {}
    impl Sealed for super::TxIn {}
    impl Sealed for super::TxOut {}
    impl Sealed for super::Version {}
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for InputWeightPrediction {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=5)? {
            0 => Ok(Self::pq_p2wpkh(PqScheme::Falcon512)),
            1 => Ok(Self::pq_p2wpkh(PqScheme::MlDsa87)),
            2 => Ok(Self::pq_nested_p2wpkh(PqScheme::MlDsa87)),
            3 => Ok(Self::pq_non_witness_key_spend(PqScheme::MlDsa87)),
            4 => {
                let input_script_len = usize::arbitrary(u)?;
                let witness_element_lengths: Vec<usize> = Vec::arbitrary(u)?;
                Ok(Self::new(input_script_len, witness_element_lengths))
            }
            _ => {
                let input_script_len = usize::arbitrary(u)?;
                let witness_element_lengths: Vec<usize> = Vec::arbitrary(u)?;
                Ok(Self::from_slice(input_script_len, &witness_element_lengths))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use internals::hex_lit as hex;

    use super::*;
    use crate::constants::WITNESS_SCALE_FACTOR;
    use crate::script::ScriptBufExt as _;
    use crate::script::ScriptSigBuf;
    use crate::{hex, parse_int, TxSighashType};

    fn synthetic_witness(tag: u8, lens: &[usize]) -> Witness {
        let mut witness = Witness::new();
        for (idx, len) in lens.iter().copied().enumerate() {
            witness.push(vec![tag.wrapping_add(idx as u8); len]);
        }
        witness
    }

    fn synthetic_txin(tag: u8, script_len: usize, witness_lens: &[usize]) -> TxIn {
        TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: tag.into() },
            script_sig: ScriptSigBuf::from_bytes(vec![tag; script_len]),
            sequence: Sequence::MAX,
            witness: synthetic_witness(tag, witness_lens),
        }
    }

    fn synthetic_txout(tag: u8, script_len: usize) -> TxOut {
        TxOut {
            amount: Amount::from_sat_u32(tag.into()),
            script_pubkey: ScriptPubKeyBuf::from_bytes(vec![tag; script_len]),
        }
    }

    fn synthetic_transaction(segwit: bool) -> Transaction {
        let witness_lens: &[usize] = if segwit {
            &[
                PqScheme::Falcon512.max_sig_len_in_script(),
                PqScheme::Falcon512.prefixed_pubkey_len(),
            ]
        } else {
            &[]
        };
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![synthetic_txin(0x21, 3, witness_lens)],
            outputs: vec![synthetic_txout(0x31, 3)],
        }
    }

    #[test]
    fn encode_transaction_roundtrip() {
        let mut buf = [0u8; 1024];
        let tx = synthetic_transaction(false);
        let raw_tx = encoding::encode_to_vec(&tx);

        let encoded = encoding::encode_to_vec(&tx);
        let size = encoded.len();
        buf[..size].copy_from_slice(&encoded);
        assert_eq!(size, raw_tx.len());
        assert_eq!(raw_tx.as_slice(), &buf[..size]);
    }

    #[test]
    fn outpoint() {
        assert_eq!("i don't care".parse::<OutPoint>(), Err(ParseOutPointError::Format));
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:1:1"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:".parse::<OutPoint>(),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:11111111111"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::TooLong)
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:01"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::VoutNotCanonical)
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:+42"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::VoutNotCanonical)
        );
        assert_eq!(
            "i don't care:1".parse::<OutPoint>(),
            Err(ParseOutPointError::Txid("i don't care".parse::<Txid>().unwrap_err()))
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X:1"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::Txid(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X"
                    .parse::<Txid>()
                    .unwrap_err()
            ))
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:lol"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::Vout(parse_int::int_from_str::<u32>("lol").unwrap_err()))
        );

        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:42"
                .parse::<OutPoint>(),
            Ok(OutPoint {
                txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                    .parse()
                    .unwrap(),
                vout: 42,
            })
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0"
                .parse::<OutPoint>(),
            Ok(OutPoint {
                txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                    .parse()
                    .unwrap(),
                vout: 0,
            })
        );
    }

    #[test]
    fn txin() {
        let original = synthetic_txin(0xA1, 3, &[]);
        let encoded = encoding::encode_to_vec(&original);
        let txin: TxIn = encoding::decode_from_slice(&encoded).unwrap();
        assert_eq!(txin, original);
    }

    #[test]
    fn is_coinbase() {
        use crate::constants;
        use crate::network::Network;

        let genesis = constants::genesis_block(Network::Tidecoin);
        assert!(genesis.transactions()[0].is_coinbase());
        let tx = synthetic_transaction(false);
        assert!(!tx.is_coinbase());
    }

    #[test]
    fn nonsegwit_transaction() {
        let original = synthetic_transaction(false);
        let tx_bytes = encoding::encode_to_vec(&original);
        let tx: Result<Transaction, _> = encoding::decode_from_slice(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        assert_eq!(realtx, original);
        assert_eq!(realtx.version, Version::TWO);
        assert_eq!(realtx.inputs.len(), 1);
        assert_eq!(realtx.inputs[0].previous_output.txid, Txid::from_byte_array([0x21; 32]));
        assert_eq!(realtx.inputs[0].previous_output.vout, 0x21);
        assert_eq!(realtx.outputs.len(), 1);
        assert_eq!(realtx.lock_time, absolute::LockTime::ZERO);

        assert_eq!(realtx.compute_txid().to_byte_array(), realtx.compute_wtxid().to_byte_array());
        assert_eq!(realtx.weight().to_wu() as usize, tx_bytes.len() * WITNESS_SCALE_FACTOR);
        assert_eq!(realtx.total_size(), tx_bytes.len());
        assert_eq!(realtx.vsize(), tx_bytes.len());
        assert_eq!(realtx.base_size(), tx_bytes.len());
    }

    #[test]
    fn segwit_invalid_transaction() {
        let tx_bytes = hex!("0000fd000001021921212121212121212121f8b372b0239cc1dff600000000004f4f4f4f4f4f4f4f000000000000000000000000000000333732343133380d000000000000000000000000000000ff000000000009000dff000000000000000800000000000000000d");
        let tx: Result<Transaction, _> = encoding::decode_from_slice(&tx_bytes);
        assert!(tx.is_err());
        assert!(matches!(tx.unwrap_err(), encoding::DecodeError::Parse(_)));
    }

    #[test]
    fn segwit_transaction() {
        let original = synthetic_transaction(true);
        let tx_bytes = encoding::encode_to_vec(&original);
        let tx: Result<Transaction, _> = encoding::decode_from_slice(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        assert_eq!(realtx, original);
        assert_eq!(realtx.version, Version::TWO);
        assert_eq!(realtx.inputs.len(), 1);
        assert_eq!(realtx.inputs[0].previous_output.txid, Txid::from_byte_array([0x21; 32]));
        assert_eq!(realtx.inputs[0].previous_output.vout, 0x21);
        assert_eq!(realtx.outputs.len(), 1);
        assert_eq!(realtx.lock_time, absolute::LockTime::ZERO);

        assert_ne!(realtx.compute_txid().to_byte_array(), realtx.compute_wtxid().to_byte_array());
        assert_eq!(realtx.weight(), original.weight());
        assert_eq!(realtx.total_size(), tx_bytes.len());

        let expected_strippedsize = (realtx.weight().to_wu() as usize - realtx.total_size()) / 3;
        assert_eq!(realtx.base_size(), expected_strippedsize);

        // Construct a transaction without the witness data.
        let mut tx_without_witness = realtx;
        tx_without_witness.inputs.iter_mut().for_each(|input| input.witness.clear());
        assert_eq!(tx_without_witness.total_size(), tx_without_witness.base_size());
        assert_eq!(tx_without_witness.total_size(), expected_strippedsize);
    }

    // We temporarily abuse `Transaction` for testing consensus serde adapter.
    #[test]
    #[cfg(feature = "serde")]
    fn consensus_serde() {
        use primitives::serde_as_consensus as con_serde;
        let json = "\"010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3603da1b0e00045503bd5704c7dd8a0d0ced13bb5785010800000000000a636b706f6f6c122f4e696e6a61506f6f6c2f5345475749542fffffffff02b4e5a212000000001976a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac0000000000000000266a24aa21a9edf91c46b49eb8a29089980f02ee6b57e7d63d33b18b4fddac2bcd7db2a39837040120000000000000000000000000000000000000000000000000000000000000000000000000\"";
        let mut deserializer = serde_json::Deserializer::from_str(json);
        let tx: Transaction = con_serde::deserialize(&mut deserializer).unwrap();
        let tx_bytes = hex::decode_to_vec(&json[1..(json.len() - 1)]).unwrap();
        let expected = encoding::decode_from_slice::<Transaction>(&tx_bytes).unwrap();
        assert_eq!(tx, expected);
        let mut bytes = alloc::vec::Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut bytes);
        con_serde::serialize(&tx, &mut serializer).unwrap();
        assert_eq!(bytes, json.as_bytes())
    }

    #[test]
    fn transaction_version() {
        let original = Transaction {
            version: Version::maybe_non_standard(u32::MAX),
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![synthetic_txin(0x41, 0, &[])],
            outputs: vec![synthetic_txout(0x42, 0)],
        };
        let tx_bytes = encoding::encode_to_vec(&original);
        let tx: Result<Transaction, _> = encoding::decode_from_slice(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        assert_eq!(realtx.version, Version::maybe_non_standard(u32::MAX));
        assert_eq!(realtx, original);
    }

    #[test]
    fn tx_no_input_deserialization() {
        let tx_bytes = hex!(
            "010000000001000100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000"
        );
        let err = encoding::decode_from_slice::<Transaction>(&tx_bytes)
            .expect_err("zero-input transaction should be rejected");

        assert!(format!("{err:?}").contains("NoInputs"));
    }

    #[test]
    fn ntxid() {
        let mut tx = synthetic_transaction(false);

        let old_ntxid = tx.compute_ntxid();
        // changing sigs does not affect it
        tx.inputs[0].script_sig = ScriptSigBuf::new();
        assert_eq!(old_ntxid, tx.compute_ntxid());
        // changing pks does
        tx.outputs[0].script_pubkey = ScriptPubKeyBuf::new();
        assert!(old_ntxid != tx.compute_ntxid());
    }

    #[test]
    fn txid() {
        let tx = synthetic_transaction(true);
        let decoded: Transaction =
            encoding::decode_from_slice(&encoding::encode_to_vec(&tx)).unwrap();

        assert_eq!(decoded, tx);
        assert_ne!(decoded.compute_txid().to_byte_array(), decoded.compute_wtxid().to_byte_array());
        assert_eq!(format!("{:.10x}", decoded.compute_txid()).len(), 10);
        assert_eq!(decoded.weight(), tx.weight());

        let tx = synthetic_transaction(false);
        let decoded: Transaction =
            encoding::decode_from_slice(&encoding::encode_to_vec(&tx)).unwrap();

        assert_eq!(decoded, tx);
        assert_eq!(decoded.compute_txid().to_byte_array(), decoded.compute_wtxid().to_byte_array());
    }

    #[test]
    fn sighashtype_fromstr_display() {
        let sighashtypes = [
            ("SIGHASH_ALL", TxSighashType::All),
            ("SIGHASH_NONE", TxSighashType::None),
            ("SIGHASH_SINGLE", TxSighashType::Single),
            ("SIGHASH_ALL|SIGHASH_ANYONECANPAY", TxSighashType::AllPlusAnyoneCanPay),
            ("SIGHASH_NONE|SIGHASH_ANYONECANPAY", TxSighashType::NonePlusAnyoneCanPay),
            ("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY", TxSighashType::SinglePlusAnyoneCanPay),
        ];
        for (s, sht) in sighashtypes {
            assert_eq!(sht.to_string(), s);
            assert_eq!(s.parse::<TxSighashType>().unwrap(), sht);
        }
        let sht_mistakes = [
            "SIGHASH_ALL | SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |SIGHASH_ANYONECANPAY",
            "SIGHASH_SINGLE| SIGHASH_ANYONECANPAY",
            "SIGHASH_ALL SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |",
            "SIGHASH_SIGNLE",
            "sighash_none",
            "Sighash_none",
            "SigHash_None",
            "SigHash_NONE",
        ];
        for s in sht_mistakes {
            assert_eq!(
                s.parse::<TxSighashType>().unwrap_err().to_string(),
                format!("unrecognized SIGHASH string '{}'", s)
            );
        }
    }

    #[test]
    fn huge_witness() {
        let hex =
            hex::decode_to_vec(include_str!("../../tests/data/huge_witness.hex").trim()).unwrap();
        encoding::decode_from_slice::<Transaction>(&hex).unwrap();
    }

    #[test]
    fn sequence_number() {
        let seq_final = Sequence::from_consensus(0xFFFFFFFF);
        let seq_non_rbf = Sequence::from_consensus(0xFFFFFFFE);
        let block_time_lock = Sequence::from_consensus(0xFFFF);
        let unit_time_lock = Sequence::from_consensus(0x40FFFF);
        let lock_time_disabled = Sequence::from_consensus(0x80000000);

        assert!(seq_final.is_final());
        assert!(!seq_final.is_rbf());
        assert!(!seq_final.is_relative_lock_time());
        assert!(!seq_non_rbf.is_rbf());
        assert!(block_time_lock.is_relative_lock_time());
        assert!(block_time_lock.is_height_locked());
        assert!(block_time_lock.is_rbf());
        assert!(unit_time_lock.is_relative_lock_time());
        assert!(unit_time_lock.is_time_locked());
        assert!(unit_time_lock.is_rbf());
        assert!(!lock_time_disabled.is_relative_lock_time());
    }

    #[test]
    fn sequence_from_hex_lower() {
        let sequence = Sequence::from_hex("0xffffffff").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_hex_upper() {
        let sequence = Sequence::from_hex("0XFFFFFFFF").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_unprefixed_hex_lower() {
        let sequence = Sequence::from_unprefixed_hex("ffffffff").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_unprefixed_hex_upper() {
        let sequence = Sequence::from_unprefixed_hex("FFFFFFFF").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_str_hex_invalid_hex_should_err() {
        let hex = "0xzb93";
        let result = Sequence::from_hex(hex);
        assert!(result.is_err());
    }

    #[test]
    fn effective_value_happy_path() {
        let value = "1 cTDC".parse::<Amount>().unwrap();
        let fee_rate = FeeRate::from_sat_per_kwu(10);
        let prediction = InputWeightPrediction::MAX_KNOWN_PQ_P2WPKH;
        let effective_value = effective_value(fee_rate, prediction, value);

        let expected_fee =
            SignedAmount::from_sat(fee_rate.to_fee(prediction.total_weight()).to_sat() as i64)
                .unwrap();
        let expected_effective_value = (value.to_signed() - expected_fee).unwrap();
        assert_eq!(effective_value, expected_effective_value);
    }

    #[test]
    fn effective_value_fee_rate_does_not_overflow() {
        let prediction = InputWeightPrediction::MAX_KNOWN_PQ_P2WPKH;
        let eff_value = effective_value(FeeRate::MAX, prediction, Amount::ZERO);
        let fee =
            SignedAmount::from_sat(FeeRate::MAX.to_fee(prediction.total_weight()).to_sat() as i64)
                .unwrap();
        let want = Amount::ZERO.to_signed().checked_sub(fee).unwrap();
        assert_eq!(eff_value, want)
    }

    #[test]
    fn txin_txout_weight() {
        let txs = [
            synthetic_transaction(true),
            synthetic_transaction(false),
            Transaction {
                version: Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                inputs: vec![
                    synthetic_txin(
                        0x51,
                        0,
                        &[
                            PqScheme::MlDsa44.max_sig_len_in_script(),
                            PqScheme::MlDsa44.prefixed_pubkey_len(),
                        ],
                    ),
                    synthetic_txin(0x52, 10, &[]),
                ],
                outputs: vec![synthetic_txout(0x61, 22), synthetic_txout(0x62, 23)],
            },
            Transaction {
                version: Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                inputs: vec![
                    synthetic_txin(
                        0x71,
                        2,
                        &[
                            PqScheme::MlDsa87.max_sig_len_in_script(),
                            PqScheme::MlDsa87.prefixed_pubkey_len(),
                        ],
                    ),
                    synthetic_txin(
                        0x72,
                        0,
                        &[
                            PqScheme::Falcon512.max_sig_len_in_script(),
                            PqScheme::Falcon512.prefixed_pubkey_len(),
                        ],
                    ),
                ],
                outputs: vec![synthetic_txout(0x81, 34)],
            },
        ];

        let empty_transaction_weight = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![],
            outputs: vec![],
        }
        .weight();

        for tx in &txs {
            let is_segwit = tx.uses_segwit_serialization();
            let txin_weight = if is_segwit { TxIn::segwit_weight } else { TxIn::legacy_weight };

            let mut calculated_weight = empty_transaction_weight
                + tx.inputs.iter().fold(Weight::ZERO, |sum, i| sum + txin_weight(i))
                + tx.outputs.iter().fold(Weight::ZERO, |sum, o| sum + o.weight());

            // The empty tx uses SegWit serialization but a legacy tx does not.
            if !tx.uses_segwit_serialization() {
                calculated_weight -= Weight::from_wu(2);
            }

            assert_eq!(calculated_weight, tx.weight());
        }
    }

    #[test]
    fn tx_sigop_count() {
        fn p2pkh_script(tag: u8) -> ScriptPubKeyBuf {
            let mut bytes = vec![0x76, 0xa9, 0x14];
            bytes.extend_from_slice(&[tag; 20]);
            bytes.extend_from_slice(&[0x88, 0xac]);
            ScriptPubKeyBuf::from_bytes(bytes)
        }
        fn p2sh_script(tag: u8) -> ScriptPubKeyBuf {
            let mut bytes = vec![0xa9, 0x14];
            bytes.extend_from_slice(&[tag; 20]);
            bytes.push(0x87);
            ScriptPubKeyBuf::from_bytes(bytes)
        }
        fn p2wpkh_script(tag: u8) -> ScriptPubKeyBuf {
            let mut bytes = vec![0x00, 0x14];
            bytes.extend_from_slice(&[tag; 20]);
            ScriptPubKeyBuf::from_bytes(bytes)
        }
        fn p2wsh_script(tag: u8) -> ScriptPubKeyBuf {
            let mut bytes = vec![0x00, 0x20];
            bytes.extend_from_slice(&[tag; 32]);
            ScriptPubKeyBuf::from_bytes(bytes)
        }
        fn p2wsh512_script(tag: u8) -> ScriptPubKeyBuf {
            let mut bytes = vec![0x51, 0x40];
            bytes.extend_from_slice(&[tag; 64]);
            ScriptPubKeyBuf::from_bytes(bytes)
        }
        fn pushed_script_sig(script: &ScriptPubKeyBuf) -> ScriptSigBuf {
            let script = script.as_bytes();
            assert!(script.len() <= 75);
            let mut bytes = vec![script.len() as u8];
            bytes.extend_from_slice(script);
            ScriptSigBuf::from_bytes(bytes)
        }
        fn prevout(script_pubkey: ScriptPubKeyBuf) -> TxOut {
            TxOut { amount: Amount::from_sat_u32(1), script_pubkey }
        }
        fn return_none(_outpoint: &OutPoint) -> Option<TxOut> {
            None
        }

        #[derive(Clone, Copy)]
        enum PrevoutKind {
            None,
            P2sh,
            P2wpkh,
            P2wsh,
            P2wsh512,
        }
        impl PrevoutKind {
            fn txout(self) -> Option<TxOut> {
                match self {
                    Self::None => None,
                    Self::P2sh => Some(prevout(p2sh_script(0x11))),
                    Self::P2wpkh => Some(prevout(p2wpkh_script(0x12))),
                    Self::P2wsh => Some(prevout(p2wsh_script(0x13))),
                    Self::P2wsh512 => Some(prevout(p2wsh512_script(0x14))),
                }
            }
        }

        let multisig_3_of_3 = ScriptPubKeyBuf::from_bytes(vec![0x53, 0xae]);
        let multisig_4_of_4 = ScriptPubKeyBuf::from_bytes(vec![0x54, 0xae]);
        let nested_p2wsh = p2wsh_script(0x21);

        let txs = [
            // 0 sigops: legacy-looking input script and witness output only.
            (synthetic_transaction(false), 0, PrevoutKind::None, 0),
            // 5 sigops: P2WPKH input (1) plus P2PKH output (1 x 4).
            (
                Transaction {
                    version: Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    inputs: vec![synthetic_txin(0x31, 0, &[64, 32])],
                    outputs: vec![prevout(p2pkh_script(0x32))],
                },
                5,
                PrevoutKind::P2wpkh,
                4,
            ),
            // 8 sigops: P2WSH 4-of-4 witness script (4) plus P2PKH output (1 x 4).
            (
                Transaction {
                    version: Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    inputs: vec![TxIn {
                        witness: Witness::from_iter([multisig_4_of_4.as_bytes()]),
                        ..synthetic_txin(0x41, 0, &[])
                    }],
                    outputs: vec![prevout(p2pkh_script(0x42)), prevout(p2wsh_script(0x43))],
                },
                8,
                PrevoutKind::P2wsh,
                4,
            ),
            // 5 sigops: nested P2SH-P2WPKH input (1) plus P2PKH output (1 x 4).
            (
                Transaction {
                    version: Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    inputs: vec![TxIn {
                        script_sig: pushed_script_sig(&p2wpkh_script(0x51)),
                        witness: synthetic_witness(0x52, &[64, 32]),
                        ..synthetic_txin(0x53, 0, &[])
                    }],
                    outputs: vec![prevout(p2sh_script(0x54)), prevout(p2pkh_script(0x55))],
                },
                5,
                PrevoutKind::P2sh,
                4,
            ),
            // 12 sigops: P2SH 3-of-3 redeem script (3 x 4).
            (
                Transaction {
                    version: Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    inputs: vec![TxIn {
                        script_sig: pushed_script_sig(&multisig_3_of_3),
                        ..synthetic_txin(0x61, 0, &[])
                    }],
                    outputs: vec![prevout(p2sh_script(0x62))],
                },
                12,
                PrevoutKind::P2sh,
                0,
            ),
            // 3 sigops: nested P2SH-P2WSH 3-of-3 witness script.
            (
                Transaction {
                    version: Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    inputs: vec![TxIn {
                        script_sig: pushed_script_sig(&nested_p2wsh),
                        witness: Witness::from_iter([multisig_3_of_3.as_bytes()]),
                        ..synthetic_txin(0x71, 0, &[])
                    }],
                    outputs: vec![prevout(p2sh_script(0x73)), prevout(p2wsh_script(0x74))],
                },
                3,
                PrevoutKind::P2sh,
                0,
            ),
            // 3 sigops: P2WSH-512 counts the executed witness script like the node.
            (
                Transaction {
                    version: Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    inputs: vec![TxIn {
                        witness: Witness::from_iter([multisig_3_of_3.as_bytes()]),
                        ..synthetic_txin(0x79, 0, &[])
                    }],
                    outputs: vec![prevout(p2sh_script(0x7a))],
                },
                3,
                PrevoutKind::P2wsh512,
                0,
            ),
            // 80 sigops: bare multisig output uses the consensus fallback of 20 sigops x 4.
            (
                Transaction {
                    version: Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    inputs: vec![synthetic_txin(0x81, 0, &[])],
                    outputs: vec![prevout(ScriptPubKeyBuf::from_bytes(vec![0xae]))],
                },
                80,
                PrevoutKind::None,
                80,
            ),
        ];

        for (tx, expected, prevout_kind, expected_none) in txs {
            assert_eq!(tx.total_sigop_cost(|_| prevout_kind.txout()), expected);
            assert_eq!(tx.total_sigop_cost(return_none), expected_none);
        }
    }

    #[test]
    fn weight_predictions() {
        let schemes = [PqScheme::Falcon512, PqScheme::MlDsa44, PqScheme::MlDsa87];
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: schemes
                .into_iter()
                .enumerate()
                .map(|(idx, scheme)| {
                    let mut witness = Witness::new();
                    witness.push(vec![0x30; scheme.max_sig_len_in_script()]);
                    witness.push(vec![scheme.prefix(); scheme.prefixed_pubkey_len()]);
                    TxIn {
                        previous_output: OutPoint {
                            txid: Txid::from_byte_array([idx as u8 + 1; 32]),
                            vout: idx as u32,
                        },
                        script_sig: ScriptSigBuf::new(),
                        sequence: Sequence::MAX,
                        witness,
                    }
                })
                .collect(),
            outputs: vec![
                TxOut {
                    amount: Amount::from_sat_u32(1),
                    script_pubkey: ScriptPubKeyBuf::builder()
                        .push_opcode(crate::opcodes::all::OP_HASH160)
                        .push_slice([0x42; 20])
                        .push_opcode(crate::opcodes::all::OP_EQUAL)
                        .into_script(),
                },
                TxOut {
                    amount: Amount::from_sat_u32(2),
                    script_pubkey: ScriptPubKeyBuf::builder()
                        .push_int_unchecked(0)
                        .push_slice([0x43; 20])
                        .into_script(),
                },
            ],
        };
        let input_weights = vec![
            InputWeightPrediction::pq_p2wpkh(PqScheme::Falcon512),
            InputWeightPrediction::pq_p2wpkh(PqScheme::MlDsa44),
            InputWeightPrediction::pq_p2wpkh(PqScheme::MlDsa87),
        ];
        // Outputs: [P2SH, P2WPKH]

        // Confirm the transaction's predicted weight matches its actual weight.
        let predicted = predict_weight(input_weights, tx.script_pubkey_lens());
        let expected = tx.weight();
        assert_eq!(predicted, expected);
    }

    #[test]
    fn weight_prediction_const_from_slices() {
        let predict = [
            InputWeightPrediction::MAX_KNOWN_PQ_P2WPKH,
            InputWeightPrediction::MAX_KNOWN_PQ_NESTED_P2WPKH,
            InputWeightPrediction::MAX_KNOWN_PQ_NON_WITNESS_KEY_SPEND,
            InputWeightPrediction::MAX_KNOWN_PQ_WITNESS_SCRIPT_KEY_SPEND,
        ];

        let weight = predict_weight_from_slices(&predict, &[1]);
        assert_eq!(weight, predict_weight(predict, [1]));
    }

    #[test]
    // needless_borrows_for_generic_args incorrectly identifies &[] as a needless borrow
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn weight_prediction_new() {
        let scheme = PqScheme::Falcon512;
        let sig_len = scheme.max_sig_len_in_script();
        let pubkey_len = scheme.prefixed_pubkey_len();

        let p2wpkh = InputWeightPrediction::new(0, [sig_len, pubkey_len]);
        assert_eq!(p2wpkh, InputWeightPrediction::pq_p2wpkh(scheme));

        let nested_p2wpkh = InputWeightPrediction::new(23, [sig_len, pubkey_len]);
        assert_eq!(nested_p2wpkh, InputWeightPrediction::pq_nested_p2wpkh(scheme));

        let non_witness_script_len = CompactSizeEncoder::encoded_size(sig_len)
            + sig_len
            + CompactSizeEncoder::encoded_size(pubkey_len)
            + pubkey_len;
        let non_witness = InputWeightPrediction::new(non_witness_script_len, &[]);
        assert_eq!(non_witness, InputWeightPrediction::pq_non_witness_key_spend(scheme));

        let witness_script_len = 3 + pubkey_len + 1;
        let witness_script = InputWeightPrediction::new(0, [sig_len, witness_script_len]);
        assert_eq!(witness_script, InputWeightPrediction::pq_witness_script_key_spend(scheme));
    }

    #[test]

    fn outpoint_format() {
        let outpoint = OutPoint::COINBASE_PREVOUT;

        let debug = "OutPoint { txid: Txid(tidecoin_hashes::sha256d::Hash(0000000000000000000000000000000000000000000000000000000000000000)), vout: 4294967295 }";
        assert_eq!(debug, format!("{:?}", outpoint));

        let display = "0000000000000000000000000000000000000000000000000000000000000000:4294967295";
        assert_eq!(display, format!("{}", outpoint));

        let pretty_debug = "OutPoint {
    txid: Txid(
        tidecoin_hashes::sha256d::Hash(
            0x0000000000000000000000000000000000000000000000000000000000000000,
        ),
    ),
    vout: 4294967295,
}";
        assert_eq!(pretty_debug, format!("{:#?}", outpoint));

        let debug_txid = "Txid(tidecoin_hashes::sha256d::Hash(0000000000000000000000000000000000000000000000000000000000000000))";
        assert_eq!(debug_txid, format!("{:?}", outpoint.txid));

        let display_txid = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(display_txid, format!("{}", outpoint.txid));

        let pretty_txid = "0x0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(pretty_txid, format!("{:#}", outpoint.txid));
    }

    #[test]
    fn coinbase_assume_methods() {
        use crate::block::BlockCheckedExt as _;
        use crate::constants;
        use crate::network::Network;

        let genesis = constants::genesis_block(Network::Tidecoin);
        let coinbase_tx = &genesis.transactions()[0];

        // The view borrows the original transaction and its input.
        let coinbase_ref = CoinbaseRef::assume_coinbase(coinbase_tx);
        assert_eq!(coinbase_ref.compute_txid(), coinbase_tx.compute_txid());
        assert_eq!(coinbase_ref.wtxid(), Wtxid::COINBASE);
        assert!(core::ptr::eq(coinbase_ref.as_transaction(), coinbase_tx));
        assert!(core::ptr::eq(coinbase_ref.first_input(), &coinbase_tx.inputs[0]));
        assert_eq!(genesis.coinbase(), coinbase_ref);

        // Test that we can create a Coinbase using assume_coinbase
        let coinbase_owned = Coinbase::assume_coinbase(coinbase_tx.clone());
        assert_eq!(coinbase_owned.compute_txid(), coinbase_tx.compute_txid());
        assert_eq!(coinbase_owned.wtxid(), Wtxid::COINBASE);
        assert_eq!(coinbase_owned.as_coinbase_ref(), coinbase_ref);
        assert!(core::ptr::eq(
            coinbase_owned.first_input(),
            &coinbase_owned.as_transaction().inputs[0]
        ));
        assert_eq!(coinbase_owned.into_transaction(), *coinbase_tx);
    }
}
