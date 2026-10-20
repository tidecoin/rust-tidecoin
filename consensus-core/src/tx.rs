//! Transaction context and precomputed data for consensus validation.

use alloc::vec::Vec;

use core::fmt;
use hashes::{sha256, sha256d, sha512};
use primitives::{Transaction, TxOut};

use crate::TidecoinValidationError;

/// Malformed previous-output context supplied by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpentOutputsError {
    /// A complete set must contain exactly one output per transaction input.
    CountMismatch {
        /// Transaction input count.
        expected: usize,
        /// Supplied output count.
        actual: usize,
    },
    /// The current output disagrees with the separately supplied amount or script.
    CurrentOutputMismatch {
        /// Input whose context disagrees.
        index: usize,
    },
}

impl fmt::Display for SpentOutputsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountMismatch { expected, actual } => {
                write!(f, "expected {expected} spent outputs, got {actual}")
            }
            Self::CurrentOutputMismatch { index } => {
                write!(f, "spent output disagrees with current input {index}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SpentOutputsError {}

/// Borrows the transaction being verified.
#[derive(Debug, Clone, Copy)]
pub struct TransactionContext<'tx> {
    tx: &'tx Transaction,
}

impl<'tx> TransactionContext<'tx> {
    /// Creates a typed transaction validation context.
    pub fn new(tx: &'tx Transaction) -> Self {
        Self { tx }
    }

    /// Returns the borrowed transaction.
    pub fn tx(&self) -> &'tx Transaction {
        self.tx
    }

    /// Ensures `input_index` points to an existing transaction input.
    pub fn ensure_input_index(&self, input_index: usize) -> Result<(), TidecoinValidationError> {
        if input_index >= self.tx.inputs.len() {
            Err(TidecoinValidationError::InvalidInputIndex {
                index: input_index,
                inputs: self.tx.inputs.len(),
            })
        } else {
            Ok(())
        }
    }

    /// Builds precomputed data required for signature hashing.
    pub fn build_precomputed(
        &self,
        spent_outputs: Option<&SpentOutputs>,
        force: bool,
    ) -> Result<PrecomputedTransactionData, SpentOutputsError> {
        PrecomputedTransactionData::new(self.tx, spent_outputs, force)
    }
}

/// Typed spent outputs in transaction input order.
///
/// The caller must resolve each input's outpoint to its actual output. `TxOut`
/// contains no outpoint, so this collection cannot independently check that
/// association. Boundaries validate the count and separately supplied current
/// output. Use `None`, rather than a partial collection, for unavailable context.
#[derive(Debug, Clone)]
pub struct SpentOutputs {
    txouts: Vec<TxOut>,
}

impl SpentOutputs {
    /// Creates a spent-output set from typed transaction outputs.
    pub fn from_txouts(txouts: Vec<TxOut>) -> Self {
        Self { txouts }
    }

    /// Returns the borrowed spent outputs.
    pub fn txouts(&self) -> &[TxOut] {
        &self.txouts
    }

    /// Validates that this is a complete set for `tx`.
    pub fn validate(&self, tx: &Transaction) -> Result<(), SpentOutputsError> {
        if self.txouts.len() != tx.inputs.len() {
            return Err(SpentOutputsError::CountMismatch {
                expected: tx.inputs.len(),
                actual: self.txouts.len(),
            });
        }
        Ok(())
    }

    pub(crate) fn validate_current(
        &self,
        index: usize,
        amount: u64,
        script: &[u8],
    ) -> Result<(), SpentOutputsError> {
        match self.txouts.get(index) {
            Some(output)
                if output.amount.to_sat() == amount
                    && output.script_pubkey.as_bytes() == script =>
            {
                Ok(())
            }
            _ => Err(SpentOutputsError::CurrentOutputMismatch { index }),
        }
    }
}

/// Precomputed transaction data for witness-aware verification.
#[derive(Debug, Clone, Default)]
pub struct PrecomputedTransactionData {
    /// Single-SHA256 hash of all prevouts for Tidecoin witness paths.
    pub prevouts_hash32: Option<sha256::Hash>,
    /// Single-SHA256 hash of all input sequences for Tidecoin witness paths.
    pub sequences_hash32: Option<sha256::Hash>,
    /// Single-SHA256 hash of all outputs for Tidecoin witness paths.
    pub outputs_hash32: Option<sha256::Hash>,
    /// SHA-512 hash of input outpoints for `WITNESS_V1_512`.
    pub hash_prevouts512: Option<sha512::Hash>,
    /// SHA-512 hash of input sequences for `WITNESS_V1_512`.
    pub hash_sequence512: Option<sha512::Hash>,
    /// SHA-512 hash of transaction outputs for `WITNESS_V1_512`.
    pub hash_outputs512: Option<sha512::Hash>,
    /// SHA-512 hash of all spent amounts, serialized as eight-byte integers.
    pub spent_amounts_hash512: Option<sha512::Hash>,
    /// SHA-512 hash of all spent scripts, including CompactSize lengths.
    pub spent_scripts_hash512: Option<sha512::Hash>,
    /// Double-SHA256 prevout hash for legacy and SegWit v0 sighash.
    pub hash_prevouts: Option<sha256d::Hash>,
    /// Double-SHA256 sequence hash for legacy and SegWit v0 sighash.
    pub hash_sequence: Option<sha256d::Hash>,
    /// Double-SHA256 output hash for legacy and SegWit v0 sighash.
    pub hash_outputs: Option<sha256d::Hash>,
    /// Whether SegWit v0 precomputation is available.
    pub witness_v0_ready: bool,
    /// Whether transaction SHA-512 hashes are available (even without spent outputs).
    pub witness_v1_ready: bool,
    /// Whether the complete spent-output set was supplied.
    pub spent_outputs_ready: bool,
}

impl PrecomputedTransactionData {
    /// Precomputes the hashes needed by active Tidecoin sighash modes.
    pub fn new(
        tx: &Transaction,
        spent_outputs: Option<&SpentOutputs>,
        force: bool,
    ) -> Result<Self, SpentOutputsError> {
        if let Some(spent) = spent_outputs {
            spent.validate(tx)?;
        }
        let mut data = Self {
            spent_outputs_ready: spent_outputs.is_some_and(|spent| !spent.txouts.is_empty()),
            ..Self::default()
        };
        // Match node Init: any witness (including wrapped v1) prepares both hash families.
        if force || tx.inputs.iter().any(|input| !input.witness.is_empty()) {
            let prevouts = hash_prevouts_single(tx);
            let sequences = hash_sequences_single(tx);
            let outputs = hash_outputs_single(tx);
            data.prevouts_hash32 = Some(prevouts);
            data.sequences_hash32 = Some(sequences);
            data.outputs_hash32 = Some(outputs);
            data.hash_prevouts = Some(prevouts.hash_again());
            data.hash_sequence = Some(sequences.hash_again());
            data.hash_outputs = Some(outputs.hash_again());
            data.witness_v0_ready = true;
            data.hash_prevouts512 =
                Some(hash_serialized512(tx.inputs.iter().map(|input| &input.previous_output)));
            data.hash_sequence512 =
                Some(hash_serialized512(tx.inputs.iter().map(|input| &input.sequence)));
            data.hash_outputs512 = Some(hash_serialized512(tx.outputs.iter()));
            if let Some(spent) = spent_outputs.filter(|_| data.spent_outputs_ready) {
                data.spent_amounts_hash512 =
                    Some(hash_serialized512(spent.txouts.iter().map(|out| &out.amount)));
                data.spent_scripts_hash512 = Some(hash_serialized512(
                    spent.txouts.iter().map(|out| out.script_pubkey.as_script()),
                ));
            }
            data.witness_v1_ready = true;
        }
        Ok(data)
    }
}

fn hash_prevouts_single(tx: &Transaction) -> sha256::Hash {
    hash_serialized(tx.inputs.iter().map(|input| &input.previous_output))
}

fn hash_sequences_single(tx: &Transaction) -> sha256::Hash {
    hash_serialized(tx.inputs.iter().map(|input| &input.sequence))
}

fn hash_outputs_single(tx: &Transaction) -> sha256::Hash {
    hash_serialized(tx.outputs.iter())
}

fn hash_serialized512<'a, I, T>(items: I) -> sha512::Hash
where
    I: IntoIterator<Item = &'a T>,
    T: encoding::Encodable + 'a + ?Sized,
{
    let mut engine = sha512::Hash::engine();
    for item in items {
        io::encode_to_writer(item, &mut engine).expect("hash engine writes are infallible");
    }
    sha512::Hash::from_engine(engine)
}

fn hash_serialized<'a, I, T>(items: I) -> sha256::Hash
where
    I: IntoIterator<Item = &'a T>,
    T: encoding::Encodable + 'a + ?Sized,
{
    let mut engine = sha256::Hash::engine();
    for item in items {
        io::encode_to_writer(item, &mut engine).expect("hash engine writes are infallible");
    }
    sha256::Hash::from_engine(engine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use encoding::encode_to_vec;
    use primitives::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptPubKeyBuf, Sequence,
        TxIn, Txid, Witness,
    };

    #[test]
    fn borrows_transaction_and_detects_hashes() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 },
                script_sig: primitives::ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(42).expect("valid amount"),
                script_pubkey: ScriptPubKeyBuf::new(),
            }],
        };

        let _encoded = encode_to_vec(&tx);
        let ctx = TransactionContext::new(&tx);

        assert_eq!(ctx.tx().compute_txid(), tx.compute_txid());

        let pre = ctx.build_precomputed(None, true).unwrap();
        assert!(pre.hash_prevouts.is_some());
        assert!(pre.hash_sequence.is_some());
        assert!(pre.hash_outputs.is_some());
    }

    #[test]
    fn spent_outputs_from_txouts() {
        let spent = SpentOutputs::from_txouts(vec![TxOut {
            amount: Amount::from_sat(10).expect("valid amount"),
            script_pubkey: ScriptPubKeyBuf::from_bytes([0x51u8; 34].to_vec()),
        }]);
        assert_eq!(spent.txouts().len(), 1);
        assert_eq!(spent.txouts()[0].amount.to_sat(), 10);
    }

    #[test]
    fn precomputed_marks_witness_v1_ready_when_prevouts_known() {
        let witness_v1_script =
            ScriptPubKeyBuf::from_bytes([vec![0x51, 64], vec![0u8; 64]].concat());

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([2u8; 32]), vout: 0 },
                script_sig: primitives::ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from(vec![vec![0x01]]),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(100).expect("valid amount"),
                script_pubkey: ScriptPubKeyBuf::new(),
            }],
        };

        let spent = SpentOutputs::from_txouts(vec![TxOut {
            amount: Amount::from_sat(50).expect("valid amount"),
            script_pubkey: witness_v1_script,
        }]);

        let ctx = TransactionContext::new(&tx);
        let pre = ctx.build_precomputed(Some(&spent), false).unwrap();
        assert!(pre.witness_v1_ready);
        assert!(pre.spent_amounts_hash512.is_some());
        assert!(pre.spent_scripts_hash512.is_some());
        assert!(pre.witness_v0_ready);
    }
}
