//! Transaction context and precomputed data for consensus validation.

use alloc::vec::Vec;

use hashes::{sha256, sha256d};
use primitives::{Transaction, TxOut};

use crate::{TidecoinValidationError, WitnessProgram};

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
    ) -> PrecomputedTransactionData {
        PrecomputedTransactionData::new(self.tx, spent_outputs, force)
    }
}

/// Typed spent outputs referenced by a transaction during verification.
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
    /// Single-SHA256 hash of spent-output amounts for `WITNESS_V1_512`.
    pub spent_amounts_hash32: Option<sha256::Hash>,
    /// Single-SHA256 hash of spent-output scripts for `WITNESS_V1_512`.
    pub spent_scripts_hash32: Option<sha256::Hash>,
    /// Double-SHA256 prevout hash for legacy and SegWit v0 sighash.
    pub hash_prevouts: Option<sha256d::Hash>,
    /// Double-SHA256 sequence hash for legacy and SegWit v0 sighash.
    pub hash_sequence: Option<sha256d::Hash>,
    /// Double-SHA256 output hash for legacy and SegWit v0 sighash.
    pub hash_outputs: Option<sha256d::Hash>,
    /// Whether SegWit v0 precomputation is available.
    pub witness_v0_ready: bool,
    /// Whether Tidecoin witness-v1-512 precomputation is available.
    pub witness_v1_ready: bool,
}

impl PrecomputedTransactionData {
    /// Precomputes the hashes needed by active Tidecoin sighash modes.
    pub fn new(tx: &Transaction, spent_outputs: Option<&SpentOutputs>, force: bool) -> Self {
        let mut data = Self::default();

        let (mut uses_witness_v0, mut uses_witness_v1) = (force, force);

        for (idx, input) in tx.inputs.iter().enumerate() {
            if input.witness.is_empty() {
                continue;
            }

            if let Some(spent) = spent_outputs {
                if WitnessProgram::is_v1_512(spent.txouts[idx].script_pubkey.as_bytes()) {
                    uses_witness_v1 = true;
                } else {
                    uses_witness_v0 = true;
                }
            } else {
                uses_witness_v0 = true;
            }

            if uses_witness_v0 && uses_witness_v1 {
                break;
            }
        }

        if uses_witness_v0 || uses_witness_v1 {
            let prevouts = hash_prevouts_single(tx);
            let sequences = hash_sequences_single(tx);
            let outputs = hash_outputs_single(tx);
            data.prevouts_hash32 = Some(prevouts);
            data.sequences_hash32 = Some(sequences);
            data.outputs_hash32 = Some(outputs);
        }

        if uses_witness_v0 {
            data.hash_prevouts = Some(hash_prevouts_double(tx));
            data.hash_sequence = Some(hash_sequences_double(tx));
            data.hash_outputs = Some(hash_outputs_double(tx));
            data.witness_v0_ready = true;
        }

        if uses_witness_v1 {
            if let Some(spent) = spent_outputs {
                data.spent_amounts_hash32 = Some(hash_spent_amounts_single(spent));
                data.spent_scripts_hash32 = Some(hash_spent_scripts_single(spent));
                data.witness_v1_ready = true;
            }
        }

        data
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

fn hash_prevouts_double(tx: &Transaction) -> sha256d::Hash {
    hash_serialized_double(tx.inputs.iter().map(|input| &input.previous_output))
}

fn hash_sequences_double(tx: &Transaction) -> sha256d::Hash {
    hash_serialized_double(tx.inputs.iter().map(|input| &input.sequence))
}

fn hash_outputs_double(tx: &Transaction) -> sha256d::Hash {
    hash_serialized_double(tx.outputs.iter())
}

fn hash_spent_amounts_single(spent: &SpentOutputs) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();
    for txout in spent.txouts() {
        io::encode_to_writer(&txout.amount, &mut engine)
            .expect("hash engine writes are infallible");
    }
    sha256::Hash::from_engine(engine)
}

fn hash_spent_scripts_single(spent: &SpentOutputs) -> sha256::Hash {
    hash_serialized(spent.txouts().iter().map(|txout| txout.script_pubkey.as_script()))
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

fn hash_serialized_double<'a, I, T>(items: I) -> sha256d::Hash
where
    I: IntoIterator<Item = &'a T>,
    T: encoding::Encodable + 'a + ?Sized,
{
    let mut engine = sha256d::Hash::engine();
    for item in items {
        io::encode_to_writer(item, &mut engine).expect("hash engine writes are infallible");
    }
    sha256d::Hash::from_engine(engine)
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

        let pre = ctx.build_precomputed(None, true);
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
        let pre = ctx.build_precomputed(Some(&spent), false);
        assert!(pre.witness_v1_ready);
        assert!(pre.spent_amounts_hash32.is_some());
        assert!(pre.spent_scripts_hash32.is_some());
        assert!(!pre.witness_v0_ready);
    }
}
