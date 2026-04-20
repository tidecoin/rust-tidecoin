// SPDX-License-Identifier: CC0-1.0

//! Transaction and script validation.
//!
//! Tidecoin uses a Tidecoin-aware validation path for script execution,
//! including PQ keys, `OP_SHA512`, and witness-v1-512.
//!
//! Public validation always executes through the pure-Rust Tidecoin consensus
//! core. Real-node parity remains available through explicit test/dev harnesses,
//! not by swapping the product backend at runtime.
//!
//! The remaining validation gap in this crate is at the policy surface above
//! script execution: Tidecoin node entry points such as `IsWitnessStandard`,
//! `IsStandardTx`, and virtual-size or weight helpers are not exposed here yet.

use core::convert::Infallible;
use core::fmt;

use internals::write_err;

use crate::amount::Amount;
#[cfg(doc)]
use crate::consensus_validation;
use crate::internal_macros::define_extension_trait;
use crate::prelude::Vec;
use crate::script::ScriptPubKey;
use crate::transaction::{OutPoint, Transaction, TxOut};
pub use consensus_core::{
    ScriptError, TidecoinValidationError, VERIFY_ALL_TIDECOIN, VERIFY_CHECKLOCKTIMEVERIFY,
    VERIFY_CHECKSEQUENCEVERIFY, VERIFY_CLEANSTACK, VERIFY_CONST_SCRIPTCODE,
    VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    VERIFY_MINIMALDATA, VERIFY_MINIMALIF, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_NULLFAIL,
    VERIFY_P2SH, VERIFY_PQ_STRICT, VERIFY_SHA512, VERIFY_SIGPUSHONLY, VERIFY_WITNESS,
    VERIFY_WITNESS_V1_512,
};
#[path = "consensus_validation_tidecoin.rs"]
mod consensus_validation_impl;
use self::consensus_validation_impl as tidecoin;
#[cfg(all(test, feature = "tidecoin-node-validation"))]
#[path = "consensus_validation_node.rs"]
mod consensus_validation_node;

/// Verifies spend of an input script.
pub fn verify_script(
    script: &ScriptPubKey,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
) -> Result<(), ValidationError> {
    verify_script_with_flags(script, index, amount, spending_tx, VERIFY_ALL_TIDECOIN)
}

/// Verifies spend of an input script.
pub fn verify_script_with_flags<F: Into<u32>>(
    script: &ScriptPubKey,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
    flags: F,
) -> Result<(), ValidationError> {
    let flags = flags.into();
    let tx: Transaction = encoding::decode_from_slice(spending_tx)
        .map_err(|_| ValidationError::MalformedTransaction)?;
    tidecoin::verify_script_input(script, index, amount, &tx, flags)
        .map_err(ValidationError::Tidecoin)
}

/// Verifies that this transaction is able to spend its inputs.
pub fn verify_transaction<S>(tx: &Transaction, spent: S) -> Result<(), TxVerifyError>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    verify_transaction_with_flags(tx, spent, VERIFY_ALL_TIDECOIN)
}

/// Verifies that this transaction is able to spend its inputs.
pub fn verify_transaction_with_flags<S, F>(
    tx: &Transaction,
    mut spent: S,
    flags: F,
) -> Result<(), TxVerifyError>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
    F: Into<u32>,
{
    let serialized_tx = encoding::encode_to_vec(tx);
    let flags = flags.into();
    let mut spent_outputs = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let output = spent(&input.previous_output)
            .ok_or(TxVerifyError::UnknownSpentOutput(input.previous_output))?;
        spent_outputs.push(output);
    }

    for (idx, output) in spent_outputs.iter().enumerate() {
        verify_script_with_flags(
            &output.script_pubkey,
            idx,
            output.amount,
            serialized_tx.as_slice(),
            flags,
        )?;
    }
    Ok(())
}

define_extension_trait! {
    /// Extension functionality to add validation support to the [`ScriptPubKey`] type.
    pub trait ScriptPubKeyExt impl for ScriptPubKey {
        /// Verifies spend of an input script.
        fn verify(
            &self,
            index: usize,
            amount: Amount,
            spending_tx: &[u8],
        ) -> Result<(), ValidationError> {
            verify_script(self, index, amount, spending_tx)
        }

        /// Verifies spend of an input script with explicit flags.
        fn verify_with_flags(
            &self,
            index: usize,
            amount: Amount,
            spending_tx: &[u8],
            flags: impl Into<u32>,
        ) -> Result<(), ValidationError> {
            verify_script_with_flags(self, index, amount, spending_tx, flags)
        }
    }
}

/// Extension functionality for the [`Transaction`] type.
pub trait TransactionExt: sealed::Sealed {
    /// Verifies that this transaction is able to spend its inputs.
    fn verify<S>(&self, spent: S) -> Result<(), TxVerifyError>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>;

    /// Verifies that this transaction is able to spend its inputs.
    fn verify_with_flags<S, F>(&self, spent: S, flags: F) -> Result<(), TxVerifyError>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
        F: Into<u32>;
}

impl TransactionExt for Transaction {
    fn verify<S>(&self, spent: S) -> Result<(), TxVerifyError>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        verify_transaction(self, spent)
    }

    fn verify_with_flags<S, F>(&self, spent: S, flags: F) -> Result<(), TxVerifyError>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
        F: Into<u32>,
    {
        verify_transaction_with_flags(self, spent, flags)
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ScriptPubKey {}
    impl Sealed for super::Transaction {}
}

/// Validation error from the Tidecoin validation surface.
///
/// This is the product-level error type for script/input verification. It
/// separates malformed serialized transaction input from
/// [`TidecoinValidationError`], which is the re-exported shared-core
/// verification error returned once decoding and routing have succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// Serialized spending transaction bytes could not be decoded.
    ///
    /// This indicates malformed caller input before consensus verification even
    /// starts.
    MalformedTransaction,
    /// Error returned by the Tidecoin-specific validation path.
    ///
    /// This wraps the shared Tidecoin validation engine error once the
    /// serialized transaction bytes were decoded successfully.
    Tidecoin(TidecoinValidationError),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MalformedTransaction => {
                f.write_str("serialized spending transaction is malformed")
            }
            Self::Tidecoin(err) => write_err!(f, "tidecoin validation error"; err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedTransaction => None,
            Self::Tidecoin(err) => Some(err),
        }
    }
}

/// An error during transaction validation.
///
/// This is the multi-input transaction-level companion to [`ValidationError`].
/// It distinguishes missing caller-supplied prevout state from per-input script
/// verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxVerifyError {
    /// Error validating one of the transaction inputs.
    ///
    /// The wrapped [`ValidationError`] explains whether the failure was
    /// malformed serialized input or a shared-core validation error.
    ScriptVerification(ValidationError),
    /// Cannot find the spent output.
    ///
    /// This indicates the caller did not provide required UTXO context for at
    /// least one input. It does not by itself say the transaction is
    /// consensus-invalid.
    UnknownSpentOutput(OutPoint),
}

impl fmt::Display for TxVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ScriptVerification(ref e) => write_err!(f, "script verification failed"; e),
            Self::UnknownSpentOutput(ref output) => write!(f, "spent output missing: {}", output),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::ScriptVerification(ref e) => Some(e),
            Self::UnknownSpentOutput(_) => None,
        }
    }
}

impl From<ValidationError> for TxVerifyError {
    fn from(e: ValidationError) -> Self {
        Self::ScriptVerification(e)
    }
}

impl From<Infallible> for TxVerifyError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

#[cfg(test)]
mod tests {
    use super::{
        verify_script_with_flags, verify_transaction, verify_transaction_with_flags,
        ScriptPubKeyExt, TransactionExt, TxVerifyError, ValidationError, VERIFY_NONE,
    };
    use crate::absolute;
    use crate::crypto::pq::{
        DeterministicTestRng, PqPublicKey, PqScheme, PqSchemeCryptoExt as _, PqSecretKey,
        PqSignature,
    };
    use crate::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160};
    use crate::prelude::Vec;
    use crate::script::{PushBytesBuf, ScriptBufExt as _, ScriptPubKeyBuf, ScriptSigBuf};
    use crate::transaction::{OutPoint, Transaction, TxIn, TxOut, Txid, Version};
    use crate::{Amount, Sequence, TxSighashType, Witness};
    use consensus_core::SighashCache;

    fn tagged_seed(tag: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| tag ^ (i as u8).wrapping_mul(131)).collect()
    }

    fn deterministic_keypair(scheme: PqScheme, tag: u8) -> (PqPublicKey, PqSecretKey) {
        let seed = tagged_seed(tag, scheme.deterministic_seed_len());
        scheme.generate_keypair_from_seed(&seed).unwrap()
    }

    fn deterministic_sig32(msg: &[u8; 32], sk: &PqSecretKey, tag: u64) -> PqSignature {
        let mut rng = DeterministicTestRng::new(tag);
        PqSignature::sign_msg32_with_rng(msg, sk, &mut rng).unwrap()
    }

    fn deterministic_sig32_legacy(msg: &[u8; 32], sk: &PqSecretKey, tag: u64) -> PqSignature {
        let mut rng = DeterministicTestRng::new(tag);
        PqSignature::sign_msg32_legacy_with_rng(msg, sk, &mut rng).unwrap()
    }

    fn push_bytes(data: &[u8]) -> PushBytesBuf {
        PushBytesBuf::try_from(data.to_vec()).unwrap()
    }

    fn pq_p2pkh_script_pubkey(pubkey: &PqPublicKey) -> ScriptPubKeyBuf {
        ScriptPubKeyBuf::builder()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(push_bytes(pubkey.key_id().as_ref()))
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn pq_legacy_p2pkh_spend() -> (Transaction, TxOut) {
        let (pubkey, seckey) = deterministic_keypair(PqScheme::Falcon512, 0x31);
        let script_pubkey = pq_p2pkh_script_pubkey(&pubkey);
        let prevout = OutPoint { txid: Txid::from_byte_array([1; 32]), vout: 0 };
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: prevout,
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat_u32(1),
                script_pubkey: ScriptPubKeyBuf::new(),
            }],
        };

        let cache = SighashCache::new(&tx);
        let sighash = cache
            .legacy_signature_hash(
                0,
                script_pubkey.as_script().as_bytes(),
                TxSighashType::All.to_u32(),
            )
            .unwrap();
        let sig = deterministic_sig32_legacy(sighash.as_byte_array(), &seckey, 0x31);
        let mut sig_bytes = sig.as_bytes().to_vec();
        sig_bytes.push(TxSighashType::All.to_u32() as u8);

        tx.inputs[0].script_sig = ScriptSigBuf::builder()
            .push_slice(push_bytes(&sig_bytes))
            .push_slice(push_bytes(&pubkey.to_prefixed_bytes()))
            .into_script();

        (tx, TxOut { amount: Amount::from_sat_u32(0), script_pubkey })
    }

    fn pq_strict_p2pkh_spend(tag: u8, prevout: OutPoint) -> (Transaction, TxOut) {
        let (pubkey, seckey) = deterministic_keypair(PqScheme::Falcon512, tag);
        let script_pubkey = pq_p2pkh_script_pubkey(&pubkey);
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: prevout,
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat_u32(1),
                script_pubkey: ScriptPubKeyBuf::new(),
            }],
        };

        let cache = SighashCache::new(&tx);
        let sighash = cache
            .legacy_signature_hash(
                0,
                script_pubkey.as_script().as_bytes(),
                TxSighashType::All.to_u32(),
            )
            .unwrap();
        let sig = deterministic_sig32(sighash.as_byte_array(), &seckey, tag as u64);
        let mut sig_bytes = sig.as_bytes().to_vec();
        sig_bytes.push(TxSighashType::All.to_u32() as u8);

        tx.inputs[0].script_sig = ScriptSigBuf::builder()
            .push_slice(push_bytes(&sig_bytes))
            .push_slice(push_bytes(&pubkey.to_prefixed_bytes()))
            .into_script();

        (tx, TxOut { amount: Amount::from_sat_u32(0), script_pubkey })
    }

    fn pq_strict_two_input_p2pkh_spend() -> (Transaction, Vec<(OutPoint, TxOut)>) {
        let (pubkey_a, seckey_a) = deterministic_keypair(PqScheme::Falcon512, 0x41);
        let (pubkey_b, seckey_b) = deterministic_keypair(PqScheme::MlDsa44, 0x42);
        let script_pubkey_a = pq_p2pkh_script_pubkey(&pubkey_a);
        let script_pubkey_b = pq_p2pkh_script_pubkey(&pubkey_b);
        let prevout_a = OutPoint { txid: Txid::from_byte_array([2; 32]), vout: 0 };
        let prevout_b = OutPoint { txid: Txid::from_byte_array([3; 32]), vout: 1 };
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![
                TxIn {
                    previous_output: prevout_a,
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
                TxIn {
                    previous_output: prevout_b,
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
            ],
            outputs: vec![TxOut {
                amount: Amount::from_sat_u32(1),
                script_pubkey: ScriptPubKeyBuf::new(),
            }],
        };

        let sighash_a = SighashCache::new(&tx)
            .legacy_signature_hash(
                0,
                script_pubkey_a.as_script().as_bytes(),
                TxSighashType::All.to_u32(),
            )
            .unwrap();
        let mut sig_a =
            deterministic_sig32(sighash_a.as_byte_array(), &seckey_a, 0x41).as_bytes().to_vec();
        sig_a.push(TxSighashType::All.to_u32() as u8);
        tx.inputs[0].script_sig = ScriptSigBuf::builder()
            .push_slice(push_bytes(&sig_a))
            .push_slice(push_bytes(&pubkey_a.to_prefixed_bytes()))
            .into_script();

        let sighash_b = SighashCache::new(&tx)
            .legacy_signature_hash(
                1,
                script_pubkey_b.as_script().as_bytes(),
                TxSighashType::All.to_u32(),
            )
            .unwrap();
        let mut sig_b =
            deterministic_sig32(sighash_b.as_byte_array(), &seckey_b, 0x42).as_bytes().to_vec();
        sig_b.push(TxSighashType::All.to_u32() as u8);
        tx.inputs[1].script_sig = ScriptSigBuf::builder()
            .push_slice(push_bytes(&sig_b))
            .push_slice(push_bytes(&pubkey_b.to_prefixed_bytes()))
            .into_script();

        (
            tx,
            vec![
                (
                    prevout_a,
                    TxOut { amount: Amount::from_sat_u32(0), script_pubkey: script_pubkey_a },
                ),
                (
                    prevout_b,
                    TxOut { amount: Amount::from_sat_u32(0), script_pubkey: script_pubkey_b },
                ),
            ],
        )
    }

    fn pq_strict_reused_prevout_spend() -> (Transaction, OutPoint, TxOut) {
        let (pubkey, seckey) = deterministic_keypair(PqScheme::Falcon512, 0x43);
        let script_pubkey = pq_p2pkh_script_pubkey(&pubkey);
        let prevout = OutPoint { txid: Txid::from_byte_array([8; 32]), vout: 0 };
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![
                TxIn {
                    previous_output: prevout,
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
                TxIn {
                    previous_output: prevout,
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
            ],
            outputs: vec![TxOut {
                amount: Amount::from_sat_u32(1),
                script_pubkey: ScriptPubKeyBuf::new(),
            }],
        };

        let sighash_0 = SighashCache::new(&tx)
            .legacy_signature_hash(
                0,
                script_pubkey.as_script().as_bytes(),
                TxSighashType::All.to_u32(),
            )
            .unwrap();
        let mut sig_0 =
            deterministic_sig32(sighash_0.as_byte_array(), &seckey, 0x43).as_bytes().to_vec();
        sig_0.push(TxSighashType::All.to_u32() as u8);
        tx.inputs[0].script_sig = ScriptSigBuf::builder()
            .push_slice(push_bytes(&sig_0))
            .push_slice(push_bytes(&pubkey.to_prefixed_bytes()))
            .into_script();

        let sighash_1 = SighashCache::new(&tx)
            .legacy_signature_hash(
                1,
                script_pubkey.as_script().as_bytes(),
                TxSighashType::All.to_u32(),
            )
            .unwrap();
        let mut sig_1 =
            deterministic_sig32(sighash_1.as_byte_array(), &seckey, 0x44).as_bytes().to_vec();
        sig_1.push(TxSighashType::All.to_u32() as u8);
        tx.inputs[1].script_sig = ScriptSigBuf::builder()
            .push_slice(push_bytes(&sig_1))
            .push_slice(push_bytes(&pubkey.to_prefixed_bytes()))
            .into_script();

        (tx, prevout, TxOut { amount: Amount::from_sat_u32(0), script_pubkey })
    }

    #[test]
    fn verify_script_with_flags_accepts_pq_legacy_base_spend() {
        let (tx, spent_output) = pq_legacy_p2pkh_spend();
        let serialized_tx = encoding::encode_to_vec(&tx);

        verify_script_with_flags(
            &spent_output.script_pubkey,
            0,
            spent_output.amount,
            &serialized_tx,
            VERIFY_NONE,
        )
        .unwrap();
    }

    #[test]
    fn verify_script_with_flags_errors_on_malformed_transaction_bytes() {
        let (_tx, spent_output) = pq_legacy_p2pkh_spend();

        let err = verify_script_with_flags(
            &spent_output.script_pubkey,
            0,
            spent_output.amount,
            &[0xff],
            VERIFY_NONE,
        )
        .unwrap_err();
        assert_eq!(err, ValidationError::MalformedTransaction);
    }

    #[test]
    fn verify_script_public_api_accepts_pq_strict_base_spend() {
        let (tx, spent_output) =
            pq_strict_p2pkh_spend(0x32, OutPoint { txid: Txid::from_byte_array([4; 32]), vout: 0 });
        let serialized_tx = encoding::encode_to_vec(&tx);

        spent_output.script_pubkey.verify(0, spent_output.amount, &serialized_tx).unwrap();
    }

    #[test]
    fn verify_transaction_public_api_accepts_pq_legacy_base_spend() {
        let (tx, spent_output) = pq_legacy_p2pkh_spend();
        let previous_output = tx.inputs[0].previous_output;

        verify_transaction_with_flags(
            &tx,
            |outpoint| (outpoint == &previous_output).then_some(spent_output.clone()),
            VERIFY_NONE,
        )
        .unwrap();

        tx.verify_with_flags(
            |outpoint| (outpoint == &previous_output).then_some(spent_output.clone()),
            VERIFY_NONE,
        )
        .unwrap();
    }

    #[test]
    fn verify_transaction_public_api_accepts_pq_strict_two_input_spend() {
        let (tx, spent_outputs) = pq_strict_two_input_p2pkh_spend();

        verify_transaction(&tx, |outpoint| {
            spent_outputs
                .iter()
                .find_map(|(prevout, txout)| (prevout == outpoint).then_some(txout.clone()))
        })
        .unwrap();

        tx.verify(|outpoint| {
            spent_outputs
                .iter()
                .find_map(|(prevout, txout)| (prevout == outpoint).then_some(txout.clone()))
        })
        .unwrap();
    }

    #[test]
    fn verify_transaction_public_api_errors_on_missing_spent_output() {
        let (tx, _spent_output) =
            pq_strict_p2pkh_spend(0x33, OutPoint { txid: Txid::from_byte_array([5; 32]), vout: 0 });

        let err = verify_transaction(&tx, |_outpoint| None).unwrap_err();
        assert_eq!(err, TxVerifyError::UnknownSpentOutput(tx.inputs[0].previous_output));
    }

    #[test]
    fn verify_transaction_public_api_errors_on_reused_spent_output() {
        let (tx, reused_prevout, spent_output) = pq_strict_reused_prevout_spend();

        let mut served = false;
        let err = tx
            .verify(|outpoint| {
                if outpoint == &reused_prevout && !served {
                    served = true;
                    Some(spent_output.clone())
                } else {
                    None
                }
            })
            .unwrap_err();
        assert_eq!(err, TxVerifyError::UnknownSpentOutput(reused_prevout));
    }

    #[test]
    fn verify_transaction_public_api_errors_on_corrupted_signature() {
        let (mut tx, spent_output) =
            pq_strict_p2pkh_spend(0x35, OutPoint { txid: Txid::from_byte_array([7; 32]), vout: 0 });
        tx.inputs[0].script_sig.as_mut_bytes()[2] ^= 0x01;

        let err = verify_transaction(&tx, |outpoint| {
            (outpoint == &tx.inputs[0].previous_output).then_some(spent_output.clone())
        })
        .unwrap_err();
        assert!(matches!(err, TxVerifyError::ScriptVerification(_)));
    }
}
