// SPDX-License-Identifier: CC0-1.0

//! Transaction and script validation.
//!
//! Tidecoin uses two validation paths:
//! - `bitcoinconsensus` for ordinary Bitcoin-compatible scripts
//! - a local Tidecoin-aware validator for PQ keys, `OP_SHA512`, and witness-v1-512

use core::convert::Infallible;
use core::fmt;

use internals::write_err;

use crate::amount::Amount;
use crate::consensus::{self, encode};
#[cfg(doc)]
use crate::consensus_validation;
use crate::internal_macros::define_extension_trait;
use crate::script::ScriptPubKey;
use crate::transaction::{OutPoint, Transaction, TxOut};

#[cfg(any(
    not(feature = "bitcoinconsensus"),
    feature = "tidecoin-node-validation"
))]
mod bitcoinconsensus_backend {
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum Error {}

    impl core::fmt::Display for Error {
        fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match *self {}
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for Error {}
}

#[cfg(all(
    feature = "bitcoinconsensus",
    not(feature = "tidecoin-node-validation")
))]
use bitcoinconsensus as bitcoinconsensus_backend;

#[cfg(feature = "tidecoin-node-validation")]
#[path = "consensus_validation_node.rs"]
mod consensus_validation_impl;
#[cfg(feature = "tidecoin-node-validation")]
#[path = "consensus_validation_tidecoin.rs"]
mod consensus_validation_fallback;
#[cfg(not(feature = "tidecoin-node-validation"))]
#[path = "consensus_validation_tidecoin.rs"]
mod consensus_validation_impl;
use self::consensus_validation_impl as tidecoin;

pub use self::consensus_validation_impl::{
    ScriptError, TidecoinValidationError, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_CLEANSTACK, VERIFY_CONST_SCRIPTCODE, VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, VERIFY_MINIMALDATA, VERIFY_MINIMALIF,
    VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_NULLFAIL, VERIFY_P2SH, VERIFY_PQ_STRICT, VERIFY_SHA512,
    VERIFY_SIGPUSHONLY, VERIFY_STRICTENC, VERIFY_WITNESS, VERIFY_WITNESS_V1_512,
};

/// Tidecoin's default pre-taproot verification flags.
pub const VERIFY_ALL_PRE_TAPROOT: u32 = VERIFY_P2SH
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_PQ_STRICT
    | VERIFY_WITNESS_V1_512
    | VERIFY_SHA512;

/// Verifies spend of an input script.
pub fn verify_script(
    script: &ScriptPubKey,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
) -> Result<(), BitcoinconsensusError> {
    verify_script_with_flags(script, index, amount, spending_tx, VERIFY_ALL_PRE_TAPROOT)
}

/// Verifies spend of an input script.
pub fn verify_script_with_flags<F: Into<u32>>(
    script: &ScriptPubKey,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
    flags: F,
) -> Result<(), BitcoinconsensusError> {
    let flags = flags.into();
    let tx: Transaction = consensus::deserialize(spending_tx)
        .map_err(|_| BitcoinconsensusError::Tidecoin(TidecoinValidationError::UnsupportedScript))?;

    #[cfg(feature = "tidecoin-node-validation")]
    {
        if tidecoin::should_use_tidecoin_validation(script, &tx, index, flags) {
            return tidecoin::verify_script_input(script, index, amount, &tx, flags)
                .map_err(BitcoinconsensusError::Tidecoin);
        }

        consensus_validation_fallback::verify_script_input(script, index, amount, &tx, flags)
            .map_err(map_fallback_validation_error)
            .map_err(BitcoinconsensusError::Tidecoin)
    }

    #[cfg(not(feature = "tidecoin-node-validation"))]
    if tidecoin::should_use_tidecoin_validation(script, &tx, index, flags) {
        return tidecoin::verify_script_input(script, index, amount, &tx, flags)
            .map_err(BitcoinconsensusError::Tidecoin);
    }

    #[cfg(all(
        feature = "bitcoinconsensus",
        not(feature = "tidecoin-node-validation")
    ))]
    {
        return bitcoinconsensus_backend::verify_with_flags(
            script.as_bytes(),
            amount.to_sat(),
            spending_tx,
            None,
            index,
            trim_tidecoin_flags(flags),
        )
        .map_err(BitcoinconsensusError::BitcoinConsensus);
    }

    #[cfg(all(
        not(feature = "bitcoinconsensus"),
        not(feature = "tidecoin-node-validation")
    ))]
    {
        let _ = (script, amount, spending_tx, flags);
        Err(BitcoinconsensusError::Tidecoin(TidecoinValidationError::UnsupportedScript))
    }
}

#[cfg(feature = "tidecoin-node-validation")]
fn map_fallback_validation_error(
    err: consensus_validation_fallback::TidecoinValidationError,
) -> TidecoinValidationError {
    use consensus_validation_fallback::ScriptError as FallbackScriptError;
    use consensus_validation_fallback::TidecoinValidationError as FallbackValidationError;

    match err {
        FallbackValidationError::Script(script_err) =>
            TidecoinValidationError::Script(match script_err {
                FallbackScriptError::EvalFalse => ScriptError::EvalFalse,
                FallbackScriptError::ScriptSize => ScriptError::ScriptSize,
                FallbackScriptError::PushSize => ScriptError::PushSize,
                FallbackScriptError::OpCount => ScriptError::OpCount,
                FallbackScriptError::StackSize => ScriptError::StackSize,
                FallbackScriptError::SigCount => ScriptError::SigCount,
                FallbackScriptError::PubkeyCount => ScriptError::PubkeyCount,
                FallbackScriptError::Verify => ScriptError::Verify,
                FallbackScriptError::EqualVerify => ScriptError::EqualVerify,
                FallbackScriptError::CheckMultisigVerify => ScriptError::CheckMultisigVerify,
                FallbackScriptError::CheckSigVerify => ScriptError::CheckSigVerify,
                FallbackScriptError::NumEqualVerify => ScriptError::NumEqualVerify,
                FallbackScriptError::BadOpcode => ScriptError::BadOpcode,
                FallbackScriptError::DisabledOpcode => ScriptError::DisabledOpcode,
                FallbackScriptError::InvalidStackOperation => ScriptError::InvalidStackOperation,
                FallbackScriptError::InvalidAltstackOperation => ScriptError::InvalidAltstackOperation,
                FallbackScriptError::UnbalancedConditional => ScriptError::UnbalancedConditional,
                FallbackScriptError::NegativeLocktime => ScriptError::NegativeLocktime,
                FallbackScriptError::UnsatisfiedLocktime => ScriptError::UnsatisfiedLocktime,
                FallbackScriptError::SigPushOnly => ScriptError::SigPushOnly,
                FallbackScriptError::NullDummy => ScriptError::SigNullDummy,
                FallbackScriptError::Cleanstack => ScriptError::Cleanstack,
                FallbackScriptError::MinimalIf => ScriptError::MinimalIf,
                FallbackScriptError::NullFail => ScriptError::NullFail,
                FallbackScriptError::DiscourageUpgradableNops => ScriptError::DiscourageUpgradableNops,
                FallbackScriptError::DiscourageUpgradableWitnessProgram =>
                    ScriptError::DiscourageUpgradableWitnessProgram,
                FallbackScriptError::WitnessProgramWrongLength =>
                    ScriptError::WitnessProgramWrongLength,
                FallbackScriptError::WitnessProgramWitnessEmpty =>
                    ScriptError::WitnessProgramWitnessEmpty,
                FallbackScriptError::WitnessProgramMismatch => ScriptError::WitnessProgramMismatch,
                FallbackScriptError::WitnessMalleated => ScriptError::WitnessMalleated,
                FallbackScriptError::WitnessMalleatedP2sh => ScriptError::WitnessMalleatedP2sh,
                FallbackScriptError::WitnessUnexpected => ScriptError::WitnessUnexpected,
                FallbackScriptError::OpCodeSeparator => ScriptError::OpCodeSeparator,
                FallbackScriptError::SigFindAndDelete => ScriptError::SigFindAndDelete,
            }),
        FallbackValidationError::InvalidInputIndex { index, inputs } =>
            TidecoinValidationError::InvalidInputIndex { index, inputs },
        FallbackValidationError::UnsupportedScript => TidecoinValidationError::UnsupportedScript,
        FallbackValidationError::MissingSpentOutput(outpoint) =>
            TidecoinValidationError::MissingSpentOutput(outpoint),
    }
}

/// Verifies that this transaction is able to spend its inputs.
pub fn verify_transaction<S>(tx: &Transaction, spent: S) -> Result<(), TxVerifyError>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    verify_transaction_with_flags(tx, spent, VERIFY_ALL_PRE_TAPROOT)
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
    let serialized_tx = encode::serialize(tx);
    let flags = flags.into();
    for (idx, input) in tx.inputs.iter().enumerate() {
        let Some(output) = spent(&input.previous_output) else {
            return Err(TxVerifyError::UnknownSpentOutput(input.previous_output));
        };

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
        ) -> Result<(), BitcoinconsensusError> {
            verify_script(self, index, amount, spending_tx)
        }

        /// Verifies spend of an input script with explicit flags.
        fn verify_with_flags(
            &self,
            index: usize,
            amount: Amount,
            spending_tx: &[u8],
            flags: impl Into<u32>,
        ) -> Result<(), BitcoinconsensusError> {
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

/// Validation error from either `bitcoinconsensus` or the Tidecoin PQ validator.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BitcoinconsensusError {
    /// Error returned by upstream `bitcoinconsensus`.
    BitcoinConsensus(bitcoinconsensus_backend::Error),
    /// Error returned by the Tidecoin-specific validation path.
    Tidecoin(TidecoinValidationError),
}

impl fmt::Display for BitcoinconsensusError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BitcoinConsensus(err) => write_err!(f, "bitcoinconsensus error"; err),
            Self::Tidecoin(err) => write_err!(f, "tidecoin validation error"; err),
        }
    }
}

#[cfg(all(feature = "std", feature = "bitcoinconsensus"))]
impl std::error::Error for BitcoinconsensusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BitcoinConsensus(err) => Some(err),
            Self::Tidecoin(err) => Some(err),
        }
    }
}

/// An error during transaction validation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxVerifyError {
    /// Error validating the script.
    ScriptVerification(BitcoinconsensusError),
    /// Cannot find the spent output.
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

impl From<BitcoinconsensusError> for TxVerifyError {
    fn from(e: BitcoinconsensusError) -> Self { Self::ScriptVerification(e) }
}

impl From<Infallible> for TxVerifyError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(all(
    feature = "bitcoinconsensus",
    not(feature = "tidecoin-node-validation")
))]
fn trim_tidecoin_flags(flags: u32) -> u32 {
    let mut translated = bitcoinconsensus_backend::VERIFY_NONE;

    if flags & VERIFY_P2SH != 0 {
        translated |= bitcoinconsensus_backend::VERIFY_P2SH;
    }
    if flags & VERIFY_NULLDUMMY != 0 {
        translated |= bitcoinconsensus_backend::VERIFY_NULLDUMMY;
    }
    if flags & VERIFY_CHECKLOCKTIMEVERIFY != 0 {
        translated |= bitcoinconsensus_backend::VERIFY_CHECKLOCKTIMEVERIFY;
    }
    if flags & VERIFY_CHECKSEQUENCEVERIFY != 0 {
        translated |= bitcoinconsensus_backend::VERIFY_CHECKSEQUENCEVERIFY;
    }
    if flags & VERIFY_WITNESS != 0 {
        translated |= bitcoinconsensus_backend::VERIFY_WITNESS;
    }

    translated
}
