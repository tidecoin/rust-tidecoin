// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use primitives::transaction::OutPoint;

/// Script validation errors produced by the Tidecoin validation engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptError {
    /// Default value used before script execution sets a more specific error.
    Ok,
    /// Generic script failure when no more specific code is available.
    Unknown,
    /// Script evaluation left a false top stack item.
    EvalFalse,
    /// `OP_RETURN` aborted script execution.
    OpReturn,
    /// Script exceeded the maximum allowed byte size.
    ScriptSize,
    /// A pushed element exceeded the maximum allowed byte size.
    PushSize,
    /// Script exceeded the maximum allowed opcode count.
    OpCount,
    /// Script exceeded the maximum allowed stack size.
    StackSize,
    /// Multisig signature count was invalid.
    SigCount,
    /// Multisig public-key count was invalid.
    PubkeyCount,
    /// `OP_VERIFY` failed.
    Verify,
    /// `OP_EQUALVERIFY` failed.
    EqualVerify,
    /// `OP_CHECKSIGVERIFY` failed.
    CheckSigVerify,
    /// `OP_CHECKMULTISIGVERIFY` failed.
    CheckMultiSigVerify,
    /// `OP_NUMEQUALVERIFY` failed.
    NumEqualVerify,
    /// Script contained an invalid opcode.
    BadOpcode,
    /// `OP_CODESEPARATOR` was disallowed by the active flags.
    OpCodeSeparator,
    /// Script used a disabled opcode.
    DisabledOpcode,
    /// Script attempted an invalid main-stack operation.
    InvalidStackOperation,
    /// Script attempted an invalid alt-stack operation.
    InvalidAltstackOperation,
    /// Script conditionals were unbalanced.
    UnbalancedConditional,
    /// Locktime argument was negative.
    NegativeLockTime,
    /// Locktime requirement was not satisfied.
    UnsatisfiedLockTime,
    /// Signature hash type was invalid for the current validation path.
    SigHashType,
    /// Noncanonical historical Falcon signature (relay policy).
    SigFalconEncoding,
    /// Non-minimal pushdata encoding was used when forbidden.
    MinimalData,
    /// `scriptSig` was not push-only when required.
    SigPushOnly,
    /// Dummy stack argument for multisig was not null.
    SigNullDummy,
    /// Cleanstack rule was violated.
    CleanStack,
    /// `MINIMALIF` rule was violated.
    MinimalIf,
    /// `NULLFAIL` rule was violated.
    NullFail,
    /// Upgradable NOPs were discouraged and encountered.
    DiscourageUpgradableNops,
    /// Upgradable witness programs were discouraged and encountered.
    DiscourageUpgradableWitnessProgram,
    /// Witness program length did not match the expected form.
    WitnessProgramWrongLength,
    /// Witness program required witness items but found none.
    WitnessProgramWitnessEmpty,
    /// Witness program did not match the executed witness script.
    WitnessProgramMismatch,
    /// Native witness spend was malleated.
    WitnessMalleated,
    /// P2SH-wrapped witness spend was malleated.
    WitnessMalleatedP2SH,
    /// Unexpected witness data was present.
    WitnessUnexpected,
    /// Signature find-and-delete was disallowed by the active flags.
    SigFindAndDelete,
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ok => "OK",
            Self::Unknown => "UNKNOWN",
            Self::EvalFalse => "EVAL_FALSE",
            Self::OpReturn => "OP_RETURN",
            Self::ScriptSize => "SCRIPT_SIZE",
            Self::PushSize => "PUSH_SIZE",
            Self::OpCount => "OP_COUNT",
            Self::StackSize => "STACK_SIZE",
            Self::SigCount => "SIG_COUNT",
            Self::PubkeyCount => "PUBKEY_COUNT",
            Self::Verify => "VERIFY",
            Self::EqualVerify => "EQUALVERIFY",
            Self::CheckSigVerify => "CHECKSIGVERIFY",
            Self::CheckMultiSigVerify => "CHECKMULTISIGVERIFY",
            Self::NumEqualVerify => "NUMEQUALVERIFY",
            Self::BadOpcode => "BAD_OPCODE",
            Self::OpCodeSeparator => "OP_CODESEPARATOR",
            Self::DisabledOpcode => "DISABLED_OPCODE",
            Self::InvalidStackOperation => "INVALID_STACK_OPERATION",
            Self::InvalidAltstackOperation => "INVALID_ALTSTACK_OPERATION",
            Self::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            Self::NegativeLockTime => "NEGATIVE_LOCKTIME",
            Self::UnsatisfiedLockTime => "UNSATISFIED_LOCKTIME",
            Self::SigHashType => "SIG_HASHTYPE",
            Self::SigFalconEncoding => "SIG_FALCON_ENCODING",
            Self::MinimalData => "MINIMALDATA",
            Self::SigPushOnly => "SIG_PUSHONLY",
            Self::SigNullDummy => "SIG_NULLDUMMY",
            Self::CleanStack => "CLEANSTACK",
            Self::MinimalIf => "MINIMALIF",
            Self::NullFail => "NULLFAIL",
            Self::DiscourageUpgradableNops => "DISCOURAGE_UPGRADABLE_NOPS",
            Self::DiscourageUpgradableWitnessProgram => "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            Self::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            Self::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            Self::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            Self::WitnessMalleated => "WITNESS_MALLEATED",
            Self::WitnessMalleatedP2SH => "WITNESS_MALLEATED_P2SH",
            Self::WitnessUnexpected => "WITNESS_UNEXPECTED",
            Self::SigFindAndDelete => "SIG_FINDANDDELETE",
        };
        f.write_str(s)
    }
}

/// High-level validation errors produced by the Tidecoin validation engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TidecoinValidationError {
    /// Script execution reached the consensus engine and failed with a specific
    /// script error.
    ///
    /// Callers should treat this as a consensus-invalid spend for the selected
    /// script, witness, amount, and flag combination rather than as malformed
    /// caller input.
    Script(ScriptError),
    /// The requested input index does not exist in the spending transaction.
    ///
    /// This indicates a caller-side setup error. Retrying with the same input
    /// index and transaction will fail again.
    InvalidInputIndex {
        /// The requested input index.
        index: usize,
        /// The total number of inputs in the spending transaction.
        inputs: usize,
    },
    /// Script verification flags were invalid.
    ///
    /// This indicates the caller supplied unsupported or inconsistent
    /// verification bits rather than a consensus-invalid script.
    InvalidFlags,
    /// Input amount is required for the selected witness verification path.
    ///
    /// This indicates the caller attempted a witness-aware verification path
    /// without providing the spent output amount required by the engine.
    AmountRequired,
    /// A spent output needed for validation was missing.
    ///
    /// This indicates required prevout state was unavailable at the engine
    /// boundary. It is a missing-context error, not a script failure.
    MissingSpentOutput(OutPoint),
    /// Supplied previous-output context is inconsistent.
    SpentOutputs(crate::SpentOutputsError),
}

impl fmt::Display for TidecoinValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Script(err) => write!(f, "script validation failed: {}", err),
            Self::InvalidInputIndex { index, inputs } => {
                write!(
                    f,
                    "input index {} out of bounds for transaction with {} inputs",
                    index, inputs
                )
            }
            Self::InvalidFlags => f.write_str("script verification flags are invalid"),
            Self::AmountRequired => {
                f.write_str("input amount is required if witness verification is used")
            }
            Self::SpentOutputs(err) => err.fmt(f),
            Self::MissingSpentOutput(outpoint) => {
                write!(f, "missing spent output {:?}", outpoint)
            }
        }
    }
}

impl From<ScriptError> for TidecoinValidationError {
    fn from(value: ScriptError) -> Self {
        Self::Script(value)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TidecoinValidationError {}

impl From<crate::SpentOutputsError> for TidecoinValidationError {
    fn from(value: crate::SpentOutputsError) -> Self {
        Self::SpentOutputs(value)
    }
}
