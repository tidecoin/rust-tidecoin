// SPDX-License-Identifier: CC0-1.0

use core::fmt;

/// Error returned by the shared Tidecoin node parity harness.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeParityError {
    /// The configured Tidecoin node checkout is missing or malformed.
    Environment(&'static str),
    /// A required C-string conversion failed.
    InvalidCString(&'static str),
    /// A native bridge call returned an unexpected failure mode.
    BridgeFailure(&'static str),
    /// The original-node process could not produce an authenticated verdict.
    Oracle(String),
    /// The node decoder rejected the input before validation could run.
    NodeDecode(String),
    /// The original node rejected the supplied block or header.
    NodeValidation {
        /// Node reject reason.
        reason: String,
        /// Node BlockValidationResult discriminant.
        result: i32,
    },
    /// A Tidecoin-node script verification call returned a script error.
    Script(ScriptError),
}

impl fmt::Display for NodeParityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment(msg) => f.write_str(msg),
            Self::InvalidCString(name) => write!(f, "failed to build C string for {}", name),
            Self::BridgeFailure(name) => {
                write!(f, "tidecoin node parity bridge call failed: {}", name)
            }
            Self::Script(err) => write!(f, "script validation failed: {}", err),
            Self::NodeDecode(err) => write!(f, "node decoding failed: {err}"),
            Self::Oracle(err) => write!(f, "original node oracle failed: {err}"),
            Self::NodeValidation { reason, result } => {
                write!(f, "node rejected: {reason} (result {result})")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NodeParityError {}

/// Tidecoin-node script error codes exposed through the node parity bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScriptError {
    /// `SCRIPT_ERR_OK`
    Ok,
    /// `SCRIPT_ERR_UNKNOWN_ERROR`
    UnknownError,
    /// `SCRIPT_ERR_EVAL_FALSE`
    EvalFalse,
    /// `SCRIPT_ERR_OP_RETURN`
    OpReturn,
    /// `SCRIPT_ERR_SCRIPT_SIZE`
    ScriptSize,
    /// `SCRIPT_ERR_PUSH_SIZE`
    PushSize,
    /// `SCRIPT_ERR_OP_COUNT`
    OpCount,
    /// `SCRIPT_ERR_STACK_SIZE`
    StackSize,
    /// `SCRIPT_ERR_SIG_COUNT`
    SigCount,
    /// `SCRIPT_ERR_PUBKEY_COUNT`
    PubkeyCount,
    /// `SCRIPT_ERR_VERIFY`
    Verify,
    /// `SCRIPT_ERR_EQUALVERIFY`
    EqualVerify,
    /// `SCRIPT_ERR_CHECKMULTISIGVERIFY`
    CheckMultisigVerify,
    /// `SCRIPT_ERR_CHECKSIGVERIFY`
    CheckSigVerify,
    /// `SCRIPT_ERR_NUMEQUALVERIFY`
    NumEqualVerify,
    /// `SCRIPT_ERR_BAD_OPCODE`
    BadOpcode,
    /// `SCRIPT_ERR_DISABLED_OPCODE`
    DisabledOpcode,
    /// `SCRIPT_ERR_INVALID_STACK_OPERATION`
    InvalidStackOperation,
    /// `SCRIPT_ERR_INVALID_ALTSTACK_OPERATION`
    InvalidAltstackOperation,
    /// `SCRIPT_ERR_UNBALANCED_CONDITIONAL`
    UnbalancedConditional,
    /// `SCRIPT_ERR_NEGATIVE_LOCKTIME`
    NegativeLocktime,
    /// `SCRIPT_ERR_UNSATISFIED_LOCKTIME`
    UnsatisfiedLocktime,
    /// `SCRIPT_ERR_SIG_HASHTYPE`
    SigHashType,
    /// Noncanonical historical Falcon signature (relay policy).
    SigFalconEncoding,
    /// `SCRIPT_ERR_MINIMALDATA`
    MinimalData,
    /// `SCRIPT_ERR_SIG_PUSHONLY`
    SigPushOnly,
    /// `SCRIPT_ERR_SIG_HIGH_S`
    SigHighS,
    /// `SCRIPT_ERR_SIG_NULLDUMMY`
    SigNullDummy,
    /// `SCRIPT_ERR_PUBKEYTYPE`
    PubkeyType,
    /// `SCRIPT_ERR_CLEANSTACK`
    Cleanstack,
    /// `SCRIPT_ERR_MINIMALIF`
    MinimalIf,
    /// `SCRIPT_ERR_NULLFAIL`
    NullFail,
    /// `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS`
    DiscourageUpgradableNops,
    /// `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`
    DiscourageUpgradableWitnessProgram,
    /// `SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH`
    WitnessProgramWrongLength,
    /// `SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY`
    WitnessProgramWitnessEmpty,
    /// `SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH`
    WitnessProgramMismatch,
    /// `SCRIPT_ERR_WITNESS_MALLEATED`
    WitnessMalleated,
    /// `SCRIPT_ERR_WITNESS_MALLEATED_P2SH`
    WitnessMalleatedP2sh,
    /// `SCRIPT_ERR_WITNESS_UNEXPECTED`
    WitnessUnexpected,
    /// `SCRIPT_ERR_OP_CODESEPARATOR`
    OpCodeSeparator,
    /// `SCRIPT_ERR_SIG_FINDANDDELETE`
    SigFindAndDelete,
}

impl ScriptError {
    /// Maps a raw Tidecoin-node FFI script-error code into the shared enum.
    /// Codes outside `ScriptError_t` become `UnknownError`; use
    /// [`Self::try_from_ffi`] where an unexpected code must be detected.
    pub fn from_ffi(code: i32) -> Self {
        Self::try_from_ffi(code).unwrap_or(Self::UnknownError)
    }

    /// Maps a raw `ScriptError_t` code, returning `None` outside the known range.
    pub fn try_from_ffi(code: i32) -> Option<Self> {
        Some(match code {
            0 => Self::Ok,
            1 => Self::UnknownError,
            2 => Self::EvalFalse,
            3 => Self::OpReturn,
            4 => Self::ScriptSize,
            5 => Self::PushSize,
            6 => Self::OpCount,
            7 => Self::StackSize,
            8 => Self::SigCount,
            9 => Self::PubkeyCount,
            10 => Self::Verify,
            11 => Self::EqualVerify,
            12 => Self::CheckMultisigVerify,
            13 => Self::CheckSigVerify,
            14 => Self::NumEqualVerify,
            15 => Self::BadOpcode,
            16 => Self::DisabledOpcode,
            17 => Self::InvalidStackOperation,
            18 => Self::InvalidAltstackOperation,
            19 => Self::UnbalancedConditional,
            20 => Self::NegativeLocktime,
            21 => Self::UnsatisfiedLocktime,
            22 => Self::SigHashType,
            23 => Self::MinimalData,
            24 => Self::SigPushOnly,
            25 => Self::SigHighS,
            26 => Self::SigNullDummy,
            27 => Self::PubkeyType,
            28 => Self::Cleanstack,
            29 => Self::MinimalIf,
            30 => Self::NullFail,
            31 => Self::DiscourageUpgradableNops,
            32 => Self::DiscourageUpgradableWitnessProgram,
            33 => Self::WitnessProgramWrongLength,
            34 => Self::WitnessProgramWitnessEmpty,
            35 => Self::WitnessProgramMismatch,
            36 => Self::WitnessMalleated,
            37 => Self::WitnessMalleatedP2sh,
            38 => Self::WitnessUnexpected,
            39 => Self::OpCodeSeparator,
            40 => Self::SigFindAndDelete,
            41 => Self::SigFalconEncoding,
            _ => return None,
        })
    }

    /// Parses the display-name form used in Tidecoin node JSON fixtures.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "OK" => Self::Ok,
            "UNKNOWN_ERROR" => Self::UnknownError,
            "EVAL_FALSE" => Self::EvalFalse,
            "OP_RETURN" => Self::OpReturn,
            "SCRIPT_SIZE" => Self::ScriptSize,
            "PUSH_SIZE" => Self::PushSize,
            "OP_COUNT" => Self::OpCount,
            "STACK_SIZE" => Self::StackSize,
            "SIG_COUNT" => Self::SigCount,
            "PUBKEY_COUNT" => Self::PubkeyCount,
            "VERIFY" => Self::Verify,
            "EQUALVERIFY" => Self::EqualVerify,
            "CHECKMULTISIGVERIFY" => Self::CheckMultisigVerify,
            "CHECKSIGVERIFY" => Self::CheckSigVerify,
            "NUMEQUALVERIFY" => Self::NumEqualVerify,
            "BAD_OPCODE" => Self::BadOpcode,
            "DISABLED_OPCODE" => Self::DisabledOpcode,
            "INVALID_STACK_OPERATION" => Self::InvalidStackOperation,
            "INVALID_ALTSTACK_OPERATION" => Self::InvalidAltstackOperation,
            "UNBALANCED_CONDITIONAL" => Self::UnbalancedConditional,
            "NEGATIVE_LOCKTIME" => Self::NegativeLocktime,
            "UNSATISFIED_LOCKTIME" => Self::UnsatisfiedLocktime,
            "SIG_HASHTYPE" => Self::SigHashType,
            "SIG_FALCON_ENCODING" => Self::SigFalconEncoding,
            "MINIMALDATA" => Self::MinimalData,
            "SIG_PUSHONLY" => Self::SigPushOnly,
            "SIG_HIGH_S" => Self::SigHighS,
            "SIG_NULLDUMMY" => Self::SigNullDummy,
            "PUBKEYTYPE" => Self::PubkeyType,
            "CLEANSTACK" => Self::Cleanstack,
            "MINIMALIF" => Self::MinimalIf,
            "NULLFAIL" => Self::NullFail,
            "DISCOURAGE_UPGRADABLE_NOPS" => Self::DiscourageUpgradableNops,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => Self::DiscourageUpgradableWitnessProgram,
            "WITNESS_PROGRAM_WRONG_LENGTH" => Self::WitnessProgramWrongLength,
            "WITNESS_PROGRAM_WITNESS_EMPTY" => Self::WitnessProgramWitnessEmpty,
            "WITNESS_PROGRAM_MISMATCH" => Self::WitnessProgramMismatch,
            "WITNESS_MALLEATED" => Self::WitnessMalleated,
            "WITNESS_MALLEATED_P2SH" => Self::WitnessMalleatedP2sh,
            "WITNESS_UNEXPECTED" => Self::WitnessUnexpected,
            "OP_CODESEPARATOR" => Self::OpCodeSeparator,
            "SIG_FINDANDDELETE" => Self::SigFindAndDelete,
            _ => return None,
        })
    }
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ok => "OK",
            Self::UnknownError => "UNKNOWN_ERROR",
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
            Self::CheckMultisigVerify => "CHECKMULTISIGVERIFY",
            Self::CheckSigVerify => "CHECKSIGVERIFY",
            Self::NumEqualVerify => "NUMEQUALVERIFY",
            Self::BadOpcode => "BAD_OPCODE",
            Self::DisabledOpcode => "DISABLED_OPCODE",
            Self::InvalidStackOperation => "INVALID_STACK_OPERATION",
            Self::InvalidAltstackOperation => "INVALID_ALTSTACK_OPERATION",
            Self::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            Self::NegativeLocktime => "NEGATIVE_LOCKTIME",
            Self::UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
            Self::SigHashType => "SIG_HASHTYPE",
            Self::SigFalconEncoding => "SIG_FALCON_ENCODING",
            Self::MinimalData => "MINIMALDATA",
            Self::SigPushOnly => "SIG_PUSHONLY",
            Self::SigHighS => "SIG_HIGH_S",
            Self::SigNullDummy => "SIG_NULLDUMMY",
            Self::PubkeyType => "PUBKEYTYPE",
            Self::Cleanstack => "CLEANSTACK",
            Self::MinimalIf => "MINIMALIF",
            Self::NullFail => "NULLFAIL",
            Self::DiscourageUpgradableNops => "DISCOURAGE_UPGRADABLE_NOPS",
            Self::DiscourageUpgradableWitnessProgram => "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            Self::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            Self::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            Self::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            Self::WitnessMalleated => "WITNESS_MALLEATED",
            Self::WitnessMalleatedP2sh => "WITNESS_MALLEATED_P2SH",
            Self::WitnessUnexpected => "WITNESS_UNEXPECTED",
            Self::OpCodeSeparator => "OP_CODESEPARATOR",
            Self::SigFindAndDelete => "SIG_FINDANDDELETE",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ScriptError;

    /// Original `ScriptError_t` has 42 values, `SCRIPT_ERR_OK = 0` through
    /// `SCRIPT_ERR_SIG_FALCON_ENCODING = 41`; `SCRIPT_ERR_ERROR_COUNT` is 42.
    #[test]
    fn ffi_codes_cover_exactly_the_original_enum() {
        let mut seen = Vec::new();
        for code in 0..42 {
            let error = ScriptError::try_from_ffi(code).expect("known code");
            assert!(!seen.contains(&error), "code {code} reuses {error}");
            assert_eq!(ScriptError::from_name(&error.to_string()), Some(error), "code {code}");
            seen.push(error);
        }
        for code in [-1, 42, i32::MAX] {
            assert_eq!(ScriptError::try_from_ffi(code), None);
            assert_eq!(ScriptError::from_ffi(code), ScriptError::UnknownError);
        }
    }
}
