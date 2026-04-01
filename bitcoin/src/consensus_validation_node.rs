// SPDX-License-Identifier: CC0-1.0

#![allow(missing_docs)]

use core::ffi::{c_char, c_int};
use core::fmt;

use std::ffi::CString;

use crate::amount::Amount;
#[cfg(test)]
use crate::consensus::encode::deserialize_hex;
use crate::consensus::encode::serialize_hex;
use crate::crypto::pq::PqPublicKey;
use crate::opcodes::all::OP_SHA512;
use crate::opcodes::Opcode;
#[cfg(test)]
use crate::prelude::Vec;
#[cfg(test)]
use crate::script::{ScriptPubKeyBuf, ScriptSigBuf};
use crate::script::{Instruction, Script, ScriptExt as _, ScriptPubKey, WitnessScript};
use crate::transaction::{OutPoint, Transaction};
use crate::witness::Witness;

pub const VERIFY_NONE: u32 = 0;
pub const VERIFY_P2SH: u32 = 1 << 0;
pub const VERIFY_STRICTENC: u32 = 0;
pub const VERIFY_NULLDUMMY: u32 = 1 << 1;
pub const VERIFY_SIGPUSHONLY: u32 = 1 << 2;
pub const VERIFY_MINIMALDATA: u32 = 1 << 3;
pub const VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 1 << 4;
pub const VERIFY_CLEANSTACK: u32 = 1 << 5;
pub const VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 6;
pub const VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 7;
pub const VERIFY_WITNESS: u32 = 1 << 8;
pub const VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: u32 = 1 << 9;
pub const VERIFY_MINIMALIF: u32 = 1 << 10;
pub const VERIFY_NULLFAIL: u32 = 1 << 11;
pub const VERIFY_CONST_SCRIPTCODE: u32 = 1 << 12;
pub const VERIFY_PQ_STRICT: u32 = 1 << 13;
pub const VERIFY_WITNESS_V1_512: u32 = 1 << 14;
pub const VERIFY_SHA512: u32 = 1 << 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScriptError {
    Ok,
    UnknownError,
    EvalFalse,
    OpReturn,
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    NegativeLocktime,
    UnsatisfiedLocktime,
    SigHashType,
    MinimalData,
    SigPushOnly,
    SigHighS,
    SigNullDummy,
    PubkeyType,
    Cleanstack,
    MinimalIf,
    NullFail,
    DiscourageUpgradableNops,
    DiscourageUpgradableWitnessProgram,
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2sh,
    WitnessUnexpected,
    OpCodeSeparator,
    SigFindAndDelete,
}

impl ScriptError {
    fn from_ffi(code: i32) -> Self {
        match code {
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
            _ => Self::UnknownError,
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TidecoinValidationError {
    Script(ScriptError),
    InvalidInputIndex { index: usize, inputs: usize },
    UnsupportedScript,
    MissingSpentOutput(OutPoint),
    BridgeFailure(&'static str),
}

impl fmt::Display for TidecoinValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Script(err) => write!(f, "script validation failed: {}", err),
            Self::InvalidInputIndex { index, inputs } => {
                write!(f, "input index {} out of bounds for transaction with {} inputs", index, inputs)
            }
            Self::UnsupportedScript => f.write_str("script requires unsupported validation path"),
            Self::MissingSpentOutput(outpoint) => write!(f, "missing spent output {}", outpoint),
            Self::BridgeFailure(name) => write!(f, "tidecoin node validation bridge call failed: {}", name),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TidecoinValidationError {}

unsafe extern "C" {
    fn tidecoin_node_verify_tx_input(
        tx_hex: *const c_char,
        input_index: usize,
        prev_script: *const u8,
        prev_script_len: usize,
        amount: i64,
        flags: u32,
        script_error_out: *mut c_int,
    ) -> c_int;
}

#[cfg(test)]
unsafe extern "C" {
    fn tidecoin_node_check_transaction(tx_hex: *const c_char) -> c_int;
    fn tidecoin_node_parse_script_asm(
        script_asm: *const c_char,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    fn tidecoin_node_verify_script_case(
        script_sig: *const u8,
        script_sig_len: usize,
        script_pubkey: *const u8,
        script_pubkey_len: usize,
        witness_items: *const *const u8,
        witness_lens: *const usize,
        witness_count: usize,
        amount: i64,
        flags: u32,
        script_error_out: *mut c_int,
    ) -> c_int;
}

#[allow(dead_code)]
pub(crate) fn should_use_tidecoin_validation(
    script_pubkey: &ScriptPubKey,
    tx: &Transaction,
    index: usize,
    _flags: u32,
) -> bool {
    if script_pubkey.is_p2wsh512()
        || script_contains_pq_material(script_pubkey)
        || script_contains_opcode(script_pubkey, OP_SHA512)
    {
        return true;
    }

    let Some(input) = tx.inputs.get(index) else {
        return false;
    };

    script_contains_pq_material(&input.script_sig)
        || witness_contains_pq_material(&input.witness)
        || witness_contains_opcode_script(&input.witness, OP_SHA512)
}

pub(crate) fn verify_script_input(
    script_pubkey: &ScriptPubKey,
    index: usize,
    amount: Amount,
    tx: &Transaction,
    flags: u32,
) -> Result<(), TidecoinValidationError> {
    if index >= tx.inputs.len() {
        return Err(TidecoinValidationError::InvalidInputIndex {
            index,
            inputs: tx.inputs.len(),
        });
    }

    let tx_hex = CString::new(serialize_hex(tx))
        .map_err(|_| TidecoinValidationError::BridgeFailure("serialize_hex"))?;
    let mut script_error = 0;
    let rc = unsafe {
        tidecoin_node_verify_tx_input(
            tx_hex.as_ptr(),
            index,
            script_pubkey.as_bytes().as_ptr(),
            script_pubkey.len(),
            amount.to_sat().try_into().unwrap(),
            normalize_flags(flags),
            &mut script_error,
        )
    };

    match rc {
        1 => Ok(()),
        0 => {
            let err = ScriptError::from_ffi(script_error);
            Err(TidecoinValidationError::Script(if err == ScriptError::Ok {
                ScriptError::UnknownError
            } else {
                err
            }))
        }
        _ => Err(TidecoinValidationError::BridgeFailure(
            "tidecoin_node_verify_tx_input",
        )),
    }
}

#[cfg(test)]
fn check_transaction_sanity(tx: &Transaction) -> Result<(), TidecoinValidationError> {
    let tx_hex = CString::new(serialize_hex(tx))
        .map_err(|_| TidecoinValidationError::BridgeFailure("serialize_hex"))?;
    let rc = unsafe { tidecoin_node_check_transaction(tx_hex.as_ptr()) };
    match rc {
        1 => Ok(()),
        0 => Err(TidecoinValidationError::BridgeFailure("invalid transaction")),
        _ => Err(TidecoinValidationError::BridgeFailure(
            "tidecoin_node_check_transaction",
        )),
    }
}

fn normalize_flags(mut flags: u32) -> u32 {
    if flags & VERIFY_CLEANSTACK != 0 {
        flags |= VERIFY_P2SH | VERIFY_WITNESS;
    }
    flags
}

#[allow(dead_code)]
fn script_contains_opcode<T>(
    script: &Script<T>,
    opcode: Opcode,
) -> bool {
    script
        .instructions()
        .any(|ins| matches!(ins, Ok(Instruction::Op(op)) if op == opcode))
}

#[allow(dead_code)]
fn script_contains_pq_material<T>(script: &Script<T>) -> bool {
    script.instructions().any(|ins| match ins {
        Ok(Instruction::PushBytes(bytes)) => PqPublicKey::from_prefixed_slice(bytes.as_bytes()).is_ok(),
        _ => false,
    })
}

#[allow(dead_code)]
fn witness_contains_pq_material(witness: &Witness) -> bool {
    witness.iter().any(|item| PqPublicKey::from_prefixed_slice(item).is_ok())
}

#[allow(dead_code)]
fn witness_contains_opcode_script(witness: &Witness, opcode: Opcode) -> bool {
    witness
        .last()
        .map(WitnessScript::from_bytes)
        .is_some_and(|script| script_contains_opcode(script, opcode))
}

#[cfg(test)]
fn parse_script_asm(script_asm: &str) -> Result<Vec<u8>, TidecoinValidationError> {
    let script_asm = CString::new(script_asm)
        .map_err(|_| TidecoinValidationError::BridgeFailure("CString::new"))?;
    let mut out_len = 0usize;
    let probe = unsafe { tidecoin_node_parse_script_asm(script_asm.as_ptr(), core::ptr::null_mut(), &mut out_len) };
    if probe != 0 {
        return Err(TidecoinValidationError::BridgeFailure(
            "tidecoin_node_parse_script_asm",
        ));
    }
    let mut out = vec![0u8; out_len];
    let rc = unsafe { tidecoin_node_parse_script_asm(script_asm.as_ptr(), out.as_mut_ptr(), &mut out_len) };
    if rc != 1 {
        return Err(TidecoinValidationError::BridgeFailure(
            "tidecoin_node_parse_script_asm",
        ));
    }
    out.truncate(out_len);
    Ok(out)
}

#[cfg(test)]
fn verify_script_case(
    script_sig: &ScriptSigBuf,
    script_pubkey: &ScriptPubKeyBuf,
    witness: &Witness,
    amount: Amount,
    flags: u32,
) -> Result<(), TidecoinValidationError> {
    let witness_items: Vec<*const u8> = witness.iter().map(|item| item.as_ptr()).collect();
    let witness_lens: Vec<usize> = witness.iter().map(|item| item.len()).collect();
    let mut script_error = 0;
    let rc = unsafe {
        tidecoin_node_verify_script_case(
            script_sig.as_bytes().as_ptr(),
            script_sig.len(),
            script_pubkey.as_bytes().as_ptr(),
            script_pubkey.len(),
            witness_items.as_ptr(),
            witness_lens.as_ptr(),
            witness.len(),
            amount.to_sat().try_into().unwrap(),
            normalize_flags(flags),
            &mut script_error,
        )
    };

    match rc {
        1 => Ok(()),
        0 => {
            let err = ScriptError::from_ffi(script_error);
            Err(TidecoinValidationError::Script(if err == ScriptError::Ok {
                ScriptError::UnknownError
            } else {
                err
            }))
        }
        _ => Err(TidecoinValidationError::BridgeFailure(
            "tidecoin_node_verify_script_case",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::PathBuf;

    use hashes::sha256;
    use hashes::sha512;
    use serde_json::Value;

    use super::*;
    use crate::absolute;
    use crate::crypto::pq::{PqPublicKey, PqScheme, PqSecretKey, PqSignature};
    use crate::crypto::sighash::{EcdsaSighashType, SighashCache};
    use crate::opcodes::all::{
        OP_ADD, OP_CHECKMULTISIG, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY,
        OP_FROMALTSTACK, OP_HASH160, OP_NUMEQUAL, OP_SHA256, OP_SHA512, OP_TOALTSTACK, OP_TRUE,
    };
    use crate::script::PushBytesBuf;
    use crate::script::{
        ScriptBufExt as _, ScriptPubKeyBuf, ScriptSigBuf, WitnessScriptBuf,
    };
    use crate::script::ScriptPubKeyBufExt as _;
    use crate::transaction::{self, OutPoint, Transaction, TxIn};
    use crate::{Amount, Sequence, TxOut, Txid, Witness};

    fn node_repo_dir() -> PathBuf {
        if let Some(path) = std::env::var_os("TIDECOIN_NODE_REPO") {
            return PathBuf::from(path);
        }
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tidecoin-node")
    }

    fn test_data_path(name: &str) -> PathBuf { node_repo_dir().join("src/test/data").join(name) }

    fn read_json(name: &str) -> Value {
        let path = test_data_path(name);
        let data = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
    }

    fn tagged_seed(tag: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| tag ^ (i as u8).wrapping_mul(131))
            .collect()
    }

    fn deterministic_keypair(scheme: PqScheme, tag: u8) -> (PqPublicKey, PqSecretKey) {
        let seed = tagged_seed(tag, scheme.deterministic_seed_len());
        scheme.generate_keypair_from_seed(&seed).unwrap()
    }

    fn tx_template(input_count: usize) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: (0..input_count)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([i as u8 + 1; 32]),
                        vout: i as u32,
                    },
                    sequence: Sequence::MAX,
                    ..TxIn::EMPTY_COINBASE
                })
                .collect(),
            outputs: vec![TxOut {
                amount: Amount::from_sat_u32(1),
                script_pubkey: ScriptPubKeyBuf::new(),
            }],
        }
    }

    fn push_bytes(data: &[u8]) -> PushBytesBuf {
        PushBytesBuf::try_from(data.to_vec()).unwrap()
    }

    fn sighash_all_byte() -> u8 {
        EcdsaSighashType::All.to_u32() as u8
    }

    fn witness_v0_sig(
        tx: &Transaction,
        input_index: usize,
        amount: Amount,
        witness_script: &WitnessScriptBuf,
        sk: &PqSecretKey,
        _legacy: bool,
    ) -> Vec<u8> {
        let mut cache = SighashCache::new(tx);
        let sighash = cache
            .p2wsh_signature_hash(
                input_index,
                witness_script.as_script(),
                amount,
                EcdsaSighashType::All,
            )
            .unwrap();
        let sig = PqSignature::sign_msg32(sighash.as_byte_array(), sk).unwrap();
        let mut out = sig.as_bytes().to_vec();
        out.push(sighash_all_byte());
        out
    }

    fn witness_v1_512_sig(
        tx: &Transaction,
        input_index: usize,
        amount: Amount,
        witness_script: &WitnessScriptBuf,
        sk: &PqSecretKey,
        legacy: bool,
    ) -> Vec<u8> {
        let mut cache = SighashCache::new(tx);
        let sighash = cache
            .p2wsh512_signature_hash(
                input_index,
                witness_script.as_script(),
                amount,
                EcdsaSighashType::All,
            )
            .unwrap();
        let sig = if legacy {
            PqSignature::sign_msg64_legacy(sighash.as_byte_array(), sk).unwrap()
        } else {
            PqSignature::sign_msg64(sighash.as_byte_array(), sk).unwrap()
        };
        let mut out = sig.as_bytes().to_vec();
        out.push(sighash_all_byte());
        out
    }

    fn base_sig(
        tx: &Transaction,
        input_index: usize,
        script_pubkey: &ScriptPubKeyBuf,
        sk: &PqSecretKey,
        legacy: bool,
    ) -> Vec<u8> {
        let cache = SighashCache::new(tx);
        let sighash = cache
            .legacy_signature_hash(
                input_index,
                script_pubkey.as_script(),
                EcdsaSighashType::All.to_u32(),
            )
            .unwrap();
        let sig = if legacy {
            PqSignature::sign_msg32_legacy(sighash.as_byte_array(), sk).unwrap()
        } else {
            PqSignature::sign_msg32(sighash.as_byte_array(), sk).unwrap()
        };
        let mut out = sig.as_bytes().to_vec();
        out.push(sighash_all_byte());
        out
    }

    fn multisig_witness_script(pubkeys: &[PqPublicKey], m: i32) -> WitnessScriptBuf {
        let mut builder = ScriptPubKeyBuf::builder().push_int(m).unwrap();
        for pubkey in pubkeys {
            builder = builder.push_slice(push_bytes(&pubkey.to_prefixed_bytes()));
        }
        let script = builder
            .push_int(pubkeys.len() as i32)
            .unwrap()
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        WitnessScriptBuf::from_bytes(script.into_bytes())
    }

    fn committed_hash_witness_script(pubkeys: &[PqPublicKey], m: i32) -> WitnessScriptBuf {
        let commitments: Vec<[u8; 32]> = pubkeys
            .iter()
            .map(|pubkey| sha256::Hash::hash(&pubkey.to_prefixed_bytes()).to_byte_array())
            .collect();

        let mut builder = ScriptPubKeyBuf::builder();
        for (idx, commitment) in commitments.iter().enumerate().rev() {
            builder = builder
                .push_opcode(OP_DUP)
                .push_opcode(OP_SHA256)
                .push_slice(push_bytes(commitment))
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_CHECKSIG);
            if idx != 0 {
                builder = builder.push_opcode(OP_TOALTSTACK);
            }
        }
        for _ in 0..commitments.len().saturating_sub(1) {
            builder = builder.push_opcode(OP_FROMALTSTACK).push_opcode(OP_ADD);
        }
        let script = builder.push_int(m).unwrap().push_opcode(OP_NUMEQUAL).into_script();
        WitnessScriptBuf::from_bytes(script.into_bytes())
    }

    fn direct_p2wsh_script_pubkey(witness_script: &WitnessScriptBuf) -> ScriptPubKeyBuf {
        let program = sha256::Hash::hash(witness_script.as_bytes()).to_byte_array();
        ScriptPubKeyBuf::builder()
            .push_int(0)
            .unwrap()
            .push_slice(program)
            .into_script()
    }

    fn wrapped_p2wsh(script: &WitnessScriptBuf) -> (ScriptPubKeyBuf, ScriptSigBuf) {
        let redeem_script = direct_p2wsh_script_pubkey(script);
        let script_pubkey = ScriptPubKeyBuf::new_p2sh(redeem_script.as_script().script_hash().unwrap());
        let script_sig = ScriptSigBuf::builder()
            .push_slice(push_bytes(redeem_script.as_bytes()))
            .into_script();
        (script_pubkey, script_sig)
    }

    fn signed_multisig_witness(
        tx: &Transaction,
        input_index: usize,
        amount: Amount,
        witness_script: &WitnessScriptBuf,
        signers: &[PqSecretKey],
        legacy: bool,
    ) -> Witness {
        let mut items = Vec::with_capacity(signers.len() + 2);
        items.push(Vec::new());
        for signer in signers {
            items.push(witness_v0_sig(tx, input_index, amount, witness_script, signer, legacy));
        }
        items.push(witness_script.as_bytes().to_vec());
        Witness::from_slice(&items)
    }

    fn signed_committed_hash_witness(
        tx: &Transaction,
        input_index: usize,
        amount: Amount,
        witness_script: &WitnessScriptBuf,
        keys: &[(PqPublicKey, PqSecretKey)],
        sign_count: usize,
        legacy: bool,
    ) -> Witness {
        let mut items = Vec::with_capacity(keys.len() * 2 + 1);
        for (idx, (pubkey, seckey)) in keys.iter().enumerate() {
            if idx < sign_count {
                items.push(witness_v0_sig(tx, input_index, amount, witness_script, seckey, legacy));
            } else {
                items.push(Vec::new());
            }
            items.push(pubkey.to_prefixed_bytes());
        }
        items.push(witness_script.as_bytes().to_vec());
        Witness::from_slice(&items)
    }

    fn parse_script_flags(flags: &str) -> u32 {
        if flags.is_empty() || flags == "NONE" {
            return VERIFY_NONE;
        }

        flags.split(',').fold(VERIFY_NONE, |acc, word| {
            acc | match word {
                "P2SH" => VERIFY_P2SH,
                "SIGPUSHONLY" => VERIFY_SIGPUSHONLY,
                "MINIMALDATA" => VERIFY_MINIMALDATA,
                "NULLDUMMY" => VERIFY_NULLDUMMY,
                "DISCOURAGE_UPGRADABLE_NOPS" => VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
                "CLEANSTACK" => VERIFY_CLEANSTACK,
                "MINIMALIF" => VERIFY_MINIMALIF,
                "NULLFAIL" => VERIFY_NULLFAIL,
                "CHECKLOCKTIMEVERIFY" => VERIFY_CHECKLOCKTIMEVERIFY,
                "CHECKSEQUENCEVERIFY" => VERIFY_CHECKSEQUENCEVERIFY,
                "WITNESS" => VERIFY_WITNESS,
                "SHA512" => VERIFY_SHA512,
                "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                    VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
                }
                "WITNESS_V1_512" => VERIFY_WITNESS_V1_512,
                "CONST_SCRIPTCODE" => VERIFY_CONST_SCRIPTCODE,
                "PQ_STRICT" => VERIFY_PQ_STRICT,
                _ => panic!("unknown verification flag {}", word),
            }
        })
    }

    fn parse_script_error(name: &str) -> ScriptError {
        match name {
            "OK" => ScriptError::Ok,
            "UNKNOWN_ERROR" => ScriptError::UnknownError,
            "EVAL_FALSE" => ScriptError::EvalFalse,
            "OP_RETURN" => ScriptError::OpReturn,
            "SCRIPT_SIZE" => ScriptError::ScriptSize,
            "PUSH_SIZE" => ScriptError::PushSize,
            "OP_COUNT" => ScriptError::OpCount,
            "STACK_SIZE" => ScriptError::StackSize,
            "SIG_COUNT" => ScriptError::SigCount,
            "PUBKEY_COUNT" => ScriptError::PubkeyCount,
            "VERIFY" => ScriptError::Verify,
            "EQUALVERIFY" => ScriptError::EqualVerify,
            "CHECKMULTISIGVERIFY" => ScriptError::CheckMultisigVerify,
            "CHECKSIGVERIFY" => ScriptError::CheckSigVerify,
            "NUMEQUALVERIFY" => ScriptError::NumEqualVerify,
            "BAD_OPCODE" => ScriptError::BadOpcode,
            "DISABLED_OPCODE" => ScriptError::DisabledOpcode,
            "INVALID_STACK_OPERATION" => ScriptError::InvalidStackOperation,
            "INVALID_ALTSTACK_OPERATION" => ScriptError::InvalidAltstackOperation,
            "UNBALANCED_CONDITIONAL" => ScriptError::UnbalancedConditional,
            "NEGATIVE_LOCKTIME" => ScriptError::NegativeLocktime,
            "UNSATISFIED_LOCKTIME" => ScriptError::UnsatisfiedLocktime,
            "SIG_HASHTYPE" => ScriptError::SigHashType,
            "MINIMALDATA" => ScriptError::MinimalData,
            "SIG_PUSHONLY" => ScriptError::SigPushOnly,
            "SIG_HIGH_S" => ScriptError::SigHighS,
            "SIG_NULLDUMMY" => ScriptError::SigNullDummy,
            "PUBKEYTYPE" => ScriptError::PubkeyType,
            "CLEANSTACK" => ScriptError::Cleanstack,
            "MINIMALIF" => ScriptError::MinimalIf,
            "NULLFAIL" => ScriptError::NullFail,
            "DISCOURAGE_UPGRADABLE_NOPS" => ScriptError::DiscourageUpgradableNops,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => ScriptError::DiscourageUpgradableWitnessProgram,
            "WITNESS_PROGRAM_WRONG_LENGTH" => ScriptError::WitnessProgramWrongLength,
            "WITNESS_PROGRAM_WITNESS_EMPTY" => ScriptError::WitnessProgramWitnessEmpty,
            "WITNESS_PROGRAM_MISMATCH" => ScriptError::WitnessProgramMismatch,
            "WITNESS_MALLEATED" => ScriptError::WitnessMalleated,
            "WITNESS_MALLEATED_P2SH" => ScriptError::WitnessMalleatedP2sh,
            "WITNESS_UNEXPECTED" => ScriptError::WitnessUnexpected,
            "OP_CODESEPARATOR" => ScriptError::OpCodeSeparator,
            "SIG_FINDANDDELETE" => ScriptError::SigFindAndDelete,
            _ => panic!("unknown script error {}", name),
        }
    }

    fn parse_hex_bytes(value: &str) -> Vec<u8> {
        if let Some(rest) = value.strip_prefix("0x") {
            crate::hex::decode_to_vec(rest).unwrap()
        } else {
            crate::hex::decode_to_vec(value).unwrap()
        }
    }

    fn parse_witness_and_amount(value: &Value) -> (Witness, Amount) {
        let arr = value.as_array().expect("witness tuple");
        let mut items = Vec::with_capacity(arr.len().saturating_sub(1));
        for item in &arr[..arr.len() - 1] {
            items.push(parse_hex_bytes(item.as_str().expect("witness item")));
        }
        let amount = amount_from_json(&arr[arr.len() - 1]);
        (Witness::from_slice(&items), amount)
    }

    fn amount_from_json(value: &Value) -> Amount {
        if let Some(sats) = value.as_i64() {
            Amount::from_sat(sats.try_into().unwrap()).unwrap()
        } else if let Some(sats) = value.as_u64() {
            Amount::from_sat(sats).unwrap()
        } else if let Some(text) = value.as_str() {
            let btc: f64 = text.parse().unwrap();
            Amount::from_sat((btc * 100_000_000.0).round() as u64).unwrap()
        } else if let Some(btc) = value.as_f64() {
            Amount::from_sat((btc * 100_000_000.0).round() as u64).unwrap()
        } else {
            panic!("unsupported amount json {}", value);
        }
    }

    fn parse_script_sig_asm(value: &str) -> ScriptSigBuf {
        ScriptSigBuf::from_bytes(parse_script_asm(value).unwrap())
    }

    fn parse_script_pubkey_asm(value: &str) -> ScriptPubKeyBuf {
        ScriptPubKeyBuf::from_bytes(parse_script_asm(value).unwrap())
    }

    fn parse_tx_outpoint(txid_hex: &str, vout: u32) -> OutPoint {
        let mut encoded = parse_hex_bytes(txid_hex);
        encoded.reverse();
        encoded.extend_from_slice(&vout.to_le_bytes());
        crate::consensus::deserialize(&encoded).unwrap()
    }

    fn parse_tx_inputs(value: &Value) -> (BTreeMap<OutPoint, TxOut>, Vec<OutPoint>) {
        let mut prevouts = BTreeMap::new();
        let mut order = Vec::new();
        for entry in value.as_array().expect("input vector") {
            let input = entry.as_array().expect("input tuple");
            let outpoint = parse_tx_outpoint(
                input[0].as_str().expect("txid"),
                input[1].as_u64().expect("vout") as u32,
            );
            let txout = TxOut {
                amount: if input.len() >= 4 {
                    amount_from_json(&input[3])
                } else {
                    Amount::from_sat(0).unwrap()
                },
                script_pubkey: parse_script_pubkey_asm(input[2].as_str().expect("script")),
            };
            order.push(outpoint);
            prevouts.insert(outpoint, txout);
        }
        (prevouts, order)
    }

    fn all_consensus_flags() -> Vec<u32> {
        let mut out = Vec::new();
        for i in 0..64u32 {
            let mut flags = VERIFY_NONE;
            if i & 1 != 0 {
                flags |= VERIFY_P2SH;
            }
            if i & 2 != 0 {
                flags |= VERIFY_NULLDUMMY;
            }
            if i & 4 != 0 {
                flags |= VERIFY_CHECKLOCKTIMEVERIFY;
            }
            if i & 8 != 0 {
                flags |= VERIFY_CHECKSEQUENCEVERIFY;
            }
            if i & 16 != 0 {
                flags |= VERIFY_WITNESS;
            }
            if i & 32 != 0 {
                flags |= VERIFY_PQ_STRICT;
            }
            if flags & VERIFY_WITNESS != 0 && flags & VERIFY_P2SH == 0 {
                continue;
            }
            out.push(flags);
        }
        out
    }

    fn fill_flags(mut flags: u32) -> u32 {
        if flags & VERIFY_CLEANSTACK != 0 {
            flags |= VERIFY_WITNESS;
        }
        if flags & VERIFY_WITNESS != 0 {
            flags |= VERIFY_P2SH;
        }
        flags
    }

    #[test]
    fn script_tests_pq_json_roundtrip() {
        let tests = read_json("script_tests_pq.json").as_array().unwrap().clone();
        assert!(!tests.is_empty());

        for (idx, test) in tests.iter().enumerate() {
            let row = test.as_array().unwrap();
            let mut pos = 0usize;
            let (witness, amount) = if row[0].is_array() {
                pos += 1;
                parse_witness_and_amount(&row[0])
            } else {
                (Witness::default(), Amount::from_sat(0).unwrap())
            };
            let script_sig = parse_script_sig_asm(row[pos].as_str().unwrap());
            let script_pubkey = parse_script_pubkey_asm(row[pos + 1].as_str().unwrap());
            let flags = normalize_flags(parse_script_flags(row[pos + 2].as_str().unwrap()));
            let expected = parse_script_error(row[pos + 3].as_str().unwrap());

            let result = verify_script_case(&script_sig, &script_pubkey, &witness, amount, flags);
            match (result, expected) {
                (Ok(()), ScriptError::Ok) => {}
                (Err(TidecoinValidationError::Script(actual)), expected) => {
                    assert_eq!(actual, expected, "script_tests_pq[{}]", idx);
                }
                (other, expected) => panic!("unexpected result {:?} for expected {:?} at {}", other, expected, idx),
            }
        }
    }

    #[test]
    fn tx_valid_pq_json_roundtrip() {
        let tests = read_json("tx_valid_pq.json").as_array().unwrap().clone();
        assert!(!tests.is_empty());

        for (idx, test) in tests.iter().enumerate() {
            let row = test.as_array().unwrap();
            let (prevouts, _) = parse_tx_inputs(&row[0]);
            let tx: Transaction = deserialize_hex(row[1].as_str().unwrap()).unwrap();
            let flags = fill_flags(parse_script_flags(row[2].as_str().unwrap()));

            check_transaction_sanity(&tx).unwrap_or_else(|e| panic!("valid tx sanity failed at {}: {}", idx, e));
            for (input_idx, input) in tx.inputs.iter().enumerate() {
                let spent = prevouts.get(&input.previous_output).unwrap();
                verify_script_input(&spent.script_pubkey, input_idx, spent.amount, &tx, flags)
                    .unwrap_or_else(|e| panic!("tx_valid_pq[{}] input {} failed: {}", idx, input_idx, e));
            }
        }
    }

    #[test]
    fn tx_invalid_pq_json_roundtrip() {
        let tests = read_json("tx_invalid_pq.json").as_array().unwrap().clone();
        assert!(!tests.is_empty());

        for (idx, test) in tests.iter().enumerate() {
            let row = test.as_array().unwrap();
            let (prevouts, _) = parse_tx_inputs(&row[0]);
            let tx: Transaction = deserialize_hex(row[1].as_str().unwrap()).unwrap();
            let flags = row[2].as_str().unwrap();

            if flags == "BADTX" {
                assert!(check_transaction_sanity(&tx).is_err(), "tx_invalid_pq[{}] should be structurally invalid", idx);
                continue;
            }

            let flags = fill_flags(parse_script_flags(flags));
            let mut any_failed = false;
            for (input_idx, input) in tx.inputs.iter().enumerate() {
                let spent = prevouts.get(&input.previous_output).unwrap();
                if verify_script_input(&spent.script_pubkey, input_idx, spent.amount, &tx, flags).is_err() {
                    any_failed = true;
                    break;
                }
            }
            assert!(any_failed, "tx_invalid_pq[{}] unexpectedly passed", idx);
        }
    }

    #[test]
    fn script_assets_json_monotonicity() {
        let tests = read_json("script_assets_test.json").as_array().unwrap().clone();
        assert!(!tests.is_empty());
        let all_flags = all_consensus_flags();

        for (idx, test) in tests.iter().enumerate() {
            let obj = test.as_object().unwrap();
            let mut tx: Transaction = deserialize_hex(obj["tx"].as_str().unwrap()).unwrap();
            let prevouts: Vec<TxOut> = obj["prevouts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| deserialize_hex(entry.as_str().unwrap()).unwrap())
                .collect();
            assert_eq!(prevouts.len(), tx.inputs.len(), "script_assets_test[{}] prevouts/input mismatch", idx);
            let index = obj["index"].as_u64().unwrap() as usize;
            let test_flags = parse_script_flags(obj["flags"].as_str().unwrap());
            let is_final = obj.get("final").and_then(Value::as_bool).unwrap_or(false);

            if let Some(success) = obj.get("success") {
                tx.inputs[index].script_sig =
                    ScriptSigBuf::from_bytes(parse_hex_bytes(success["scriptSig"].as_str().unwrap()));
                let witness_items: Vec<Vec<u8>> = success["witness"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|item| parse_hex_bytes(item.as_str().unwrap()))
                    .collect();
                tx.inputs[index].witness = Witness::from_slice(&witness_items);

                for flags in &all_flags {
                    if is_final || (*flags & test_flags) == *flags {
                        let prevout = &prevouts[index];
                        verify_script_input(&prevout.script_pubkey, index, prevout.amount, &tx, *flags)
                            .unwrap_or_else(|e| panic!("script_assets_test[{}] success failed under {:x}: {}", idx, flags, e));
                    }
                }
            }

            if let Some(failure) = obj.get("failure") {
                tx.inputs[index].script_sig =
                    ScriptSigBuf::from_bytes(parse_hex_bytes(failure["scriptSig"].as_str().unwrap()));
                let witness_items: Vec<Vec<u8>> = failure["witness"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|item| parse_hex_bytes(item.as_str().unwrap()))
                    .collect();
                tx.inputs[index].witness = Witness::from_slice(&witness_items);

                for flags in &all_flags {
                    if (*flags & test_flags) == test_flags {
                        let prevout = &prevouts[index];
                        assert!(
                            verify_script_input(&prevout.script_pubkey, index, prevout.amount, &tx, *flags).is_err(),
                            "script_assets_test[{}] failure unexpectedly passed under {:x}",
                            idx,
                            flags
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn script_case_parsing_matches_node_bridge() {
        let tests = read_json("script_tests_pq.json").as_array().unwrap().clone();
        let mut seen = BTreeSet::new();
        for test in tests.iter().take(8) {
            let row = test.as_array().unwrap();
            let pos = usize::from(row[0].is_array());
            let script_sig = row[pos].as_str().unwrap();
            let script_pubkey = row[pos + 1].as_str().unwrap();
            seen.insert(parse_script_asm(script_sig).unwrap());
            seen.insert(parse_script_asm(script_pubkey).unwrap());
        }
        assert!(!seen.is_empty());
    }

    #[test]
    fn script_op_sha512_matches_node_cases() {
        let input = PushBytesBuf::try_from(vec![0x01, 0x02, 0x03]).unwrap();
        let expected = PushBytesBuf::try_from(sha512::Hash::hash(input.as_bytes()).to_byte_array().to_vec()).unwrap();
        let equal_hash_script = ScriptPubKeyBuf::builder()
            .push_slice(&input)
            .push_opcode(OP_SHA512)
            .push_slice(&expected)
            .push_opcode(OP_EQUAL)
            .into_script();
        verify_script_case(
            &ScriptSigBuf::new(),
            &equal_hash_script,
            &Witness::default(),
            Amount::from_sat(0).unwrap(),
            VERIFY_SHA512,
        )
        .unwrap();

        let same_input_script = ScriptPubKeyBuf::builder()
            .push_slice(&input)
            .push_opcode(OP_SHA512)
            .push_slice(&input)
            .push_opcode(OP_EQUAL)
            .into_script();
        verify_script_case(
            &ScriptSigBuf::new(),
            &same_input_script,
            &Witness::default(),
            Amount::from_sat(0).unwrap(),
            VERIFY_NONE,
        )
        .unwrap();
        assert_eq!(
            verify_script_case(
                &ScriptSigBuf::new(),
                &same_input_script,
                &Witness::default(),
                Amount::from_sat(0).unwrap(),
                VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            ),
            Err(TidecoinValidationError::Script(
                ScriptError::DiscourageUpgradableNops,
            ))
        );

        assert_eq!(
            verify_script_case(
                &ScriptSigBuf::new(),
                &ScriptPubKeyBuf::builder().push_opcode(OP_SHA512).into_script(),
                &Witness::default(),
                Amount::from_sat(0).unwrap(),
                VERIFY_SHA512,
            ),
            Err(TidecoinValidationError::Script(
                ScriptError::InvalidStackOperation,
            ))
        );

        let max_input = PushBytesBuf::try_from(vec![0x42; 8192]).unwrap();
        let max_expected =
            PushBytesBuf::try_from(sha512::Hash::hash(max_input.as_bytes()).to_byte_array().to_vec())
                .unwrap();
        let max_script = ScriptPubKeyBuf::builder()
            .push_slice(&max_input)
            .push_opcode(OP_SHA512)
            .push_slice(&max_expected)
            .push_opcode(OP_EQUAL)
            .into_script();
        verify_script_case(
            &ScriptSigBuf::new(),
            &max_script,
            &Witness::default(),
            Amount::from_sat(0).unwrap(),
            VERIFY_SHA512,
        )
        .unwrap();

        let too_big = PushBytesBuf::try_from(vec![0x42; 8193]).unwrap();
        let too_big_script =
            ScriptPubKeyBuf::builder().push_slice(&too_big).push_opcode(OP_SHA512).into_script();
        assert_eq!(
            verify_script_case(
                &ScriptSigBuf::new(),
                &too_big_script,
                &Witness::default(),
                Amount::from_sat(0).unwrap(),
                VERIFY_SHA512,
            ),
            Err(TidecoinValidationError::Script(ScriptError::PushSize))
        );
    }

    #[test]
    fn witness_v1_512_policy_matches_node_case() {
        let witness_script = ScriptPubKeyBuf::builder().push_opcode(OP_TRUE).into_script();
        let program = sha512::Hash::hash(witness_script.as_bytes()).to_byte_array();
        let script_pubkey = ScriptPubKeyBuf::builder()
            .push_int(1)
            .unwrap()
            .push_slice(program)
            .into_script();
        let witness = Witness::from_slice(&[witness_script.as_bytes()]);

        verify_script_case(
            &ScriptSigBuf::new(),
            &script_pubkey,
            &witness,
            Amount::from_sat(0).unwrap(),
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .unwrap();

        assert_eq!(
            verify_script_case(
                &ScriptSigBuf::new(),
                &script_pubkey,
                &witness,
                Amount::from_sat(0).unwrap(),
                VERIFY_WITNESS | VERIFY_P2SH | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
            ),
            Err(TidecoinValidationError::Script(
                ScriptError::DiscourageUpgradableWitnessProgram,
            ))
        );
    }

    #[test]
    fn witness_v0_v1_mix_matches_node_case() {
        let witness_script_v0 = WitnessScriptBuf::from_bytes(
            ScriptPubKeyBuf::builder().push_opcode(OP_TRUE).into_script().into_bytes(),
        );
        let witness_script_v1 = WitnessScriptBuf::from_bytes(
            ScriptPubKeyBuf::builder().push_opcode(OP_TRUE).into_script().into_bytes(),
        );
        let script_pubkey_v0 = direct_p2wsh_script_pubkey(&witness_script_v0);
        let program_v1 = sha512::Hash::hash(witness_script_v1.as_bytes()).to_byte_array();
        let script_pubkey_v1 = ScriptPubKeyBuf::builder()
            .push_int(1)
            .unwrap()
            .push_slice(program_v1)
            .into_script();

        let mut tx = tx_template(2);
        tx.inputs[0].witness = Witness::from_slice(&[witness_script_v0.as_bytes()]);
        tx.inputs[1].witness = Witness::from_slice(&[witness_script_v1.as_bytes()]);

        let flags = VERIFY_WITNESS | VERIFY_P2SH | VERIFY_WITNESS_V1_512 | VERIFY_SHA512;
        let amount = Amount::from_sat_u32(1);
        verify_script_input(&script_pubkey_v0, 0, amount, &tx, flags).unwrap();
        verify_script_input(&script_pubkey_v1, 1, amount, &tx, flags).unwrap();
    }

    #[test]
    fn pq_multisig_mixed_scheme_direct_and_wrapped_match_node() {
        let keys = [
            deterministic_keypair(PqScheme::Falcon512, 0x80),
            deterministic_keypair(PqScheme::MlDsa44, 0x81),
            deterministic_keypair(PqScheme::MlDsa87, 0x82),
        ];
        let pubkeys: Vec<PqPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let witness_script = multisig_witness_script(&pubkeys, 2);
        let amount = Amount::from_sat_u32(1);

        let mut direct_tx = tx_template(1);
        direct_tx.inputs[0].witness = signed_multisig_witness(
            &direct_tx,
            0,
            amount,
            &witness_script,
            &[keys[0].1.clone(), keys[1].1.clone()],
            true,
        );
        verify_script_input(
            &direct_p2wsh_script_pubkey(&witness_script),
            0,
            amount,
            &direct_tx,
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .unwrap();

        let (wrapped_spk, wrapped_sig) = wrapped_p2wsh(&witness_script);
        let mut wrapped_tx = tx_template(1);
        wrapped_tx.inputs[0].script_sig = wrapped_sig;
        wrapped_tx.inputs[0].witness = signed_multisig_witness(
            &wrapped_tx,
            0,
            amount,
            &witness_script,
            &[keys[0].1.clone(), keys[1].1.clone()],
            true,
        );
        verify_script_input(&wrapped_spk, 0, amount, &wrapped_tx, VERIFY_WITNESS | VERIFY_P2SH)
            .unwrap();
    }

    #[test]
    fn pq_multisig_negative_and_limit_cases_match_node() {
        let keys = [
            deterministic_keypair(PqScheme::Falcon512, 0x21),
            deterministic_keypair(PqScheme::Falcon512, 0x22),
            deterministic_keypair(PqScheme::Falcon512, 0x23),
        ];
        let pubkeys: Vec<PqPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let witness_script = multisig_witness_script(&pubkeys, 2);
        let script_pubkey = direct_p2wsh_script_pubkey(&witness_script);
        let amount = Amount::from_sat_u32(1);

        let mut tx = tx_template(1);
        let good_sig1 = witness_v0_sig(&tx, 0, amount, &witness_script, &keys[0].1, true);
        let good_sig2 = witness_v0_sig(&tx, 0, amount, &witness_script, &keys[1].1, true);
        let outsider = deterministic_keypair(PqScheme::Falcon512, 0x31);
        let outsider_sig = witness_v0_sig(&tx, 0, amount, &witness_script, &outsider.1, true);

        tx.inputs[0].witness = Witness::from_slice(&[
            Vec::<u8>::new(),
            good_sig1.clone(),
            Vec::<u8>::new(),
            witness_script.as_bytes().to_vec(),
        ]);
        assert!(verify_script_input(&script_pubkey, 0, amount, &tx, VERIFY_WITNESS | VERIFY_P2SH).is_err());

        tx.inputs[0].witness = Witness::from_slice(&[
            Vec::<u8>::new(),
            good_sig2.clone(),
            good_sig1.clone(),
            witness_script.as_bytes().to_vec(),
        ]);
        assert!(verify_script_input(&script_pubkey, 0, amount, &tx, VERIFY_WITNESS | VERIFY_P2SH).is_err());

        tx.inputs[0].witness = Witness::from_slice(&[
            Vec::<u8>::new(),
            outsider_sig,
            good_sig2.clone(),
            witness_script.as_bytes().to_vec(),
        ]);
        assert!(verify_script_input(&script_pubkey, 0, amount, &tx, VERIFY_WITNESS | VERIFY_P2SH).is_err());

        let mut wrong_sighash = good_sig1;
        *wrong_sighash.last_mut().unwrap() = EcdsaSighashType::None.to_u32() as u8;
        tx.inputs[0].witness = Witness::from_slice(&[
            Vec::<u8>::new(),
            wrong_sighash,
            good_sig2,
            witness_script.as_bytes().to_vec(),
        ]);
        assert!(verify_script_input(&script_pubkey, 0, amount, &tx, VERIFY_WITNESS | VERIFY_P2SH).is_err());

        let zero_script = multisig_witness_script(&[], 0);
        let zero_spk = direct_p2wsh_script_pubkey(&zero_script);
        let mut zero_tx = tx_template(1);
        zero_tx.inputs[0].witness = Witness::from_slice(&[Vec::<u8>::new(), zero_script.as_bytes().to_vec()]);
        verify_script_input(&zero_spk, 0, amount, &zero_tx, VERIFY_WITNESS | VERIFY_P2SH).unwrap();

        let too_many_pubkeys: Vec<PqPublicKey> = (0..21)
            .map(|idx| deterministic_keypair(PqScheme::Falcon512, 0x60 + idx).0)
            .collect();
        let too_many_script = multisig_witness_script(&too_many_pubkeys, 21);
        let too_many_spk = direct_p2wsh_script_pubkey(&too_many_script);
        let mut too_many_tx = tx_template(1);
        let mut too_many_witness = vec![Vec::new()];
        too_many_witness.extend((0..21).map(|_| vec![0]));
        too_many_witness.push(too_many_script.as_bytes().to_vec());
        too_many_tx.inputs[0].witness = Witness::from_slice(&too_many_witness);
        assert_eq!(
            verify_script_input(&too_many_spk, 0, amount, &too_many_tx, VERIFY_WITNESS | VERIFY_P2SH),
            Err(TidecoinValidationError::Script(ScriptError::PubkeyCount))
        );

        let limit_keys = [
            deterministic_keypair(PqScheme::MlDsa87, 0x40),
            deterministic_keypair(PqScheme::MlDsa87, 0x41),
        ];
        let limit_pubkeys: Vec<PqPublicKey> = limit_keys.iter().map(|(pk, _)| pk.clone()).collect();
        let limit_script = multisig_witness_script(&limit_pubkeys, 1);
        let limit_spk = direct_p2wsh_script_pubkey(&limit_script);
        let mut limit_tx = tx_template(1);
        let mut limit_witness = signed_multisig_witness(
            &limit_tx,
            0,
            amount,
            &limit_script,
            &[limit_keys[0].1.clone()],
            true,
        )
        .to_vec();
        limit_witness[1] = vec![0x42; 8193];
        limit_tx.inputs[0].witness = Witness::from_slice(&limit_witness);
        assert_eq!(
            verify_script_input(&limit_spk, 0, amount, &limit_tx, VERIFY_WITNESS | VERIFY_P2SH),
            Err(TidecoinValidationError::Script(ScriptError::PushSize))
        );
    }

    #[test]
    fn pq_committed_hash_mixed_scheme_and_failures_match_node() {
        let keys = vec![
            deterministic_keypair(PqScheme::Falcon512, 0xD0),
            deterministic_keypair(PqScheme::MlDsa44, 0xD1),
            deterministic_keypair(PqScheme::MlDsa87, 0xD2),
        ];
        let pubkeys: Vec<PqPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let witness_script = committed_hash_witness_script(&pubkeys, 2);
        let amount = Amount::from_sat_u32(1);

        let mut direct_tx = tx_template(1);
        direct_tx.inputs[0].witness =
            signed_committed_hash_witness(&direct_tx, 0, amount, &witness_script, &keys, 2, true);
        verify_script_input(
            &direct_p2wsh_script_pubkey(&witness_script),
            0,
            amount,
            &direct_tx,
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .unwrap();

        let (wrapped_spk, wrapped_sig) = wrapped_p2wsh(&witness_script);
        let mut wrapped_tx = tx_template(1);
        wrapped_tx.inputs[0].script_sig = wrapped_sig;
        wrapped_tx.inputs[0].witness =
            signed_committed_hash_witness(&wrapped_tx, 0, amount, &witness_script, &keys, 2, true);
        verify_script_input(&wrapped_spk, 0, amount, &wrapped_tx, VERIFY_WITNESS | VERIFY_P2SH)
            .unwrap();

        let mut bad_pubkey_witness =
            signed_committed_hash_witness(&direct_tx, 0, amount, &witness_script, &keys, 2, true)
                .to_vec();
        bad_pubkey_witness.swap(1, 3);
        let mut bad_pubkey_tx = tx_template(1);
        bad_pubkey_tx.inputs[0].witness = Witness::from_slice(&bad_pubkey_witness);
        assert!(verify_script_input(
            &direct_p2wsh_script_pubkey(&witness_script),
            0,
            amount,
            &bad_pubkey_tx,
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .is_err());

        let mut bad_sig_blob =
            signed_committed_hash_witness(&direct_tx, 0, amount, &witness_script, &keys, 2, true)
                .to_vec();
        bad_sig_blob[0] = vec![0x01];
        let mut bad_sig_tx = tx_template(1);
        bad_sig_tx.inputs[0].witness = Witness::from_slice(&bad_sig_blob);
        assert!(verify_script_input(
            &direct_p2wsh_script_pubkey(&witness_script),
            0,
            amount,
            &bad_sig_tx,
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .is_err());

        let mut threshold_tx = tx_template(1);
        threshold_tx.inputs[0].witness =
            signed_committed_hash_witness(&threshold_tx, 0, amount, &witness_script, &keys, 1, true);
        assert!(verify_script_input(
            &direct_p2wsh_script_pubkey(&witness_script),
            0,
            amount,
            &threshold_tx,
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .is_err());

        let mut swapped_sig_witness =
            signed_committed_hash_witness(&direct_tx, 0, amount, &witness_script, &keys, 2, true)
                .to_vec();
        swapped_sig_witness.swap(0, 2);
        let mut swapped_sig_tx = tx_template(1);
        swapped_sig_tx.inputs[0].witness = Witness::from_slice(&swapped_sig_witness);
        assert!(verify_script_input(
            &direct_p2wsh_script_pubkey(&witness_script),
            0,
            amount,
            &swapped_sig_tx,
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .is_err());
    }

    #[test]
    fn witness_v1_512_zero_sighash_byte_is_rejected() {
        let (pubkey, seckey) = deterministic_keypair(PqScheme::Falcon512, 0x51);
        let witness_script = WitnessScriptBuf::from_bytes(
            ScriptPubKeyBuf::builder()
                .push_slice(push_bytes(&pubkey.to_prefixed_bytes()))
                .push_opcode(OP_CHECKSIG)
                .into_script()
                .into_bytes(),
        );
        let program = sha512::Hash::hash(witness_script.as_bytes()).to_byte_array();
        let script_pubkey = ScriptPubKeyBuf::builder()
            .push_int(1)
            .unwrap()
            .push_slice(program)
            .into_script();
        let amount = Amount::from_sat_u32(1);
        let mut tx = tx_template(1);
        let mut sig = witness_v1_512_sig(&tx, 0, amount, &witness_script, &seckey, true);
        *sig.last_mut().unwrap() = 0;
        tx.inputs[0].witness =
            Witness::from_slice(&[sig, witness_script.as_bytes().to_vec()]);

        assert!(verify_script_input(
            &script_pubkey,
            0,
            amount,
            &tx,
            VERIFY_WITNESS | VERIFY_P2SH | VERIFY_WITNESS_V1_512 | VERIFY_SHA512,
        )
        .is_err());
    }

    #[test]
    fn pq_legacy_base_p2pkh_signature_verifies() {
        let (pubkey, seckey) = deterministic_keypair(PqScheme::Falcon512, 0x11);
        let script_pubkey = ScriptPubKeyBuf::builder()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(push_bytes(pubkey.key_id().as_ref()))
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let mut tx = tx_template(1);
        let sig = base_sig(&tx, 0, &script_pubkey, &seckey, true);
        tx.inputs[0].script_sig = ScriptSigBuf::builder()
            .push_slice(push_bytes(&sig))
            .push_slice(push_bytes(&pubkey.to_prefixed_bytes()))
            .into_script();

        verify_script_input(&script_pubkey, 0, Amount::from_sat_u32(0), &tx, VERIFY_NONE).unwrap();
    }
}
