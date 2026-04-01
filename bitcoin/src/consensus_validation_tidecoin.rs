// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(feature = "tidecoin-node-validation", allow(dead_code))]

use core::fmt;

use hashes::{hash160, sha1, sha256, sha256d, sha512};

use crate::absolute;
use crate::amount::Amount;
use crate::crypto::pq::{PqPublicKey, PqSignature};
use crate::opcodes::all::*;
use crate::opcodes::Opcode;
use crate::prelude::Vec;
use crate::script::{
    read_scriptbool, read_scriptint_non_minimal, Error as ScriptDecodeError, Instruction,
    PushBytesBuf, RedeemScriptBuf, Script, ScriptBufExt as _, ScriptExt as _,
    ScriptPubKey, ScriptPubKeyBuf, ScriptPubKeyExt as _, ScriptSigBuf, WitnessScript,
    WitnessScriptBuf,
    WitnessScriptExt as _,
};
use crate::sighash::{EcdsaSighashType, SighashCache};
use crate::transaction::{OutPoint, Transaction};
use crate::witness::Witness;
use crate::{Sequence, WitnessProgram};

pub const VERIFY_NONE: u32 = 0;
pub const VERIFY_P2SH: u32 = 1 << 0;
pub const VERIFY_STRICTENC: u32 = 0;
pub const VERIFY_MINIMALDATA: u32 = 1 << 3;
pub const VERIFY_NULLDUMMY: u32 = 1 << 1;
pub const VERIFY_SIGPUSHONLY: u32 = 1 << 2;
pub const VERIFY_CLEANSTACK: u32 = 1 << 5;
pub const VERIFY_MINIMALIF: u32 = 1 << 10;
pub const VERIFY_NULLFAIL: u32 = 1 << 11;
pub const VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 6;
pub const VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 7;
pub const VERIFY_WITNESS: u32 = 1 << 8;
pub const VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 1 << 4;
pub const VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: u32 = 1 << 9;
pub const VERIFY_CONST_SCRIPTCODE: u32 = 1 << 12;
pub const VERIFY_PQ_STRICT: u32 = 1 << 13;
pub const VERIFY_WITNESS_V1_512: u32 = 1 << 14;
pub const VERIFY_SHA512: u32 = 1 << 15;

const MAX_SCRIPT_ELEMENT_SIZE: usize = 8192;
const MAX_OPS_PER_SCRIPT: usize = 201;
const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
const MAX_SCRIPT_SIZE: usize = 65536;
const MAX_STACK_SIZE: usize = 1000;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptError {
    EvalFalse,
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
    SigPushOnly,
    NullDummy,
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

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::EvalFalse => "EVAL_FALSE",
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
            Self::SigPushOnly => "SIG_PUSHONLY",
            Self::NullDummy => "NULLDUMMY",
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
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TidecoinValidationError {
    Script(ScriptError),
    InvalidInputIndex { index: usize, inputs: usize },
    UnsupportedScript,
    MissingSpentOutput(OutPoint),
}

impl fmt::Display for TidecoinValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Script(err) => write!(f, "script validation failed: {}", err),
            Self::InvalidInputIndex { index, inputs } =>
                write!(f, "input index {} out of bounds for transaction with {} inputs", index, inputs),
            Self::UnsupportedScript => f.write_str("script requires unsupported validation path"),
            Self::MissingSpentOutput(outpoint) => write!(f, "missing spent output {}", outpoint),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TidecoinValidationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigVersion {
    Base,
    WitnessV0,
    WitnessV1_512,
}

type Stack = Vec<Vec<u8>>;

pub(crate) fn should_use_tidecoin_validation(
    script_pubkey: &ScriptPubKey,
    tx: &Transaction,
    index: usize,
    _flags: u32,
) -> bool {
    if script_pubkey.is_p2wsh512() || script_contains_pq_material(script_pubkey) || script_contains_opcode(script_pubkey, OP_SHA512) {
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
    let mut flags = flags;
    if flags & VERIFY_CLEANSTACK != 0 {
        flags |= VERIFY_P2SH | VERIFY_WITNESS;
    }

    let input = tx.inputs.get(index).ok_or(TidecoinValidationError::InvalidInputIndex {
        index,
        inputs: tx.inputs.len(),
    })?;

    if flags & VERIFY_SIGPUSHONLY != 0 && !input.script_sig.is_push_only() {
        return Err(TidecoinValidationError::Script(ScriptError::SigPushOnly));
    }

    let mut stack = Vec::new();
    let mut stack_copy = Vec::new();
    eval_script(
        &mut stack,
        &input.script_sig,
        EvalContext { tx, input_index: index, amount, flags, sigversion: SigVersion::Base },
    )?;
    if flags & VERIFY_P2SH != 0 {
        stack_copy = stack.clone();
    }

    eval_script(
        &mut stack,
        script_pubkey,
        EvalContext { tx, input_index: index, amount, flags, sigversion: SigVersion::Base },
    )?;

    if stack.last().is_none_or(|top| !read_scriptbool(top)) {
        return Err(TidecoinValidationError::Script(ScriptError::EvalFalse));
    }

    let mut had_witness = false;
    if flags & VERIFY_WITNESS != 0 {
        if let Some(program) = witness_program_from_script(script_pubkey) {
            had_witness = true;
            if !input.script_sig.is_empty() {
                return Err(TidecoinValidationError::Script(ScriptError::WitnessMalleated));
            }
            verify_witness_program(
                &input.witness,
                program,
                EvalContext { tx, input_index: index, amount, flags, sigversion: SigVersion::Base },
            )?;
            stack.resize(1, vec![1]);
        }
    }

    if flags & VERIFY_P2SH != 0 && script_pubkey.is_p2sh() {
        if !input.script_sig.is_push_only() {
            return Err(TidecoinValidationError::Script(ScriptError::SigPushOnly));
        }

        stack = stack_copy;
        let redeem_raw = stack.pop().ok_or(TidecoinValidationError::Script(
            ScriptError::EvalFalse,
        ))?;
        let redeem_script = RedeemScriptBuf::from_bytes(redeem_raw.clone());
        eval_script(
            &mut stack,
            redeem_script.as_script(),
            EvalContext { tx, input_index: index, amount, flags, sigversion: SigVersion::Base },
        )?;
        if stack.last().is_none_or(|top| !read_scriptbool(top)) {
            return Err(TidecoinValidationError::Script(ScriptError::EvalFalse));
        }

        if flags & VERIFY_WITNESS != 0 {
            if let Some(program) = witness_program_from_script(redeem_script.as_script()) {
                had_witness = true;
                let expected = ScriptSigBuf::from_bytes(push_script(&redeem_raw));
                if input.script_sig.as_bytes() != expected.as_bytes() {
                    return Err(TidecoinValidationError::Script(
                        ScriptError::WitnessMalleatedP2sh,
                    ));
                }
                verify_witness_program(
                    &input.witness,
                    program,
                    EvalContext { tx, input_index: index, amount, flags, sigversion: SigVersion::Base },
                )?;
                stack.resize(1, vec![1]);
            }
        }
    }

    if flags & VERIFY_CLEANSTACK != 0 && stack.len() != 1 {
        return Err(TidecoinValidationError::Script(ScriptError::Cleanstack));
    }

    if flags & VERIFY_WITNESS != 0 && !had_witness && !input.witness.is_empty() {
        return Err(TidecoinValidationError::Script(ScriptError::WitnessUnexpected));
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct EvalContext<'a> {
    tx: &'a Transaction,
    input_index: usize,
    amount: Amount,
    flags: u32,
    sigversion: SigVersion,
}

fn eval_script<T>(
    stack: &mut Stack,
    script: &Script<T>,
    ctx: EvalContext<'_>,
) -> Result<(), TidecoinValidationError> {
    if script.len() > MAX_SCRIPT_SIZE {
        return Err(TidecoinValidationError::Script(ScriptError::ScriptSize));
    }

    let mut altstack = Vec::new();
    let mut vf_exec: Vec<bool> = Vec::new();
    let mut op_count = 0usize;
    let mut pbegincodehash = 0usize;
    let enforce_minimal = ctx.flags & VERIFY_MINIMALDATA != 0;
    let instructions = if enforce_minimal {
        script.instruction_indices_minimal()
    } else {
        script.instruction_indices()
    };

    for result in instructions {
        let (idx, instruction) = match result {
            Ok(v) => v,
            Err(ScriptDecodeError::NonMinimalPush) =>
                return Err(TidecoinValidationError::Script(ScriptError::BadOpcode)),
            Err(_) => return Err(TidecoinValidationError::Script(ScriptError::BadOpcode)),
        };

        let f_exec = vf_exec.iter().all(|v| *v);

        if matches!(instruction, Instruction::Op(op) if op == OP_CODESEPARATOR)
            && ctx.sigversion == SigVersion::Base
            && ctx.flags & VERIFY_CONST_SCRIPTCODE != 0
        {
            return Err(TidecoinValidationError::Script(ScriptError::OpCodeSeparator));
        }

        match instruction {
            Instruction::PushBytes(bytes) => {
                if !f_exec {
                    continue;
                }
                if bytes.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(TidecoinValidationError::Script(ScriptError::PushSize));
                }
                stack.push(bytes.as_bytes().to_vec());
            }
            Instruction::Op(op) if op == OP_0 => {
                if f_exec {
                    stack.push(Vec::new());
                }
            }
            Instruction::Op(op @ (OP_1NEGATE | OP_1 | OP_2 | OP_3 | OP_4 | OP_5 | OP_6 | OP_7 | OP_8 | OP_9 | OP_10 | OP_11 | OP_12 | OP_13 | OP_14 | OP_15 | OP_16)) => {
                if !f_exec {
                    continue;
                }
                stack.push(encode_script_num(op_to_num(op)));
            }
            Instruction::Op(op @ (OP_IF | OP_NOTIF)) => {
                let value = if f_exec {
                    let top = stack.pop().ok_or(TidecoinValidationError::Script(
                        ScriptError::InvalidStackOperation,
                    ))?;
                    if (ctx.sigversion == SigVersion::WitnessV0
                        || ctx.sigversion == SigVersion::WitnessV1_512)
                        && ctx.flags & VERIFY_MINIMALIF != 0
                        && !(top.is_empty() || top == [1])
                    {
                        return Err(TidecoinValidationError::Script(ScriptError::MinimalIf));
                    }
                    let mut truthy = read_scriptbool(&top);
                    if op == OP_NOTIF {
                        truthy = !truthy;
                    }
                    truthy
                } else {
                    false
                };
                vf_exec.push(value);
            }
            Instruction::Op(OP_ELSE) => {
                let last = vf_exec
                    .last_mut()
                    .ok_or(TidecoinValidationError::Script(ScriptError::UnbalancedConditional))?;
                *last = !*last;
            }
            Instruction::Op(OP_ENDIF) => {
                vf_exec
                    .pop()
                    .ok_or(TidecoinValidationError::Script(ScriptError::UnbalancedConditional))?;
            }
            Instruction::Op(op) if !f_exec => {
                if matches!(op, OP_VERIF | OP_VERNOTIF) {
                    return Err(TidecoinValidationError::Script(ScriptError::BadOpcode));
                }
            }
            Instruction::Op(op) => {
                if op.to_u8() > OP_16.to_u8() {
                    op_count += 1;
                    if op_count > MAX_OPS_PER_SCRIPT {
                        return Err(TidecoinValidationError::Script(ScriptError::OpCount));
                    }
                }

                match op {
                    OP_NOP | OP_NOP1 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                        if ctx.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS != 0 {
                            return Err(TidecoinValidationError::Script(
                                ScriptError::DiscourageUpgradableNops,
                            ));
                        }
                    }
                    OP_CLTV => {
                        if ctx.flags & VERIFY_CHECKLOCKTIMEVERIFY == 0 {
                            if ctx.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS != 0 {
                                return Err(TidecoinValidationError::Script(
                                    ScriptError::DiscourageUpgradableNops,
                                ));
                            }
                        } else {
                            check_lock_time(stack.last().ok_or(TidecoinValidationError::Script(
                                ScriptError::InvalidStackOperation,
                            ))?, ctx)?;
                        }
                    }
                    OP_CSV => {
                        if ctx.flags & VERIFY_CHECKSEQUENCEVERIFY == 0 {
                            if ctx.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS != 0 {
                                return Err(TidecoinValidationError::Script(
                                    ScriptError::DiscourageUpgradableNops,
                                ));
                            }
                        } else {
                            check_sequence(stack.last().ok_or(TidecoinValidationError::Script(
                                ScriptError::InvalidStackOperation,
                            ))?, ctx)?;
                        }
                    }
                    OP_DUP => {
                        let top = stack
                            .last()
                            .ok_or(TidecoinValidationError::Script(ScriptError::InvalidStackOperation))?
                            .clone();
                        stack.push(top);
                    }
                    OP_DROP => {
                        stack
                            .pop()
                            .ok_or(TidecoinValidationError::Script(ScriptError::InvalidStackOperation))?;
                    }
                    OP_TOALTSTACK => {
                        let top = stack
                            .pop()
                            .ok_or(TidecoinValidationError::Script(ScriptError::InvalidStackOperation))?;
                        altstack.push(top);
                    }
                    OP_FROMALTSTACK => {
                        let top = altstack
                            .pop()
                            .ok_or(TidecoinValidationError::Script(ScriptError::InvalidAltstackOperation))?;
                        stack.push(top);
                    }
                    OP_SIZE => {
                        let len = stack
                            .last()
                            .ok_or(TidecoinValidationError::Script(ScriptError::InvalidStackOperation))?
                            .len() as i64;
                        stack.push(encode_script_num(len));
                    }
                    OP_EQUAL | OP_EQUALVERIFY => {
                        if stack.len() < 2 {
                            return Err(TidecoinValidationError::Script(
                                ScriptError::InvalidStackOperation,
                            ));
                        }
                        let a = stack.pop().expect("len checked");
                        let b = stack.pop().expect("len checked");
                        let equal = a == b;
                        if op == OP_EQUALVERIFY {
                            if !equal {
                                return Err(TidecoinValidationError::Script(
                                    ScriptError::EqualVerify,
                                ));
                            }
                        } else {
                            stack.push(bool_bytes(equal));
                        }
                    }
                    OP_VERIFY => {
                        let top = stack
                            .pop()
                            .ok_or(TidecoinValidationError::Script(ScriptError::InvalidStackOperation))?;
                        if !read_scriptbool(&top) {
                            return Err(TidecoinValidationError::Script(ScriptError::Verify));
                        }
                    }
                    OP_ADD => {
                        if stack.len() < 2 {
                            return Err(TidecoinValidationError::Script(
                                ScriptError::InvalidStackOperation,
                            ));
                        }
                        let a = decode_script_num(&stack.pop().expect("len checked"))?;
                        let b = decode_script_num(&stack.pop().expect("len checked"))?;
                        stack.push(encode_script_num(a + b));
                    }
                    OP_NUMEQUAL | OP_NUMEQUALVERIFY => {
                        if stack.len() < 2 {
                            return Err(TidecoinValidationError::Script(
                                ScriptError::InvalidStackOperation,
                            ));
                        }
                        let a = decode_script_num(&stack.pop().expect("len checked"))?;
                        let b = decode_script_num(&stack.pop().expect("len checked"))?;
                        let equal = a == b;
                        if op == OP_NUMEQUALVERIFY {
                            if !equal {
                                return Err(TidecoinValidationError::Script(
                                    ScriptError::NumEqualVerify,
                                ));
                            }
                        } else {
                            stack.push(bool_bytes(equal));
                        }
                    }
                    OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 | OP_SHA512 => {
                        if stack.is_empty() {
                            return Err(TidecoinValidationError::Script(
                                ScriptError::InvalidStackOperation,
                            ));
                        }
                        if op == OP_SHA512 && ctx.flags & VERIFY_SHA512 == 0 {
                            if ctx.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS != 0 {
                                return Err(TidecoinValidationError::Script(
                                    ScriptError::DiscourageUpgradableNops,
                                ));
                            }
                            continue;
                        }
                        let value = stack.pop().expect("checked");
                        let hash = match op {
                            OP_RIPEMD160 => hashes::ripemd160::Hash::hash(&value).to_byte_array().to_vec(),
                            OP_SHA1 => sha1::Hash::hash(&value).to_byte_array().to_vec(),
                            OP_SHA256 => sha256::Hash::hash(&value).to_byte_array().to_vec(),
                            OP_HASH160 => hash160::Hash::hash(&value).to_byte_array().to_vec(),
                            OP_HASH256 => sha256d::Hash::hash(&value).to_byte_array().to_vec(),
                            OP_SHA512 => sha512::Hash::hash(&value).to_byte_array().to_vec(),
                            _ => unreachable!(),
                        };
                        stack.push(hash);
                    }
                    OP_CODESEPARATOR => {
                        pbegincodehash = idx + 1;
                    }
                    OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                        if stack.len() < 2 {
                            return Err(TidecoinValidationError::Script(
                                ScriptError::InvalidStackOperation,
                            ));
                        }
                        let pubkey = stack.pop().expect("len checked");
                        let sig = stack.pop().expect("len checked");
                        let success = checksig(&sig, &pubkey, script, pbegincodehash, ctx)?;
                        if op == OP_CHECKSIGVERIFY {
                            if !success {
                                return Err(TidecoinValidationError::Script(
                                    ScriptError::CheckSigVerify,
                                ));
                            }
                        } else {
                            stack.push(bool_bytes(success));
                        }
                    }
                    OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                        let success = checkmultisig(stack, script, pbegincodehash, ctx)?;
                        if op == OP_CHECKMULTISIGVERIFY {
                            if !success {
                                return Err(TidecoinValidationError::Script(
                                    ScriptError::CheckMultisigVerify,
                                ));
                            }
                        } else {
                            stack.push(bool_bytes(success));
                        }
                    }
                    OP_VERIF | OP_VERNOTIF => {
                        return Err(TidecoinValidationError::Script(ScriptError::BadOpcode));
                    }
                    OP_CAT => {
                        return Err(TidecoinValidationError::Script(
                            ScriptError::DisabledOpcode,
                        ));
                    }
                    _ => return Err(TidecoinValidationError::Script(ScriptError::BadOpcode)),
                }
            }
        }

        if stack.len() + altstack.len() > MAX_STACK_SIZE {
            return Err(TidecoinValidationError::Script(ScriptError::StackSize));
        }
    }

    if !vf_exec.is_empty() {
        return Err(TidecoinValidationError::Script(
            ScriptError::UnbalancedConditional,
        ));
    }

    Ok(())
}

fn checksig<T>(
    sig_with_hash_type: &[u8],
    pubkey_bytes: &[u8],
    script: &Script<T>,
    code_separator_index: usize,
    ctx: EvalContext<'_>,
) -> Result<bool, TidecoinValidationError> {
    let (sig_bytes, hash_type) = split_signature_hash_type(sig_with_hash_type);
    let pubkey = match PqPublicKey::from_prefixed_slice(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return Ok(false),
    };

    if sig_bytes.is_empty() {
        return Ok(false);
    }

    let clean_script = build_script_code_for_checksig(
        script,
        code_separator_index,
        sig_with_hash_type,
        ctx.sigversion == SigVersion::Base,
    )?;

    let verified = verify_signature(sig_bytes, hash_type, &pubkey, &clean_script, ctx);
    if !verified
        && ctx.flags & VERIFY_NULLFAIL != 0
        && !sig_bytes.is_empty()
    {
        return Err(TidecoinValidationError::Script(ScriptError::NullFail));
    }
    Ok(verified)
}

fn checkmultisig<T>(
    stack: &mut Stack,
    script: &Script<T>,
    code_separator_index: usize,
    ctx: EvalContext<'_>,
) -> Result<bool, TidecoinValidationError> {
    let mut i = 1usize;
    if stack.len() < i {
        return Err(TidecoinValidationError::Script(
            ScriptError::InvalidStackOperation,
        ));
    }

    let n_keys = decode_script_num(&stack[stack.len() - i])?;
    if n_keys < 0 || n_keys as usize > MAX_PUBKEYS_PER_MULTISIG {
        return Err(TidecoinValidationError::Script(ScriptError::PubkeyCount));
    }
    let n_keys = n_keys as usize;
    let op_count = n_keys;
    if op_count > MAX_OPS_PER_SCRIPT {
        return Err(TidecoinValidationError::Script(ScriptError::OpCount));
    }
    let mut ikey = i + 1;
    let mut ikey2 = n_keys + 2;
    i += n_keys + 1;
    if stack.len() < i {
        return Err(TidecoinValidationError::Script(
            ScriptError::InvalidStackOperation,
        ));
    }

    let n_sigs = decode_script_num(&stack[stack.len() - i])?;
    if n_sigs < 0 || n_sigs as usize > n_keys {
        return Err(TidecoinValidationError::Script(ScriptError::SigCount));
    }
    let mut n_sigs = n_sigs as usize;
    let mut isig = i + 1;
    i += n_sigs + 1;
    if stack.len() < i {
        return Err(TidecoinValidationError::Script(
            ScriptError::InvalidStackOperation,
        ));
    }

    let sigs: Vec<Vec<u8>> = (0..n_sigs)
        .map(|k| stack[stack.len() - (isig + k)].clone())
        .collect();
    let clean_script = build_multisig_script_code(script, code_separator_index, &sigs, ctx)?;

    let mut keys_left = n_keys;
    let mut success = true;
    while success && n_sigs > 0 {
        let sig = stack[stack.len() - isig].clone();
        let pubkey = stack[stack.len() - ikey].clone();
        let ok = checksig_against_code(&sig, &pubkey, &clean_script, ctx)?;
        if ok {
            isig += 1;
            n_sigs -= 1;
        }
        ikey += 1;
        keys_left -= 1;
        if n_sigs > keys_left {
            success = false;
        }
    }

    while i > 1 {
        i -= 1;
        if !success && ctx.flags & VERIFY_NULLFAIL != 0 && ikey2 == 0 && !stack.last().is_none_or(|x| x.is_empty()) {
            return Err(TidecoinValidationError::Script(ScriptError::NullFail));
        }
        ikey2 = ikey2.saturating_sub(1);
        stack.pop();
    }

    let dummy = stack
        .pop()
        .ok_or(TidecoinValidationError::Script(ScriptError::InvalidStackOperation))?;
    if ctx.flags & VERIFY_NULLDUMMY != 0 && !dummy.is_empty() {
        return Err(TidecoinValidationError::Script(ScriptError::NullDummy));
    }

    Ok(success)
}

fn checksig_against_code(
    sig_with_hash_type: &[u8],
    pubkey_bytes: &[u8],
    clean_script: &[u8],
    ctx: EvalContext<'_>,
) -> Result<bool, TidecoinValidationError> {
    let (sig_bytes, hash_type) = split_signature_hash_type(sig_with_hash_type);
    let pubkey = match PqPublicKey::from_prefixed_slice(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return Ok(false),
    };
    if sig_bytes.is_empty() {
        return Ok(false);
    }
    let verified = verify_signature(sig_bytes, hash_type, &pubkey, clean_script, ctx);
    if !verified && ctx.flags & VERIFY_NULLFAIL != 0 && !sig_bytes.is_empty() {
        return Err(TidecoinValidationError::Script(ScriptError::NullFail));
    }
    Ok(verified)
}

fn build_script_code_for_checksig<T>(
    script: &Script<T>,
    code_separator_index: usize,
    sig_with_hash_type: &[u8],
    remove_sig: bool,
) -> Result<Vec<u8>, TidecoinValidationError> {
    let raw = &script.as_bytes()[code_separator_index..];
    if !remove_sig {
        return Ok(raw.to_vec());
    }
    let sig_script = push_script(sig_with_hash_type);
    let (cleaned, found) = find_and_delete(raw, &sig_script);
    if found {
        return Ok(cleaned);
    }
    Ok(cleaned)
}

fn build_multisig_script_code<T>(
    script: &Script<T>,
    code_separator_index: usize,
    sigs: &[Vec<u8>],
    ctx: EvalContext<'_>,
) -> Result<Vec<u8>, TidecoinValidationError> {
    let mut out = script.as_bytes()[code_separator_index..].to_vec();
    if ctx.sigversion != SigVersion::Base {
        return Ok(out);
    }
    for sig in sigs {
        let sig_script = push_script(sig);
        let (next, found) = find_and_delete(&out, &sig_script);
        if found && ctx.flags & VERIFY_CONST_SCRIPTCODE != 0 {
            return Err(TidecoinValidationError::Script(ScriptError::SigFindAndDelete));
        }
        out = next;
    }
    Ok(out)
}

fn verify_signature(
    sig_bytes: &[u8],
    hash_type: u8,
    pubkey: &PqPublicKey,
    script_code: &[u8],
    ctx: EvalContext<'_>,
) -> bool {
    let sig = PqSignature::from_slice(sig_bytes);
    match ctx.sigversion {
        SigVersion::Base => {
            let script_code = RedeemScriptBuf::from_bytes(script_code.to_vec());
            let cache = SighashCache::new(ctx.tx);
            let Ok(sighash) =
                cache.legacy_signature_hash(ctx.input_index, script_code.as_script(), hash_type as u32)
            else {
                return false;
            };
            let msg = *sighash.as_byte_array();
            if ctx.flags & VERIFY_PQ_STRICT != 0 {
                sig.verify_msg32(&msg, pubkey).is_ok()
            } else {
                sig.verify_msg32_allow_legacy(&msg, pubkey).is_ok()
            }
        }
        SigVersion::WitnessV0 => {
            let script_code = WitnessScriptBuf::from_bytes(script_code.to_vec());
            let mut cache = SighashCache::new(ctx.tx);
            let sighash_type = EcdsaSighashType::from_consensus(hash_type as u32);
            let Ok(sighash) = cache.p2wsh_signature_hash(
                ctx.input_index,
                script_code.as_script(),
                ctx.amount,
                sighash_type,
            ) else {
                return false;
            };
            let msg = *sighash.as_byte_array();
            if ctx.flags & VERIFY_PQ_STRICT != 0 {
                sig.verify_msg32(&msg, pubkey).is_ok()
            } else {
                sig.verify_msg32_allow_legacy(&msg, pubkey).is_ok()
            }
        }
        SigVersion::WitnessV1_512 => {
            if hash_type == 0 {
                return false;
            }
            let script_code = WitnessScriptBuf::from_bytes(script_code.to_vec());
            let mut cache = SighashCache::new(ctx.tx);
            let sighash_type = EcdsaSighashType::from_consensus(hash_type as u32);
            let Ok(sighash) = cache.p2wsh512_signature_hash(
                ctx.input_index,
                script_code.as_script(),
                ctx.amount,
                sighash_type,
            ) else {
                return false;
            };
            let msg = *sighash.as_byte_array();
            if ctx.flags & VERIFY_PQ_STRICT != 0 {
                sig.verify_msg64(&msg, pubkey).is_ok()
            } else {
                sig.verify_msg64_allow_legacy(&msg, pubkey).is_ok()
            }
        }
    }
}

fn verify_witness_program(
    witness: &Witness,
    program: WitnessProgram,
    ctx: EvalContext<'_>,
) -> Result<(), TidecoinValidationError> {
    if program.version().to_num() == 0 {
        if program.program().len() == 32 {
            if witness.is_empty() {
                return Err(TidecoinValidationError::Script(
                    ScriptError::WitnessProgramWitnessEmpty,
                ));
            }
            let script_bytes = witness
                .last()
                .ok_or(TidecoinValidationError::Script(
                    ScriptError::WitnessProgramWitnessEmpty,
                ))?;
            let exec_script = WitnessScriptBuf::from_bytes(script_bytes.to_vec());
            let expected = exec_script
                .wscript_hash()
                .map_err(|_| TidecoinValidationError::Script(ScriptError::PushSize))?;
            if program.program().as_bytes() != expected.as_byte_array() {
                return Err(TidecoinValidationError::Script(
                    ScriptError::WitnessProgramMismatch,
                ));
            }
            let mut stack = witness.to_vec();
            let _ = stack.pop();
            eval_script(
                &mut stack,
                exec_script.as_script(),
                EvalContext { sigversion: SigVersion::WitnessV0, ..ctx },
            )?;
            if stack.len() != 1 || !read_scriptbool(&stack[0]) {
                return Err(TidecoinValidationError::Script(ScriptError::EvalFalse));
            }
            return Ok(());
        }

        if program.program().len() == 20 {
            if witness.len() != 2 {
                return Err(TidecoinValidationError::Script(
                    ScriptError::WitnessProgramMismatch,
                ));
            }
            let exec_script = ScriptPubKeyBuf::builder()
                .push_opcode(OP_DUP)
                .push_opcode(OP_HASH160)
                .push_slice(program.program())
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_CHECKSIG)
                .into_script();
            let mut stack = witness.to_vec();
            eval_script(
                &mut stack,
                exec_script.as_script(),
                EvalContext { sigversion: SigVersion::WitnessV0, ..ctx },
            )?;
            if stack.len() != 1 || !read_scriptbool(&stack[0]) {
                return Err(TidecoinValidationError::Script(ScriptError::EvalFalse));
            }
            return Ok(());
        }

        return Err(TidecoinValidationError::Script(
            ScriptError::WitnessProgramWrongLength,
        ));
    }

    if program.version().to_num() == 1 {
        if ctx.flags & VERIFY_WITNESS_V1_512 == 0 {
            if ctx.flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM != 0 {
                return Err(TidecoinValidationError::Script(
                    ScriptError::DiscourageUpgradableWitnessProgram,
                ));
            }
            return Ok(());
        }
        if program.program().len() != 64 {
            return Err(TidecoinValidationError::Script(
                ScriptError::WitnessProgramWrongLength,
            ));
        }
        if witness.is_empty() {
            return Err(TidecoinValidationError::Script(
                ScriptError::WitnessProgramWitnessEmpty,
            ));
        }
        let script_bytes = witness
            .last()
            .ok_or(TidecoinValidationError::Script(
                ScriptError::WitnessProgramWitnessEmpty,
            ))?;
        let exec_script = WitnessScriptBuf::from_bytes(script_bytes.to_vec());
        let hash = sha512::Hash::hash(exec_script.as_bytes());
        if program.program().as_bytes() != hash.as_byte_array() {
            return Err(TidecoinValidationError::Script(
                ScriptError::WitnessProgramMismatch,
            ));
        }
        let mut stack = witness.to_vec();
        let _ = stack.pop();
        eval_script(
            &mut stack,
            exec_script.as_script(),
            EvalContext { sigversion: SigVersion::WitnessV1_512, ..ctx },
        )?;
        if stack.len() != 1 || !read_scriptbool(&stack[0]) {
            return Err(TidecoinValidationError::Script(ScriptError::EvalFalse));
        }
        return Ok(());
    }

    if ctx.flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM != 0 {
        return Err(TidecoinValidationError::Script(
            ScriptError::DiscourageUpgradableWitnessProgram,
        ));
    }

    Ok(())
}

fn witness_program_from_script<T: crate::script::ScriptHashableTag>(
    script: &Script<T>,
) -> Option<WitnessProgram> {
    let version = script.witness_version()?;
    let program = &script.as_bytes()[2..];
    WitnessProgram::new(version, program).ok()
}

fn script_contains_opcode<T>(script: &Script<T>, opcode: Opcode) -> bool {
    script
        .instructions()
        .any(|ins| matches!(ins, Ok(Instruction::Op(op)) if op == opcode))
}

fn script_contains_pq_material<T>(script: &Script<T>) -> bool {
    script.instructions().any(|ins| match ins {
        Ok(Instruction::PushBytes(bytes)) => PqPublicKey::from_prefixed_slice(bytes.as_bytes()).is_ok(),
        _ => false,
    })
}

fn witness_contains_pq_material(witness: &Witness) -> bool {
    witness.iter().any(|item| PqPublicKey::from_prefixed_slice(item).is_ok())
}

fn witness_contains_opcode_script(witness: &Witness, opcode: Opcode) -> bool {
    witness
        .last()
        .map(WitnessScript::from_bytes)
        .is_some_and(|script| script_contains_opcode(script, opcode))
}

fn split_signature_hash_type(sig: &[u8]) -> (&[u8], u8) {
    match sig.split_last() {
        Some((&hash_type, body)) => (body, hash_type),
        None => (&[], 0),
    }
}

fn bool_bytes(value: bool) -> Vec<u8> {
    if value {
        vec![1]
    } else {
        Vec::new()
    }
}

fn encode_script_num(value: i64) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let len = crate::script::write_scriptint(&mut buf, value);
    buf[..len].to_vec()
}

fn decode_script_num(bytes: &[u8]) -> Result<i64, TidecoinValidationError> {
    read_scriptint_non_minimal(bytes)
        .map(i64::from)
        .map_err(|_| TidecoinValidationError::Script(ScriptError::InvalidStackOperation))
}

fn op_to_num(op: Opcode) -> i64 {
    let v = op.to_u8();
    match v {
        0x4f => -1,
        0x51..=0x60 => i64::from(v - 0x50),
        _ => 0,
    }
}

fn find_and_delete(script: &[u8], needle: &[u8]) -> (Vec<u8>, bool) {
    if needle.is_empty() || needle.len() > script.len() {
        return (script.to_vec(), false);
    }

    let mut out = Vec::with_capacity(script.len());
    let mut i = 0usize;
    let mut found = false;
    while i < script.len() {
        if i + needle.len() <= script.len() && script[i..i + needle.len()] == *needle {
            found = true;
            i += needle.len();
        } else {
            out.push(script[i]);
            i += 1;
        }
    }
    (out, found)
}

fn push_script(data: &[u8]) -> Vec<u8> {
    let bytes = PushBytesBuf::try_from(data.to_vec()).expect("push size bounded by script limits");
    ScriptSigBuf::builder().push_slice(bytes).into_bytes()
}

fn check_lock_time(top: &[u8], ctx: EvalContext<'_>) -> Result<(), TidecoinValidationError> {
    let lock_time = decode_script_num(top)?;
    if lock_time < 0 {
        return Err(TidecoinValidationError::Script(ScriptError::NegativeLocktime));
    }

    let required = absolute::LockTime::from_consensus(lock_time as u32);
    if !required.is_same_unit(ctx.tx.lock_time) || !required.is_implied_by(ctx.tx.lock_time) {
        return Err(TidecoinValidationError::Script(
            ScriptError::UnsatisfiedLocktime,
        ));
    }

    if ctx.tx.inputs[ctx.input_index].sequence == Sequence::MAX {
        return Err(TidecoinValidationError::Script(
            ScriptError::UnsatisfiedLocktime,
        ));
    }

    Ok(())
}

fn check_sequence(top: &[u8], ctx: EvalContext<'_>) -> Result<(), TidecoinValidationError> {
    let sequence = decode_script_num(top)?;
    if sequence < 0 {
        return Err(TidecoinValidationError::Script(ScriptError::NegativeLocktime));
    }

    if ctx.tx.version.to_u32() < 2 {
        return Err(TidecoinValidationError::Script(
            ScriptError::UnsatisfiedLocktime,
        ));
    }

    let tx_sequence = ctx.tx.inputs[ctx.input_index].sequence.to_consensus_u32();
    if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        return Err(TidecoinValidationError::Script(
            ScriptError::UnsatisfiedLocktime,
        ));
    }

    let seq = sequence as u32;
    let tx_masked = tx_sequence & (SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK);
    let seq_masked = seq & (SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK);

    let same_unit =
        (tx_masked < SEQUENCE_LOCKTIME_TYPE_FLAG && seq_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)
            || (tx_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG
                && seq_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG);
    if !same_unit || seq_masked > tx_masked {
        return Err(TidecoinValidationError::Script(
            ScriptError::UnsatisfiedLocktime,
        ));
    }

    Ok(())
}
