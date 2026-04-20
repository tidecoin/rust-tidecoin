// SPDX-License-Identifier: CC0-1.0

#![allow(missing_docs)]

use core::fmt;

#[cfg(test)]
use consensus_core::{
    VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_CONST_SCRIPTCODE,
    VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    VERIFY_MINIMALDATA, VERIFY_MINIMALIF, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_NULLFAIL,
    VERIFY_PQ_STRICT, VERIFY_SHA512, VERIFY_SIGPUSHONLY, VERIFY_WITNESS_V1_512,
};
use consensus_core::{VERIFY_CLEANSTACK, VERIFY_P2SH, VERIFY_WITNESS};
use internals::hex::DisplayHex as _;
pub use node_parity::ScriptError;
use node_parity::{NodeParityError, TidecoinNodeHarness};

use crate::amount::Amount;
use crate::prelude::String;
#[cfg(test)]
use crate::prelude::Vec;
use crate::script::ScriptPubKey;
#[cfg(test)]
use crate::script::{ScriptPubKeyBuf, ScriptSigBuf};
use crate::transaction::{OutPoint, Transaction};
#[cfg(test)]
use crate::Witness;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TidecoinValidationError {
    Script(ScriptError),
    InvalidInputIndex { index: usize, inputs: usize },
    InvalidFlags,
    AmountRequired,
    MissingSpentOutput(OutPoint),
    BridgeFailure(&'static str),
}

fn encode_consensus_hex<T: encoding::Encodable + ?Sized>(value: &T) -> String {
    encoding::encode_to_vec(value).to_lower_hex_string()
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
            Self::MissingSpentOutput(outpoint) => write!(f, "missing spent output {}", outpoint),
            Self::BridgeFailure(name) => {
                write!(f, "tidecoin node validation bridge call failed: {}", name)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TidecoinValidationError {}

impl From<consensus_core::TidecoinValidationError> for TidecoinValidationError {
    fn from(value: consensus_core::TidecoinValidationError) -> Self {
        match value {
            consensus_core::TidecoinValidationError::Script(err) => {
                Self::Script(map_core_script_error(err))
            }
            consensus_core::TidecoinValidationError::InvalidInputIndex { index, inputs } => {
                Self::InvalidInputIndex { index, inputs }
            }
            consensus_core::TidecoinValidationError::InvalidFlags => Self::InvalidFlags,
            consensus_core::TidecoinValidationError::AmountRequired => Self::AmountRequired,
            consensus_core::TidecoinValidationError::MissingSpentOutput(outpoint) => {
                Self::MissingSpentOutput(outpoint)
            }
        }
    }
}

fn map_core_script_error(value: consensus_core::ScriptError) -> ScriptError {
    match value {
        consensus_core::ScriptError::Ok => ScriptError::Ok,
        consensus_core::ScriptError::Unknown => ScriptError::UnknownError,
        consensus_core::ScriptError::EvalFalse => ScriptError::EvalFalse,
        consensus_core::ScriptError::OpReturn => ScriptError::OpReturn,
        consensus_core::ScriptError::ScriptSize => ScriptError::ScriptSize,
        consensus_core::ScriptError::PushSize => ScriptError::PushSize,
        consensus_core::ScriptError::OpCount => ScriptError::OpCount,
        consensus_core::ScriptError::StackSize => ScriptError::StackSize,
        consensus_core::ScriptError::SigCount => ScriptError::SigCount,
        consensus_core::ScriptError::PubkeyCount => ScriptError::PubkeyCount,
        consensus_core::ScriptError::Verify => ScriptError::Verify,
        consensus_core::ScriptError::EqualVerify => ScriptError::EqualVerify,
        consensus_core::ScriptError::CheckSigVerify => ScriptError::CheckSigVerify,
        consensus_core::ScriptError::CheckMultiSigVerify => ScriptError::CheckMultisigVerify,
        consensus_core::ScriptError::NumEqualVerify => ScriptError::NumEqualVerify,
        consensus_core::ScriptError::BadOpcode => ScriptError::BadOpcode,
        consensus_core::ScriptError::OpCodeSeparator => ScriptError::OpCodeSeparator,
        consensus_core::ScriptError::DisabledOpcode => ScriptError::DisabledOpcode,
        consensus_core::ScriptError::InvalidStackOperation => ScriptError::InvalidStackOperation,
        consensus_core::ScriptError::InvalidAltstackOperation => {
            ScriptError::InvalidAltstackOperation
        }
        consensus_core::ScriptError::UnbalancedConditional => ScriptError::UnbalancedConditional,
        consensus_core::ScriptError::NegativeLockTime => ScriptError::NegativeLocktime,
        consensus_core::ScriptError::UnsatisfiedLockTime => ScriptError::UnsatisfiedLocktime,
        consensus_core::ScriptError::SigHashType => ScriptError::SigHashType,
        consensus_core::ScriptError::MinimalData => ScriptError::MinimalData,
        consensus_core::ScriptError::SigPushOnly => ScriptError::SigPushOnly,
        consensus_core::ScriptError::SigNullDummy => ScriptError::SigNullDummy,
        consensus_core::ScriptError::CleanStack => ScriptError::Cleanstack,
        consensus_core::ScriptError::MinimalIf => ScriptError::MinimalIf,
        consensus_core::ScriptError::NullFail => ScriptError::NullFail,
        consensus_core::ScriptError::DiscourageUpgradableNops => {
            ScriptError::DiscourageUpgradableNops
        }
        consensus_core::ScriptError::DiscourageUpgradableWitnessProgram => {
            ScriptError::DiscourageUpgradableWitnessProgram
        }
        consensus_core::ScriptError::WitnessProgramWrongLength => {
            ScriptError::WitnessProgramWrongLength
        }
        consensus_core::ScriptError::WitnessProgramWitnessEmpty => {
            ScriptError::WitnessProgramWitnessEmpty
        }
        consensus_core::ScriptError::WitnessProgramMismatch => ScriptError::WitnessProgramMismatch,
        consensus_core::ScriptError::WitnessMalleated => ScriptError::WitnessMalleated,
        consensus_core::ScriptError::WitnessMalleatedP2SH => ScriptError::WitnessMalleatedP2sh,
        consensus_core::ScriptError::WitnessUnexpected => ScriptError::WitnessUnexpected,
        consensus_core::ScriptError::SigFindAndDelete => ScriptError::SigFindAndDelete,
    }
}

pub(crate) fn verify_script_input(
    script_pubkey: &ScriptPubKey,
    index: usize,
    amount: Amount,
    tx: &Transaction,
    flags: u32,
) -> Result<(), TidecoinValidationError> {
    if index >= tx.inputs.len() {
        return Err(TidecoinValidationError::InvalidInputIndex { index, inputs: tx.inputs.len() });
    }

    TidecoinNodeHarness::from_env()
        .map_err(map_node_parity_error)?
        .verify_tx_input_hex(
            &encode_consensus_hex(tx),
            index,
            script_pubkey.as_bytes(),
            amount.to_sat().try_into().unwrap(),
            normalize_flags(flags),
        )
        .map_err(map_node_parity_error)
}

#[cfg(test)]
fn check_transaction_sanity(tx: &Transaction) -> Result<(), TidecoinValidationError> {
    TidecoinNodeHarness::from_env()
        .map_err(map_node_parity_error)?
        .check_transaction_hex(&encode_consensus_hex(tx))
        .map_err(map_node_parity_error)
}

fn normalize_flags(mut flags: u32) -> u32 {
    if flags & VERIFY_CLEANSTACK != 0 {
        flags |= VERIFY_P2SH | VERIFY_WITNESS;
    }
    flags
}

#[cfg(test)]
fn parse_script_asm(script_asm: &str) -> Result<Vec<u8>, TidecoinValidationError> {
    TidecoinNodeHarness::from_env()
        .map_err(map_node_parity_error)?
        .parse_script_asm(script_asm)
        .map_err(map_node_parity_error)
}

#[cfg(test)]
fn verify_script_case(
    script_sig: &ScriptSigBuf,
    script_pubkey: &ScriptPubKeyBuf,
    witness: &Witness,
    amount: Amount,
    flags: u32,
) -> Result<(), TidecoinValidationError> {
    let witness_items: Vec<&[u8]> = witness.iter().collect();
    TidecoinNodeHarness::from_env()
        .map_err(map_node_parity_error)?
        .verify_script_case(
            script_sig.as_bytes(),
            script_pubkey.as_bytes(),
            &witness_items,
            amount.to_sat().try_into().unwrap(),
            normalize_flags(flags),
        )
        .map_err(map_node_parity_error)
}

fn map_node_parity_error(err: NodeParityError) -> TidecoinValidationError {
    match err {
        NodeParityError::Script(script_err) => TidecoinValidationError::Script(script_err),
        NodeParityError::Environment(_) => {
            TidecoinValidationError::BridgeFailure("TidecoinNodeHarness::from_env")
        }
        NodeParityError::InvalidCString(name) | NodeParityError::BridgeFailure(name) => {
            TidecoinValidationError::BridgeFailure(name)
        }
        _ => TidecoinValidationError::BridgeFailure("node_parity"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::thread;

    use hashes::{sha256, sha256d, sha512, HashEngine as _};
    use node_parity::fixtures::test_data_path;
    use serde_json::Value;

    use super::*;
    use crate::absolute;
    use crate::block::Header;
    use crate::crypto::pq::{
        PqPublicKey, PqScheme, PqSchemeCryptoExt as _, PqSecretKey, PqSignature,
    };
    use crate::opcodes::all::{
        OP_ADD, OP_CHECKMULTISIG, OP_CHECKSIG, OP_DROP, OP_DUP, OP_EQUAL, OP_EQUALVERIFY,
        OP_FROMALTSTACK, OP_HASH160, OP_NUMEQUAL, OP_SHA256, OP_SHA512, OP_TOALTSTACK, OP_TRUE,
    };
    use crate::pqhd;
    use crate::script::PushBytesBuf;
    use crate::script::ScriptExt as _;
    use crate::script::ScriptPubKeyBufExt as _;
    use crate::script::{ScriptBufExt as _, ScriptPubKeyBuf, ScriptSigBuf, WitnessScriptBuf};
    use crate::transaction::{self, OutPoint, Transaction, TxIn};
    use crate::Weight;
    use crate::{Address, Amount, Network, PqWifKey, Sequence, TxOut, TxSighashType, Txid};
    use crate::{Block, BlockTime, CompactTarget, TxMerkleNode};
    use consensus_core::SighashCache;

    fn node_harness_available() -> bool {
        match TidecoinNodeHarness::from_env() {
            Ok(_) => true,
            Err(err) => {
                std::eprintln!("skipping Tidecoin node-backed validation test: {err}");
                false
            }
        }
    }

    macro_rules! require_node_harness {
        () => {
            if !node_harness_available() {
                return;
            }
        };
    }

    fn node_harness() -> TidecoinNodeHarness {
        TidecoinNodeHarness::from_env().expect("TidecoinNodeHarness::from_env")
    }

    fn read_json(name: &str) -> Value {
        let path = test_data_path(name);
        let data = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
    }

    fn tagged_seed(tag: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| tag ^ (i as u8).wrapping_mul(131)).collect()
    }

    fn deterministic_keypair(scheme: PqScheme, tag: u8) -> (PqPublicKey, PqSecretKey) {
        let seed = tagged_seed(tag, scheme.deterministic_seed_len());
        scheme.generate_keypair_from_seed(&seed).unwrap()
    }

    fn node_keypair_from_seed(scheme: PqScheme, seed: &[u8]) -> (PqPublicKey, PqSecretKey) {
        let (pk, sk) = node_harness()
            .pq_keypair_from_seed(scheme.prefix(), seed, scheme.pubkey_len(), scheme.seckey_len())
            .unwrap_or_else(|e| panic!("pq_keypair_from_seed failed for {:?}: {}", scheme, e));
        (
            PqPublicKey::from_prefixed_slice(&[&[scheme.prefix()][..], &pk].concat()).unwrap(),
            PqSecretKey::from_prefixed_slice(&[&[scheme.prefix()][..], &sk].concat()).unwrap(),
        )
    }

    fn node_keypair_from_stream_key(
        scheme: PqScheme,
        stream_key: &[u8],
    ) -> (PqPublicKey, PqSecretKey) {
        let (pk, sk) = node_harness()
            .pq_keypair_from_stream_key(
                scheme.prefix(),
                stream_key,
                scheme.pubkey_len(),
                scheme.seckey_len(),
            )
            .unwrap_or_else(|e| {
                panic!("pq_keypair_from_stream_key failed for {:?}: {}", scheme, e)
            });
        (
            PqPublicKey::from_prefixed_slice(&[&[scheme.prefix()][..], &pk].concat()).unwrap(),
            PqSecretKey::from_prefixed_slice(&[&[scheme.prefix()][..], &sk].concat()).unwrap(),
        )
    }

    fn node_public_key_from_secret(scheme: PqScheme, sk: &PqSecretKey) -> PqPublicKey {
        let pk = node_harness()
            .pq_public_key_from_secret(scheme.prefix(), sk.as_bytes(), scheme.pubkey_len())
            .unwrap_or_else(|e| panic!("pq_public_key_from_secret failed for {:?}: {}", scheme, e));
        PqPublicKey::from_prefixed_slice(&[&[scheme.prefix()][..], &pk].concat()).unwrap()
    }

    fn node_sign_message(
        scheme: PqScheme,
        msg: &[u8],
        sk: &PqSecretKey,
        legacy: bool,
    ) -> PqSignature {
        let sig = node_harness()
            .pq_sign_message(scheme.prefix(), msg, sk.as_bytes(), scheme.max_sig_len(), legacy)
            .unwrap_or_else(|e| panic!("pq_sign_message failed for {:?}: {}", scheme, e));
        PqSignature::from_slice(&sig)
    }

    fn node_verify_message(
        scheme: PqScheme,
        msg: &[u8],
        sig: &PqSignature,
        pk: &PqPublicKey,
        legacy: bool,
    ) -> bool {
        node_harness()
            .pq_verify_message(scheme.prefix(), msg, sig.as_bytes(), pk.as_bytes(), legacy)
            .unwrap_or_else(|e| panic!("pq_verify_message failed for {:?}: {}", scheme, e))
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
        TxSighashType::All.to_u32() as u8
    }

    fn witness_v0_sig(
        tx: &Transaction,
        input_index: usize,
        amount: Amount,
        witness_script: &WitnessScriptBuf,
        sk: &PqSecretKey,
        legacy: bool,
    ) -> Vec<u8> {
        let mut cache = SighashCache::new(tx);
        let sighash = cache
            .p2wsh_signature_hash(
                input_index,
                witness_script.as_script().as_bytes(),
                amount,
                TxSighashType::All,
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
                witness_script.as_script().as_bytes(),
                amount,
                TxSighashType::All,
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
                script_pubkey.as_script().as_bytes(),
                TxSighashType::All.to_u32(),
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
        ScriptPubKeyBuf::builder().push_int(0).unwrap().push_slice(program).into_script()
    }

    fn wrapped_p2wsh(script: &WitnessScriptBuf) -> (ScriptPubKeyBuf, ScriptSigBuf) {
        let redeem_script = direct_p2wsh_script_pubkey(script);
        let script_pubkey =
            ScriptPubKeyBuf::new_p2sh(redeem_script.as_script().script_hash().unwrap());
        let script_sig =
            ScriptSigBuf::builder().push_slice(push_bytes(redeem_script.as_bytes())).into_script();
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

    fn verify_multisig_case(
        keys: &[(PqPublicKey, PqSecretKey)],
        m: usize,
        wrap: bool,
        flags: u32,
        legacy: bool,
    ) {
        let pubkeys: Vec<PqPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let signers: Vec<PqSecretKey> = keys.iter().take(m).map(|(_, sk)| sk.clone()).collect();
        let witness_script = multisig_witness_script(&pubkeys, m as i32);
        let amount = Amount::from_sat_u32(1);
        let mut tx = tx_template(1);
        let script_pubkey = if wrap {
            let (spk, script_sig) = wrapped_p2wsh(&witness_script);
            tx.inputs[0].script_sig = script_sig;
            spk
        } else {
            direct_p2wsh_script_pubkey(&witness_script)
        };
        tx.inputs[0].witness =
            signed_multisig_witness(&tx, 0, amount, &witness_script, &signers, legacy);
        verify_script_input(&script_pubkey, 0, amount, &tx, flags).unwrap();
    }

    fn verify_committed_hash_case(
        keys: &[(PqPublicKey, PqSecretKey)],
        m: usize,
        wrap: bool,
        flags: u32,
        legacy: bool,
    ) {
        let pubkeys: Vec<PqPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let witness_script = committed_hash_witness_script(&pubkeys, m as i32);
        let amount = Amount::from_sat_u32(1);
        let mut tx = tx_template(1);
        let script_pubkey = if wrap {
            let (spk, script_sig) = wrapped_p2wsh(&witness_script);
            tx.inputs[0].script_sig = script_sig;
            spk
        } else {
            direct_p2wsh_script_pubkey(&witness_script)
        };
        tx.inputs[0].witness =
            signed_committed_hash_witness(&tx, 0, amount, &witness_script, keys, m, legacy);
        verify_script_input(&script_pubkey, 0, amount, &tx, flags).unwrap();
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
        ScriptError::from_name(name).unwrap_or_else(|| panic!("unknown script error {}", name))
    }

    fn parse_hex_bytes(value: &str) -> Vec<u8> {
        if let Some(rest) = value.strip_prefix("0x") {
            crate::hex::decode_to_vec(rest).unwrap()
        } else {
            crate::hex::decode_to_vec(value).unwrap()
        }
    }

    fn decode_consensus_hex<T: encoding::Decodable>(
        value: &str,
    ) -> Result<T, encoding::DecodeError<<T::Decoder as encoding::Decoder>::Error>> {
        encoding::decode_from_slice(&parse_hex_bytes(value))
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
            let tdc: f64 = text.parse().unwrap();
            Amount::from_sat((tdc * 100_000_000.0).round() as u64).unwrap()
        } else if let Some(tdc) = value.as_f64() {
            Amount::from_sat((tdc * 100_000_000.0).round() as u64).unwrap()
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
        OutPoint { txid: txid_hex.parse().unwrap(), vout }
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

    fn run_with_large_stack(name: &'static str, f: impl FnOnce() + Send + 'static) {
        thread::Builder::new()
            .name(name.into())
            .stack_size(32 << 20)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn script_tests_pq_json_roundtrip() {
        require_node_harness!();

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
                (other, expected) => {
                    panic!("unexpected result {:?} for expected {:?} at {}", other, expected, idx)
                }
            }
        }
    }

    #[test]
    fn tx_valid_pq_json_roundtrip() {
        require_node_harness!();

        let tests = read_json("tx_valid_pq.json").as_array().unwrap().clone();
        assert!(!tests.is_empty());

        for (idx, test) in tests.iter().enumerate() {
            let row = test.as_array().unwrap();
            let (prevouts, _) = parse_tx_inputs(&row[0]);
            let tx: Transaction = decode_consensus_hex(row[1].as_str().unwrap()).unwrap();
            let flags = fill_flags(parse_script_flags(row[2].as_str().unwrap()));

            check_transaction_sanity(&tx)
                .unwrap_or_else(|e| panic!("valid tx sanity failed at {}: {}", idx, e));
            for (input_idx, input) in tx.inputs.iter().enumerate() {
                let spent = prevouts.get(&input.previous_output).unwrap();
                verify_script_input(&spent.script_pubkey, input_idx, spent.amount, &tx, flags)
                    .unwrap_or_else(|e| {
                        panic!("tx_valid_pq[{}] input {} failed: {}", idx, input_idx, e)
                    });
            }
        }
    }

    #[test]
    fn tx_invalid_pq_json_roundtrip() {
        require_node_harness!();

        let tests = read_json("tx_invalid_pq.json").as_array().unwrap().clone();
        assert!(!tests.is_empty());

        for (idx, test) in tests.iter().enumerate() {
            let row = test.as_array().unwrap();
            let (prevouts, _) = parse_tx_inputs(&row[0]);
            let tx: Transaction = decode_consensus_hex(row[1].as_str().unwrap()).unwrap();
            let flags = row[2].as_str().unwrap();

            if flags == "BADTX" {
                assert!(
                    check_transaction_sanity(&tx).is_err(),
                    "tx_invalid_pq[{}] should be structurally invalid",
                    idx
                );
                continue;
            }

            let flags = fill_flags(parse_script_flags(flags));
            let mut any_failed = false;
            for (input_idx, input) in tx.inputs.iter().enumerate() {
                let spent = prevouts.get(&input.previous_output).unwrap();
                if verify_script_input(&spent.script_pubkey, input_idx, spent.amount, &tx, flags)
                    .is_err()
                {
                    any_failed = true;
                    break;
                }
            }
            assert!(any_failed, "tx_invalid_pq[{}] unexpectedly passed", idx);
        }
    }

    fn coinbase_sanity_tx(script_sig_len: usize) -> Transaction {
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE_PREVOUT,
                script_sig: ScriptSigBuf::from_bytes(vec![0x51; script_sig_len]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        }
    }

    fn zero_input_sanity_tx() -> Transaction {
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        }
    }

    fn spend_sanity_input(tag: u8) -> TxIn {
        TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: tag.into() },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }
    }

    fn spend_sanity_tx(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs,
            outputs,
        }
    }

    fn zero_output_sanity_tx() -> Transaction {
        spend_sanity_tx(vec![spend_sanity_input(0x11)], vec![])
    }

    fn duplicate_input_sanity_tx() -> Transaction {
        let input = spend_sanity_input(0x12);
        spend_sanity_tx(
            vec![input.clone(), input],
            vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        )
    }

    fn null_prevout_non_coinbase_sanity_tx() -> Transaction {
        let mut input = spend_sanity_input(0x13);
        input.previous_output = OutPoint::COINBASE_PREVOUT;
        spend_sanity_tx(
            vec![input, spend_sanity_input(0x14)],
            vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        )
    }

    fn oversized_stripped_sanity_tx() -> Transaction {
        let oversized_script_len = (Weight::MAX_BLOCK.to_wu() / Weight::WITNESS_SCALE_FACTOR + 1)
            .try_into()
            .expect("max block size fits usize");
        let mut tx = spend_sanity_tx(
            vec![spend_sanity_input(0x15)],
            vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        );
        tx.inputs[0].script_sig = ScriptSigBuf::from_bytes(vec![0x51; oversized_script_len]);
        tx
    }

    #[test]
    fn check_transaction_sanity_edges_match_node() {
        require_node_harness!();

        let harness = node_harness();
        let cases = [
            ("zero_inputs", zero_input_sanity_tx(), false),
            ("zero_outputs", zero_output_sanity_tx(), false),
            ("duplicate_input", duplicate_input_sanity_tx(), false),
            ("null_prevout_non_coinbase", null_prevout_non_coinbase_sanity_tx(), false),
            ("oversized_stripped", oversized_stripped_sanity_tx(), false),
            ("coinbase_scriptsig_1", coinbase_sanity_tx(1), false),
            ("coinbase_scriptsig_2", coinbase_sanity_tx(2), true),
            ("coinbase_scriptsig_100", coinbase_sanity_tx(100), true),
            ("coinbase_scriptsig_101", coinbase_sanity_tx(101), true),
            ("coinbase_scriptsig_106", coinbase_sanity_tx(106), true),
            ("coinbase_scriptsig_107", coinbase_sanity_tx(107), false),
        ];

        for (name, tx, expected_valid) in cases {
            let tx_hex = encode_consensus_hex(&tx);
            let node_valid = harness.check_transaction_hex(&tx_hex).is_ok();
            let rust_decode = decode_consensus_hex::<Transaction>(&tx_hex);

            assert_eq!(node_valid, expected_valid, "{name} node sanity");
            assert_eq!(rust_decode.is_ok(), expected_valid, "{name} Rust decode sanity");
            if let Ok(tx) = rust_decode {
                transaction::check_transaction_sanity(&tx)
                    .unwrap_or_else(|err| panic!("{name} primitive sanity: {err}"));
                assert!(
                    check_transaction_sanity(&tx).is_ok(),
                    "{name} decoded Rust transaction should pass node sanity"
                );
            }
        }
    }

    fn block_coinbase(script_sig_len: usize, output_tag: u8) -> Transaction {
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE_PREVOUT,
                script_sig: ScriptSigBuf::from_bytes(vec![0x51; script_sig_len]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                amount: Amount::ONE_SAT,
                script_pubkey: ScriptPubKeyBuf::from_bytes(vec![output_tag]),
            }],
        }
    }

    fn block_spend(tag: u8) -> Transaction {
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([tag; 32]),
                    vout: tag.into(),
                },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                amount: Amount::ONE_SAT,
                script_pubkey: ScriptPubKeyBuf::from_bytes(vec![tag]),
            }],
        }
    }

    fn block_from_transactions(transactions: Vec<Transaction>) -> Block {
        let merkle_root = crate::block::compute_merkle_root(&transactions)
            .unwrap_or_else(|| TxMerkleNode::from_byte_array([0; 32]));
        Block::new_unchecked(
            Header {
                version: crate::block::Version::ONE,
                prev_blockhash: crate::BlockHash::from_byte_array([0x11; 32]),
                merkle_root,
                time: BlockTime::from_u32(1_700_000_000),
                bits: CompactTarget::from_consensus(0x200f_0f0f),
                nonce: 0,
                auxpow: None,
            },
            transactions,
        )
    }

    fn block_with_merkle(transactions: Vec<Transaction>, merkle_root: TxMerkleNode) -> Block {
        Block::new_unchecked(
            Header {
                version: crate::block::Version::ONE,
                prev_blockhash: crate::BlockHash::from_byte_array([0x11; 32]),
                merkle_root,
                time: BlockTime::from_u32(1_700_000_000),
                bits: CompactTarget::from_consensus(0x200f_0f0f),
                nonce: 0,
                auxpow: None,
            },
            transactions,
        )
    }

    fn merkle_root_allow_mutation(transactions: &[Transaction]) -> TxMerkleNode {
        let mut hashes =
            transactions.iter().map(|tx| tx.compute_txid().to_byte_array()).collect::<Vec<_>>();
        assert!(!hashes.is_empty(), "test helper requires at least one transaction");

        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 {
                hashes.push(*hashes.last().expect("nonempty hashes"));
            }

            let mut next = Vec::with_capacity(hashes.len() / 2);
            for pair in hashes.chunks_exact(2) {
                let mut engine = sha256d::Hash::engine();
                engine.input(&pair[0]);
                engine.input(&pair[1]);
                next.push(sha256d::Hash::from_engine(engine).to_byte_array());
            }
            hashes = next;
        }

        TxMerkleNode::from_byte_array(hashes[0])
    }

    fn duplicate_txid_merkle_mutation_block() -> Block {
        let mut transactions = vec![block_coinbase(2, 0x51), block_spend(0x22), block_spend(0x23)];
        transactions.push(transactions[2].clone());
        let merkle_root = merkle_root_allow_mutation(&transactions);
        block_with_merkle(transactions, merkle_root)
    }

    fn oversized_stripped_block() -> Block {
        let mut coinbase = block_coinbase(2, 0x51);
        coinbase.outputs[0].script_pubkey = ScriptPubKeyBuf::from_bytes(vec![0x51; 1_500_100]);
        block_from_transactions(vec![coinbase])
    }

    #[test]
    fn check_block_sanity_edges_match_node() {
        require_node_harness!();

        let mut too_many_sigops = block_coinbase(2, 0x51);
        too_many_sigops.outputs[0].script_pubkey =
            ScriptPubKeyBuf::from_bytes(vec![OP_CHECKSIG.to_u8(); 20_001]);

        let bad_merkle = block_with_merkle(
            vec![block_coinbase(2, 0x51)],
            TxMerkleNode::from_byte_array([0xff; 32]),
        );

        let cases = [
            ("valid", block_from_transactions(vec![block_coinbase(2, 0x51)]), true),
            ("no_transactions", block_from_transactions(vec![]), false),
            ("missing_coinbase", block_from_transactions(vec![block_spend(0x22)]), false),
            (
                "multiple_coinbase",
                block_from_transactions(vec![block_coinbase(2, 0x51), block_coinbase(3, 0x52)]),
                false,
            ),
            ("bad_merkle", bad_merkle, false),
            ("duplicate_txid_merkle_mutation", duplicate_txid_merkle_mutation_block(), false),
            ("bad_transaction", block_from_transactions(vec![block_coinbase(1, 0x51)]), false),
            ("too_many_legacy_sigops", block_from_transactions(vec![too_many_sigops]), false),
            ("oversized_stripped_block", oversized_stripped_block(), false),
        ];

        let harness = node_harness();
        for (name, block, expected_valid) in cases {
            let block_hex = encode_consensus_hex(&block);
            let node_valid = harness.check_block_hex(&block_hex, 2, false, true).is_ok();
            let rust_valid = crate::block::check_block_sanity(&block).is_ok();

            assert_eq!(node_valid, expected_valid, "{name} node block sanity");
            assert_eq!(rust_valid, expected_valid, "{name} Rust block sanity");
        }
    }

    #[test]
    fn script_assets_json_monotonicity() {
        require_node_harness!();

        let tests = read_json("script_assets_test.json").as_array().unwrap().clone();
        assert!(!tests.is_empty());
        let all_flags = all_consensus_flags();

        for (idx, test) in tests.iter().enumerate() {
            let obj = test.as_object().unwrap();
            let mut tx: Transaction = decode_consensus_hex(obj["tx"].as_str().unwrap()).unwrap();
            let prevouts: Vec<TxOut> = obj["prevouts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| decode_consensus_hex(entry.as_str().unwrap()).unwrap())
                .collect();
            assert_eq!(
                prevouts.len(),
                tx.inputs.len(),
                "script_assets_test[{}] prevouts/input mismatch",
                idx
            );
            let index = obj["index"].as_u64().unwrap() as usize;
            let test_flags = parse_script_flags(obj["flags"].as_str().unwrap());
            let is_final = obj.get("final").and_then(Value::as_bool).unwrap_or(false);

            if let Some(success) = obj.get("success") {
                tx.inputs[index].script_sig = ScriptSigBuf::from_bytes(parse_hex_bytes(
                    success["scriptSig"].as_str().unwrap(),
                ));
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
                        verify_script_input(
                            &prevout.script_pubkey,
                            index,
                            prevout.amount,
                            &tx,
                            *flags,
                        )
                        .unwrap_or_else(|e| {
                            panic!(
                                "script_assets_test[{}] success failed under {:x}: {}",
                                idx, flags, e
                            )
                        });
                    }
                }
            }

            if let Some(failure) = obj.get("failure") {
                tx.inputs[index].script_sig = ScriptSigBuf::from_bytes(parse_hex_bytes(
                    failure["scriptSig"].as_str().unwrap(),
                ));
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
                            verify_script_input(
                                &prevout.script_pubkey,
                                index,
                                prevout.amount,
                                &tx,
                                *flags
                            )
                            .is_err(),
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
        require_node_harness!();

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
        require_node_harness!();

        let input = PushBytesBuf::try_from(vec![0x01, 0x02, 0x03]).unwrap();
        let expected =
            PushBytesBuf::try_from(sha512::Hash::hash(input.as_bytes()).to_byte_array().to_vec())
                .unwrap();
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
            Err(TidecoinValidationError::Script(ScriptError::DiscourageUpgradableNops,))
        );

        assert_eq!(
            verify_script_case(
                &ScriptSigBuf::new(),
                &ScriptPubKeyBuf::builder().push_opcode(OP_SHA512).into_script(),
                &Witness::default(),
                Amount::from_sat(0).unwrap(),
                VERIFY_SHA512,
            ),
            Err(TidecoinValidationError::Script(ScriptError::InvalidStackOperation,))
        );

        let max_input = PushBytesBuf::try_from(vec![0x42; 8192]).unwrap();
        let max_expected = PushBytesBuf::try_from(
            sha512::Hash::hash(max_input.as_bytes()).to_byte_array().to_vec(),
        )
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
        require_node_harness!();

        let witness_script = ScriptPubKeyBuf::builder().push_opcode(OP_TRUE).into_script();
        let program = sha512::Hash::hash(witness_script.as_bytes()).to_byte_array();
        let script_pubkey =
            ScriptPubKeyBuf::builder().push_int(1).unwrap().push_slice(program).into_script();
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
            Err(TidecoinValidationError::Script(ScriptError::DiscourageUpgradableWitnessProgram,))
        );
    }

    fn witness_v1_512_script_with_size(len: usize) -> ScriptPubKeyBuf {
        let mut builder = ScriptPubKeyBuf::builder();
        let full_chunk = PushBytesBuf::try_from(vec![0x42; 8192]).unwrap();
        for _ in 0..7 {
            builder = builder.push_slice(&full_chunk).push_opcode(OP_DROP);
        }
        let used = 7 * (3 + 8192 + 1) + 1;
        let tail_len = len.checked_sub(used + 4).expect("script size too small for fixture");
        let tail = PushBytesBuf::try_from(vec![0x24; tail_len]).unwrap();
        builder.push_slice(&tail).push_opcode(OP_DROP).push_opcode(OP_TRUE).into_script()
    }

    fn verify_witness_v1_512_script_size(script_len: usize) -> Result<(), TidecoinValidationError> {
        let witness_script = witness_v1_512_script_with_size(script_len);
        assert_eq!(witness_script.len(), script_len);
        let program = sha512::Hash::hash(witness_script.as_bytes()).to_byte_array();
        let script_pubkey =
            ScriptPubKeyBuf::builder().push_int(1).unwrap().push_slice(program).into_script();
        let witness = Witness::from_slice(&[witness_script.as_bytes()]);
        verify_script_case(
            &ScriptSigBuf::new(),
            &script_pubkey,
            &witness,
            Amount::from_sat(0).unwrap(),
            VERIFY_WITNESS | VERIFY_P2SH | VERIFY_WITNESS_V1_512,
        )
    }

    #[test]
    fn witness_v1_512_script_size_boundary_matches_node() {
        require_node_harness!();

        verify_witness_v1_512_script_size(65_536).unwrap();
        assert_eq!(
            verify_witness_v1_512_script_size(65_537),
            Err(TidecoinValidationError::Script(ScriptError::ScriptSize))
        );
    }

    #[test]
    fn witness_v0_v1_mix_matches_node_case() {
        require_node_harness!();

        let witness_script_v0 = WitnessScriptBuf::from_bytes(
            ScriptPubKeyBuf::builder().push_opcode(OP_TRUE).into_script().into_bytes(),
        );
        let witness_script_v1 = WitnessScriptBuf::from_bytes(
            ScriptPubKeyBuf::builder().push_opcode(OP_TRUE).into_script().into_bytes(),
        );
        let script_pubkey_v0 = direct_p2wsh_script_pubkey(&witness_script_v0);
        let program_v1 = sha512::Hash::hash(witness_script_v1.as_bytes()).to_byte_array();
        let script_pubkey_v1 =
            ScriptPubKeyBuf::builder().push_int(1).unwrap().push_slice(program_v1).into_script();

        let mut tx = tx_template(2);
        tx.inputs[0].witness = Witness::from_slice(&[witness_script_v0.as_bytes()]);
        tx.inputs[1].witness = Witness::from_slice(&[witness_script_v1.as_bytes()]);

        let flags = VERIFY_WITNESS | VERIFY_P2SH | VERIFY_WITNESS_V1_512 | VERIFY_SHA512;
        let amount = Amount::from_sat_u32(1);
        verify_script_input(&script_pubkey_v0, 0, amount, &tx, flags).unwrap();
        verify_script_input(&script_pubkey_v1, 1, amount, &tx, flags).unwrap();
    }

    #[test]
    fn pq_multisig_single_scheme_matrix_matches_node() {
        require_node_harness!();

        run_with_large_stack("pq-multisig-single-scheme", || {
            let flags = VERIFY_WITNESS | VERIFY_P2SH;
            let cases = [(1usize, 1usize), (2, 3), (3, 5), (15, 15), (20, 20)];

            for scheme in [
                PqScheme::Falcon512,
                PqScheme::Falcon1024,
                PqScheme::MlDsa44,
                PqScheme::MlDsa65,
                PqScheme::MlDsa87,
            ] {
                for (m, n) in cases {
                    let keys: Vec<(PqPublicKey, PqSecretKey)> = (0..n)
                        .map(|idx| deterministic_keypair(scheme, (0x10 + n + idx) as u8))
                        .collect();
                    verify_multisig_case(&keys, m, false, flags, true);
                    verify_multisig_case(&keys, m, true, flags, true);
                }
            }
        });
    }

    #[test]
    fn pq_multisig_mixed_scheme_direct_and_wrapped_match_node() {
        require_node_harness!();

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
        require_node_harness!();

        run_with_large_stack("pq-multisig-negative-limit", || {
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
            assert!(verify_script_input(
                &script_pubkey,
                0,
                amount,
                &tx,
                VERIFY_WITNESS | VERIFY_P2SH
            )
            .is_err());

            tx.inputs[0].witness = Witness::from_slice(&[
                Vec::<u8>::new(),
                good_sig2.clone(),
                good_sig1.clone(),
                witness_script.as_bytes().to_vec(),
            ]);
            assert!(verify_script_input(
                &script_pubkey,
                0,
                amount,
                &tx,
                VERIFY_WITNESS | VERIFY_P2SH
            )
            .is_err());

            tx.inputs[0].witness = Witness::from_slice(&[
                Vec::<u8>::new(),
                outsider_sig,
                good_sig2.clone(),
                witness_script.as_bytes().to_vec(),
            ]);
            assert!(verify_script_input(
                &script_pubkey,
                0,
                amount,
                &tx,
                VERIFY_WITNESS | VERIFY_P2SH
            )
            .is_err());

            let mut wrong_sighash = good_sig1;
            *wrong_sighash.last_mut().unwrap() = TxSighashType::None.to_u32() as u8;
            tx.inputs[0].witness = Witness::from_slice(&[
                Vec::<u8>::new(),
                wrong_sighash,
                good_sig2,
                witness_script.as_bytes().to_vec(),
            ]);
            assert!(verify_script_input(
                &script_pubkey,
                0,
                amount,
                &tx,
                VERIFY_WITNESS | VERIFY_P2SH
            )
            .is_err());

            let zero_script = multisig_witness_script(&[], 0);
            let zero_spk = direct_p2wsh_script_pubkey(&zero_script);
            let mut zero_tx = tx_template(1);
            zero_tx.inputs[0].witness =
                Witness::from_slice(&[Vec::<u8>::new(), zero_script.as_bytes().to_vec()]);
            verify_script_input(&zero_spk, 0, amount, &zero_tx, VERIFY_WITNESS | VERIFY_P2SH)
                .unwrap();

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
                verify_script_input(
                    &too_many_spk,
                    0,
                    amount,
                    &too_many_tx,
                    VERIFY_WITNESS | VERIFY_P2SH
                ),
                Err(TidecoinValidationError::Script(ScriptError::PubkeyCount))
            );

            let limit_keys = [
                deterministic_keypair(PqScheme::MlDsa87, 0x40),
                deterministic_keypair(PqScheme::MlDsa87, 0x41),
            ];
            let limit_pubkeys: Vec<PqPublicKey> =
                limit_keys.iter().map(|(pk, _)| pk.clone()).collect();
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
        });
    }

    #[test]
    fn pq_committed_hash_mixed_scheme_and_failures_match_node() {
        require_node_harness!();

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
        threshold_tx.inputs[0].witness = signed_committed_hash_witness(
            &threshold_tx,
            0,
            amount,
            &witness_script,
            &keys,
            1,
            true,
        );
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
    fn pq_committed_hash_single_scheme_matrix_matches_node() {
        require_node_harness!();

        run_with_large_stack("pq-committed-hash-single-scheme", || {
            let flags = VERIFY_WITNESS | VERIFY_P2SH;
            let cases = [(1usize, 1usize), (2, 3), (3, 5), (15, 15), (20, 20)];

            for scheme in [
                PqScheme::Falcon512,
                PqScheme::Falcon1024,
                PqScheme::MlDsa44,
                PqScheme::MlDsa65,
                PqScheme::MlDsa87,
            ] {
                for (m, n) in cases {
                    let keys: Vec<(PqPublicKey, PqSecretKey)> = (0..n)
                        .map(|idx| deterministic_keypair(scheme, (0xC0 + n + idx) as u8))
                        .collect();
                    verify_committed_hash_case(&keys, m, false, flags, true);
                    verify_committed_hash_case(&keys, m, true, flags, true);
                }
            }
        });
    }

    #[test]
    fn witness_v1_512_zero_sighash_byte_is_rejected() {
        require_node_harness!();

        let (pubkey, seckey) = deterministic_keypair(PqScheme::Falcon512, 0x51);
        let witness_script = WitnessScriptBuf::from_bytes(
            ScriptPubKeyBuf::builder()
                .push_slice(push_bytes(&pubkey.to_prefixed_bytes()))
                .push_opcode(OP_CHECKSIG)
                .into_script()
                .into_bytes(),
        );
        let program = sha512::Hash::hash(witness_script.as_bytes()).to_byte_array();
        let script_pubkey =
            ScriptPubKeyBuf::builder().push_int(1).unwrap().push_slice(program).into_script();
        let amount = Amount::from_sat_u32(1);
        let mut tx = tx_template(1);
        let mut sig = witness_v1_512_sig(&tx, 0, amount, &witness_script, &seckey, true);
        *sig.last_mut().unwrap() = 0;
        tx.inputs[0].witness = Witness::from_slice(&[sig, witness_script.as_bytes().to_vec()]);

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
    fn pq_multisig_strict_mode_matches_node() {
        require_node_harness!();

        let flags = VERIFY_WITNESS | VERIFY_P2SH | VERIFY_PQ_STRICT;
        let keys = vec![deterministic_keypair(PqScheme::Falcon512, 0x11)];

        verify_multisig_case(&keys, 1, false, flags, false);
        verify_committed_hash_case(&keys, 1, false, flags, false);
    }

    #[test]
    fn pq_legacy_base_p2pkh_signature_verifies() {
        require_node_harness!();

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

    #[test]
    fn key_io_txcreatesignv1_p2pkh_legacy_wif_verifies() {
        require_node_harness!();

        let wif = "6ddD664vfvjyAquu3uNwVWehzSCoywRyjqo1EA9xdA2iQH8bBNYi7VNEPkqx7rm5b2pqUsDtu9YdwQ4rkHs2Xq5XzpLywUsYS7LeiZyBXmmmZ47q1zxB6b2N14PKvXfywgajjpxv7WFRAqtWDXi6uy5NVwsLn2KdJQybjQpMzX9772M1gCoc3EgBvwfin8c7aeeBdSWShh9gh5pbGTrcU2LeQPoWP4yTRhZ2sCxNuaJWaMPbjyhEf5QFBpXmLCtQQiGjSghttdLayrhBr3hw3ydGk4rwTTgv8MX68rZvnEEV3xibEG3ud8Rq7jGfumk4FaAEUdfiRdHZEZdBx4wDYaQurihxcm6EMCApZ9v1B68NNh4whtQLuHfsqod5ye8K9TPHWS19MtFT96dtdMuSB5CwvhL8Fa6TTjwPAGBYpU5xynym9bdMrZRMsUhTzAyoGmFD1sp94jUE46iwdfp7FFrboyPLV5zLiDfToKmM1J2343quyuzrTewmA6wdqUZbKAmhtL28pbDAoy6jMwk2TM1cggcFmSR3uSXcgDVnV7J9mTBmpvXDaN8xxG18JcSWSbewFVnHLCddvhPn2ZutGPpMRtDkMc3vWt5s9iD3gTUyWC9kjZsjc65Gd6t3JChSKDpUC5BGA5pdHBwo2P5j87DkZqcrUjpeMX25zgPMdt9ZWeRs6SUqJtTGMj4Hk1syNbovpm4Eqha66n8vTvVnwHrxvn85ds4ZcFpxv1FukG7TQ6iStJLBcmwcUSFtyvBFmbK9qu8ToXNGoPnqVCR8V6XveLPCfDELjHoCMCLnp4eQa3AwJpg9Pg9qVQjvcoHqD44JuZ86CAjLcyAmm9QnFcs3JX7JyLKCnBzj3DfjWr2SNgrhjiGnMBrykjEVX6vis6vDL9cJ56jTuxWDovhwzBr5VbkoBArh6MS6z1SPv6Xvv8Sj7ej3nRHZ31Gh5estzKzdUKSU2vQxmtd4Q6KqjjBSf6xLU1K1S9mAtqn3CzKMMDKeLFtTu1oFwHTGDqaCDmAKXWJX1o2xzmTdWCd3UHB9wobBjtjWUcNxvw4ig7BHW89JgsbfzRneyktwdk1cYWU52AHTdFUSnchYwQBPEqyJ5bD7zWo5AbVNMPrebEnt2Sb29CS2XYBwsD88hU6ka2BHmNmTGedEHJmhHzkrJkyWqFAkSZBsH5yq6x6ttYrDH8zXX7i98FzV2ZKnKuyy6NcgwpC8rYaMYPSie14DzoPfGUJc6BytBV69mZDsoJ2UUoVH94uiBkZUPTFfDcyCoDxBACCPxdCnJokerkAvDmFzujELyf2rK9nEoQeVdh9QJdYTTLAgJdzMyREHHYWyseWWti9n2gadocnRwiUMSqEt683KHiMW4Bn8AWBDSFQfXZYvVBcuEL4jvBSXMVJt4Z6cD11gqmCM9BgEGy2CoNLELVmRDRq3RMN22G2jX5U353eqikvgumub2sGRuErt3vbDuEELbmJAzLrVrXjfmbeU5ev5ZhMpBP7CiyRy7sk2DViDYDrZ9W5J8hPDRDVy7SV85bF1MHz1GjXjMjCMSSBYwvPTT9gd7Rmmc1MfVo26t6iS4YVdVeoCBGdvLdCUWd6Z8UZPmkpPASnVN3yj9m119DRyXsZUsqyeNF2vEDTVSNfjfofLGqfFmKtHDEkECW94huFapxokwmSvgi15sYiEKXBXknHnctaEiahSh7ha9qJ6UqhEnd7aJxzG1JbUerZbZMF4dxLEumd66ixzbgAWSBHoC1";
        let key = PqWifKey::from_wif(wif).unwrap();
        assert_eq!(key.network(), Network::Tidecoin);

        let prev_script_pubkey = ScriptPubKeyBuf::from_hex_no_length_prefix(
            "76a9145a2f1784c55a322ffe4cc3ca9fea8dfb44cdea1188ac",
        )
        .unwrap();
        assert_eq!(
            prev_script_pubkey,
            ScriptPubKeyBuf::builder()
                .push_opcode(OP_DUP)
                .push_opcode(OP_HASH160)
                .push_slice(push_bytes(key.public_key.key_id().as_ref()))
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_CHECKSIG)
                .into_script()
        );

        let destination = "ERNkirDf3jsER2ykJevf8USM2rj8Xi3GCF"
            .parse::<Address<_>>()
            .unwrap()
            .require_network(Network::Tidecoin)
            .unwrap();
        let mut tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: "4d49a71ec9da436f71ec4ee231d04f292a29cd316f598bb7068feccabdc59485"
                        .parse()
                        .unwrap(),
                    vout: 0,
                },
                sequence: Sequence::MAX,
                ..TxIn::EMPTY_COINBASE
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(100_000).unwrap(),
                script_pubkey: destination.script_pubkey(),
            }],
        };
        let sig = base_sig(&tx, 0, &prev_script_pubkey, &key.secret_key, true);
        tx.inputs[0].script_sig = ScriptSigBuf::builder()
            .push_slice(push_bytes(&sig))
            .push_slice(push_bytes(&key.public_key.to_prefixed_bytes()))
            .into_script();

        verify_script_input(&prev_script_pubkey, 0, Amount::from_sat_u32(0), &tx, VERIFY_NONE)
            .unwrap();
    }

    #[test]
    fn key_io_txcreatesignv1_p2pkh_toolpath_verifies() {
        require_node_harness!();

        // The library has no signing-provider abstraction, so the node toolpath vector reduces to
        // the same BASE-sighash legacy-signature behavior exercised by the exact WIF test above.
        key_io_txcreatesignv1_p2pkh_legacy_wif_verifies();
    }

    #[test]
    fn pq_seed_keygen_matches_node_for_all_schemes() {
        require_node_harness!();

        for (scheme, tag) in [
            (PqScheme::Falcon512, 0x11),
            (PqScheme::Falcon1024, 0x22),
            (PqScheme::MlDsa44, 0x33),
            (PqScheme::MlDsa65, 0x44),
            (PqScheme::MlDsa87, 0x55),
        ] {
            let seed = tagged_seed(tag, scheme.deterministic_seed_len());
            let rust_pair = scheme.generate_keypair_from_seed(&seed).unwrap();
            let node_pair = node_keypair_from_seed(scheme, &seed);

            assert_eq!(rust_pair.0, node_pair.0, "{scheme:?} public key mismatch");
            assert_eq!(rust_pair.1, node_pair.1, "{scheme:?} secret key mismatch");
        }
    }

    #[test]
    fn pq_public_key_derivation_matches_node_for_all_schemes() {
        require_node_harness!();

        for (scheme, tag) in [
            (PqScheme::Falcon512, 0x61),
            (PqScheme::Falcon1024, 0x62),
            (PqScheme::MlDsa44, 0x63),
            (PqScheme::MlDsa65, 0x64),
            (PqScheme::MlDsa87, 0x65),
        ] {
            let (_pk, sk) = deterministic_keypair(scheme, tag);
            let rust_pk = PqPublicKey::from_secret_key(&sk).unwrap();
            let node_pk = node_public_key_from_secret(scheme, &sk);
            assert_eq!(rust_pk, node_pk, "{scheme:?} derived public key mismatch");
        }
    }

    #[test]
    fn pq_signatures_cross_verify_with_node_for_msg32_and_msg64() {
        require_node_harness!();

        let msg32 = [0xA5u8; 32];
        let msg64 = [0x5Au8; 64];

        for (scheme, tag) in [
            (PqScheme::Falcon512, 0x71),
            (PqScheme::Falcon1024, 0x72),
            (PqScheme::MlDsa44, 0x73),
            (PqScheme::MlDsa65, 0x74),
            (PqScheme::MlDsa87, 0x75),
        ] {
            let (pk, sk) = deterministic_keypair(scheme, tag);

            let rust_sig32 = PqSignature::sign_msg32(&msg32, &sk).unwrap();
            assert!(node_verify_message(scheme, &msg32, &rust_sig32, &pk, false));

            let rust_sig64 = PqSignature::sign_msg64(&msg64, &sk).unwrap();
            assert!(node_verify_message(scheme, &msg64, &rust_sig64, &pk, false));

            let node_sig32 = node_sign_message(scheme, &msg32, &sk, false);
            node_sig32.verify_msg32(&msg32, &pk).unwrap();

            let node_sig64 = node_sign_message(scheme, &msg64, &sk, false);
            node_sig64.verify_msg64(&msg64, &pk).unwrap();
        }
    }

    #[test]
    fn pqhd_keygen_from_stream_key_matches_node_for_all_schemes() {
        require_node_harness!();

        let master_seed = [0x42u8; 32];
        let master = pqhd::make_master_node(&master_seed);
        let vectors = [
            (PqScheme::Falcon512, pqhd::make_v1_leaf_path(PqScheme::Falcon512, 0, 0, 7)),
            (PqScheme::Falcon1024, pqhd::make_v1_leaf_path(PqScheme::Falcon1024, 0, 1, 9)),
            (PqScheme::MlDsa44, pqhd::make_v1_leaf_path(PqScheme::MlDsa44, 1, 0, 3)),
            (PqScheme::MlDsa65, pqhd::make_v1_leaf_path(PqScheme::MlDsa65, 2, 1, 5)),
            (PqScheme::MlDsa87, pqhd::make_v1_leaf_path(PqScheme::MlDsa87, 3, 0, 11)),
        ];

        for (scheme, path) in vectors {
            let leaf = pqhd::derive_path(&path, &master).unwrap();
            let material = pqhd::derive_leaf_material_v1(&leaf.node_secret, &path).unwrap();
            let rust_pair = pqhd::derive_keypair_v1(&material).unwrap();
            let node_pair = node_keypair_from_stream_key(scheme, material.stream_key.as_slice());

            assert_eq!(material.scheme, scheme);
            assert_eq!(rust_pair.0, node_pair.0, "{scheme:?} PQHD public key mismatch");
            assert_eq!(rust_pair.1, node_pair.1, "{scheme:?} PQHD secret key mismatch");
        }
    }
}
