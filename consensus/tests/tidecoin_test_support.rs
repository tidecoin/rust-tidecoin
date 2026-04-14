#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::str::FromStr;

use consensus::{ScriptError as RustScriptError, Utxo};
use consensus_core::{
    VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_CLEANSTACK,
    VERIFY_CONST_SCRIPTCODE, VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, VERIFY_MINIMALDATA, VERIFY_MINIMALIF,
    VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_NULLFAIL, VERIFY_P2SH, VERIFY_PQ_STRICT, VERIFY_SHA512,
    VERIFY_SIGPUSHONLY, VERIFY_WITNESS, VERIFY_WITNESS_V1_512,
};
use encoding::{decode_from_slice, encode_to_vec};
use node_parity::{fixtures::test_data_path, NodeParityError, ScriptError, TidecoinNodeHarness};
use primitives::{
    absolute::LockTime,
    script::{Builder, ScriptBuf},
    Amount, OutPoint, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
};
use serde_json::Value;

pub const ALL_TIDECOIN_SCRIPT_FLAGS: u32 = VERIFY_P2SH
    | VERIFY_NULLDUMMY
    | VERIFY_SIGPUSHONLY
    | VERIFY_MINIMALDATA
    | VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    | VERIFY_CLEANSTACK
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | VERIFY_MINIMALIF
    | VERIFY_NULLFAIL
    | VERIFY_CONST_SCRIPTCODE
    | VERIFY_PQ_STRICT
    | VERIFY_WITNESS_V1_512
    | VERIFY_SHA512;

pub const TIDECOIN_SCRIPT_ACTIVATION_FLAGS: u32 = VERIFY_WITNESS_V1_512 | VERIFY_SHA512;

pub fn try_harness() -> Option<TidecoinNodeHarness> {
    TidecoinNodeHarness::from_env().ok()
}

pub fn parse_script_flags(flags: &str) -> u32 {
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
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
            "WITNESS_V1_512" => VERIFY_WITNESS_V1_512,
            "CONST_SCRIPTCODE" => VERIFY_CONST_SCRIPTCODE,
            "PQ_STRICT" => VERIFY_PQ_STRICT,
            other => panic!("unknown Tidecoin verification flag {other}"),
        }
    })
}

pub fn normalize_flags(mut flags: u32) -> u32 {
    if flags & VERIFY_CLEANSTACK != 0 {
        flags |= VERIFY_P2SH | VERIFY_WITNESS;
    }
    flags
}

pub fn is_valid_script_flag_combination(flags: u32) -> bool {
    if flags & !ALL_TIDECOIN_SCRIPT_FLAGS != 0 {
        return false;
    }
    if flags & VERIFY_CLEANSTACK != 0
        && flags & (VERIFY_P2SH | VERIFY_WITNESS) != VERIFY_P2SH | VERIFY_WITNESS
    {
        return false;
    }
    if flags & VERIFY_WITNESS != 0 && flags & VERIFY_P2SH == 0 {
        return false;
    }
    true
}

pub fn parse_script_error(name: &str) -> ScriptError {
    ScriptError::from_name(name).unwrap_or_else(|| panic!("unknown script error {name}"))
}

pub fn parse_hex_bytes(value: &str) -> Vec<u8> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    assert!(
        hex.len().is_multiple_of(2) && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid hex payload {value}"
    );

    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

pub fn amount_from_json(value: &Value) -> i64 {
    if let Some(sats) = value.as_i64() {
        sats
    } else if let Some(sats) = value.as_u64() {
        sats.try_into().unwrap()
    } else if let Some(text) = value.as_str() {
        let btc: f64 = text.parse().unwrap();
        (btc * 100_000_000.0).round() as i64
    } else if let Some(btc) = value.as_f64() {
        (btc * 100_000_000.0).round() as i64
    } else {
        panic!("unsupported amount json {value}");
    }
}

pub fn parse_witness_and_amount(value: &Value) -> (Vec<Vec<u8>>, i64) {
    let arr = value.as_array().expect("witness tuple");
    let mut items = Vec::with_capacity(arr.len().saturating_sub(1));
    for item in &arr[..arr.len() - 1] {
        items.push(parse_hex_bytes(item.as_str().expect("witness item")));
    }
    let amount = amount_from_json(&arr[arr.len() - 1]);
    (items, amount)
}

#[derive(Clone)]
pub struct PrevoutData {
    pub script_pubkey: Vec<u8>,
    pub amount_sat: i64,
}

pub fn parse_tx_outpoint(txid_hex: &str, vout: u32) -> OutPoint {
    OutPoint {
        txid: Txid::from_str(txid_hex).unwrap_or_else(|e| panic!("invalid txid {txid_hex}: {e}")),
        vout,
    }
}

pub fn parse_script_asm_bytes(harness: &TidecoinNodeHarness, value: &str) -> Vec<u8> {
    harness
        .parse_script_asm(value)
        .unwrap_or_else(|e| panic!("failed to parse script asm `{value}`: {e}"))
}

pub fn parse_tx_inputs(
    harness: &TidecoinNodeHarness,
    value: &Value,
) -> BTreeMap<OutPoint, PrevoutData> {
    let mut prevouts = BTreeMap::new();
    for entry in value.as_array().expect("input vector") {
        let input = entry.as_array().expect("input tuple");
        let outpoint = parse_tx_outpoint(
            input[0].as_str().expect("txid"),
            input[1].as_u64().expect("vout") as u32,
        );
        prevouts.insert(
            outpoint,
            PrevoutData {
                script_pubkey: parse_script_asm_bytes(
                    harness,
                    input[2].as_str().expect("script asm"),
                ),
                amount_sat: if input.len() >= 4 { amount_from_json(&input[3]) } else { 0 },
            },
        );
    }
    prevouts
}

pub fn read_fixture(name: &str) -> Vec<Value> {
    let path = test_data_path(name);
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
}

pub fn read_fixture_from_path(path: &std::path::Path) -> Vec<Value> {
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
}

pub fn build_test_transaction(
    script_pubkey: &[u8],
    script_sig: &[u8],
    witness_items: &[Vec<u8>],
    amount: u64,
) -> Vec<u8> {
    let credit_tx = Transaction {
        version: TransactionVersion::ONE,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE_PREVOUT,
            script_sig: Builder::new()
                .push_int(0)
                .expect("push zero")
                .push_int(0)
                .expect("push zero")
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            amount: Amount::from_sat(amount).unwrap(),
            script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
        }],
    };
    let prevout = OutPoint { txid: credit_tx.compute_txid(), vout: 0 };
    let tx = Transaction {
        version: TransactionVersion::ONE,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(witness_items),
        }],
        outputs: vec![TxOut {
            amount: Amount::from_sat(amount).unwrap(),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    encode_to_vec(&tx)
}

pub fn map_rust_script_error(err: RustScriptError) -> ScriptError {
    match err {
        RustScriptError::Ok => ScriptError::Ok,
        RustScriptError::Unknown => ScriptError::UnknownError,
        RustScriptError::EvalFalse => ScriptError::EvalFalse,
        RustScriptError::OpReturn => ScriptError::OpReturn,
        RustScriptError::ScriptSize => ScriptError::ScriptSize,
        RustScriptError::PushSize => ScriptError::PushSize,
        RustScriptError::OpCount => ScriptError::OpCount,
        RustScriptError::StackSize => ScriptError::StackSize,
        RustScriptError::SigCount => ScriptError::SigCount,
        RustScriptError::PubkeyCount => ScriptError::PubkeyCount,
        RustScriptError::Verify => ScriptError::Verify,
        RustScriptError::EqualVerify => ScriptError::EqualVerify,
        RustScriptError::CheckSigVerify => ScriptError::CheckSigVerify,
        RustScriptError::CheckMultiSigVerify => ScriptError::CheckMultisigVerify,
        RustScriptError::NumEqualVerify => ScriptError::NumEqualVerify,
        RustScriptError::BadOpcode => ScriptError::BadOpcode,
        RustScriptError::OpCodeSeparator => ScriptError::OpCodeSeparator,
        RustScriptError::DisabledOpcode => ScriptError::DisabledOpcode,
        RustScriptError::InvalidStackOperation => ScriptError::InvalidStackOperation,
        RustScriptError::InvalidAltstackOperation => ScriptError::InvalidAltstackOperation,
        RustScriptError::UnbalancedConditional => ScriptError::UnbalancedConditional,
        RustScriptError::NegativeLockTime => ScriptError::NegativeLocktime,
        RustScriptError::UnsatisfiedLockTime => ScriptError::UnsatisfiedLocktime,
        RustScriptError::SigHashType => ScriptError::SigHashType,
        RustScriptError::MinimalData => ScriptError::MinimalData,
        RustScriptError::SigPushOnly => ScriptError::SigPushOnly,
        RustScriptError::SigNullDummy => ScriptError::SigNullDummy,
        RustScriptError::CleanStack => ScriptError::Cleanstack,
        RustScriptError::MinimalIf => ScriptError::MinimalIf,
        RustScriptError::NullFail => ScriptError::NullFail,
        RustScriptError::DiscourageUpgradableNops => ScriptError::DiscourageUpgradableNops,
        RustScriptError::DiscourageUpgradableWitnessProgram => {
            ScriptError::DiscourageUpgradableWitnessProgram
        }
        RustScriptError::WitnessProgramWrongLength => ScriptError::WitnessProgramWrongLength,
        RustScriptError::WitnessProgramWitnessEmpty => ScriptError::WitnessProgramWitnessEmpty,
        RustScriptError::WitnessProgramMismatch => ScriptError::WitnessProgramMismatch,
        RustScriptError::WitnessMalleated => ScriptError::WitnessMalleated,
        RustScriptError::WitnessMalleatedP2SH => ScriptError::WitnessMalleatedP2sh,
        RustScriptError::WitnessUnexpected => ScriptError::WitnessUnexpected,
        RustScriptError::SigFindAndDelete => ScriptError::SigFindAndDelete,
    }
}

pub fn node_script_result(result: Result<(), NodeParityError>) -> Result<(), ScriptError> {
    match result {
        Ok(()) => Ok(()),
        Err(NodeParityError::Script(err)) => Err(err),
        Err(err) => panic!("unexpected Tidecoin-node harness failure: {err}"),
    }
}

pub fn parse_prevout_txouts(value: &Value) -> Vec<TxOut> {
    value
        .as_array()
        .expect("prevouts array")
        .iter()
        .map(|item| {
            let hex = item.as_str().expect("prevout hex");
            decode_from_slice::<TxOut>(&parse_hex_bytes(hex))
                .unwrap_or_else(|e| panic!("invalid prevout txout `{hex}`: {e}"))
        })
        .collect()
}

pub struct OwnedUtxoSet {
    scripts: Vec<Vec<u8>>,
    utxos: Vec<Utxo>,
}

impl OwnedUtxoSet {
    pub fn from_txouts(prevouts: &[TxOut]) -> Self {
        let scripts: Vec<Vec<u8>> =
            prevouts.iter().map(|txout| txout.script_pubkey.as_bytes().to_vec()).collect();
        let utxos = scripts
            .iter()
            .zip(prevouts.iter())
            .map(|(script, txout)| Utxo {
                script_pubkey: script.as_ptr(),
                script_pubkey_len: script.len().try_into().unwrap(),
                value: txout.amount.to_sat().try_into().unwrap(),
            })
            .collect();
        Self { scripts, utxos }
    }

    pub fn as_slice(&self) -> &[Utxo] {
        &self.utxos
    }

    pub fn len(&self) -> usize {
        self.scripts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    pub fn script_pubkey(&self, index: usize) -> &[u8] {
        &self.scripts[index]
    }
}

pub fn all_script_assets_consensus_flags() -> Vec<u32> {
    let mut flags = Vec::new();
    for bits in 0u32..64 {
        let mut value = 0u32;
        if bits & 1 != 0 {
            value |= VERIFY_P2SH;
        }
        if bits & 2 != 0 {
            value |= VERIFY_NULLDUMMY;
        }
        if bits & 4 != 0 {
            value |= VERIFY_CHECKLOCKTIMEVERIFY;
        }
        if bits & 8 != 0 {
            value |= VERIFY_CHECKSEQUENCEVERIFY;
        }
        if bits & 16 != 0 {
            value |= VERIFY_WITNESS;
        }
        if bits & 32 != 0 {
            value |= VERIFY_PQ_STRICT;
        }
        if value & VERIFY_WITNESS != 0 && value & VERIFY_P2SH == 0 {
            continue;
        }
        flags.push(value);
    }
    flags
}
