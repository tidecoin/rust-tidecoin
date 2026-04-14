#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tidecoin::absolute;
use tidecoin::opcodes::all;
use tidecoin::policy;
use tidecoin::script::{Builder, ScriptExt as _, ScriptPubKeyBuf, ScriptPubKeyExt as _};
use tidecoin::transaction::{OutPoint, TransactionExt as _, TxIn, TxOut};
use tidecoin::{
    Amount, BlockHeight, FeeRate, Sequence, Transaction, TransactionVersion, Txid, Witness,
};
use tidecoin_consensus_encoding::{decode_from_slice, encode_to_vec};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    if let Ok(script) = decode_from_slice::<ScriptPubKeyBuf>(data) {
        exercise_script(&script);
    }

    let mut u = Unstructured::new(data);
    if let Ok(script) = ScriptPubKeyBuf::arbitrary(&mut u) {
        exercise_script(&script);
    }
}

fn exercise_script(script: &ScriptPubKeyBuf) {
    let encoded = encode_to_vec(script);
    if let Ok(decoded) = decode_from_slice::<ScriptPubKeyBuf>(&encoded) {
        assert_eq!(decoded, *script);
    }

    let _ = script.instructions().collect::<Result<Vec<_>, _>>();
    let _ = script.instructions_minimal().collect::<Result<Vec<_>, _>>();
    let _ = script.count_sigops();
    let _ = script.count_sigops_legacy();
    let _ = script.minimal_non_dust();
    let _ = script.minimal_non_dust_custom(FeeRate::DUST);
    let _ = policy::standard_policy_script_flags(
        tidecoin::network::Params::REGTEST,
        BlockHeight::from_u32(script.len() as u32),
    );

    let script_pubkey = ScriptPubKeyBuf::from_bytes(script.as_bytes().to_vec());
    let _ = script_pubkey.first_opcode();
    let _ = script_pubkey.is_op_return();
    let _ = script_pubkey.is_standard_op_return();
    let _ = script_pubkey.is_p2sh();
    let _ = script_pubkey.is_p2pkh();
    let _ = script_pubkey.is_p2wpkh();
    let _ = script_pubkey.is_p2wsh();
    let _ = script_pubkey.is_p2wsh512();
    let _ = script_pubkey.witness_version();
    let _ = script_pubkey.is_witness_program();
    let _ = script_pubkey.p2wpkh_script_code();

    let tx = transaction_with_output(script_pubkey);
    let without_bare = policy::is_standard_tx(&tx, Some(80_000), false, FeeRate::DUST);
    let with_bare = policy::is_standard_tx(&tx, Some(80_000), true, FeeRate::DUST);
    if without_bare.is_ok() {
        assert!(with_bare.is_ok());
    }

    let prevout = TxOut {
        amount: Amount::from_sat(100_000).expect("small amount is valid"),
        script_pubkey: synthetic_prevout_script(script.len()),
    };
    let _ = policy::are_inputs_standard(&tx, |_| Some(prevout.clone()));
    let _ = policy::is_witness_standard(&tx, |_| Some(prevout.clone()));
    let _ = tx.total_sigop_cost(|_| Some(prevout.clone()));
}

fn transaction_with_output(script_pubkey: ScriptPubKeyBuf) -> Transaction {
    Transaction {
        version: TransactionVersion::ONE,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 },
            script_sig: tidecoin::ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            amount: Amount::from_sat(100_000).expect("small amount is valid"),
            script_pubkey,
        }],
    }
}

fn synthetic_prevout_script(seed: usize) -> ScriptPubKeyBuf {
    match seed % 4 {
        0 => Builder::new().push_opcode(all::OP_0).push_slice([0x11; 20]).into_script(),
        1 => Builder::new().push_opcode(all::OP_0).push_slice([0x22; 32]).into_script(),
        2 => Builder::new().push_opcode(all::OP_1).push_slice([0x33; 64]).into_script(),
        _ => ScriptPubKeyBuf::new(),
    }
}

fuzz_target!(|data| {
    do_test(data);
});
