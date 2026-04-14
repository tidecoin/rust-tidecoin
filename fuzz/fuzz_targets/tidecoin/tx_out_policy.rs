#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tidecoin::absolute;
use tidecoin::policy;
use tidecoin::script::{ScriptPubKeyBuf, ScriptPubKeyExt as _};
use tidecoin::transaction::{OutPoint, TransactionExt as _, TxIn, TxOut, TxOutExt as _};
use tidecoin::{Amount, FeeRate, Sequence, Transaction, TransactionVersion, Txid, Witness};
use tidecoin_consensus_encoding::{decode_from_slice, encode_to_vec};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    if let Ok(txout) = decode_from_slice::<TxOut>(data) {
        exercise_txout(&txout);
    }

    let mut u = Unstructured::new(data);
    if let Ok(txout) = TxOut::arbitrary(&mut u) {
        exercise_txout(&txout);
    }

    let mut u = Unstructured::new(data);
    if let Ok(script_pubkey) = ScriptPubKeyBuf::arbitrary(&mut u) {
        exercise_script_thresholds(script_pubkey);
    }
}

fn exercise_txout(txout: &TxOut) {
    let encoded = encode_to_vec(txout);
    if let Ok(decoded) = decode_from_slice::<TxOut>(&encoded) {
        assert_eq!(decoded, *txout);
    }

    let _ = txout.size();
    let _ = txout.weight();
    exercise_script_thresholds(txout.script_pubkey.clone());

    let tx = transaction_spending_and_creating(txout.clone());
    let _ = policy::is_standard_tx(
        &tx,
        Some(policy::MAX_STANDARD_TX_WEIGHT as usize / 4),
        true,
        FeeRate::DUST,
    );
    let _ = tx.total_sigop_cost(|_| Some(txout.clone()));
    let _ = policy::are_inputs_standard(&tx, |_| Some(txout.clone()));
    let _ = policy::is_witness_standard(&tx, |_| Some(txout.clone()));
}

fn exercise_script_thresholds(script_pubkey: ScriptPubKeyBuf) {
    let default_threshold = script_pubkey.minimal_non_dust();
    let custom_threshold = script_pubkey.minimal_non_dust_custom(FeeRate::DUST);
    if let Some(custom_threshold) = custom_threshold {
        assert_eq!(default_threshold, custom_threshold);
    }

    let minimal = TxOut::minimal_non_dust(script_pubkey.clone());
    assert_eq!(minimal.script_pubkey, script_pubkey);
    assert_eq!(minimal.amount, default_threshold);

    let maybe_custom = TxOut::minimal_non_dust_custom(script_pubkey, FeeRate::DUST);
    if let Some(custom) = maybe_custom {
        assert_eq!(custom.amount, default_threshold);
    }
}

fn transaction_spending_and_creating(txout: TxOut) -> Transaction {
    Transaction {
        version: TransactionVersion::ONE,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0x42; 32]), vout: 0 },
            script_sig: tidecoin::ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            amount: Amount::from_sat(100_000).expect("small amount is valid"),
            script_pubkey: txout.script_pubkey,
        }],
    }
}

fuzz_target!(|data| {
    do_test(data);
});
