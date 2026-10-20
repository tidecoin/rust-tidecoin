// SPDX-License-Identifier: CC0-1.0
//! Regressions first exposed during phase 1 and resolved by phase 2.
use consensus_core::{
    PrecomputedTransactionData, SighashCache, SpentOutputs, SpentOutputsError, TxSighashType,
};
use primitives::{
    absolute::LockTime, Amount, OutPoint, ScriptSigBuf, Sequence, Transaction, TransactionVersion,
    TxIn, Txid, Witness,
};

fn tx() -> Transaction {
    Transaction {
        version: TransactionVersion::TWO,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([1; 32]), vout: 0 },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x51]]),
        }],
        outputs: vec![],
    }
}

#[test]
fn r02_witness_v1_single_without_output_must_fail() {
    let tx = tx();
    for mode in [TxSighashType::Single, TxSighashType::SinglePlusAnyoneCanPay] {
        assert!(
            SighashCache::new(&tx)
                .p2wsh512_signature_hash(0, &[0x51], Amount::from_sat(1000).unwrap(), mode)
                .is_err(),
            "rc2 SignatureHash512 rejects SINGLE without a corresponding output"
        );
    }
}

#[test]
fn r10_incomplete_spent_output_context_must_not_panic() {
    let tx = tx();
    let spent = SpentOutputs::from_txouts(vec![]);
    let result =
        std::panic::catch_unwind(|| PrecomputedTransactionData::new(&tx, Some(&spent), false))
            .expect("malformed caller context must not panic");
    assert_eq!(result.unwrap_err(), SpentOutputsError::CountMismatch { expected: 1, actual: 0 });
}
