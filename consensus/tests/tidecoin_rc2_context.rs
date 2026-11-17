// SPDX-License-Identifier: CC0-1.0
//! Differential rc2 context/hash tests against the pinned node implementation.
use consensus_core::*;
use hashes::{hash160, sha512};
use node_parity::{SpentOutput, TidecoinNodeHarness};
use primitives::{
    absolute::LockTime, opcodes::all, script::Builder, Amount, OutPoint, ScriptPubKeyBuf,
    ScriptSigBuf, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
};

const MODES: [TxSighashType; 6] = [
    TxSighashType::All,
    TxSighashType::None,
    TxSighashType::Single,
    TxSighashType::AllPlusAnyoneCanPay,
    TxSighashType::NonePlusAnyoneCanPay,
    TxSighashType::SinglePlusAnyoneCanPay,
];
macro_rules! oracle {
    () => {
        match TidecoinNodeHarness::optional_from_env() {
            Some(h) => h,
            None => return,
        }
    };
}
fn amount(value: u64) -> Amount {
    Amount::from_sat(value).unwrap()
}
fn output(value: u64, script: &[u8]) -> TxOut {
    TxOut { amount: amount(value), script_pubkey: ScriptPubKeyBuf::from_bytes(script.to_vec()) }
}
fn transaction() -> Transaction {
    Transaction {
        version: TransactionVersion::TWO,
        lock_time: LockTime::from_consensus(17),
        inputs: (0..2)
            .map(|i| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([i + 1; 32]),
                    vout: i as u32,
                },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::from_consensus(0xfffffffe - i as u32),
                witness: Witness::new(),
            })
            .collect(),
        outputs: vec![output(700, &[0x51]), output(500, &[0x52])],
    }
}
fn hex(tx: &Transaction) -> String {
    encoding::encode_to_vec(tx).iter().map(|b| format!("{b:02x}")).collect()
}
fn node_outputs(outputs: &[TxOut]) -> Vec<SpentOutput<'_>> {
    outputs
        .iter()
        .map(|out| SpentOutput {
            amount: out.amount.to_sat() as i64,
            script_pubkey: out.script_pubkey.as_bytes(),
        })
        .collect()
}
fn cache<'a>(tx: &'a Transaction, outputs: &[TxOut]) -> SighashCache<&'a Transaction> {
    SighashCache::new_with_spent_outputs(tx, SpentOutputs::from_txouts(outputs.to_vec())).unwrap()
}
fn verify(
    tx: &Transaction,
    index: usize,
    current: &TxOut,
    outputs: Option<&[TxOut]>,
    flags: u32,
) -> Result<(), TidecoinValidationError> {
    verify_script_input(
        tx,
        index,
        SpendContext::new(
            current.script_pubkey.as_bytes(),
            outputs.map(|v| SpentOutputs::from_txouts(v.to_vec())),
            current.amount.to_sat(),
            true,
        ),
        flags,
    )
}
fn verify_bytes(
    tx: &Transaction,
    index: usize,
    current: &TxOut,
    outputs: Option<&[TxOut]>,
    flags: u32,
) -> Result<(), consensus::ScriptFailure> {
    let raw = outputs.map(|outs| {
        outs.iter()
            .map(|out| consensus::Utxo {
                script_pubkey: out.script_pubkey.as_bytes(),
                value: out.amount.to_sat() as i64,
            })
            .collect::<Vec<_>>()
    });
    consensus::verify_with_flags_detailed(
        current.script_pubkey.as_bytes(),
        current.amount.to_sat(),
        &encoding::encode_to_vec(tx),
        raw.as_deref(),
        index,
        flags,
    )
}

#[test]
fn all_modes_match_node_with_cache_reuse_and_compactsize_boundaries() {
    let h = oracle!();
    let tx = transaction();
    for length in [0, 1, 252, 253, 65535, 65536] {
        let outputs = [output(1000, &[0x51]), output(2000, &vec![0x52; length])];
        let mut cached = cache(&tx, &outputs);
        for index in 0..2 {
            for mode in MODES {
                let rust = cached
                    .p2wsh512_signature_hash(index, &[0x51], outputs[index].amount, mode)
                    .unwrap();
                let node = h
                    .signature_hash_512(
                        &hex(&tx),
                        index,
                        &[0x51],
                        outputs[index].amount.to_sat() as i64,
                        mode.to_u32() as i32,
                        &node_outputs(&outputs),
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    rust.to_byte_array(),
                    node,
                    "length={length} index={index} mode={mode:?}"
                );
                let missing = SighashCache::new(&tx).p2wsh512_signature_hash(
                    index,
                    &[0x51],
                    outputs[index].amount,
                    mode,
                );
                if mode.to_u32() & 0x80 == 0 {
                    assert_eq!(missing, Err(WitnessV1SighashError::SpentOutputsRequired));
                } else {
                    assert_eq!(missing.unwrap(), rust);
                }
            }
        }
    }
}

#[test]
fn malformed_context_returns_explicit_errors_without_panics() {
    let tx = transaction();
    let outputs = [output(1000, &[0x51]), output(2000, &[0x52])];
    for count in [0, 1, 3] {
        let bad = vec![outputs[0].clone(); count];
        let expected = SpentOutputsError::CountMismatch { expected: 2, actual: count };
        assert_eq!(
            PrecomputedTransactionData::new(
                &tx,
                Some(&SpentOutputs::from_txouts(bad.clone())),
                false
            )
            .unwrap_err(),
            expected
        );
        assert_eq!(
            SighashCache::new_with_spent_outputs(&tx, SpentOutputs::from_txouts(bad.clone()))
                .unwrap_err(),
            expected
        );
        assert_eq!(
            verify(&tx, 0, &outputs[0], Some(&bad), VERIFY_ALL_TIDECOIN),
            Err(TidecoinValidationError::SpentOutputs(expected))
        );
        assert_eq!(
            verify_bytes(&tx, 0, &outputs[0], Some(&bad), VERIFY_ALL_TIDECOIN).unwrap_err().error,
            consensus::Error::ERR_SPENT_OUTPUTS_MISMATCH
        );
    }
    for current in [output(1001, &[0x51]), output(1000, &[0x53])] {
        assert_eq!(
            verify(&tx, 0, &current, Some(&outputs), VERIFY_ALL_TIDECOIN),
            Err(TidecoinValidationError::SpentOutputs(SpentOutputsError::CurrentOutputMismatch {
                index: 0
            }))
        );
        assert_eq!(
            verify_bytes(&tx, 0, &current, Some(&outputs), VERIFY_ALL_TIDECOIN).unwrap_err().error,
            consensus::Error::ERR_SPENT_OUTPUTS_MISMATCH
        );
    }
    for mode in MODES {
        assert_eq!(
            cache(&tx, &outputs).p2wsh512_signature_hash(0, &[0x51], amount(1001), mode),
            Err(WitnessV1SighashError::SpentOutputs(SpentOutputsError::CurrentOutputMismatch {
                index: 0
            }))
        );
        assert!(matches!(
            cache(&tx, &outputs).p2wsh512_signature_hash(2, &[0x51], amount(1000), mode),
            Err(WitnessV1SighashError::InputIndex(_))
        ));
    }
    assert_eq!(
        verify(&tx, 2, &outputs[0], None, VERIFY_ALL_TIDECOIN),
        Err(TidecoinValidationError::InvalidInputIndex { index: 2, inputs: 2 })
    );
}

#[test]
fn native_and_wrapped_signed_spends_match_node_for_all_modes_and_context_mutations() {
    let h = oracle!();
    let (pk, sk) = h.pq_keypair_from_seed(9, &[42; 32], 1312, 2560).unwrap();
    let script = Builder::<()>::new()
        .push_slice([vec![9], pk].concat())
        .push_opcode(all::OP_CHECKSIG)
        .into_script();
    let program =
        [vec![0x51, 64], sha512::Hash::hash(script.as_bytes()).as_byte_array().to_vec()].concat();
    for wrapped in [false, true] {
        let locking = if wrapped {
            Builder::<()>::new()
                .push_opcode(all::OP_HASH160)
                .push_slice(hash160::Hash::hash(&program).to_byte_array())
                .push_opcode(all::OP_EQUAL)
                .into_script()
                .into_bytes()
        } else {
            program.clone()
        };
        let outputs = [output(1000, &locking), output(2000, &locking)];
        for mode in MODES {
            let mut tx = transaction();
            for index in 0..2 {
                // Alternate digest sources: both engines must verify both sources.
                let digest = if index == 0 {
                    cache(&tx, &outputs)
                        .p2wsh512_signature_hash(
                            index,
                            script.as_bytes(),
                            outputs[index].amount,
                            mode,
                        )
                        .unwrap()
                        .to_byte_array()
                } else {
                    h.signature_hash_512(
                        &hex(&tx),
                        index,
                        script.as_bytes(),
                        outputs[index].amount.to_sat() as i64,
                        mode.to_u32() as i32,
                        &node_outputs(&outputs),
                    )
                    .unwrap()
                    .unwrap()
                };
                let mut sig = h.pq_sign_message(9, &digest, &sk, 2420, false).unwrap();
                sig.push(mode.to_u32() as u8);
                tx.inputs[index].witness = Witness::from_slice(&[sig, script.as_bytes().to_vec()]);
                if wrapped {
                    tx.inputs[index].script_sig = ScriptSigBuf::from_bytes(
                        Builder::<()>::new().push_slice(program.clone()).into_script().into_bytes(),
                    );
                }
            }
            if wrapped {
                // rc3 leaves wrapped v1-512 as ordinary script in every era.
                // A populated witness is unexpected, regardless of its signature.
                for index in 0..2 {
                    assert!(verify(
                        &tx,
                        index,
                        &outputs[index],
                        Some(&outputs),
                        VERIFY_ALL_TIDECOIN
                    )
                    .is_err());
                    assert!(h
                        .verify_tx_input_with_spent_outputs(
                            &hex(&tx),
                            index,
                            outputs[index].script_pubkey.as_bytes(),
                            outputs[index].amount.to_sat() as i64,
                            VERIFY_ALL_TIDECOIN,
                            &node_outputs(&outputs)
                        )
                        .is_err());
                }
                continue;
            }
            verify_transaction_inputs(
                &tx,
                SpentOutputs::from_txouts(outputs.to_vec()),
                VERIFY_ALL_TIDECOIN,
            )
            .unwrap();
            for index in 0..2 {
                let current = &outputs[index];
                let check = |context: Option<&[TxOut]>, expected: bool| {
                    let node = h.verify_tx_input_with_spent_outputs(
                        &hex(&tx),
                        index,
                        current.script_pubkey.as_bytes(),
                        current.amount.to_sat() as i64,
                        VERIFY_ALL_TIDECOIN,
                        &node_outputs(context.unwrap_or(&[])),
                    );
                    let rust = verify(&tx, index, current, context, VERIFY_ALL_TIDECOIN);
                    assert_eq!(
                        node.is_ok(),
                        expected,
                        "node wrapped={wrapped} mode={mode:?} index={index}: {node:?}"
                    );
                    assert_eq!(
                        rust.is_ok(),
                        expected,
                        "rust wrapped={wrapped} mode={mode:?} index={index}: {rust:?}"
                    );
                    assert_eq!(
                        verify_bytes(&tx, index, current, context, VERIFY_ALL_TIDECOIN).is_ok(),
                        expected
                    );
                };
                check(Some(&outputs), true);
                check(None, mode.to_u32() & 0x80 != 0);
                for change_script in [false, true] {
                    let mut changed = outputs.clone();
                    let foreign = 1 - index;
                    if change_script {
                        changed[foreign].script_pubkey = ScriptPubKeyBuf::from_bytes(vec![0x53]);
                    } else {
                        changed[foreign].amount = amount(changed[foreign].amount.to_sat() + 1);
                    }
                    check(Some(&changed), mode.to_u32() & 0x80 != 0);
                }
                // Change only the current locking form, preserving the executed
                // witness script. Non-ACP commits to that locking script; ACP does not.
                let mut relocked = tx.clone();
                let mut changed_scripts = outputs.clone();
                let alternate = if wrapped {
                    relocked.inputs[index].script_sig = ScriptSigBuf::new();
                    program.clone()
                } else {
                    relocked.inputs[index].script_sig = ScriptSigBuf::from_bytes(
                        Builder::<()>::new().push_slice(program.clone()).into_script().into_bytes(),
                    );
                    Builder::<()>::new()
                        .push_opcode(all::OP_HASH160)
                        .push_slice(hash160::Hash::hash(&program).to_byte_array())
                        .push_opcode(all::OP_EQUAL)
                        .into_script()
                        .into_bytes()
                };
                changed_scripts[index].script_pubkey = ScriptPubKeyBuf::from_bytes(alternate);
                // Moving native v1 to P2SH removes witness interpretation even for ACP.
                let expected = false;
                assert_eq!(
                    verify(
                        &relocked,
                        index,
                        &changed_scripts[index],
                        Some(&changed_scripts),
                        VERIFY_ALL_TIDECOIN
                    )
                    .is_ok(),
                    expected
                );
                assert_eq!(
                    h.verify_tx_input_with_spent_outputs(
                        &hex(&relocked),
                        index,
                        changed_scripts[index].script_pubkey.as_bytes(),
                        current.amount.to_sat() as i64,
                        VERIFY_ALL_TIDECOIN,
                        &node_outputs(&changed_scripts)
                    )
                    .is_ok(),
                    expected
                );

                // Consistent current-amount changes are signed in every mode.
                let mut changed = outputs.clone();
                changed[index].amount = amount(current.amount.to_sat() + 1);
                assert!(verify(&tx, index, &changed[index], Some(&changed), VERIFY_ALL_TIDECOIN)
                    .is_err());
                assert!(h
                    .verify_tx_input_with_spent_outputs(
                        &hex(&tx),
                        index,
                        current.script_pubkey.as_bytes(),
                        changed[index].amount.to_sat() as i64,
                        VERIFY_ALL_TIDECOIN,
                        &node_outputs(&changed)
                    )
                    .is_err());
            }
        }
    }
}

#[test]
fn unavailable_v1_digest_is_a_false_signature_not_an_unconditional_script_abort() {
    let h = oracle!();
    let (pk, sk) = h.pq_keypair_from_seed(9, &[43; 32], 1312, 2560).unwrap();
    let script = Builder::<()>::new()
        .push_slice([vec![9], pk].concat())
        .push_opcode(all::OP_CHECKSIG)
        .push_opcode(all::OP_NOT)
        .into_script();
    let program =
        [vec![0x51, 64], sha512::Hash::hash(script.as_bytes()).as_byte_array().to_vec()].concat();
    let outputs = [output(1000, &program), output(2000, &[0x51])];
    for (mode, missing_outputs) in [
        (TxSighashType::All, true),
        (TxSighashType::Single, false),
        (TxSighashType::SinglePlusAnyoneCanPay, false),
    ] {
        let mut tx = transaction();
        if !missing_outputs {
            tx.outputs.clear();
        }
        let mut old_constant = [0; 64];
        old_constant[0] = 1;
        let mut sig = h.pq_sign_message(9, &old_constant, &sk, 2420, false).unwrap();
        sig.push(mode.to_u32() as u8);
        tx.inputs[0].witness = Witness::from_slice(&[sig, script.as_bytes().to_vec()]);
        let context = if missing_outputs { None } else { Some(outputs.as_slice()) };
        for nullfail in [false, true] {
            let flags = if nullfail {
                VERIFY_ALL_TIDECOIN | VERIFY_NULLFAIL
            } else {
                VERIFY_ALL_TIDECOIN & !VERIFY_NULLFAIL
            };
            let node = h.verify_tx_input_with_spent_outputs(
                &hex(&tx),
                0,
                &program,
                1000,
                flags,
                &node_outputs(context.unwrap_or(&[])),
            );
            let rust = verify(&tx, 0, &outputs[0], context, flags);
            assert_eq!(node.is_ok(), !nullfail, "{node:?}");
            assert_eq!(rust.is_ok(), !nullfail, "{rust:?}");
        }
    }
}

#[test]
fn v1_single_boundaries_and_legacy_v0_controls() {
    let h = oracle!();
    let mut tx = transaction();
    tx.outputs.truncate(1);
    let outputs = [output(1000, &[0x51]), output(2000, &[0x52])];
    for mode in [TxSighashType::Single, TxSighashType::SinglePlusAnyoneCanPay] {
        for index in 0..2 {
            let node = h
                .signature_hash_512(
                    &hex(&tx),
                    index,
                    &[0x51],
                    outputs[index].amount.to_sat() as i64,
                    mode.to_u32() as i32,
                    &node_outputs(&outputs),
                )
                .unwrap();
            let rust = cache(&tx, &outputs).p2wsh512_signature_hash(
                index,
                &[0x51],
                outputs[index].amount,
                mode,
            );
            if index == 0 {
                assert_eq!(rust.unwrap().to_byte_array(), node.unwrap());
            } else {
                assert!(node.is_none());
                assert_eq!(rust, Err(WitnessV1SighashError::SingleMissingOutput));
            }
        }
    }
    let mut constant_one = [0; 32];
    constant_one[0] = 1;
    assert_eq!(
        SighashCache::new(&tx).legacy_signature_hash(1, &[0x51], 3).unwrap().to_byte_array(),
        constant_one
    );
    assert!(SighashCache::new(&tx)
        .p2wsh_signature_hash(1, &[0x51], outputs[1].amount, TxSighashType::Single)
        .is_ok());
    // Adding complete context must not affect v0 digests in any signing mode.
    for mode in MODES {
        assert_eq!(
            SighashCache::new(&tx)
                .p2wsh_signature_hash(0, &[0x51], outputs[0].amount, mode)
                .unwrap(),
            cache(&tx, &outputs).p2wsh_signature_hash(0, &[0x51], outputs[0].amount, mode).unwrap()
        );
    }
}

#[test]
fn mutable_transaction_invalidates_cached_hashes_and_rechecks_context_count() {
    let outputs = [output(1000, &[0x51]), output(2000, &[0x52])];
    let mut cache = SighashCache::new_with_spent_outputs(
        transaction(),
        SpentOutputs::from_txouts(outputs.to_vec()),
    )
    .unwrap();
    let before =
        cache.p2wsh512_signature_hash(0, &[0x51], amount(1000), TxSighashType::All).unwrap();
    cache.transaction_mut().outputs[0].amount = amount(701);
    let after =
        cache.p2wsh512_signature_hash(0, &[0x51], amount(1000), TxSighashType::All).unwrap();
    assert_ne!(before, after);
    assert_eq!(
        after,
        SighashCache::new_with_spent_outputs(
            cache.transaction(),
            SpentOutputs::from_txouts(outputs.to_vec())
        )
        .unwrap()
        .p2wsh512_signature_hash(0, &[0x51], amount(1000), TxSighashType::All)
        .unwrap()
    );
    cache.transaction_mut().inputs.pop();
    assert!(matches!(
        cache.p2wsh512_signature_hash(0, &[0x51], amount(1000), TxSighashType::All),
        Err(WitnessV1SighashError::SpentOutputs(SpentOutputsError::CountMismatch { .. }))
    ));
}
