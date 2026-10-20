// SPDX-License-Identifier: CC0-1.0
//! rc2 oracle regression cases. Expectations come from the pinned C++ source;
//! these establish the oracle before Rust consensus migration.
use consensus_core::*;
use hashes::{sha256, sha256d, sha512};
use node_parity::{NodeParityError, ScriptError as NodeError, SpentOutput, TidecoinNodeHarness};
use primitives::{
    absolute::LockTime, opcodes::all, script::Builder, Amount, OutPoint, ScriptPubKeyBuf,
    ScriptSigBuf, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
};

macro_rules! oracle {
    () => {
        match TidecoinNodeHarness::optional_from_env() {
            Some(h) => h,
            None => return,
        }
    };
}
fn amount(n: u64) -> Amount {
    Amount::from_sat(n).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn tx() -> Transaction {
    Transaction {
        version: TransactionVersion::TWO,
        lock_time: LockTime::from_consensus(17),
        inputs: (0..2)
            .map(|i| {
                let mut id = [0; 32];
                id[0] = i + 1;
                TxIn {
                    previous_output: OutPoint { txid: Txid::from_byte_array(id), vout: i as u32 },
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::from_consensus(0xfffffffe - i as u32),
                    witness: Witness::new(),
                }
            })
            .collect(),
        outputs: vec![
            TxOut { amount: amount(700), script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0x51]) },
            TxOut { amount: amount(500), script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0x52]) },
        ],
    }
}

#[test]
fn rc2_regtest_genesis_stays_scrypt_when_activation_is_delayed_or_disabled() {
    let h = oracle!();
    for activation in [0, 1, 20, i32::MAX] {
        assert!(h.uses_scrypt_pow(2, 0, activation).unwrap());
        for height in [1, 19, 20, 21] {
            assert_eq!(h.uses_scrypt_pow(2, height, activation).unwrap(), height >= activation);
        }
    }
    assert!(!h.uses_scrypt_pow(0, 0, i32::MAX).unwrap());
    assert!(!h.uses_scrypt_pow(1, 0, 1000).unwrap());
}

fn tx_hex(tx: &Transaction) -> String {
    hex(&encoding::encode_to_vec(tx))
}
fn witness_program(script: &[u8], v1: bool) -> Vec<u8> {
    if v1 {
        [vec![0x51, 64], sha512::Hash::hash(script).as_byte_array().to_vec()].concat()
    } else {
        [vec![0, 32], sha256::Hash::hash(script).as_byte_array().to_vec()].concat()
    }
}
fn key(h: &TidecoinNodeHarness) -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = h.pq_keypair_from_seed(9, &[42; 32], 1312, 2560).unwrap();
    ([vec![9], pk].concat(), sk)
}
fn sign(h: &TidecoinNodeHarness, msg: &[u8], sk: &[u8], mode: u8) -> Vec<u8> {
    let mut sig = h.pq_sign_message(9, msg, sk, 2420, false).unwrap();
    sig.push(mode);
    sig
}
fn assert_script_failure(result: Result<(), NodeParityError>) {
    assert!(matches!(result, Err(NodeParityError::Script(_))), "{result:?}");
}

#[test]
fn rc2_independent_sighash_vector_and_spent_output_commitments() {
    let h = oracle!();
    // src/test/sighash_tests.cpp::witness_v1_spent_output_commitments.
    // That vector was serialized independently of SignatureHash512.
    let tx_hex = tx_hex(&tx());
    let outputs = [
        SpentOutput { amount: 1000, script_pubkey: &[0x51] },
        SpentOutput { amount: 2000, script_pubkey: &[0x52] },
    ];
    let hash = h.signature_hash_512(&tx_hex, 0, &[0x51], 1000, 1, &outputs).unwrap().unwrap();
    assert_eq!(hex(&hash.into_iter().rev().collect::<Vec<_>>()),
        "94631936f659cab4c86cc42fde7a4201fd1dfafa56d1960d0f6bf46889bdbc7cfac097db48749c51fd55423ee412da866fb567bfdad9f090cc815372f9f0e4de");
    for mode in [1, 2, 3, 0x81, 0x82, 0x83] {
        let original =
            h.signature_hash_512(&tx_hex, 0, &[0x51], 1000, mode, &outputs).unwrap().unwrap();
        let missing = h.signature_hash_512(&tx_hex, 0, &[0x51], 1000, mode, &[]).unwrap();
        assert_eq!(missing, if mode & 0x80 == 0 { None } else { Some(original) });
        for index in 0..2 {
            for change_script in [false, true] {
                let mut changed = outputs;
                if change_script {
                    changed[index].script_pubkey = &[0x53];
                } else {
                    changed[index].amount += 1;
                }
                let hash = h
                    .signature_hash_512(&tx_hex, 0, &[0x51], 1000, mode, &changed)
                    .unwrap()
                    .unwrap();
                assert_eq!(hash == original, mode & 0x80 != 0, "mode={mode:x} input={index}");
            }
        }
    }
    assert!(matches!(
        h.signature_hash_512(&tx_hex, 0, &[0x51], 1000, 1, &outputs[..1]),
        Err(NodeParityError::BridgeFailure(_))
    ));
    assert!(h.signature_hash_512(&tx_hex, 2, &[0x51], 1000, 1, &outputs).is_err());
}

#[test]
fn rc2_signed_v1_spends_require_ordered_outputs_except_anyonecanpay() {
    let h = oracle!();
    let (pk, sk) = key(&h);
    let script = Builder::<()>::new().push_slice(pk).push_opcode(all::OP_CHECKSIG).into_script();
    let program = witness_program(script.as_bytes(), true);
    let outputs = [
        SpentOutput { amount: 1000, script_pubkey: &program },
        SpentOutput { amount: 2000, script_pubkey: &[0x52] },
    ];
    for mode in [1, 2, 3, 0x81, 0x82, 0x83] {
        let mut tx = tx();
        let hash = h
            .signature_hash_512(&tx_hex(&tx), 0, script.as_bytes(), 1000, mode, &outputs)
            .unwrap()
            .unwrap();
        tx.inputs[0].witness =
            Witness::from_slice(&[sign(&h, &hash, &sk, mode as u8), script.as_bytes().to_vec()]);
        let encoded = tx_hex(&tx);
        let verify = |outputs: &[SpentOutput<'_>]| {
            h.verify_tx_input_with_spent_outputs(
                &encoded,
                0,
                &program,
                1000,
                VERIFY_ALL_TIDECOIN,
                outputs,
            )
        };
        verify(&outputs).unwrap();
        let missing = verify(&[]);
        if mode & 0x80 == 0 {
            assert_script_failure(missing);
        } else {
            missing.unwrap();
        }
        for change_script in [false, true] {
            let mut changed = outputs;
            if change_script {
                changed[1].script_pubkey = &[0x53];
            } else {
                changed[1].amount += 1;
            }
            if mode & 0x80 == 0 {
                assert_script_failure(verify(&changed));
            } else {
                verify(&changed).unwrap();
            }
        }
        let swapped = [outputs[1], outputs[0]];
        if mode & 0x80 == 0 {
            assert_script_failure(verify(&swapped));
        } else {
            verify(&swapped).unwrap();
        }
        assert!(matches!(verify(&outputs[..1]), Err(NodeParityError::BridgeFailure(_))));
        // The explicitly supplied current amount is signed in every mode.
        assert_script_failure(h.verify_tx_input_with_spent_outputs(
            &encoded,
            0,
            &program,
            1001,
            VERIFY_ALL_TIDECOIN,
            &outputs,
        ));
    }
}

#[test]
fn rc2_single_without_matching_output_has_no_digest_or_valid_constant_signature() {
    let h = oracle!();
    let (pk, sk) = key(&h);
    let script = Builder::<()>::new().push_slice(pk).push_opcode(all::OP_CHECKSIG).into_script();
    let program = witness_program(script.as_bytes(), true);
    let outputs = [
        SpentOutput { amount: 1000, script_pubkey: &program },
        SpentOutput { amount: 2000, script_pubkey: &[0x52] },
    ];
    let mut tx = tx();
    tx.outputs.clear();
    for mode in [3, 0x83] {
        assert_eq!(
            h.signature_hash_512(&tx_hex(&tx), 0, script.as_bytes(), 1000, mode, &outputs).unwrap(),
            None
        );
        let mut one = [0; 64];
        one[0] = 1;
        tx.inputs[0].witness =
            Witness::from_slice(&[sign(&h, &one, &sk, mode as u8), script.as_bytes().to_vec()]);
        assert_script_failure(h.verify_tx_input_with_spent_outputs(
            &tx_hex(&tx),
            0,
            &program,
            1000,
            VERIFY_ALL_TIDECOIN,
            &outputs,
        ));
    }
}

#[test]
fn rc2_v1_activation_and_undefined_hash_type_errors() {
    let h = oracle!();
    let mut tx = tx();
    let program = witness_program(&[0x51], true);
    let flags = VERIFY_P2SH | VERIFY_WITNESS;
    tx.inputs[0].witness = Witness::from_slice(&[vec![0x51]]);
    assert_eq!(
        h.verify_tx_input_hex(&tx_hex(&tx), 0, &program, 1000, flags),
        Err(NodeParityError::Script(NodeError::WitnessUnexpected))
    );
    h.verify_tx_input_hex(&tx_hex(&tx), 0, &program, 1000, flags | VERIFY_WITNESS_V1_512).unwrap();
    tx.inputs[0].witness = Witness::new();
    tx.inputs[0].script_sig = ScriptSigBuf::from_bytes(vec![0x51]);
    h.verify_tx_input_hex(&tx_hex(&tx), 0, &program, 1000, flags).unwrap();
    assert_eq!(
        h.verify_tx_input_hex(&tx_hex(&tx), 0, &program, 1000, flags | VERIFY_WITNESS_V1_512),
        Err(NodeParityError::Script(NodeError::WitnessMalleated))
    );

    let script = [0x00, 0xac, 0x91]; // empty pubkey CHECKSIG NOT
    let program = witness_program(&script, true);
    tx.inputs[0].script_sig = ScriptSigBuf::new();
    for mode in [0, 4, 0x41, 0x80, 0x84, 0xff] {
        tx.inputs[0].witness = Witness::from_slice(&[vec![1, mode], script.to_vec()]);
        assert_eq!(
            h.verify_tx_input_hex(&tx_hex(&tx), 0, &program, 1000, VERIFY_ALL_TIDECOIN),
            Err(NodeParityError::Script(NodeError::SigHashType)),
            "mode={mode:x}"
        );
    }
}

#[test]
fn rc2_mldsa_authorization_activates_with_pq_strict() {
    let h = oracle!();
    let (pk, sk) = key(&h);
    let script = Builder::<()>::new().push_slice(pk).push_opcode(all::OP_CHECKSIG).into_script();
    let mut tx = tx();
    // Legacy digest is unchanged in rc2; node accepts this control after activation.
    let hash = SighashCache::new(&tx).legacy_signature_hash(0, script.as_bytes(), 1).unwrap();
    tx.inputs[0].script_sig = ScriptSigBuf::from_bytes(
        Builder::<()>::new()
            .push_slice(sign(&h, hash.as_byte_array(), &sk, 1))
            .into_script()
            .into_bytes(),
    );
    assert_script_failure(h.verify_tx_input_hex(
        &tx_hex(&tx),
        0,
        script.as_bytes(),
        1000,
        VERIFY_P2SH | VERIFY_WITNESS,
    ));
    h.verify_tx_input_hex(
        &tx_hex(&tx),
        0,
        script.as_bytes(),
        1000,
        VERIFY_P2SH | VERIFY_WITNESS | VERIFY_PQ_STRICT,
    )
    .unwrap();
}

#[test]
fn rc2_witness_v0_undefined_hash_type_preserves_raw_byte_until_policy_rejects_it() {
    let h = oracle!();
    let (pk, sk) = key(&h);
    let script = Builder::<()>::new().push_slice(pk).push_opcode(all::OP_CHECKSIG).into_script();
    let mut tx = tx();
    // Independently encode the preimage, retaining raw 0x41 in the last field.
    let prevouts: Vec<u8> =
        tx.inputs.iter().flat_map(|i| encoding::encode_to_vec(&i.previous_output)).collect();
    let sequences: Vec<u8> =
        tx.inputs.iter().flat_map(|i| encoding::encode_to_vec(&i.sequence)).collect();
    let outputs: Vec<u8> = tx.outputs.iter().flat_map(encoding::encode_to_vec).collect();
    let mut preimage = encoding::encode_to_vec(&tx.version);
    preimage.extend_from_slice(sha256d::Hash::hash(&prevouts).as_byte_array());
    preimage.extend_from_slice(sha256d::Hash::hash(&sequences).as_byte_array());
    preimage.extend(encoding::encode_to_vec(&tx.inputs[0].previous_output));
    preimage.extend(encoding::encode_to_vec(script.as_script()));
    preimage.extend_from_slice(&1000u64.to_le_bytes());
    preimage.extend(encoding::encode_to_vec(&tx.inputs[0].sequence));
    preimage.extend_from_slice(sha256d::Hash::hash(&outputs).as_byte_array());
    preimage.extend(encoding::encode_to_vec(&tx.lock_time));
    preimage.extend_from_slice(&0x41u32.to_le_bytes());
    tx.inputs[0].witness = Witness::from_slice(&[
        sign(&h, sha256d::Hash::hash(&preimage).as_byte_array(), &sk, 0x41),
        script.as_bytes().to_vec(),
    ]);
    let program = witness_program(script.as_bytes(), false);
    let flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_PQ_STRICT;
    h.verify_tx_input_hex(&tx_hex(&tx), 0, &program, 1000, flags).unwrap();
    assert_eq!(
        h.verify_tx_input_hex(&tx_hex(&tx), 0, &program, 1000, flags | (1 << 16)),
        Err(NodeParityError::Script(NodeError::SigHashType))
    );
}
