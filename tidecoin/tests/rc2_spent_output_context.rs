// SPDX-License-Identifier: CC0-1.0
#![cfg(feature = "tidecoin-node-validation")]
//! Product API regression: retain all previous outputs across input verification.
use node_parity::{SpentOutput, TidecoinNodeHarness};
use tidecoin::consensus_validation::{
    verify_script_with_flags, verify_script_with_spent_outputs, verify_transaction_with_flags,
    TxVerifyError, VERIFY_ALL_TIDECOIN,
};
use tidecoin::{
    absolute,
    hashes::{hash160, sha512},
    opcodes::all,
    script::{Builder, ScriptPubKeyBuf, ScriptSigBuf},
    transaction::{OutPoint, Transaction, TxIn, TxOut, Txid, Version},
    Amount, Sequence, SighashCache, SpentOutputs, TxSighashType, Witness,
};

#[test]
fn rc2_product_multi_input_verification_retains_spent_output_context() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let (pk, sk) = node.pq_keypair_from_seed(9, &[44; 32], 1312, 2560).unwrap();
    let script = Builder::<()>::new()
        .push_slice([vec![9], pk].concat())
        .push_opcode(all::OP_CHECKSIG)
        .into_script();
    let program =
        [vec![0x51, 64], sha512::Hash::hash(script.as_bytes()).as_byte_array().to_vec()].concat();
    let outputs = vec![
        TxOut {
            amount: Amount::from_sat_u32(1000),
            script_pubkey: ScriptPubKeyBuf::from_bytes(program.clone()),
        },
        TxOut {
            amount: Amount::from_sat_u32(2000),
            script_pubkey: ScriptPubKeyBuf::from_bytes(program),
        },
    ];
    for mode in [
        TxSighashType::All,
        TxSighashType::None,
        TxSighashType::Single,
        TxSighashType::AllPlusAnyoneCanPay,
        TxSighashType::NonePlusAnyoneCanPay,
        TxSighashType::SinglePlusAnyoneCanPay,
    ] {
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: (0..2)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([i + 1; 32]),
                        vout: i as u32,
                    },
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: vec![
                TxOut {
                    amount: Amount::from_sat_u32(500),
                    script_pubkey: ScriptPubKeyBuf::new()
                };
                2
            ],
        };
        let mut cache =
            SighashCache::new_with_spent_outputs(&tx, SpentOutputs::from_txouts(outputs.clone()))
                .unwrap();
        let signatures: Vec<_> = (0..2)
            .map(|index| {
                let hash = cache
                    .p2wsh512_signature_hash(index, script.as_bytes(), outputs[index].amount, mode)
                    .unwrap();
                let mut sig =
                    node.pq_sign_message(9, hash.as_byte_array(), &sk, 2420, false).unwrap();
                sig.push(mode.to_u32() as u8);
                sig
            })
            .collect();
        for (index, sig) in signatures.into_iter().enumerate() {
            tx.inputs[index].witness = Witness::from_slice(&[sig, script.as_bytes().to_vec()]);
        }
        let mut lookups = Vec::new();
        verify_transaction_with_flags(
            &tx,
            |outpoint| {
                lookups.push(*outpoint);
                Some(outputs[outpoint.vout as usize].clone())
            },
            VERIFY_ALL_TIDECOIN,
        )
        .unwrap();
        assert_eq!(
            lookups,
            tx.inputs.iter().map(|input| input.previous_output).collect::<Vec<_>>()
        );
        let serialized = encoding::encode_to_vec(&tx);
        let hex: String = serialized.iter().map(|b| format!("{b:02x}")).collect();
        let node_outputs: Vec<_> = outputs
            .iter()
            .map(|out| SpentOutput {
                amount: out.amount.to_sat() as i64,
                script_pubkey: out.script_pubkey.as_bytes(),
            })
            .collect();
        for index in 0..2 {
            verify_script_with_spent_outputs(
                index,
                &serialized,
                outputs.clone(),
                VERIFY_ALL_TIDECOIN,
            )
            .unwrap();
            node.verify_tx_input_with_spent_outputs(
                &hex,
                index,
                outputs[index].script_pubkey.as_bytes(),
                outputs[index].amount.to_sat() as i64,
                VERIFY_ALL_TIDECOIN,
                &node_outputs,
            )
            .unwrap();
            assert_eq!(
                verify_script_with_flags(
                    &outputs[index].script_pubkey,
                    index,
                    outputs[index].amount,
                    &serialized,
                    VERIFY_ALL_TIDECOIN
                )
                .is_ok(),
                mode.to_u32() & 0x80 != 0
            );
        }
        assert_eq!(
            verify_transaction_with_flags(
                &tx,
                |outpoint| {
                    if outpoint.vout == 0 {
                        Some(outputs[0].clone())
                    } else {
                        None
                    }
                },
                VERIFY_ALL_TIDECOIN
            ),
            Err(TxVerifyError::UnknownSpentOutput(tx.inputs[1].previous_output))
        );
        assert!(verify_transaction_with_flags(
            &tx,
            |outpoint| {
                let mut out = outputs[outpoint.vout as usize].clone();
                if outpoint.vout == 1 {
                    out.amount = Amount::from_sat_u32(2001);
                }
                Some(out)
            },
            VERIFY_ALL_TIDECOIN
        )
        .is_err());
    }
}

#[test]
fn sigop_cost_uses_candidate_flags_and_matches_node_count_witness_sigops() {
    use tidecoin::consensus_validation::{VERIFY_P2SH, VERIFY_WITNESS, VERIFY_WITNESS_V1_512};
    use tidecoin::transaction::TransactionExt as _;
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let witness_script = vec![0xac, 0x52, 0xae];
    for (version, length) in [(0, 20), (0, 32), (1, 64), (1, 32), (2, 32)] {
        let program =
            [vec![if version == 0 { 0 } else { 0x50 + version }, length], vec![1; length as usize]]
                .concat();
        for wrapped in [false, true] {
            let script_sig = if wrapped {
                ScriptSigBuf::from_bytes(
                    Builder::<()>::new().push_slice(program.clone()).into_script().into_bytes(),
                )
            } else {
                ScriptSigBuf::new()
            };
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
            let output = TxOut {
                amount: Amount::ONE_SAT,
                script_pubkey: ScriptPubKeyBuf::from_bytes(locking.clone()),
            };
            let mut tx = Transaction {
                version: Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint { txid: Txid::from_byte_array([3; 32]), vout: 0 },
                    script_sig,
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    amount: Amount::ONE_SAT,
                    script_pubkey: ScriptPubKeyBuf::new(),
                }],
            };
            for has_witness in [false, true] {
                tx.inputs[0].witness = if has_witness {
                    Witness::from_slice(std::slice::from_ref(&witness_script))
                } else {
                    Witness::new()
                };
                for flags in [
                    0,
                    VERIFY_P2SH,
                    VERIFY_P2SH | VERIFY_WITNESS,
                    VERIFY_P2SH | VERIFY_WITNESS | VERIFY_WITNESS_V1_512,
                ] {
                    let serialized = encoding::encode_to_vec(&tx);
                    let hex: String = serialized.iter().map(|b| format!("{b:02x}")).collect();
                    let native = node.count_witness_sigops(&hex, 0, &locking, flags).unwrap();
                    let expected = if flags & VERIFY_WITNESS == 0 {
                        0
                    } else if version == 0 && length == 20 {
                        1
                    } else if has_witness
                        && ((version == 0 && length == 32)
                            || (version == 1
                                && length == 64
                                && !wrapped
                                && flags & VERIFY_WITNESS_V1_512 != 0))
                    {
                        3
                    } else {
                        0
                    };
                    assert_eq!(native, expected);
                    assert_eq!(
                        tx.total_sigop_cost_with_flags(|_| Some(output.clone()), flags),
                        native
                    );
                }
            }
            if wrapped {
                let mut malformed = vec![0x75];
                malformed.extend_from_slice(tx.inputs[0].script_sig.as_bytes());
                tx.inputs[0].script_sig = ScriptSigBuf::from_bytes(malformed);
                let hex: String =
                    encoding::encode_to_vec(&tx).iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(
                    node.count_witness_sigops(&hex, 0, &locking, VERIFY_ALL_TIDECOIN).unwrap(),
                    0
                );
                assert_eq!(
                    tx.total_sigop_cost_with_flags(|_| Some(output.clone()), VERIFY_ALL_TIDECOIN),
                    0
                );
            }
        }
    }
}

#[test]
fn regtest_genesis_pow_is_independent_of_auxpow_activation() {
    use tidecoin::{
        network::Params,
        pow::{pow_hash_algorithm_at_height, MiningHashAlgorithm},
        BlockHeight,
    };
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    for (network, mut params) in [(0, Params::MAINNET), (1, Params::TESTNET), (2, Params::REGTEST)]
    {
        for activation in [0, 1, 20, i32::MAX] {
            params.auxpow_start_height = if activation == i32::MAX {
                None
            } else {
                Some(BlockHeight::from_u32(activation as u32))
            };
            for height in [0, 1, 19, 20, 21] {
                assert_eq!(
                    pow_hash_algorithm_at_height(&params, BlockHeight::from_u32(height))
                        == MiningHashAlgorithm::Scrypt,
                    node.uses_scrypt_pow(network, height as i32, activation).unwrap()
                );
            }
        }
    }
}
