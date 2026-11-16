// SPDX-License-Identifier: CC0-1.0
#![cfg(feature = "tidecoin-node-validation")]
use node_parity::{validation, TidecoinNodeHarness};
use serde_json::json;
use tidecoin::script::{ScriptPubKeyBuf, ScriptSigBuf};
use tidecoin::{
    absolute,
    hashes::{hash160, sha256, sha512},
    transaction::{TransactionExt, Version},
    Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn rc3_witness_policy_dependence_and_sigops_match_original_node() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let script = [0x51, 0xac]; // One sigop; policy is separate from execution.
    let programs = [
        [vec![0, 32], sha256::Hash::hash(&script).to_byte_array().to_vec()].concat(),
        [vec![0x51, 64], sha512::Hash::hash(&script).to_byte_array().to_vec()].concat(),
        [vec![0x51, 32], vec![3; 32]].concat(),
        vec![0x51, 2, 0x4e, 0x73], // pay-to-anchor
        [vec![0x52, 32], vec![3; 32]].concat(),
    ];
    let mut requests = Vec::new();
    let mut expected = Vec::new();
    for (kind, program) in programs.iter().enumerate() {
        for wrapped in [false, true] {
            for active in [false, true] {
                let flags = consensus_core::VERIFY_P2SH
                    | consensus_core::VERIFY_WITNESS
                    | if active { consensus_core::VERIFY_WITNESS_V1_512 } else { 0 };
                let locking = if wrapped {
                    [
                        vec![0xa9, 20],
                        hash160::Hash::hash(program).to_byte_array().to_vec(),
                        vec![0x87],
                    ]
                    .concat()
                } else {
                    program.clone()
                };
                let script_sig = if wrapped {
                    [vec![program.len() as u8], program.clone()].concat()
                } else {
                    vec![]
                };
                let tx = Transaction {
                    version: Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    inputs: vec![TxIn {
                        previous_output: OutPoint { txid: Txid::from_byte_array([2; 32]), vout: 0 },
                        script_sig: ScriptSigBuf::from_bytes(script_sig),
                        sequence: Sequence::MAX,
                        witness: Witness::from_slice(&[script.as_slice()]),
                    }],
                    outputs: vec![TxOut {
                        amount: Amount::ONE_SAT,
                        script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0x51]),
                    }],
                };
                let prevout = TxOut {
                    amount: Amount::from_sat_u32(1000),
                    script_pubkey: ScriptPubKeyBuf::from_bytes(locking.clone()),
                };
                let raw = hex(&encoding::encode_to_vec(&tx));
                let sigops = usize::from(kind == 0 || (kind == 1 && active && !wrapped));
                assert_eq!(node.count_witness_sigops(&raw, 0, &locking, flags).unwrap(), sigops);
                assert_eq!(
                    tx.total_sigop_cost_with_flags(|_| Some(prevout.clone()), flags),
                    sigops
                );
                let standard =
                    tidecoin::policy::is_witness_standard(&tx, |_| Some(prevout.clone()));
                let dependent = tidecoin::policy::spends_non_anchor_witness_program_with_flags(
                    &tx,
                    |_| Some(prevout.clone()),
                    flags,
                );
                assert_eq!(dependent, sigops != 0);
                requests.push(json!({"op":"witness_policy", "tx":raw,"prev_script":hex(&locking),"flags":flags}));
                expected.push((standard, dependent));
            }
        }
    }
    for (result, (standard, dependent)) in validation::run(&requests).unwrap().iter().zip(expected)
    {
        assert_eq!(result["standard"], standard);
        assert_eq!(result["dependent"], dependent);
    }
}

#[test]
#[cfg(feature = "p2p")]
fn rc3_headers_batch_size_and_message_limits_match_node() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    use p2p_messages::message::{HeadersMessageSize, MAX_MSG_SIZE};
    let mut cases = Vec::new();
    for count in [0, 1, 252, 253, 1999, 2000, 2001] {
        cases.push(vec![80; count]);
    }
    for last in [1_499_994, 1_499_995, 1_499_996] {
        cases.push(vec![1_500_000, 1_500_000, 1_500_000, last]);
    }
    for max_count in [3, 2000] {
        let requests = cases
            .iter()
            .map(|sizes| json!({"op":"headers_size","sizes":sizes,"max_count":max_count}))
            .collect::<Vec<_>>();
        for (sizes, result) in cases.iter().zip(validation::run(&requests).unwrap()) {
            let mut size = HeadersMessageSize::new();
            for &bytes in sizes {
                size.add(bytes);
            }
            assert_eq!(result["size"], size.size());
            assert_eq!(result["full"], size.is_full(max_count));
            assert_eq!(result["max_message"], MAX_MSG_SIZE);
            assert_eq!(result["max_header"], tidecoin::block_validation::MAX_BLOCK_HEADER_SIZE);
        }
    }
}
