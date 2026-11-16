#![cfg(feature = "node-oracle")]
use node_parity::TidecoinNodeHarness;
use tidecoin_fuzz::differential::{compare, generated, script_case};

#[test]
fn original_node_execution_boundaries_and_reuse() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    for mode in 0..6 {
        for bits in [
            tidecoin_fuzz::differential::flags(u32::MAX),
            0,
            consensus_core::VERIFY_ALL_TIDECOIN,
            consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_FALCON_CANONICAL,
            consensus_core::VERIFY_ALL_TIDECOIN & !consensus_core::VERIFY_WITNESS_V1_512,
        ] {
            for selector in 1..7 {
                for boundary in 0..17 {
                    let mut input = vec![mode];
                    input.extend(bits.to_le_bytes());
                    input.extend([selector, boundary, 0]);
                    compare(&node, &generated(&input));
                }
            }
            for script in [
                vec![0x51],
                vec![0x51, 0x6e, 0x75, 0x75, 0x75],
                vec![0x51, 0x63],
                vec![0x51, 0x6b, 0x6a],
                vec![0x00, 0x63, 0x7e, 0x68, 0x51],
            ] {
                compare(&node, &script_case(mode, script, vec![], bits));
            }
        }
    }
}

#[test]
fn signed_context_mutations_match_original_node() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(move || {
            use tidecoin_fuzz::differential::{compare_sighashes, mutate_signed, signed_cases};
            for case in signed_cases(&node) {
                for mutation in 0..10 {
                    for index in 0..3 {
                        for value in [0, 1, 2, 3, 0x80, 0x81, 0x82, 0x83, 0xff] {
                            let mut changed = case.clone();
                            mutate_signed(&mut changed, &[mutation, index, value, 0xff, 0xff]);
                            compare(&node, &changed);
                        }
                    }
                }
            }
            for i in 0..32 {
                compare_sighashes(&node, &[i, i / 2, 0xff, 0xff, 0xff, 0, 0, 0x51, 0xab, 0xac]);
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn wire_decoding_and_transaction_sanity_match_original_node() {
    use tidecoin::{script::ScriptPubKeyBuf, Amount, TxOut};
    use tidecoin_fuzz::differential::{compare_transaction_bytes, transaction};
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    for witness in [vec![], vec![vec![]], vec![vec![1], vec![2; 253]]] {
        let tx = transaction(vec![], witness);
        let bytes = tidecoin_consensus_encoding::encode_to_vec(&tx);
        compare_transaction_bytes(&node, &bytes);
        for end in 0..bytes.len() {
            compare_transaction_bytes(&node, &bytes[..end]);
        }
        for pos in 0..bytes.len() {
            for value in [0, 1, 2, 0xfd, 0xfe, 0xff] {
                let mut changed = bytes.clone();
                changed[pos] = value;
                compare_transaction_bytes(&node, &changed);
            }
        }
        let mut trailing = bytes;
        trailing.push(0);
        compare_transaction_bytes(&node, &trailing);
    }
    let base = transaction(vec![], vec![]);
    for count in [0, 1, 252, 253] {
        let mut tx = base.clone();
        tx.inputs = (0..count)
            .map(|i| {
                let mut input = base.inputs[0].clone();
                input.previous_output.vout = i;
                input
            })
            .collect();
        compare_transaction_bytes(&node, &tidecoin_consensus_encoding::encode_to_vec(&tx));
    }
    for values in [
        vec![],
        vec![Amount::ZERO],
        vec![Amount::MAX_MONEY],
        vec![Amount::MAX_MONEY, Amount::ONE_SAT],
    ] {
        let mut tx = base.clone();
        tx.outputs = values
            .into_iter()
            .map(|amount| TxOut { amount, script_pubkey: ScriptPubKeyBuf::new() })
            .collect();
        compare_transaction_bytes(&node, &tidecoin_consensus_encoding::encode_to_vec(&tx));
    }
    // Noncanonical/oversized input counts, marker and unknown witness flags.
    for prefix in [
        vec![0xfd, 1, 0],
        vec![0xfe, 1, 0, 0, 0],
        vec![0xff, 1, 0, 0, 0, 0, 0, 0, 0],
        vec![0xfe, 0xff, 0xff, 0xff, 0x7f],
        vec![0, 0],
        vec![0, 2],
        vec![0, 3],
    ] {
        let bytes = tidecoin_consensus_encoding::encode_to_vec(&base);
        let changed = [bytes[..4].to_vec(), prefix, bytes[5..].to_vec()].concat();
        compare_transaction_bytes(&node, &changed);
    }
    for size in [1_499_940, 1_499_941, 1_500_000] {
        let mut tx = base.clone();
        tx.outputs[0].script_pubkey = ScriptPubKeyBuf::from_bytes(vec![0; size]);
        compare_transaction_bytes(&node, &tidecoin_consensus_encoding::encode_to_vec(&tx));
    }
}

#[test]
fn malformed_legacy_multisig_tail_preserves_original_error_order() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    // Minimized from crash-61efecbb: valid zero-of-zero multisig, then an
    // incomplete push. Preparing scriptCode must leave that malformed tail.
    for mode in 0..6 {
        for script in
            [vec![0, 0, 0, 0xaf, 2], vec![0, 0, 0, 0xae, 0x69, 2], vec![0, 0, 0, 0xaf, 0x6a, 2]]
        {
            compare(&node, &script_case(mode, script, vec![], consensus_core::VERIFY_ALL_TIDECOIN));
        }
    }
}

#[test]
fn minimalif_and_competing_opcode_errors_follow_original_flags() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    for mode in 0..6 {
        for bits in [
            consensus_core::VERIFY_ALL_TIDECOIN,
            consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_MINIMALIF,
        ] {
            for condition in [vec![], vec![0], vec![1], vec![2], vec![0x80], vec![1, 0]] {
                compare(
                    &node,
                    &script_case(mode, vec![0x63, 0x51, 0x67, 0x51, 0x68], vec![condition], bits),
                );
            }
            for count in [200, 201, 202] {
                for opcode in [0x7e, 0x65, 0x6a, 0xab, 0xff] {
                    let mut script = vec![0x61; count];
                    script.extend([opcode, 0x51]);
                    compare(&node, &script_case(mode, script, vec![], bits));
                }
            }
        }
    }
}

#[test]
fn numeric_opcode_depth_precedes_scriptnum_errors() {
    use tidecoin_fuzz::differential::{push, script_case};
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    // Minimized from crash-8e940121. Original EvalScript checks stack depth
    // before CScriptNum, so one oversized or non-minimal operand is
    // INVALID_STACK_OPERATION. Decoding still reports UNKNOWN_ERROR once the
    // required operands are present.
    let oversized = vec![0u8; 5];
    let minimal = vec![1u8];
    let nonminimal = vec![1u8, 0];
    let binary = [0x93, 0x94, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4];
    for mode in 0..6 {
        for bits in [
            consensus_core::VERIFY_ALL_TIDECOIN,
            consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_MINIMALDATA,
        ] {
            for opcode in binary {
                compare(&node, &script_case(mode, vec![opcode], vec![oversized.clone()], bits));
                compare(&node, &script_case(mode, vec![opcode], vec![minimal.clone()], bits));
                compare(&node, &script_case(mode, vec![opcode], vec![nonminimal.clone()], bits));
                compare(
                    &node,
                    &script_case(
                        mode,
                        vec![opcode],
                        vec![minimal.clone(), oversized.clone()],
                        bits,
                    ),
                );
                compare(
                    &node,
                    &script_case(
                        mode,
                        vec![opcode],
                        vec![minimal.clone(), nonminimal.clone()],
                        bits,
                    ),
                );
            }
            for opcode in [0x79, 0x7a] {
                for operand in [&oversized, &nonminimal] {
                    let mut short = push(operand);
                    short.push(opcode);
                    compare(&node, &script_case(mode, short, vec![], bits));
                    let mut deep = push(&minimal);
                    deep.extend(push(operand));
                    deep.push(opcode);
                    compare(&node, &script_case(mode, deep, vec![], bits));
                }
            }
            compare(
                &node,
                &script_case(mode, vec![0xa5], vec![minimal.clone(), oversized.clone()], bits),
            );
            compare(
                &node,
                &script_case(
                    mode,
                    vec![0xa5],
                    vec![minimal.clone(), minimal.clone(), oversized.clone()],
                    bits,
                ),
            );
            compare(
                &node,
                &script_case(
                    mode,
                    vec![0xa5],
                    vec![minimal.clone(), minimal.clone(), nonminimal.clone()],
                    bits,
                ),
            );
        }
    }
}

#[test]
fn legacy_signature_removal_uses_explicit_push_encoding() {
    use tidecoin_fuzz::differential::{push, script_case};
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    // Minimized from crash-bf928ece. Original FindAndDelete searches for
    // `CScript() << vchSig`, which always has a length prefix: [0x04] is
    // `01 04`, never OP_4. The script holds both encodings so either
    // implementation choice is visible in the error, the removal count
    // (CONST_SCRIPTCODE) and the resulting scriptCode.
    let pubkey = vec![0x07; 33];
    let mut signatures =
        vec![vec![], vec![0x00], vec![0x11], vec![0x4f], vec![0x81], vec![0x04, 0x01]];
    signatures.extend((1..=16u8).map(|value| vec![value]));
    let minimal = |sig: &[u8]| match sig {
        [] => vec![0x00],
        [0x81] => vec![0x4f],
        [value @ 1..=16] => vec![0x50 + value],
        other => push(other),
    };
    for mode in 0..6 {
        for bits in [
            0,
            consensus_core::VERIFY_ALL_TIDECOIN,
            consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_CONST_SCRIPTCODE,
            consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_NULLFAIL,
            consensus_core::VERIFY_ALL_TIDECOIN
                | consensus_core::VERIFY_CONST_SCRIPTCODE
                | consensus_core::VERIFY_NULLFAIL,
        ] {
            for sig in &signatures {
                for (minimal_copy, explicit_copy) in [(true, false), (false, true), (true, true)] {
                    let mut prefix = Vec::new();
                    let mut drops = 0;
                    if minimal_copy {
                        prefix.extend(minimal(sig));
                        drops += 1;
                    }
                    if explicit_copy {
                        prefix.extend(push(sig));
                        drops += 1;
                    }
                    prefix.extend(vec![0x75; drops]);

                    // <sig> <pubkey> | encodings DROP.. CHECKSIG NOT
                    let mut checksig = prefix.clone();
                    checksig.extend([0xac, 0x91]);
                    compare(
                        &node,
                        &script_case(mode, checksig, vec![sig.clone(), pubkey.clone()], bits),
                    );

                    // <dummy> <sig> | encodings DROP.. 1 <pubkey> 1 CHECKMULTISIG NOT
                    let mut multisig = prefix;
                    multisig.push(0x51);
                    multisig.extend(push(&pubkey));
                    multisig.extend([0x51, 0xae, 0x91]);
                    compare(&node, &script_case(mode, multisig, vec![vec![], sig.clone()], bits));
                }
            }
        }
    }
    // The fuzz input itself: OP_4 sig/pubkey, CHECKSIG, then a later invalid opcode.
    let mut original = vec![0x54, 0x54, 0xac, 0x54, 0xa2, 0x54, 0x54, 0x54, 0xd6, 0x51];
    original.splice(0..0, [0x0b, 0xc7, 0x00, 0x26, 0x0b, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    compare(&node, &script_case(0, original, vec![], consensus_core::VERIFY_CONST_SCRIPTCODE));
}

#[test]
fn witness_program_recognition_matches_original_execution() {
    use tidecoin::{hashes::hash160, script::ScriptPubKeyBuf, Amount, TxOut};
    use tidecoin_fuzz::differential::{flags, push, transaction, Case};
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    for version in [0u8, 1, 2, 16] {
        for length in [0, 1, 2, 20, 32, 40, 41, 63, 64, 65] {
            for value in [0, 1] {
                let program = [
                    vec![if version == 0 { 0 } else { 0x50 + version }, length as u8],
                    vec![value; length],
                ]
                .concat();
                for wrapped in [false, true] {
                    for witness in [vec![], vec![vec![]]] {
                        for bits in [
                            consensus_core::VERIFY_ALL_TIDECOIN,
                            consensus_core::VERIFY_ALL_TIDECOIN
                                & !consensus_core::VERIFY_WITNESS_V1_512,
                            flags(u32::MAX),
                        ] {
                            let (sig, locking) = if wrapped {
                                (
                                    push(&program),
                                    [
                                        vec![0xa9, 20],
                                        hash160::Hash::hash(&program).to_byte_array().to_vec(),
                                        vec![0x87],
                                    ]
                                    .concat(),
                                )
                            } else {
                                (vec![], program.clone())
                            };
                            compare(
                                &node,
                                &Case {
                                    tx: transaction(sig, witness.clone()),
                                    spent: vec![TxOut {
                                        amount: Amount::from_sat_u32(2),
                                        script_pubkey: ScriptPubKeyBuf::from_bytes(locking),
                                    }],
                                    flags: bits,
                                },
                            );
                        }
                    }
                }
            }
        }
    }
}
