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
                                    eval: vec![],
                                },
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn opcode_results_match_original_eval_script() {
    use tidecoin_fuzz::differential::compare_eval_only;
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    // Verdicts alone miss wrong results (a misordered ROT usually leaves a
    // true top element). Run every opcode on stacks whose exact contents show
    // ordering, arithmetic and encoding mistakes, and compare whole stacks.
    let values: Vec<Vec<u8>> = vec![
        vec![],     // 0 / false
        vec![0x00], // non-minimal zero
        vec![0x80], // negative zero
        vec![0x01],
        vec![0x02],
        vec![0x81],                         // -1
        vec![0x7f],                         // 127
        vec![0xff],                         // -127
        vec![0x80, 0x00],                   // 128
        vec![0x01, 0x00],                   // non-minimal 1
        vec![0xff, 0xff, 0xff, 0x7f],       // i32::MAX
        vec![0xff, 0xff, 0xff, 0xff],       // -i32::MAX
        vec![0x00, 0x00, 0x00, 0x80, 0x00], // 5 bytes: 2^31
        vec![0xab; 20],                     // non-numeric data
    ];
    let small = &values[..6];
    let mut stacks: Vec<Vec<Vec<u8>>> = vec![vec![]];
    stacks.extend(values.iter().map(|a| vec![a.clone()]));
    for a in &values {
        for b in &values {
            stacks.push(vec![a.clone(), b.clone()]);
        }
    }
    for a in small {
        for b in small {
            for c in small {
                stacks.push(vec![a.clone(), b.clone(), c.clone()]);
            }
        }
    }
    // Distinct items expose any misordering by the stack-shuffling opcodes.
    let distinct: Vec<Vec<u8>> = (1..=7u8).map(|i| vec![0x10 + i]).collect();
    // Every depth from 1 to 7, so each opcode sees exactly its minimum depth.
    stacks.extend((1..=distinct.len()).map(|depth| distinct[..depth].to_vec()));
    for index in [vec![], vec![0x01], vec![0x02], vec![0x05], vec![0x06], vec![0x07], vec![0x81]] {
        let mut stack = distinct.clone();
        stack.push(index);
        stacks.push(stack);
    }
    for bits in [0, consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_MINIMALDATA] {
        for opcode in 0u8..=0xff {
            for stack in &stacks {
                compare_eval_only(&node, &[opcode], stack, bits);
            }
        }
    }
}

/// Minimal script-number encoding of `value`.
fn script_num(value: i64) -> Vec<u8> {
    let mut magnitude = value.unsigned_abs();
    let mut out = Vec::new();
    while magnitude > 0 {
        out.push(magnitude as u8);
        magnitude >>= 8;
    }
    if let Some(last) = out.last_mut() {
        if *last & 0x80 != 0 {
            out.push(if value < 0 { 0x80 } else { 0 });
        } else if value < 0 {
            *last |= 0x80;
        }
    }
    out
}

/// Pushes `value` the way MINIMALDATA requires.
fn push_num(value: i64) -> Vec<u8> {
    match value {
        0 => vec![0x00],
        -1 => vec![0x4f],
        1..=16 => vec![0x50 + value as u8],
        _ => tidecoin_fuzz::differential::push(&script_num(value)),
    }
}

/// Every encoding of `data` the script format can express: direct, PUSHDATA1/2/4.
fn push_encodings(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if data.len() < 76 {
        out.push([vec![data.len() as u8], data.to_vec()].concat());
    }
    if data.len() <= 255 {
        out.push([vec![0x4c, data.len() as u8], data.to_vec()].concat());
    }
    if data.len() <= 65535 {
        out.push([vec![0x4d], (data.len() as u16).to_le_bytes().to_vec(), data.to_vec()].concat());
    }
    out.push([vec![0x4e], (data.len() as u32).to_le_bytes().to_vec(), data.to_vec()].concat());
    out
}

#[test]
fn witness_stack_depth_is_checked_only_by_execution() {
    use tidecoin_fuzz::differential::compare;
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    // The original witness path checks element sizes before execution, but
    // stack depth only after each executed opcode.
    for mode in 2..6 {
        for depth in [998, 999, 1000, 1001, 1002] {
            // Empty script, NOP, 2DROP, DROP, DEPTH.
            for script in [vec![], vec![0x61], vec![0x6d], vec![0x75], vec![0x74]] {
                for bits in [consensus_core::VERIFY_ALL_TIDECOIN, u32::MAX] {
                    compare(&node, &script_case(mode, script.clone(), vec![vec![]; depth], bits));
                }
            }
        }
        for size in [8191, 8192, 8193] {
            compare(
                &node,
                &script_case(
                    mode,
                    vec![0x75],
                    vec![vec![1; size]],
                    consensus_core::VERIFY_ALL_TIDECOIN,
                ),
            );
        }
    }
}

#[test]
fn lock_time_and_sequence_boundaries_match_original_node() {
    use tidecoin::{absolute::LockTime, Sequence, TransactionVersion};
    use tidecoin_fuzz::differential::compare;
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let threshold = 500_000_000i64;
    let cltv_args = [0, 1, threshold - 1, threshold, threshold + 1, u32::MAX as i64, 1 << 32, -1];
    let tx_locks =
        [0u32, 1, threshold as u32 - 1, threshold as u32, threshold as u32 + 1, u32::MAX];
    let csv_args = [
        0i64,
        1,
        0xffff,
        0x1_0000,
        1 << 22,
        (1 << 22) | 1,
        (1 << 22) | 0xffff,
        1 << 31,
        (1 << 31) | 1,
        u32::MAX as i64,
        1 << 32,
        -1,
    ];
    let tx_sequences = [
        0u32,
        1,
        0xffff,
        0x1_0000,
        1 << 22,
        (1 << 22) | 1,
        (1 << 22) | 2,
        1 << 31,
        u32::MAX - 1,
        u32::MAX,
    ];
    for mode in [0, 2] {
        for bits in [0, consensus_core::VERIFY_ALL_TIDECOIN] {
            for arg in cltv_args {
                for lock in tx_locks {
                    for sequence in [0, u32::MAX - 1, u32::MAX] {
                        let mut case =
                            script_case(mode, [push_num(arg), vec![0xb1]].concat(), vec![], bits);
                        case.tx.lock_time = LockTime::from_consensus(lock);
                        case.tx.inputs[0].sequence = Sequence::from_consensus(sequence);
                        compare(&node, &case);
                    }
                }
            }
            for arg in csv_args {
                for sequence in tx_sequences {
                    for version in [1u32, 2, 3, u32::MAX] {
                        let mut case =
                            script_case(mode, [push_num(arg), vec![0xb2]].concat(), vec![], bits);
                        case.tx.version = TransactionVersion::maybe_non_standard(version);
                        case.tx.inputs[0].sequence = Sequence::from_consensus(sequence);
                        compare(&node, &case);
                    }
                }
            }
        }
    }
}

#[test]
fn push_encodings_and_signature_removal_match_original_node() {
    use tidecoin_fuzz::differential::{compare, compare_eval_only};
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let flag_sets = [
        0,
        consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_MINIMALDATA,
        consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_CONST_SCRIPTCODE,
    ];
    let mut data: Vec<Vec<u8>> = vec![vec![]];
    data.extend((0x00..=0x11).chain([0x4f, 0x80, 0x81, 0xff]).map(|b| vec![b]));
    data.extend([2usize, 75, 76, 77, 255, 256, 257, 520].map(|len| vec![0x5a; len]));
    // MINIMALDATA over every encoding of every boundary length and value.
    for item in &data {
        for script in push_encodings(item) {
            for bits in flag_sets {
                compare_eval_only(&node, &script, &[], bits);
            }
        }
    }
    // FindAndDelete removes only the explicit push encoding of the signature,
    // walking the script by instruction; CONST_SCRIPTCODE reports any match.
    let pubkey = vec![0x07; 33];
    let tails: [&[u8]; 5] =
        [&[], &[0x4c], &[0x4d, 0x05], &[0x4e, 0x01, 0x00, 0x00], &[0x4c, 0x05, 0x01]];
    for len in [1usize, 2, 75, 76, 77, 255, 256, 300] {
        let mut sig = vec![0x5a; len];
        *sig.last_mut().unwrap() = 0x01;
        let mut patterns = push_encodings(&sig);
        // The pattern inside another push must not match.
        patterns.push(tidecoin_fuzz::differential::push(
            &[vec![0xaa], tidecoin_fuzz::differential::push(&sig), vec![0xbb]].concat(),
        ));
        patterns.push(
            [tidecoin_fuzz::differential::push(&sig), tidecoin_fuzz::differential::push(&sig)]
                .concat(),
        );
        for pattern in &patterns {
            for tail in tails {
                let script = [
                    pattern.clone(),
                    vec![0x6d, 0x51], // 2DROP leaves the signature under OP_1 on short patterns
                    tidecoin_fuzz::differential::push(&pubkey),
                    vec![0xac],
                    tail.to_vec(),
                ]
                .concat();
                for mode in [0, 1] {
                    for bits in flag_sets {
                        compare(
                            &node,
                            &script_case(
                                mode,
                                script.clone(),
                                vec![sig.clone(), sig.clone()],
                                bits,
                            ),
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn multisig_counts_and_operation_limit_match_original_node() {
    use tidecoin_fuzz::differential::{compare, compare_eval_only};
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let bits_all = consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_NULLFAIL;
    for keys in 0..=3usize {
        for sigs in 0..=keys + 1 {
            for missing in 0..=2usize {
                for sig in [vec![], vec![0x01], vec![0x00], vec![0xaa, 0x01]] {
                    // Bottom to top: dummy, signatures, count, keys, count.
                    let mut stack = vec![vec![]];
                    stack.extend(std::iter::repeat_n(sig.clone(), sigs));
                    stack.push(script_num(sigs as i64));
                    stack.extend((0..keys).map(|i| vec![0x02 + i as u8; 33]));
                    stack.push(script_num(keys as i64));
                    let stack = stack[missing.min(stack.len())..].to_vec();
                    for bits in [0, bits_all] {
                        compare_eval_only(&node, &[0xae], &stack, bits);
                        compare_eval_only(&node, &[0xaf], &stack, bits);
                    }
                }
            }
        }
    }
    // OP_1..OP_16 are not counted toward the 201 operation limit.
    for nops in [199, 200, 201, 202] {
        for last in [0x00, 0x4f, 0x51, 0x60, 0x61] {
            let script = [vec![0x61; nops], vec![0x60, last]].concat();
            for mode in 0..4 {
                compare(&node, &script_case(mode, script.clone(), vec![], bits_all));
            }
        }
    }
}

#[test]
fn script_code_follows_code_separator_and_executing_script() {
    use consensus_core::{SighashCache, SpentOutputs, TxSighashType};
    use tidecoin::{
        script::{ScriptPubKeyBuf, ScriptSigBuf},
        PqScheme, PqSchemeCryptoExt, PqSignature, Witness,
    };
    use tidecoin_fuzz::differential::{compare, push};
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    // Two signature checks in one input whose script codes differ. Reusing the
    // first script code for the second check fails the second signature.
    let (pk, sk) = PqScheme::Falcon512
        .generate_keypair_from_seed(&vec![41; PqScheme::Falcon512.deterministic_seed_len()])
        .unwrap();
    let key = push(&pk.to_prefixed_bytes());
    let bits = (consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_NULLFAIL)
        & !consensus_core::VERIFY_CONST_SCRIPTCODE;
    // Locking script with a code separator between the two checks.
    let separated = [key.clone(), vec![0xad, 0xab], key.clone(), vec![0xac]].concat();
    let after_separator = [key.clone(), vec![0xac]].concat();
    let sign = |case: &tidecoin_fuzz::differential::Case, code: &[u8], kind: u8| {
        let mut cache = SighashCache::new_with_spent_outputs(
            &case.tx,
            SpentOutputs::from_txouts(case.spent.clone()),
        )
        .unwrap();
        let amount = case.spent[0].amount;
        let mut sig = match kind {
            0 => PqSignature::sign_msg32(
                &cache.legacy_signature_hash(0, code, 1).unwrap().to_byte_array(),
                &sk,
            ),
            1 => PqSignature::sign_msg32(
                &cache
                    .p2wsh_signature_hash(0, code, amount, TxSighashType::All)
                    .unwrap()
                    .to_byte_array(),
                &sk,
            ),
            _ => PqSignature::sign_msg64(
                &cache
                    .p2wsh512_signature_hash(0, code, amount, TxSighashType::All)
                    .unwrap()
                    .to_byte_array(),
                &sk,
            ),
        }
        .unwrap()
        .as_bytes()
        .to_vec();
        sig.push(0x01);
        sig
    };
    let check = |case: &tidecoin_fuzz::differential::Case| {
        compare(&node, case);
        consensus_core::verify_transaction_inputs(
            &case.tx,
            SpentOutputs::from_txouts(case.spent.clone()),
            case.flags,
        )
        .unwrap();
    };

    // Legacy: the first check signs the whole script without separators.
    let mut case = script_case(0, separated.clone(), vec![], bits);
    let stripped = [key.clone(), vec![0xad], key.clone(), vec![0xac]].concat();
    let (first, second) = (sign(&case, &stripped, 0), sign(&case, &after_separator, 0));
    case.tx.inputs[0].script_sig = ScriptSigBuf::from_bytes([push(&second), push(&first)].concat());
    case.eval.clear();
    check(&case);

    // Legacy: the first check runs in the signature script, the second in the
    // locking script, both from offset zero.
    let mut case = script_case(0, after_separator.clone(), vec![], bits);
    let second = sign(&case, &after_separator, 0);
    let first = sign(&case, &[push(&second), key.clone(), vec![0xad]].concat(), 0);
    case.tx.inputs[0].script_sig =
        ScriptSigBuf::from_bytes([push(&second), push(&first), key, vec![0xad]].concat());
    case.spent[0].script_pubkey = ScriptPubKeyBuf::from_bytes(after_separator.clone());
    case.eval.clear();
    check(&case);

    // Witness v0 and v1_512 keep separators and start after the last one executed.
    for (mode, kind) in [(2u8, 1u8), (3, 2)] {
        let mut case = script_case(mode, separated.clone(), vec![], bits);
        let (first, second) = (sign(&case, &separated, kind), sign(&case, &after_separator, kind));
        case.tx.inputs[0].witness = Witness::from(vec![second, first, separated.clone()]);
        case.eval.clear();
        check(&case);
    }
}

#[test]
fn instruction_boundaries_match_original_node() {
    use tidecoin::script::ScriptSigBuf;
    use tidecoin_fuzz::differential::{compare, push};
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    // Original GetOp walks instruction by instruction. A Rust length or offset
    // mistake in a PUSHDATA form lands the walk inside a payload, where these
    // payloads hold the signature pattern behind OP_0 padding. Signature
    // removal (with CONST_SCRIPTCODE) and the P2SH push-only check both show it.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move |bound: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % bound as u64) as usize
    };
    let encode = |data: &[u8], form: usize| {
        let forms = push_encodings(data);
        forms[form % forms.len()].clone()
    };
    let pubkey = vec![0x07; 33];
    let flag_sets = [
        consensus_core::VERIFY_ALL_TIDECOIN,
        consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_CONST_SCRIPTCODE,
        consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_SIGPUSHONLY,
    ];
    for _ in 0..400 {
        let mut sig = vec![0x5a; [1, 2, 3, 76, 256][next(5)]];
        *sig.last_mut().unwrap() = 0x01;
        let pattern = push(&sig);
        let mut region = Vec::new();
        for _ in 0..1 + next(4) {
            let payload = match next(4) {
                0 => pattern.clone(),
                1 => [vec![0; next(6)], pattern.clone(), vec![0; next(3)]].concat(),
                2 => [vec![0; next(6)], pattern.clone(), vec![0; 0x51 + next(16)]].concat(),
                _ => vec![0; next(90)],
            };
            region.extend(encode(&payload, next(4)));
            if next(3) == 0 {
                region.extend(pattern.clone());
            }
        }
        // OP_0 IF <region> ENDIF: the region is walked but not executed.
        let script = [vec![0x00, 0x63], region, vec![0x68], push(&pubkey), vec![0xac]].concat();
        for mode in [0, 1] {
            for bits in flag_sets {
                let mut case = script_case(mode, script.clone(), vec![sig.clone()], bits);
                // Signature-script pushes in every encoding, for the push-only checks.
                let mut script_sig = encode(&sig, next(4));
                if mode == 1 {
                    script_sig.extend(encode(&script, next(4)));
                }
                case.tx.inputs[0].script_sig = ScriptSigBuf::from_bytes(script_sig);
                compare(&node, &case);
            }
        }
    }
}

#[test]
fn signed_multisig_matches_original_node() {
    use consensus_core::{SighashCache, SpentOutputs, TxSighashType};
    use tidecoin::{script::ScriptSigBuf, PqScheme, PqSchemeCryptoExt, PqSignature, Witness};
    use tidecoin_fuzz::differential::{compare, push};
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let keys: Vec<_> = (0..3u8)
        .map(|i| {
            PqScheme::Falcon512
                .generate_keypair_from_seed(&vec![
                    50 + i;
                    PqScheme::Falcon512.deterministic_seed_len()
                ])
                .unwrap()
        })
        .collect();
    let bits = consensus_core::VERIFY_ALL_TIDECOIN | consensus_core::VERIFY_NULLFAIL;
    // (required, key count, signing keys in order, verifies)
    let layouts: [(usize, usize, &[usize], bool); 8] = [
        (1, 1, &[0], true),
        (1, 2, &[0], true),
        (1, 2, &[1], true),
        (2, 2, &[0, 1], true),
        (2, 3, &[0, 2], true),
        (2, 3, &[1, 2], true),
        (2, 2, &[1, 0], false),
        (2, 3, &[2, 0], false),
    ];
    for (required, count, signers, valid) in layouts {
        let script = [
            vec![0x50 + required as u8],
            keys[..count].iter().flat_map(|(pk, _)| push(&pk.to_prefixed_bytes())).collect(),
            vec![0x50 + count as u8, 0xae],
        ]
        .concat();
        for mode in [0u8, 2] {
            let mut case = script_case(mode, script.clone(), vec![], bits);
            let amount = case.spent[0].amount;
            let mut cache = SighashCache::new_with_spent_outputs(
                &case.tx,
                SpentOutputs::from_txouts(case.spent.clone()),
            )
            .unwrap();
            let hash = if mode == 0 {
                cache.legacy_signature_hash(0, &script, 1).unwrap().to_byte_array()
            } else {
                cache
                    .p2wsh_signature_hash(0, &script, amount, TxSighashType::All)
                    .unwrap()
                    .to_byte_array()
            };
            let mut items = vec![vec![]];
            for &signer in signers {
                let mut sig =
                    PqSignature::sign_msg32(&hash, &keys[signer].1).unwrap().as_bytes().to_vec();
                sig.push(0x01);
                items.push(sig);
            }
            if mode == 0 {
                case.tx.inputs[0].script_sig =
                    ScriptSigBuf::from_bytes(items.iter().flat_map(|item| push(item)).collect());
            } else {
                items.push(script.clone());
                case.tx.inputs[0].witness = Witness::from(items);
            }
            case.eval.clear();
            compare(&node, &case);
            let result = consensus_core::verify_transaction_inputs(
                &case.tx,
                SpentOutputs::from_txouts(case.spent.clone()),
                case.flags,
            );
            assert_eq!(
                result.is_ok(),
                valid,
                "{required}-of-{count} signers={signers:?} mode={mode}"
            );
        }
    }
}

#[test]
fn signature_hashes_match_original_node_for_generated_transactions() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut byte = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state >> 24) as u8
    };
    for _ in 0..4000 {
        let input: Vec<u8> = (0..512).map(|_| byte()).collect();
        tidecoin_fuzz::differential::compare_random_sighashes(&node, &input);
    }
}

#[test]
fn legacy_signature_hash_removes_code_separators_like_original_node() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let tx = tidecoin_fuzz::differential::transaction(vec![], vec![]);
    let bytes = tidecoin_consensus_encoding::encode_to_vec(&tx);
    for script in [
        vec![0xab],
        vec![0xab, 0x51, 0xab, 0xab, 0xac],
        vec![0x51, 0x01, 0xab, 0xab], // separator byte inside a push is kept
        vec![0x51, 0xab, 0x4c],       // truncated PUSHDATA1 tail
        vec![0xab, 0x4d, 0x05, 0x00, 0xab], // truncated PUSHDATA2 payload
        // Same scripts as the consensus-core serializer unit test.
        vec![0x4c, 0x01, 0xab, 0xab],
        vec![0x51, 0xab, 0x4c, 0x05, 0x01],
        vec![0x02, 0xab],
        vec![0xab, 0x4d, 0x05],
        vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0xab],
        vec![0x4e, 0x02, 0x00, 0x00, 0x00, 0xab],
    ] {
        for hash_type in [1u32, 2, 3, 0x81, 0, 0xff, 0x8000_0001] {
            let original = node
                .signature_hashes(
                    &bytes,
                    0,
                    node_parity::SighashVersion::Legacy,
                    0,
                    &[(hash_type as i32, &script)],
                )
                .unwrap()[0];
            let rust = consensus_core::SighashCache::new(&tx)
                .legacy_signature_hash(0, &script, hash_type)
                .unwrap();
            assert_eq!(rust.to_byte_array(), original, "script={script:02x?} {hash_type:#x}");
        }
    }
}

#[test]
fn witness_encoding_with_invalid_script_sig_is_decoded_exactly() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    // Payload of crash-0d0b65f0 (kind 4). It generates a witness encoding with
    // no outputs whose second input has an invalid scriptSig. The bridge's former
    // RPC heuristics rejected that reading and accepted the same bytes as a
    // zero-input legacy transaction; comparison bridges now decode exactly.
    let payload = [
        0x6f, 0x48, 0xc3, 0xe1, 0x5d, 0x64, 0x6b, 0x72, 0x79, 0x80, 0x87, 0x8e, 0x95, 0x9c, 0xa3,
        0x16, 0x1d, 0x01, 0x00, 0x00, 0xef, 0xff, 0x30, 0xb3, 0x04, 0x24, 0x2b, 0x35, 0x38, 0x40,
        0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6d, 0x65, 0x5f, 0xd8, 0xdf, 0xe6, 0xed, 0xf4, 0xfb, 0x02,
        0x09, 0x10, 0x17, 0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2, 0xa9, 0xb0, 0xb7,
        0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0xe1, 0xe8, 0x76, 0x7d, 0x53, 0x74, 0x31, 0x33, 0x72, 0x17,
        0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2, 0xa9,
        0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0xe1, 0xe8, 0xef,
    ];
    tidecoin_fuzz::differential::compare_random_sighashes(&node, &payload);
}

#[test]
fn signature_before_truncated_push_reaches_the_same_error() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    use tidecoin_fuzz::differential::{node_script_result, push};
    // A signature check precedes a truncated push in the executing script. The
    // spend is invalid either way, but the digest decides the first error: with
    // a signature valid for the node digest, CHECKSIGVERIFY succeeds and the
    // node stops at BAD_OPCODE. Rust previously hashed the whole tail and
    // reported a signature failure first.
    let (pk, sk) = node.pq_keypair_from_seed(9, &[46; 32], 1312, 2560).unwrap();
    for tail in [vec![0x4c], vec![0x4c, 0x05, 0x01], vec![0x02, 0xab], vec![0xab, 0x4d, 0x05]] {
        let script = [push(&[vec![9], pk.clone()].concat()), vec![0xad], tail.clone()].concat();
        for mode in [0, 1] {
            // PQ_STRICT selects the signature rules this signer produces.
            for bits in [
                consensus_core::VERIFY_ALL_TIDECOIN,
                consensus_core::VERIFY_P2SH | consensus_core::VERIFY_PQ_STRICT,
            ] {
                // Legacy digests blank every scriptSig, so a placeholder suffices.
                let unsigned = script_case(mode, script.clone(), vec![vec![0; 8]], bits);
                let digest = node
                    .signature_hashes(
                        &tidecoin_consensus_encoding::encode_to_vec(&unsigned.tx),
                        0,
                        node_parity::SighashVersion::Legacy,
                        0,
                        &[(1, &script)],
                    )
                    .unwrap()[0];
                let mut sig = node.pq_sign_message(9, &digest, &sk, 2420, false).unwrap();
                sig.push(1);
                let case = script_case(mode, script.clone(), vec![sig], bits);
                compare(&node, &case);
                let spent = &case.spent[0];
                let original = node_script_result(node.verify_tx_input_with_spent_outputs(
                    &tidecoin_fuzz::differential::hex(&tidecoin_consensus_encoding::encode_to_vec(
                        &case.tx,
                    )),
                    0,
                    spent.script_pubkey.as_bytes(),
                    spent.amount.to_sat() as i64,
                    case.flags,
                    &[node_parity::SpentOutput {
                        amount: spent.amount.to_sat() as i64,
                        script_pubkey: spent.script_pubkey.as_bytes(),
                    }],
                ));
                assert_eq!(
                    original,
                    Err(node_parity::ScriptError::BadOpcode),
                    "tail={tail:02x?} mode={mode} flags={bits:#x}"
                );
            }
        }
    }
}
