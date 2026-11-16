// SPDX-License-Identifier: CC0-1.0
//! Source-derived activation and signature-rule matrices against pinned rc2.
use consensus_core::*;
use hashes::{hash160, sha256, sha512};
use node_parity::{NodeParityError, SpentOutput, TidecoinNodeHarness};
use primitives::{
    absolute::LockTime, opcodes::all, script::Builder, Amount, OutPoint, ScriptPubKeyBuf,
    ScriptSigBuf, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
};
const BASE: u32 = VERIFY_P2SH | VERIFY_WITNESS;
fn tx() -> Transaction {
    Transaction {
        version: TransactionVersion::TWO,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([7; 32]), vout: 0 },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            amount: Amount::ONE_SAT,
            script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0x51]),
        }],
    }
}
fn program(script: &[u8], v1: bool) -> Vec<u8> {
    if v1 {
        [vec![0x51, 64], sha512::Hash::hash(script).as_byte_array().to_vec()].concat()
    } else {
        [vec![0, 32], sha256::Hash::hash(script).as_byte_array().to_vec()].concat()
    }
}
fn lock_program(tx: &mut Transaction, program: &[u8], wrapped: bool) -> Vec<u8> {
    if wrapped {
        tx.inputs[0].script_sig = ScriptSigBuf::from_bytes(
            Builder::<()>::new().push_slice(program).into_script().into_bytes(),
        );
        Builder::<()>::new()
            .push_opcode(all::OP_HASH160)
            .push_slice(hash160::Hash::hash(program).to_byte_array())
            .push_opcode(all::OP_EQUAL)
            .into_script()
            .into_bytes()
    } else {
        tx.inputs[0].script_sig = ScriptSigBuf::new();
        program.to_vec()
    }
}
fn check(
    node: &TidecoinNodeHarness,
    tx: &Transaction,
    locking: &[u8],
    flags: u32,
    expected: Option<ScriptError>,
) {
    let out = TxOut {
        amount: Amount::from_sat_u32(1000),
        script_pubkey: ScriptPubKeyBuf::from_bytes(locking.to_vec()),
    };
    let rust = verify_script_input(
        tx,
        0,
        SpendContext::new(locking, Some(SpentOutputs::from_txouts(vec![out])), 1000, true),
        flags,
    );
    let encoded = encoding::encode_to_vec(tx);
    let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();
    let result = node.verify_tx_input_with_spent_outputs(
        &hex,
        0,
        locking,
        1000,
        flags,
        &[SpentOutput { amount: 1000, script_pubkey: locking }],
    );
    let actual = match result {
        Ok(()) => None,
        Err(NodeParityError::Script(e)) => Some(
            format!("{e:?}")
                .replace("UnknownError", "Unknown")
                .replace("Cleanstack", "CleanStack")
                .replace("CheckMultisig", "CheckMultiSig")
                .replace("P2sh", "P2SH"),
        ),
        other => panic!("{other:?}"),
    };
    assert_eq!(actual, expected.map(|e| format!("{e:?}")), "node flags={flags:x}");
    assert_eq!(
        rust,
        expected.map_or(Ok(()), |e| Err(TidecoinValidationError::Script(e))),
        "flags={flags:x}"
    );
}

#[test]
fn all_raw_hash_bytes_match_legacy_v0_consensus_and_relay_policy() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let (pk, sk) = node.pq_keypair_from_seed(9, &[45; 32], 1312, 2560).unwrap();
    let script = Builder::<()>::new()
        .push_slice([vec![9], pk].concat())
        .push_opcode(all::OP_CHECKSIG)
        .into_script();
    for witness in [false, true] {
        for byte in 0u32..=255 {
            let mut tx = tx();
            let mut cache = SighashCache::new(&tx);
            let digest = if witness {
                cache
                    .p2wsh_signature_hash_raw(
                        0,
                        script.as_bytes(),
                        Amount::from_sat_u32(1000),
                        byte,
                    )
                    .unwrap()
                    .to_byte_array()
            } else {
                cache.legacy_signature_hash(0, script.as_bytes(), byte).unwrap().to_byte_array()
            };
            let mut sig = node.pq_sign_message(9, &digest, &sk, 2420, false).unwrap();
            sig.push(byte as u8);
            let locking = if witness {
                tx.inputs[0].witness = Witness::from_slice(&[sig, script.as_bytes().to_vec()]);
                program(script.as_bytes(), false)
            } else {
                tx.inputs[0].script_sig = ScriptSigBuf::from_bytes(
                    Builder::<()>::new().push_slice(sig).into_script().into_bytes(),
                );
                script.as_bytes().to_vec()
            };
            check(&node, &tx, &locking, BASE | VERIFY_PQ_STRICT, None);
            let expected =
                TxSighashType::from_standard(byte).err().map(|_| ScriptError::SigHashType);
            check(
                &node,
                &tx,
                &locking,
                BASE | VERIFY_PQ_STRICT | VERIFY_DEFINED_HASHTYPE,
                expected,
            );
        }
    }
}

#[test]
fn hash_type_checks_precede_key_matching_and_cover_unreachable_multisig_arguments() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    for v1 in [false, true] {
        for multisig in [false, true] {
            let script: &[u8] =
                if multisig { &[0x52, 0, 0, 0x52, 0xae, 0x91] } else { &[0, 0xac, 0x91] };
            for byte in 0u32..=255 {
                let mut tx = tx();
                let mut items = if multisig {
                    vec![vec![], vec![1, byte as u8], vec![1, 1]]
                } else {
                    vec![vec![1, byte as u8]]
                };
                items.push(script.to_vec());
                tx.inputs[0].witness = Witness::from_slice(&items);
                let locking = program(script, v1);
                for policy in [0, VERIFY_DEFINED_HASHTYPE] {
                    let flags = BASE | VERIFY_WITNESS_V1_512 | policy;
                    let expected =
                        if (v1 || policy != 0) && TxSighashType::from_standard(byte).is_err() {
                            Some(ScriptError::SigHashType)
                        } else {
                            None
                        };
                    check(&node, &tx, &locking, flags, expected);
                }
            }
            // Empty signatures remain exempt under both v1 and relay restrictions.
            let mut tx = tx();
            let mut items = if multisig { vec![vec![], vec![], vec![]] } else { vec![vec![]] };
            items.push(script.to_vec());
            tx.inputs[0].witness = Witness::from_slice(&items);
            check(
                &node,
                &tx,
                &program(script, v1),
                BASE | VERIFY_WITNESS_V1_512 | VERIFY_DEFINED_HASHTYPE | VERIFY_NULLFAIL,
                None,
            );
        }
    }
}

#[test]
fn witness_activation_recognition_native_wrapped_and_independent_flags() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let p = program(&[0x51], true);
    for wrapped in [false, true] {
        for activation in [0, VERIFY_WITNESS_V1_512] {
            for pq in [0, VERIFY_PQ_STRICT] {
                for discourage in [0, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM] {
                    let flags = BASE | activation | pq | discourage;
                    let mut tx = tx();
                    let locking = lock_program(&mut tx, &p, wrapped);
                    tx.inputs[0].witness = Witness::from_slice(&[vec![0x51]]);
                    check(
                        &node,
                        &tx,
                        &locking,
                        flags,
                        if activation == 0 || wrapped {
                            Some(ScriptError::WitnessUnexpected)
                        } else {
                            None
                        },
                    );
                    tx.inputs[0].witness = Witness::new();
                    check(
                        &node,
                        &tx,
                        &locking,
                        flags,
                        if activation == 0 || wrapped {
                            None
                        } else {
                            Some(ScriptError::WitnessProgramWitnessEmpty)
                        },
                    );
                    // Before activation this is a normal script and extra stack data is allowed.
                    let mut bytes = vec![0x51];
                    bytes.extend_from_slice(tx.inputs[0].script_sig.as_bytes());
                    tx.inputs[0].script_sig = ScriptSigBuf::from_bytes(bytes);
                    check(
                        &node,
                        &tx,
                        &locking,
                        flags,
                        if activation == 0 || wrapped {
                            None
                        } else if wrapped {
                            Some(ScriptError::WitnessMalleatedP2SH)
                        } else {
                            Some(ScriptError::WitnessMalleated)
                        },
                    );
                }
            }
        }
    }
}

#[test]
fn scheme_authorization_and_v1_strictness_are_separate_rules() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
            for scheme in PqScheme::KNOWN {
                let (pk, sk) = node
                    .pq_keypair_from_seed(
                        scheme.prefix(),
                        &vec![46; scheme.deterministic_seed_len()],
                        scheme.pubkey_len(),
                        scheme.seckey_len(),
                    )
                    .unwrap();
                let script = Builder::<()>::new()
                    .push_slice([vec![scheme.prefix()], pk.clone()].concat())
                    .push_opcode(all::OP_CHECKSIG)
                    .into_script();
                for version in 0..3 {
                    for wrapped in [false, true] {
                        if version == 0 && wrapped {
                            continue;
                        }
                        for legacy in [false, true] {
                            if legacy && scheme != PqScheme::Falcon512 {
                                continue;
                            }
                            let mut tx = tx();
                            let locking = if version == 0 {
                                script.as_bytes().to_vec()
                            } else {
                                lock_program(
                                    &mut tx,
                                    &program(script.as_bytes(), version == 2),
                                    wrapped,
                                )
                            };
                            let out = TxOut {
                                amount: Amount::from_sat_u32(1000),
                                script_pubkey: ScriptPubKeyBuf::from_bytes(locking.clone()),
                            };
                            let mut cache = SighashCache::new_with_spent_outputs(
                                &tx,
                                SpentOutputs::from_txouts(vec![out]),
                            )
                            .unwrap();
                            let digest = match version {
                                0 => cache
                                    .legacy_signature_hash(0, script.as_bytes(), 1)
                                    .unwrap()
                                    .to_byte_array()
                                    .to_vec(),
                                1 => cache
                                    .p2wsh_signature_hash(
                                        0,
                                        script.as_bytes(),
                                        Amount::from_sat_u32(1000),
                                        TxSighashType::All,
                                    )
                                    .unwrap()
                                    .to_byte_array()
                                    .to_vec(),
                                _ => cache
                                    .p2wsh512_signature_hash(
                                        0,
                                        script.as_bytes(),
                                        Amount::from_sat_u32(1000),
                                        TxSighashType::All,
                                    )
                                    .unwrap()
                                    .to_byte_array()
                                    .to_vec(),
                            };
                            let mut sig = node
                                .pq_sign_message(
                                    scheme.prefix(),
                                    &digest,
                                    &sk,
                                    scheme.max_sig_len(),
                                    legacy,
                                )
                                .unwrap();
                            let raw_sig = sig.clone();
                            sig.push(1);
                            if version == 0 {
                                tx.inputs[0].script_sig = ScriptSigBuf::from_bytes(
                                    Builder::<()>::new().push_slice(sig).into_script().into_bytes(),
                                );
                            } else {
                                tx.inputs[0].witness =
                                    Witness::from_slice(&[sig, script.as_bytes().to_vec()]);
                            }
                            for strict in [false, true] {
                                let flags = BASE
                                    | VERIFY_WITNESS_V1_512
                                    | if strict { VERIFY_PQ_STRICT } else { 0 };
                                let eligible = strict || scheme == PqScheme::Falcon512;
                                let valid = eligible
                                    && node
                                        .pq_verify_message(
                                            scheme.prefix(),
                                            &digest,
                                            &raw_sig,
                                            &pk,
                                            !strict && version != 2,
                                        )
                                        .unwrap();
                                check(
                                    &node,
                                    &tx,
                                    &locking,
                                    flags,
                                    if version == 2 && wrapped {
                                        Some(ScriptError::WitnessUnexpected)
                                    } else if valid {
                                        None
                                    } else {
                                        Some(ScriptError::EvalFalse)
                                    },
                                );
                            }
                        }
                    }
                }
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn multisig_hash_type_and_nullfail_precede_nulldummy() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let script = [0x51, 0, 0x51, 0xae]; // 1-of-1 with an invalid key
    for hash_type in [1, 0x41] {
        let mut tx = tx();
        tx.inputs[0].witness = Witness::from_slice(&[vec![1], vec![1, hash_type], script.to_vec()]);
        let expected =
            if hash_type == 1 { ScriptError::NullFail } else { ScriptError::SigHashType };
        check(
            &node,
            &tx,
            &program(&script, true),
            BASE | VERIFY_WITNESS_V1_512 | VERIFY_NULLFAIL | VERIFY_NULLDUMMY,
            Some(expected),
        );
    }
    // CHECKSIG checks FindAndDelete before hash type; CHECKMULTISIG checks each
    // hash type before FindAndDelete. Both ordering rules are deliberate in rc2.
    for multisig in [false, true] {
        let sig = vec![1, 0x41];
        let mut builder = Builder::<()>::new().push_slice(sig.clone()).push_opcode(all::OP_DROP);
        builder = if multisig {
            builder
                .push_opcode(all::OP_PUSHNUM_1)
                .push_slice(Vec::<u8>::new())
                .push_opcode(all::OP_PUSHNUM_1)
                .push_opcode(all::OP_CHECKMULTISIG)
        } else {
            builder.push_slice(Vec::<u8>::new()).push_opcode(all::OP_CHECKSIG)
        };
        let script = builder.into_script();
        let mut tx = tx();
        let mut unlock = Builder::<()>::new();
        if multisig {
            unlock = unlock.push_slice(Vec::<u8>::new());
        }
        tx.inputs[0].script_sig =
            ScriptSigBuf::from_bytes(unlock.push_slice(sig).into_script().into_bytes());
        check(
            &node,
            &tx,
            script.as_bytes(),
            BASE | VERIFY_CONST_SCRIPTCODE | VERIFY_DEFINED_HASHTYPE,
            Some(if multisig { ScriptError::SigHashType } else { ScriptError::SigFindAndDelete }),
        );
    }
}

#[test]
fn legacy_falcon_size_and_v1_strictness_match_node_boundaries() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("data/rc2_falcon512_legacy_boundary.json")).unwrap();
    let decode = |value: &serde_json::Value| {
        let text = value.as_str().unwrap();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    for v1 in [false, true] {
        let vector = &vectors[if v1 { "v1" } else { "v0" }];
        let pk = decode(&vector["public_key"]);
        let mut sig = decode(&vector["signature"]);
        let message = decode(&vector["message"]);
        assert_eq!(sig.len(), 745);
        assert!(node.pq_verify_message(7, &message, &sig, &pk, true).unwrap());
        assert!(!node.pq_verify_message(7, &message, &sig, &pk, false).unwrap());
        let excess = &vectors[if v1 { "v1_excess_norm" } else { "v0_excess_norm" }];
        for legacy in [false, true] {
            assert!(!node
                .pq_verify_message(
                    7,
                    &message,
                    &decode(&excess["signature"]),
                    &decode(&excess["public_key"]),
                    legacy
                )
                .unwrap());
        }
        for malformed in [sig[..sig.len() - 1].to_vec(), [sig.clone(), vec![0]].concat()] {
            assert!(!node.pq_verify_message(7, &message, &malformed, &pk, true).unwrap());
        }
        let mut tx = tx();
        let locking = program(&[0xac], v1);
        let out = TxOut {
            amount: Amount::from_sat_u32(1000),
            script_pubkey: ScriptPubKeyBuf::from_bytes(locking.clone()),
        };
        let mut cache =
            SighashCache::new_with_spent_outputs(&tx, SpentOutputs::from_txouts(vec![out]))
                .unwrap();
        let calculated = if v1 {
            cache
                .p2wsh512_signature_hash(0, &[0xac], Amount::from_sat_u32(1000), TxSighashType::All)
                .unwrap()
                .to_byte_array()
                .to_vec()
        } else {
            cache
                .p2wsh_signature_hash(0, &[0xac], Amount::from_sat_u32(1000), TxSighashType::All)
                .unwrap()
                .to_byte_array()
                .to_vec()
        };
        assert_eq!(calculated, message);
        sig.push(1);
        tx.inputs[0].witness = Witness::from_slice(&[sig, [vec![7], pk].concat(), vec![0xac]]);
        for strict in [false, true] {
            let flags = BASE | VERIFY_WITNESS_V1_512 | if strict { VERIFY_PQ_STRICT } else { 0 };
            check(
                &node,
                &tx,
                &locking,
                flags,
                if v1 || strict { Some(ScriptError::EvalFalse) } else { None },
            );
        }
    }
}

#[test]
fn activation_preserves_ordinary_boolean_and_unknown_version_rules() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    // Original node script_witness_v1_512_activation: CLEANSTACK precedes
    // unexpected witness, and ordinary script boolean evaluation still runs.
    for wrapped in [false, true] {
        let mut tx = tx();
        let locking = lock_program(&mut tx, &program(&[0x51], true), wrapped);
        tx.inputs[0].witness = Witness::from_slice(&[vec![0x51]]);
        check(&node, &tx, &locking, BASE | VERIFY_CLEANSTACK, Some(ScriptError::CleanStack));
        check(
            &node,
            &tx,
            &locking,
            BASE | VERIFY_CLEANSTACK | VERIFY_WITNESS_V1_512,
            if wrapped { Some(ScriptError::CleanStack) } else { None },
        );
        tx.inputs[0].witness = Witness::from_slice(&[vec![0]]);
        check(
            &node,
            &tx,
            &locking,
            BASE | VERIFY_WITNESS_V1_512,
            Some(if wrapped {
                ScriptError::WitnessUnexpected
            } else {
                ScriptError::WitnessProgramMismatch
            }),
        );
    }
    for last in [0, 0x80] {
        let mut locking = vec![0x51, 64];
        locking.extend_from_slice(&[0; 64]);
        *locking.last_mut().unwrap() = last;
        let mut tx = tx();
        tx.inputs[0].witness = Witness::from_slice(&[vec![0x51]]);
        for activation in [0, VERIFY_WITNESS_V1_512] {
            check(&node, &tx, &locking, BASE | activation, Some(ScriptError::EvalFalse));
        }
    }
    for version in [1, 2, 16] {
        for length in [2, 20, 32, 40] {
            let mut locking = vec![0x50 + version, length];
            locking.extend(vec![1; length as usize]);
            for wrapped in [false, true] {
                let mut tx = tx();
                let locking = lock_program(&mut tx, &locking, wrapped);
                tx.inputs[0].witness = Witness::from_slice(&[vec![0x51]]);
                check(&node, &tx, &locking, BASE, None);
                check(
                    &node,
                    &tx,
                    &locking,
                    BASE | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
                    Some(ScriptError::DiscourageUpgradableWitnessProgram),
                );
                check(&node, &tx, &locking, BASE | VERIFY_WITNESS_V1_512, None);
            }
        }
    }
}

#[test]
fn falcon_padding_profiles_match_node_and_script_activation() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("data/rc2_falcon512_legacy_boundary.json")).unwrap();
    let decode = |value: &serde_json::Value| {
        let text = value.as_str().unwrap();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    for v1 in [false, true] {
        for scheme in [PqScheme::Falcon512, PqScheme::Falcon1024] {
            let key = match (v1, scheme) {
                (false, PqScheme::Falcon512) => "v0_strict",
                (true, PqScheme::Falcon512) => "v1_strict",
                (false, _) => "v0_falcon1024",
                (true, _) => "v1_falcon1024",
            };
            let vector = &vectors[key];
            let message = decode(&vector["message"]);
            let pk = decode(&vector["public_key"]);
            let sig = decode(&vector["signature"]);
            let padded = if scheme == PqScheme::Falcon512 { 666 } else { 1280 };
            let prefixed = [vec![scheme.prefix()], pk.clone()].concat();
            let public_key = PqPublicKey::from_prefixed_slice(&prefixed).unwrap();
            for size in [sig.len(), sig.len() + 1, padded - 1, padded, padded + 1] {
                let mut candidate = sig.clone();
                candidate.resize(size, 0);
                for legacy in [false, true] {
                    let expected = size == sig.len();
                    assert_eq!(
                        node.pq_verify_message(scheme.prefix(), &message, &candidate, &pk, legacy)
                            .unwrap(),
                        expected,
                        "node scheme={scheme:?}, size={size}, legacy={legacy}"
                    );
                    let signature = PqSignature::from_slice(&candidate);
                    let result = if v1 {
                        let msg = message.as_slice().try_into().unwrap();
                        if legacy {
                            signature.verify_msg64_legacy(msg, &public_key)
                        } else {
                            signature.verify_msg64(msg, &public_key)
                        }
                    } else {
                        let msg = message.as_slice().try_into().unwrap();
                        if legacy {
                            signature.verify_msg32_legacy(msg, &public_key)
                        } else {
                            signature.verify_msg32(msg, &public_key)
                        }
                    };
                    assert_eq!(
                        result.is_ok(),
                        expected,
                        "Rust scheme={scheme:?}, size={size}, legacy={legacy}"
                    );
                }
                let mut tx = tx();
                let locking = program(&[0xac], v1);
                candidate.push(1);
                tx.inputs[0].witness =
                    Witness::from_slice(&[candidate, prefixed.clone(), vec![0xac]]);
                for strict in [false, true] {
                    let valid = (strict || scheme == PqScheme::Falcon512) && size == sig.len();
                    check(
                        &node,
                        &tx,
                        &locking,
                        BASE | VERIFY_WITNESS_V1_512 | if strict { VERIFY_PQ_STRICT } else { 0 },
                        if valid { None } else { Some(ScriptError::EvalFalse) },
                    );
                }
            }
        }
    }
}

// Locate coefficient signs and the unused tail in an independently generated
// original-node signature. This is test data mutation, not a second verifier.
fn falcon_encoding_positions(signature: &[u8]) -> (Vec<usize>, usize) {
    let mut pos = 41 * 8;
    let mut zeros = Vec::new();
    let bit = |p: usize| (signature[p / 8] >> (7 - p % 8)) & 1;
    for _ in 0..512 {
        let sign = pos;
        pos += 1;
        let mut value = 0;
        for _ in 0..7 {
            value = value * 2 + usize::from(bit(pos));
            pos += 1;
        }
        while bit(pos) == 0 {
            value += 128;
            pos += 1;
        }
        pos += 1;
        if value == 0 {
            zeros.push(sign);
        }
    }
    (zeros, pos)
}

#[test]
fn rc3_legacy_falcon_encoding_and_crypto_match_original_node() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let (pk, sk) = node
        .pq_keypair_from_seed(
            7,
            &vec![91; primitives::PqScheme::Falcon512.deterministic_seed_len()],
            897,
            1281,
        )
        .unwrap();
    let mut message = [27; 32];
    let mut selected = None;
    for attempt in 0..128 {
        message[0] = attempt;
        let sig = node.pq_sign_message(7, &message, &sk, 1462, true).unwrap();
        let (zeros, end) = falcon_encoding_positions(&sig);
        if !zeros.is_empty() && end % 8 != 0 {
            selected = Some((sig, zeros, end));
            break;
        }
    }
    let (sig, zeros, end) =
        selected.expect("original signer produces zero coefficients and unused tail bits");
    let key = PqPublicKey::from_scheme_and_bytes(primitives::PqScheme::Falcon512, &pk).unwrap();
    let mut cases = vec![(sig.clone(), false, true)];
    for sign in zeros {
        let mut bytes = sig.clone();
        bytes[sign / 8] |= 1 << (7 - sign % 8);
        cases.push((bytes, true, true));
    }
    for tail in 1..(1u8 << (8 - end % 8)) {
        let mut bytes = sig.clone();
        *bytes.last_mut().unwrap() |= tail;
        cases.push((bytes, true, true));
    }
    let mut combined = cases[1].0.clone();
    *combined.last_mut().unwrap() |= 1;
    cases.push((combined, true, true));
    cases.push(([cases[1].0.clone(), vec![0]].concat(), false, false));
    cases.push((sig[..sig.len() - 1].to_vec(), false, false));
    let mut overflow = sig.clone();
    overflow[41..44].fill(0);
    cases.push((overflow, false, false));
    let mut header = sig.clone();
    header[0] = 0x3a;
    cases.push((header, false, false));
    let requests = cases.iter().map(|(b,_,_)| serde_json::json!({"op":"falcon_encoding", "bytes":b.iter().map(|x|format!("{x:02x}")).collect::<String>()})).collect::<Vec<_>>();
    for ((bytes, noncanonical, valid), result) in
        cases.iter().zip(node_parity::validation::run(&requests).unwrap())
    {
        assert_eq!(result["valid"], *noncanonical);
        assert_eq!(is_noncanonical_legacy_falcon512(bytes), *noncanonical);
        assert_eq!(node.pq_verify_message(7, &message, bytes, &pk, true).unwrap(), *valid);
        let signature = PqSignature::from_slice(bytes);
        assert_eq!(signature.verify_msg32_legacy(&message, &key).is_ok(), *valid);
        assert_eq!(signature.verify_msg32_allow_legacy(&message, &key).is_ok(), *valid);
        assert_eq!(
            signature.verify_msg32(&message, &key).is_ok(),
            node.pq_verify_message(7, &message, bytes, &pk, false).unwrap()
        );
    }
}

#[test]
fn rc3_relay_encoding_checks_run_before_crypto_and_all_multisig_arguments() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    // 512 compressed zero coefficients, with the first encoded as negative zero.
    let mut sig = vec![0x39];
    sig.extend([0; 40]);
    sig.extend([0; 576]);
    for i in 0..512 {
        let p = i * 9 + 8;
        sig[41 + p / 8] |= 1 << (7 - p % 8);
    }
    sig[41] |= 0x80;
    assert!(is_noncanonical_legacy_falcon512(&sig));
    for multisig in [false, true] {
        for hashtype in [1, 0] {
            let mut signature = sig.clone();
            signature.push(hashtype);
            // Empty key forces cryptographic failure. MULTISIG has more
            // signatures than keys remaining after the first failure, so its
            // second argument must be checked before the verification loop.
            let script =
                if multisig { vec![0x52, 0, 0, 0x52, 0xae, 0x91] } else { vec![0, 0xac, 0x91] };
            let mut tx = tx();
            let locking = program(&script, false);
            let items = if multisig {
                vec![vec![], vec![], signature, script]
            } else {
                vec![signature, script]
            };
            tx.inputs[0].witness = Witness::from_slice(&items);
            for canonical in [0, VERIFY_FALCON_CANONICAL] {
                for strict in [0, VERIFY_PQ_STRICT] {
                    let expected = if hashtype == 0 {
                        Some(ScriptError::SigHashType)
                    } else if canonical != 0 && strict == 0 {
                        Some(ScriptError::SigFalconEncoding)
                    } else {
                        None
                    };
                    check(
                        &node,
                        &tx,
                        &locking,
                        BASE | VERIFY_DEFINED_HASHTYPE | canonical | strict,
                        expected,
                    );
                }
            }
        }
    }
}
