use consensus::{
    verify_with_flags_detailed, ScriptError as RustScriptError, ScriptFailure, VERIFY_NULLDUMMY,
    VERIFY_NULLFAIL, VERIFY_P2SH, VERIFY_PQ_STRICT, VERIFY_WITNESS,
};
use consensus_core::{PqPublicKey, PqScheme, SighashCache, TxSighashType};
use encoding::encode_to_vec;
use hashes::{hash160, sha256};
use primitives::{
    absolute::LockTime,
    opcodes::all,
    script::{Builder as BuilderT, ScriptBuf as PrimitiveScriptBuf, ScriptPubKeyBuf, ScriptSigBuf},
    Amount, OutPoint, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Witness,
};

mod tidecoin_test_support;

use tidecoin_test_support::{
    map_rust_script_error, node_script_result, normalize_flags, try_harness,
};

type Builder = BuilderT<()>;
type ScriptBuf = PrimitiveScriptBuf<()>;

fn sat(value: u64) -> Amount {
    Amount::from_sat(value).expect("test amount in range")
}

fn deterministic_seed(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|idx| tag.wrapping_add(idx as u8)).collect()
}

fn seed_len(scheme: PqScheme) -> usize {
    match scheme {
        PqScheme::Falcon512 | PqScheme::Falcon1024 => 48,
        PqScheme::MlDsa44 | PqScheme::MlDsa65 | PqScheme::MlDsa87 => 32,
    }
}

fn seckey_len(scheme: PqScheme) -> usize {
    match scheme {
        PqScheme::Falcon512 => 1281,
        PqScheme::Falcon1024 => 2305,
        PqScheme::MlDsa44 => 2560,
        PqScheme::MlDsa65 => 4032,
        PqScheme::MlDsa87 => 4896,
    }
}

fn deterministic_keypair(
    harness: &node_parity::TidecoinNodeHarness,
    scheme: PqScheme,
    tag: u8,
) -> (PqPublicKey, Vec<u8>) {
    let seed = deterministic_seed(tag, seed_len(scheme));
    let (pk, sk) = harness
        .pq_keypair_from_seed(scheme.prefix(), &seed, scheme.pubkey_len(), seckey_len(scheme))
        .unwrap_or_else(|e| panic!("node PQ keygen failed for {scheme:?}: {e}"));
    let mut prefixed_pk = Vec::with_capacity(pk.len() + 1);
    prefixed_pk.push(scheme.prefix());
    prefixed_pk.extend_from_slice(&pk);
    let pk = PqPublicKey::from_prefixed_slice(&prefixed_pk).expect("valid prefixed public key");
    (pk, sk)
}

fn multisig_witness_script(pubkeys: &[PqPublicKey], m: i32) -> ScriptBuf {
    let mut builder = Builder::new().push_int(m).expect("valid multisig threshold");
    for pubkey in pubkeys {
        let mut prefixed = Vec::with_capacity(pubkey.as_bytes().len() + 1);
        prefixed.push(pubkey.scheme().prefix());
        prefixed.extend_from_slice(pubkey.as_bytes());
        builder = builder.push_slice(prefixed);
    }
    builder
        .push_int(pubkeys.len() as i32)
        .expect("valid pubkey count")
        .push_opcode(all::OP_CHECKMULTISIG)
        .into_script()
}

fn direct_p2wsh_script_pubkey(witness_script: &ScriptBuf) -> ScriptBuf {
    let program = sha256::Hash::hash(witness_script.as_bytes());
    Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(program.to_byte_array())
        .into_script()
}

fn wrapped_p2wsh(witness_script: &ScriptBuf) -> (ScriptBuf, ScriptBuf) {
    let redeem_script = direct_p2wsh_script_pubkey(witness_script);
    let redeem_hash = hash160::Hash::hash(redeem_script.as_bytes());
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_HASH160)
        .push_slice(redeem_hash.to_byte_array())
        .push_opcode(all::OP_EQUAL)
        .into_script();
    let script_sig = Builder::new().push_slice(redeem_script.as_bytes()).into_script();
    (script_pubkey, script_sig)
}

fn synthetic_spend_tx(
    script_pubkey: &ScriptBuf,
    script_sig: ScriptBuf,
    witness: Witness,
    amount: Amount,
) -> Transaction {
    let credit_tx = Transaction {
        version: TransactionVersion::ONE,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE_PREVOUT,
            script_sig: ScriptSigBuf::from(
                Builder::new()
                    .push_int(0)
                    .expect("push zero")
                    .push_int(0)
                    .expect("push zero")
                    .into_script()
                    .into_bytes(),
            ),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            amount,
            script_pubkey: ScriptPubKeyBuf::from_bytes(script_pubkey.as_bytes().to_vec()),
        }],
    };
    Transaction {
        version: TransactionVersion::ONE,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: credit_tx.compute_txid(), vout: 0 },
            script_sig: ScriptSigBuf::from(script_sig.into_bytes()),
            sequence: Sequence::MAX,
            witness,
        }],
        outputs: vec![TxOut { amount, script_pubkey: ScriptPubKeyBuf::new() }],
    }
}

#[allow(clippy::too_many_arguments)]
fn witness_v0_sig(
    harness: &node_parity::TidecoinNodeHarness,
    tx: &Transaction,
    input_index: usize,
    amount: Amount,
    witness_script: &ScriptBuf,
    scheme: PqScheme,
    secret_key: &[u8],
    legacy: bool,
) -> Vec<u8> {
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .p2wsh_signature_hash(input_index, witness_script.as_bytes(), amount, TxSighashType::All)
        .expect("witness-v0 sighash");
    let legacy = legacy && scheme == PqScheme::Falcon512;
    let mut sig = harness
        .pq_sign_message(
            scheme.prefix(),
            sighash.as_byte_array(),
            secret_key,
            scheme.max_sig_len(),
            legacy,
        )
        .unwrap_or_else(|e| panic!("node PQ sign failed for {scheme:?}: {e}"));
    sig.push(TxSighashType::All.to_u32() as u8);
    sig
}

fn signed_multisig_witness(
    harness: &node_parity::TidecoinNodeHarness,
    tx: &Transaction,
    amount: Amount,
    witness_script: &ScriptBuf,
    signers: &[(PqScheme, Vec<u8>)],
    legacy: bool,
) -> Witness {
    let mut items = Vec::with_capacity(signers.len() + 2);
    items.push(Vec::new());
    for (scheme, secret_key) in signers {
        items.push(witness_v0_sig(
            harness,
            tx,
            0,
            amount,
            witness_script,
            *scheme,
            secret_key,
            legacy,
        ));
    }
    items.push(witness_script.as_bytes().to_vec());
    Witness::from_slice(&items)
}

#[allow(clippy::too_many_arguments)]
fn assert_case(
    harness: &node_parity::TidecoinNodeHarness,
    script_pubkey: &ScriptBuf,
    script_sig: &ScriptBuf,
    witness: &Witness,
    amount: Amount,
    flags: u32,
    expect_ok: bool,
    context: &str,
) -> Result<(), ScriptFailure> {
    let flags = normalize_flags(flags);
    let tx = synthetic_spend_tx(script_pubkey, script_sig.clone(), witness.clone(), amount);
    let tx_bytes = encode_to_vec(&tx);
    let ours = verify_with_flags_detailed(
        script_pubkey.as_bytes(),
        amount.to_sat(),
        &tx_bytes,
        None,
        0,
        flags,
    );

    let witness_refs: Vec<&[u8]> = witness.iter().collect();
    let node = node_script_result(harness.verify_script_case(
        script_sig.as_bytes(),
        script_pubkey.as_bytes(),
        &witness_refs,
        amount.to_sat() as i64,
        flags,
    ));
    match (&ours, node) {
        (Ok(()), Ok(())) => {}
        (Err(failure), Err(node_err)) => {
            let ours_err = map_rust_script_error(failure.script_error);
            assert_eq!(ours_err, node_err, "{context}: node/runtime script error mismatch");
        }
        (lhs, rhs) => {
            panic!("{context}: node/runtime acceptance mismatch: ours={lhs:?} node={rhs:?}")
        }
    }

    assert_eq!(ours.is_ok(), expect_ok, "{context}: unexpected local result: {ours:?}");
    ours
}

#[test]
fn tidecoin_pq_multisig_single_scheme_matrix_matches_node() {
    let Some(harness) = try_harness() else {
        eprintln!("skipping Tidecoin PQ multisig parity: TIDECOIN_NODE_REPO is not configured");
        return;
    };

    let flags = VERIFY_WITNESS | VERIFY_P2SH;
    let cases = [(1usize, 1usize), (2, 3), (3, 5), (15, 15), (20, 20)];

    for scheme in [
        PqScheme::Falcon512,
        PqScheme::Falcon1024,
        PqScheme::MlDsa44,
        PqScheme::MlDsa65,
        PqScheme::MlDsa87,
    ] {
        for (m, n) in cases {
            let keys: Vec<(PqPublicKey, Vec<u8>)> = (0..n)
                .map(|idx| deterministic_keypair(&harness, scheme, (0x10 + n + idx) as u8))
                .collect();
            let pubkeys: Vec<PqPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
            let signers: Vec<(PqScheme, Vec<u8>)> =
                keys.iter().take(m).map(|(pk, sk)| (pk.scheme(), sk.clone())).collect();
            let witness_script = multisig_witness_script(&pubkeys, m as i32);
            let amount = sat(1);

            for wrap in [false, true] {
                let (script_pubkey, script_sig) = if wrap {
                    wrapped_p2wsh(&witness_script)
                } else {
                    (direct_p2wsh_script_pubkey(&witness_script), ScriptBuf::new())
                };
                let unsigned_tx =
                    synthetic_spend_tx(&script_pubkey, script_sig.clone(), Witness::new(), amount);
                let witness = signed_multisig_witness(
                    &harness,
                    &unsigned_tx,
                    amount,
                    &witness_script,
                    &signers,
                    true,
                );
                assert_case(
                    &harness,
                    &script_pubkey,
                    &script_sig,
                    &witness,
                    amount,
                    flags,
                    true,
                    &format!("single-scheme multisig {scheme:?} {m}-of-{n} wrap={wrap}"),
                )
                .expect("single-scheme multisig should verify");
            }
        }
    }
}

#[test]
fn tidecoin_pq_multisig_mixed_scheme_direct_and_wrapped_match_node() {
    let Some(harness) = try_harness() else {
        eprintln!("skipping Tidecoin PQ multisig parity: TIDECOIN_NODE_REPO is not configured");
        return;
    };

    let keys = [
        deterministic_keypair(&harness, PqScheme::Falcon512, 0x80),
        deterministic_keypair(&harness, PqScheme::MlDsa44, 0x81),
        deterministic_keypair(&harness, PqScheme::MlDsa87, 0x82),
    ];
    let pubkeys: Vec<PqPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
    let signers =
        vec![(keys[0].0.scheme(), keys[0].1.clone()), (keys[1].0.scheme(), keys[1].1.clone())];
    let witness_script = multisig_witness_script(&pubkeys, 2);
    let amount = sat(1);

    for wrap in [false, true] {
        let (script_pubkey, script_sig) = if wrap {
            wrapped_p2wsh(&witness_script)
        } else {
            (direct_p2wsh_script_pubkey(&witness_script), ScriptBuf::new())
        };
        let unsigned_tx =
            synthetic_spend_tx(&script_pubkey, script_sig.clone(), Witness::new(), amount);
        let witness = signed_multisig_witness(
            &harness,
            &unsigned_tx,
            amount,
            &witness_script,
            &signers,
            true,
        );
        assert_case(
            &harness,
            &script_pubkey,
            &script_sig,
            &witness,
            amount,
            VERIFY_WITNESS | VERIFY_P2SH,
            true,
            &format!("mixed-scheme multisig wrap={wrap}"),
        )
        .expect("mixed-scheme multisig should verify");
    }
}

#[test]
fn tidecoin_pq_multisig_negative_and_limit_cases_match_node() {
    let Some(harness) = try_harness() else {
        eprintln!("skipping Tidecoin PQ multisig parity: TIDECOIN_NODE_REPO is not configured");
        return;
    };

    let keys = [
        deterministic_keypair(&harness, PqScheme::Falcon512, 0x21),
        deterministic_keypair(&harness, PqScheme::Falcon512, 0x22),
        deterministic_keypair(&harness, PqScheme::Falcon512, 0x23),
    ];
    let pubkeys: Vec<PqPublicKey> = keys.iter().map(|(pk, _)| pk.clone()).collect();
    let witness_script = multisig_witness_script(&pubkeys, 2);
    let script_pubkey = direct_p2wsh_script_pubkey(&witness_script);
    let amount = sat(1);
    let unsigned_tx = synthetic_spend_tx(&script_pubkey, ScriptBuf::new(), Witness::new(), amount);
    let good_sig1 = witness_v0_sig(
        &harness,
        &unsigned_tx,
        0,
        amount,
        &witness_script,
        keys[0].0.scheme(),
        &keys[0].1,
        true,
    );
    let good_sig2 = witness_v0_sig(
        &harness,
        &unsigned_tx,
        0,
        amount,
        &witness_script,
        keys[1].0.scheme(),
        &keys[1].1,
        true,
    );
    let outsider = deterministic_keypair(&harness, PqScheme::Falcon512, 0x31);
    let outsider_sig = witness_v0_sig(
        &harness,
        &unsigned_tx,
        0,
        amount,
        &witness_script,
        outsider.0.scheme(),
        &outsider.1,
        true,
    );

    let missing_sig = Witness::from_slice(&[
        Vec::<u8>::new(),
        good_sig1.clone(),
        Vec::<u8>::new(),
        witness_script.as_bytes().to_vec(),
    ]);
    let missing_failure = assert_case(
        &harness,
        &script_pubkey,
        &ScriptBuf::new(),
        &missing_sig,
        amount,
        VERIFY_WITNESS | VERIFY_P2SH,
        false,
        "multisig missing one signature",
    )
    .expect_err("missing multisig signature should fail");
    assert_eq!(missing_failure.script_error, RustScriptError::EvalFalse);

    let wrong_order = Witness::from_slice(&[
        Vec::<u8>::new(),
        good_sig2.clone(),
        good_sig1.clone(),
        witness_script.as_bytes().to_vec(),
    ]);
    let wrong_order_failure = assert_case(
        &harness,
        &script_pubkey,
        &ScriptBuf::new(),
        &wrong_order,
        amount,
        VERIFY_WITNESS | VERIFY_P2SH,
        false,
        "multisig wrong signature order",
    )
    .expect_err("wrong signature order should fail");
    assert_eq!(wrong_order_failure.script_error, RustScriptError::EvalFalse);

    let outsider_witness = Witness::from_slice(&[
        Vec::<u8>::new(),
        outsider_sig,
        good_sig2.clone(),
        witness_script.as_bytes().to_vec(),
    ]);
    let outsider_failure = assert_case(
        &harness,
        &script_pubkey,
        &ScriptBuf::new(),
        &outsider_witness,
        amount,
        VERIFY_WITNESS | VERIFY_P2SH,
        false,
        "multisig outsider signature",
    )
    .expect_err("outsider signature should fail");
    assert_eq!(outsider_failure.script_error, RustScriptError::EvalFalse);

    let mut wrong_sighash = good_sig1;
    *wrong_sighash.last_mut().unwrap() = TxSighashType::None.to_u32() as u8;
    let wrong_sighash_witness = Witness::from_slice(&[
        Vec::<u8>::new(),
        wrong_sighash,
        good_sig2,
        witness_script.as_bytes().to_vec(),
    ]);
    assert_case(
        &harness,
        &script_pubkey,
        &ScriptBuf::new(),
        &wrong_sighash_witness,
        amount,
        VERIFY_WITNESS | VERIFY_P2SH,
        false,
        "multisig wrong sighash byte",
    )
    .expect_err("wrong sighash byte should fail");
    let zero_script = multisig_witness_script(&[], 0);
    let zero_spk = direct_p2wsh_script_pubkey(&zero_script);
    let zero_witness = Witness::from_slice(&[Vec::<u8>::new(), zero_script.as_bytes().to_vec()]);
    assert_case(
        &harness,
        &zero_spk,
        &ScriptBuf::new(),
        &zero_witness,
        amount,
        VERIFY_WITNESS | VERIFY_P2SH,
        true,
        "0-of-0 multisig witness",
    )
    .expect("0-of-0 multisig should pass");

    let too_many_pubkeys: Vec<PqPublicKey> = (0..21)
        .map(|idx| deterministic_keypair(&harness, PqScheme::Falcon512, 0x60 + idx).0)
        .collect();
    let too_many_script = multisig_witness_script(&too_many_pubkeys, 21);
    let too_many_spk = direct_p2wsh_script_pubkey(&too_many_script);
    let mut too_many_items = vec![Vec::new()];
    too_many_items.extend((0..21).map(|_| vec![0u8]));
    too_many_items.push(too_many_script.as_bytes().to_vec());
    let too_many_witness = Witness::from_slice(&too_many_items);
    let too_many_failure = assert_case(
        &harness,
        &too_many_spk,
        &ScriptBuf::new(),
        &too_many_witness,
        amount,
        VERIFY_WITNESS | VERIFY_P2SH,
        false,
        "multisig pubkey-count limit",
    )
    .expect_err("too many pubkeys should fail");
    assert_eq!(too_many_failure.script_error, RustScriptError::PubkeyCount);

    let limit_keys = [
        deterministic_keypair(&harness, PqScheme::MlDsa87, 0x40),
        deterministic_keypair(&harness, PqScheme::MlDsa87, 0x41),
    ];
    let limit_pubkeys: Vec<PqPublicKey> = limit_keys.iter().map(|(pk, _)| pk.clone()).collect();
    let limit_script = multisig_witness_script(&limit_pubkeys, 1);
    let limit_spk = direct_p2wsh_script_pubkey(&limit_script);
    let limit_tx = synthetic_spend_tx(&limit_spk, ScriptBuf::new(), Witness::new(), amount);
    let mut limit_items = signed_multisig_witness(
        &harness,
        &limit_tx,
        amount,
        &limit_script,
        &[(limit_keys[0].0.scheme(), limit_keys[0].1.clone())],
        true,
    )
    .to_vec();
    limit_items[1] = vec![0x42; 8193];
    let limit_witness = Witness::from_slice(&limit_items);
    let limit_failure = assert_case(
        &harness,
        &limit_spk,
        &ScriptBuf::new(),
        &limit_witness,
        amount,
        VERIFY_WITNESS | VERIFY_P2SH,
        false,
        "multisig push-size limit",
    )
    .expect_err("oversized signature push should fail");
    assert_eq!(limit_failure.script_error, RustScriptError::PushSize);
}

#[test]
fn tidecoin_pq_multisig_nulldummy_nullfail_and_strict_match_node() {
    let Some(harness) = try_harness() else {
        eprintln!("skipping Tidecoin PQ multisig parity: TIDECOIN_NODE_REPO is not configured");
        return;
    };

    let key = deterministic_keypair(&harness, PqScheme::Falcon512, 0x51);
    let outsider = deterministic_keypair(&harness, PqScheme::Falcon512, 0x61);
    let pubkeys = vec![key.0.clone()];
    let witness_script = multisig_witness_script(&pubkeys, 1);
    let script_pubkey = direct_p2wsh_script_pubkey(&witness_script);
    let amount = sat(1);
    let unsigned_tx = synthetic_spend_tx(&script_pubkey, ScriptBuf::new(), Witness::new(), amount);

    let legacy_sig = witness_v0_sig(
        &harness,
        &unsigned_tx,
        0,
        amount,
        &witness_script,
        key.0.scheme(),
        &key.1,
        true,
    );
    let outsider_sig = witness_v0_sig(
        &harness,
        &unsigned_tx,
        0,
        amount,
        &witness_script,
        outsider.0.scheme(),
        &outsider.1,
        true,
    );

    let nulldummy_witness =
        Witness::from_slice(&[vec![1u8], legacy_sig.clone(), witness_script.as_bytes().to_vec()]);
    let nulldummy_failure = assert_case(
        &harness,
        &script_pubkey,
        &ScriptBuf::new(),
        &nulldummy_witness,
        amount,
        VERIFY_WITNESS | VERIFY_P2SH | VERIFY_NULLDUMMY,
        false,
        "multisig NULLDUMMY",
    )
    .expect_err("non-zero multisig dummy should fail");
    assert_eq!(nulldummy_failure.script_error, RustScriptError::SigNullDummy);

    let nullfail_script = Builder::new()
        .push_int(1)
        .expect("threshold")
        .push_slice({
            let mut prefixed = vec![key.0.scheme().prefix()];
            prefixed.extend_from_slice(key.0.as_bytes());
            prefixed
        })
        .push_int(1)
        .expect("pubkey count")
        .push_opcode(all::OP_CHECKMULTISIG)
        .push_opcode(all::OP_NOT)
        .into_script();
    let nullfail_spk = direct_p2wsh_script_pubkey(&nullfail_script);
    let nullfail_witness =
        Witness::from_slice(&[Vec::<u8>::new(), outsider_sig, nullfail_script.as_bytes().to_vec()]);
    let nullfail_failure = assert_case(
        &harness,
        &nullfail_spk,
        &ScriptBuf::new(),
        &nullfail_witness,
        amount,
        VERIFY_WITNESS | VERIFY_P2SH | VERIFY_NULLFAIL,
        false,
        "multisig NULLFAIL",
    )
    .expect_err("failing non-empty multisig signatures should trigger NULLFAIL");
    assert_eq!(nullfail_failure.script_error, RustScriptError::NullFail);

    let strict_sig = witness_v0_sig(
        &harness,
        &unsigned_tx,
        0,
        amount,
        &witness_script,
        key.0.scheme(),
        &key.1,
        false,
    );
    assert_case(
        &harness,
        &script_pubkey,
        &ScriptBuf::new(),
        &Witness::from_slice(&[Vec::<u8>::new(), strict_sig, witness_script.as_bytes().to_vec()]),
        amount,
        VERIFY_WITNESS | VERIFY_P2SH | VERIFY_PQ_STRICT,
        true,
        "multisig PQ_STRICT accepts strict Falcon512",
    )
    .expect("strict Falcon512 signature should verify");
}
