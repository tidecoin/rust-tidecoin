use consensus::{verify_with_flags_detailed, ScriptFailure, VERIFY_P2SH, VERIFY_WITNESS};
use hashes::{hash160, sha256};
use primitives::{
    opcodes::all,
    script::{Builder as BuilderT, ScriptBuf as PrimitiveScriptBuf},
    Amount, Witness,
};

mod tidecoin_test_support;

use tidecoin_test_support::{
    build_test_transaction, map_rust_script_error, node_script_result, normalize_flags, try_harness,
};

type Builder = BuilderT<()>;
type ScriptBuf = PrimitiveScriptBuf<()>;

fn sat(value: u64) -> Amount {
    Amount::from_sat(value).expect("test amount in range")
}

fn p2sh_script_pubkey(redeem_script: &ScriptBuf) -> ScriptBuf {
    let redeem_hash = hash160::Hash::hash(redeem_script.as_bytes());
    Builder::new()
        .push_opcode(all::OP_HASH160)
        .push_slice(redeem_hash.to_byte_array())
        .push_opcode(all::OP_EQUAL)
        .into_script()
}

#[allow(clippy::too_many_arguments)]
fn assert_case(
    harness: &Option<node_parity::TidecoinNodeHarness>,
    script_sig: &ScriptBuf,
    script_pubkey: &ScriptBuf,
    witness: &Witness,
    amount: Amount,
    flags: u32,
    expect_ok: bool,
    context: &str,
) -> Result<(), ScriptFailure> {
    let mut flags = normalize_flags(flags);
    if flags & VERIFY_WITNESS != 0 {
        flags |= VERIFY_P2SH;
    }
    let witness_items: Vec<Vec<u8>> = witness.iter().map(|item| item.to_vec()).collect();
    let tx_bytes = build_test_transaction(
        script_pubkey.as_bytes(),
        script_sig.as_bytes(),
        &witness_items,
        amount.to_sat(),
    );
    let ours = verify_with_flags_detailed(
        script_pubkey.as_bytes(),
        amount.to_sat(),
        &tx_bytes,
        None,
        0,
        flags,
    );

    let witness_refs: Vec<&[u8]> = witness.iter().collect();
    if let Some(harness) = harness {
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
    }

    assert_eq!(ours.is_ok(), expect_ok, "{context}: unexpected local result: {ours:?}");
    ours
}

#[test]
fn tidecoin_witness_wrapped_program_detection_surface() {
    let harness = try_harness();
    let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
    let witness_program = sha256::Hash::hash(witness_script.as_bytes());
    let redeem_script = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(witness_program.to_byte_array())
        .into_script();
    let spent_script = p2sh_script_pubkey(&redeem_script);
    let amount = sat(1_000);

    let with_redeem = assert_case(
        &harness,
        &Builder::new().push_slice(redeem_script.as_bytes()).into_script(),
        &spent_script,
        &Witness::new(),
        amount,
        VERIFY_P2SH | VERIFY_WITNESS,
        false,
        "wrapped witness spend with redeem script but empty witness",
    )
    .expect_err("wrapped witness spends require witness stack");
    assert_eq!(with_redeem.script_error, consensus::ScriptError::WitnessProgramWitnessEmpty);

    let without_redeem = assert_case(
        &harness,
        &ScriptBuf::new(),
        &spent_script,
        &Witness::new(),
        amount,
        VERIFY_P2SH | VERIFY_WITNESS,
        false,
        "wrapped witness spend without redeem script",
    )
    .expect_err("without redeem script there is no wrapped witness dispatch");
    assert_eq!(without_redeem.script_error, consensus::ScriptError::InvalidStackOperation);
}

#[test]
fn tidecoin_witness_wrong_length_empty_and_mismatch_cases() {
    let harness = try_harness();
    let amount = sat(50_000);

    let wrong_len =
        Builder::new().push_opcode(all::OP_PUSHBYTES_0).push_slice([1u8; 5]).into_script();
    let wrong_len_err = assert_case(
        &harness,
        &ScriptBuf::new(),
        &wrong_len,
        &Witness::new(),
        amount,
        VERIFY_WITNESS,
        false,
        "witness program wrong length",
    )
    .expect_err("invalid witness length fails");
    assert_eq!(wrong_len_err.script_error, consensus::ScriptError::WitnessProgramWrongLength);

    let empty_stack =
        Builder::new().push_opcode(all::OP_PUSHBYTES_0).push_slice([1u8; 32]).into_script();
    let empty_err = assert_case(
        &harness,
        &ScriptBuf::new(),
        &empty_stack,
        &Witness::new(),
        amount,
        VERIFY_WITNESS,
        false,
        "missing witness stack",
    )
    .expect_err("missing witness stack fails");
    assert_eq!(empty_err.script_error, consensus::ScriptError::WitnessProgramWitnessEmpty);

    let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
    let p2wsh_program = sha256::Hash::hash(witness_script.as_bytes());
    let p2wsh = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(p2wsh_program.to_byte_array())
        .into_script();
    let wrong_script = Builder::new().push_opcode(all::OP_PUSHNUM_2).into_script();
    let p2wsh_err = assert_case(
        &harness,
        &ScriptBuf::new(),
        &p2wsh,
        &Witness::from(vec![wrong_script.as_bytes().to_vec()]),
        amount,
        VERIFY_WITNESS,
        false,
        "p2wsh mismatch",
    )
    .expect_err("p2wsh hash mismatch fails");
    assert_eq!(p2wsh_err.script_error, consensus::ScriptError::WitnessProgramMismatch);

    let p2wpkh =
        Builder::new().push_opcode(all::OP_PUSHBYTES_0).push_slice([0x11u8; 20]).into_script();
    let p2wpkh_err = assert_case(
        &harness,
        &ScriptBuf::new(),
        &p2wpkh,
        &Witness::from(vec![vec![0x01]]),
        amount,
        VERIFY_WITNESS,
        false,
        "p2wpkh mismatch",
    )
    .expect_err("p2wpkh requires two witness items");
    assert_eq!(p2wpkh_err.script_error, consensus::ScriptError::WitnessProgramMismatch);
}

#[test]
fn tidecoin_witness_malleation_and_unexpected_cases() {
    let harness = try_harness();
    let amount = sat(50_000);

    let bare_witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
    let bare_program = sha256::Hash::hash(bare_witness_script.as_bytes());
    let bare_script_pubkey = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(bare_program.to_byte_array())
        .into_script();
    let bare_malleated = assert_case(
        &harness,
        &Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script(),
        &bare_script_pubkey,
        &Witness::from(vec![bare_witness_script.as_bytes().to_vec()]),
        amount,
        VERIFY_WITNESS,
        false,
        "bare witness malleated by non-empty scriptSig",
    )
    .expect_err("bare witness with scriptSig fails");
    assert_eq!(bare_malleated.script_error, consensus::ScriptError::WitnessMalleated);

    let unexpected = assert_case(
        &harness,
        &ScriptBuf::new(),
        &Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script(),
        &Witness::from(vec![vec![0x01]]),
        amount,
        VERIFY_WITNESS,
        false,
        "unexpected witness data on non-witness script",
    )
    .expect_err("unexpected witness data fails");
    assert_eq!(unexpected.script_error, consensus::ScriptError::WitnessUnexpected);

    let inner_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
    let program = sha256::Hash::hash(inner_script.as_bytes());
    let redeem_script = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(program.to_byte_array())
        .into_script();
    let script_pubkey = p2sh_script_pubkey(&redeem_script);
    let p2sh_malleated = assert_case(
        &harness,
        &Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(redeem_script.as_bytes())
            .into_script(),
        &script_pubkey,
        &Witness::from(vec![inner_script.as_bytes().to_vec()]),
        amount,
        VERIFY_WITNESS | VERIFY_P2SH,
        false,
        "p2sh witness malleated by non-canonical redeem push",
    )
    .expect_err("non-canonical redeem push fails after P2SH witness detection");
    assert_eq!(p2sh_malleated.script_error, consensus::ScriptError::WitnessMalleatedP2SH);

    let redeem_non_witness = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
    let p2sh_non_witness = p2sh_script_pubkey(&redeem_non_witness);
    let p2sh_unexpected = assert_case(
        &harness,
        &Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(redeem_non_witness.as_bytes())
            .into_script(),
        &p2sh_non_witness,
        &Witness::from(vec![vec![0x01]]),
        amount,
        VERIFY_WITNESS | VERIFY_P2SH,
        false,
        "non-witness p2sh with witness data",
    )
    .expect_err("non-witness P2SH spends must report unexpected witness data");
    assert_eq!(p2sh_unexpected.script_error, consensus::ScriptError::WitnessUnexpected);
}
