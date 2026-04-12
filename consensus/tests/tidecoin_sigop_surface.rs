use consensus::{verify_with_flags, VERIFY_P2SH, VERIFY_WITNESS};
use encoding::encode_to_vec;
use hashes::{hash160, sha256};
use primitives::{
    absolute::LockTime,
    opcodes::all,
    script::{Builder as BuilderT, ScriptBuf as PrimitiveScriptBuf, ScriptPubKeyBuf, ScriptSigBuf},
    Amount, OutPoint, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
};

mod tidecoin_test_support;

use tidecoin_test_support::{node_script_result, try_harness};

type Builder = BuilderT<()>;
type ScriptBuf = PrimitiveScriptBuf<()>;

fn dummy_outpoint() -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([2u8; 32]), vout: 0 }
}

fn spend_tx(script_sig: ScriptBuf, witness: Witness) -> Transaction {
    Transaction {
        version: TransactionVersion::TWO,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: dummy_outpoint(),
            script_sig: ScriptSigBuf::from(script_sig.into_bytes()),
            sequence: Sequence::MAX,
            witness,
        }],
        outputs: vec![TxOut {
            amount: Amount::from_sat(1).expect("test amount in range"),
            script_pubkey: ScriptPubKeyBuf::new(),
        }],
    }
}

fn assert_surface_parity(
    harness: &Option<node_parity::TidecoinNodeHarness>,
    script_pubkey: &ScriptBuf,
    script_sig: &ScriptBuf,
    witness: &Witness,
    flags: u32,
    expected_ok: bool,
    context: &str,
) {
    let tx = spend_tx(script_sig.clone(), witness.clone());
    let tx_bytes = encode_to_vec(&tx);
    let ours = verify_with_flags(script_pubkey.as_bytes(), 1, &tx_bytes, None, 0, flags);

    let witness_refs: Vec<&[u8]> = witness.iter().collect();
    if let Some(harness) = harness {
        let node = node_script_result(harness.verify_script_case(
            script_sig.as_bytes(),
            script_pubkey.as_bytes(),
            &witness_refs,
            1,
            flags,
        ));
        assert_eq!(
            ours.is_ok(),
            node.is_ok(),
            "{context}: node/runtime acceptance mismatch: ours={ours:?} node={node:?}"
        );
    }

    assert_eq!(
        ours.is_ok(),
        expected_ok,
        "{context}: unexpected result for flags={flags:#x}: ours={ours:?}"
    );
}

#[test]
fn tidecoin_sigop_surface_p2wpkh_witness_toggle() {
    let harness = try_harness();
    let script_pubkey =
        Builder::new().push_opcode(all::OP_PUSHBYTES_0).push_slice([0x11; 20]).into_script();
    let script_sig = ScriptBuf::new();
    let witness = Witness::from(vec![vec![], vec![0x02]]);

    assert_surface_parity(
        &harness,
        &script_pubkey,
        &script_sig,
        &witness,
        VERIFY_P2SH,
        true,
        "p2wpkh witness ignored without VERIFY_WITNESS",
    );
    assert_surface_parity(
        &harness,
        &script_pubkey,
        &script_sig,
        &witness,
        VERIFY_P2SH | VERIFY_WITNESS,
        false,
        "p2wpkh malformed witness rejected with VERIFY_WITNESS",
    );
}

#[test]
fn tidecoin_sigop_surface_p2wsh_witness_toggle() {
    let harness = try_harness();
    let witness_script = Builder::new()
        .push_opcode(all::OP_PUSHNUM_1)
        .push_slice([0x02; 33])
        .push_slice([0x03; 33])
        .push_opcode(all::OP_PUSHNUM_2)
        .push_opcode(all::OP_CHECKMULTISIGVERIFY)
        .into_script();
    let program = sha256::Hash::hash(witness_script.as_bytes());
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(program.to_byte_array())
        .into_script();
    let script_sig = ScriptBuf::new();
    let witness = Witness::from(vec![vec![], vec![], witness_script.as_bytes().to_vec()]);

    assert_surface_parity(
        &harness,
        &script_pubkey,
        &script_sig,
        &witness,
        VERIFY_P2SH,
        true,
        "p2wsh witness ignored without VERIFY_WITNESS",
    );
    assert_surface_parity(
        &harness,
        &script_pubkey,
        &script_sig,
        &witness,
        VERIFY_P2SH | VERIFY_WITNESS,
        false,
        "p2wsh sigop-heavy witness rejected with VERIFY_WITNESS",
    );
}

#[test]
fn tidecoin_sigop_surface_p2sh_p2wsh_witness_toggle() {
    let harness = try_harness();
    let witness_script = Builder::new()
        .push_opcode(all::OP_PUSHNUM_1)
        .push_slice([0x02; 33])
        .push_slice([0x03; 33])
        .push_opcode(all::OP_PUSHNUM_2)
        .push_opcode(all::OP_CHECKMULTISIGVERIFY)
        .into_script();
    let witness_program = sha256::Hash::hash(witness_script.as_bytes());
    let redeem_script = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(witness_program.to_byte_array())
        .into_script();
    let redeem_hash = hash160::Hash::hash(redeem_script.as_bytes());
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_HASH160)
        .push_slice(redeem_hash.to_byte_array())
        .push_opcode(all::OP_EQUAL)
        .into_script();
    let script_sig = Builder::new().push_slice(redeem_script.as_bytes()).into_script();
    let witness = Witness::from(vec![vec![], vec![], witness_script.as_bytes().to_vec()]);

    assert_surface_parity(
        &harness,
        &script_pubkey,
        &script_sig,
        &witness,
        VERIFY_P2SH,
        true,
        "p2sh-p2wsh witness ignored without VERIFY_WITNESS",
    );
    assert_surface_parity(
        &harness,
        &script_pubkey,
        &script_sig,
        &witness,
        VERIFY_P2SH | VERIFY_WITNESS,
        false,
        "p2sh-p2wsh sigop-heavy witness rejected with VERIFY_WITNESS",
    );
}
