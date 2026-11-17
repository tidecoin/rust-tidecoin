#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::Unstructured;
use consensus::{
    verify_with_flags_detailed, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_CLEANSTACK, VERIFY_CONST_SCRIPTCODE, VERIFY_DEFINED_HASHTYPE,
    VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    VERIFY_FALCON_CANONICAL, VERIFY_MINIMALDATA, VERIFY_MINIMALIF, VERIFY_NONE, VERIFY_NULLDUMMY,
    VERIFY_NULLFAIL, VERIFY_P2SH, VERIFY_PQ_STRICT, VERIFY_SHA512, VERIFY_SIGPUSHONLY,
    VERIFY_WITNESS, VERIFY_WITNESS_V1_512,
};
use libfuzzer_sys::fuzz_target;
use tidecoin::absolute;
use tidecoin::hashes::{hash160, sha256, sha512};
use tidecoin::opcodes::all;
use tidecoin::script::{Builder, ScriptPubKeyBuf, ScriptSigBuf};
use tidecoin::transaction::{OutPoint, TxIn, TxOut};
use tidecoin::{Amount, Sequence, Transaction, TransactionVersion, Txid, Witness};
use tidecoin_consensus_encoding::encode_to_vec;

#[cfg(not(fuzzing))]
fn main() {}

const MAX_SCRIPT_BYTES: usize = 512;
const MAX_WITNESS_ITEMS: usize = 8;
const MAX_WITNESS_ITEM_BYTES: usize = 512;

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let mode = u.int_in_range::<u8>(0..=4).unwrap_or_default();
    let script_sig_bytes = bounded_bytes(&mut u, MAX_SCRIPT_BYTES);
    let spend_script_bytes = bounded_bytes(&mut u, MAX_SCRIPT_BYTES);
    let witness = arbitrary_witness(&mut u);
    let flags = select_flags(u.arbitrary::<u32>().unwrap_or_default());

    let (script_sig, script_pubkey) =
        script_case(mode, script_sig_bytes, spend_script_bytes, witness.clone());
    let tx = spending_transaction(script_sig, witness);
    let tx_bytes = encode_to_vec(&tx);

    let _ = verify_with_flags_detailed(script_pubkey.as_bytes(), 50_000, &tx_bytes, None, 0, flags);
    // Exercise the rc2 complete-context path as well as missing-context behavior.
    // The script buffer remains alive through the byte API call.
    let spent_outputs =
        [consensus::Utxo { script_pubkey: script_pubkey.as_bytes(), value: 50_000 }];
    let _ = verify_with_flags_detailed(
        script_pubkey.as_bytes(),
        50_000,
        &tx_bytes,
        Some(&spent_outputs),
        0,
        flags,
    );
}

fn script_case(
    mode: u8,
    script_sig_bytes: Vec<u8>,
    spend_script_bytes: Vec<u8>,
    witness: Witness,
) -> (ScriptSigBuf, ScriptPubKeyBuf) {
    match mode {
        0 => (
            ScriptSigBuf::from_bytes(script_sig_bytes),
            ScriptPubKeyBuf::from_bytes(spend_script_bytes),
        ),
        1 => {
            let redeem_script = ScriptPubKeyBuf::from_bytes(spend_script_bytes);
            let redeem_hash = hash160::Hash::hash(redeem_script.as_bytes());
            let script_sig = Builder::new().push_slice(redeem_script.as_bytes()).into_script();
            let script_pubkey = Builder::new()
                .push_opcode(all::OP_HASH160)
                .push_slice(redeem_hash.to_byte_array())
                .push_opcode(all::OP_EQUAL)
                .into_script();
            (script_sig, script_pubkey)
        }
        2 => {
            let witness_script = witness
                .last()
                .map(|bytes| ScriptPubKeyBuf::from_bytes(bytes.to_vec()))
                .unwrap_or_else(|| ScriptPubKeyBuf::from_bytes(spend_script_bytes));
            let program = sha256::Hash::hash(witness_script.as_bytes());
            let script_pubkey = Builder::new()
                .push_opcode(all::OP_PUSHBYTES_0)
                .push_slice(program.to_byte_array())
                .into_script();
            (ScriptSigBuf::new(), script_pubkey)
        }
        3 => {
            let witness_script = witness
                .last()
                .map(|bytes| ScriptPubKeyBuf::from_bytes(bytes.to_vec()))
                .unwrap_or_else(|| ScriptPubKeyBuf::from_bytes(spend_script_bytes));
            let program = sha512::Hash::hash(witness_script.as_bytes());
            let script_pubkey = Builder::new()
                .push_opcode(all::OP_PUSHNUM_1)
                .push_slice(program.to_byte_array())
                .into_script();
            (ScriptSigBuf::new(), script_pubkey)
        }
        _ => (
            ScriptSigBuf::from_bytes(script_sig_bytes),
            Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script(),
        ),
    }
}

fn bounded_bytes(u: &mut Unstructured<'_>, max_len: usize) -> Vec<u8> {
    let len = u.int_in_range::<usize>(0..=max_len).unwrap_or_default();
    (0..len).map(|_| u.arbitrary::<u8>().unwrap_or_default()).collect()
}

fn arbitrary_witness(u: &mut Unstructured<'_>) -> Witness {
    let count = u.int_in_range::<usize>(0..=MAX_WITNESS_ITEMS).unwrap_or_default();
    let items = (0..count).map(|_| bounded_bytes(u, MAX_WITNESS_ITEM_BYTES)).collect::<Vec<_>>();
    Witness::from(items)
}

fn select_flags(seed: u32) -> u32 {
    const FLAGS: [u32; 17] = [
        VERIFY_P2SH,
        VERIFY_NULLDUMMY,
        VERIFY_SIGPUSHONLY,
        VERIFY_MINIMALDATA,
        VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
        VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        VERIFY_CLEANSTACK,
        VERIFY_CHECKLOCKTIMEVERIFY,
        VERIFY_CHECKSEQUENCEVERIFY,
        VERIFY_WITNESS,
        VERIFY_MINIMALIF,
        VERIFY_NULLFAIL,
        VERIFY_PQ_STRICT,
        VERIFY_WITNESS_V1_512,
        VERIFY_SHA512,
        VERIFY_FALCON_CANONICAL,
        VERIFY_DEFINED_HASHTYPE,
    ];

    let mut flags = VERIFY_NONE;
    for (bit, flag) in FLAGS.into_iter().enumerate() {
        if seed & (1 << bit) != 0 {
            flags |= flag;
        }
    }
    if seed & (1 << 17) != 0 {
        flags |= VERIFY_CONST_SCRIPTCODE;
    }
    flags
}

fn spending_transaction(script_sig: ScriptSigBuf, witness: Witness) -> Transaction {
    Transaction {
        version: TransactionVersion::TWO,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0x55; 32]), vout: 0 },
            script_sig,
            sequence: Sequence::MAX,
            witness,
        }],
        outputs: vec![TxOut {
            amount: Amount::from_sat(10_000).expect("small amount is valid"),
            script_pubkey: ScriptPubKeyBuf::new(),
        }],
    }
}

fuzz_target!(|data| {
    do_test(data);
});
