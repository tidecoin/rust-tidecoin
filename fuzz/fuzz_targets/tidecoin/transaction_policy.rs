#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tidecoin::absolute;
use tidecoin::network::NetworkExt as _;
use tidecoin::opcodes::all;
use tidecoin::policy::{self, StandardRelayPrecheckPolicy};
use tidecoin::script::{Builder, ScriptPubKeyBuf, ScriptPubKeyExt as _};
use tidecoin::transaction::{check_transaction_sanity, OutPoint, TransactionExt as _, TxOut};
use tidecoin::{Amount, BlockHeight, Network, Transaction};
use tidecoin_consensus_encoding::{decode_from_slice, encode_to_vec};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    if let Ok(tx) = decode_from_slice::<Transaction>(data) {
        exercise_transaction(&tx, data);
    }

    let mut u = Unstructured::new(data);
    if let Ok(tx) = Transaction::arbitrary(&mut u) {
        exercise_transaction(&tx, data);
    }
}

fn exercise_transaction(tx: &Transaction, seed: &[u8]) {
    let serialized = encode_to_vec(tx);
    if let Ok(decoded) = decode_from_slice::<Transaction>(&serialized) {
        assert_eq!(decoded, *tx);
        assert!(
            check_transaction_sanity(&decoded).is_ok(),
            "canonical transaction decoder must reject sanity-invalid transactions",
        );
    }

    let _ = check_transaction_sanity(tx);
    let _ = tx.compute_txid();
    let _ = tx.compute_wtxid();
    let _ = tx.is_coinbase();
    let _ = tx.is_explicitly_rbf();
    let _ = tx.is_lock_time_enabled();
    let _ = tx.is_absolute_timelock_satisfied(
        absolute::Height::from_u32(BlockHeight::MAX.to_u32()).expect("valid absolute height"),
        absolute::MedianTimePast::from_u32(500_000_000).expect("valid MTP"),
    );

    let weight = tx.weight().to_wu();
    let sigop_cost_without_prevouts = tx.total_sigop_cost(|_| None);
    let _ = policy::get_virtual_tx_size(
        i64::try_from(weight).unwrap_or(i64::MAX),
        i64::try_from(sigop_cost_without_prevouts).unwrap_or(i64::MAX),
    );

    let standard_without_bare = policy::is_standard_tx(
        tx,
        Some(80_000),
        false,
        policy::StandardRelayPrecheckPolicy::DEFAULT.dust_relay_fee,
    );
    let standard_with_bare = policy::is_standard_tx(
        tx,
        Some(80_000),
        true,
        policy::StandardRelayPrecheckPolicy::DEFAULT.dust_relay_fee,
    );
    if standard_without_bare.is_ok() {
        assert!(
            standard_with_bare.is_ok(),
            "permit_bare_multisig=true must not reject a tx accepted with it disabled",
        );
    }

    let prevouts = synthetic_prevouts(tx, seed);
    let _ = policy::are_inputs_standard(tx, |outpoint| lookup_prevout(&prevouts, outpoint));
    let _ = policy::is_witness_standard(tx, |outpoint| lookup_prevout(&prevouts, outpoint));
    let _ = tx.total_sigop_cost(|outpoint| lookup_prevout(&prevouts, outpoint));

    let network = select_network(seed);
    let next_block_height = select_height(seed);
    let relay_result = policy::check_standard_relay_prechecks(
        tx,
        network.params(),
        next_block_height,
        |outpoint| lookup_prevout(&prevouts, outpoint),
        StandardRelayPrecheckPolicy::DEFAULT,
    );
    if relay_result.is_ok() {
        assert!(check_transaction_sanity(tx).is_ok());
        assert!(!tx.is_coinbase());
    }
}

fn synthetic_prevouts(tx: &Transaction, seed: &[u8]) -> Vec<(OutPoint, TxOut)> {
    tx.inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| input.previous_output != OutPoint::COINBASE_PREVOUT)
        .map(|(index, input)| {
            let tag = seed.get(index % seed.len().max(1)).copied().unwrap_or(index as u8);
            (input.previous_output, synthetic_prevout(index, tag))
        })
        .collect()
}

fn lookup_prevout(prevouts: &[(OutPoint, TxOut)], outpoint: &OutPoint) -> Option<TxOut> {
    prevouts.iter().find(|(candidate, _)| candidate == outpoint).map(|(_, txout)| txout.clone())
}

fn synthetic_prevout(index: usize, tag: u8) -> TxOut {
    let amount = Amount::from_sat(100_000 + u64::from(tag)).expect("small amount is valid");
    TxOut { amount, script_pubkey: synthetic_script_pubkey(index, tag) }
}

fn synthetic_script_pubkey(index: usize, tag: u8) -> ScriptPubKeyBuf {
    match index % 7 {
        0 => ScriptPubKeyBuf::new(),
        1 => Builder::new().push_opcode(all::OP_RETURN).push_slice([tag; 8]).into_script(),
        2 => Builder::new()
            .push_opcode(all::OP_DUP)
            .push_opcode(all::OP_HASH160)
            .push_slice([tag; 20])
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_CHECKSIG)
            .into_script(),
        3 => Builder::new()
            .push_opcode(all::OP_HASH160)
            .push_slice([tag; 20])
            .push_opcode(all::OP_EQUAL)
            .into_script(),
        4 => Builder::new().push_opcode(all::OP_0).push_slice([tag; 20]).into_script(),
        5 => Builder::new().push_opcode(all::OP_0).push_slice([tag; 32]).into_script(),
        _ => Builder::new().push_opcode(all::OP_1).push_slice([tag; 64]).into_script(),
    }
}

fn select_network(seed: &[u8]) -> Network {
    match seed.first().copied().unwrap_or_default() % 3 {
        0 => Network::Tidecoin,
        1 => Network::Testnet,
        _ => Network::Regtest,
    }
}

fn select_height(seed: &[u8]) -> BlockHeight {
    let mut bytes = [0u8; 4];
    for (dst, src) in bytes.iter_mut().zip(seed.iter().skip(1)) {
        *dst = *src;
    }
    BlockHeight::from_u32(u32::from_le_bytes(bytes))
}

fuzz_target!(|data| {
    do_test(data);
});
