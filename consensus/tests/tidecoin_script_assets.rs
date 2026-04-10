use consensus::verify_with_flags_detailed;
use encoding::{decode_from_slice, encode_to_vec};
use hashes::hex_unstable::DisplayHex;
use node_parity::fixtures::test_data_path;
use primitives::{script::ScriptBuf, Transaction, TxOut, Witness};
use serde_json::Value;

mod tidecoin_test_support;

use tidecoin_test_support::{
    all_script_assets_consensus_flags, map_rust_script_error, node_script_result, normalize_flags,
    parse_hex_bytes, parse_prevout_txouts, parse_script_flags, read_fixture_from_path, try_harness,
    OwnedUtxoSet,
};

fn parse_asset_variant(variant: &Value) -> (Vec<u8>, Vec<Vec<u8>>) {
    let script_sig = parse_hex_bytes(variant["scriptSig"].as_str().expect("scriptSig hex"));
    let witness = variant["witness"]
        .as_array()
        .expect("witness array")
        .iter()
        .map(|item| parse_hex_bytes(item.as_str().expect("witness hex")))
        .collect();
    (script_sig, witness)
}

fn apply_asset_variant(tx: &Transaction, index: usize, variant: &Value) -> Transaction {
    let mut tx = tx.clone();
    let (script_sig, witness) = parse_asset_variant(variant);
    tx.inputs[index].script_sig = ScriptBuf::from_bytes(script_sig);
    tx.inputs[index].witness = Witness::from_slice(&witness);
    tx
}

fn to_rust_result(
    tx: &Transaction,
    prevouts: &OwnedUtxoSet,
    input_index: usize,
    flags: u32,
) -> Result<(), consensus::ScriptError> {
    let tx_bytes = encode_to_vec(tx);
    let prevout = &prevouts.as_slice()[input_index];
    verify_with_flags_detailed(
        prevouts.script_pubkey(input_index),
        prevout.value as u64,
        &tx_bytes,
        Some(prevouts.as_slice()),
        input_index,
        flags,
    )
    .map_err(|failure| failure.script_error)
}

fn to_node_result(
    tx: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    flags: u32,
) -> Result<(), node_parity::ScriptError> {
    let harness = try_harness().expect("TIDECOIN_NODE_REPO must be configured");
    let tx_hex = encode_to_vec(tx).to_lower_hex_string();
    let prevout = &prevouts[input_index];
    node_script_result(harness.verify_tx_input_hex(
        &tx_hex,
        input_index,
        prevout.script_pubkey.as_bytes(),
        prevout.amount.to_sat() as i64,
        flags,
    ))
}

#[test]
fn tidecoin_script_assets_match_node_subset_superset_semantics() {
    let Some(_harness) = try_harness() else {
        eprintln!("skipping Tidecoin script-assets test: TIDECOIN_NODE_REPO is not configured");
        return;
    };

    let path = test_data_path("script_assets_test.json");
    let tests = read_fixture_from_path(&path);
    assert!(!tests.is_empty(), "script_assets_test.json should not be empty");

    let all_flags = all_script_assets_consensus_flags();
    let mut executed_success = 0usize;
    let mut executed_failure = 0usize;

    for (index, row) in tests.iter().enumerate() {
        let base_tx: Transaction =
            decode_from_slice(&parse_hex_bytes(row["tx"].as_str().expect("tx hex")))
                .unwrap_or_else(|e| panic!("script_assets[{index}] invalid tx hex: {e}"));
        let prevout_txouts = parse_prevout_txouts(&row["prevouts"]);
        assert_eq!(
            prevout_txouts.len(),
            base_tx.inputs.len(),
            "script_assets[{index}] prevout count mismatch"
        );
        let owned_prevouts = OwnedUtxoSet::from_txouts(&prevout_txouts);
        let input_index = row["index"].as_u64().expect("input index") as usize;
        let test_flags = normalize_flags(parse_script_flags(row["flags"].as_str().expect("flags")));
        let is_final = row.get("final").and_then(Value::as_bool).unwrap_or(false);

        if let Some(success) = row.get("success") {
            let tx = apply_asset_variant(&base_tx, input_index, success);
            for flags in &all_flags {
                if is_final || ((flags & test_flags) == *flags) {
                    let ours = to_rust_result(&tx, &owned_prevouts, input_index, *flags)
                        .map_err(map_rust_script_error);
                    let node = to_node_result(&tx, &prevout_txouts, input_index, *flags);
                    assert_eq!(
                        ours.is_ok(),
                        node.is_ok(),
                        "script_assets[{index}] success-case subset mismatch at flags=0x{flags:08x}: ours={ours:?} node={node:?}"
                    );
                    assert!(
                        ours.is_ok(),
                        "script_assets[{index}] success-case should validate at flags=0x{flags:08x}: ours={ours:?} node={node:?}"
                    );
                    executed_success += 1;
                }
            }
        }

        if let Some(failure) = row.get("failure") {
            let tx = apply_asset_variant(&base_tx, input_index, failure);
            for flags in &all_flags {
                if (*flags & test_flags) == test_flags {
                    let ours = to_rust_result(&tx, &owned_prevouts, input_index, *flags)
                        .map_err(map_rust_script_error);
                    let node = to_node_result(&tx, &prevout_txouts, input_index, *flags);
                    assert_eq!(
                        ours.is_ok(),
                        node.is_ok(),
                        "script_assets[{index}] failure-case superset mismatch at flags=0x{flags:08x}: ours={ours:?} node={node:?}"
                    );
                    assert!(
                        ours.is_err(),
                        "script_assets[{index}] failure-case should fail at flags=0x{flags:08x}: ours={ours:?} node={node:?}"
                    );
                    executed_failure += 1;
                }
            }
        }
    }

    assert!(executed_success > 0, "no success script-assets cases were executed");
    assert!(executed_failure > 0, "no failure script-assets cases were executed");
}
