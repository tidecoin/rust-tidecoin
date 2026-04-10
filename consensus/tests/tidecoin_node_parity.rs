use std::fs;

use encoding::decode_from_slice;
use node_parity::fixtures::test_data_path;
use primitives::Transaction;
use serde_json::Value;

mod tidecoin_test_support;

use tidecoin_test_support::{
    normalize_flags, parse_hex_bytes, parse_script_error, parse_script_flags, parse_tx_inputs,
    parse_witness_and_amount, read_fixture, try_harness,
};

#[test]
fn tidecoin_node_script_tests_pq_fixture_roundtrip() {
    let Some(harness) = try_harness() else {
        eprintln!("skipping Tidecoin node parity test: TIDECOIN_NODE_REPO is not configured");
        return;
    };

    let path = test_data_path("script_tests_pq.json");
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    let tests: Vec<Value> = serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e));

    let mut executed = 0usize;

    for (index, row) in tests.iter().enumerate() {
        let Some(arr) = row.as_array() else {
            continue;
        };

        if arr.len() == 1 && arr[0].is_string() {
            continue;
        }

        let mut position = 0usize;
        let mut witness = Vec::new();
        let mut amount = 0i64;

        if arr.get(position).is_some_and(Value::is_array) {
            let (parsed_witness, parsed_amount) = parse_witness_and_amount(&arr[position]);
            witness = parsed_witness;
            amount = parsed_amount;
            position += 1;
        }

        if arr.len() < position + 4 {
            continue;
        }

        let script_sig_asm = arr[position].as_str().unwrap();
        position += 1;
        let script_pubkey_asm = arr[position].as_str().unwrap();
        position += 1;
        let flags = normalize_flags(parse_script_flags(arr[position].as_str().unwrap()));
        position += 1;
        let expected_error = arr[position].as_str().unwrap();

        let script_sig = harness
            .parse_script_asm(script_sig_asm)
            .unwrap_or_else(|e| panic!("vector #{index} failed to parse scriptSig: {e}"));
        let script_pubkey = harness
            .parse_script_asm(script_pubkey_asm)
            .unwrap_or_else(|e| panic!("vector #{index} failed to parse scriptPubKey: {e}"));
        let witness_refs: Vec<&[u8]> = witness.iter().map(Vec::as_slice).collect();

        let actual_error = match harness.verify_script_case(
            &script_sig,
            &script_pubkey,
            &witness_refs,
            amount,
            flags,
        ) {
            Ok(()) => None,
            Err(node_parity::NodeParityError::Script(err)) => Some(err),
            Err(err) => panic!("vector #{index} harness failure: {err}"),
        };

        match expected_error {
            "OK" => {
                assert!(
                    actual_error.is_none(),
                    "vector #{index} expected OK but got {:?}",
                    actual_error
                );
            }
            other => {
                assert_eq!(
                    actual_error,
                    Some(parse_script_error(other)),
                    "vector #{index} mismatch"
                );
            }
        }

        executed += 1;
    }

    assert!(executed > 0, "no Tidecoin script fixture rows were executed");
}

#[test]
fn tidecoin_node_tx_valid_pq_fixture_roundtrip() {
    let Some(harness) = try_harness() else {
        eprintln!("skipping Tidecoin node parity test: TIDECOIN_NODE_REPO is not configured");
        return;
    };

    let tests = read_fixture("tx_valid_pq.json");
    assert!(!tests.is_empty(), "tx_valid_pq fixture should not be empty");

    for (index, row) in tests.iter().enumerate() {
        let arr = row.as_array().expect("tx_valid vector row");
        let prevouts = parse_tx_inputs(&harness, &arr[0]);
        let tx_hex = arr[1].as_str().expect("tx hex");
        let tx_bytes = parse_hex_bytes(tx_hex);
        let tx: Transaction = decode_from_slice(&tx_bytes)
            .unwrap_or_else(|e| panic!("vector #{index} invalid tx hex: {e}"));
        let flags = normalize_flags(parse_script_flags(arr[2].as_str().expect("flags")));

        harness
            .check_transaction_hex(tx_hex)
            .unwrap_or_else(|e| panic!("tx_valid_pq[{index}] sanity failed: {e}"));

        for (input_index, input) in tx.inputs.iter().enumerate() {
            let spent = prevouts.get(&input.previous_output).unwrap_or_else(|| {
                panic!("tx_valid_pq[{index}] missing prevout {:?}", input.previous_output)
            });
            harness
                .verify_tx_input_hex(
                    tx_hex,
                    input_index,
                    &spent.script_pubkey,
                    spent.amount_sat,
                    flags,
                )
                .unwrap_or_else(|e| panic!("tx_valid_pq[{index}] input {input_index} failed: {e}"));
        }
    }
}

#[test]
fn tidecoin_node_tx_invalid_pq_fixture_roundtrip() {
    let Some(harness) = try_harness() else {
        eprintln!("skipping Tidecoin node parity test: TIDECOIN_NODE_REPO is not configured");
        return;
    };

    let tests = read_fixture("tx_invalid_pq.json");
    assert!(!tests.is_empty(), "tx_invalid_pq fixture should not be empty");

    for (index, row) in tests.iter().enumerate() {
        let arr = row.as_array().expect("tx_invalid vector row");
        let prevouts = parse_tx_inputs(&harness, &arr[0]);
        let tx_hex = arr[1].as_str().expect("tx hex");
        let flags_str = arr[2].as_str().expect("flags");

        if flags_str == "BADTX" {
            assert!(
                harness.check_transaction_hex(tx_hex).is_err(),
                "tx_invalid_pq[{index}] should be structurally invalid"
            );
            continue;
        }

        let tx_bytes = parse_hex_bytes(tx_hex);
        let tx: Transaction = decode_from_slice(&tx_bytes)
            .unwrap_or_else(|e| panic!("vector #{index} invalid tx hex: {e}"));
        let flags = normalize_flags(parse_script_flags(flags_str));

        let mut any_failed = false;
        for (input_index, input) in tx.inputs.iter().enumerate() {
            let spent = prevouts.get(&input.previous_output).unwrap_or_else(|| {
                panic!("tx_invalid_pq[{index}] missing prevout {:?}", input.previous_output)
            });
            if harness
                .verify_tx_input_hex(
                    tx_hex,
                    input_index,
                    &spent.script_pubkey,
                    spent.amount_sat,
                    flags,
                )
                .is_err()
            {
                any_failed = true;
                break;
            }
        }
        assert!(any_failed, "tx_invalid_pq[{index}] unexpectedly passed");
    }
}
