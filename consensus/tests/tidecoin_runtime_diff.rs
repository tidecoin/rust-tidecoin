use std::collections::BTreeMap;

use consensus::verify_with_flags_detailed;
use encoding::decode_from_slice;
use node_parity::ScriptError;
use primitives::Transaction;
use serde_json::Value;

mod tidecoin_test_support;

use tidecoin_test_support::{
    build_test_transaction, map_rust_script_error, node_script_result, normalize_flags,
    parse_hex_bytes, parse_script_asm_bytes, parse_script_flags, parse_tx_inputs,
    parse_witness_and_amount, read_fixture, try_harness,
};

#[derive(Default, Debug)]
struct RuntimeDiffStats {
    compared_inputs: usize,
    script_vectors: usize,
    tx_valid_vectors: usize,
    tx_invalid_vectors: usize,
    exercised_flag_counts: BTreeMap<&'static str, usize>,
    exercised_flag_combo_counts: BTreeMap<String, usize>,
    exercised_token_counts: BTreeMap<String, usize>,
    rust_error_counts: BTreeMap<String, usize>,
    node_error_counts: BTreeMap<String, usize>,
}

fn record_exercised_token_coverage(stats: &mut RuntimeDiffStats, raw_flags: &str) {
    let mut saw_token = false;
    for token in
        raw_flags.split(',').map(str::trim).filter(|token| !token.is_empty() && *token != "NONE")
    {
        saw_token = true;
        *stats.exercised_token_counts.entry(token.to_owned()).or_default() += 1;
    }
    if !saw_token || raw_flags.trim() == "NONE" {
        *stats.exercised_token_counts.entry("NONE".to_owned()).or_default() += 1;
    }
}

fn record_exercised_flag_coverage(stats: &mut RuntimeDiffStats, flags: u32) {
    let known_flags = [
        ("P2SH", consensus::VERIFY_P2SH),
        ("SIGPUSHONLY", consensus::VERIFY_SIGPUSHONLY),
        ("MINIMALDATA", consensus::VERIFY_MINIMALDATA),
        ("NULLDUMMY", consensus::VERIFY_NULLDUMMY),
        ("DISCOURAGE_UPGRADABLE_NOPS", consensus::VERIFY_DISCOURAGE_UPGRADABLE_NOPS),
        ("CLEANSTACK", consensus::VERIFY_CLEANSTACK),
        ("MINIMALIF", consensus::VERIFY_MINIMALIF),
        ("NULLFAIL", consensus::VERIFY_NULLFAIL),
        ("CHECKLOCKTIMEVERIFY", consensus::VERIFY_CHECKLOCKTIMEVERIFY),
        ("CHECKSEQUENCEVERIFY", consensus::VERIFY_CHECKSEQUENCEVERIFY),
        ("WITNESS", consensus::VERIFY_WITNESS),
        (
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            consensus::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        ),
        ("CONST_SCRIPTCODE", consensus::VERIFY_CONST_SCRIPTCODE),
        ("PQ_STRICT", consensus::VERIFY_PQ_STRICT),
        ("WITNESS_V1_512", consensus::VERIFY_WITNESS_V1_512),
        ("SHA512", consensus::VERIFY_SHA512),
    ];

    for (name, bit) in known_flags {
        if flags & bit != 0 {
            *stats.exercised_flag_counts.entry(name).or_default() += 1;
        }
    }
    *stats.exercised_flag_combo_counts.entry(format!("{flags:#x}")).or_default() += 1;
}

fn record_error_counts(
    stats: &mut RuntimeDiffStats,
    ours: &Result<(), ScriptError>,
    node: &Result<(), ScriptError>,
) {
    if let Err(err) = ours {
        *stats.rust_error_counts.entry(err.to_string()).or_default() += 1;
    }
    if let Err(err) = node {
        *stats.node_error_counts.entry(err.to_string()).or_default() += 1;
    }
}

fn print_runtime_diff_summary(stats: &RuntimeDiffStats) {
    eprintln!(
        "tidecoin_runtime_diff: compared_inputs={} script_vectors={} tx_valid_vectors={} tx_invalid_vectors={}",
        stats.compared_inputs, stats.script_vectors, stats.tx_valid_vectors, stats.tx_invalid_vectors
    );
    if !stats.exercised_token_counts.is_empty() {
        eprintln!("tidecoin_runtime_diff exercised tokens: {:?}", stats.exercised_token_counts);
    }
    if !stats.exercised_flag_counts.is_empty() {
        eprintln!("tidecoin_runtime_diff exercised flag bits: {:?}", stats.exercised_flag_counts);
    }
    if !stats.exercised_flag_combo_counts.is_empty() {
        eprintln!(
            "tidecoin_runtime_diff exercised flag combos: {:?}",
            stats.exercised_flag_combo_counts
        );
    }
    if !stats.rust_error_counts.is_empty() || !stats.node_error_counts.is_empty() {
        eprintln!(
            "tidecoin_runtime_diff error classes: rust={:?} node={:?}",
            stats.rust_error_counts, stats.node_error_counts
        );
    }
}

#[test]
fn tidecoin_runtime_diff_script_tests_pq_matches_node() {
    let Some(harness) = try_harness() else {
        eprintln!("skipping Tidecoin runtime diff test: TIDECOIN_NODE_REPO is not configured");
        return;
    };

    let tests = read_fixture("script_tests_pq.json");
    let mut stats = RuntimeDiffStats::default();

    for (index, row) in tests.iter().enumerate() {
        let Some(arr) = row.as_array() else {
            continue;
        };

        if arr.len() == 1 && arr[0].is_string() {
            continue;
        }

        let mut position = 0usize;
        let mut witness = Vec::new();
        let mut amount_sat = 0i64;

        if arr.get(position).is_some_and(Value::is_array) {
            let (parsed_witness, parsed_amount) = parse_witness_and_amount(&arr[position]);
            witness = parsed_witness;
            amount_sat = parsed_amount;
            position += 1;
        }

        if arr.len() < position + 4 {
            continue;
        }

        let script_sig = parse_script_asm_bytes(&harness, arr[position].as_str().unwrap());
        position += 1;
        let script_pubkey = parse_script_asm_bytes(&harness, arr[position].as_str().unwrap());
        position += 1;
        let flags_str = arr[position].as_str().unwrap();
        let flags = normalize_flags(parse_script_flags(flags_str));

        let witness_refs: Vec<&[u8]> = witness.iter().map(Vec::as_slice).collect();
        let node = node_script_result(harness.verify_script_case(
            &script_sig,
            &script_pubkey,
            &witness_refs,
            amount_sat,
            flags,
        ));

        let tx_bytes =
            build_test_transaction(&script_pubkey, &script_sig, &witness, amount_sat.max(0) as u64);
        let ours = verify_with_flags_detailed(
            &script_pubkey,
            amount_sat.max(0) as u64,
            &tx_bytes,
            None,
            0,
            flags,
        )
        .map_err(|failure| map_rust_script_error(failure.script_error));

        record_exercised_token_coverage(&mut stats, flags_str);
        record_exercised_flag_coverage(&mut stats, flags);
        record_error_counts(&mut stats, &ours, &node);

        assert_eq!(
            ours, node,
            "script_tests_pq row #{index} diverged between consensus and Tidecoin node"
        );

        stats.script_vectors += 1;
        stats.compared_inputs += 1;
    }

    print_runtime_diff_summary(&stats);
    assert!(stats.script_vectors > 0, "no Tidecoin script diff rows were executed");
}

#[test]
fn tidecoin_runtime_diff_tx_corpora_match_node() {
    let Some(harness) = try_harness() else {
        eprintln!("skipping Tidecoin runtime diff test: TIDECOIN_NODE_REPO is not configured");
        return;
    };

    let mut stats = RuntimeDiffStats::default();

    for fixture_name in ["tx_valid_pq.json", "tx_invalid_pq.json"] {
        let rows = read_fixture(fixture_name);
        assert!(!rows.is_empty(), "{fixture_name} should not be empty");

        for (index, row) in rows.iter().enumerate() {
            let arr = row.as_array().expect("tx vector row");
            let prevouts = parse_tx_inputs(&harness, &arr[0]);
            let tx_hex = arr[1].as_str().expect("tx hex");
            let flags_str = arr[2].as_str().expect("flags");

            if fixture_name == "tx_invalid_pq.json" && flags_str == "BADTX" {
                continue;
            }

            let flags = normalize_flags(parse_script_flags(flags_str));
            let tx_bytes = parse_hex_bytes(tx_hex);
            let tx: Transaction = decode_from_slice(&tx_bytes)
                .unwrap_or_else(|e| panic!("{fixture_name}[{index}] invalid tx hex: {e}"));

            let mut node_results = Vec::with_capacity(tx.inputs.len());
            let mut ours_results = Vec::with_capacity(tx.inputs.len());

            for (input_index, input) in tx.inputs.iter().enumerate() {
                let spent = prevouts.get(&input.previous_output).unwrap_or_else(|| {
                    panic!("{fixture_name}[{index}] missing prevout {:?}", input.previous_output)
                });

                let node = node_script_result(harness.verify_tx_input_hex(
                    tx_hex,
                    input_index,
                    &spent.script_pubkey,
                    spent.amount_sat,
                    flags,
                ));
                node_results.push(node);

                let ours = verify_with_flags_detailed(
                    &spent.script_pubkey,
                    spent.amount_sat.max(0) as u64,
                    &tx_bytes,
                    None,
                    input_index,
                    flags,
                )
                .map_err(|failure| map_rust_script_error(failure.script_error));
                ours_results.push(ours);
                stats.compared_inputs += 1;
            }

            record_exercised_token_coverage(&mut stats, flags_str);
            record_exercised_flag_coverage(&mut stats, flags);
            for (ours, node) in ours_results.iter().zip(node_results.iter()) {
                record_error_counts(&mut stats, ours, node);
            }

            assert_eq!(
                ours_results, node_results,
                "{fixture_name}[{index}] diverged between consensus and Tidecoin node"
            );

            if fixture_name == "tx_valid_pq.json" {
                stats.tx_valid_vectors += 1;
            } else {
                stats.tx_invalid_vectors += 1;
            }
        }
    }

    print_runtime_diff_summary(&stats);
    assert!(stats.tx_valid_vectors > 0, "no Tidecoin tx_valid runtime diff rows were executed");
    assert!(stats.tx_invalid_vectors > 0, "no Tidecoin tx_invalid runtime diff rows were executed");
}
