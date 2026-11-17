use std::collections::BTreeMap;

use consensus::verify_with_flags_detailed;
use encoding::decode_from_slice;
use node_parity::ScriptError;
use primitives::Transaction;
use serde_json::Value;

mod tidecoin_test_support;

use tidecoin_test_support::{
    build_test_transaction, is_valid_script_flag_combination, map_rust_script_error,
    node_script_result, normalize_flags, parse_hex_bytes, parse_script_asm_bytes,
    parse_script_flags, parse_tx_inputs, parse_witness_and_amount, read_fixture, try_harness,
    ALL_TIDECOIN_SCRIPT_FLAGS, TIDECOIN_SCRIPT_ACTIVATION_FLAGS,
};

const SCRIPT_MONOTONICITY_TRIALS_PER_VECTOR: usize = 16;

#[derive(Default, Debug)]
struct RuntimeDiffStats {
    compared_inputs: usize,
    script_vectors: usize,
    tx_valid_vectors: usize,
    tx_invalid_vectors: usize,
    script_monotonicity_checks: usize,
    script_monotonicity_skipped_flags: usize,
    exercised_flag_counts: BTreeMap<&'static str, usize>,
    exercised_flag_combo_counts: BTreeMap<String, usize>,
    exercised_token_counts: BTreeMap<String, usize>,
    rust_error_counts: BTreeMap<String, usize>,
    node_error_counts: BTreeMap<String, usize>,
}

#[derive(Clone)]
struct DeterministicFlagRng(u64);

impl DeterministicFlagRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x as u32
    }
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
        "tidecoin_runtime_diff: compared_inputs={} script_vectors={} tx_valid_vectors={} tx_invalid_vectors={} script_monotonicity_checks={} script_monotonicity_skipped_flags={}",
        stats.compared_inputs,
        stats.script_vectors,
        stats.tx_valid_vectors,
        stats.tx_invalid_vectors,
        stats.script_monotonicity_checks,
        stats.script_monotonicity_skipped_flags
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

fn compare_script_case(
    harness: &node_parity::TidecoinNodeHarness,
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    amount_sat: i64,
    flags: u32,
) -> (Result<(), ScriptError>, Result<(), ScriptError>) {
    let witness_refs: Vec<&[u8]> = witness.iter().map(Vec::as_slice).collect();
    let node = node_script_result(harness.verify_script_case(
        script_sig,
        script_pubkey,
        &witness_refs,
        amount_sat,
        flags,
    ));

    let tx_bytes =
        build_test_transaction(script_pubkey, script_sig, witness, amount_sat.max(0) as u64);
    let outputs = [consensus::Utxo { script_pubkey, value: amount_sat }];
    let ours = verify_with_flags_detailed(
        script_pubkey,
        amount_sat.max(0) as u64,
        &tx_bytes,
        Some(&outputs),
        0,
        flags,
    )
    .map_err(|failure| map_rust_script_error(failure.script_error));

    (ours, node)
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

        let (ours, node) =
            compare_script_case(&harness, &script_sig, &script_pubkey, &witness, amount_sat, flags);

        record_exercised_token_coverage(&mut stats, flags_str);
        record_exercised_flag_coverage(&mut stats, flags);
        record_error_counts(&mut stats, &ours, &node);

        assert_eq!(
            ours, node,
            "script_tests_pq row #{index} diverged between consensus and Tidecoin node"
        );

        let expected_ok = node.is_ok();
        let mut rng = DeterministicFlagRng::new(0x7d1e_5c1a_cafe_f00d ^ index as u64);
        for trial in 0..SCRIPT_MONOTONICITY_TRIALS_PER_VECTOR {
            let extra_flags = rng.next_u32() & ALL_TIDECOIN_SCRIPT_FLAGS;
            let combined_flags =
                node_parity::script_flags_for_comparison(flags, extra_flags, expected_ok);
            if (combined_flags ^ flags) & TIDECOIN_SCRIPT_ACTIVATION_FLAGS != 0
                || !is_valid_script_flag_combination(combined_flags)
            {
                stats.script_monotonicity_skipped_flags += 1;
                continue;
            }

            let (monotonic_ours, monotonic_node) = compare_script_case(
                &harness,
                &script_sig,
                &script_pubkey,
                &witness,
                amount_sat,
                combined_flags,
            );
            assert_eq!(
                monotonic_ours.is_ok(),
                monotonic_node.is_ok(),
                "script_tests_pq row #{index} monotonicity trial #{trial} diverged between consensus and Tidecoin node at flags={combined_flags:#x}: ours={monotonic_ours:?} node={monotonic_node:?}"
            );
            assert_eq!(
                monotonic_node.is_ok(),
                expected_ok,
                "script_tests_pq row #{index} monotonicity trial #{trial} changed node acceptance at flags={combined_flags:#x}; base_flags={flags:#x} base_expected_ok={expected_ok}"
            );
            record_exercised_flag_coverage(&mut stats, combined_flags);
            stats.script_monotonicity_checks += 1;
        }

        stats.script_vectors += 1;
        stats.compared_inputs += 1;
    }

    print_runtime_diff_summary(&stats);
    assert!(stats.script_vectors > 0, "no Tidecoin script diff rows were executed");
    assert!(
        stats.script_monotonicity_checks >= stats.script_vectors,
        "script monotonicity coverage too small: checks={} vectors={} skipped_flags={}",
        stats.script_monotonicity_checks,
        stats.script_vectors,
        stats.script_monotonicity_skipped_flags
    );
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
            let outputs: Vec<_> = tx
                .inputs
                .iter()
                .map(|input| {
                    let out = prevouts.get(&input.previous_output).expect("previous output");
                    consensus::Utxo { script_pubkey: &out.script_pubkey, value: out.amount_sat }
                })
                .collect();

            for (input_index, input) in tx.inputs.iter().enumerate() {
                let spent = prevouts.get(&input.previous_output).unwrap_or_else(|| {
                    panic!("{fixture_name}[{index}] missing prevout {:?}", input.previous_output)
                });

                let node = node_script_result(
                    harness.verify_tx_input_with_spent_outputs(
                        tx_hex,
                        input_index,
                        &spent.script_pubkey,
                        spent.amount_sat,
                        flags,
                        &tx.inputs
                            .iter()
                            .map(|input| {
                                let out =
                                    prevouts.get(&input.previous_output).expect("previous output");
                                node_parity::SpentOutput {
                                    amount: out.amount_sat,
                                    script_pubkey: &out.script_pubkey,
                                }
                            })
                            .collect::<Vec<_>>(),
                    ),
                );
                node_results.push(node);

                let ours = verify_with_flags_detailed(
                    &spent.script_pubkey,
                    spent.amount_sat.max(0) as u64,
                    &tx_bytes,
                    Some(&outputs),
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
