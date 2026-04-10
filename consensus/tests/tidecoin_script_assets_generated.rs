use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use consensus::verify_with_flags_detailed;
use encoding::{decode_from_slice, encode_to_vec};
use hashes::{hex_unstable::DisplayHex, sha256};
use node_parity::fixtures::{test_data_path, TIDECOIN_NODE_REPO_ENV};
use node_parity::{ScriptError, TidecoinNodeHarness};
use primitives::{script::ScriptBuf, Amount, Transaction, TxOut, Witness};
use serde_json::{json, Map, Value};

mod tidecoin_test_support;

use tidecoin_test_support::{
    all_script_assets_consensus_flags, map_rust_script_error, node_script_result, normalize_flags,
    parse_hex_bytes, parse_prevout_txouts, parse_script_flags, parse_tx_inputs, read_fixture,
    try_harness, OwnedUtxoSet, PrevoutData,
};

const DEFAULT_MIN_GENERATED_CASES: usize = 25;
const DEFAULT_PROGRESS_EVERY: usize = 100;
const GENERATED_METADATA_DEFAULT_NAME: &str = "tidecoin_script_assets_generated_metadata.json";
const GENERATED_SOURCE_TAG: &str = "tidecoin_tx_pq_vectors_monotonicity";

const SCRIPT_ASSETS_FLAGS_MASK: u32 = consensus::VERIFY_P2SH
    | consensus::VERIFY_NULLDUMMY
    | consensus::VERIFY_CHECKLOCKTIMEVERIFY
    | consensus::VERIFY_CHECKSEQUENCEVERIFY
    | consensus::VERIFY_WITNESS
    | consensus::VERIFY_PQ_STRICT;

const ALL_TX_VECTOR_FLAGS: u32 = consensus::VERIFY_P2SH
    | consensus::VERIFY_SIGPUSHONLY
    | consensus::VERIFY_MINIMALDATA
    | consensus::VERIFY_NULLDUMMY
    | consensus::VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    | consensus::VERIFY_CLEANSTACK
    | consensus::VERIFY_MINIMALIF
    | consensus::VERIFY_NULLFAIL
    | consensus::VERIFY_CHECKLOCKTIMEVERIFY
    | consensus::VERIFY_CHECKSEQUENCEVERIFY
    | consensus::VERIFY_WITNESS
    | consensus::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | consensus::VERIFY_CONST_SCRIPTCODE
    | consensus::VERIFY_PQ_STRICT
    | consensus::VERIFY_WITNESS_V1_512
    | consensus::VERIFY_SHA512;

#[derive(Default, Debug)]
struct GeneratedCorpusStats {
    total_vectors: usize,
    parsed_vectors: usize,
    generated_success_cases: usize,
    generated_failure_cases: usize,
    skipped_badtx: usize,
    skipped_unknown: usize,
    skipped_noncanonical: usize,
    skipped_incompatible_inputs: usize,
    unknown_token_counts: BTreeMap<String, usize>,
}

struct GeneratedCorpusMetadata {
    source_node_commit: String,
    source_generation: String,
    source_tx_valid_pq_sha256: String,
    source_tx_invalid_pq_sha256: String,
    generated_case_count: usize,
    generated_sha256: String,
}

#[derive(Debug)]
enum TxVectorFlagParse {
    Parsed(u32),
    Skip(TxVectorSkipReason),
}

#[derive(Debug)]
enum TxVectorSkipReason {
    BadTx,
    UnknownToken(String),
}

fn generated_metadata_path() -> PathBuf {
    if let Ok(path) = env::var("TIDECOIN_SCRIPT_ASSETS_GENERATED_METADATA_JSON") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(GENERATED_METADATA_DEFAULT_NAME)
}

fn parse_tx_vector_flags(raw: &str) -> TxVectorFlagParse {
    if raw.trim().is_empty() || raw == "NONE" {
        return TxVectorFlagParse::Parsed(0);
    }

    let mut bits = 0u32;
    for token in raw.split(',').map(str::trim).filter(|token| !token.is_empty()) {
        let bit = match token {
            "P2SH" => consensus::VERIFY_P2SH,
            "SIGPUSHONLY" => consensus::VERIFY_SIGPUSHONLY,
            "MINIMALDATA" => consensus::VERIFY_MINIMALDATA,
            "NULLDUMMY" => consensus::VERIFY_NULLDUMMY,
            "DISCOURAGE_UPGRADABLE_NOPS" => consensus::VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            "CLEANSTACK" => consensus::VERIFY_CLEANSTACK,
            "MINIMALIF" => consensus::VERIFY_MINIMALIF,
            "NULLFAIL" => consensus::VERIFY_NULLFAIL,
            "CHECKLOCKTIMEVERIFY" => consensus::VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => consensus::VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => consensus::VERIFY_WITNESS,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                consensus::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
            }
            "CONST_SCRIPTCODE" => consensus::VERIFY_CONST_SCRIPTCODE,
            "PQ_STRICT" => consensus::VERIFY_PQ_STRICT,
            "WITNESS_V1_512" => consensus::VERIFY_WITNESS_V1_512,
            "SHA512" => consensus::VERIFY_SHA512,
            "BADTX" => return TxVectorFlagParse::Skip(TxVectorSkipReason::BadTx),
            other => {
                return TxVectorFlagParse::Skip(TxVectorSkipReason::UnknownToken(other.to_owned()));
            }
        };
        bits |= bit;
    }

    TxVectorFlagParse::Parsed(bits)
}

fn fill_flags(mut flags: u32) -> u32 {
    if flags & consensus::VERIFY_CLEANSTACK != 0 {
        flags |= consensus::VERIFY_WITNESS | consensus::VERIFY_P2SH;
    }
    if flags & consensus::VERIFY_WITNESS_V1_512 != 0 {
        flags |= consensus::VERIFY_WITNESS | consensus::VERIFY_P2SH;
    }
    if flags & consensus::VERIFY_WITNESS != 0 {
        flags |= consensus::VERIFY_P2SH;
    }
    flags
}

fn script_assets_flags_to_string(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & consensus::VERIFY_P2SH != 0 {
        parts.push("P2SH");
    }
    if flags & consensus::VERIFY_NULLDUMMY != 0 {
        parts.push("NULLDUMMY");
    }
    if flags & consensus::VERIFY_CHECKLOCKTIMEVERIFY != 0 {
        parts.push("CHECKLOCKTIMEVERIFY");
    }
    if flags & consensus::VERIFY_CHECKSEQUENCEVERIFY != 0 {
        parts.push("CHECKSEQUENCEVERIFY");
    }
    if flags & consensus::VERIFY_WITNESS != 0 {
        parts.push("WITNESS");
    }
    if flags & consensus::VERIFY_PQ_STRICT != 0 {
        parts.push("PQ_STRICT");
    }
    parts.join(",")
}

fn build_prevouts_in_input_order(
    tx: &Transaction,
    prevouts: &BTreeMap<primitives::OutPoint, PrevoutData>,
) -> Option<Vec<TxOut>> {
    tx.inputs
        .iter()
        .map(|input| {
            let spent = prevouts.get(&input.previous_output)?;
            Some(TxOut {
                amount: Amount::from_sat(spent.amount_sat.try_into().ok()?).ok()?,
                script_pubkey: ScriptBuf::from_bytes(spent.script_pubkey.clone()),
            })
        })
        .collect()
}

fn to_rust_result(
    tx: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    flags: u32,
) -> Result<(), ScriptError> {
    let tx_bytes = encode_to_vec(tx);
    let owned_prevouts = OwnedUtxoSet::from_txouts(prevouts);
    let prevout = &prevouts[input_index];
    verify_with_flags_detailed(
        prevout.script_pubkey.as_bytes(),
        prevout.amount.to_sat(),
        &tx_bytes,
        Some(owned_prevouts.as_slice()),
        input_index,
        flags,
    )
    .map_err(|failure| map_rust_script_error(failure.script_error))
}

fn to_node_result(
    harness: &TidecoinNodeHarness,
    tx: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    flags: u32,
) -> Result<(), ScriptError> {
    let tx_hex = encode_to_vec(tx).to_lower_hex_string();
    let prevout = &prevouts[input_index];
    node_script_result(harness.verify_tx_input_hex(
        &tx_hex,
        input_index,
        prevout.script_pubkey.as_bytes(),
        prevout.amount.to_sat().try_into().unwrap(),
        flags,
    ))
}

fn build_generated_entries_from_tx_vectors(
    harness: &TidecoinNodeHarness,
    fixture_name: &str,
    expect_success: bool,
    entries: &mut Vec<Value>,
    stats: &mut GeneratedCorpusStats,
) {
    let rows = read_fixture(fixture_name);
    for row in rows {
        let arr = match row.as_array() {
            Some(arr)
                if arr.len() >= 3
                    && arr[0].is_array()
                    && arr[1].is_string()
                    && arr[2].is_string() =>
            {
                arr
            }
            _ => continue,
        };
        stats.total_vectors += 1;

        let parsed_flags = match parse_tx_vector_flags(arr[2].as_str().expect("flags")) {
            TxVectorFlagParse::Parsed(flags) => {
                stats.parsed_vectors += 1;
                flags
            }
            TxVectorFlagParse::Skip(TxVectorSkipReason::BadTx) => {
                stats.skipped_badtx += 1;
                continue;
            }
            TxVectorFlagParse::Skip(TxVectorSkipReason::UnknownToken(token)) => {
                stats.skipped_unknown += 1;
                *stats.unknown_token_counts.entry(token).or_default() += 1;
                continue;
            }
        };

        let script_assets_flags = if expect_success {
            let included_flags = ALL_TX_VECTOR_FLAGS & !parsed_flags;
            if fill_flags(included_flags) != included_flags {
                stats.skipped_noncanonical += 1;
                continue;
            }
            included_flags & SCRIPT_ASSETS_FLAGS_MASK
        } else {
            let required_flags = fill_flags(parsed_flags);
            if required_flags != parsed_flags {
                stats.skipped_noncanonical += 1;
                continue;
            }
            required_flags & SCRIPT_ASSETS_FLAGS_MASK
        };

        let tx_hex = arr[1].as_str().expect("tx hex");
        let tx: Transaction = decode_from_slice(&parse_hex_bytes(tx_hex))
            .unwrap_or_else(|e| panic!("{fixture_name} invalid tx hex: {e}"));
        let prevout_map = parse_tx_inputs(harness, &arr[0]);
        let Some(prevouts) = build_prevouts_in_input_order(&tx, &prevout_map) else {
            stats.skipped_incompatible_inputs += 1;
            continue;
        };

        let flags_field = script_assets_flags_to_string(script_assets_flags);
        let prevouts_json: Vec<Value> = prevouts
            .iter()
            .map(|txout| Value::String(encode_to_vec(txout).to_lower_hex_string()))
            .collect();

        for (input_index, txin) in tx.inputs.iter().enumerate() {
            let node = to_node_result(harness, &tx, &prevouts, input_index, script_assets_flags);
            let include = if expect_success { node.is_ok() } else { node.is_err() };
            if !include {
                stats.skipped_incompatible_inputs += 1;
                continue;
            }

            let branch_key = if expect_success { "success" } else { "failure" };
            let branch_value = json!({
                "scriptSig": txin.script_sig.as_bytes().to_lower_hex_string(),
                "witness": txin
                    .witness
                    .iter()
                    .map(|item| Value::String(item.to_lower_hex_string()))
                    .collect::<Vec<_>>(),
            });

            let mut obj = Map::new();
            obj.insert("tx".to_owned(), Value::String(tx_hex.to_owned()));
            obj.insert("prevouts".to_owned(), Value::Array(prevouts_json.clone()));
            obj.insert("index".to_owned(), Value::from(input_index as u64));
            obj.insert("flags".to_owned(), Value::String(flags_field.clone()));
            obj.insert(branch_key.to_owned(), branch_value);
            entries.push(Value::Object(obj));

            if expect_success {
                stats.generated_success_cases += 1;
            } else {
                stats.generated_failure_cases += 1;
            }
        }
    }
}

fn generate_script_assets_entries(
    harness: &TidecoinNodeHarness,
) -> (Vec<Value>, GeneratedCorpusStats) {
    let mut entries = Vec::new();
    let mut stats = GeneratedCorpusStats::default();
    build_generated_entries_from_tx_vectors(
        harness,
        "tx_valid_pq.json",
        true,
        &mut entries,
        &mut stats,
    );
    build_generated_entries_from_tx_vectors(
        harness,
        "tx_invalid_pq.json",
        false,
        &mut entries,
        &mut stats,
    );
    (entries, stats)
}

fn push_canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::Number(v) => out.push_str(&v.to_string()),
        Value::String(v) => out.push_str(&serde_json::to_string(v).expect("string encode")),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                push_canonical_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("key encode"));
                out.push(':');
                push_canonical_json(&map[key], out);
            }
            out.push('}');
        }
    }
}

fn hash_json_entries(entries: &[Value]) -> String {
    let mut canonical = String::new();
    push_canonical_json(&Value::Array(entries.to_vec()), &mut canonical);
    sha256::Hash::hash(canonical.as_bytes()).to_string()
}

fn hash_file(path: &Path) -> String {
    let bytes =
        fs::read(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    sha256::Hash::hash(&bytes).to_string()
}

fn parse_generated_metadata(path: &Path) -> GeneratedCorpusMetadata {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read metadata {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("invalid metadata {}: {err}", path.display()));
    let obj = value
        .as_object()
        .unwrap_or_else(|| panic!("metadata {} must be an object", path.display()));
    let source_fixtures = obj
        .get("source_fixtures")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("metadata {} missing source_fixtures", path.display()));

    GeneratedCorpusMetadata {
        source_node_commit: obj
            .get("source_node_commit")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("metadata {} missing source_node_commit", path.display()))
            .to_owned(),
        source_generation: obj
            .get("source_generation")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("metadata {} missing source_generation", path.display()))
            .to_owned(),
        source_tx_valid_pq_sha256: source_fixtures
            .get("tx_valid_pq_sha256")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("metadata {} missing tx_valid_pq_sha256", path.display()))
            .to_owned(),
        source_tx_invalid_pq_sha256: source_fixtures
            .get("tx_invalid_pq_sha256")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("metadata {} missing tx_invalid_pq_sha256", path.display()))
            .to_owned(),
        generated_case_count: obj
            .get("generated_case_count")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("metadata {} missing generated_case_count", path.display()))
            as usize,
        generated_sha256: obj
            .get("generated_sha256")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("metadata {} missing generated_sha256", path.display()))
            .to_owned(),
    }
}

fn resolve_node_commit() -> String {
    let repo = env::var(TIDECOIN_NODE_REPO_ENV)
        .unwrap_or_else(|_| panic!("{TIDECOIN_NODE_REPO_ENV} must be set to resolve node commit"));
    let output = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .unwrap_or_else(|err| panic!("failed to run git rev-parse in {repo}: {err}"));
    assert!(
        output.status.success(),
        "git rev-parse failed in {repo}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 git output").trim().to_owned()
}

fn assert_generated_metadata_integrity(entries: &[Value]) {
    let path = generated_metadata_path();
    let metadata = parse_generated_metadata(&path);
    let tx_valid_path = test_data_path("tx_valid_pq.json");
    let tx_invalid_path = test_data_path("tx_invalid_pq.json");

    assert_eq!(
        metadata.source_generation,
        GENERATED_SOURCE_TAG,
        "generated metadata source_generation mismatch in {}",
        path.display()
    );
    assert_eq!(
        metadata.source_node_commit,
        resolve_node_commit(),
        "generated metadata source_node_commit mismatch in {}",
        path.display()
    );
    assert_eq!(
        metadata.source_tx_valid_pq_sha256,
        hash_file(&tx_valid_path),
        "generated metadata tx_valid_pq hash mismatch in {}",
        path.display()
    );
    assert_eq!(
        metadata.source_tx_invalid_pq_sha256,
        hash_file(&tx_invalid_path),
        "generated metadata tx_invalid_pq hash mismatch in {}",
        path.display()
    );
    assert_eq!(
        metadata.generated_case_count,
        entries.len(),
        "generated metadata case-count mismatch in {}",
        path.display()
    );
    assert_eq!(
        metadata.generated_sha256,
        hash_json_entries(entries),
        "generated metadata corpus hash mismatch in {}",
        path.display()
    );
}

fn maybe_export_generated_corpus(entries: &[Value]) {
    let Ok(path) = env::var("TIDECOIN_SCRIPT_ASSETS_WRITE_GENERATED_JSON") else {
        return;
    };
    let output_path = PathBuf::from(path);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|err| {
            panic!("failed to create parent directory for {}: {err}", output_path.display())
        });
    }
    let encoded =
        serde_json::to_vec_pretty(entries).expect("generated script-assets corpus serialization");
    fs::write(&output_path, encoded).unwrap_or_else(|err| {
        panic!("failed to write generated script-assets corpus {}: {err}", output_path.display())
    });
    eprintln!(
        "wrote Tidecoin generated script-assets corpus to {} (cases={})",
        output_path.display(),
        entries.len()
    );
}

fn progress_every() -> usize {
    env::var("TIDECOIN_SCRIPT_ASSETS_PROGRESS_EVERY")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PROGRESS_EVERY)
}

fn min_generated_cases() -> usize {
    env::var("TIDECOIN_SCRIPT_ASSETS_MIN_CASES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MIN_GENERATED_CASES)
}

fn run_generated_entries_monotonicity(harness: &TidecoinNodeHarness, entries: &[Value]) {
    let all_flags = all_script_assets_consensus_flags();
    let progress_every = progress_every();
    let started = Instant::now();

    for (index, row) in entries.iter().enumerate() {
        let tx: Transaction =
            decode_from_slice(&parse_hex_bytes(row["tx"].as_str().expect("tx hex")))
                .unwrap_or_else(|e| panic!("generated script_assets[{index}] invalid tx hex: {e}"));
        let prevouts = parse_prevout_txouts(&row["prevouts"]);
        let input_index = row["index"].as_u64().expect("input index") as usize;
        let test_flags = normalize_flags(parse_script_flags(row["flags"].as_str().expect("flags")));

        if let Some(success) = row.get("success") {
            let mut tx = tx.clone();
            tx.inputs[input_index].script_sig = ScriptBuf::from_bytes(parse_hex_bytes(
                success["scriptSig"].as_str().expect("scriptSig hex"),
            ));
            tx.inputs[input_index].witness = Witness::from_slice(
                &success["witness"]
                    .as_array()
                    .expect("witness array")
                    .iter()
                    .map(|item| parse_hex_bytes(item.as_str().expect("witness hex")))
                    .collect::<Vec<_>>(),
            );

            for flags in &all_flags {
                if (flags & test_flags) == *flags {
                    let ours = to_rust_result(&tx, &prevouts, input_index, *flags);
                    let node = to_node_result(harness, &tx, &prevouts, input_index, *flags);
                    assert_eq!(
                        ours.is_ok(),
                        node.is_ok(),
                        "generated script_assets[{index}] success-case subset mismatch at flags=0x{flags:08x}: ours={ours:?} node={node:?}"
                    );
                    assert!(
                        ours.is_ok(),
                        "generated script_assets[{index}] success-case should validate at flags=0x{flags:08x}: ours={ours:?} node={node:?}"
                    );
                }
            }
        }

        if let Some(failure) = row.get("failure") {
            let mut tx = tx.clone();
            tx.inputs[input_index].script_sig = ScriptBuf::from_bytes(parse_hex_bytes(
                failure["scriptSig"].as_str().expect("scriptSig hex"),
            ));
            tx.inputs[input_index].witness = Witness::from_slice(
                &failure["witness"]
                    .as_array()
                    .expect("witness array")
                    .iter()
                    .map(|item| parse_hex_bytes(item.as_str().expect("witness hex")))
                    .collect::<Vec<_>>(),
            );

            for flags in &all_flags {
                if (*flags & test_flags) == test_flags {
                    let ours = to_rust_result(&tx, &prevouts, input_index, *flags);
                    let node = to_node_result(harness, &tx, &prevouts, input_index, *flags);
                    assert_eq!(
                        ours.is_ok(),
                        node.is_ok(),
                        "generated script_assets[{index}] failure-case superset mismatch at flags=0x{flags:08x}: ours={ours:?} node={node:?}"
                    );
                    assert!(
                        ours.is_err(),
                        "generated script_assets[{index}] failure-case should fail at flags=0x{flags:08x}: ours={ours:?} node={node:?}"
                    );
                }
            }
        }

        let completed = index + 1;
        if progress_every > 0 && (completed % progress_every == 0 || completed == entries.len()) {
            eprintln!(
                "tidecoin generated script-assets progress: completed={}/{} elapsed={:.2}s",
                completed,
                entries.len(),
                started.elapsed().as_secs_f64()
            );
        }
    }
}

#[test]
fn tidecoin_generated_script_assets_monotonicity() {
    let Some(harness) = try_harness() else {
        eprintln!(
            "skipping Tidecoin generated script-assets test: {TIDECOIN_NODE_REPO_ENV} is not configured"
        );
        return;
    };

    let (entries, stats) = generate_script_assets_entries(&harness);
    assert!(
        stats.unknown_token_counts.is_empty(),
        "unknown Tidecoin tx-vector flags while generating script-assets corpus: {:?}",
        stats.unknown_token_counts
    );
    assert!(
        entries.len() >= min_generated_cases(),
        "generated Tidecoin script-assets corpus is too small: {} cases",
        entries.len()
    );
    maybe_export_generated_corpus(&entries);
    assert_generated_metadata_integrity(&entries);
    eprintln!(
        "tidecoin generated script-assets corpus: cases={} success_cases={} failure_cases={} vectors_total={} vectors_parsed={} skipped_badtx={} skipped_unknown={} skipped_noncanonical={} skipped_incompatible_inputs={}",
        entries.len(),
        stats.generated_success_cases,
        stats.generated_failure_cases,
        stats.total_vectors,
        stats.parsed_vectors,
        stats.skipped_badtx,
        stats.skipped_unknown,
        stats.skipped_noncanonical,
        stats.skipped_incompatible_inputs
    );
    run_generated_entries_monotonicity(&harness, &entries);
}

#[test]
fn tidecoin_generated_script_assets_metadata_integrity() {
    let Some(harness) = try_harness() else {
        eprintln!(
            "skipping Tidecoin generated script-assets metadata test: {TIDECOIN_NODE_REPO_ENV} is not configured"
        );
        return;
    };
    let (entries, stats) = generate_script_assets_entries(&harness);
    assert!(
        stats.unknown_token_counts.is_empty(),
        "unknown Tidecoin tx-vector flags while generating script-assets corpus: {:?}",
        stats.unknown_token_counts
    );
    assert_generated_metadata_integrity(&entries);
}
