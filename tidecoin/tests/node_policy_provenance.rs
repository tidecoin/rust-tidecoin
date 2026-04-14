use std::{env, fs, path::Path, process::Command};

use serde_json::Value;
use tidecoin::hashes::{sha256, sha512};
use tidecoin::opcodes::all;
use tidecoin::policy::{
    self, StandardRelayPrecheckError, StandardRelayPrecheckPolicy, StandardTxError,
};
use tidecoin::script::{
    Builder, PushBytesBuf, ScriptBufExt as _, ScriptPubKeyBuf, ScriptSigBuf, WitnessScriptBuf,
};
use tidecoin::transaction::{InputWeightPrediction, OutPoint, TxIn, TxOut};
use tidecoin::{
    absolute, Amount, BlockHeight, FeeRate, Params, PqScheme, PqSchemeCryptoExt, Sequence,
    Transaction, TransactionVersion, Txid, Witness,
};

const CORPUS: &str = include_str!("data/node_policy_provenance_corpus.json");

#[test]
fn node_policy_provenance_corpus_matches_rust_stateless_policy() {
    let corpus: Value = serde_json::from_str(CORPUS).expect("node policy provenance corpus JSON");
    assert_eq!(u64_field(&corpus, "schema_version"), 1);
    assert_eq!(
        u64_field(&corpus, "case_count"),
        corpus["cases"].as_array().expect("cases array").len() as u64
    );

    if let Ok(node_repo) = env::var("TIDECOIN_NODE_REPO") {
        assert_node_sources_match_corpus(Path::new(&node_repo), &corpus);
    }

    assert_constants_match(&corpus["constants"]);

    for case in corpus["cases"].as_array().expect("cases array") {
        match str_field(case, "kind") {
            "datacarrier" => assert_datacarrier_case(case),
            "bare_multisig" => assert_bare_multisig_case(case),
            "descriptor_script_size" => assert_descriptor_script_size_case(case),
            "witness_standard" => assert_witness_standard_case(case),
            "dust_count" => assert_dust_count_case(case),
            "truc_vsize" => assert_truc_vsize_case(case),
            other => panic!("unknown node policy provenance case kind `{other}`"),
        }
    }
}

fn assert_node_sources_match_corpus(node_repo: &Path, corpus: &Value) {
    let commit = Command::new("git")
        .arg("-C")
        .arg(node_repo)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .expect("git rev-parse Tidecoin node HEAD");
    assert!(commit.status.success(), "failed to resolve Tidecoin node commit");
    assert_eq!(
        String::from_utf8(commit.stdout).expect("git commit utf8").trim(),
        str_field(corpus, "source_node_commit"),
        "node policy provenance corpus source_node_commit mismatch"
    );

    let source_files = corpus["source_files"].as_object().expect("source_files object");
    for (key, source) in source_files {
        let path = node_repo.join(str_field(source, "path"));
        let got = sha256::Hash::hash(
            &fs::read(&path).unwrap_or_else(|err| panic!("failed to read {path:?}: {err}")),
        )
        .to_string();
        assert_eq!(
            got,
            str_field(source, "sha256"),
            "node policy provenance source hash mismatch for {key}"
        );
    }
}

fn assert_constants_match(constants: &Value) {
    assert_eq!(
        u64_field(constants, "MAX_STANDARD_TX_WEIGHT"),
        policy::MAX_STANDARD_TX_WEIGHT as u64
    );
    assert_eq!(
        u64_field(constants, "MIN_STANDARD_TX_NONWITNESS_SIZE"),
        policy::MIN_STANDARD_TX_NONWITNESS_SIZE as u64
    );
    assert_eq!(u64_field(constants, "MAX_P2SH_SIGOPS"), policy::MAX_P2SH_SIGOPS as u64);
    assert_eq!(u64_field(constants, "MAX_TX_LEGACY_SIGOPS"), policy::MAX_TX_LEGACY_SIGOPS as u64);
    assert_eq!(
        u64_field(constants, "DEFAULT_BYTES_PER_SIGOP"),
        policy::DEFAULT_BYTES_PER_SIGOP as u64
    );
    assert_eq!(
        bool_field(constants, "DEFAULT_PERMIT_BAREMULTISIG"),
        policy::DEFAULT_PERMIT_BAREMULTISIG
    );
    assert_eq!(
        u64_field(constants, "MAX_STANDARD_P2WSH_STACK_ITEMS"),
        policy::MAX_STANDARD_P2WSH_STACK_ITEMS as u64
    );
    assert_eq!(
        u64_field(constants, "MAX_STANDARD_P2WSH_STACK_ITEM_SIZE"),
        policy::MAX_STANDARD_P2WSH_STACK_ITEM_SIZE as u64
    );
    assert_eq!(
        u64_field(constants, "MAX_STANDARD_P2WSH_SCRIPT_SIZE"),
        policy::MAX_STANDARD_P2WSH_SCRIPT_SIZE as u64
    );
    assert_eq!(
        u64_field(constants, "MAX_STANDARD_SCRIPTSIG_SIZE"),
        policy::MAX_STANDARD_SCRIPTSIG_SIZE as u64
    );
    assert_eq!(u64_field(constants, "DUST_RELAY_TX_FEE"), policy::DUST_RELAY_TX_FEE as u64);
    assert_eq!(
        u64_field(constants, "DEFAULT_MIN_RELAY_TX_FEE"),
        policy::DEFAULT_MIN_RELAY_TX_FEE as u64
    );
    assert_eq!(
        u64_field(constants, "MAX_DUST_OUTPUTS_PER_TX"),
        policy::MAX_DUST_OUTPUTS_PER_TX as u64
    );
    assert_eq!(
        u64_field(constants, "TX_MIN_STANDARD_VERSION"),
        policy::TX_MIN_STANDARD_VERSION.to_u32() as u64
    );
    assert_eq!(
        u64_field(constants, "TX_MAX_STANDARD_VERSION"),
        policy::TX_MAX_STANDARD_VERSION.to_u32() as u64
    );
    assert_eq!(
        u64_field(constants, "MAX_OP_RETURN_RELAY"),
        policy::MAX_STANDARD_TX_WEIGHT as u64 / 4
    );
    assert_eq!(u64_field(constants, "TRUC_MAX_VSIZE"), policy::TRUC_MAX_VSIZE as u64);
    assert_eq!(u64_field(constants, "TRUC_CHILD_MAX_VSIZE"), policy::TRUC_CHILD_MAX_VSIZE as u64);
}

fn assert_datacarrier_case(case: &Value) {
    let script_pubkey = op_return_script(&case["payload"]);
    let tx = tx_with_single_input(ScriptSigBuf::new(), vec![txout(script_pubkey, 0)]);
    let got = policy::is_standard_tx(
        &tx,
        Some(usize_field(case, "max_datacarrier_bytes")),
        policy::DEFAULT_PERMIT_BAREMULTISIG,
        FeeRate::DUST,
    );
    match str_field(case, "expected") {
        "ok" => assert_eq!(got, Ok(()), "{}", str_field(case, "id")),
        "datacarrier" => {
            assert_eq!(got, Err(StandardTxError::DataCarrier), "{}", str_field(case, "id"));
        }
        other => panic!("unknown datacarrier expected result `{other}`"),
    }
}

fn assert_bare_multisig_case(case: &Value) {
    let pubkeys = deterministic_pubkeys(usize_field(case, "pubkeys"));
    let script_pubkey = bare_multisig_script(i32_field(case, "required_sigs"), &pubkeys);
    let tx = tx_with_single_input(ScriptSigBuf::new(), vec![txout(script_pubkey, 30_000)]);
    let got_with_bare = policy::is_standard_tx(&tx, Some(200_000), true, FeeRate::DUST);
    let got_without_bare = policy::is_standard_tx(&tx, Some(200_000), false, FeeRate::DUST);

    if bool_field(case, "standard_with_bare_multisig") {
        assert_eq!(got_with_bare, Ok(()), "{}", str_field(case, "id"));
        assert_eq!(
            got_without_bare,
            Err(StandardTxError::BareMultisig),
            "{}",
            str_field(case, "id")
        );
    } else {
        assert_eq!(got_with_bare, Err(StandardTxError::ScriptPubKey), "{}", str_field(case, "id"));
        assert_eq!(
            got_without_bare,
            Err(StandardTxError::ScriptPubKey),
            "{}",
            str_field(case, "id")
        );
    }
}

fn assert_descriptor_script_size_case(case: &Value) {
    let expected_size = usize_field(case, "expected_script_size");
    match str_field(case, "descriptor") {
        "pk" => {
            let prefix = u8_field(case, "prefix");
            let pubkey_len = usize_field(case, "prefixed_pubkey_len");
            let pubkey = prefixed_pubkey_bytes(prefix, pubkey_len);
            let script: ScriptPubKeyBuf = Builder::new()
                .push_slice(PushBytesBuf::try_from(pubkey).unwrap())
                .push_opcode(all::OP_CHECKSIG)
                .into_script();
            assert_eq!(
                InputWeightPrediction::script_push_len(pubkey_len) + 1,
                expected_size,
                "{}",
                str_field(case, "id")
            );
            assert_eq!(script.len(), expected_size, "{}", str_field(case, "id"));
        }
        "multi" => {
            let threshold = i32_field(case, "threshold");
            let prefixes = case["prefixes"].as_array().expect("prefixes array");
            let lengths = case["prefixed_pubkey_lens"].as_array().expect("pubkey lens array");
            let mut builder = Builder::new().push_int(threshold).unwrap();
            let mut expected_from_parts = 1usize;
            for (prefix, len) in prefixes.iter().zip(lengths) {
                let len = usize::try_from(len.as_u64().expect("pubkey len")).unwrap();
                let pubkey = prefixed_pubkey_bytes(
                    u8::try_from(prefix.as_u64().expect("prefix")).unwrap(),
                    len,
                );
                expected_from_parts += InputWeightPrediction::script_push_len(len);
                builder = builder.push_slice(PushBytesBuf::try_from(pubkey).unwrap());
            }
            expected_from_parts += 1; // n-keys opcode.
            expected_from_parts += 1; // OP_CHECKMULTISIG.
            let script: ScriptPubKeyBuf = builder
                .push_int(i32::try_from(prefixes.len()).unwrap())
                .unwrap()
                .push_opcode(all::OP_CHECKMULTISIG)
                .into_script();
            assert_eq!(expected_from_parts, expected_size, "{}", str_field(case, "id"));
            assert_eq!(script.len(), expected_size, "{}", str_field(case, "id"));
        }
        other => panic!("unknown descriptor_script_size descriptor `{other}`"),
    }
}

fn assert_witness_standard_case(case: &Value) {
    let version = u64_field(case, "witness_version");
    let dimension = str_field(case, "dimension");
    let value = usize_field(case, "value");
    let (witness_script, witness_items) = match dimension {
        "stack_items" => {
            let script: WitnessScriptBuf = Builder::new().push_opcode(all::OP_TRUE).into_script();
            let mut items = vec![vec![1u8]; value];
            items.push(script.as_bytes().to_vec());
            (script, items)
        }
        "stack_item_size" => {
            let script: WitnessScriptBuf = Builder::new().push_opcode(all::OP_DROP).into_script();
            let items = vec![vec![1u8; value], script.as_bytes().to_vec()];
            (script, items)
        }
        "witness_script_size" => {
            let script = WitnessScriptBuf::from_bytes(vec![all::OP_TRUE.to_u8(); value]);
            let items = vec![vec![1u8], script.as_bytes().to_vec()];
            (script, items)
        }
        other => panic!("unknown witness_standard dimension `{other}`"),
    };
    let prev_script = match version {
        0 => p2wsh_script_pubkey(&witness_script),
        1 => p2wsh512_script_pubkey(&witness_script),
        other => panic!("unsupported witness version {other}"),
    };
    let tx = tx_with_witness(ScriptSigBuf::new(), Witness::from_slice(&witness_items));
    let got = policy::is_witness_standard(&tx, |_| Some(txout(prev_script.clone(), 1)));
    assert_eq!(got, str_field(case, "expected") == "ok", "{}", str_field(case, "id"));
}

fn assert_dust_count_case(case: &Value) {
    let script_pubkey = p2pkh_script_pubkey(0x44);
    let outputs =
        (0..usize_field(case, "dust_outputs")).map(|_| txout(script_pubkey.clone(), 1)).collect();
    let tx = tx_with_single_input(ScriptSigBuf::new(), outputs);
    let got = policy::is_standard_tx(&tx, Some(200_000), false, FeeRate::DUST);
    match str_field(case, "expected") {
        "ok" => assert_eq!(got, Ok(()), "{}", str_field(case, "id")),
        "dust" => assert_eq!(got, Err(StandardTxError::Dust), "{}", str_field(case, "id")),
        other => panic!("unknown dust_count expected result `{other}`"),
    }
}

fn assert_truc_vsize_case(case: &Value) {
    let target_vsize = i64_field(case, "target_vsize");
    let payload_len = witness_payload_len_for_vsize(target_vsize)
        .unwrap_or_else(|| panic!("missing synthetic payload for vsize {target_vsize}"));
    let tx = truc_tx_with_witness_payload(payload_len);
    let prevout = txout(
        ScriptPubKeyBuf::builder().push_int_unchecked(0).push_slice([0x72; 20]).into_script(),
        30_000,
    );
    let got = policy::check_standard_relay_prechecks(
        &tx,
        Params::REGTEST,
        BlockHeight::from_u32(0),
        |_| Some(prevout.clone()),
        StandardRelayPrecheckPolicy::default(),
    );
    match str_field(case, "expected") {
        "ok" => assert_eq!(got, Ok(()), "{}", str_field(case, "id")),
        "TRUC-violation" => assert_eq!(
            got,
            Err(StandardRelayPrecheckError::TrucTxSize { vsize: target_vsize }),
            "{}",
            str_field(case, "id")
        ),
        other => panic!("unknown truc_vsize expected result `{other}`"),
    }
}

fn prefixed_pubkey_bytes(prefix: u8, len: usize) -> Vec<u8> {
    let mut bytes = vec![0x42; len];
    bytes[0] = prefix;
    bytes
}

fn op_return_script(payload: &Value) -> ScriptPubKeyBuf {
    let mut builder = Builder::new().push_opcode(all::OP_RETURN);
    if str_field(payload, "shape") == "bytes" {
        builder = builder
            .push_slice(PushBytesBuf::try_from(vec![0x42; usize_field(payload, "len")]).unwrap());
    }
    builder.into_script()
}

fn deterministic_pubkeys(count: usize) -> Vec<tidecoin::PqPublicKey> {
    (0..count)
        .map(|i| {
            let scheme = PqScheme::Falcon512;
            let seed: Vec<u8> = (0..scheme.deterministic_seed_len())
                .map(|j| 0x90 ^ (i as u8).wrapping_mul(17) ^ (j as u8).wrapping_mul(131))
                .collect();
            scheme.generate_keypair_from_seed(&seed).unwrap().0
        })
        .collect()
}

fn bare_multisig_script(required_sigs: i32, pubkeys: &[tidecoin::PqPublicKey]) -> ScriptPubKeyBuf {
    let mut builder = Builder::new().push_int(required_sigs).unwrap();
    for pubkey in pubkeys {
        builder = builder.push_slice(PushBytesBuf::try_from(pubkey.to_prefixed_bytes()).unwrap());
    }
    builder.push_int(pubkeys.len() as i32).unwrap().push_opcode(all::OP_CHECKMULTISIG).into_script()
}

fn p2pkh_script_pubkey(tag: u8) -> ScriptPubKeyBuf {
    ScriptPubKeyBuf::builder()
        .push_opcode(all::OP_DUP)
        .push_opcode(all::OP_HASH160)
        .push_slice([tag; 20])
        .push_opcode(all::OP_EQUALVERIFY)
        .push_opcode(all::OP_CHECKSIG)
        .into_script()
}

fn p2wsh_script_pubkey(witness_script: &WitnessScriptBuf) -> ScriptPubKeyBuf {
    ScriptPubKeyBuf::builder()
        .push_int_unchecked(0)
        .push_slice(sha256::Hash::hash(witness_script.as_bytes()).to_byte_array())
        .into_script()
}

fn p2wsh512_script_pubkey(witness_script: &WitnessScriptBuf) -> ScriptPubKeyBuf {
    ScriptPubKeyBuf::builder()
        .push_int_unchecked(1)
        .push_slice(sha512::Hash::hash(witness_script.as_bytes()).to_byte_array())
        .into_script()
}

fn tx_with_witness(script_sig: ScriptSigBuf, witness: Witness) -> Transaction {
    let mut tx = tx_with_single_input(script_sig, vec![txout(ScriptPubKeyBuf::new(), 30_000)]);
    tx.inputs[0].witness = witness;
    tx
}

fn truc_tx_with_witness_payload(payload_len: usize) -> Transaction {
    let mut tx =
        tx_with_single_input(ScriptSigBuf::new(), vec![txout(p2pkh_script_pubkey(0x81), 30_000)]);
    tx.version = policy::TRUC_VERSION;
    tx.inputs[0].witness.push(vec![0x42; payload_len]);
    tx
}

fn witness_payload_len_for_vsize(target_vsize: i64) -> Option<usize> {
    (0..=(target_vsize as usize * 4 + 512)).find(|payload_len| {
        let tx = truc_tx_with_witness_payload(*payload_len);
        policy::get_virtual_tx_size(tx.weight().to_wu() as i64, 0) == target_vsize
    })
}

fn tx_with_single_input(script_sig: ScriptSigBuf, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: TransactionVersion::ONE,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([1; 32]), vout: 0 },
            script_sig,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs,
    }
}

fn txout(script_pubkey: ScriptPubKeyBuf, amount_sat: u64) -> TxOut {
    TxOut { amount: Amount::from_sat(amount_sat).unwrap(), script_pubkey }
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_else(|| panic!("missing string field `{key}`"))
}

fn bool_field(value: &Value, key: &str) -> bool {
    value[key].as_bool().unwrap_or_else(|| panic!("missing bool field `{key}`"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value[key].as_u64().unwrap_or_else(|| panic!("missing u64 field `{key}`"))
}

fn i64_field(value: &Value, key: &str) -> i64 {
    value[key].as_i64().unwrap_or_else(|| panic!("missing i64 field `{key}`"))
}

fn usize_field(value: &Value, key: &str) -> usize {
    usize::try_from(u64_field(value, key)).unwrap()
}

fn u8_field(value: &Value, key: &str) -> u8 {
    u8::try_from(u64_field(value, key)).unwrap()
}

fn i32_field(value: &Value, key: &str) -> i32 {
    i32::try_from(i64_field(value, key)).unwrap()
}
