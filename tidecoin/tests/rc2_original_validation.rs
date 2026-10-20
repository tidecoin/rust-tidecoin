// SPDX-License-Identifier: CC0-1.0
#![cfg(feature = "tidecoin-node-validation")]
//! Differential checks against unmodified validation.cpp, not a rule copy.
use std::convert::Infallible;

use node_parity::{validation, TidecoinNodeHarness};
use serde_json::{json, Value};
use tidecoin::block::{BlockHash, BlockHeight, Header, Version};
use tidecoin::block_validation::{
    contextual_check_block_header_with_options, ContextualHeaderCheck,
};
use tidecoin::network::Params;
use tidecoin::{BlockTime, CompactTarget, TxMerkleNode};

fn hex<T: encoding::Encodable>(value: &T) -> String {
    encoding::encode_to_vec(value).iter().map(|b| format!("{b:02x}")).collect()
}
fn history(params: &Params, count: u32) -> Vec<Header> {
    let mut result = Vec::new();
    for height in 0..count {
        let previous =
            result.last().map(Header::block_hash).unwrap_or(BlockHash::from_byte_array([0; 32]));
        result.push(Header {
            version: Version::from_consensus(0x20000004),
            prev_blockhash: previous,
            merkle_root: TxMerkleNode::from_byte_array([height as u8; 32]),
            time: BlockTime::from_u32(1_700_000_000 + height * 60),
            bits: params.max_attainable_target.to_compact_lossy(),
            nonce: 0,
            auxpow: None,
        });
    }
    result
}
fn candidate(headers: &[Header]) -> Header {
    let previous = headers.last().unwrap();
    Header {
        version: Version::from_consensus(4),
        prev_blockhash: previous.block_hash(),
        time: BlockTime::from_u32(previous.time.to_u32() + 60),
        ..previous.clone()
    }
}
fn overrides(params: &Params) -> Value {
    json!({
        "auxpow_start_height": params.auxpow_start_height.map(|h| h.to_u32() as i32).unwrap_or(i32::MAX),
        "bip34_height": params.bip34_height.to_u32(), "bip65_height": params.bip65_height.to_u32(),
        "bip66_height": params.bip66_height.to_u32(), "csv_height": params.csv_height.to_u32(),
        "segwit_height": params.segwit_height.to_u32(), "enforce_bip94": params.enforce_bip94,
        "strict_chain_id": params.strict_auxpow_chain_id, "no_retargeting": params.no_pow_retargeting,
        "target_timespan": params.pow_target_timespan,
    })
}
struct Case {
    name: String,
    request: Value,
    rust_valid: bool,
    expected: bool,
    reason: &'static str,
}
// Keep each source-derived boundary's explicit context together at the call site.
#[allow(clippy::too_many_arguments)]
fn add_case(
    cases: &mut Vec<Case>,
    name: impl Into<String>,
    params: &Params,
    headers: &[Header],
    header: Header,
    now: u32,
    expected: bool,
    reason: &'static str,
) {
    let previous = headers.last().unwrap();
    let rust = contextual_check_block_header_with_options(
        params,
        previous,
        BlockHeight::from_u32(headers.len() as u32 - 1),
        &header,
        |height| -> Result<Header, Infallible> { Ok(headers[height.to_u32() as usize].clone()) },
        ContextualHeaderCheck { check_proof: false, current_time: Some(BlockTime::from_u32(now)) },
    );
    // Pure-header input intentionally permits flag-without-payload here: this
    // operation isolates ContextualCheckBlockHeader, which does not check proof.
    let raw = hex(&header);
    cases.push(Case { name: name.into(), rust_valid: rust.is_ok(), expected, reason,
        request: json!({"op": "contextual_header", "network": match params.network { tidecoin::Network::Tidecoin => 0, tidecoin::Network::Testnet => 1, tidecoin::Network::Regtest => 2 }, "params": overrides(params),
            "history": headers.iter().map(hex).collect::<Vec<_>>(),
            "header": &raw[..160], "pure_header": true, "now": now}) });
}
fn check_cases(cases: Vec<Case>) {
    let requests = cases.iter().map(|c| c.request.clone()).collect::<Vec<_>>();
    let results = validation::run(&requests).expect("original validation.cpp verdicts");
    for (case, node) in cases.iter().zip(results) {
        assert_eq!(node["valid"], case.expected, "{} node: {node}", case.name);
        assert_eq!(case.rust_valid, case.expected, "{} Rust; node: {node}", case.name);
        assert!(node["reason"].as_str().unwrap().starts_with(case.reason), "{}: {node}", case.name);
    }
}

#[test]
fn original_contextual_header_activation_versions_and_chain_id() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    let mut cases = Vec::new();
    for activation in [None, Some(31), Some(32), Some(33)] {
        for segwit in [0, 33] {
            for strict in [false, true] {
                let mut params = Params::REGTEST;
                params.auxpow_start_height = activation.map(BlockHeight::from_u32);
                params.segwit_height = BlockHeight::from_u32(segwit);
                params.strict_auxpow_chain_id = strict;
                let headers = history(&params, 32);
                let post = activation.is_some_and(|h| h <= 32);
                for version in [
                    0,
                    1,
                    2,
                    3,
                    4,
                    0x20000000,
                    0x20000004,
                    0x20008004,
                    0x20010004,
                    0x20000104,
                    0x20080104,
                    -1,
                    i32::MIN,
                ] {
                    let mut header = candidate(&headers);
                    header.version = Version::from_consensus(version);
                    let base = header.version.base_version();
                    let reason = if (!post && segwit <= 32 && version < 0x20000000) || base < 4 {
                        "bad-version"
                    } else if post
                        && strict
                        && !header.version.is_auxpow()
                        && (version & Version::MASK_AUXPOW_CHAINID_SHIFTED) != 0
                    {
                        "auxpow-chainid"
                    } else if post && !Version::is_valid_base_version(base) {
                        "bad-version"
                    } else {
                        ""
                    };
                    add_case(&mut cases, format!("activation={activation:?} segwit={segwit} strict={strict} version={version:#x}"),
                        &params, &headers, header, 1_700_010_000, reason.is_empty(), reason);
                }
            }
        }
    }
    check_cases(cases);
}

#[test]
fn original_contextual_header_time_and_difficulty_boundaries() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    let mut params = Params::REGTEST;
    params.enforce_bip94 = true;
    params.pow_target_timespan = 16 * params.pow_target_spacing;
    let mut headers = history(&params, 32);
    // A late tip makes the timewarp bound distinct from median time past.
    headers.last_mut().unwrap().time = BlockTime::from_u32(1_700_010_000);
    let base = candidate(&headers);
    let mut cases = Vec::new();
    for (time, expected, reason) in [
        (1_700_001_560, false, "time-too-old"),
        (1_700_009_399, false, "time-timewarp-attack"),
        (1_700_009_400, true, ""),
        (1_700_027_200, true, ""),
        (1_700_027_201, false, "time-too-new"),
    ] {
        let mut header = base.clone();
        header.time = BlockTime::from_u32(time);
        add_case(
            &mut cases,
            format!("timestamp={time}"),
            &params,
            &headers,
            header,
            1_700_020_000,
            expected,
            reason,
        );
    }
    let mut wrong = base.clone();
    wrong.bits = CompactTarget::from_consensus(base.bits.to_consensus() - 1);
    add_case(
        &mut cases,
        "wrong difficulty",
        &params,
        &headers,
        wrong,
        1_700_020_000,
        false,
        "bad-diffbits",
    );
    for active in [false, true] {
        let mut p = params.clone();
        p.enforce_bip94 = active;
        let mut h = base.clone();
        h.time = BlockTime::from_u32(1_700_009_399);
        add_case(
            &mut cases,
            format!("timewarp enabled={active}"),
            &p,
            &headers,
            h,
            1_700_020_000,
            !active,
            if active { "time-timewarp-attack" } else { "" },
        );
    }
    check_cases(cases);
}

#[test]
fn original_contextual_header_retarget_and_buried_deployment_boundaries() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    let mut cases = Vec::new();
    for network in
        [tidecoin::Network::Tidecoin, tidecoin::Network::Testnet, tidecoin::Network::Regtest]
    {
        for activation in [None, Some(32)] {
            for count in [31, 32, 33] {
                for delay in [60, 120, 121] {
                    let mut params = Params::new(network);
                    params.auxpow_start_height = activation.map(BlockHeight::from_u32);
                    params.pow_target_timespan = 16 * params.pow_target_spacing;
                    let mut headers = history(&params, count);
                    for h in &mut headers {
                        h.bits = CompactTarget::from_consensus(h.bits.to_consensus() - 0x10000);
                    }
                    // Reconnect hashes after changing historical difficulty.
                    for i in 1..headers.len() {
                        headers[i].prev_blockhash = headers[i - 1].block_hash();
                    }
                    let mut header = candidate(&headers);
                    header.version =
                        Version::from_consensus(if activation.is_some_and(|h| count >= h) {
                            4
                        } else {
                            0x20000004
                        });
                    header.time =
                        BlockTime::from_u32(headers.last().unwrap().time.to_u32() + delay);
                    header.bits = tidecoin::pow::next_target_after(
                        headers.last().unwrap().clone(),
                        BlockHeight::from_u32(count - 1),
                        &params,
                        Some(header.time.to_u32()),
                        |height| -> Result<Header, Infallible> {
                            Ok(headers[height.to_u32() as usize].clone())
                        },
                    )
                    .unwrap();
                    add_case(
                        &mut cases,
                        format!("retarget {network:?} {activation:?} height={count} delay={delay}"),
                        &params,
                        &headers,
                        header.clone(),
                        1_700_100_000,
                        true,
                        "",
                    );
                    header.bits = CompactTarget::from_consensus(header.bits.to_consensus() - 1);
                    add_case(
                        &mut cases,
                        "incorrect retarget",
                        &params,
                        &headers,
                        header,
                        1_700_100_000,
                        false,
                        "bad-diffbits",
                    );
                }
            }
        }
    }
    for deployment in [34, 66, 65] {
        for activation in [31, 32, 33] {
            let mut params = Params::REGTEST;
            params.auxpow_start_height = None;
            params.segwit_height = BlockHeight::from_u32(i32::MAX as u32);
            params.bip34_height = params.segwit_height;
            params.bip65_height = params.segwit_height;
            params.bip66_height = params.segwit_height;
            let height = BlockHeight::from_u32(activation);
            let minimum = match deployment {
                34 => {
                    params.bip34_height = height;
                    2
                }
                66 => {
                    params.bip66_height = height;
                    3
                }
                _ => {
                    params.bip65_height = height;
                    4
                }
            };
            let headers = history(&params, 32);
            for version in 1..=4 {
                let mut header = candidate(&headers);
                header.version = Version::from_consensus(version);
                let valid = activation > 32 || version >= minimum;
                add_case(
                    &mut cases,
                    format!("deployment={deployment} activation={activation} version={version}"),
                    &params,
                    &headers,
                    header,
                    1_700_010_000,
                    valid,
                    if valid { "" } else { "bad-version" },
                );
            }
        }
    }
    check_cases(cases);
}

fn auxpow_header() -> Header {
    use tidecoin::transaction::{TxIn, TxOut};
    use tidecoin::{absolute, Amount, Sequence, Transaction, Witness};
    let mut header = candidate(&history(&Params::REGTEST, 32));
    header.version = Version::with_base_version(4, 8).with_auxpow(true);
    let mut root = header.block_hash().to_byte_array();
    root.reverse();
    let mut script = vec![0xfa, 0xbe, 0x6d, 0x6d];
    script.extend(root);
    script.extend(1u32.to_le_bytes());
    script.extend(0u32.to_le_bytes());
    let tx = Transaction {
        version: tidecoin::transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![TxIn {
            script_sig: tidecoin::script::ScriptSigBuf::from_bytes(script),
            sequence: Sequence::MAX,
            witness: Witness::new(),
            ..TxIn::EMPTY_COINBASE
        }],
        outputs: vec![TxOut {
            amount: Amount::ZERO,
            script_pubkey: tidecoin::script::ScriptPubKeyBuf::new(),
        }],
    };
    let mut parent = header.clone();
    parent.version = Version::TWO;
    parent.merkle_root = tidecoin::block::compute_merkle_root(std::slice::from_ref(&tx)).unwrap();
    let target = tidecoin::pow::derive_target(header.bits, Params::REGTEST).unwrap();
    while !target.is_met_by(tidecoin::pow::scrypt_pow_hash(&parent)) {
        parent.nonce += 1;
    }
    header.auxpow = Some(Box::new(tidecoin::block::AuxPow {
        coinbase_tx: tx,
        merkle_branch: vec![],
        chain_merkle_branch: vec![],
        chain_index: 0,
        parent_block: parent,
    }));
    header
}

#[test]
fn original_auxpow_rejections_preserve_replaceable_proof_categories() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    let good = auxpow_header();
    let mut requests = Vec::new();
    let mut expected = Vec::new();
    for name in
        ["valid", "missing", "unexpected", "preactivation", "chainid", "commitment", "parent-pow"]
    {
        let mut header = good.clone();
        let mut params = Params::REGTEST;
        let mut request = json!({"op": "proof", "network": 2, "height": 32});
        let reason = match name {
            "valid" => "",
            "missing" => {
                header.auxpow = None;
                request["drop_auxpow"] = json!(true);
                "auxpow-missing"
            }
            "unexpected" => {
                header.version = header.version.with_auxpow(false);
                request["clear_auxpow_flag"] = json!(true);
                "auxpow-unexpected"
            }
            "preactivation" => {
                params.auxpow_start_height = Some(BlockHeight::from_u32(33));
                "auxpow-pre-activation"
            }
            "chainid" => {
                header.version = Version::with_base_version(4, 9).with_auxpow(true);
                "auxpow-chainid"
            }
            "commitment" => {
                header.auxpow.as_mut().unwrap().chain_index = 1;
                "auxpow-invalid"
            }
            _ => {
                let target = tidecoin::pow::derive_target(header.bits, &params).unwrap();
                let parent = &mut header.auxpow.as_mut().unwrap().parent_block;
                while target.is_met_by(tidecoin::pow::scrypt_pow_hash(parent)) {
                    parent.nonce += 1;
                }
                assert_eq!(good.block_hash(), header.block_hash());
                "auxpow-parent-pow"
            }
        };
        request["header"] =
            json!(hex(if matches!(name, "missing" | "unexpected") { &good } else { &header }));
        request["params"] = overrides(&params);
        let rust = tidecoin::pow::validate_auxpow_context(
            &header,
            &params,
            Some(BlockHeight::from_u32(32)),
        );
        expected.push((
            name,
            reason,
            rust.is_ok(),
            rust.err().is_some_and(|e| e.is_replaceable_proof()),
        ));
        requests.push(request);
    }
    let results = validation::run(&requests).unwrap();
    for ((name, reason, valid, mutated), node) in expected.into_iter().zip(results) {
        assert_eq!(node["valid"], valid, "{name}: {node}");
        assert_eq!(node["reason"], reason, "{name}: {node}");
        assert_eq!(node["mutated"], mutated, "{name}: {node}");
    }
}

#[test]
fn original_network_defaults_match_rust_without_oracle_overrides() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    let actual = validation::run(&[
        json!({"op": "params", "network": 0}),
        json!({"op": "params", "network": 1}),
        json!({"op": "params", "network": 2}),
    ])
    .unwrap();
    for (params, node) in
        [Params::MAINNET, Params::TESTNET, Params::REGTEST].into_iter().zip(actual)
    {
        let mut expected = overrides(&params);
        for (key, value) in json!({
            "genesis_scrypt": params.pow_genesis_scrypt, "chain_id": params.auxpow_chain_id,
            "subsidy_interval": params.subsidy_initial_interval,
            "pow_limit_compact": params.max_attainable_target.to_compact_lossy().to_consensus(),
            "target_spacing": params.pow_target_spacing, "allow_min_difficulty": params.allow_min_difficulty_blocks,
            "min_difficulty_after": params.pow_allow_min_difficulty_blocks_after_height.map(|h| h.to_u32()),
            "averaging_window": params.pow_averaging_window, "max_adjust_down": params.pow_max_adjust_down,
            "max_adjust_up": params.pow_max_adjust_up,
        }).as_object().unwrap() { expected[key] = value.clone(); }
        assert_eq!(node, expected, "network={:?}", params.network);
    }
}
