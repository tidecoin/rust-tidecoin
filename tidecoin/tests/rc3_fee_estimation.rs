// SPDX-License-Identifier: CC0-1.0
#![cfg(feature = "tidecoin-node-validation")]
//! Compare sizing modes and rounding with original node creators and serialization.
use node_parity::{validation, TidecoinNodeHarness};
use serde_json::json;
use tidecoin::ext::ScriptPubKeyExt as _;
use tidecoin::transaction::{predict_weight, InputWeightPrediction};
use tidecoin::{FeeRate, PqScheme, PqSignatureSize, ScriptPubKeyBuf};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn sizing_modes_match_original_dummy_creators_and_transaction_weights() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let mut requests = Vec::new();
    let mut expected = Vec::new();
    for scheme in PqScheme::KNOWN {
        let (pk, _) = node
            .pq_keypair_from_seed(
                scheme.prefix(),
                &vec![51; scheme.deterministic_seed_len()],
                scheme.pubkey_len(),
                scheme.seckey_len(),
            )
            .unwrap();
        let pubkey = [vec![scheme.prefix()], pk].concat();
        for mode in [PqSignatureSize::LocalSigning, PqSignatureSize::Maximum] {
            for (kind, prediction) in [
                ("pkh", InputWeightPrediction::pq_non_witness_key_spend_with_mode(scheme, mode)),
                ("wpkh", InputWeightPrediction::pq_p2wpkh_with_mode(scheme, mode)),
                ("sh-wpkh", InputWeightPrediction::pq_nested_p2wpkh_with_mode(scheme, mode)),
                ("wsh", InputWeightPrediction::pq_witness_script_key_spend_with_mode(scheme, mode)),
                (
                    "wsh512",
                    InputWeightPrediction::pq_witness_script_key_spend_with_mode(scheme, mode),
                ),
            ] {
                for (inputs, outputs, output_len) in [
                    (1, 1, 0),
                    (1, 1, 1),
                    (1, 1, 2),
                    (1, 1, 3),
                    (252, 1, 1),
                    (253, 1, 1),
                    (1, 252, 252),
                    (1, 253, 253),
                ] {
                    let weight = predict_weight(
                        core::iter::repeat_n(prediction, inputs),
                        core::iter::repeat_n(output_len, outputs),
                    );
                    for rate in [0, 1, 999, 1000, 1001, 3702] {
                        requests.push(json!({"op":"pq_estimate", "pubkey":hex(&pubkey),
                            "maximum":mode == PqSignatureSize::Maximum, "kind":kind,
                            "inputs":inputs, "outputs":outputs, "output_len":output_len, "rate":rate}));
                        expected.push((
                            mode.signature_len_in_script(Some(scheme)),
                            weight,
                            FeeRate::from_sat_per_kvb(rate)
                                .mul_by_vsize(weight.to_vbytes_ceil())
                                .unwrap(),
                        ));
                    }
                }
            }
            requests.push(json!({"op":"pq_estimate", "pubkey":hex(&pubkey), "unknown":true,
                "maximum":mode == PqSignatureSize::Maximum, "kind":"wpkh", "rate":0}));
            let sig_len = mode.signature_len_in_script(None);
            let weight = predict_weight(
                [InputWeightPrediction::pq_p2wpkh_with_sizes(sig_len, pubkey.len())],
                [1],
            );
            expected.push((sig_len, weight, tidecoin::Amount::ZERO));
        }
    }
    for ((request, (sig_len, weight, fee)), result) in
        requests.iter().zip(expected).zip(validation::run(&requests).unwrap())
    {
        assert_eq!(result["sig_len"].as_u64().unwrap(), sig_len as u64, "{request}");
        assert_eq!(result["weight"].as_u64().unwrap(), weight.to_wu(), "{request}");
        assert_eq!(result["vsize"].as_u64().unwrap(), weight.to_vbytes_ceil(), "{request}");
        assert_eq!(result["fee"].as_u64().unwrap(), fee.to_sat(), "{request}");
    }
}

#[test]
fn fee_dust_and_push_boundaries_match_original_node() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    let mut requests = Vec::new();
    let mut expected = Vec::new();
    for rate in [0, 1, 2, 3, 4, 999, 1000, 1001, 3702, 2_147_483_647] {
        for vsize in [0, 1, 3, 4, 999, 1000, 1001, 1_500_000] {
            requests.push(json!({"op":"fee", "rate":rate, "vsize":vsize}));
            expected.push((
                "fee",
                FeeRate::from_sat_per_kvb(rate).mul_by_vsize(vsize).unwrap().to_sat(),
            ));
        }
        for bytes in [
            vec![0x51],
            vec![0x6a],
            [vec![0x76, 0xa9, 20], vec![0x42; 20], vec![0x88, 0xac]].concat(),
            [vec![0xa9, 20], vec![0x42; 20], vec![0x87]].concat(),
            [vec![0, 20], vec![0x42; 20]].concat(),
            [vec![0, 32], vec![0x42; 32]].concat(),
            [vec![0x51, 64], vec![0x42; 64]].concat(),
            [vec![0x51, 32], vec![0x42; 32]].concat(),
        ] {
            let script = ScriptPubKeyBuf::from_bytes(bytes);
            requests.push(json!({"op":"dust", "script":hex(script.as_bytes()), "rate":rate}));
            expected.push((
                "dust",
                script.minimal_non_dust_custom(FeeRate::from_sat_per_kvb(rate)).unwrap().to_sat(),
            ));
        }
    }
    for size in [0, 1, 75, 76, 252, 253, 255, 256, 65535, 65536] {
        requests.push(json!({"op":"script_push", "size":size}));
        expected.push(("size", InputWeightPrediction::script_push_len(size) as u64));
    }
    for ((request, (field, expected)), result) in
        requests.iter().zip(expected).zip(validation::run(&requests).unwrap())
    {
        assert_eq!(result[field].as_u64().unwrap(), expected, "{request}");
    }
}
