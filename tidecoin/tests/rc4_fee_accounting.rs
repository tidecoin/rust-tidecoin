// SPDX-License-Identifier: CC0-1.0
#![cfg(feature = "tidecoin-node-validation")]
//! Serialization evidence for the boundaries corrected in rc4 wallet funding.
//! Synthetic satisfactions measure size only; they do not establish spend validity,
//! wallet selection/change reconciliation, or caller/ancestor weight-limit enforcement.

use internals::hex::DisplayHex as _;
use node_parity::{validation, TidecoinNodeHarness};
use serde_json::{json, Value};
use tidecoin::script::{ScriptPubKeyBuf, ScriptSigBuf};
use tidecoin::transaction::{
    predict_weight, predict_weight_from_slices, InputWeightPrediction, TxInExt as _, Version,
};
use tidecoin::{
    absolute, Amount, FeeRate, OutPoint, PqScheme, PqSignatureSize, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};

fn hex(bytes: &[u8]) -> String {
    bytes.to_lower_hex_string()
}

// All PQ signatures and public keys here require PUSHDATA2. Construct the actual
// script independently of InputWeightPrediction::script_push_len.
fn push_pq(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() > 255);
    let mut script = vec![0x4d];
    script.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_le_bytes());
    script.extend_from_slice(bytes);
    script
}

fn input(scheme: PqScheme, mode: PqSignatureSize, kind: usize) -> (TxIn, InputWeightPrediction) {
    let sig = vec![0x42; mode.signature_len_in_script(Some(scheme))];
    let mut pk = vec![0x55; scheme.prefixed_pubkey_len()];
    pk[0] = scheme.prefix();
    let (script, witness, prediction) = match kind {
        0 => (
            [push_pq(&sig), push_pq(&pk)].concat(),
            Vec::new(),
            InputWeightPrediction::pq_non_witness_key_spend_with_mode(scheme, mode),
        ),
        1 => (Vec::new(), vec![sig, pk], InputWeightPrediction::pq_p2wpkh_with_mode(scheme, mode)),
        2 => (
            [vec![22, 0, 20], vec![0; 20]].concat(),
            vec![sig, pk],
            InputWeightPrediction::pq_nested_p2wpkh_with_mode(scheme, mode),
        ),
        3 => (
            Vec::new(),
            vec![sig, [push_pq(&pk), vec![0xac]].concat()],
            InputWeightPrediction::pq_witness_script_key_spend_with_mode(scheme, mode),
        ),
        _ => unreachable!(),
    };
    (
        TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([2; 32]), vout: 0 },
            script_sig: ScriptSigBuf::from_bytes(script),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&witness),
        },
        prediction,
    )
}

fn output(index: usize) -> TxOut {
    let bytes = match index % 5 {
        0 => [vec![0x76, 0xa9, 20], vec![0; 20], vec![0x88, 0xac]].concat(),
        1 => [vec![0xa9, 20], vec![0; 20], vec![0x87]].concat(),
        2 => [vec![0, 20], vec![0; 20]].concat(),
        3 => [vec![0, 32], vec![0; 32]].concat(),
        _ => [vec![0x51, 64], vec![0; 64]].concat(),
    };
    TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::from_bytes(bytes) }
}

fn weight_request(tx: &Transaction, rate: u32) -> Value {
    json!({"op":"tx_weight", "tx":hex(&encoding::encode_to_vec(tx)), "rate":rate})
}

#[test]
fn rc4_count_change_and_mixed_input_weights_match_node() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    for (scheme_index, scheme) in PqScheme::KNOWN.into_iter().enumerate() {
        for mode in [PqSignatureSize::LocalSigning, PqSignatureSize::Maximum] {
            // Legacy-only, witness-only, and mixed legacy/native-v0/wrapped-v0/v1
            // satisfactions. The mixed case also changes scheme and size mode per input.
            for layout in 0..3 {
                let mut requests = Vec::new();
                let mut expected = Vec::new();
                for (inputs, recipients) in [(252, 1), (253, 1), (1, 252), (1, 253), (253, 252)] {
                    let mut tx = Transaction {
                        version: Version::TWO,
                        lock_time: absolute::LockTime::ZERO,
                        inputs: Vec::new(),
                        outputs: (0..recipients).map(output).collect(),
                    };
                    let mut predictions = Vec::new();
                    for i in 0..inputs {
                        let (scheme, mode, kind) = if layout == 2 {
                            (
                                PqScheme::KNOWN[(scheme_index + i) % PqScheme::KNOWN.len()],
                                if i % 2 == 0 { mode } else { PqSignatureSize::Maximum },
                                i % 4,
                            )
                        } else {
                            (scheme, mode, layout)
                        };
                        let (mut input, prediction) = input(scheme, mode, kind);
                        input.previous_output.vout = u32::try_from(i).unwrap();
                        tx.inputs.push(input);
                        predictions.push(prediction);
                    }
                    let without_change = tx.weight();
                    for change in [false, true] {
                        if change {
                            let change_output = output(scheme_index);
                            let marginal = change_output.weight().to_wu()
                                + if recipients == 252 { 8 } else { 0 };
                            tx.outputs.push(change_output);
                            assert_eq!(tx.weight().to_wu(), without_change.to_wu() + marginal);
                        }
                        let lens = tx
                            .outputs
                            .iter()
                            .map(|out| out.script_pubkey.len())
                            .collect::<Vec<_>>();
                        let weight =
                            predict_weight(predictions.iter().copied(), lens.iter().copied());
                        assert_eq!(weight, predict_weight_from_slices(&predictions, &lens));
                        assert_eq!(weight, tx.weight());
                        let input_weights = tx
                            .inputs
                            .iter()
                            .map(|input| input.segwit_weight().to_wu())
                            .collect::<Vec<_>>();
                        for rate in [0, 1, 3702] {
                            requests.push(weight_request(&tx, rate));
                            expected.push((weight, input_weights.clone(), rate));
                        }
                    }
                }
                let results = validation::run(&requests).unwrap();
                for ((weight, input_weights, rate), result) in expected.into_iter().zip(results) {
                    let context =
                        format!("scheme={scheme:?} mode={mode:?} layout={layout} rate={rate}");
                    assert_eq!(result["weight"].as_u64().unwrap(), weight.to_wu(), "{context}");
                    assert_eq!(
                        result["vsize"].as_u64().unwrap(),
                        weight.to_vbytes_ceil(),
                        "{context}"
                    );
                    assert_eq!(result["input_weights"], json!(input_weights), "{context}");
                    let fee = FeeRate::from_sat_per_kvb(rate)
                        .mul_by_vsize(weight.to_vbytes_ceil())
                        .unwrap();
                    assert_eq!(result["rate_fee"].as_u64().unwrap(), fee.to_sat(), "{context}");
                }
            }
        }
    }
}

#[test]
fn rc4_input_weight_convention_preserves_single_wu_differences() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        inputs: Vec::new(),
        outputs: vec![output(0)],
    };
    // 173..176 WU all round to 44 vbytes. An explicit input budget must retain
    // these distinctions; comparing rounded vbytes cannot detect a 1..3 WU deficit.
    for size in 7..=10 {
        tx.inputs.push(TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([3; 32]), vout: size },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x42; size as usize]]),
        });
    }
    let legacy = TxIn { witness: Witness::new(), ..tx.inputs[0].clone() };
    assert_eq!(legacy.legacy_weight().to_wu(), 164);
    assert_eq!(legacy.segwit_weight().to_wu(), 165);
    assert_eq!(InputWeightPrediction::from_slice(0, &[]).total_weight().to_wu(), 164);
    tx.inputs.push(legacy);
    let result = validation::run(&[weight_request(&tx, 1000)]).unwrap().remove(0);
    assert_eq!(result["input_weights"], json!([173, 174, 175, 176, 165]));
    for input in &tx.inputs[..4] {
        assert_eq!(input.segwit_weight().to_vbytes_ceil(), 44);
    }
    assert_eq!(result["weight"].as_u64().unwrap(), tx.weight().to_wu());
}
