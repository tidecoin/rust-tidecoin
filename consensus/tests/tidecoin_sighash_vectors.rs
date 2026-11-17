use consensus_core::SighashCache;
use encoding::decode_from_slice;
use primitives::Transaction;

mod tidecoin_test_support;

use tidecoin_test_support::{parse_hex_bytes, read_fixture, try_harness};

fn to_fixture_hex(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn tidecoin_node_sighash_vectors_legacy() {
    if try_harness().is_none() {
        eprintln!("skipping Tidecoin sighash vector test: TIDECOIN_NODE_REPO is not configured");
        return;
    }

    let vectors = read_fixture("sighash.json");
    for case in vectors {
        let arr = match case.as_array() {
            Some(value) => value,
            None => continue,
        };
        if arr.len() == 1 && arr[0].is_string() {
            continue;
        }
        if arr.len() < 5 {
            continue;
        }

        let raw_tx = arr[0].as_str().expect("raw tx must be string");
        let raw_script = arr[1].as_str().expect("script must be string");
        let input_index = arr[2].as_i64().expect("input index must be integer") as usize;
        let hash_type = arr[3].as_i64().expect("hash type must be integer") as u32;
        let expected = arr[4].as_str().expect("expected hash must be string");

        let tx_bytes = parse_hex_bytes(raw_tx);
        let tx: Transaction =
            decode_from_slice(&tx_bytes).unwrap_or_else(|e| panic!("invalid tx fixture: {e}"));
        // Raw script code, as the node test passes it to SignatureHash: the
        // Rust digest removes OP_CODESEPARATOR during serialization too.
        let script_code = parse_hex_bytes(raw_script);

        let got = SighashCache::new(&tx)
            .legacy_signature_hash(input_index, &script_code, hash_type)
            .expect("legacy sighash calculation");

        assert_eq!(
            to_fixture_hex(got.as_byte_array()),
            expected,
            "legacy sighash mismatch for hash_type={hash_type:#x} input={input_index}"
        );
    }
}
