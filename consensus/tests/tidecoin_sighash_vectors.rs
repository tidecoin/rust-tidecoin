use consensus_core::SighashCache;
use encoding::decode_from_slice;
use primitives::{opcodes::all, script::ScriptBuf as PrimitiveScriptBuf, Transaction};

mod tidecoin_test_support;

use tidecoin_test_support::{parse_hex_bytes, read_fixture, try_harness};

type ScriptBuf = PrimitiveScriptBuf<()>;

fn to_fixture_hex(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect()
}

fn remove_op_codeseparator(script: &ScriptBuf) -> ScriptBuf {
    let bytes = script.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let start = i;
        let opcode = bytes[i];
        i += 1;

        let push_len = if opcode <= 0x4b {
            Some(opcode as usize)
        } else if opcode == all::OP_PUSHDATA1.to_u8() {
            if i >= bytes.len() {
                break;
            }
            let len = bytes[i] as usize;
            i += 1;
            Some(len)
        } else if opcode == all::OP_PUSHDATA2.to_u8() {
            if i + 1 >= bytes.len() {
                break;
            }
            let len = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
            i += 2;
            Some(len)
        } else if opcode == all::OP_PUSHDATA4.to_u8() {
            if i + 3 >= bytes.len() {
                break;
            }
            let len =
                u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
            i += 4;
            Some(len)
        } else {
            None
        };

        if let Some(len) = push_len {
            let end = i.saturating_add(len).min(bytes.len());
            out.extend_from_slice(&bytes[start..end]);
            i = end;
            continue;
        }

        if opcode != all::OP_CODESEPARATOR.to_u8() {
            out.push(opcode);
        }
    }
    ScriptBuf::from_bytes(out)
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
        let script_code =
            remove_op_codeseparator(&ScriptBuf::from_bytes(parse_hex_bytes(raw_script)));

        let got = SighashCache::new(&tx)
            .legacy_signature_hash(input_index, script_code.as_bytes(), hash_type)
            .expect("legacy sighash calculation");

        assert_eq!(
            to_fixture_hex(got.as_byte_array()),
            expected,
            "legacy sighash mismatch for hash_type={hash_type:#x} input={input_index}"
        );
    }
}
