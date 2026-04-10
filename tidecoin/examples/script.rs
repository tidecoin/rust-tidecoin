// SPDX-License-Identifier: CC0-1.0

//! Demonstrates the API for parsing and formatting Tidecoin scripts.
//!
//! Tidecoin script is conceptually a vector of bytes. As such it is consensus encoded with a
//! CompactSize length prefix.

use hex_unstable::DisplayHex as _;
use tidecoin::key::WPubkeyHash;
use tidecoin::{script, WitnessScriptBuf};

fn main() {
    let pk = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb".parse::<WPubkeyHash>().unwrap();

    // TL;DR Use `to_hex_string_prefixed` and `from_hex_prefixed`.
    let script_code = script::p2wpkh_script_code(pk);
    let hex = script_code.to_hex_string_prefixed();
    let decoded = WitnessScriptBuf::from_hex_prefixed(&hex).unwrap();
    assert_eq!(decoded, script_code);

    // Or if you prefer: `to_hex_string_no_length_prefix` and `from_hex_no_length_prefix`.
    let script_code = script::p2wpkh_script_code(pk);
    let hex = script_code.to_hex_string_no_length_prefix();
    let decoded = WitnessScriptBuf::from_hex_no_length_prefix(&hex).unwrap();
    assert_eq!(decoded, script_code);

    // Writes the script as human-readable eg, OP_DUP OP_HASH160 OP_PUSHBYTES_20 ...
    println!("human-readable script: {script_code}");

    // We do not implement parsing scripts from human-readable format.
    // let decoded = s.parse::<WitnessScriptBuf>().unwrap();

    // This is not equivalent to consensus encoding i.e., does not include the length prefix.
    let hex_lower_hex_trait = format!("{script_code:x}");
    println!("hex created using `LowerHex`: {hex_lower_hex_trait}");

    // Consensus decoding requires the length prefix.
    let bare_bytes = tidecoin::hex::decode_to_vec(&hex_lower_hex_trait).unwrap();
    assert!(encoding::decode_from_slice::<WitnessScriptBuf>(&bare_bytes).is_err());
    // And so does `from_hex_prefixed`.
    assert!(WitnessScriptBuf::from_hex_prefixed(&hex_lower_hex_trait).is_err());
    // But we provide an explicit constructor that does not.
    assert_eq!(
        WitnessScriptBuf::from_hex_no_length_prefix(&hex_lower_hex_trait).unwrap(),
        script_code
    );

    // This is consensus encoding i.e., includes the length prefix.
    let hex_inherent = script_code.to_hex_string_prefixed(); // Defined in `ScriptExt`.
    println!("hex created using inherent `to_hex_string_prefixed`: {hex_inherent}");

    // The inverse of `to_hex_string_prefixed` is `from_hex_prefixed`.
    let decoded = WitnessScriptBuf::from_hex_prefixed(&hex_inherent).unwrap(); // Defined in `ScriptBufExt`.
    assert_eq!(decoded, script_code);
    // We can also parse the output of `to_hex_string_prefixed` using consensus decoding.
    let decoded = encoding::decode_from_slice::<WitnessScriptBuf>(
        &tidecoin::hex::decode_to_vec(&hex_inherent).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded, script_code);

    // Consensus encoding includes the CompactSize length prefix.
    let encoded = encoding::encode_to_vec(&script_code).to_lower_hex_string();
    println!("hex created using consensus encoding: {encoded}");

    let decoded: WitnessScriptBuf =
        encoding::decode_from_slice(&tidecoin::hex::decode_to_vec(&encoded).unwrap()).unwrap();
    assert_eq!(decoded, script_code);

    // And we can mix these two calls because both include the length prefix.
    let encoded = encoding::encode_to_vec(&script_code).to_lower_hex_string();
    let decoded = WitnessScriptBuf::from_hex_prefixed(&encoded).unwrap();
    assert_eq!(decoded, script_code);

    // Encode/decode using a byte vector.
    let encoded = encoding::encode_to_vec(&script_code);
    assert_eq!(&encoded[1..], script_code.as_bytes()); // Shows that prefix is the first byte.
    let decoded: WitnessScriptBuf = encoding::decode_from_slice(&encoded).unwrap();
    assert_eq!(decoded, script_code);

    // to/from bytes excludes the prefix, these are not encoding/decoding functions so this is sane.
    let bytes = script_code.to_vec();
    let got = WitnessScriptBuf::from_bytes(bytes);
    assert_eq!(got, script_code);
}
