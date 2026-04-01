// SPDX-License-Identifier: CC0-1.0

extern crate serde_json;
extern crate tidecoin;

use std::str::FromStr;

use serde_json::Value;
use tidecoin::address::{Address, NetworkUnchecked};
use tidecoin::hex;
use tidecoin::{Network, WifKey};

fn parse_network(chain: &str) -> Network {
    match chain {
        "main" => Network::Tidecoin,
        "test" => Network::Testnet,
        "regtest" => Network::Regtest,
        unknown => panic!("unexpected chain in node vector: {unknown}"),
    }
}

#[test]
fn key_io_valid_vectors_match_tidecoin_node() {
    let vectors: Vec<(String, String, Value)> =
        serde_json::from_str(include_str!("data/key_io_valid.json")).unwrap();

    for (encoded, payload_hex, meta) in vectors {
        let network = parse_network(meta["chain"].as_str().unwrap());
        let is_privkey = meta["isPrivkey"].as_bool().unwrap();
        let is_compressed = meta["isCompressed"].as_bool().unwrap_or(false);

        if is_privkey {
            let wif = WifKey::from_str(&encoded).unwrap();
            let payload = hex::decode_to_array::<32>(&payload_hex).unwrap();

            assert_eq!(wif.network(), network, "wrong WIF network for {encoded}");
            assert_eq!(
                wif.private_key.as_inner().to_secret_bytes(),
                payload,
                "wrong secret bytes for {encoded}"
            );
            assert_eq!(
                wif.private_key.compressed(),
                is_compressed,
                "wrong compression flag for {encoded}"
            );
            assert_eq!(wif.to_wif(), encoded, "WIF round-trip changed for {encoded}");
        } else {
            let address = Address::<NetworkUnchecked>::from_str(&encoded)
                .unwrap()
                .require_network(network)
                .unwrap();
            let script_pubkey = hex::decode_to_vec(&payload_hex).unwrap();

            assert_eq!(
                address.script_pubkey().as_bytes(),
                script_pubkey.as_slice(),
                "wrong scriptPubKey for {encoded}"
            );
            assert_eq!(address.to_string(), encoded, "address round-trip changed for {encoded}");
        }
    }
}

#[test]
fn key_io_invalid_vectors_are_rejected() {
    let vectors: Vec<(String,)> =
        serde_json::from_str(include_str!("data/key_io_invalid.json")).unwrap();

    for (encoded,) in vectors {
        if encoded.is_empty() {
            assert!(WifKey::from_str(&encoded).is_err());
            assert!(Address::<NetworkUnchecked>::from_str(&encoded).is_err());
            continue;
        }

        assert!(
            WifKey::from_str(&encoded).is_err(),
            "invalid node vector parsed as WIF: {encoded}"
        );
        assert!(
            Address::<NetworkUnchecked>::from_str(&encoded).is_err(),
            "invalid node vector parsed as address: {encoded}"
        );
    }
}
