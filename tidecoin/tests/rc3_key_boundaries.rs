// SPDX-License-Identifier: CC0-1.0
#![cfg(feature = "tidecoin-node-validation")]
//! Source-derived rc3 key and path boundaries against original C++ functions.
use node_parity::{validation, TidecoinNodeHarness};
use serde_json::json;
use tidecoin::{pqhd, MlKem512PublicKey, Network, PqPublicKey, PqScheme, PqSecretKey, PqWifKey};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn pqhd_path_boundaries_match_original_validator() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    let h = pqhd::HARDENED;
    let mut paths = Vec::new();
    for purpose in [10007, 10044, 10049, 10084, 10087, 10086, 10088, 0] {
        for coin in [1, 6868, 0, 6869] {
            for scheme in [7, 8, 9, 10, 11, 6, 12, 263] {
                for change in [0, 1, 2] {
                    paths.push(vec![h | purpose, h | coin, h | scheme, h, h | change, u32::MAX]);
                }
            }
        }
    }
    let valid = vec![h | 10084, h | 1, h | 7, h, h, h];
    for i in 0..6 {
        let mut path = valid.clone();
        path[i] &= !h;
        paths.push(path);
    }
    paths.push(valid[..5].to_vec());
    paths.push([valid.as_slice(), &[h]].concat());
    let requests =
        paths.iter().map(|path| json!({"op":"pqhd_path", "path":path})).collect::<Vec<_>>();
    for (path, result) in paths.iter().zip(validation::run(&requests).unwrap()) {
        assert_eq!(
            pqhd::validate_v1_leaf_path(path),
            result["valid"].as_bool().unwrap(),
            "{path:?}"
        );
        if pqhd::validate_v1_leaf_path(path) {
            let master = pqhd::make_master_node(&[42; 32]);
            let leaf = pqhd::derive_path(path, &master).unwrap();
            let stream = pqhd::derive_keygen_stream_key(&leaf.node_secret, path).unwrap();
            assert_eq!(hex(stream.as_bytes()), result["stream"].as_str().unwrap(), "{path:?}");
        }
    }
}

#[test]
fn falcon_public_key_full_encoding_matches_node() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let mut cases = Vec::new();
    for scheme in [PqScheme::Falcon512, PqScheme::Falcon1024] {
        let (pk, _) = node
            .pq_keypair_from_seed(
                scheme.prefix(),
                &vec![23; scheme.deterministic_seed_len()],
                scheme.pubkey_len(),
                scheme.seckey_len(),
            )
            .unwrap();
        let prefixed = [vec![scheme.prefix()], pk].concat();
        cases.push(prefixed.clone());
        for header in [0, 9, 10, 0xff] {
            let mut b = prefixed.clone();
            b[1] = header;
            cases.push(b);
        }
        // Public coefficients are packed as 14-bit integers; q=12289.
        for value in [0u16, 12288, 12289, 16383] {
            for index in [0, (scheme.pubkey_len() - 1) * 8 / 14 - 1] {
                let mut b = prefixed.clone();
                for bit in 0..14 {
                    let pos = index * 14 + bit;
                    let mask = 1 << (7 - pos % 8);
                    b[2 + pos / 8] =
                        (b[2 + pos / 8] & !mask) | ((((value >> (13 - bit)) & 1) as u8) * mask);
                }
                cases.push(b);
            }
        }
    }
    let requests =
        cases.iter().map(|b| json!({"op":"pubkey_valid", "bytes":hex(b)})).collect::<Vec<_>>();
    for (b, result) in cases.iter().zip(validation::run(&requests).unwrap()) {
        assert_eq!(
            PqPublicKey::from_prefixed_slice(b).unwrap().is_fully_valid(),
            result["valid"].as_bool().unwrap()
        );
    }
}

#[test]
fn mlkem_encapsulation_canonical_coefficients_match_node() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let (pk, _) = node.mlkem512_keypair_from_coins(&[32; 64], 800, 1632).unwrap();
    for index in [0, 1, 255, 256, 510, 511] {
        for value in [0u16, 3328, 3329, 4095] {
            let mut bytes = pk.clone();
            for bit in 0..12 {
                let pos = index * 12 + bit;
                let mask = 1 << (pos % 8);
                bytes[pos / 8] = (bytes[pos / 8] & !mask) | ((((value >> bit) & 1) as u8) * mask);
            }
            let rust =
                MlKem512PublicKey::from_slice(&bytes).unwrap().encapsulate_deterministic(&[17; 32]);
            let cpp = node.mlkem512_encaps_deterministic(&bytes, &[17; 32], 768, 32);
            assert_eq!(rust.is_ok(), value < 3329, "coefficient {index}={value}");
            assert_eq!(rust.is_ok(), cpp.is_ok());
            if let (Ok((ct, ss)), Ok((nct, nss))) = (rust, cpp) {
                assert_eq!(ct.as_bytes(), nct);
                assert_eq!(ss.as_bytes().as_slice(), nss);
            }
        }
    }
    let mut bytes = pk;
    bytes[768..].fill(0xff); // The seed is unrestricted, not a polynomial coefficient.
    let (ct, ss) = MlKem512PublicKey::from_slice(&bytes)
        .unwrap()
        .encapsulate_deterministic(&[17; 32])
        .unwrap();
    let (nct, nss) = node.mlkem512_encaps_deterministic(&bytes, &[17; 32], 768, 32).unwrap();
    assert_eq!(ct.as_bytes(), nct);
    assert_eq!(ss.as_bytes().as_slice(), nss);
}

#[test]
fn historical_and_prefixed_wif_match_original_import_and_export() {
    let Some(node) = TidecoinNodeHarness::optional_from_env() else { return };
    let (_, sk) = node
        .pq_keypair_from_seed(7, &vec![34; PqScheme::Falcon512.deterministic_seed_len()], 897, 1281)
        .unwrap();
    for (network, number) in [(Network::Tidecoin, 0), (Network::Testnet, 1), (Network::Regtest, 2)]
    {
        let secret = PqSecretKey::from_slice(PqScheme::Falcon512, &sk).unwrap();
        let prefixed = PqWifKey::new(secret.clone(), network).unwrap().to_wif();
        let legacy = PqWifKey::new_legacy_falcon512(secret, network).unwrap().to_wif();
        let decoded = base58::decode_check(&legacy).unwrap();
        let mut raw = vec![decoded[0]];
        raw.extend_from_slice(&sk);
        let mut marked = raw.clone();
        marked.push(1);
        let mut wrong_key = decoded.clone();
        *wrong_key.last_mut().unwrap() ^= 1;
        let mut wrong_tag = decoded.clone();
        wrong_tag[1282] = 0;
        let mut rc2 = decoded.clone();
        rc2.insert(1283, 7);
        let mut prefixed_marker = base58::decode_check(&prefixed).unwrap();
        prefixed_marker.push(1);
        let cases = [
            (prefixed.clone(), true),
            (legacy.clone(), true),
            (base58::encode_check(&raw), true),
            (base58::encode_check(&marked), true),
            (base58::encode_check(&wrong_key), false),
            (base58::encode_check(&wrong_tag), false),
            (base58::encode_check(&rc2), false),
            (base58::encode_check(&prefixed_marker), false),
        ];
        let requests = cases
            .iter()
            .map(|(wif, _)| json!({"op":"wif", "network":number,"wif":wif}))
            .collect::<Vec<_>>();
        for ((wif, valid), result) in cases.iter().zip(validation::run(&requests).unwrap()) {
            assert_eq!(result["valid"], *valid);
            let rust = PqWifKey::from_wif(wif);
            assert_eq!(rust.is_ok(), *valid);
            if let Ok(key) = rust {
                assert_eq!(key.secret_key.as_bytes(), sk);
                assert_eq!(result["prefixed"], prefixed);
                assert_eq!(result["legacy"], legacy);
            }
        }
    }
}

#[test]
fn default_descriptors_separate_families_and_networks() {
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    use tidecoin::key_expression::{
        generate_pqhd_wallet_descriptor, PqhdDescriptor, WalletOutputType,
    };
    use tidecoin::network::Params;
    let families = [
        (WalletOutputType::Legacy, 10044),
        (WalletOutputType::P2shSegwit, 10049),
        (WalletOutputType::Bech32, 10084),
        (WalletOutputType::Bech32Pq, 10087),
    ];
    let seed_id = pqhd::SeedId::compute(&[42; 32]);
    let mut requests = Vec::new();
    let mut streams = Vec::new();
    for params in [Params::MAINNET, Params::TESTNET, Params::REGTEST] {
        let height = params.auxpow_start_height.map(|h| h.to_u32()).unwrap_or(0);
        for (family, purpose) in families {
            for internal in [false, true] {
                let generated = generate_pqhd_wallet_descriptor(
                    seed_id,
                    PqScheme::Falcon512,
                    family,
                    internal,
                    &params,
                    height,
                );
                if family == WalletOutputType::Bech32Pq && params.auxpow_start_height.is_none() {
                    assert!(generated.is_err());
                    continue;
                }
                let descriptor: PqhdDescriptor = generated.unwrap().parse().unwrap();
                let path = descriptor.key_expression().leaf_path(Some(23)).unwrap();
                assert_eq!(path[0], purpose | pqhd::HARDENED);
                assert_eq!(
                    path[1],
                    pqhd::HARDENED | if params.network == Network::Tidecoin { 6868 } else { 1 }
                );
                assert_eq!(path[4], pqhd::HARDENED | u32::from(internal));
                let master = pqhd::make_master_node(&[42; 32]);
                let leaf = pqhd::derive_path(&path, &master).unwrap();
                streams.push(hex(pqhd::derive_keygen_stream_key(&leaf.node_secret, &path)
                    .unwrap()
                    .as_bytes()));
                requests.push(json!({"op":"pqhd_path","path":path}));
            }
        }
    }
    for (result, stream) in validation::run(&requests).unwrap().iter().zip(streams) {
        assert_eq!(result["stream"], stream);
    }
}
