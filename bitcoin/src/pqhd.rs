// SPDX-License-Identifier: CC0-1.0

//! Tidecoin PQHD derivation primitives.
//!
//! This module mirrors Tidecoin node's PQHD v1 KDF and path validation logic.

use core::fmt;
use core::str::FromStr;

use hashes::{sha256, sha512, Hash as _, HashEngine as _, HmacEngine};

use crate::crypto::pq::PqScheme;

/// PQHD v1 purpose constant.
pub const PURPOSE: u32 = 10_007;
/// PQHD v1 coin type constant.
pub const COIN_TYPE: u32 = 6_868;
/// Hardened-bit mask used for PQHD path elements.
pub const HARDENED: u32 = 0x8000_0000;

const PQHD_MASTER_KEY: &[u8] = b"Tidecoin PQHD seed";
const PQHD_HKDF_SALT: &[u8] = b"Tidecoin PQHD hkdf v1";
const PQHD_STREAM_INFO: &[u8] = b"Tidecoin PQHD stream key v1";
const PQHD_RNG_PREFIX: &[u8] = b"Tidecoin PQHD rng v1";
const PQHD_SEEDID_TAG: &[u8] = b"Tidecoin PQHD seedid v1";
const V1_PATH_LEN: usize = 6;

/// Canonical SeedID32 bytes.
///
/// Internally this keeps the canonical big-endian digest order used by the node's
/// human-readable `uint256::ToString()` representation. PSBT proprietary records
/// serialize the node's `uint256` storage layout, available through
/// [`SeedId::to_storage_bytes`].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SeedId(sha256::Hash);

impl SeedId {
    /// Computes `SHA256("Tidecoin PQHD seedid v1" || master_seed)`.
    pub fn compute(master_seed: &[u8; 32]) -> Self {
        let mut engine = sha256::Hash::engine();
        engine.input(PQHD_SEEDID_TAG);
        engine.input(master_seed);
        Self(sha256::Hash::from_engine(engine))
    }

    /// Constructs a seed id from canonical bytes.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Self { Self(sha256::Hash::from_byte_array(bytes)) }

    /// Constructs a seed id from the node's internal `uint256` storage bytes.
    pub fn from_storage_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        Self::from_canonical_bytes(bytes)
    }

    /// Returns canonical bytes.
    pub fn to_canonical_bytes(self) -> [u8; 32] { self.0.to_byte_array() }

    /// Returns the node's internal `uint256` storage bytes.
    pub fn to_storage_bytes(self) -> [u8; 32] {
        let mut bytes = self.to_canonical_bytes();
        bytes.reverse();
        bytes
    }
}

impl fmt::Display for SeedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl FromStr for SeedId {
    type Err = crate::hex::DecodeFixedLengthBytesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::hex::decode_to_array::<32>(s).map(Self::from_canonical_bytes)
    }
}

/// A PQHD node secret and chain code pair.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Node {
    /// The PQHD node secret.
    pub node_secret: [u8; 32],
    /// The PQHD chain code.
    pub chain_code: [u8; 32],
}

/// Leaf material for a validated PQHD v1 leaf.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct LeafMaterialV1 {
    /// The PQ scheme encoded in the leaf path.
    pub scheme: PqScheme,
    /// The derived 64-byte stream key.
    pub stream_key: [u8; 64],
}

/// Computes the PQHD master node from a master seed.
pub fn make_master_node(master_seed: &[u8; 32]) -> Node {
    let hmac = hmac_sha512(PQHD_MASTER_KEY, master_seed);
    let mut node_secret = [0_u8; 32];
    let mut chain_code = [0_u8; 32];
    node_secret.copy_from_slice(&hmac[..32]);
    chain_code.copy_from_slice(&hmac[32..]);
    Node { node_secret, chain_code }
}

/// Derives a hardened-only child node.
pub fn derive_child(parent: &Node, index_hardened: u32) -> Option<Node> {
    if index_hardened & HARDENED == 0 {
        return None;
    }

    let mut data = [0_u8; 1 + 32 + 4];
    data[1..33].copy_from_slice(&parent.node_secret);
    data[33..].copy_from_slice(&ser32be(index_hardened));

    let hmac = hmac_sha512(&parent.chain_code, &data);
    let mut node_secret = [0_u8; 32];
    let mut chain_code = [0_u8; 32];
    node_secret.copy_from_slice(&hmac[..32]);
    chain_code.copy_from_slice(&hmac[32..]);
    Some(Node { node_secret, chain_code })
}

/// Derives a hardened PQHD path.
pub fn derive_path(path_hardened: &[u32], master: &Node) -> Option<Node> {
    let mut node = *master;
    for &index in path_hardened {
        node = derive_child(&node, index)?;
    }
    Some(node)
}

/// Validates a PQHD v1 leaf path.
pub fn validate_v1_leaf_path(path_hardened: &[u32]) -> bool {
    if path_hardened.len() != V1_PATH_LEN {
        return false;
    }
    if path_hardened.iter().any(|elem| elem & HARDENED == 0) {
        return false;
    }
    if path_hardened[0] != HARDENED | PURPOSE {
        return false;
    }
    if path_hardened[1] != HARDENED | COIN_TYPE {
        return false;
    }

    let scheme_u32 = path_hardened[2] & !HARDENED;
    if scheme_u32 > u32::from(u8::MAX) {
        return false;
    }
    if PqScheme::from_prefix(scheme_u32 as u8).is_none() {
        return false;
    }

    let change = path_hardened[4] & !HARDENED;
    change <= 1
}

/// Derives the validated PQHD v1 leaf material.
pub fn derive_leaf_material_v1(
    node_secret_leaf: &[u8; 32],
    path_hardened: &[u32],
) -> Option<LeafMaterialV1> {
    if !validate_v1_leaf_path(path_hardened) {
        return None;
    }

    let scheme = PqScheme::from_prefix((path_hardened[2] & !HARDENED) as u8)
        .expect("validated path contains a supported 1-byte scheme");
    let prk = hmac_sha512(PQHD_HKDF_SALT, node_secret_leaf);

    let mut engine = HmacEngine::<sha512::HashEngine>::new(&prk);
    engine.input(PQHD_STREAM_INFO);
    engine.input(&ser32be(u32::from(scheme.prefix())));
    for &elem in path_hardened {
        engine.input(&ser32be(elem));
    }
    engine.input(&[0x01]);

    Some(LeafMaterialV1 { scheme, stream_key: engine.finalize().to_byte_array() })
}

/// Derives the PQHD v1 keygen stream key.
pub fn derive_keygen_stream_key(
    node_secret_leaf: &[u8; 32],
    path_hardened: &[u32],
) -> Option<[u8; 64]> {
    derive_leaf_material_v1(node_secret_leaf, path_hardened).map(|material| material.stream_key)
}

/// Derives a single 64-byte stream block from a keygen stream key and counter.
pub fn derive_keygen_stream_block(stream_key: &[u8; 64], ctr: u32) -> [u8; 64] {
    let mut engine = HmacEngine::<sha512::HashEngine>::new(stream_key);
    engine.input(PQHD_RNG_PREFIX);
    engine.input(&ser32be(ctr));
    engine.finalize().to_byte_array()
}

/// Constructs a PQHD v1 leaf path.
pub fn make_v1_leaf_path(scheme: PqScheme, account: u32, change: u32, index: u32) -> [u32; 6] {
    [
        HARDENED | PURPOSE,
        HARDENED | COIN_TYPE,
        HARDENED | u32::from(scheme.prefix()),
        HARDENED | account,
        HARDENED | change,
        HARDENED | index,
    ]
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut engine = HmacEngine::<sha512::HashEngine>::new(key);
    engine.input(msg);
    engine.finalize().to_byte_array()
}

fn ser32be(value: u32) -> [u8; 4] { value.to_be_bytes() }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::DisplayHex;
    use crate::prelude::String;
    use crate::prelude::ToString;

    fn decode_array<const N: usize>(hex: &str) -> [u8; N] {
        crate::hex::decode_to_array::<N>(hex).unwrap()
    }

    fn hex(bytes: &[u8]) -> String { bytes.as_hex().to_string() }

    #[test]
    fn vectors_master_seed_0() {
        let master_seed =
            decode_array::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        let seedid = SeedId::compute(&master_seed);
        assert_eq!(seedid.to_string(), "13f45473287a2920f659a303dfc449ab5bf97cba2e23024c61439348ae0eb602");

        let master = make_master_node(&master_seed);
        assert_eq!(
            hex(&master.node_secret),
            "9f46d25ef75d6dd7e5af0e0e88351e80792962fbc8fe936f8685db6aa42edc96"
        );
        assert_eq!(
            hex(&master.chain_code),
            "7238ac4acb263a6caa7728529d899aebd8fdafdd9f232664bb6894cb79b143b8"
        );
    }

    #[test]
    fn seedid_storage_roundtrip_matches_node() {
        let master_seed =
            decode_array::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let seedid = SeedId::compute(&master_seed);
        let roundtrip = SeedId::from_storage_bytes(seedid.to_storage_bytes());
        assert_eq!(seedid, roundtrip);
    }

    #[test]
    fn vectors_leaf_falcon512_receive_0() {
        let master_seed =
            decode_array::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let master = make_master_node(&master_seed);
        let path = make_v1_leaf_path(PqScheme::Falcon512, 0, 0, 0);

        let leaf = derive_path(&path, &master).unwrap();
        assert_eq!(
            hex(&leaf.node_secret),
            "6a314c506be113c29cdfde990b32494205789711f93e8b435bc42d11177ed6a9"
        );
        assert_eq!(
            hex(&leaf.chain_code),
            "6333f60d7b7636d6bb0d76adeec9392461f511f4d29877b48fe0738d4aed8418"
        );

        let stream_key = derive_keygen_stream_key(&leaf.node_secret, &path).unwrap();
        assert_eq!(
            hex(&stream_key),
            concat!(
                "1d28d7fc52b10ad564be42667eea7830ffddcd9beb7666966c9e7fd1f0c6769d",
                "90da93994e186053b4fe6655e9b79aa19306b0994af09d6b77ae141f88cac2e8"
            )
        );

        let block0 = derive_keygen_stream_block(&stream_key, 0);
        assert_eq!(
            hex(&block0),
            concat!(
                "a826fbc6d97bb72b34628430561b572aca14b6281caeb4fd9fa6b9295f1d711f",
                "4bbcd9f1d3697afda50b9889216634edc8a4ea7b18126cdc0d754b853474ebd2"
            )
        );

        let block1 = derive_keygen_stream_block(&stream_key, 1);
        assert_eq!(
            hex(&block1),
            concat!(
                "979d62443c10984b5b05af367181c33bb39541b9a1841896858c4df39c5c2347",
                "e7a452264c58eb756c9bc869106cdf76b8e4615b950cd1608b5052049a220719"
            )
        );
    }

    #[test]
    fn vectors_leaf_mldsa65_change_5() {
        let master_seed =
            decode_array::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let master = make_master_node(&master_seed);
        let path = make_v1_leaf_path(PqScheme::MlDsa65, 2, 1, 5);

        let leaf = derive_path(&path, &master).unwrap();
        assert_eq!(
            hex(&leaf.node_secret),
            "632ed8f96d5addcf359e80ce43977034b666ab468c0023f9143ae1bea78341df"
        );
        assert_eq!(
            hex(&leaf.chain_code),
            "58f87112c1632aac4da7dfaea6f8f377733fff977fdf4b6b473d55109c9d1da6"
        );

        let stream_key = derive_keygen_stream_key(&leaf.node_secret, &path).unwrap();
        assert_eq!(
            hex(&stream_key),
            concat!(
                "d84fe3ee51ac4f613ba55b2357c5ab18bf2397709844fdba2a3ee1a3b8041130",
                "4bb08b20e73508a958e7fc08c1005f75770542d951979a365b869742a953774b"
            )
        );

        let block0 = derive_keygen_stream_block(&stream_key, 0);
        assert_eq!(
            hex(&block0),
            concat!(
                "980181e20ecf0e7cba979df337b300b35299d52ad75fae9b4154c43b72315263",
                "0daeab708aac355f660677f142052cd68b35a9f9d6fdba772fe62e63279cd0eb"
            )
        );
    }

    #[test]
    fn rejects_non_hardened_inputs() {
        let master_seed =
            decode_array::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let master = make_master_node(&master_seed);
        assert!(derive_path(&[PURPOSE], &master).is_none());

        let mut path = make_v1_leaf_path(PqScheme::Falcon512, 0, 0, 0);
        let leaf = derive_path(&path, &master).unwrap();
        path[4] = 0;
        assert!(derive_keygen_stream_key(&leaf.node_secret, &path).is_none());
    }

    #[test]
    fn validate_v1_leaf_path_rejects_wrong_shape() {
        let good = make_v1_leaf_path(PqScheme::Falcon512, 0, 0, 0);
        assert!(validate_v1_leaf_path(&good));

        assert!(!validate_v1_leaf_path(&good[..5]));

        let mut bad_purpose = good;
        bad_purpose[0] = HARDENED | (PURPOSE + 1);
        assert!(!validate_v1_leaf_path(&bad_purpose));

        let mut bad_coin = good;
        bad_coin[1] = HARDENED | (COIN_TYPE + 1);
        assert!(!validate_v1_leaf_path(&bad_coin));

        let mut bad_change = good;
        bad_change[4] = HARDENED | 2;
        assert!(!validate_v1_leaf_path(&bad_change));
    }

    #[test]
    fn rejects_scheme_element_out_of_range() {
        let master_seed =
            decode_array::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let master = make_master_node(&master_seed);
        let path = [
            HARDENED | PURPOSE,
            HARDENED | COIN_TYPE,
            HARDENED | 0x1FF,
            HARDENED,
            HARDENED,
            HARDENED,
        ];

        let leaf = derive_path(&path, &master).unwrap();
        assert!(derive_keygen_stream_key(&leaf.node_secret, &path).is_none());
    }

    #[test]
    fn rejects_unknown_scheme() {
        let master_seed =
            decode_array::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let master = make_master_node(&master_seed);
        let path = [
            HARDENED | PURPOSE,
            HARDENED | COIN_TYPE,
            HARDENED | 0x01,
            HARDENED,
            HARDENED,
            HARDENED,
        ];

        let leaf = derive_path(&path, &master).unwrap();
        assert!(derive_keygen_stream_key(&leaf.node_secret, &path).is_none());
    }

    #[test]
    fn rejects_change_domain_outside_receive_or_change() {
        let master_seed =
            decode_array::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let master = make_master_node(&master_seed);
        let path = make_v1_leaf_path(PqScheme::Falcon512, 0, 2, 0);

        let leaf = derive_path(&path, &master).unwrap();
        assert!(derive_keygen_stream_key(&leaf.node_secret, &path).is_none());
    }
}
