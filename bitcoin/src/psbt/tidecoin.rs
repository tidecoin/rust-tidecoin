// SPDX-License-Identifier: CC0-1.0

//! Tidecoin-specific PSBT proprietary helpers.

use crate::crypto::pq::{PqPublicKey, PqSignature};
use crate::pqhd::{self, SeedId};
use crate::prelude::{btree_map, BTreeMap, Vec};
use crate::psbt::map::{Input, Output};
use crate::psbt::raw;
use crate::consensus::encode::{Decodable, Encodable};

/// Tidecoin proprietary PSBT identifier.
pub const PROPRIETARY_IDENTIFIER: &[u8] = b"tidecoin";
/// Tidecoin proprietary subtype for PQHD origin metadata.
pub const SUBTYPE_PQHD_ORIGIN: u64 = 0x01;
/// Tidecoin proprietary subtype for PQ partial signatures.
pub const SUBTYPE_PQ_PARTIAL_SIGNATURE: u64 = 0x02;
const V1_PATH_LEN: usize = 6;

/// Decoded Tidecoin PQHD origin metadata.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PqhdOrigin {
    /// Prefixed PQ public key bytes.
    pub pubkey: PqPublicKey,
    /// Canonical seed id.
    pub seed_id: SeedId,
    /// Hardened-only PQHD v1 path.
    pub path_hardened: Vec<u32>,
}

/// Decoded Tidecoin PQ partial signature metadata for a PSBT input.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PqPartialSignature {
    /// Prefixed PQ public key bytes.
    pub pubkey: PqPublicKey,
    /// Raw PQ signature bytes.
    pub signature: PqSignature,
}

impl Input {
    /// Adds a Tidecoin PQHD origin record for this input.
    pub fn add_pqhd_origin(
        &mut self,
        pubkey: &PqPublicKey,
        seed_id: SeedId,
        path_hardened: &[u32],
    ) -> bool {
        add_pqhd_origin(&mut self.proprietary, pubkey, seed_id, path_hardened)
    }

    /// Returns decoded Tidecoin PQHD origin records on this input.
    pub fn pqhd_origins(&self) -> Vec<PqhdOrigin> {
        self.proprietary.iter().filter_map(|(key, value)| decode_pqhd_origin(key, value)).collect()
    }

    /// Adds a Tidecoin PQ partial signature record for this input.
    pub fn add_pq_partial_signature(
        &mut self,
        pubkey: &PqPublicKey,
        signature: &PqSignature,
    ) -> bool {
        add_pq_partial_signature(&mut self.proprietary, pubkey, signature)
    }

    /// Returns decoded Tidecoin PQ partial signatures on this input.
    pub fn pq_partial_signatures(&self) -> Vec<PqPartialSignature> {
        self.proprietary
            .iter()
            .filter_map(|(key, value)| decode_pq_partial_signature(key, value))
            .collect()
    }
}

impl Output {
    /// Adds a Tidecoin PQHD origin record for this output.
    pub fn add_pqhd_origin(
        &mut self,
        pubkey: &PqPublicKey,
        seed_id: SeedId,
        path_hardened: &[u32],
    ) -> bool {
        add_pqhd_origin(&mut self.proprietary, pubkey, seed_id, path_hardened)
    }

    /// Returns decoded Tidecoin PQHD origin records on this output.
    pub fn pqhd_origins(&self) -> Vec<PqhdOrigin> {
        self.proprietary.iter().filter_map(|(key, value)| decode_pqhd_origin(key, value)).collect()
    }
}

/// Builds a Tidecoin PQHD origin record value.
pub fn make_pqhd_origin_value(seed_id: SeedId, path_hardened: &[u32]) -> Vec<u8> {
    let mut value = Vec::with_capacity(32 + 9 + path_hardened.len() * 4);
    value.extend_from_slice(&seed_id.to_storage_bytes());
    path_hardened.consensus_encode(&mut value).expect("in-memory writers do not fail");
    value
}

/// Decodes a Tidecoin PQHD origin record if the key and value are valid.
pub fn decode_pqhd_origin(key: &raw::ProprietaryKey, value: &[u8]) -> Option<PqhdOrigin> {
    if key.prefix != PROPRIETARY_IDENTIFIER {
        return None;
    }
    if key.subtype != SUBTYPE_PQHD_ORIGIN {
        return None;
    }

    let pubkey = PqPublicKey::from_prefixed_slice(&key.key).ok()?;

    let mut reader = value;
    let seed_id = SeedId::from_storage_bytes(<[u8; 32]>::consensus_decode(&mut reader).ok()?);
    let path_hardened = Vec::<u32>::consensus_decode(&mut reader).ok()?;
    if !reader.is_empty() {
        return None;
    }
    if path_hardened.len() != V1_PATH_LEN {
        return None;
    }
    if !pqhd::validate_v1_leaf_path(&path_hardened) {
        return None;
    }
    if (path_hardened[2] & !pqhd::HARDENED) as u8 != pubkey.scheme().prefix() {
        return None;
    }

    Some(PqhdOrigin { pubkey, seed_id, path_hardened })
}

/// Adds a Tidecoin PQHD origin record to a proprietary map.
pub fn add_pqhd_origin(
    proprietary: &mut BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    pubkey: &PqPublicKey,
    seed_id: SeedId,
    path_hardened: &[u32],
) -> bool {
    let key = raw::ProprietaryKey {
        prefix: PROPRIETARY_IDENTIFIER.to_vec(),
        subtype: SUBTYPE_PQHD_ORIGIN,
        key: pubkey.to_prefixed_bytes(),
    };
    let value = make_pqhd_origin_value(seed_id, path_hardened);

    match proprietary.entry(key) {
        btree_map::Entry::Vacant(entry) => {
            entry.insert(value);
            true
        }
        btree_map::Entry::Occupied(_) => false,
    }
}

/// Decodes a Tidecoin PQ partial signature record if the key and value are valid.
pub fn decode_pq_partial_signature(
    key: &raw::ProprietaryKey,
    value: &[u8],
) -> Option<PqPartialSignature> {
    if key.prefix != PROPRIETARY_IDENTIFIER {
        return None;
    }
    if key.subtype != SUBTYPE_PQ_PARTIAL_SIGNATURE {
        return None;
    }

    let pubkey = PqPublicKey::from_prefixed_slice(&key.key).ok()?;
    if value.is_empty() || value.len() > pubkey.scheme().max_sig_len() {
        return None;
    }

    Some(PqPartialSignature { pubkey, signature: PqSignature::from_slice(value) })
}

/// Adds a Tidecoin PQ partial signature record to a proprietary map.
pub fn add_pq_partial_signature(
    proprietary: &mut BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    pubkey: &PqPublicKey,
    signature: &PqSignature,
) -> bool {
    if signature.is_empty() || signature.len() > pubkey.scheme().max_sig_len() {
        return false;
    }

    let key = raw::ProprietaryKey {
        prefix: PROPRIETARY_IDENTIFIER.to_vec(),
        subtype: SUBTYPE_PQ_PARTIAL_SIGNATURE,
        key: pubkey.to_prefixed_bytes(),
    };
    let value = signature.as_bytes().to_vec();

    match proprietary.entry(key) {
        btree_map::Entry::Vacant(entry) => {
            entry.insert(value);
            true
        }
        btree_map::Entry::Occupied(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::Psbt;
    use crate::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use crate::{absolute, Amount, Sequence, Witness};

    fn dummy_pubkey(prefix: u8) -> PqPublicKey {
        let scheme = crate::PqScheme::from_prefix(prefix).unwrap();
        let mut bytes = Vec::with_capacity(scheme.prefixed_pubkey_len());
        bytes.push(prefix);
        bytes.extend(core::iter::repeat_n(0x42, scheme.pubkey_len()));
        PqPublicKey::from_prefixed_slice(&bytes).unwrap()
    }

    fn minimal_psbt() -> Psbt {
        let tx = Transaction {
            version: crate::transaction::Version::maybe_non_standard(2),
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: crate::Txid::from_byte_array([1; 32]), vout: 0 },
                script_sig: Default::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(1).expect("amount fits in range"),
                script_pubkey: Default::default(),
            }],
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    fn seed_id_one() -> SeedId {
        let mut storage = [0_u8; 32];
        storage[0] = 1;
        SeedId::from_storage_bytes(storage)
    }

    fn path_for_scheme(prefix: u8) -> [u32; 6] {
        pqhd::make_v1_leaf_path(crate::PqScheme::from_prefix(prefix).unwrap(), 0, 0, 0)
    }

    #[test]
    fn pqhd_origin_roundtrip_input_and_output() {
        let mut psbt = minimal_psbt();
        let pubkey_in = dummy_pubkey(0x07);
        let pubkey_out = dummy_pubkey(0x0A);
        let seed_id = seed_id_one();
        let path_in = path_for_scheme(0x07);
        let path_out = path_for_scheme(0x0A);

        assert!(psbt.inputs[0].add_pqhd_origin(&pubkey_in, seed_id, &path_in));
        assert!(psbt.outputs[0].add_pqhd_origin(&pubkey_out, seed_id, &path_out));

        let encoded = psbt.serialize();
        let decoded = Psbt::deserialize(&encoded).unwrap();

        let origin_in = decoded.inputs[0].pqhd_origins().pop().unwrap();
        assert_eq!(origin_in.pubkey, pubkey_in);
        assert_eq!(origin_in.seed_id, seed_id);
        assert_eq!(origin_in.path_hardened, path_in);

        let origin_out = decoded.outputs[0].pqhd_origins().pop().unwrap();
        assert_eq!(origin_out.pubkey, pubkey_out);
        assert_eq!(origin_out.seed_id, seed_id);
        assert_eq!(origin_out.path_hardened, path_out);
    }

    #[test]
    fn pqhd_origin_decode_rejects_wrong_identifier_or_subtype() {
        let key = raw::ProprietaryKey { prefix: b"nottide".to_vec(), subtype: SUBTYPE_PQHD_ORIGIN, key: vec![] };
        assert!(decode_pqhd_origin(&key, &make_pqhd_origin_value(seed_id_one(), &[])).is_none());

        let key = raw::ProprietaryKey {
            prefix: PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: SUBTYPE_PQHD_ORIGIN + 1,
            key: vec![],
        };
        assert!(decode_pqhd_origin(&key, &make_pqhd_origin_value(seed_id_one(), &[])).is_none());
    }

    #[test]
    fn pqhd_origin_decode_rejects_malformed_values() {
        let pubkey = dummy_pubkey(0x07);
        let key = raw::ProprietaryKey {
            prefix: PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: SUBTYPE_PQHD_ORIGIN,
            key: pubkey.to_prefixed_bytes(),
        };
        assert!(decode_pqhd_origin(&key, &[1, 2, 3]).is_none());

        let non_hardened_path = [0_u32, 1, 2];
        assert!(decode_pqhd_origin(&key, &make_pqhd_origin_value(seed_id_one(), &non_hardened_path)).is_none());

        let short_path = [
            pqhd::HARDENED | pqhd::PURPOSE,
            pqhd::HARDENED | pqhd::COIN_TYPE,
            pqhd::HARDENED | 0x07,
        ];
        assert!(decode_pqhd_origin(&key, &make_pqhd_origin_value(seed_id_one(), &short_path)).is_none());

        let mut bad_purpose_path = path_for_scheme(0x07);
        bad_purpose_path[0] = pqhd::HARDENED | (pqhd::PURPOSE + 1);
        assert!(decode_pqhd_origin(&key, &make_pqhd_origin_value(seed_id_one(), &bad_purpose_path)).is_none());

        let mut bad_coin_path = path_for_scheme(0x07);
        bad_coin_path[1] = pqhd::HARDENED | (pqhd::COIN_TYPE + 1);
        assert!(decode_pqhd_origin(&key, &make_pqhd_origin_value(seed_id_one(), &bad_coin_path)).is_none());

        let mut bad_change_path = path_for_scheme(0x07);
        bad_change_path[4] = pqhd::HARDENED | 2;
        assert!(decode_pqhd_origin(&key, &make_pqhd_origin_value(seed_id_one(), &bad_change_path)).is_none());

        let mismatch_scheme_path = [
            pqhd::HARDENED | pqhd::PURPOSE,
            pqhd::HARDENED | pqhd::COIN_TYPE,
            pqhd::HARDENED | 0x0A,
            pqhd::HARDENED,
            pqhd::HARDENED,
            pqhd::HARDENED,
        ];
        assert!(decode_pqhd_origin(&key, &make_pqhd_origin_value(seed_id_one(), &mismatch_scheme_path)).is_none());
    }

    #[test]
    fn combine_psbt_preserves_proprietary_records() {
        let mut psbt_a = minimal_psbt();
        let mut psbt_b = minimal_psbt();

        let seed_id_a = seed_id_one();
        let mut storage_b = [0_u8; 32];
        storage_b[0] = 2;
        let seed_id_b = SeedId::from_storage_bytes(storage_b);

        assert!(psbt_a.inputs[0].add_pqhd_origin(&dummy_pubkey(0x07), seed_id_a, &path_for_scheme(0x07)));
        assert!(psbt_b.inputs[0].add_pqhd_origin(&dummy_pubkey(0x0A), seed_id_b, &path_for_scheme(0x0A)));
        assert!(psbt_a.outputs[0].add_pqhd_origin(&dummy_pubkey(0x08), seed_id_a, &path_for_scheme(0x08)));
        assert!(psbt_b.outputs[0].add_pqhd_origin(&dummy_pubkey(0x0B), seed_id_b, &path_for_scheme(0x0B)));

        psbt_a.combine(psbt_b).unwrap();
        assert_eq!(psbt_a.inputs[0].pqhd_origins().len(), 2);
        assert_eq!(psbt_a.outputs[0].pqhd_origins().len(), 2);
    }

    #[test]
    fn combine_psbt_deduplicates_identical_proprietary_records() {
        let mut psbt_a = minimal_psbt();
        let mut psbt_b = minimal_psbt();
        let seed_id = seed_id_one();
        let in_pubkey = dummy_pubkey(0x07);
        let out_pubkey = dummy_pubkey(0x08);

        assert!(psbt_a.inputs[0].add_pqhd_origin(&in_pubkey, seed_id, &path_for_scheme(0x07)));
        assert!(psbt_b.inputs[0].add_pqhd_origin(&in_pubkey, seed_id, &path_for_scheme(0x07)));
        assert!(psbt_a.outputs[0].add_pqhd_origin(&out_pubkey, seed_id, &path_for_scheme(0x08)));
        assert!(psbt_b.outputs[0].add_pqhd_origin(&out_pubkey, seed_id, &path_for_scheme(0x08)));

        psbt_a.combine(psbt_b).unwrap();
        assert_eq!(psbt_a.inputs[0].pqhd_origins().len(), 1);
        assert_eq!(psbt_a.outputs[0].pqhd_origins().len(), 1);
    }

    #[test]
    fn pq_partial_signature_roundtrip_and_combine() {
        let mut psbt_a = minimal_psbt();
        let mut psbt_b = minimal_psbt();

        let pubkey_a = dummy_pubkey(0x07);
        let pubkey_b = dummy_pubkey(0x0A);
        let sig_a = PqSignature::from_slice(&vec![0x11; 700]);
        let sig_b = PqSignature::from_slice(&vec![0x22; 1024]);

        assert!(psbt_a.inputs[0].add_pq_partial_signature(&pubkey_a, &sig_a));
        assert!(psbt_b.inputs[0].add_pq_partial_signature(&pubkey_b, &sig_b));

        let encoded = psbt_a.serialize();
        let decoded = Psbt::deserialize(&encoded).unwrap();
        let partial = decoded.inputs[0].pq_partial_signatures().pop().unwrap();
        assert_eq!(partial.pubkey, pubkey_a);
        assert_eq!(partial.signature, sig_a);

        psbt_a.combine(psbt_b).unwrap();
        let partials = psbt_a.inputs[0].pq_partial_signatures();
        assert_eq!(partials.len(), 2);
        assert!(partials.iter().any(|partial| partial.pubkey == pubkey_a && partial.signature == sig_a));
        assert!(partials.iter().any(|partial| partial.pubkey == pubkey_b && partial.signature == sig_b));
    }

    #[test]
    fn pq_partial_signature_rejects_invalid_records() {
        let pubkey = dummy_pubkey(0x07);
        let key = raw::ProprietaryKey {
            prefix: PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: SUBTYPE_PQ_PARTIAL_SIGNATURE,
            key: pubkey.to_prefixed_bytes(),
        };

        assert!(decode_pq_partial_signature(&key, &[]).is_none());
        assert!(decode_pq_partial_signature(
            &key,
            &vec![0x33; pubkey.scheme().max_sig_len() + 1]
        )
        .is_none());

        let wrong_id = raw::ProprietaryKey {
            prefix: b"nottide".to_vec(),
            subtype: SUBTYPE_PQ_PARTIAL_SIGNATURE,
            key: pubkey.to_prefixed_bytes(),
        };
        assert!(decode_pq_partial_signature(&wrong_id, &[0x44]).is_none());

        let wrong_subtype = raw::ProprietaryKey {
            prefix: PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: SUBTYPE_PQ_PARTIAL_SIGNATURE + 1,
            key: pubkey.to_prefixed_bytes(),
        };
        assert!(decode_pq_partial_signature(&wrong_subtype, &[0x44]).is_none());

        let mut psbt = minimal_psbt();
        assert!(!psbt.inputs[0].add_pq_partial_signature(&pubkey, &PqSignature::from_slice(&[])));
        assert!(!psbt.inputs[0].add_pq_partial_signature(
            &pubkey,
            &PqSignature::from_slice(&vec![0x55; pubkey.scheme().max_sig_len() + 1]),
        ));
    }
}
