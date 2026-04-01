// SPDX-License-Identifier: CC0-1.0

//! Post-quantum cryptographic types.
//!
//! Type definitions for the five post-quantum signature schemes used by
//! Tidecoin: Falcon-512, Falcon-1024, ML-DSA-44, ML-DSA-65, and ML-DSA-87.
//! This module provides key and signature containers only; actual
//! signing and verification are delegated to the underlying PQ crypto
//! libraries.

use core::fmt;

use hashes::hash160;

use crate::prelude::Vec;

/// Identifies which post-quantum signature scheme a key or signature belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PqScheme {
    /// Falcon-512 (prefix `0x07`).
    Falcon512 = 0x07,
    /// Falcon-1024 (prefix `0x08`).
    Falcon1024 = 0x08,
    /// ML-DSA-44 / Dilithium2 (prefix `0x09`).
    MlDsa44 = 0x09,
    /// ML-DSA-65 / Dilithium3 (prefix `0x0A`).
    MlDsa65 = 0x0A,
    /// ML-DSA-87 / Dilithium5 (prefix `0x0B`).
    MlDsa87 = 0x0B,
}

impl PqScheme {
    /// Resolves a scheme from its on-wire prefix byte.
    pub fn from_prefix(byte: u8) -> Option<Self> {
        match byte {
            0x07 => Some(Self::Falcon512),
            0x08 => Some(Self::Falcon1024),
            0x09 => Some(Self::MlDsa44),
            0x0A => Some(Self::MlDsa65),
            0x0B => Some(Self::MlDsa87),
            _ => None,
        }
    }

    /// Returns the on-wire prefix byte for this scheme.
    pub fn prefix(self) -> u8 { self as u8 }

    /// Raw public key length in bytes (without the scheme prefix).
    pub fn pubkey_len(self) -> usize {
        match self {
            Self::Falcon512 => 897,
            Self::Falcon1024 => 1793,
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Secret key length in bytes.
    pub fn seckey_len(self) -> usize {
        match self {
            Self::Falcon512 => 1281,
            Self::Falcon1024 => 2305,
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// Maximum signature length in bytes.
    pub fn max_sig_len(self) -> usize {
        match self {
            Self::Falcon512 => 752,
            Self::Falcon1024 => 1462,
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// Public key length including the one-byte scheme prefix.
    pub fn prefixed_pubkey_len(self) -> usize { self.pubkey_len() + 1 }
}

/// A post-quantum public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PqPublicKey {
    scheme: PqScheme,
    data: Vec<u8>,
}

impl PqPublicKey {
    /// Parses a prefixed public key: `[scheme_prefix_byte][raw_pubkey_bytes]`.
    pub fn from_prefixed_slice(data: &[u8]) -> Result<Self, PqError> {
        let (&prefix, raw) = data.split_first().ok_or(PqError::EmptyData)?;
        let scheme = PqScheme::from_prefix(prefix).ok_or(PqError::UnknownScheme(prefix))?;
        let expected = scheme.pubkey_len();
        if raw.len() != expected {
            return Err(PqError::InvalidKeyLength { expected, got: raw.len() });
        }
        Ok(Self { scheme, data: raw.to_vec() })
    }

    /// Serializes as `[scheme_prefix_byte][raw_pubkey_bytes]`.
    pub fn to_prefixed_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.data.len());
        buf.push(self.scheme.prefix());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Returns the scheme this key belongs to.
    pub fn scheme(&self) -> PqScheme { self.scheme }

    /// Raw public key bytes without the scheme prefix.
    pub fn as_bytes(&self) -> &[u8] { &self.data }

    /// HASH160 of the prefixed public key, suitable for P2PKH / P2WPKH addresses.
    pub fn key_id(&self) -> hash160::Hash {
        hash160::Hash::hash(&self.to_prefixed_bytes())
    }
}

/// A post-quantum secret key.
#[derive(Debug)]
pub struct PqSecretKey {
    scheme: PqScheme,
    data: Vec<u8>,
}

impl PqSecretKey {
    /// Creates a secret key from raw bytes for the given scheme.
    pub fn from_slice(scheme: PqScheme, data: &[u8]) -> Result<Self, PqError> {
        let expected = scheme.seckey_len();
        if data.len() != expected {
            return Err(PqError::InvalidKeyLength { expected, got: data.len() });
        }
        Ok(Self { scheme, data: data.to_vec() })
    }

    /// Returns the scheme this key belongs to.
    pub fn scheme(&self) -> PqScheme { self.scheme }

    /// Raw secret key bytes.
    pub fn as_bytes(&self) -> &[u8] { &self.data }
}

/// A raw post-quantum signature (without the sighash type byte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSignature {
    data: Vec<u8>,
}

impl PqSignature {
    /// Wraps raw signature bytes.
    pub fn from_slice(data: &[u8]) -> Self { Self { data: data.to_vec() } }

    /// Raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] { &self.data }

    /// Length of the raw signature in bytes.
    pub fn len(&self) -> usize { self.data.len() }

    /// Returns whether the signature is empty.
    pub fn is_empty(&self) -> bool { self.data.is_empty() }
}

/// Errors related to post-quantum key and signature handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqError {
    /// The prefix byte does not map to a known PQ scheme.
    UnknownScheme(u8),
    /// Key data has the wrong length.
    InvalidKeyLength {
        /// Expected number of bytes.
        expected: usize,
        /// Actual number of bytes received.
        got: usize,
    },
    /// Signature data exceeds the maximum allowed length.
    InvalidSignatureLength {
        /// Maximum allowed bytes for this scheme.
        max: usize,
        /// Actual number of bytes received.
        got: usize,
    },
    /// The input slice was empty.
    EmptyData,
}

impl fmt::Display for PqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownScheme(b) => write!(f, "unknown PQ scheme prefix: 0x{:02x}", b),
            Self::InvalidKeyLength { expected, got } =>
                write!(f, "invalid key length: expected {} bytes, got {}", expected, got),
            Self::InvalidSignatureLength { max, got } =>
                write!(f, "invalid signature length: max {} bytes, got {}", max, got),
            Self::EmptyData => write!(f, "empty data"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PqError {}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn scheme_round_trip() {
        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            let prefix = scheme.prefix();
            let parsed = PqScheme::from_prefix(prefix).unwrap();
            assert_eq!(parsed, scheme);
            assert_eq!(scheme.prefix(), prefix);
            assert_eq!(scheme.prefixed_pubkey_len(), scheme.pubkey_len() + 1);
        }
        assert!(PqScheme::from_prefix(0x00).is_none());
    }

    #[test]
    fn pubkey_parse_and_serialize_all_schemes() {
        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            let raw = vec![scheme.prefix(); scheme.pubkey_len()];
            let mut prefixed = vec![scheme.prefix()];
            prefixed.extend_from_slice(&raw);

            let pk = PqPublicKey::from_prefixed_slice(&prefixed).unwrap();
            assert_eq!(pk.scheme(), scheme);
            assert_eq!(pk.as_bytes(), &raw[..]);
            assert_eq!(pk.to_prefixed_bytes(), prefixed);
            assert_eq!(pk.key_id(), hash160::Hash::hash(&prefixed));
        }
    }

    #[test]
    fn pubkey_key_id_changes_with_prefix() {
        let raw_512 = vec![0xAB; PqScheme::Falcon512.pubkey_len()];
        let mut prefixed_512 = vec![PqScheme::Falcon512.prefix()];
        prefixed_512.extend_from_slice(&raw_512);
        let pk_512 = PqPublicKey::from_prefixed_slice(&prefixed_512).unwrap();

        let raw_1024 = vec![0xAB; PqScheme::Falcon1024.pubkey_len()];
        let mut prefixed_1024 = vec![PqScheme::Falcon1024.prefix()];
        prefixed_1024.extend_from_slice(&raw_1024);
        let pk_1024 = PqPublicKey::from_prefixed_slice(&prefixed_1024).unwrap();

        assert_eq!(pk_512.key_id(), hash160::Hash::hash(&prefixed_512));
        assert_eq!(pk_1024.key_id(), hash160::Hash::hash(&prefixed_1024));
        assert_ne!(pk_512.key_id(), pk_1024.key_id());
    }

    #[test]
    fn pubkey_wrong_length() {
        let err = PqPublicKey::from_prefixed_slice(&[0x07, 0x01, 0x02]).unwrap_err();
        assert_eq!(err, PqError::InvalidKeyLength { expected: 897, got: 2 });
        assert_eq!(err.to_string(), "invalid key length: expected 897 bytes, got 2");
    }

    #[test]
    fn pubkey_empty() {
        assert_eq!(PqPublicKey::from_prefixed_slice(&[]).unwrap_err(), PqError::EmptyData);
    }

    #[test]
    fn pubkey_unknown_scheme() {
        let data = vec![0xFF; 100];
        assert_eq!(PqPublicKey::from_prefixed_slice(&data).unwrap_err(), PqError::UnknownScheme(0xFF));
    }

    #[test]
    fn seckey_parse_all_schemes() {
        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            let raw = vec![scheme.prefix(); scheme.seckey_len()];
            let sk = PqSecretKey::from_slice(scheme, &raw).unwrap();
            assert_eq!(sk.scheme(), scheme);
            assert_eq!(sk.as_bytes(), &raw[..]);
        }
    }

    #[test]
    fn seckey_wrong_length() {
        let err = PqSecretKey::from_slice(PqScheme::MlDsa44, &[0; 10]).unwrap_err();
        assert_eq!(err, PqError::InvalidKeyLength { expected: 2560, got: 10 });
        assert_eq!(err.to_string(), "invalid key length: expected 2560 bytes, got 10");
    }

    #[test]
    fn seckey_length_table_matches_node_expectations() {
        let cases = [
            (PqScheme::Falcon512, 897, 1281, 752),
            (PqScheme::Falcon1024, 1793, 2305, 1462),
            (PqScheme::MlDsa44, 1312, 2560, 2420),
            (PqScheme::MlDsa65, 1952, 4032, 3309),
            (PqScheme::MlDsa87, 2592, 4896, 4627),
        ];

        for (scheme, pub_len, sec_len, sig_len) in cases {
            assert_eq!(scheme.pubkey_len(), pub_len);
            assert_eq!(scheme.seckey_len(), sec_len);
            assert_eq!(scheme.max_sig_len(), sig_len);
        }
    }

    #[test]
    fn signature_round_trip() {
        let raw = vec![0x42; 700];
        let sig = PqSignature::from_slice(&raw);
        assert_eq!(sig.as_bytes(), &raw[..]);
        assert_eq!(sig.len(), 700);
        assert!(!sig.is_empty());
    }

    #[test]
    fn signature_empty_and_boundary() {
        let empty = PqSignature::from_slice(&[]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let boundary = PqSignature::from_slice(&vec![0x11; PqScheme::Falcon512.max_sig_len()]);
        assert_eq!(boundary.len(), PqScheme::Falcon512.max_sig_len());
        assert!(!boundary.is_empty());
    }

    #[test]
    fn signature_error_display() {
        let err = PqError::InvalidSignatureLength { max: 752, got: 753 };
        assert_eq!(err.to_string(), "invalid signature length: max 752 bytes, got 753");
    }
}
