// SPDX-License-Identifier: CC0-1.0

//! Verification-only post-quantum signature facade shared by Tidecoin
//! consensus consumers.

use alloc::vec::Vec;
use core::fmt;

use fips204::traits::{SerDes, Verifier};
use primitives::PqScheme;
use tide_fn_dsa_vrfy::{FalconProfile, VerifyingKey as TideVerifyingKey, VerifyingKeyStandard};

/// Format-only rc3 relay check; malformed full buffers are not classified as
/// noncanonical legacy encodings. The caller separately verifies signatures.
pub fn is_noncanonical_legacy_falcon512(signature: &[u8]) -> bool {
    tide_fn_dsa_vrfy::is_noncanonical_legacy_falcon512(signature)
}

/// A verification-only post-quantum public key.
///
/// Construction checks the scheme and byte length. Falcon verification decodes
/// the key before checking the signature, returning [`PqError::BackendFailure`]
/// for an invalid key encoding even when the signature is also malformed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PqPublicKey {
    scheme: PqScheme,
    data: Vec<u8>,
}

impl PqPublicKey {
    /// Builds a verification key from an already-separated scheme and raw public
    /// key bytes.
    pub fn from_scheme_and_bytes(scheme: PqScheme, data: &[u8]) -> Result<Self, PqError> {
        let expected = scheme.pubkey_len();
        if data.len() != expected {
            return Err(PqError::InvalidKeyLength { expected, got: data.len() });
        }
        Ok(Self { scheme, data: data.to_vec() })
    }

    /// Parses a prefixed public key `[scheme_prefix][raw_pubkey]`.
    pub fn from_prefixed_slice(data: &[u8]) -> Result<Self, PqError> {
        let (&prefix, raw) = data.split_first().ok_or(PqError::EmptyData)?;
        let scheme = PqScheme::from_prefix(prefix).ok_or(PqError::UnknownScheme(prefix))?;
        Self::from_scheme_and_bytes(scheme, raw)
    }

    /// Validates the full encoding as rc3 IsValidPubKey does, without changing
    /// structural parsing used by consensus signature checks.
    pub fn is_fully_valid(&self) -> bool {
        match self.scheme {
            PqScheme::Falcon512 | PqScheme::Falcon1024 => {
                VerifyingKeyStandard::decode(&self.data).is_some()
            }
            _ => true,
        }
    }

    /// Returns the scheme this key belongs to.
    pub fn scheme(&self) -> PqScheme {
        self.scheme
    }

    /// Raw public key bytes without the scheme prefix.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// A raw post-quantum signature without the appended sighash byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSignature {
    data: Vec<u8>,
}

impl PqSignature {
    /// Wraps raw signature bytes.
    pub fn from_slice(data: &[u8]) -> Self {
        Self { data: data.to_vec() }
    }

    /// Raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Verifies a 32-byte message digest against the given public key.
    pub fn verify_msg32(&self, msg: &[u8; 32], pk: &PqPublicKey) -> Result<(), PqError> {
        self.verify_message(msg, pk)
    }

    /// Verifies a 64-byte message digest against the given public key.
    pub fn verify_msg64(&self, msg: &[u8; 64], pk: &PqPublicKey) -> Result<(), PqError> {
        self.verify_message(msg, pk)
    }

    /// Verifies a 32-byte message digest, accepting either strict or legacy
    /// Falcon-512 signatures.
    pub fn verify_msg32_allow_legacy(
        &self,
        msg: &[u8; 32],
        pk: &PqPublicKey,
    ) -> Result<(), PqError> {
        self.verify_message_allow_legacy(msg, pk)
    }

    /// Verifies a 32-byte message digest using the node's Falcon-512 legacy
    /// verification mode when applicable.
    pub fn verify_msg32_legacy(&self, msg: &[u8; 32], pk: &PqPublicKey) -> Result<(), PqError> {
        self.verify_message_legacy(msg, pk)
    }

    /// Verifies a 64-byte message digest using the node's Falcon-512 legacy
    /// verification mode when applicable.
    pub fn verify_msg64_legacy(&self, msg: &[u8; 64], pk: &PqPublicKey) -> Result<(), PqError> {
        self.verify_message_legacy(msg, pk)
    }

    /// Verifies a 64-byte message digest, accepting either strict or legacy
    /// Falcon-512 signatures.
    pub fn verify_msg64_allow_legacy(
        &self,
        msg: &[u8; 64],
        pk: &PqPublicKey,
    ) -> Result<(), PqError> {
        self.verify_message_allow_legacy(msg, pk)
    }

    fn verify_message(&self, msg: &[u8], pk: &PqPublicKey) -> Result<(), PqError> {
        match pk.scheme() {
            PqScheme::Falcon512 | PqScheme::Falcon1024 => {
                let vk =
                    VerifyingKeyStandard::decode(pk.as_bytes()).ok_or(PqError::BackendFailure)?;
                if vk.verify_falcon(FalconProfile::TidecoinStrict, self.as_bytes(), msg) {
                    Ok(())
                } else {
                    Err(PqError::VerificationFailed)
                }
            }
            PqScheme::MlDsa44 => {
                let pk_arr: [u8; 1312] =
                    pk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?;
                let pk_obj = fips204::ml_dsa_44::PublicKey::try_from_bytes(pk_arr)
                    .map_err(|_| PqError::BackendFailure)?;
                let sig_arr: [u8; 2420] =
                    self.as_bytes().try_into().map_err(|_| PqError::VerificationFailed)?;
                if pk_obj.verify(msg, &sig_arr, &[]) {
                    Ok(())
                } else {
                    Err(PqError::VerificationFailed)
                }
            }
            PqScheme::MlDsa65 => {
                let pk_arr: [u8; 1952] =
                    pk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?;
                let pk_obj = fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_arr)
                    .map_err(|_| PqError::BackendFailure)?;
                let sig_arr: [u8; 3309] =
                    self.as_bytes().try_into().map_err(|_| PqError::VerificationFailed)?;
                if pk_obj.verify(msg, &sig_arr, &[]) {
                    Ok(())
                } else {
                    Err(PqError::VerificationFailed)
                }
            }
            PqScheme::MlDsa87 => {
                let pk_arr: [u8; 2592] =
                    pk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?;
                let pk_obj = fips204::ml_dsa_87::PublicKey::try_from_bytes(pk_arr)
                    .map_err(|_| PqError::BackendFailure)?;
                let sig_arr: [u8; 4627] =
                    self.as_bytes().try_into().map_err(|_| PqError::VerificationFailed)?;
                if pk_obj.verify(msg, &sig_arr, &[]) {
                    Ok(())
                } else {
                    Err(PqError::VerificationFailed)
                }
            }
        }
    }

    fn verify_message_legacy(&self, msg: &[u8], pk: &PqPublicKey) -> Result<(), PqError> {
        if pk.scheme() != PqScheme::Falcon512 {
            return self.verify_message(msg, pk);
        }
        let vk = VerifyingKeyStandard::decode(pk.as_bytes()).ok_or(PqError::BackendFailure)?;
        if vk.verify_falcon(FalconProfile::TidecoinLegacyFalcon512, self.as_bytes(), msg) {
            Ok(())
        } else {
            Err(PqError::VerificationFailed)
        }
    }

    fn verify_message_allow_legacy(&self, msg: &[u8], pk: &PqPublicKey) -> Result<(), PqError> {
        match self.verify_message(msg, pk) {
            Ok(()) => Ok(()),
            Err(PqError::VerificationFailed) if pk.scheme() == PqScheme::Falcon512 => {
                self.verify_message_legacy(msg, pk)
            }
            Err(err) => Err(err),
        }
    }
}

/// Verification-side PQ parse/verify error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqError {
    /// The prefix byte does not map to a known PQ scheme.
    UnknownScheme(u8),
    /// Public key bytes do not have the expected length.
    InvalidKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },
    /// Signature verification failed.
    VerificationFailed,
    /// Backend verification setup failed.
    BackendFailure,
    /// Empty encoded input.
    EmptyData,
}

impl fmt::Display for PqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UnknownScheme(b) => write!(f, "unknown PQ scheme prefix: 0x{b:02x}"),
            Self::InvalidKeyLength { expected, got } => {
                write!(f, "invalid key length: expected {expected} bytes, got {got}")
            }
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::BackendFailure => write!(f, "backend PQ operation failed"),
            Self::EmptyData => write!(f, "empty data"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PqError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_prefix_round_trip() {
        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            assert_eq!(PqScheme::from_prefix(scheme.prefix()), Some(scheme));
        }
    }

    #[test]
    fn prefixed_pubkey_rejects_wrong_length() {
        let err =
            PqPublicKey::from_prefixed_slice(&[PqScheme::Falcon512.prefix(), 1, 2]).unwrap_err();
        assert_eq!(err, PqError::InvalidKeyLength { expected: 897, got: 2 });
    }
    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |b: u8| (b as char).to_digit(16).unwrap() as u8;
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn falcon_rc3_verification_vectors() {
        let mut count = 0;
        for line in include_str!("../tests/data/falcon-rc3.txt").lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 8);
            let label = fields[0];
            let message = unhex(fields[1]);
            let raw_key = unhex(fields[2]);
            let scheme = match raw_key[0] {
                9 => PqScheme::Falcon512,
                10 => PqScheme::Falcon1024,
                _ => panic!("unexpected fixture degree"),
            };
            let key = PqPublicKey::from_scheme_and_bytes(scheme, &raw_key).unwrap();
            let signature = PqSignature::from_slice(&unhex(fields[3]));
            // The node legacy switch applies only to Falcon-512.
            let strict = fields[5] == "true";
            let legacy = if scheme == PqScheme::Falcon512 { fields[4] == "true" } else { strict };
            let results = match message.len() {
                32 => {
                    let msg = message.as_slice().try_into().unwrap();
                    [
                        signature.verify_msg32(msg, &key).is_ok(),
                        signature.verify_msg32_legacy(msg, &key).is_ok(),
                        signature.verify_msg32_allow_legacy(msg, &key).is_ok(),
                    ]
                }
                64 => {
                    let msg = message.as_slice().try_into().unwrap();
                    [
                        signature.verify_msg64(msg, &key).is_ok(),
                        signature.verify_msg64_legacy(msg, &key).is_ok(),
                        signature.verify_msg64_allow_legacy(msg, &key).is_ok(),
                    ]
                }
                _ => panic!("unexpected message width"),
            };
            assert_eq!(results, [strict, legacy, strict || legacy], "{label}");
            assert_eq!(
                is_noncanonical_legacy_falcon512(signature.as_bytes()),
                fields[7] == "true",
                "{label}"
            );
            // Changed-message and malformed-key controls. Synthetic norm fixtures
            // need not bind uniquely to a key after an arbitrary coefficient edit.
            let mut wrong_message = message.clone();
            wrong_message[0] ^= 1;
            assert!(
                signature.verify_message_allow_legacy(&wrong_message, &key).is_err(),
                "{label}"
            );
            let mut wrong_key = raw_key.clone();
            wrong_key[0] = 0xff;
            let wrong_key = PqPublicKey::from_scheme_and_bytes(scheme, &wrong_key).unwrap();
            assert!(
                signature.verify_message_allow_legacy(&message, &wrong_key).is_err(),
                "{label}"
            );
            if strict || legacy {
                let mut wrong_header = signature.as_bytes().to_vec();
                wrong_header[0] = 0xff;
                let mut overflow = signature.as_bytes().to_vec();
                // A zero low part followed by 16 unary zero bits exceeds 2047.
                overflow[41..44].fill(0);
                for malformed in [
                    &[][..],
                    &wrong_header,
                    &overflow,
                    &signature.as_bytes()[..signature.as_bytes().len() - 1],
                    &[signature.as_bytes(), &[0]].concat(),
                    &[signature.as_bytes(), &[1]].concat(),
                ] {
                    let malformed = PqSignature::from_slice(malformed);
                    assert!(
                        malformed.verify_message_allow_legacy(&message, &key).is_err(),
                        "{label}"
                    );
                    assert!(!is_noncanonical_legacy_falcon512(malformed.as_bytes()), "{label}");
                }
            }
            count += 1;
        }
        assert_eq!(count, 37);
    }

    #[test]
    fn falcon_invalid_key_precedes_invalid_signature() {
        for scheme in [PqScheme::Falcon512, PqScheme::Falcon1024] {
            let key =
                PqPublicKey::from_scheme_and_bytes(scheme, &alloc::vec![0xff; scheme.pubkey_len()])
                    .unwrap();
            let signature = PqSignature::from_slice(&[]);
            assert_eq!(signature.verify_msg32(&[0; 32], &key), Err(PqError::BackendFailure));
            assert_eq!(signature.verify_msg32_legacy(&[0; 32], &key), Err(PqError::BackendFailure));
            assert_eq!(
                signature.verify_msg32_allow_legacy(&[0; 32], &key),
                Err(PqError::BackendFailure)
            );
            assert_eq!(signature.verify_msg64(&[0; 64], &key), Err(PqError::BackendFailure));
            assert_eq!(signature.verify_msg64_legacy(&[0; 64], &key), Err(PqError::BackendFailure));
            assert_eq!(
                signature.verify_msg64_allow_legacy(&[0; 64], &key),
                Err(PqError::BackendFailure)
            );
        }
    }
}
