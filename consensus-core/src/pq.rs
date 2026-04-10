// SPDX-License-Identifier: CC0-1.0

//! Verification-only post-quantum signature facade shared by Tidecoin
//! consensus consumers.

use alloc::vec::Vec;
use core::fmt;

use fips204::traits::{SerDes, Verifier};
use tide_fn_dsa::{FalconProfile, VerifyingKey as TideVerifyingKey, VerifyingKeyStandard};

/// Identifies which post-quantum signature scheme a key belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PqScheme {
    /// Falcon-512.
    Falcon512 = 0x07,
    /// Falcon-1024.
    Falcon1024 = 0x08,
    /// ML-DSA-44.
    MlDsa44 = 0x09,
    /// ML-DSA-65.
    MlDsa65 = 0x0A,
    /// ML-DSA-87.
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
    pub fn prefix(self) -> u8 {
        self as u8
    }

    /// Raw public key length in bytes.
    pub fn pubkey_len(self) -> usize {
        match self {
            Self::Falcon512 => 897,
            Self::Falcon1024 => 1793,
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
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
}

/// A verification-only post-quantum public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PqPublicKey {
    scheme: PqScheme,
    data: Vec<u8>,
}

impl PqPublicKey {
    /// Parses a prefixed public key `[scheme_prefix][raw_pubkey]`.
    pub fn from_prefixed_slice(data: &[u8]) -> Result<Self, PqError> {
        let (&prefix, raw) = data.split_first().ok_or(PqError::EmptyData)?;
        let scheme = PqScheme::from_prefix(prefix).ok_or(PqError::UnknownScheme(prefix))?;
        let expected = scheme.pubkey_len();
        if raw.len() != expected {
            return Err(PqError::InvalidKeyLength { expected, got: raw.len() });
        }
        Ok(Self { scheme, data: raw.to_vec() })
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
                if vk.verify_falcon(FalconProfile::PqClean, self.as_bytes(), msg) {
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
}
