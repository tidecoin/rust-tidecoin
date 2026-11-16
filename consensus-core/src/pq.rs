// SPDX-License-Identifier: CC0-1.0

//! Verification-only post-quantum signature facade shared by Tidecoin
//! consensus consumers.

use alloc::vec::Vec;
use core::fmt;

use fips204::traits::{SerDes, Verifier};
use primitives::PqScheme;
use tide_fn_dsa_vrfy::{FalconProfile, VerifyingKey as TideVerifyingKey, VerifyingKeyStandard};

// rc3 src/pq/falcon512.c preserves the 0.18.3 compressed decoder for legacy
// verification: negative zero and unused final bits are accepted, but extra
// bytes, truncation and magnitudes above 2047 are not. Clear only those two
// encoding differences before using the existing legacy arithmetic verifier.
// This does not change the nonce, coefficients, norm bound or message hashing.
fn canonical_falcon(signature: &[u8], logn: u8) -> Option<Vec<u8>> {
    if signature.first() != Some(&(0x30 + logn)) || signature.len() <= 41 {
        return None;
    }
    let body = &signature[41..];
    let mut bit = 0usize;
    let mut zero_signs = Vec::new();
    for _ in 0..(1usize << logn) {
        let sign_bit = bit;
        let mut low = 0u16;
        for _ in 0..8 {
            low = (low << 1) | u16::from((body.get(bit / 8)? >> (7 - bit % 8)) & 1);
            bit += 1;
        }
        let mut magnitude = low & 127;
        loop {
            let stop = (body.get(bit / 8)? >> (7 - bit % 8)) & 1;
            bit += 1;
            if stop != 0 {
                break;
            }
            magnitude += 128;
            if magnitude > 2047 {
                return None;
            }
        }
        if magnitude == 0 && low & 128 != 0 {
            zero_signs.push(sign_bit);
        }
    }
    if bit.div_ceil(8) != body.len() {
        return None;
    }
    let mut canonical = signature.to_vec();
    for sign in zero_signs {
        canonical[41 + sign / 8] &= !(1 << (7 - sign % 8));
    }
    if !bit.is_multiple_of(8) {
        *canonical.last_mut()? &= 0xff << (8 - bit % 8);
    }
    Some(canonical)
}

/// Format-only rc3 relay check; malformed full buffers are not classified as
/// noncanonical legacy encodings. The caller separately verifies signatures.
pub fn is_noncanonical_legacy_falcon512(signature: &[u8]) -> bool {
    canonical_falcon(signature, 9).is_some_and(|canonical| canonical != signature)
}

/// A verification-only post-quantum public key.
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
                let logn = if pk.scheme() == PqScheme::Falcon512 { 9 } else { 10 };
                // rc3 removes PQClean's padded-size exception for both schemes.
                if canonical_falcon(self.as_bytes(), logn)
                    .is_none_or(|canonical| canonical != self.as_bytes())
                {
                    return Err(PqError::VerificationFailed);
                }
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
        let canonical = canonical_falcon(self.as_bytes(), 9).ok_or(PqError::VerificationFailed)?;
        if vk.verify_falcon(FalconProfile::TidecoinLegacyFalcon512, &canonical, msg) {
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
