// SPDX-License-Identifier: CC0-1.0

//! Post-quantum cryptographic types.
//!
//! Type definitions and crypto wrappers for the five post-quantum signature
//! schemes used by Tidecoin: Falcon-512, Falcon-1024, ML-DSA-44, ML-DSA-65,
//! and ML-DSA-87.

use core::fmt;

use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use fn_dsa::{
    keygen_pqclean, pubkey_from_signing_key, sign_key_size, signature_size, vrfy_key_size,
    SigningKey, SigningKeyStandard, VerifyingKey, VerifyingKeyStandard, DOMAIN_NONE,
    FN_DSA_LOGN_1024, FN_DSA_LOGN_512, HASH_ID_ORIGINAL_FALCON,
};
use hashes::hash160;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem512, B32};
use rand_core::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::network::Params;
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
    pub fn prefix(self) -> u8 {
        self as u8
    }

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
    pub fn prefixed_pubkey_len(self) -> usize {
        self.pubkey_len() + 1
    }

    /// Secret key length including the one-byte scheme prefix.
    pub fn prefixed_seckey_len(self) -> usize {
        self.seckey_len() + 1
    }

    /// Deterministic keygen seed length used by Tidecoin PQHD v1.
    pub fn deterministic_seed_len(self) -> usize {
        match self {
            Self::Falcon512 | Self::Falcon1024 => 48,
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => 32,
        }
    }

    /// Returns whether this scheme is allowed at the given chain height.
    ///
    /// Tidecoin permits only Falcon-512 before auxpow activation. Once auxpow is active,
    /// all current PQ schemes are allowed.
    pub fn is_allowed_at_height(self, height: u32, params: impl AsRef<Params>) -> bool {
        match params.as_ref().auxpow_start_height {
            Some(start_height) if height >= start_height.to_u32() => true,
            _ => self == Self::Falcon512,
        }
    }

    /// Generates a fresh PQ keypair for this scheme.
    pub fn generate_keypair(self) -> (PqPublicKey, PqSecretKey) {
        match self {
            Self::Falcon512 => {
                let mut seed = Zeroizing::new([0u8; 48]);
                rand_core::OsRng.fill_bytes(seed.as_mut());
                let mut sk_buf = Zeroizing::new(vec![0u8; sign_key_size(FN_DSA_LOGN_512)]);
                let mut vk_buf = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
                assert!(
                    keygen_pqclean(FN_DSA_LOGN_512, &seed[..], &mut sk_buf[..], &mut vk_buf[..]),
                    "Falcon-512 keygen"
                );
                (
                    PqPublicKey::from_backend(self, &vk_buf),
                    PqSecretKey::from_backend(self, &sk_buf),
                )
            }
            Self::Falcon1024 => {
                let mut seed = Zeroizing::new([0u8; 48]);
                rand_core::OsRng.fill_bytes(seed.as_mut());
                let mut sk_buf = Zeroizing::new(vec![0u8; sign_key_size(FN_DSA_LOGN_1024)]);
                let mut vk_buf = vec![0u8; vrfy_key_size(FN_DSA_LOGN_1024)];
                assert!(
                    keygen_pqclean(FN_DSA_LOGN_1024, &seed[..], &mut sk_buf[..], &mut vk_buf[..]),
                    "Falcon-1024 keygen"
                );
                (
                    PqPublicKey::from_backend(self, &vk_buf),
                    PqSecretKey::from_backend(self, &sk_buf),
                )
            }
            Self::MlDsa44 => {
                let (pk, sk) = fips204::ml_dsa_44::try_keygen_with_rng(&mut rand_core::OsRng)
                    .expect("ML-DSA-44 keygen");
                let sk_bytes = Zeroizing::new(sk.into_bytes());
                (
                    PqPublicKey::from_backend(self, &pk.into_bytes()),
                    PqSecretKey::from_backend(self, sk_bytes.as_ref()),
                )
            }
            Self::MlDsa65 => {
                let (pk, sk) = fips204::ml_dsa_65::try_keygen_with_rng(&mut rand_core::OsRng)
                    .expect("ML-DSA-65 keygen");
                let sk_bytes = Zeroizing::new(sk.into_bytes());
                (
                    PqPublicKey::from_backend(self, &pk.into_bytes()),
                    PqSecretKey::from_backend(self, sk_bytes.as_ref()),
                )
            }
            Self::MlDsa87 => {
                let (pk, sk) = fips204::ml_dsa_87::try_keygen_with_rng(&mut rand_core::OsRng)
                    .expect("ML-DSA-87 keygen");
                let sk_bytes = Zeroizing::new(sk.into_bytes());
                (
                    PqPublicKey::from_backend(self, &pk.into_bytes()),
                    PqSecretKey::from_backend(self, sk_bytes.as_ref()),
                )
            }
        }
    }

    /// Generates a deterministic PQ keypair from a scheme-specific seed.
    pub fn generate_keypair_from_seed(
        self,
        seed: &[u8],
    ) -> Result<(PqPublicKey, PqSecretKey), PqError> {
        let expected = self.deterministic_seed_len();
        if seed.len() != expected {
            return Err(PqError::InvalidSeedLength { expected, got: seed.len() });
        }

        match self {
            Self::Falcon512 | Self::Falcon1024 => {
                let logn = match self {
                    Self::Falcon512 => FN_DSA_LOGN_512,
                    _ => FN_DSA_LOGN_1024,
                };
                let mut sk_buf = Zeroizing::new(vec![0u8; sign_key_size(logn)]);
                let mut vk_buf = vec![0u8; vrfy_key_size(logn)];
                if !keygen_pqclean(logn, seed, &mut sk_buf[..], &mut vk_buf[..]) {
                    return Err(PqError::BackendFailure);
                }
                Ok((
                    PqPublicKey::from_backend(self, &vk_buf),
                    PqSecretKey::from_backend(self, &sk_buf),
                ))
            }
            Self::MlDsa44 => {
                let xi: &[u8; 32] = seed.try_into().map_err(|_| PqError::BackendFailure)?;
                let (pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(xi);
                let sk_bytes = Zeroizing::new(sk.into_bytes());
                Ok((
                    PqPublicKey { scheme: self, data: pk.into_bytes().to_vec() },
                    PqSecretKey { scheme: self, data: sk_bytes[..].to_vec() },
                ))
            }
            Self::MlDsa65 => {
                let xi: &[u8; 32] = seed.try_into().map_err(|_| PqError::BackendFailure)?;
                let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(xi);
                let sk_bytes = Zeroizing::new(sk.into_bytes());
                Ok((
                    PqPublicKey { scheme: self, data: pk.into_bytes().to_vec() },
                    PqSecretKey { scheme: self, data: sk_bytes[..].to_vec() },
                ))
            }
            Self::MlDsa87 => {
                let xi: &[u8; 32] = seed.try_into().map_err(|_| PqError::BackendFailure)?;
                let (pk, sk) = fips204::ml_dsa_87::KG::keygen_from_seed(xi);
                let sk_bytes = Zeroizing::new(sk.into_bytes());
                Ok((
                    PqPublicKey { scheme: self, data: pk.into_bytes().to_vec() },
                    PqSecretKey { scheme: self, data: sk_bytes[..].to_vec() },
                ))
            }
        }
    }
}

/// A post-quantum public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PqPublicKey {
    scheme: PqScheme,
    data: Vec<u8>,
}

impl PqPublicKey {
    fn from_backend(scheme: PqScheme, data: &[u8]) -> Self {
        Self { scheme, data: data.to_vec() }
    }

    /// Derives the public key matching the given secret key.
    pub fn from_secret_key(sk: &PqSecretKey) -> Result<Self, PqError> {
        let scheme = sk.scheme();
        let data = match scheme {
            PqScheme::Falcon512 | PqScheme::Falcon1024 => {
                let logn = match scheme {
                    PqScheme::Falcon512 => FN_DSA_LOGN_512,
                    _ => FN_DSA_LOGN_1024,
                };
                let mut vk = vec![0u8; vrfy_key_size(logn)];
                if !pubkey_from_signing_key(sk.as_bytes(), &mut vk) {
                    return Err(PqError::BackendFailure);
                }
                vk
            }
            _ => {
                let result: Result<Vec<u8>, PqError> = match scheme {
                    PqScheme::MlDsa44 => {
                        let sk_arr = Zeroizing::new(
                            sk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?,
                        );
                        let sk_obj = fips204::ml_dsa_44::PrivateKey::try_from_bytes(*sk_arr)
                            .map_err(|_| PqError::BackendFailure)?;
                        Ok(sk_obj.get_public_key().into_bytes().to_vec())
                    }
                    PqScheme::MlDsa65 => {
                        let sk_arr = Zeroizing::new(
                            sk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?,
                        );
                        let sk_obj = fips204::ml_dsa_65::PrivateKey::try_from_bytes(*sk_arr)
                            .map_err(|_| PqError::BackendFailure)?;
                        Ok(sk_obj.get_public_key().into_bytes().to_vec())
                    }
                    PqScheme::MlDsa87 => {
                        let sk_arr = Zeroizing::new(
                            sk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?,
                        );
                        let sk_obj = fips204::ml_dsa_87::PrivateKey::try_from_bytes(*sk_arr)
                            .map_err(|_| PqError::BackendFailure)?;
                        Ok(sk_obj.get_public_key().into_bytes().to_vec())
                    }
                    _ => unreachable!(),
                };
                result?
            }
        };

        Ok(Self { scheme, data })
    }

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
    pub fn scheme(&self) -> PqScheme {
        self.scheme
    }

    /// Raw public key bytes without the scheme prefix.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// HASH160 of the prefixed public key, suitable for P2PKH / P2WPKH addresses.
    pub fn key_id(&self) -> hash160::Hash {
        hash160::Hash::hash(&self.to_prefixed_bytes())
    }
}

/// A post-quantum secret key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSecretKey {
    scheme: PqScheme,
    data: Vec<u8>,
}

impl Drop for PqSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for PqSecretKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl PqSecretKey {
    fn from_backend(scheme: PqScheme, data: &[u8]) -> Self {
        Self { scheme, data: data.to_vec() }
    }

    /// Creates a secret key from raw bytes for the given scheme.
    pub fn from_slice(scheme: PqScheme, data: &[u8]) -> Result<Self, PqError> {
        let expected = scheme.seckey_len();
        if data.len() != expected {
            return Err(PqError::InvalidKeyLength { expected, got: data.len() });
        }
        if !scheme.is_valid_secret_key_encoding(data) {
            return Err(PqError::InvalidSecretKeyEncoding(scheme));
        }
        Ok(Self { scheme, data: data.to_vec() })
    }

    /// Parses a prefixed secret key: `[scheme_prefix_byte][raw_seckey_bytes]`.
    pub fn from_prefixed_slice(data: &[u8]) -> Result<Self, PqError> {
        let (&prefix, raw) = data.split_first().ok_or(PqError::EmptyData)?;
        let scheme = PqScheme::from_prefix(prefix).ok_or(PqError::UnknownScheme(prefix))?;
        let expected = scheme.seckey_len();
        if raw.len() != expected {
            return Err(PqError::InvalidKeyLength { expected, got: raw.len() });
        }
        Self::from_slice(scheme, raw)
    }

    /// Decodes a secret key from prefixed bytes or, when allowed, a legacy raw secret key.
    pub fn decode_slice(data: &[u8], allow_legacy: bool) -> Result<Self, PqError> {
        if data.is_empty() {
            return Err(PqError::EmptyData);
        }

        if let Some(scheme) = PqScheme::from_prefix(data[0]) {
            if data.len() == scheme.prefixed_seckey_len() {
                return Self::from_prefixed_slice(data);
            }
        }

        if !allow_legacy {
            return Err(PqError::InvalidKeyLength { expected: 0, got: data.len() });
        }

        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            if data.len() == scheme.seckey_len() && scheme.is_valid_secret_key_encoding(data) {
                return Ok(Self { scheme, data: data.to_vec() });
            }
        }

        Err(PqError::InvalidSecretKeyEncodingForLength(data.len()))
    }

    /// Serializes as `[scheme_prefix_byte][raw_seckey_bytes]`.
    pub fn to_prefixed_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Vec::with_capacity(1 + self.data.len());
        buf.push(self.scheme.prefix());
        buf.extend_from_slice(&self.data);
        Zeroizing::new(buf)
    }

    /// Returns the scheme this key belongs to.
    pub fn scheme(&self) -> PqScheme {
        self.scheme
    }

    /// Raw secret key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// A raw post-quantum signature (without the sighash type byte).
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

    /// Length of the raw signature in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the signature is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Signs a 32-byte message digest with the given secret key.
    pub fn sign_msg32(msg: &[u8; 32], sk: &PqSecretKey) -> Result<Self, PqError> {
        Self::sign_message(msg, sk)
    }

    /// Signs a 64-byte message digest with the given secret key.
    pub fn sign_msg64(msg: &[u8; 64], sk: &PqSecretKey) -> Result<Self, PqError> {
        Self::sign_message(msg, sk)
    }

    /// Verifies a 32-byte message digest against the given public key.
    pub fn verify_msg32(&self, msg: &[u8; 32], pk: &PqPublicKey) -> Result<(), PqError> {
        self.verify_message(msg, pk)
    }

    /// Verifies a 64-byte message digest against the given public key.
    pub fn verify_msg64(&self, msg: &[u8; 64], pk: &PqPublicKey) -> Result<(), PqError> {
        self.verify_message(msg, pk)
    }

    /// Signs a 32-byte message digest using the node's Falcon-512 legacy format when applicable.
    pub fn sign_msg32_legacy(msg: &[u8; 32], sk: &PqSecretKey) -> Result<Self, PqError> {
        Self::sign_message_legacy(msg, sk)
    }

    /// Signs a 64-byte message digest using the node's Falcon-512 legacy format when applicable.
    pub fn sign_msg64_legacy(msg: &[u8; 64], sk: &PqSecretKey) -> Result<Self, PqError> {
        Self::sign_message_legacy(msg, sk)
    }

    /// Verifies a 32-byte message digest using the node's Falcon-512 legacy format when applicable.
    pub fn verify_msg32_legacy(&self, msg: &[u8; 32], pk: &PqPublicKey) -> Result<(), PqError> {
        self.verify_message_legacy(msg, pk)
    }

    /// Verifies a 64-byte message digest using the node's Falcon-512 legacy format when applicable.
    pub fn verify_msg64_legacy(&self, msg: &[u8; 64], pk: &PqPublicKey) -> Result<(), PqError> {
        self.verify_message_legacy(msg, pk)
    }

    /// Verifies a 32-byte message digest, accepting either strict or legacy Falcon-512 signatures.
    pub fn verify_msg32_allow_legacy(
        &self,
        msg: &[u8; 32],
        pk: &PqPublicKey,
    ) -> Result<(), PqError> {
        self.verify_message_allow_legacy(msg, pk)
    }

    /// Verifies a 64-byte message digest, accepting either strict or legacy Falcon-512 signatures.
    pub fn verify_msg64_allow_legacy(
        &self,
        msg: &[u8; 64],
        pk: &PqPublicKey,
    ) -> Result<(), PqError> {
        self.verify_message_allow_legacy(msg, pk)
    }

    fn sign_message(msg: &[u8], sk: &PqSecretKey) -> Result<Self, PqError> {
        Ok(match sk.scheme() {
            PqScheme::Falcon512 | PqScheme::Falcon1024 => {
                let logn = match sk.scheme() {
                    PqScheme::Falcon512 => FN_DSA_LOGN_512,
                    _ => FN_DSA_LOGN_1024,
                };
                let mut signing_key =
                    SigningKeyStandard::decode(sk.as_bytes()).ok_or(PqError::BackendFailure)?;
                let mut sig = vec![0u8; signature_size(logn)];
                signing_key.sign(
                    &mut rand_core::OsRng,
                    &DOMAIN_NONE,
                    &HASH_ID_ORIGINAL_FALCON,
                    msg,
                    &mut sig,
                );
                Self::from_slice(&sig)
            }
            PqScheme::MlDsa44 => {
                let sk_arr = Zeroizing::new(
                    sk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?,
                );
                let sk_obj = fips204::ml_dsa_44::PrivateKey::try_from_bytes(*sk_arr)
                    .map_err(|_| PqError::BackendFailure)?;
                let sig = sk_obj
                    .try_sign_with_rng(&mut rand_core::OsRng, msg, &[])
                    .map_err(|_| PqError::BackendFailure)?;
                Self::from_slice(&sig)
            }
            PqScheme::MlDsa65 => {
                let sk_arr = Zeroizing::new(
                    sk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?,
                );
                let sk_obj = fips204::ml_dsa_65::PrivateKey::try_from_bytes(*sk_arr)
                    .map_err(|_| PqError::BackendFailure)?;
                let sig = sk_obj
                    .try_sign_with_rng(&mut rand_core::OsRng, msg, &[])
                    .map_err(|_| PqError::BackendFailure)?;
                Self::from_slice(&sig)
            }
            PqScheme::MlDsa87 => {
                let sk_arr = Zeroizing::new(
                    sk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?,
                );
                let sk_obj = fips204::ml_dsa_87::PrivateKey::try_from_bytes(*sk_arr)
                    .map_err(|_| PqError::BackendFailure)?;
                let sig = sk_obj
                    .try_sign_with_rng(&mut rand_core::OsRng, msg, &[])
                    .map_err(|_| PqError::BackendFailure)?;
                Self::from_slice(&sig)
            }
        })
    }

    fn sign_message_legacy(msg: &[u8], sk: &PqSecretKey) -> Result<Self, PqError> {
        if sk.scheme() != PqScheme::Falcon512 {
            return Self::sign_message(msg, sk);
        }
        let mut signing_key =
            SigningKeyStandard::decode(sk.as_bytes()).ok_or(PqError::BackendFailure)?;
        let mut sig = vec![0u8; signature_size(FN_DSA_LOGN_512)];
        signing_key.sign(
            &mut rand_core::OsRng,
            &DOMAIN_NONE,
            &HASH_ID_ORIGINAL_FALCON,
            msg,
            &mut sig,
        );
        let trimmed_len = sig.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        let min_len = 42;
        let final_len = trimmed_len.max(min_len);
        sig.truncate(final_len);
        Ok(Self { data: sig })
    }

    fn verify_message(&self, msg: &[u8], pk: &PqPublicKey) -> Result<(), PqError> {
        match pk.scheme() {
            PqScheme::Falcon512 | PqScheme::Falcon1024 => {
                let vk =
                    VerifyingKeyStandard::decode(pk.as_bytes()).ok_or(PqError::BackendFailure)?;
                let ok = vk.verify(self.as_bytes(), &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, msg)
                    || vk.verify_varlen(
                        self.as_bytes(),
                        &DOMAIN_NONE,
                        &HASH_ID_ORIGINAL_FALCON,
                        msg,
                    );
                if ok {
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
        if vk.verify_varlen(self.as_bytes(), &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, msg) {
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

/// ML-KEM-512 public-key size in bytes.
pub const MLKEM512_PUBLICKEY_BYTES: usize = 800;
/// ML-KEM-512 secret-key size in bytes.
pub const MLKEM512_SECRETKEY_BYTES: usize = 1632;
/// ML-KEM-512 ciphertext size in bytes.
pub const MLKEM512_CIPHERTEXT_BYTES: usize = 768;
/// ML-KEM-512 shared-secret size in bytes.
pub const MLKEM512_SHARED_SECRET_BYTES: usize = 32;
/// Tidecoin-node deterministic ML-KEM-512 keypair coin length.
pub const MLKEM512_KEYPAIR_COINS_BYTES: usize = 2 * MLKEM512_SHARED_SECRET_BYTES;

/// An ML-KEM-512 public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKem512PublicKey {
    data: Vec<u8>,
}

impl MlKem512PublicKey {
    /// Parses a public key from raw bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, PqError> {
        if data.len() != MLKEM512_PUBLICKEY_BYTES {
            return Err(PqError::InvalidKeyLength {
                expected: MLKEM512_PUBLICKEY_BYTES,
                got: data.len(),
            });
        }
        Ok(Self { data: data.to_vec() })
    }

    /// Returns the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// An ML-KEM-512 secret key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKem512SecretKey {
    data: Vec<u8>,
}

impl Drop for MlKem512SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for MlKem512SecretKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl MlKem512SecretKey {
    /// Parses a secret key from raw bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, PqError> {
        if data.len() != MLKEM512_SECRETKEY_BYTES {
            return Err(PqError::InvalidKeyLength {
                expected: MLKEM512_SECRETKEY_BYTES,
                got: data.len(),
            });
        }
        Ok(Self { data: data.to_vec() })
    }

    /// Returns the raw secret key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// An ML-KEM-512 ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKem512Ciphertext {
    data: Vec<u8>,
}

impl MlKem512Ciphertext {
    /// Parses a ciphertext from raw bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, PqError> {
        if data.len() != MLKEM512_CIPHERTEXT_BYTES {
            return Err(PqError::InvalidKeyLength {
                expected: MLKEM512_CIPHERTEXT_BYTES,
                got: data.len(),
            });
        }
        Ok(Self { data: data.to_vec() })
    }

    /// Returns the raw ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// An ML-KEM-512 shared secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKem512SharedSecret {
    data: [u8; MLKEM512_SHARED_SECRET_BYTES],
}

impl Drop for MlKem512SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for MlKem512SharedSecret {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl MlKem512SharedSecret {
    /// Parses a shared secret from raw bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, PqError> {
        if data.len() != MLKEM512_SHARED_SECRET_BYTES {
            return Err(PqError::InvalidKeyLength {
                expected: MLKEM512_SHARED_SECRET_BYTES,
                got: data.len(),
            });
        }
        let mut buf = [0_u8; MLKEM512_SHARED_SECRET_BYTES];
        buf.copy_from_slice(data);
        Ok(Self { data: buf })
    }

    /// Returns the raw shared-secret bytes.
    pub fn as_bytes(&self) -> &[u8; MLKEM512_SHARED_SECRET_BYTES] {
        &self.data
    }
}

/// An initialized ML-KEM-512 keypair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKem512Keypair {
    public_key: MlKem512PublicKey,
    secret_key: MlKem512SecretKey,
}

impl MlKem512Keypair {
    /// Generates a fresh random ML-KEM-512 keypair.
    pub fn generate() -> Self {
        let (dk, ek) = MlKem512::generate(&mut rand_core::OsRng);
        let mut dk_bytes = dk.as_bytes();
        let secret_key = MlKem512SecretKey { data: dk_bytes.as_slice().to_vec() };
        dk_bytes.as_mut_slice().zeroize();
        Self {
            public_key: MlKem512PublicKey { data: ek.as_bytes().as_slice().to_vec() },
            secret_key,
        }
    }

    /// Generates a deterministic ML-KEM-512 keypair from Tidecoin-node coins.
    pub fn generate_deterministic(coins: &[u8]) -> Result<Self, PqError> {
        if coins.len() != MLKEM512_KEYPAIR_COINS_BYTES {
            return Err(PqError::InvalidSeedLength {
                expected: MLKEM512_KEYPAIR_COINS_BYTES,
                got: coins.len(),
            });
        }

        let mut d = B32::try_from(&coins[..32]).map_err(|_| PqError::BackendFailure)?;
        let mut z = B32::try_from(&coins[32..64]).map_err(|_| PqError::BackendFailure)?;
        let (dk, ek) = MlKem512::generate_deterministic(&d, &z);
        let mut dk_bytes = dk.as_bytes();
        let secret_key = MlKem512SecretKey { data: dk_bytes.as_slice().to_vec() };
        dk_bytes.as_mut_slice().zeroize();
        d.as_mut_slice().zeroize();
        z.as_mut_slice().zeroize();
        Ok(Self {
            public_key: MlKem512PublicKey { data: ek.as_bytes().as_slice().to_vec() },
            secret_key,
        })
    }

    /// Constructs a keypair from raw public and secret key bytes.
    pub fn from_slices(public_key: &[u8], secret_key: &[u8]) -> Result<Self, PqError> {
        Ok(Self {
            public_key: MlKem512PublicKey::from_slice(public_key)?,
            secret_key: MlKem512SecretKey::from_slice(secret_key)?,
        })
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &MlKem512PublicKey {
        &self.public_key
    }

    /// Returns the secret key.
    pub fn secret_key(&self) -> &MlKem512SecretKey {
        &self.secret_key
    }

    /// Consumes the keypair and returns both parts.
    pub fn into_parts(self) -> (MlKem512PublicKey, MlKem512SecretKey) {
        (self.public_key, self.secret_key)
    }
}

impl MlKem512PublicKey {
    /// Encapsulates to this public key.
    pub fn encapsulate(&self) -> Result<(MlKem512Ciphertext, MlKem512SharedSecret), PqError> {
        let ek_arr =
            <ml_kem::Encoded<<MlKem512 as KemCore>::EncapsulationKey>>::try_from(self.as_bytes())
                .map_err(|_| PqError::BackendFailure)?;
        let ek = <<MlKem512 as KemCore>::EncapsulationKey as EncodedSizeUser>::from_bytes(&ek_arr);
        let (ct, ss) =
            ek.encapsulate(&mut rand_core::OsRng).map_err(|_| PqError::BackendFailure)?;
        let mut ss = ss;
        let shared_secret = MlKem512SharedSecret::from_slice(ss.as_slice())?;
        ss.as_mut_slice().zeroize();
        Ok((
            MlKem512Ciphertext { data: ct.as_slice().to_vec() },
            shared_secret,
        ))
    }

    /// Deterministically encapsulates using Tidecoin-node coins.
    pub fn encapsulate_deterministic(
        &self,
        coins: &[u8],
    ) -> Result<(MlKem512Ciphertext, MlKem512SharedSecret), PqError> {
        if coins.len() != MLKEM512_SHARED_SECRET_BYTES {
            return Err(PqError::InvalidSeedLength {
                expected: MLKEM512_SHARED_SECRET_BYTES,
                got: coins.len(),
            });
        }

        let ek_arr =
            <ml_kem::Encoded<<MlKem512 as KemCore>::EncapsulationKey>>::try_from(self.as_bytes())
                .map_err(|_| PqError::BackendFailure)?;
        let ek = <<MlKem512 as KemCore>::EncapsulationKey as EncodedSizeUser>::from_bytes(&ek_arr);
        let mut m = B32::try_from(coins).map_err(|_| PqError::BackendFailure)?;
        let (ct, ss) = ek.encapsulate_deterministic(&m).map_err(|_| PqError::BackendFailure)?;
        let mut ss = ss;
        let shared_secret = MlKem512SharedSecret::from_slice(ss.as_slice())?;
        m.as_mut_slice().zeroize();
        ss.as_mut_slice().zeroize();
        Ok((
            MlKem512Ciphertext { data: ct.as_slice().to_vec() },
            shared_secret,
        ))
    }
}

impl MlKem512SecretKey {
    /// Decapsulates an ML-KEM-512 ciphertext with this secret key.
    pub fn decapsulate(
        &self,
        ciphertext: &MlKem512Ciphertext,
    ) -> Result<MlKem512SharedSecret, PqError> {
        let mut dk_arr =
            <ml_kem::Encoded<<MlKem512 as KemCore>::DecapsulationKey>>::try_from(self.as_bytes())
                .map_err(|_| PqError::BackendFailure)?;
        let dk = <<MlKem512 as KemCore>::DecapsulationKey as EncodedSizeUser>::from_bytes(&dk_arr);
        let ct_arr = <ml_kem::Ciphertext<MlKem512>>::try_from(ciphertext.as_bytes())
            .map_err(|_| PqError::BackendFailure)?;
        let ss = dk.decapsulate(&ct_arr).map_err(|_| PqError::BackendFailure)?;
        let mut ss = ss;
        let shared_secret = MlKem512SharedSecret::from_slice(ss.as_slice())?;
        dk_arr.as_mut_slice().zeroize();
        ss.as_mut_slice().zeroize();
        Ok(shared_secret)
    }
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
    /// Deterministic key material has the wrong length.
    InvalidSeedLength {
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
    /// Secret key bytes do not use the scheme's required encoding.
    InvalidSecretKeyEncoding(PqScheme),
    /// Secret key bytes do not match any known scheme encoding for their length.
    InvalidSecretKeyEncodingForLength(usize),
    /// Signature verification failed.
    VerificationFailed,
    /// Backend key/signature operation failed.
    BackendFailure,
    /// The input slice was empty.
    EmptyData,
}

impl fmt::Display for PqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownScheme(b) => write!(f, "unknown PQ scheme prefix: 0x{:02x}", b),
            Self::InvalidKeyLength { expected, got } => {
                write!(f, "invalid key length: expected {} bytes, got {}", expected, got)
            }
            Self::InvalidSeedLength { expected, got } => write!(
                f,
                "invalid deterministic seed length: expected {} bytes, got {}",
                expected, got
            ),
            Self::InvalidSignatureLength { max, got } => {
                write!(f, "invalid signature length: max {} bytes, got {}", max, got)
            }
            Self::InvalidSecretKeyEncoding(scheme) => {
                write!(f, "invalid secret key encoding for {:?}", scheme)
            }
            Self::InvalidSecretKeyEncodingForLength(len) => {
                write!(f, "invalid secret key encoding for {}-byte key", len)
            }
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::BackendFailure => write!(f, "backend PQ operation failed"),
            Self::EmptyData => write!(f, "empty data"),
        }
    }
}

impl PqScheme {
    fn is_valid_secret_key_encoding(self, data: &[u8]) -> bool {
        if data.len() != self.seckey_len() {
            return false;
        }
        match self {
            Self::Falcon512 => data.first().copied() == Some(0x59),
            Self::Falcon1024 => data.first().copied() == Some(0x5A),
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => true,
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
        assert_eq!(
            PqPublicKey::from_prefixed_slice(&data).unwrap_err(),
            PqError::UnknownScheme(0xFF)
        );
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
            let fill = match scheme {
                PqScheme::Falcon512 => 0x59,
                PqScheme::Falcon1024 => 0x5A,
                _ => scheme.prefix(),
            };
            let raw = vec![fill; scheme.seckey_len()];
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
    fn seckey_prefixed_roundtrip_all_schemes() {
        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            let (_, sk) = scheme.generate_keypair();
            let prefixed = sk.to_prefixed_bytes();
            let reparsed = PqSecretKey::from_prefixed_slice(&prefixed).unwrap();
            assert_eq!(reparsed, sk);
            assert_eq!(prefixed.len(), scheme.prefixed_seckey_len());
        }
    }

    #[test]
    fn seckey_legacy_decode_roundtrip_all_schemes() {
        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            let (_, sk) = scheme.generate_keypair();
            let reparsed = PqSecretKey::decode_slice(sk.as_bytes(), true).unwrap();
            assert_eq!(reparsed, sk);
        }
    }

    #[test]
    fn seckey_legacy_decode_disallowed_when_prefix_missing() {
        let (_, sk) = PqScheme::Falcon512.generate_keypair();
        assert_eq!(
            PqSecretKey::decode_slice(sk.as_bytes(), false).unwrap_err(),
            PqError::InvalidKeyLength { expected: 0, got: sk.as_bytes().len() }
        );
    }

    #[test]
    fn falcon_seckey_validates_scheme_header_byte() {
        let (_, sk_512) = PqScheme::Falcon512.generate_keypair();
        let mut bad_512 = sk_512.as_bytes().to_vec();
        bad_512[0] = 0x58;
        assert_eq!(
            PqSecretKey::from_slice(PqScheme::Falcon512, &bad_512).unwrap_err(),
            PqError::InvalidSecretKeyEncoding(PqScheme::Falcon512)
        );

        let (_, sk_1024) = PqScheme::Falcon1024.generate_keypair();
        let mut bad_1024 = sk_1024.as_bytes().to_vec();
        bad_1024[0] = 0x59;
        assert_eq!(
            PqSecretKey::from_slice(PqScheme::Falcon1024, &bad_1024).unwrap_err(),
            PqError::InvalidSecretKeyEncoding(PqScheme::Falcon1024)
        );
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

    #[test]
    fn generate_keypair_matches_length_table() {
        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            let (pk, sk) = scheme.generate_keypair();
            assert_eq!(pk.scheme(), scheme);
            assert_eq!(sk.scheme(), scheme);
            assert_eq!(pk.as_bytes().len(), scheme.pubkey_len());
            assert_eq!(sk.as_bytes().len(), scheme.seckey_len());
        }
    }

    #[test]
    fn derive_public_key_from_secret_all_schemes() {
        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            let (pk, sk) = scheme.generate_keypair();
            let derived = PqPublicKey::from_secret_key(&sk).unwrap();
            assert_eq!(derived, pk);
        }
    }

    #[test]
    fn deterministic_keypair_generation_is_stable_all_schemes() {
        let seed48 = [0x42_u8; 48];
        let seed32 = [0x24_u8; 32];

        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            let seed = match scheme.deterministic_seed_len() {
                48 => &seed48[..],
                32 => &seed32[..],
                _ => unreachable!(),
            };

            let (pk_a, sk_a) = scheme.generate_keypair_from_seed(seed).unwrap();
            let (pk_b, sk_b) = scheme.generate_keypair_from_seed(seed).unwrap();
            assert_eq!(pk_a, pk_b);
            assert_eq!(sk_a, sk_b);
            assert_eq!(PqPublicKey::from_secret_key(&sk_a).unwrap(), pk_a);
        }
    }

    #[test]
    fn sign_and_verify_msg32_all_schemes() {
        let msg = [0x5Au8; 32];

        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            let (pk, sk) = scheme.generate_keypair();
            let sig = PqSignature::sign_msg32(&msg, &sk).unwrap();
            assert!(sig.len() <= scheme.max_sig_len());
            sig.verify_msg32(&msg, &pk).unwrap();

            let wrong_msg = [0xA5u8; 32];
            assert_eq!(sig.verify_msg32(&wrong_msg, &pk).unwrap_err(), PqError::VerificationFailed);
        }
    }

    #[test]
    fn sign_and_verify_msg64_all_schemes() {
        let msg = [0x33u8; 64];

        for scheme in [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ] {
            let (pk, sk) = scheme.generate_keypair();
            let sig = PqSignature::sign_msg64(&msg, &sk).unwrap();
            assert!(sig.len() <= scheme.max_sig_len());
            sig.verify_msg64(&msg, &pk).unwrap();

            let wrong_msg = [0xCCu8; 64];
            assert_eq!(sig.verify_msg64(&wrong_msg, &pk).unwrap_err(), PqError::VerificationFailed);
        }
    }

    #[test]
    fn falcon512_legacy_signatures_roundtrip_for_msg32() {
        let msg = [0x42_u8; 32];
        let (pk, sk) = PqScheme::Falcon512.generate_keypair();

        let strict = PqSignature::sign_msg32(&msg, &sk).unwrap();
        let legacy = PqSignature::sign_msg32_legacy(&msg, &sk).unwrap();

        assert_eq!(legacy.as_bytes().first().copied(), Some(0x39));
        assert!(legacy.len() <= 690);
        assert_ne!(legacy, strict);
        legacy.verify_msg32_legacy(&msg, &pk).unwrap();
        legacy.verify_msg32_allow_legacy(&msg, &pk).unwrap();
    }

    #[test]
    fn falcon512_legacy_signatures_roundtrip_for_msg64() {
        let msg = [0x24_u8; 64];
        let (pk, sk) = PqScheme::Falcon512.generate_keypair();

        let legacy = PqSignature::sign_msg64_legacy(&msg, &sk).unwrap();

        assert_eq!(legacy.as_bytes().first().copied(), Some(0x39));
        assert!(legacy.len() <= 690);
        legacy.verify_msg64_legacy(&msg, &pk).unwrap();
        legacy.verify_msg64_allow_legacy(&msg, &pk).unwrap();
    }

    #[test]
    fn scheme_auxpow_gate_matches_node_policy() {
        let mut params = Params::MAINNET;
        params.auxpow_start_height = Some(crate::BlockHeight::from_u32(100));

        assert!(PqScheme::Falcon512.is_allowed_at_height(0, &params));
        assert!(!PqScheme::MlDsa44.is_allowed_at_height(0, &params));
        assert!(PqScheme::MlDsa44.is_allowed_at_height(100, &params));

        let no_auxpow = Params::MAINNET;
        assert!(PqScheme::Falcon512.is_allowed_at_height(1_000_000, &no_auxpow));
        assert!(!PqScheme::MlDsa87.is_allowed_at_height(1_000_000, &no_auxpow));
    }

    #[test]
    fn mlkem512_roundtrip() {
        let keypair = MlKem512Keypair::generate();
        let (ciphertext, shared_secret) = keypair.public_key().encapsulate().unwrap();
        let recovered = keypair.secret_key().decapsulate(&ciphertext).unwrap();
        assert_eq!(recovered, shared_secret);
        assert_eq!(shared_secret.as_bytes().len(), MLKEM512_SHARED_SECRET_BYTES);
    }

    #[test]
    fn mlkem512_deterministic_keygen_matches() {
        let coins = [0x11_u8; MLKEM512_KEYPAIR_COINS_BYTES];
        let a = MlKem512Keypair::generate_deterministic(&coins).unwrap();
        let b = MlKem512Keypair::generate_deterministic(&coins).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mlkem512_deterministic_encapsulation_matches() {
        let coins = [0x22_u8; MLKEM512_KEYPAIR_COINS_BYTES];
        let enc_coins = [0x33_u8; MLKEM512_SHARED_SECRET_BYTES];
        let keypair = MlKem512Keypair::generate_deterministic(&coins).unwrap();

        let (ct1, ss1) = keypair.public_key().encapsulate_deterministic(&enc_coins).unwrap();
        let (ct2, ss2) = keypair.public_key().encapsulate_deterministic(&enc_coins).unwrap();
        let recovered = keypair.secret_key().decapsulate(&ct1).unwrap();

        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
        assert_eq!(recovered, ss1);
    }

    #[test]
    fn secret_types_require_drop_for_zeroization() {
        assert!(core::mem::needs_drop::<PqSecretKey>());
        assert!(core::mem::needs_drop::<MlKem512SecretKey>());
        assert!(core::mem::needs_drop::<MlKem512SharedSecret>());
    }
}
