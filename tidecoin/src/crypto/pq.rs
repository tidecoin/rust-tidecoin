// SPDX-License-Identifier: CC0-1.0

//! Post-quantum cryptographic types.
//!
//! Type definitions and crypto wrappers for the five post-quantum signature
//! schemes used by Tidecoin: Falcon-512, Falcon-1024, ML-DSA-44, ML-DSA-65,
//! and ML-DSA-87.
//!
//! These are the product-facing PQ types for normal `tidecoin` users.
//!
//! The lower-level [`consensus_core`] crate also exposes verifier-side PQ types
//! with similar names for use inside the shared validation engine. Most wallet,
//! app, and plumbing code should prefer the `tidecoin` versions from this
//! module.

use core::fmt;

use consensus_core::{
    PqError as ConsensusPqError, PqPublicKey as ConsensusPqPublicKey,
    PqSignature as ConsensusPqSignature,
};
use fips204::traits::{KeyGen, SerDes, Signer};
use hashes::hash160;
use ml_kem::kem::{Decapsulate, FromSeed, Kem, Key, KeyExport};
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{MlKem512, Seed, B32};
use rand_core::{CryptoRng, RngCore};
use tide_fn_dsa_kgen::{
    sign_key_size, vrfy_key_size, KeyPairGeneratorStandard, FN_DSA_LOGN_1024, FN_DSA_LOGN_512,
};
use tide_fn_dsa_sign::{
    FalconProfile, SigningKey as TideSigningKey, SigningKeyStandard, FALCON_NONCE_LEN,
    TIDECOIN_LEGACY_FALCON512_SIG_BODY_MAX,
};
use zeroize::{Zeroize, Zeroizing};

use crate::network::Params;
use crate::prelude::Vec;

pub use primitives::PqScheme;

const TIDECOIN_LEGACY_FALCON512_SIG_MAX: usize =
    1 + FALCON_NONCE_LEN + TIDECOIN_LEGACY_FALCON512_SIG_BODY_MAX;

type MlKem512DecapsulationKey = <MlKem512 as Kem>::DecapsulationKey;
type MlKem512EncapsulationKey = <MlKem512 as Kem>::EncapsulationKey;

#[cfg(test)]
pub(crate) struct DeterministicTestRng(u64);

#[cfg(test)]
impl DeterministicTestRng {
    pub(crate) const fn new(seed: u64) -> Self {
        Self(seed)
    }
}

#[cfg(test)]
impl RngCore for DeterministicTestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(0xbf58_476d_1ce4_e5b9);
        self.0 ^ (self.0 >> 29)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset < dest.len() {
            let bytes = self.next_u64().to_le_bytes();
            let n = core::cmp::min(bytes.len(), dest.len() - offset);
            dest[offset..offset + n].copy_from_slice(&bytes[..n]);
            offset += n;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
impl CryptoRng for DeterministicTestRng {}

/// High-level cryptographic operations for Tidecoin PQ schemes.
pub trait PqSchemeCryptoExt {
    /// Returns whether this scheme is allowed at the given chain height.
    fn is_allowed_by_params_at_height(&self, height: u32, params: impl AsRef<Params>) -> bool;

    /// Generates a fresh PQ keypair for this scheme using caller-provided randomness.
    fn generate_keypair_with_rng<R>(
        self,
        rng: &mut R,
    ) -> Result<(PqPublicKey, PqSecretKey), PqError>
    where
        R: RngCore + CryptoRng;

    /// Generates a fresh PQ keypair for this scheme.
    #[cfg(feature = "rand")]
    fn generate_keypair(self) -> (PqPublicKey, PqSecretKey);

    /// Generates a deterministic PQ keypair from the scheme-specific seed bytes.
    fn generate_keypair_from_seed(self, seed: &[u8])
        -> Result<(PqPublicKey, PqSecretKey), PqError>;
}

impl PqSchemeCryptoExt for PqScheme {
    /// Returns whether this scheme is allowed at the given chain height.
    ///
    /// Tidecoin permits only Falcon-512 before auxpow activation. Once auxpow is active,
    /// all current PQ schemes are allowed.
    fn is_allowed_by_params_at_height(&self, height: u32, params: impl AsRef<Params>) -> bool {
        Self::is_allowed_at_height(
            *self,
            height,
            params.as_ref().auxpow_start_height.map(|height| height.to_u32()),
        )
    }

    /// Generates a fresh PQ keypair for this scheme using caller-provided randomness.
    fn generate_keypair_with_rng<R>(
        self,
        rng: &mut R,
    ) -> Result<(PqPublicKey, PqSecretKey), PqError>
    where
        R: RngCore + CryptoRng,
    {
        Ok(match self {
            Self::Falcon512 => {
                let mut seed = Zeroizing::new([0u8; 48]);
                rng.fill_bytes(seed.as_mut());
                let mut sk_buf = Zeroizing::new(vec![
                    0u8;
                    sign_key_size(FN_DSA_LOGN_512)
                        .map_err(|_| PqError::BackendFailure)?
                ]);
                let mut vk_buf =
                    vec![0u8; vrfy_key_size(FN_DSA_LOGN_512).map_err(|_| PqError::BackendFailure)?];
                KeyPairGeneratorStandard::default()
                    .keygen_from_seed_pqclean(
                        FN_DSA_LOGN_512,
                        &seed[..],
                        &mut sk_buf[..],
                        &mut vk_buf[..],
                    )
                    .map_err(|_| PqError::BackendFailure)?;
                (PqPublicKey::from_backend(self, &vk_buf), PqSecretKey::from_backend(self, &sk_buf))
            }
            Self::Falcon1024 => {
                let mut seed = Zeroizing::new([0u8; 48]);
                rng.fill_bytes(seed.as_mut());
                let mut sk_buf = Zeroizing::new(vec![
                    0u8;
                    sign_key_size(FN_DSA_LOGN_1024)
                        .map_err(|_| PqError::BackendFailure)?
                ]);
                let mut vk_buf = vec![
                    0u8;
                    vrfy_key_size(FN_DSA_LOGN_1024)
                        .map_err(|_| PqError::BackendFailure)?
                ];
                KeyPairGeneratorStandard::default()
                    .keygen_from_seed_pqclean(
                        FN_DSA_LOGN_1024,
                        &seed[..],
                        &mut sk_buf[..],
                        &mut vk_buf[..],
                    )
                    .map_err(|_| PqError::BackendFailure)?;
                (PqPublicKey::from_backend(self, &vk_buf), PqSecretKey::from_backend(self, &sk_buf))
            }
            Self::MlDsa44 => {
                let (pk, sk) = fips204::ml_dsa_44::try_keygen_with_rng(rng)
                    .map_err(|_| PqError::BackendFailure)?;
                let sk_bytes = Zeroizing::new(sk.into_bytes());
                (
                    PqPublicKey::from_backend(self, &pk.into_bytes()),
                    PqSecretKey::from_backend(self, sk_bytes.as_ref()),
                )
            }
            Self::MlDsa65 => {
                let (pk, sk) = fips204::ml_dsa_65::try_keygen_with_rng(rng)
                    .map_err(|_| PqError::BackendFailure)?;
                let sk_bytes = Zeroizing::new(sk.into_bytes());
                (
                    PqPublicKey::from_backend(self, &pk.into_bytes()),
                    PqSecretKey::from_backend(self, sk_bytes.as_ref()),
                )
            }
            Self::MlDsa87 => {
                let (pk, sk) = fips204::ml_dsa_87::try_keygen_with_rng(rng)
                    .map_err(|_| PqError::BackendFailure)?;
                let sk_bytes = Zeroizing::new(sk.into_bytes());
                (
                    PqPublicKey::from_backend(self, &pk.into_bytes()),
                    PqSecretKey::from_backend(self, sk_bytes.as_ref()),
                )
            }
        })
    }

    /// Generates a fresh PQ keypair for this scheme.
    #[cfg(feature = "rand")]
    fn generate_keypair(self) -> (PqPublicKey, PqSecretKey) {
        self.generate_keypair_with_rng(&mut rand_core::OsRng).expect("OS random PQ keygen")
    }

    /// Generates a deterministic PQ keypair from a scheme-specific seed.
    fn generate_keypair_from_seed(
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
                let mut sk_buf = Zeroizing::new(vec![
                    0u8;
                    sign_key_size(logn)
                        .map_err(|_| PqError::BackendFailure)?
                ]);
                let mut vk_buf =
                    vec![0u8; vrfy_key_size(logn).map_err(|_| PqError::BackendFailure)?];
                if KeyPairGeneratorStandard::default()
                    .keygen_from_seed_pqclean(logn, seed, &mut sk_buf[..], &mut vk_buf[..])
                    .is_err()
                {
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
                let signing_key =
                    SigningKeyStandard::decode(sk.as_bytes()).ok_or(PqError::BackendFailure)?;
                let mut vk = vec![0u8; vrfy_key_size(logn).map_err(|_| PqError::BackendFailure)?];
                signing_key.to_verifying_key(&mut vk).map_err(|_| PqError::BackendFailure)?;
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
        if !is_valid_secret_key_encoding(scheme, data) {
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
            if data.len() == scheme.seckey_len() && is_valid_secret_key_encoding(scheme, data) {
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
    #[cfg(feature = "rand")]
    pub fn sign_msg32(msg: &[u8; 32], sk: &PqSecretKey) -> Result<Self, PqError> {
        Self::sign_msg32_with_rng(msg, sk, &mut rand_core::OsRng)
    }

    /// Signs a 64-byte message digest with the given secret key.
    #[cfg(feature = "rand")]
    pub fn sign_msg64(msg: &[u8; 64], sk: &PqSecretKey) -> Result<Self, PqError> {
        Self::sign_msg64_with_rng(msg, sk, &mut rand_core::OsRng)
    }

    /// Signs a 32-byte message digest with caller-provided randomness.
    pub fn sign_msg32_with_rng<R>(
        msg: &[u8; 32],
        sk: &PqSecretKey,
        rng: &mut R,
    ) -> Result<Self, PqError>
    where
        R: RngCore + CryptoRng,
    {
        Self::sign_message_with_rng(msg, sk, rng)
    }

    /// Signs a 64-byte message digest with caller-provided randomness.
    pub fn sign_msg64_with_rng<R>(
        msg: &[u8; 64],
        sk: &PqSecretKey,
        rng: &mut R,
    ) -> Result<Self, PqError>
    where
        R: RngCore + CryptoRng,
    {
        Self::sign_message_with_rng(msg, sk, rng)
    }

    /// Verifies a 32-byte message digest against the given public key.
    pub fn verify_msg32(&self, msg: &[u8; 32], pk: &PqPublicKey) -> Result<(), PqError> {
        self.as_consensus_signature().verify_msg32(msg, &pk.as_consensus_key()?).map_err(Into::into)
    }

    /// Verifies a 64-byte message digest against the given public key.
    pub fn verify_msg64(&self, msg: &[u8; 64], pk: &PqPublicKey) -> Result<(), PqError> {
        self.as_consensus_signature().verify_msg64(msg, &pk.as_consensus_key()?).map_err(Into::into)
    }

    /// Signs a 32-byte message digest using the node's Falcon-512 legacy format when applicable.
    #[cfg(feature = "rand")]
    pub fn sign_msg32_legacy(msg: &[u8; 32], sk: &PqSecretKey) -> Result<Self, PqError> {
        Self::sign_msg32_legacy_with_rng(msg, sk, &mut rand_core::OsRng)
    }

    /// Signs a 64-byte message digest using the node's Falcon-512 legacy format when applicable.
    #[cfg(feature = "rand")]
    pub fn sign_msg64_legacy(msg: &[u8; 64], sk: &PqSecretKey) -> Result<Self, PqError> {
        Self::sign_msg64_legacy_with_rng(msg, sk, &mut rand_core::OsRng)
    }

    /// Signs a 32-byte message digest using caller-provided randomness and the node's
    /// Falcon-512 legacy format when applicable.
    pub fn sign_msg32_legacy_with_rng<R>(
        msg: &[u8; 32],
        sk: &PqSecretKey,
        rng: &mut R,
    ) -> Result<Self, PqError>
    where
        R: RngCore + CryptoRng,
    {
        Self::sign_message_legacy_with_rng(msg, sk, rng)
    }

    /// Signs a 64-byte message digest using caller-provided randomness and the node's
    /// Falcon-512 legacy format when applicable.
    pub fn sign_msg64_legacy_with_rng<R>(
        msg: &[u8; 64],
        sk: &PqSecretKey,
        rng: &mut R,
    ) -> Result<Self, PqError>
    where
        R: RngCore + CryptoRng,
    {
        Self::sign_message_legacy_with_rng(msg, sk, rng)
    }

    /// Verifies a 32-byte message digest using the node's Falcon-512 legacy format when applicable.
    pub fn verify_msg32_legacy(&self, msg: &[u8; 32], pk: &PqPublicKey) -> Result<(), PqError> {
        self.as_consensus_signature()
            .verify_msg32_legacy(msg, &pk.as_consensus_key()?)
            .map_err(Into::into)
    }

    /// Verifies a 64-byte message digest using the node's Falcon-512 legacy format when applicable.
    pub fn verify_msg64_legacy(&self, msg: &[u8; 64], pk: &PqPublicKey) -> Result<(), PqError> {
        self.as_consensus_signature()
            .verify_msg64_legacy(msg, &pk.as_consensus_key()?)
            .map_err(Into::into)
    }

    /// Verifies a 32-byte message digest, accepting either strict or legacy Falcon-512 signatures.
    pub fn verify_msg32_allow_legacy(
        &self,
        msg: &[u8; 32],
        pk: &PqPublicKey,
    ) -> Result<(), PqError> {
        self.as_consensus_signature()
            .verify_msg32_allow_legacy(msg, &pk.as_consensus_key()?)
            .map_err(Into::into)
    }

    /// Verifies a 64-byte message digest, accepting either strict or legacy Falcon-512 signatures.
    pub fn verify_msg64_allow_legacy(
        &self,
        msg: &[u8; 64],
        pk: &PqPublicKey,
    ) -> Result<(), PqError> {
        self.as_consensus_signature()
            .verify_msg64_allow_legacy(msg, &pk.as_consensus_key()?)
            .map_err(Into::into)
    }

    fn sign_message_with_rng<R>(msg: &[u8], sk: &PqSecretKey, rng: &mut R) -> Result<Self, PqError>
    where
        R: RngCore + CryptoRng,
    {
        Ok(match sk.scheme() {
            PqScheme::Falcon512 | PqScheme::Falcon1024 => {
                let mut signing_key =
                    SigningKeyStandard::decode(sk.as_bytes()).ok_or(PqError::BackendFailure)?;
                let mut sig = vec![0u8; sk.scheme().max_sig_len()];
                let sig_len = signing_key
                    .sign_falcon(rng, FalconProfile::PqClean, msg, &mut sig)
                    .map_err(|_| PqError::BackendFailure)?;
                sig.truncate(sig_len);
                Self::from_slice(&sig)
            }
            PqScheme::MlDsa44 => {
                let sk_arr =
                    Zeroizing::new(sk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?);
                let sk_obj = fips204::ml_dsa_44::PrivateKey::try_from_bytes(*sk_arr)
                    .map_err(|_| PqError::BackendFailure)?;
                let sig =
                    sk_obj.try_sign_with_rng(rng, msg, &[]).map_err(|_| PqError::BackendFailure)?;
                Self::from_slice(&sig)
            }
            PqScheme::MlDsa65 => {
                let sk_arr =
                    Zeroizing::new(sk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?);
                let sk_obj = fips204::ml_dsa_65::PrivateKey::try_from_bytes(*sk_arr)
                    .map_err(|_| PqError::BackendFailure)?;
                let sig =
                    sk_obj.try_sign_with_rng(rng, msg, &[]).map_err(|_| PqError::BackendFailure)?;
                Self::from_slice(&sig)
            }
            PqScheme::MlDsa87 => {
                let sk_arr =
                    Zeroizing::new(sk.as_bytes().try_into().map_err(|_| PqError::BackendFailure)?);
                let sk_obj = fips204::ml_dsa_87::PrivateKey::try_from_bytes(*sk_arr)
                    .map_err(|_| PqError::BackendFailure)?;
                let sig =
                    sk_obj.try_sign_with_rng(rng, msg, &[]).map_err(|_| PqError::BackendFailure)?;
                Self::from_slice(&sig)
            }
        })
    }

    fn sign_message_legacy_with_rng<R>(
        msg: &[u8],
        sk: &PqSecretKey,
        rng: &mut R,
    ) -> Result<Self, PqError>
    where
        R: RngCore + CryptoRng,
    {
        if sk.scheme() != PqScheme::Falcon512 {
            return Self::sign_message_with_rng(msg, sk, rng);
        }
        let mut signing_key =
            SigningKeyStandard::decode(sk.as_bytes()).ok_or(PqError::BackendFailure)?;
        let mut sig = vec![0u8; TIDECOIN_LEGACY_FALCON512_SIG_MAX];
        let sig_len = signing_key
            .sign_falcon(rng, FalconProfile::TidecoinLegacyFalcon512, msg, &mut sig)
            .map_err(|_| PqError::BackendFailure)?;
        sig.truncate(sig_len);
        Ok(Self { data: sig })
    }

    fn as_consensus_signature(&self) -> ConsensusPqSignature {
        ConsensusPqSignature::from_slice(self.as_bytes())
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
    #[cfg(feature = "rand")]
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand_core::OsRng)
    }

    /// Generates a fresh ML-KEM-512 keypair using caller-provided randomness.
    pub fn generate_with_rng<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let mut coins = [0_u8; MLKEM512_KEYPAIR_COINS_BYTES];
        rng.fill_bytes(&mut coins);
        let keypair = Self::generate_deterministic(&coins).expect("valid ML-KEM-512 coin length");
        coins.zeroize();
        keypair
    }

    /// Generates a deterministic ML-KEM-512 keypair from Tidecoin-node coins.
    pub fn generate_deterministic(coins: &[u8]) -> Result<Self, PqError> {
        if coins.len() != MLKEM512_KEYPAIR_COINS_BYTES {
            return Err(PqError::InvalidSeedLength {
                expected: MLKEM512_KEYPAIR_COINS_BYTES,
                got: coins.len(),
            });
        }

        let mut seed = Seed::try_from(coins).map_err(|_| PqError::BackendFailure)?;
        let (dk, ek) = MlKem512::from_seed(&seed);
        #[allow(deprecated)]
        let mut dk_bytes = dk.to_expanded_bytes();
        let secret_key = MlKem512SecretKey { data: dk_bytes.as_slice().to_vec() };
        dk_bytes.as_mut_slice().zeroize();
        seed.as_mut_slice().zeroize();
        Ok(Self {
            public_key: MlKem512PublicKey { data: ek.to_bytes().as_slice().to_vec() },
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
    #[cfg(feature = "rand")]
    pub fn encapsulate(&self) -> Result<(MlKem512Ciphertext, MlKem512SharedSecret), PqError> {
        self.encapsulate_with_rng(&mut rand_core::OsRng)
    }

    /// Encapsulates to this public key using caller-provided randomness.
    pub fn encapsulate_with_rng<R>(
        &self,
        rng: &mut R,
    ) -> Result<(MlKem512Ciphertext, MlKem512SharedSecret), PqError>
    where
        R: RngCore + CryptoRng,
    {
        let mut coins = [0_u8; MLKEM512_SHARED_SECRET_BYTES];
        rng.fill_bytes(&mut coins);
        let result = self.encapsulate_deterministic(&coins);
        coins.zeroize();
        result
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

        let ek_arr = Key::<MlKem512EncapsulationKey>::try_from(self.as_bytes())
            .map_err(|_| PqError::BackendFailure)?;
        let ek = MlKem512EncapsulationKey::new(&ek_arr).map_err(|_| PqError::BackendFailure)?;
        let mut m = B32::try_from(coins).map_err(|_| PqError::BackendFailure)?;
        let (ct, mut ss) = ek.encapsulate_deterministic(&m);
        let shared_secret = MlKem512SharedSecret::from_slice(ss.as_slice())?;
        m.as_mut_slice().zeroize();
        ss.as_mut_slice().zeroize();
        Ok((MlKem512Ciphertext { data: ct.as_slice().to_vec() }, shared_secret))
    }
}

impl MlKem512SecretKey {
    /// Decapsulates an ML-KEM-512 ciphertext with this secret key.
    pub fn decapsulate(
        &self,
        ciphertext: &MlKem512Ciphertext,
    ) -> Result<MlKem512SharedSecret, PqError> {
        let mut dk_arr = ml_kem::ExpandedDecapsulationKey::<MlKem512>::try_from(self.as_bytes())
            .map_err(|_| PqError::BackendFailure)?;
        #[allow(deprecated)]
        let dk = MlKem512DecapsulationKey::from_expanded_bytes(&dk_arr)
            .map_err(|_| PqError::BackendFailure)?;
        let ct_arr = <ml_kem::Ciphertext<MlKem512>>::try_from(ciphertext.as_bytes())
            .map_err(|_| PqError::BackendFailure)?;
        let mut ss = dk.decapsulate(&ct_arr);
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

impl From<ConsensusPqError> for PqError {
    fn from(err: ConsensusPqError) -> Self {
        match err {
            ConsensusPqError::UnknownScheme(prefix) => Self::UnknownScheme(prefix),
            ConsensusPqError::InvalidKeyLength { expected, got } => {
                Self::InvalidKeyLength { expected, got }
            }
            ConsensusPqError::VerificationFailed => Self::VerificationFailed,
            ConsensusPqError::BackendFailure => Self::BackendFailure,
            ConsensusPqError::EmptyData => Self::EmptyData,
        }
    }
}

impl PqPublicKey {
    fn as_consensus_key(&self) -> Result<ConsensusPqPublicKey, PqError> {
        ConsensusPqPublicKey::from_scheme_and_bytes(self.scheme, self.as_bytes())
            .map_err(Into::into)
    }
}

fn is_valid_secret_key_encoding(scheme: PqScheme, data: &[u8]) -> bool {
    if data.len() != scheme.seckey_len() {
        return false;
    }
    match scheme {
        PqScheme::Falcon512 => data.first().copied() == Some(0x59),
        PqScheme::Falcon1024 => data.first().copied() == Some(0x5A),
        PqScheme::MlDsa44 | PqScheme::MlDsa65 | PqScheme::MlDsa87 => true,
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PqError {}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    fn tagged_seed(scheme: PqScheme, tag: u8) -> Vec<u8> {
        (0..scheme.deterministic_seed_len()).map(|i| tag ^ (i as u8).wrapping_mul(131)).collect()
    }

    fn deterministic_keypair(scheme: PqScheme, tag: u8) -> (PqPublicKey, PqSecretKey) {
        scheme.generate_keypair_from_seed(&tagged_seed(scheme, tag)).unwrap()
    }

    fn all_signature_schemes() -> [PqScheme; 5] {
        [
            PqScheme::Falcon512,
            PqScheme::Falcon1024,
            PqScheme::MlDsa44,
            PqScheme::MlDsa65,
            PqScheme::MlDsa87,
        ]
    }

    fn test_rng(tag: u64) -> DeterministicTestRng {
        DeterministicTestRng::new(tag)
    }

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
            let (_, sk) = deterministic_keypair(scheme, scheme.prefix());
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
            let (_, sk) = deterministic_keypair(scheme, scheme.prefix());
            let reparsed = PqSecretKey::decode_slice(sk.as_bytes(), true).unwrap();
            assert_eq!(reparsed, sk);
        }
    }

    #[test]
    fn seckey_legacy_decode_disallowed_when_prefix_missing() {
        let (_, sk) = deterministic_keypair(PqScheme::Falcon512, 0x51);
        assert_eq!(
            PqSecretKey::decode_slice(sk.as_bytes(), false).unwrap_err(),
            PqError::InvalidKeyLength { expected: 0, got: sk.as_bytes().len() }
        );
    }

    #[test]
    fn falcon_seckey_validates_scheme_header_byte() {
        let (_, sk_512) = deterministic_keypair(PqScheme::Falcon512, 0x52);
        let mut bad_512 = sk_512.as_bytes().to_vec();
        bad_512[0] = 0x58;
        assert_eq!(
            PqSecretKey::from_slice(PqScheme::Falcon512, &bad_512).unwrap_err(),
            PqError::InvalidSecretKeyEncoding(PqScheme::Falcon512)
        );

        let (_, sk_1024) = deterministic_keypair(PqScheme::Falcon1024, 0x53);
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
            let mut rng = test_rng(u64::from(scheme.prefix()));
            let (pk, sk) = scheme.generate_keypair_with_rng(&mut rng).unwrap();
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
            let (pk, sk) = deterministic_keypair(scheme, scheme.prefix());
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
            let (pk, sk) = deterministic_keypair(scheme, scheme.prefix());
            let mut rng = test_rng(u64::from(scheme.prefix()));
            let sig = PqSignature::sign_msg32_with_rng(&msg, &sk, &mut rng).unwrap();
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
            let (pk, sk) = deterministic_keypair(scheme, scheme.prefix());
            let mut rng = test_rng(0x64 + u64::from(scheme.prefix()));
            let sig = PqSignature::sign_msg64_with_rng(&msg, &sk, &mut rng).unwrap();
            assert!(sig.len() <= scheme.max_sig_len());
            sig.verify_msg64(&msg, &pk).unwrap();

            let wrong_msg = [0xCCu8; 64];
            assert_eq!(sig.verify_msg64(&wrong_msg, &pk).unwrap_err(), PqError::VerificationFailed);
        }
    }

    #[test]
    fn corrupted_signatures_are_rejected_for_all_schemes() {
        let msg32 = [0x5Au8; 32];
        let msg64 = [0x33u8; 64];

        for scheme in all_signature_schemes() {
            let (pk, sk) = deterministic_keypair(scheme, scheme.prefix());

            let mut rng32 = test_rng(0x5100 + u64::from(scheme.prefix()));
            let sig32 = PqSignature::sign_msg32_with_rng(&msg32, &sk, &mut rng32).unwrap();
            let mut corrupted32 = sig32.as_bytes().to_vec();
            let last32 = corrupted32.last_mut().expect("signature should not be empty");
            *last32 ^= 0x01;
            let corrupted32 = PqSignature::from_slice(&corrupted32);
            assert!(
                corrupted32.verify_msg32(&msg32, &pk).is_err(),
                "{scheme:?} corrupted 32-byte-message signature verified"
            );

            let mut rng64 = test_rng(0x6400 + u64::from(scheme.prefix()));
            let sig64 = PqSignature::sign_msg64_with_rng(&msg64, &sk, &mut rng64).unwrap();
            let mut corrupted64 = sig64.as_bytes().to_vec();
            let last64 = corrupted64.last_mut().expect("signature should not be empty");
            *last64 ^= 0x01;
            let corrupted64 = PqSignature::from_slice(&corrupted64);
            assert!(
                corrupted64.verify_msg64(&msg64, &pk).is_err(),
                "{scheme:?} corrupted 64-byte-message signature verified"
            );
        }
    }

    #[test]
    fn cross_scheme_signatures_are_rejected_for_all_schemes() {
        let msg = [0xA7u8; 32];
        let schemes = all_signature_schemes();

        for signing_scheme in schemes {
            let (_, sk) = deterministic_keypair(signing_scheme, signing_scheme.prefix());
            let mut rng = test_rng(0x7700 + u64::from(signing_scheme.prefix()));
            let sig = PqSignature::sign_msg32_with_rng(&msg, &sk, &mut rng).unwrap();

            for verifying_scheme in schemes {
                if verifying_scheme == signing_scheme {
                    continue;
                }
                let (wrong_pk, _) =
                    deterministic_keypair(verifying_scheme, verifying_scheme.prefix() ^ 0x55);
                assert!(
                    sig.verify_msg32(&msg, &wrong_pk).is_err(),
                    "{signing_scheme:?} signature verified against {verifying_scheme:?} key"
                );
            }
        }
    }

    #[test]
    fn falcon512_legacy_signatures_roundtrip_for_msg32() {
        let msg = [0x42_u8; 32];
        let (pk, sk) = deterministic_keypair(PqScheme::Falcon512, 0x54);

        let strict = PqSignature::sign_msg32_with_rng(&msg, &sk, &mut test_rng(0x54)).unwrap();
        let legacy =
            PqSignature::sign_msg32_legacy_with_rng(&msg, &sk, &mut test_rng(0x55)).unwrap();

        assert_eq!(legacy.as_bytes().first().copied(), Some(0x39));
        assert!(legacy.len() <= 690);
        assert_ne!(legacy, strict);
        legacy.verify_msg32_legacy(&msg, &pk).unwrap();
        legacy.verify_msg32_allow_legacy(&msg, &pk).unwrap();
    }

    #[test]
    fn falcon512_legacy_signatures_roundtrip_for_msg64() {
        let msg = [0x24_u8; 64];
        let (pk, sk) = deterministic_keypair(PqScheme::Falcon512, 0x56);

        let legacy =
            PqSignature::sign_msg64_legacy_with_rng(&msg, &sk, &mut test_rng(0x56)).unwrap();

        assert_eq!(legacy.as_bytes().first().copied(), Some(0x39));
        assert!(legacy.len() <= 690);
        legacy.verify_msg64_legacy(&msg, &pk).unwrap();
        legacy.verify_msg64_allow_legacy(&msg, &pk).unwrap();
    }

    #[test]
    fn scheme_auxpow_gate_matches_node_policy() {
        let mut params = Params::MAINNET;
        params.auxpow_start_height = Some(crate::BlockHeight::from_u32(100));

        assert!(PqScheme::Falcon512.is_allowed_by_params_at_height(0, &params));
        assert!(!PqScheme::MlDsa44.is_allowed_by_params_at_height(0, &params));
        assert!(PqScheme::MlDsa44.is_allowed_by_params_at_height(100, &params));

        let no_auxpow = Params::MAINNET;
        assert!(PqScheme::Falcon512.is_allowed_by_params_at_height(1_000_000, &no_auxpow));
        assert!(!PqScheme::MlDsa87.is_allowed_by_params_at_height(1_000_000, &no_auxpow));
    }

    #[test]
    fn mlkem512_roundtrip() {
        let keypair = MlKem512Keypair::generate_with_rng(&mut test_rng(0x57));
        let (ciphertext, shared_secret) =
            keypair.public_key().encapsulate_with_rng(&mut test_rng(0x58)).unwrap();
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

    #[cfg(feature = "tidecoin-node-validation")]
    #[test]
    fn mlkem512_deterministic_paths_match_node() {
        let harness = match node_parity::TidecoinNodeHarness::from_env() {
            Ok(harness) => harness,
            Err(err) => {
                std::eprintln!("skipping ML-KEM node-backed validation test: {err}");
                return;
            }
        };
        let coins = [0x44_u8; MLKEM512_KEYPAIR_COINS_BYTES];
        let enc_coins = [0x45_u8; MLKEM512_SHARED_SECRET_BYTES];

        let rust_pair = MlKem512Keypair::generate_deterministic(&coins).unwrap();
        let (node_pk, node_sk) = harness
            .mlkem512_keypair_from_coins(&coins, MLKEM512_PUBLICKEY_BYTES, MLKEM512_SECRETKEY_BYTES)
            .unwrap();
        assert_eq!(rust_pair.public_key().as_bytes(), node_pk.as_slice());
        assert_eq!(rust_pair.secret_key().as_bytes(), node_sk.as_slice());

        let (rust_ct, rust_ss) =
            rust_pair.public_key().encapsulate_deterministic(&enc_coins).unwrap();
        let (node_ct, node_ss) = harness
            .mlkem512_encaps_deterministic(
                rust_pair.public_key().as_bytes(),
                &enc_coins,
                MLKEM512_CIPHERTEXT_BYTES,
                MLKEM512_SHARED_SECRET_BYTES,
            )
            .unwrap();
        assert_eq!(rust_ct.as_bytes(), node_ct.as_slice());
        assert_eq!(rust_ss.as_bytes().as_slice(), node_ss.as_slice());

        let rust_recovered = rust_pair.secret_key().decapsulate(&rust_ct).unwrap();
        let node_recovered = harness
            .mlkem512_decaps(
                rust_ct.as_bytes(),
                rust_pair.secret_key().as_bytes(),
                MLKEM512_SHARED_SECRET_BYTES,
            )
            .unwrap();
        assert_eq!(rust_recovered.as_bytes().as_slice(), node_recovered.as_slice());
    }

    #[test]
    fn secret_types_require_drop_for_zeroization() {
        assert!(core::mem::needs_drop::<PqSecretKey>());
        assert!(core::mem::needs_drop::<MlKem512SecretKey>());
        assert!(core::mem::needs_drop::<MlKem512SharedSecret>());
    }
}
