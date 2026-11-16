// SPDX-License-Identifier: CC0-1.0

//! Tidecoin key-related types.
//!
//! The live Tidecoin surface is PQ-native. This module therefore exposes:
//! - public-key-hash wrappers used by legacy hash-based script templates
//! - Tidecoin node-compatible PQ WIF import/export helpers

use core::convert::Infallible;
use core::fmt;
use core::str::FromStr;

use hashes::hash160;
use internals::write_err;
use zeroize::Zeroizing;

use crate::crypto::pq::{PqError, PqPublicKey, PqScheme, PqSecretKey};
use crate::internal_macros::impl_asref_push_bytes;
use crate::network::{Network, NetworkKind};
use crate::prelude::{String, Vec};

hashes::hash_newtype! {
    /// A HASH160 of a public key payload.
    pub struct PubkeyHash(hash160::Hash);
    /// A HASH160 used by witness pubkey-hash programs.
    pub struct WPubkeyHash(hash160::Hash);
}

hashes::impl_hex_for_newtype!(PubkeyHash, WPubkeyHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(PubkeyHash, WPubkeyHash);

impl_asref_push_bytes!(PubkeyHash, WPubkeyHash);

/// Converts WIF network inputs into an exact Tidecoin network.
#[doc(hidden)]
pub trait IntoWifNetwork {
    /// Converts this value into the exact Tidecoin network used for WIF encoding.
    #[doc(hidden)]
    fn into_wif_network(self) -> Network;
}

impl IntoWifNetwork for Network {
    fn into_wif_network(self) -> Network {
        self
    }
}

impl IntoWifNetwork for NetworkKind {
    fn into_wif_network(self) -> Network {
        match self {
            Self::Main => Network::Tidecoin,
            Self::Test => Network::Testnet,
        }
    }
}

#[inline]
fn wif_network_prefix(network: Network) -> u8 {
    match network {
        Network::Tidecoin => 125,
        Network::Testnet => 180,
        Network::Regtest => 15,
    }
}

fn parse_wif_network_prefix(prefix: u8) -> Result<Network, InvalidAddressVersionError> {
    match prefix {
        125 => Ok(Network::Tidecoin),
        180 => Ok(Network::Testnet),
        15 => Ok(Network::Regtest),
        invalid => Err(InvalidAddressVersionError { invalid }),
    }
}

/// Encodes how a [`PqWifKey`] should be serialized to base58.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum PqWifFormat {
    /// Tidecoin node's current PQ secret format: `[network_prefix][scheme_prefix][raw_secret]`.
    Prefixed,
    /// Tidecoin node's legacy Falcon-512 format:
    /// `[network_prefix][raw_falcon512_secret][0x01][raw_pubkey]`.
    LegacyFalcon512,
}

/// A Tidecoin PQ private key with node-compatible base58 import/export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqWifKey {
    /// The PQ secret key carried by this WIF payload.
    pub secret_key: PqSecretKey,
    /// The public key matching `secret_key`.
    pub public_key: PqPublicKey,
    /// The network kind on which this key should be used.
    ///
    /// Regtest keys intentionally report [`NetworkKind::Test`] here. Use [`PqWifKey::network`]
    /// when the exact network matters for WIF round-tripping.
    pub network_kind: NetworkKind,
    network: Network,
    format: PqWifFormat,
}

impl PqWifKey {
    fn with_format(
        secret_key: PqSecretKey,
        public_key: PqPublicKey,
        network: impl IntoWifNetwork,
        format: PqWifFormat,
    ) -> Self {
        let network = network.into_wif_network();
        Self { network_kind: NetworkKind::from(network), network, secret_key, public_key, format }
    }

    /// Constructs a new PQ WIF key using Tidecoin node's current prefixed secret format.
    pub fn new(secret_key: PqSecretKey, network: impl IntoWifNetwork) -> Result<Self, PqError> {
        let public_key = PqPublicKey::from_secret_key(&secret_key)?;
        Ok(Self::with_format(secret_key, public_key, network, PqWifFormat::Prefixed))
    }

    /// Constructs a new PQ WIF key using Tidecoin node's legacy Falcon-512 format.
    pub fn new_legacy_falcon512(
        secret_key: PqSecretKey,
        network: impl IntoWifNetwork,
    ) -> Result<Self, FromPqWifError> {
        if secret_key.scheme() != PqScheme::Falcon512 {
            return Err(UnsupportedLegacyWifSchemeError { scheme: secret_key.scheme() }.into());
        }
        let public_key = PqPublicKey::from_secret_key(&secret_key)?;
        Ok(Self::with_format(secret_key, public_key, network, PqWifFormat::LegacyFalcon512))
    }

    /// Returns the exact network carried by this WIF key.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the serialization format this key will use.
    pub fn format(&self) -> PqWifFormat {
        self.format
    }

    /// Formats the key to Tidecoin node's base58 secret format.
    pub fn fmt_wif(&self, fmt: &mut dyn fmt::Write) -> fmt::Result {
        let prefixed_secret = self.secret_key.to_prefixed_bytes();
        let prefixed_public = self.public_key.to_prefixed_bytes();
        let mut data =
            Zeroizing::new(Vec::with_capacity(1 + prefixed_secret.len() + prefixed_public.len()));
        data.push(wif_network_prefix(self.network));
        match self.format {
            PqWifFormat::Prefixed => {
                data.extend_from_slice(&prefixed_secret);
            }
            PqWifFormat::LegacyFalcon512 => {
                debug_assert_eq!(self.secret_key.scheme(), PqScheme::Falcon512);
                data.extend_from_slice(self.secret_key.as_bytes());
                data.push(1);
                data.extend_from_slice(self.public_key.as_bytes());
            }
        }
        fmt.write_str(&base58::encode_check(&data))
    }

    /// Gets the Tidecoin node-compatible base58 encoding of this PQ private key.
    pub fn to_wif(&self) -> String {
        let mut buf = String::new();
        let _ = self.fmt_wif(&mut buf);
        buf.shrink_to_fit();
        buf
    }

    /// Parses the Tidecoin node-compatible base58 PQ secret format.
    pub fn from_wif(wif: &str) -> Result<Self, FromPqWifError> {
        let data = Zeroizing::new(base58::decode_check(wif)?);
        if data.len() < 2 {
            return Err(InvalidBase58PayloadLengthError { length: data.len() }.into());
        }

        let (&network_prefix, payload) =
            data.split_first().ok_or(InvalidBase58PayloadLengthError { length: data.len() })?;
        let network = parse_wif_network_prefix(network_prefix)?;

        let legacy_scheme = PqScheme::Falcon512;
        let legacy_total_len = legacy_scheme.seckey_len() + 1 + legacy_scheme.pubkey_len();
        if payload.len() == legacy_total_len && payload[legacy_scheme.seckey_len()] == 1 {
            let secret_key =
                PqSecretKey::decode_slice(&payload[..legacy_scheme.seckey_len()], true)?;
            if secret_key.scheme() != legacy_scheme {
                return Err(UnsupportedLegacyWifSchemeError { scheme: secret_key.scheme() }.into());
            }
            let mut prefixed_public = Vec::with_capacity(legacy_scheme.prefixed_pubkey_len());
            prefixed_public.push(legacy_scheme.prefix());
            prefixed_public.extend_from_slice(&payload[legacy_scheme.seckey_len() + 1..]);
            let public_key = PqPublicKey::from_prefixed_slice(&prefixed_public)?;
            let derived = PqPublicKey::from_secret_key(&secret_key)?;
            if public_key != derived {
                return Err(MismatchedPqPublicKeyError.into());
            }
            return Ok(Self::with_format(
                secret_key,
                public_key,
                network,
                PqWifFormat::LegacyFalcon512,
            ));
        }

        // DecodeSecret strips the historical compressed marker only when no
        // scheme prefix is present. Prefixed encodings must consume all bytes.
        let payload = if PqScheme::from_prefix(payload[0]).is_none() && payload.last() == Some(&1) {
            &payload[..payload.len() - 1]
        } else {
            payload
        };
        let secret_key = PqSecretKey::decode_slice(payload, true)?;
        let public_key = PqPublicKey::from_secret_key(&secret_key)?;
        Ok(Self::with_format(secret_key, public_key, network, PqWifFormat::Prefixed))
    }
}

impl FromStr for PqWifKey {
    type Err = FromPqWifError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_wif(s)
    }
}

/// Error generated from PQ WIF key format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromPqWifError {
    /// A base58 decoding error.
    Base58(base58::Error),
    /// Base58 decoded data was an invalid length.
    InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
    /// Base58 decoded data contained an invalid address version byte.
    InvalidAddressVersion(InvalidAddressVersionError),
    /// PQ key decoding or validation failed.
    Pq(PqError),
    /// Legacy PQ WIF is only defined for Falcon-512.
    UnsupportedLegacyWifScheme(UnsupportedLegacyWifSchemeError),
    /// Legacy PQ WIF carried a public key that does not match the secret key.
    MismatchedPublicKey(MismatchedPqPublicKeyError),
}

impl From<Infallible> for FromPqWifError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for FromPqWifError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Base58(ref e) => write_err!(f, "invalid base58"; e),
            Self::InvalidBase58PayloadLength(ref e) => {
                write_err!(f, "decoded base58 data was an invalid length"; e)
            }
            Self::InvalidAddressVersion(ref e) => {
                write_err!(f, "decoded base58 data contained an invalid address version byte"; e)
            }
            Self::Pq(ref e) => write_err!(f, "PQ private key validation failed"; e),
            Self::UnsupportedLegacyWifScheme(ref e) => {
                write_err!(f, "unsupported legacy PQ WIF scheme"; e)
            }
            Self::MismatchedPublicKey(ref e) => {
                write_err!(f, "legacy PQ WIF public key does not match secret key"; e)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromPqWifError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Base58(ref e) => Some(e),
            Self::InvalidBase58PayloadLength(ref e) => Some(e),
            Self::InvalidAddressVersion(ref e) => Some(e),
            Self::Pq(ref e) => Some(e),
            Self::UnsupportedLegacyWifScheme(ref e) => Some(e),
            Self::MismatchedPublicKey(ref e) => Some(e),
        }
    }
}

impl From<base58::Error> for FromPqWifError {
    fn from(e: base58::Error) -> Self {
        Self::Base58(e)
    }
}

impl From<PqError> for FromPqWifError {
    fn from(e: PqError) -> Self {
        Self::Pq(e)
    }
}

impl From<InvalidBase58PayloadLengthError> for FromPqWifError {
    fn from(e: InvalidBase58PayloadLengthError) -> Self {
        Self::InvalidBase58PayloadLength(e)
    }
}

impl From<InvalidAddressVersionError> for FromPqWifError {
    fn from(e: InvalidAddressVersionError) -> Self {
        Self::InvalidAddressVersion(e)
    }
}

impl From<UnsupportedLegacyWifSchemeError> for FromPqWifError {
    fn from(e: UnsupportedLegacyWifSchemeError) -> Self {
        Self::UnsupportedLegacyWifScheme(e)
    }
}

impl From<MismatchedPqPublicKeyError> for FromPqWifError {
    fn from(e: MismatchedPqPublicKeyError) -> Self {
        Self::MismatchedPublicKey(e)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PqWifKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_wif())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PqWifKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct PqWifVisitor;

        impl serde::de::Visitor<'_> for PqWifVisitor {
            type Value = PqWifKey;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("an ASCII Tidecoin PQ WIF string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(s) = core::str::from_utf8(v) {
                    s.parse::<PqWifKey>().map_err(E::custom)
                } else {
                    Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse::<PqWifKey>().map_err(E::custom)
            }
        }

        d.deserialize_str(PqWifVisitor)
    }
}

/// Decoded base58 data was an invalid length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBase58PayloadLengthError {
    pub(crate) length: usize,
}

impl InvalidBase58PayloadLengthError {
    /// Returns the invalid payload length.
    pub fn invalid_base58_payload_length(&self) -> usize {
        self.length
    }
}

impl fmt::Display for InvalidBase58PayloadLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "decoded base58 data was an invalid length: {}", self.length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidBase58PayloadLengthError {}

/// Invalid address version in decoded base58 data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAddressVersionError {
    pub(crate) invalid: u8,
}

impl InvalidAddressVersionError {
    /// Returns the invalid version.
    pub fn invalid_address_version(&self) -> u8 {
        self.invalid
    }
}

impl fmt::Display for InvalidAddressVersionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid address version in decoded base58 data {}", self.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidAddressVersionError {}

/// Legacy PQ WIF is only defined for Falcon-512.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedLegacyWifSchemeError {
    pub(crate) scheme: PqScheme,
}

impl UnsupportedLegacyWifSchemeError {
    /// Returns the unsupported PQ scheme found in the legacy WIF path.
    pub fn scheme(&self) -> PqScheme {
        self.scheme
    }
}

impl fmt::Display for UnsupportedLegacyWifSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "legacy PQ WIF only supports Falcon-512, got {:?}", self.scheme)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnsupportedLegacyWifSchemeError {}

/// Legacy PQ WIF carried a public key that does not match the secret key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MismatchedPqPublicKeyError;

impl fmt::Display for MismatchedPqPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("legacy PQ WIF public key does not match secret key")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MismatchedPqPublicKeyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::PqSchemeCryptoExt as _;

    #[test]
    fn pq_wif_roundtrip_prefixed() {
        let (pk, sk) = PqScheme::Falcon512.generate_keypair_from_seed(&[0x42; 48]).unwrap();
        let encoded = PqWifKey::new(sk.clone(), Network::Tidecoin).unwrap().to_wif();
        let decoded = PqWifKey::from_wif(&encoded).unwrap();
        assert_eq!(decoded.secret_key, sk);
        assert_eq!(decoded.public_key, pk);
        assert_eq!(decoded.network(), Network::Tidecoin);
        assert_eq!(decoded.format(), PqWifFormat::Prefixed);
    }
}
