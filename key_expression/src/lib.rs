// SPDX-License-Identifier: CC0-1.0

//! Tidecoin key expression and deterministic derivation.
//!
//! This crate currently implements the Tidecoin node's `pqhd(...)` key
//! expression surface and the wallet descriptor strings built on top of it.

#![no_std]
#![doc(test(attr(warn(unused))))]
#![warn(deprecated_in_future)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

#[cfg(feature = "alloc")]
use tidecoin::Params;
use tidecoin::{pqhd, PqError, PqPublicKey, PqScheme, PqSecretKey, PqhdSeedId};

/// Wallet descriptor output types used by Tidecoin's PQHD wallet generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletOutputType {
    /// `pkh(...)`
    Legacy,
    /// `sh(wpkh(...))`
    P2shSegwit,
    /// `wpkh(...)`
    Bech32,
    /// `wsh512(pk(...))`
    Bech32Pq,
}

impl WalletOutputType {
    /// Returns the node string for this output type.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::P2shSegwit => "p2sh-segwit",
            Self::Bech32 => "bech32",
            Self::Bech32Pq => "bech32pq",
        }
    }
}

impl fmt::Display for WalletOutputType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WalletOutputType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "legacy" => Ok(Self::Legacy),
            "p2sh-segwit" => Ok(Self::P2shSegwit),
            "bech32" => Ok(Self::Bech32),
            "bech32pq" => Ok(Self::Bech32Pq),
            _ => Err(Error::UnknownDescriptorWrapper),
        }
    }
}

/// Final derivation step for a `pqhd(...)` key expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyIndex {
    /// A fixed final hardened index.
    Fixed(u32),
    /// A ranged final hardened wildcard (`*h`).
    Wildcard,
}

/// Metadata about the fixed derivation path and final child selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PqhdKeyPathInfo {
    /// The five fixed hardened elements before the final child.
    pub fixed_path: [u32; 5],
    /// The final fixed child or wildcard.
    pub terminal: KeyIndex,
}

/// Parsed Tidecoin `pqhd(SEEDID32)/purposeh/cointypeh/schemeh/accounth/changeh/indexh|*h`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PqhdKeyExpression {
    seed_id: PqhdSeedId,
    scheme: PqScheme,
    account: u32,
    change: u32,
    index: KeyIndex,
}

impl PqhdKeyExpression {
    /// Creates a fixed-form `pqhd(...)` key expression.
    ///
    /// # Errors
    ///
    /// Returns an error if `change` is not `0` or `1`.
    pub fn fixed(
        seed_id: PqhdSeedId,
        scheme: PqScheme,
        account: u32,
        change: u32,
        index: u32,
    ) -> Result<Self, Error> {
        validate_change(change)?;
        Ok(Self { seed_id, scheme, account, change, index: KeyIndex::Fixed(index) })
    }

    /// Creates a ranged-form `pqhd(...)` key expression.
    ///
    /// # Errors
    ///
    /// Returns an error if `change` is not `0` or `1`.
    pub fn ranged(
        seed_id: PqhdSeedId,
        scheme: PqScheme,
        account: u32,
        change: u32,
    ) -> Result<Self, Error> {
        validate_change(change)?;
        Ok(Self { seed_id, scheme, account, change, index: KeyIndex::Wildcard })
    }

    /// Returns the seed id.
    pub fn seed_id(&self) -> PqhdSeedId {
        self.seed_id
    }

    /// Returns the scheme.
    pub fn scheme(&self) -> PqScheme {
        self.scheme
    }

    /// Returns the node-style scheme prefix byte.
    pub fn scheme_prefix(&self) -> u8 {
        self.scheme.prefix()
    }

    /// Returns the account element.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Returns the change element (`0` receive, `1` internal/change).
    pub fn change(&self) -> u32 {
        self.change
    }

    /// Returns the final derivation component.
    pub fn index(&self) -> KeyIndex {
        self.index
    }

    /// Returns whether this is a ranged expression (`*h`).
    pub fn is_range(&self) -> bool {
        self.index == KeyIndex::Wildcard
    }

    /// Returns descriptor metadata for the encoded path.
    pub fn key_path_info(&self) -> PqhdKeyPathInfo {
        PqhdKeyPathInfo {
            fixed_path: [
                pqhd::HARDENED | pqhd::PURPOSE,
                pqhd::HARDENED | pqhd::COIN_TYPE,
                pqhd::HARDENED | u32::from(self.scheme.prefix()),
                pqhd::HARDENED | self.account,
                pqhd::HARDENED | self.change,
            ],
            terminal: self.index,
        }
    }

    /// Returns the referenced seed ids.
    pub fn seed_ids(&self) -> [PqhdSeedId; 1] {
        [self.seed_id]
    }

    /// Resolves the full hardened PQHD v1 leaf path.
    ///
    /// # Errors
    ///
    /// Returns an error if a ranged expression is missing an external index or
    /// if a fixed expression is given one.
    pub fn leaf_path(&self, external_index: Option<u32>) -> Result<[u32; 6], Error> {
        let index = match (self.index, external_index) {
            (KeyIndex::Fixed(index), None) => index,
            (KeyIndex::Fixed(_), Some(_)) => return Err(Error::UnexpectedIndexForFixedExpression),
            (KeyIndex::Wildcard, Some(index)) => index,
            (KeyIndex::Wildcard, None) => return Err(Error::MissingIndexForRangedExpression),
        };

        Ok(pqhd::make_v1_leaf_path(self.scheme, self.account, self.change, index))
    }

    /// Derives the deterministic PQ keypair this expression resolves to.
    ///
    /// # Errors
    ///
    /// Returns an error if the expression cannot be resolved to a valid Tidecoin
    /// PQHD v1 leaf or if PQ key derivation fails.
    pub fn derive_keypair(
        &self,
        master_seed: &[u8; 32],
        external_index: Option<u32>,
    ) -> Result<(PqPublicKey, PqSecretKey), Error> {
        let path = self.leaf_path(external_index)?;
        let master = pqhd::make_master_node(master_seed);
        let leaf = pqhd::derive_path(&path, &master).ok_or(Error::InvalidLeafPath)?;
        let material = pqhd::derive_leaf_material_v1(&leaf.node_secret, &path)
            .ok_or(Error::InvalidLeafPath)?;
        pqhd::derive_keypair_v1(&material).map_err(Error::Pq)
    }

    /// Derives only the public key for this expression.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::derive_keypair`].
    pub fn derive_public_key(
        &self,
        master_seed: &[u8; 32],
        external_index: Option<u32>,
    ) -> Result<PqPublicKey, Error> {
        self.derive_keypair(master_seed, external_index).map(|(pk, _)| pk)
    }
}

impl fmt::Display for PqhdKeyExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pqhd({})/{}h/{}h/{}h/{}h/{}h/",
            self.seed_id,
            pqhd::PURPOSE,
            pqhd::COIN_TYPE,
            self.scheme.prefix(),
            self.account,
            self.change
        )?;
        match self.index {
            KeyIndex::Fixed(index) => write!(f, "{}h", index),
            KeyIndex::Wildcard => f.write_str("*h"),
        }
    }
}

impl FromStr for PqhdKeyExpression {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('/');
        let head = parts.next().ok_or(Error::NotPqhdExpression)?;
        if !head.starts_with("pqhd(") || !head.ends_with(')') {
            return Err(Error::NotPqhdExpression);
        }

        let seed_hex = &head[5..head.len() - 1];
        if seed_hex.len() != 64 {
            return Err(Error::SeedIdLength(seed_hex.len()));
        }
        let seed_id = PqhdSeedId::from_str(seed_hex).map_err(|_| Error::InvalidSeedId)?;

        let mut elems = [0_u32; 6];
        let mut elem_count = 0_usize;
        let mut wildcard = false;
        for part in parts {
            if part.starts_with('<') && part.ends_with('>') {
                return Err(Error::MultipathUnsupported);
            }
            if part == "*h" || part == "*'" {
                wildcard = true;
                continue;
            }
            if part == "*" {
                return Err(Error::WildcardMustBeHardened);
            }
            if wildcard {
                return Err(Error::WildcardMustBeFinalElement);
            }
            if elem_count >= elems.len() {
                return Err(Error::PathElementCount(elem_count + 1));
            }
            elems[elem_count] = parse_hardened_index(part)?;
            elem_count += 1;
        }

        if wildcard {
            if elem_count != 5 {
                return Err(Error::WildcardRequiresFiveFixedElements(elem_count));
            }
        } else if elem_count != 6 {
            return Err(Error::FixedRequiresSixElements(elem_count));
        }

        check_eq(elems[0], pqhd::PURPOSE, Error::PurposeMustBe(pqhd::PURPOSE, elems[0]))?;
        check_eq(elems[1], pqhd::COIN_TYPE, Error::CoinTypeMustBe(pqhd::COIN_TYPE, elems[1]))?;

        let scheme_u32 = elems[2];
        if scheme_u32 > u32::from(u8::MAX) {
            return Err(Error::SchemeIdOutOfRange(scheme_u32));
        }
        let scheme =
            PqScheme::from_prefix(scheme_u32 as u8).ok_or(Error::UnknownScheme(scheme_u32))?;

        let change = elems[4];
        validate_change(change)?;

        let index = if wildcard { KeyIndex::Wildcard } else { KeyIndex::Fixed(elems[5]) };
        Ok(Self { seed_id, scheme, account: elems[3], change, index })
    }
}

/// A typed node-style descriptor wrapper around a `pqhd(...)` key expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PqhdDescriptor {
    output_type: WalletOutputType,
    key_expression: PqhdKeyExpression,
}

impl PqhdDescriptor {
    /// Creates a descriptor from its wrapper type and inner key expression.
    pub fn new(output_type: WalletOutputType, key_expression: PqhdKeyExpression) -> Self {
        Self { output_type, key_expression }
    }

    /// Returns the wrapper output type.
    pub fn output_type(&self) -> WalletOutputType {
        self.output_type
    }

    /// Returns the wrapped key expression.
    pub fn key_expression(&self) -> &PqhdKeyExpression {
        &self.key_expression
    }

    /// Returns whether the wrapped key expression is ranged.
    pub fn is_range(&self) -> bool {
        self.key_expression.is_range()
    }

    /// Returns the wrapped scheme prefix.
    pub fn scheme_prefix(&self) -> u8 {
        self.key_expression.scheme_prefix()
    }

    /// Returns the wrapped seed ids.
    pub fn seed_ids(&self) -> [PqhdSeedId; 1] {
        self.key_expression.seed_ids()
    }
}

impl fmt::Display for PqhdDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.output_type {
            WalletOutputType::Legacy => write!(f, "pkh({})", self.key_expression),
            WalletOutputType::P2shSegwit => write!(f, "sh(wpkh({}))", self.key_expression),
            WalletOutputType::Bech32 => write!(f, "wpkh({})", self.key_expression),
            WalletOutputType::Bech32Pq => write!(f, "wsh512(pk({}))", self.key_expression),
        }
    }
}

impl FromStr for PqhdDescriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(inner) = s.strip_prefix("pkh(").and_then(|rest| rest.strip_suffix(')')) {
            return Ok(Self::new(WalletOutputType::Legacy, inner.parse()?));
        }
        if let Some(inner) = s.strip_prefix("sh(wpkh(").and_then(|rest| rest.strip_suffix("))")) {
            return Ok(Self::new(WalletOutputType::P2shSegwit, inner.parse()?));
        }
        if let Some(inner) = s.strip_prefix("wpkh(").and_then(|rest| rest.strip_suffix(')')) {
            return Ok(Self::new(WalletOutputType::Bech32, inner.parse()?));
        }
        if let Some(inner) = s.strip_prefix("wsh512(pk(").and_then(|rest| rest.strip_suffix("))")) {
            return Ok(Self::new(WalletOutputType::Bech32Pq, inner.parse()?));
        }
        Err(Error::UnknownDescriptorWrapper)
    }
}

/// Generates the same ranged wallet descriptor strings as Tidecoin node's
/// `GeneratePQHDWalletDescriptor(...)`.
#[cfg(feature = "alloc")]
///
/// # Errors
///
/// Returns an error if the requested scheme is not allowed at `target_height`
/// or if `wsh512(pk(...))` is requested before `AuxPoW`.
pub fn generate_pqhd_wallet_descriptor(
    seed_id: PqhdSeedId,
    scheme: PqScheme,
    output_type: WalletOutputType,
    internal: bool,
    params: impl AsRef<Params>,
    target_height: u32,
) -> Result<String, Error> {
    let params = params.as_ref();
    if !scheme.is_allowed_at_height(target_height, params) {
        return Err(Error::SchemeNotAllowedAtHeight { scheme, height: target_height });
    }

    if output_type == WalletOutputType::Bech32Pq {
        match params.auxpow_start_height {
            Some(start_height) if target_height >= start_height.to_u32() => {}
            _ => return Err(Error::Bech32PqNotAllowedAtHeight(target_height)),
        }
    }

    let expr = PqhdKeyExpression::ranged(seed_id, scheme, 0, u32::from(internal))?.to_string();
    Ok(match output_type {
        WalletOutputType::Legacy => alloc::format!("pkh({expr})"),
        WalletOutputType::P2shSegwit => alloc::format!("sh(wpkh({expr}))"),
        WalletOutputType::Bech32 => alloc::format!("wpkh({expr})"),
        WalletOutputType::Bech32Pq => alloc::format!("wsh512(pk({expr}))"),
    })
}

/// Errors produced by `pqhd(...)` parsing, derivation, and descriptor generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input is not a `pqhd(...)` key expression.
    NotPqhdExpression,
    /// The seed id does not have the required 32-byte hex length.
    SeedIdLength(usize),
    /// The seed id is not valid hex.
    InvalidSeedId,
    /// The expression used multipath syntax, which Tidecoin does not support here.
    MultipathUnsupported,
    /// The wildcard must use hardened syntax (`*h` or `*'`).
    WildcardMustBeHardened,
    /// The wildcard may only appear as the final path element.
    WildcardMustBeFinalElement,
    /// A path element is missing the hardened marker.
    HardenedOnly,
    /// A path element could not be parsed as a `u32`.
    InvalidPathElement,
    /// Too many path elements were provided.
    PathElementCount(usize),
    /// Wildcard expressions must provide exactly five fixed elements.
    WildcardRequiresFiveFixedElements(usize),
    /// Fixed expressions must provide exactly six hardened elements.
    FixedRequiresSixElements(usize),
    /// The purpose element must match Tidecoin PQHD v1.
    PurposeMustBe(u32, u32),
    /// The coin type element must match Tidecoin PQHD v1.
    CoinTypeMustBe(u32, u32),
    /// The scheme element does not fit in a single byte.
    SchemeIdOutOfRange(u32),
    /// The scheme prefix is unknown.
    UnknownScheme(u32),
    /// The change element must be `0` or `1`.
    InvalidChange(u32),
    /// A ranged expression needs an external index to resolve.
    MissingIndexForRangedExpression,
    /// A fixed expression may not be given an external index.
    UnexpectedIndexForFixedExpression,
    /// The resolved path failed Tidecoin PQHD validation.
    InvalidLeafPath,
    /// Tidecoin PQ key derivation failed.
    Pq(PqError),
    /// The scheme is not allowed at the requested height.
    SchemeNotAllowedAtHeight {
        /// The requested scheme.
        scheme: PqScheme,
        /// The requested height.
        height: u32,
    },
    /// `wsh512(pk(...))` is not allowed before `AuxPoW`.
    Bech32PqNotAllowedAtHeight(u32),
    /// The descriptor wrapper is not one of the supported Tidecoin forms.
    UnknownDescriptorWrapper,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPqhdExpression => f.write_str("not a pqhd() key expression"),
            Self::SeedIdLength(len) => {
                write!(f, "pqhd() seed id is not 32-byte hex ({} characters)", len)
            }
            Self::InvalidSeedId => f.write_str("pqhd() seed id is not valid hex"),
            Self::MultipathUnsupported => {
                f.write_str("pqhd() does not support multipath derivation")
            }
            Self::WildcardMustBeHardened => f.write_str("pqhd() wildcard form must use *h"),
            Self::WildcardMustBeFinalElement => {
                f.write_str("pqhd() wildcard must be the final path element")
            }
            Self::HardenedOnly => f.write_str("pqhd() derivation must be hardened-only"),
            Self::InvalidPathElement => f.write_str("pqhd() path element is not a valid u32"),
            Self::PathElementCount(count) => write!(
                f,
                "pqhd() expects 6 hardened path elements after the seed id, got {}",
                count
            ),
            Self::WildcardRequiresFiveFixedElements(count) => write!(
                f,
                "pqhd() wildcard form must have exactly 5 fixed elements before *h, got {}",
                count
            ),
            Self::FixedRequiresSixElements(count) => write!(
                f,
                "pqhd() fixed form must have exactly 6 hardened path elements, got {}",
                count
            ),
            Self::PurposeMustBe(expected, got) => {
                write!(f, "pqhd() purpose must be {}, got {}", expected, got)
            }
            Self::CoinTypeMustBe(expected, got) => {
                write!(f, "pqhd() coin_type must be {}, got {}", expected, got)
            }
            Self::SchemeIdOutOfRange(got) => {
                write!(f, "pqhd() scheme id must fit in uint8, got {}", got)
            }
            Self::UnknownScheme(got) => write!(f, "pqhd() scheme id {} is not recognized", got),
            Self::InvalidChange(got) => write!(f, "pqhd() change must be 0 or 1, got {}", got),
            Self::MissingIndexForRangedExpression => {
                f.write_str("pqhd() ranged expression requires an external index")
            }
            Self::UnexpectedIndexForFixedExpression => {
                f.write_str("pqhd() fixed expression does not accept an external index")
            }
            Self::InvalidLeafPath => {
                f.write_str("pqhd() resolved path is not a valid Tidecoin PQHD v1 leaf")
            }
            Self::Pq(err) => fmt::Display::fmt(err, f),
            Self::SchemeNotAllowedAtHeight { scheme, height } => {
                write!(f, "PQ scheme {:?} not allowed at height {}", scheme, height)
            }
            Self::Bech32PqNotAllowedAtHeight(height) => {
                write!(f, "PQ v1 outputs not allowed at height {}", height)
            }
            Self::UnknownDescriptorWrapper => f.write_str("unsupported pqhd() descriptor wrapper"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

fn parse_hardened_index(s: &str) -> Result<u32, Error> {
    let digits = if let Some(digits) = s.strip_suffix('h') {
        digits
    } else if let Some(digits) = s.strip_suffix('\'') {
        digits
    } else {
        return Err(Error::HardenedOnly);
    };

    u32::from_str(digits).map_err(|_| Error::InvalidPathElement)
}

fn validate_change(change: u32) -> Result<(), Error> {
    if change <= 1 {
        Ok(())
    } else {
        Err(Error::InvalidChange(change))
    }
}

fn check_eq(actual: u32, expected: u32, err: Error) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(err)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;

    use super::*;

    fn seed_id() -> PqhdSeedId {
        PqhdSeedId::from_str("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
    }

    fn master_seed() -> [u8; 32] {
        tidecoin::hex::decode_to_array::<32>(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap()
    }

    #[test]
    fn pqhd_key_expression_parsing_matches_node_shapes() {
        let ranged = "pqhd(000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)/10007h/6868h/7h/0h/0h/*h"
            .parse::<PqhdKeyExpression>()
            .unwrap();
        assert_eq!(ranged.to_string(), "pqhd(000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)/10007h/6868h/7h/0h/0h/*h");
        assert!(ranged.is_range());
        assert_eq!(ranged.scheme(), PqScheme::Falcon512);
        assert_eq!(ranged.index(), KeyIndex::Wildcard);

        let fixed = "pqhd(000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)/10007h/6868h/7h/0h/0h/0h"
            .parse::<PqhdKeyExpression>()
            .unwrap();
        assert_eq!(fixed.to_string(), "pqhd(000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)/10007h/6868h/7h/0h/0h/0h");
        assert!(!fixed.is_range());
        assert_eq!(fixed.index(), KeyIndex::Fixed(0));

        let apostrophe = "pqhd(000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)/10007'/6868'/7'/0'/1'/*'"
            .parse::<PqhdKeyExpression>()
            .unwrap();
        assert_eq!(apostrophe.to_string(), "pqhd(000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)/10007h/6868h/7h/0h/1h/*h");
    }

    #[test]
    fn pqhd_key_expression_rejects_node_negative_cases() {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

        let err = format!(
            "{}",
            format!("pqhd({seed})/10007/6868h/7h/0h/0h/*h")
                .parse::<PqhdKeyExpression>()
                .unwrap_err()
        );
        assert!(err.contains("hardened-only"));

        let err = format!(
            "{}",
            format!("pqhd({seed})/10007h/6868h/7h/0h/0h/*")
                .parse::<PqhdKeyExpression>()
                .unwrap_err()
        );
        assert!(err.contains("*h"));

        let err = format!(
            "{}",
            format!("pqhd({seed})/10008h/6868h/7h/0h/0h/*h")
                .parse::<PqhdKeyExpression>()
                .unwrap_err()
        );
        assert!(err.contains("purpose"));

        let err = format!(
            "{}",
            format!("pqhd({seed})/10007h/6868h/6h/0h/0h/*h")
                .parse::<PqhdKeyExpression>()
                .unwrap_err()
        );
        assert!(err.contains("not recognized"));

        let err = format!(
            "{}",
            "pqhd(0001020304)/10007h/6868h/7h/0h/0h/*h".parse::<PqhdKeyExpression>().unwrap_err()
        );
        assert!(err.contains("seed id"));
    }

    #[test]
    fn pqhd_key_expression_derives_same_keys_as_direct_pqhd_flow() {
        let expr = "pqhd(000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)/10007h/6868h/10h/2h/1h/*h"
            .parse::<PqhdKeyExpression>()
            .unwrap();

        let derived = expr.derive_keypair(&master_seed(), Some(5)).unwrap();

        let path = pqhd::make_v1_leaf_path(PqScheme::MlDsa65, 2, 1, 5);
        let master = pqhd::make_master_node(&master_seed());
        let leaf = pqhd::derive_path(&path, &master).unwrap();
        let material = pqhd::derive_leaf_material_v1(&leaf.node_secret, &path).unwrap();
        let direct = pqhd::derive_keypair_v1(&material).unwrap();

        assert_eq!(derived, direct);
    }

    #[test]
    fn pqhd_descriptor_wrappers_roundtrip() {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let cases = [
            (WalletOutputType::Legacy, format!("pkh(pqhd({seed})/10007h/6868h/7h/0h/0h/*h)")),
            (
                WalletOutputType::P2shSegwit,
                format!("sh(wpkh(pqhd({seed})/10007h/6868h/7h/0h/0h/*h))"),
            ),
            (WalletOutputType::Bech32, format!("wpkh(pqhd({seed})/10007h/6868h/7h/0h/0h/*h)")),
            (
                WalletOutputType::Bech32Pq,
                format!("wsh512(pk(pqhd({seed})/10007h/6868h/7h/0h/0h/*h))"),
            ),
        ];

        for (output_type, raw) in cases {
            let parsed = raw.parse::<PqhdDescriptor>().unwrap();
            assert_eq!(parsed.output_type(), output_type);
            assert_eq!(parsed.to_string(), raw);
            assert!(parsed.is_range());
            assert_eq!(parsed.scheme_prefix(), PqScheme::Falcon512.prefix());
            assert_eq!(parsed.seed_ids(), [seed_id()]);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn generate_wallet_descriptor_matches_node_templates() {
        let mut params = Params::MAINNET;
        params.auxpow_start_height = Some(tidecoin::BlockHeight::from_u32(100));

        let bech32 = generate_pqhd_wallet_descriptor(
            seed_id(),
            PqScheme::Falcon512,
            WalletOutputType::Bech32,
            false,
            &params,
            0,
        )
        .unwrap();
        assert_eq!(
            bech32,
            "wpkh(pqhd(000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)/10007h/6868h/7h/0h/0h/*h)"
        );

        let bech32_internal = generate_pqhd_wallet_descriptor(
            seed_id(),
            PqScheme::Falcon512,
            WalletOutputType::Bech32,
            true,
            &params,
            0,
        )
        .unwrap();
        assert_eq!(
            bech32_internal,
            "wpkh(pqhd(000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)/10007h/6868h/7h/0h/1h/*h)"
        );

        assert_eq!(
            generate_pqhd_wallet_descriptor(
                seed_id(),
                PqScheme::MlDsa44,
                WalletOutputType::Bech32,
                false,
                &params,
                0
            )
            .unwrap_err(),
            Error::SchemeNotAllowedAtHeight { scheme: PqScheme::MlDsa44, height: 0 }
        );

        let p2wsh512 = generate_pqhd_wallet_descriptor(
            seed_id(),
            PqScheme::MlDsa44,
            WalletOutputType::Bech32Pq,
            false,
            &params,
            100,
        )
        .unwrap();
        assert_eq!(
            p2wsh512,
            "wsh512(pk(pqhd(000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)/10007h/6868h/9h/0h/0h/*h))"
        );

        assert_eq!(
            generate_pqhd_wallet_descriptor(
                seed_id(),
                PqScheme::Falcon512,
                WalletOutputType::Bech32Pq,
                false,
                &params,
                0
            )
            .unwrap_err(),
            Error::Bech32PqNotAllowedAtHeight(0)
        );

        let parsed = p2wsh512.parse::<PqhdDescriptor>().unwrap();
        assert_eq!(parsed.output_type(), WalletOutputType::Bech32Pq);
        assert_eq!(parsed.to_string(), p2wsh512);
    }
}
