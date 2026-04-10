// SPDX-License-Identifier: CC0-1.0

//! Tidecoin addresses.
//!
//! Support for segwit and legacy addresses (bech32 and base58 respectively).
//!
//! # Examples
//!
//! ### Creating a new address from a known pubkey hash.
//!
//! ```rust
//! use tidecoin::{Address, Network, PubkeyHash};
//!
//! let hash = "162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse::<PubkeyHash>().unwrap();
//! let address = Address::p2pkh(hash, Network::Tidecoin);
//! ```
//!
//! ### Using an `Address` as a struct field.
//!
//! ```rust
//! # #[cfg(feature = "serde")] {
//! # use serde::{self, Deserialize, Serialize};
//! use tidecoin::address::{Address, NetworkValidation, NetworkValidationUnchecked};
//! #[derive(Serialize, Deserialize)]
//! struct Foo<V>
//!     where V: NetworkValidation,
//! {
//!     #[serde(bound(deserialize = "V: NetworkValidationUnchecked"))]
//!     address: Address<V>,
//! }
//! # }
//! ```

pub mod error;

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use bech32::primitives::decode::UncheckedHrpstring;
use bech32::primitives::gf32::Fe32;
use bech32::primitives::hrp::Hrp;
use bech32::{Bech32m, ByteIterExt as _, Fe32IterExt as _};
use internals::array::ArrayExt;

use crate::constants::{
    PUBKEY_ADDRESS_PREFIX_MAIN, PUBKEY_ADDRESS_PREFIX_REGTEST, PUBKEY_ADDRESS_PREFIX_TEST,
    SCRIPT_ADDRESS_PREFIX_MAIN, SCRIPT_ADDRESS_PREFIX_MAIN_ALT, SCRIPT_ADDRESS_PREFIX_REGTEST,
    SCRIPT_ADDRESS_PREFIX_REGTEST_ALT, SCRIPT_ADDRESS_PREFIX_TEST, SCRIPT_ADDRESS_PREFIX_TEST_ALT,
};
use crate::crypto::key::{PubkeyHash, WPubkeyHash};
use crate::network::{Network, NetworkKind, Params};
use crate::opcodes::Opcode;
use crate::prelude::{String, ToOwned};
use crate::script::witness_program::WitnessProgram;
use crate::script::witness_version::WitnessVersion;
use crate::script::{
    self, RedeemScriptSizeError, Script, ScriptExt as _, ScriptHash, ScriptHashableTag,
    ScriptPubKey, ScriptPubKeyBuf, ScriptPubKeyBufExt as _, ScriptPubKeyExt as _, WScriptHash,
    WitnessScript, WitnessScriptExt as _, WitnessScriptSizeError,
};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::error::{
        Base58Error, Bech32Error, FromScriptError, InvalidBase58PayloadLengthError,
        InvalidLegacyPrefixError, InvalidSegwitHrpError, LegacyAddressTooLongError,
        NetworkValidationError, ParseError, ParseBech32Error, UnknownAddressTypeError,
        UnknownHrpError,
};

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressType {
    /// Pay to pubkey hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
    /// Pay to witness pubkey hash.
    P2wpkh,
    /// Pay to witness script hash.
    P2wsh,
    /// Pay to witness script hash using SHA-512 (witness v1, 64-byte program).
    P2wsh512,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Self::P2pkh => "p2pkh",
            Self::P2sh => "p2sh",
            Self::P2wpkh => "p2wpkh",
            Self::P2wsh => "p2wsh",
            Self::P2wsh512 => "p2wsh512",
        })
    }
}

impl FromStr for AddressType {
    type Err = UnknownAddressTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(Self::P2pkh),
            "p2sh" => Ok(Self::P2sh),
            "p2wpkh" => Ok(Self::P2wpkh),
            "p2wsh" => Ok(Self::P2wsh),
            "p2wsh512" => Ok(Self::P2wsh512),
            _ => Err(UnknownAddressTypeError(s.to_owned())),
        }
    }
}

mod sealed {
    pub trait NetworkValidation {}
    impl NetworkValidation for super::NetworkChecked {}
    impl NetworkValidation for super::NetworkUnchecked {}

    pub trait NetworkValidationUnchecked {}
    impl NetworkValidationUnchecked for super::NetworkUnchecked {}
}

/// Marker of status of address's network validation. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
pub trait NetworkValidation:
    sealed::NetworkValidation + Sync + Send + Sized + Unpin + Copy
{
    /// Indicates whether this `NetworkValidation` is `NetworkChecked` or not.
    const IS_CHECKED: bool;
}

/// Marker trait for `FromStr` and `serde::Deserialize`.
///
/// This allows users to use `V: NetworkValidation` in conjunction with derives. Is only ever
/// implemented for `NetworkUnchecked`.
pub trait NetworkValidationUnchecked:
    NetworkValidation + sealed::NetworkValidationUnchecked + Sync + Send + Sized + Unpin
{
}

/// Marker that address's network has been successfully validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetworkChecked {}

/// Marker that address's network has not yet been validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetworkUnchecked {}

impl NetworkValidation for NetworkChecked {
    const IS_CHECKED: bool = true;
}
impl NetworkValidation for NetworkUnchecked {
    const IS_CHECKED: bool = false;
}

impl NetworkValidationUnchecked for NetworkUnchecked {}

/// The inner representation of an address, without the network validation tag.
///
/// This struct represents the inner representation of an address without the network validation
/// tag, which is used to ensure that addresses are used only on the appropriate network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AddressInner {
    P2pkh { hash: PubkeyHash, network: LegacyAddressNetwork },
    P2sh { hash: ScriptHash, network: LegacyAddressNetwork },
    Segwit { program: WitnessProgram, hrp: KnownHrp },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum LegacyAddressNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl LegacyAddressNetwork {
    const fn network_kind(self) -> NetworkKind {
        match self {
            Self::Mainnet => NetworkKind::Main,
            Self::Testnet | Self::Regtest => NetworkKind::Test,
        }
    }

    const fn network(self) -> Network {
        match self {
            Self::Mainnet => Network::Tidecoin,
            Self::Testnet => Network::Testnet,
            Self::Regtest => Network::Regtest,
        }
    }

    const fn p2pkh_prefix(self) -> u8 {
        match self {
            Self::Mainnet => PUBKEY_ADDRESS_PREFIX_MAIN,
            Self::Testnet => PUBKEY_ADDRESS_PREFIX_TEST,
            Self::Regtest => PUBKEY_ADDRESS_PREFIX_REGTEST,
        }
    }

    const fn p2sh_prefix(self) -> u8 {
        match self {
            Self::Mainnet => SCRIPT_ADDRESS_PREFIX_MAIN,
            Self::Testnet => SCRIPT_ADDRESS_PREFIX_TEST,
            Self::Regtest => SCRIPT_ADDRESS_PREFIX_REGTEST_ALT,
        }
    }
}

impl From<Network> for LegacyAddressNetwork {
    fn from(network: Network) -> Self {
        match network {
            Network::Tidecoin => Self::Mainnet,
            Network::Testnet => Self::Testnet,
            Network::Regtest => Self::Regtest,
        }
    }
}

impl From<NetworkKind> for LegacyAddressNetwork {
    fn from(network: NetworkKind) -> Self {
        match network {
            NetworkKind::Main => Self::Mainnet,
            NetworkKind::Test => Self::Testnet,
        }
    }
}

/// Converts legacy address network inputs into an exact Tidecoin network.
#[doc(hidden)]
pub trait IntoAddressNetwork {
    /// Converts this value into the exact Tidecoin network used for legacy address encoding.
    #[doc(hidden)]
    fn into_address_network(self) -> Network;
}

impl IntoAddressNetwork for Network {
    fn into_address_network(self) -> Network {
        self
    }
}

impl IntoAddressNetwork for NetworkKind {
    fn into_address_network(self) -> Network {
        match self {
            Self::Main => Network::Tidecoin,
            Self::Test => Network::Testnet,
        }
    }
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl fmt::Display for AddressInner {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use AddressInner::*;
        match self {
            P2pkh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = network.p2pkh_prefix();
                prefixed[1..].copy_from_slice(hash.as_byte_array());
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            P2sh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = network.p2sh_prefix();
                prefixed[1..].copy_from_slice(hash.as_byte_array());
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Segwit { program, hrp } => {
                let hrp = hrp.to_hrp();
                let version = Fe32::try_from(program.version().to_num())
                    .expect("version nums 0-16 are valid fe32 values");
                let prog = program.program().as_ref();

                let is_pq = matches!(
                    hrp,
                    h if h == KnownHrp::HRP_PQ_MAINNET
                        || h == KnownHrp::HRP_PQ_TESTNET
                        || h == KnownHrp::HRP_PQ_REGTEST
                );

                if is_pq {
                    encode_pq_bech32m(fmt, hrp, version, prog, fmt.alternate())
                } else if fmt.alternate() {
                    bech32::segwit::encode_upper_to_fmt_unchecked(fmt, hrp, version, prog)
                } else {
                    bech32::segwit::encode_lower_to_fmt_unchecked(fmt, hrp, version, prog)
                }
            }
        }
    }
}

/// Known bech32 human-readable parts.
///
/// This is the human-readable part before the separator (`1`) in a bech32 encoded address e.g.,
/// the "tbc" in "tbc1q...".
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum KnownHrp {
    /// The main Tidecoin network.
    Mainnet,
    /// The test networks.
    Testnets,
    /// The regtest network.
    Regtest,
    /// PQ (post-quantum) mainnet HRP for P2WSH-512 addresses.
    PqMainnet,
    /// PQ (post-quantum) testnet HRP for P2WSH-512 addresses.
    PqTestnets,
    /// PQ (post-quantum) regtest HRP for P2WSH-512 addresses.
    PqRegtest,
}

impl KnownHrp {
    const HRP_MAINNET: Hrp = Hrp::parse_unchecked("tbc");
    const HRP_TESTNET: Hrp = Hrp::parse_unchecked("ttbc");
    const HRP_REGTEST: Hrp = Hrp::parse_unchecked("rtbc");
    const HRP_PQ_MAINNET: Hrp = Hrp::parse_unchecked("q");
    const HRP_PQ_TESTNET: Hrp = Hrp::parse_unchecked("tq");
    const HRP_PQ_REGTEST: Hrp = Hrp::parse_unchecked("rq");

    /// Constructs a new [`KnownHrp`] from [`Network`].
    fn from_network(network: Network) -> Self {
        match network {
            Network::Tidecoin => Self::Mainnet,
            Network::Testnet => Self::Testnets,
            Network::Regtest => Self::Regtest,
        }
    }

    /// Constructs a PQ (post-quantum) [`KnownHrp`] from [`Network`].
    fn from_network_pq(network: Network) -> Self {
        match network {
            Network::Tidecoin => Self::PqMainnet,
            Network::Testnet => Self::PqTestnets,
            Network::Regtest => Self::PqRegtest,
        }
    }

    /// Constructs a new [`KnownHrp`] from a [`bech32::Hrp`].
    fn from_hrp(hrp: Hrp) -> Result<Self, UnknownHrpError> {
        if hrp == Self::HRP_MAINNET {
            Ok(Self::Mainnet)
        } else if hrp == Self::HRP_TESTNET {
            Ok(Self::Testnets)
        } else if hrp == Self::HRP_REGTEST {
            Ok(Self::Regtest)
        } else if hrp == Self::HRP_PQ_MAINNET {
            Ok(Self::PqMainnet)
        } else if hrp == Self::HRP_PQ_TESTNET {
            Ok(Self::PqTestnets)
        } else if hrp == Self::HRP_PQ_REGTEST {
            Ok(Self::PqRegtest)
        } else {
            Err(UnknownHrpError(hrp.to_lowercase()))
        }
    }

    /// Converts, infallibly a known HRP to a [`bech32::Hrp`].
    fn to_hrp(self) -> Hrp {
        match self {
            Self::Mainnet => Self::HRP_MAINNET,
            Self::Testnets => Self::HRP_TESTNET,
            Self::Regtest => Self::HRP_REGTEST,
            Self::PqMainnet => Self::HRP_PQ_MAINNET,
            Self::PqTestnets => Self::HRP_PQ_TESTNET,
            Self::PqRegtest => Self::HRP_PQ_REGTEST,
        }
    }
}

impl From<Network> for KnownHrp {
    fn from(n: Network) -> Self {
        Self::from_network(n)
    }
}

impl From<KnownHrp> for NetworkKind {
    fn from(hrp: KnownHrp) -> Self {
        match hrp {
            KnownHrp::Mainnet | KnownHrp::PqMainnet => Self::Main,
            KnownHrp::Testnets | KnownHrp::PqTestnets => Self::Test,
            KnownHrp::Regtest | KnownHrp::PqRegtest => Self::Test,
        }
    }
}

/// The data encoded by an `Address`.
///
/// This is the data used to encumber an output that pays to this address i.e., it is the address
/// excluding the network information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressData {
    /// Data encoded by a P2PKH address.
    P2pkh {
        /// The pubkey hash used to encumber outputs to this address.
        pubkey_hash: PubkeyHash,
    },
    /// Data encoded by a P2SH address.
    P2sh {
        /// The script hash used to encumber outputs to this address.
        script_hash: ScriptHash,
    },
    /// Data encoded by a SegWit address.
    Segwit {
        /// The witness program used to encumber outputs to this address.
        witness_program: WitnessProgram,
    },
}

internals::transparent_newtype! {
    /// A Tidecoin address.
    ///
    /// # Parsing addresses
    ///
    /// When parsing string as an address, one has to pay attention to the network, on which the parsed
    /// address is supposed to be valid. For the purpose of this validation, `Address` has
    /// [`is_valid_for_network`](Address<NetworkUnchecked>::is_valid_for_network) method. In order to provide more safety,
    /// enforced by compiler, `Address` also contains a special marker type, which indicates whether network of the parsed
    /// address has been checked. This marker type will prevent from calling certain functions unless the network
    /// verification has been successfully completed.
    ///
    /// The result of parsing an address is `Address<NetworkUnchecked>` suggesting that network of the parsed address
    /// has not yet been verified. To perform this verification, method [`require_network`](Address<NetworkUnchecked>::require_network)
    /// can be called, providing network on which the address is supposed to be valid. If the verification succeeds,
    /// `Address<NetworkChecked>` is returned.
    ///
    /// The types `Address` and `Address<NetworkChecked>` are synonymous, i.e. they can be used interchangeably.
    ///
    /// ```rust,no_run
    /// use std::str::FromStr;
    /// use tidecoin::{Address, Network};
    /// use tidecoin::address::{NetworkUnchecked, NetworkChecked};
    ///
    /// // variant 1
    /// let address: Address<NetworkUnchecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
    /// let _address: Address<NetworkChecked> = address.require_network(Network::Tidecoin).unwrap();
    ///
    /// // variant 2
    /// let _address: Address = Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap()
    ///                .require_network(Network::Tidecoin).unwrap();
    ///
    /// // variant 3
    /// let _address: Address<NetworkChecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse::<Address<_>>()
    ///                .unwrap().require_network(Network::Tidecoin).unwrap();
    /// ```
    ///
    /// ### Formatting addresses
    ///
    /// To format address into its textual representation, both `Debug` (for usage in programmer-facing,
    /// debugging context) and `Display` (for user-facing output) can be used, with the following caveats:
    ///
    /// 1. `Display` is implemented only for `Address<NetworkChecked>`:
    ///
    /// ```no_run
    /// # use tidecoin::address::{Address, NetworkChecked};
    /// let address: Address<NetworkChecked> = "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>()
    ///                .unwrap().assume_checked();
    /// assert_eq!(address.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
    /// ```
    ///
    /// ```compile_fail
    /// # use tidecoin::address::{Address, NetworkChecked};
    /// # use tidecoin::address::NetworkUnchecked;
    /// let address: Address<NetworkUnchecked> = "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>()
    ///                .unwrap();
    /// let s = address.to_string(); // does not compile
    /// ```
    ///
    /// 2. `Debug` on `Address<NetworkUnchecked>` does not produce clean address but address wrapped by
    ///    an indicator that its network has not been checked. This is to encourage programmer to properly
    ///    check the network and use `Display` in user-facing context.
    ///
    /// ```no_run
    /// # use tidecoin::address::{Address, NetworkUnchecked};
    /// let address: Address<NetworkUnchecked> = "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>()
    ///                .unwrap();
    /// assert_eq!(format!("{:?}", address), "Address<NetworkUnchecked>(132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM)");
    /// ```
    ///
    /// ```no_run
    /// # use tidecoin::address::{Address, NetworkChecked};
    /// let address: Address<NetworkChecked> = "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>()
    ///                .unwrap().assume_checked();
    /// assert_eq!(format!("{:?}", address), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
    /// ```
    ///
    /// Tidecoin supports P2SH, witness-v0, and Tidecoin witness-v1-512 address forms.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    // The `#[repr(transparent)]` attribute is used to guarantee the layout of the `Address` struct. It
    // is an implementation detail and users should not rely on it in their code.
    pub struct Address<V = NetworkChecked>(PhantomData<V>, AddressInner)
    where
        V: NetworkValidation;

    impl<V> Address<V> {
        fn from_inner_ref(inner: &_) -> &Self;
    }
}

#[cfg(feature = "serde")]
struct DisplayUnchecked<'a, N: NetworkValidation>(&'a Address<N>);

#[cfg(feature = "serde")]
impl<N: NetworkValidation> fmt::Display for DisplayUnchecked<'_, N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0.inner(), fmt)
    }
}

#[cfg(feature = "serde")]
impl<'de, U: NetworkValidationUnchecked> serde::Deserialize<'de> for Address<U> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use core::fmt::Formatter;

        struct Visitor<U>(PhantomData<U>);
        impl<U> serde::de::Visitor<'_> for Visitor<U>
        where
            U: NetworkValidationUnchecked + NetworkValidation,
            Address<U>: FromStr,
        {
            type Value = Address<U>;

            fn expecting(&self, f: &mut Formatter) -> core::fmt::Result {
                f.write_str("A Tidecoin address")
            }

            fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // We know that `U` is only ever `NetworkUnchecked` but the compiler does not.
                let address = v.parse::<Address<NetworkUnchecked>>().map_err(E::custom)?;
                Ok(Address::from_inner(address.to_inner()))
            }
        }

        deserializer.deserialize_str(Visitor(PhantomData::<U>))
    }
}

#[cfg(feature = "serde")]
impl<V: NetworkValidation> serde::Serialize for Address<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&DisplayUnchecked(self))
    }
}

/// Methods on [`Address`] that can be called on both `Address<NetworkChecked>` and
/// `Address<NetworkUnchecked>`.
impl<V: NetworkValidation> Address<V> {
    fn from_inner(inner: AddressInner) -> Self {
        Self(PhantomData, inner)
    }

    fn to_inner(self) -> AddressInner {
        self.1
    }

    fn inner(&self) -> &AddressInner {
        &self.1
    }

    /// Returns a reference to the address as if it was unchecked.
    pub fn as_unchecked(&self) -> &Address<NetworkUnchecked> {
        Address::from_inner_ref(self.inner())
    }

    /// Marks the network of this address as unchecked.
    pub fn to_unchecked(self) -> Address<NetworkUnchecked> {
        Address::from_inner(self.to_inner())
    }

    /// Marks the network of this address as unchecked.
    #[deprecated(since = "0.33.0", note = "use to_unchecked instead")]
    pub fn into_unchecked(self) -> Address<NetworkUnchecked> {
        Address::from_inner(self.to_inner())
    }

    /// Returns the [`NetworkKind`] of this address.
    pub fn network_kind(&self) -> NetworkKind {
        use AddressInner::*;
        match *self.inner() {
            P2pkh { hash: _, ref network } => network.network_kind(),
            P2sh { hash: _, ref network } => network.network_kind(),
            Segwit { program: _, ref hrp } => NetworkKind::from(*hrp),
        }
    }
}

/// Methods and functions that can be called only on `Address<NetworkChecked>`.
impl Address {
    /// Constructs a new pay-to-public-key-hash (P2PKH) [`Address`] from a public key.
    ///
    /// This is the preferred non-witness type address.
    #[inline]
    pub fn p2pkh(pk: impl Into<PubkeyHash>, network: impl IntoAddressNetwork) -> Self {
        let hash = pk.into();
        Self::from_inner(AddressInner::P2pkh {
            hash,
            network: LegacyAddressNetwork::from(network.into_address_network()),
        })
    }

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] from a script.
    ///
    /// This address type was introduced with BIP-0016 and is the popular type to implement multi-sig
    /// these days.
    #[inline]
    pub fn p2sh<T: ScriptHashableTag>(
        redeem_script: &Script<T>,
        network: impl IntoAddressNetwork,
    ) -> Result<Self, RedeemScriptSizeError> {
        let hash = redeem_script.script_hash()?;
        Ok(Self::p2sh_from_hash(hash, network))
    }

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] from a script hash.
    ///
    /// # Warning
    ///
    /// The `hash` pre-image (redeem script) must not exceed 520 bytes in length
    /// otherwise outputs created from the returned address will be un-spendable.
    pub fn p2sh_from_hash(hash: ScriptHash, network: impl IntoAddressNetwork) -> Self {
        Self::from_inner(AddressInner::P2sh {
            hash,
            network: LegacyAddressNetwork::from(network.into_address_network()),
        })
    }

    /// Constructs a new pay-to-witness-public-key-hash (P2WPKH) [`Address`] from a pubkey hash.
    pub fn p2wpkh(pubkey_hash: WPubkeyHash, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2wpkh(pubkey_hash);
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] that embeds a
    /// pay-to-witness-public-key-hash (P2WPKH).
    pub fn p2shwpkh(pubkey_hash: WPubkeyHash, network: impl IntoAddressNetwork) -> Self {
        let builder = ScriptPubKey::builder().push_int_unchecked(0).push_slice(pubkey_hash);
        let script_hash = builder.as_script().script_hash().expect("script is less than 520 bytes");
        Self::p2sh_from_hash(script_hash, network)
    }

    /// Constructs a new pay-to-witness-script-hash (P2WSH) [`Address`] from a witness script.
    pub fn p2wsh(
        witness_script: &WitnessScript,
        hrp: impl Into<KnownHrp>,
    ) -> Result<Self, WitnessScriptSizeError> {
        let program = WitnessProgram::p2wsh(witness_script)?;
        Ok(Self::from_witness_program(program, hrp))
    }

    /// Constructs a new pay-to-witness-script-hash (P2WSH) [`Address`] from a witness script hash.
    pub fn p2wsh_from_hash(hash: WScriptHash, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2wsh_from_hash(hash);
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] that embeds a
    /// pay-to-witness-script-hash (P2WSH).
    ///
    /// This is a SegWit address type that looks familiar (as p2sh) to legacy clients.
    pub fn p2shwsh(
        witness_script: &WitnessScript,
        network: impl IntoAddressNetwork,
    ) -> Result<Self, WitnessScriptSizeError> {
        let hash = witness_script.wscript_hash()?;
        let builder =
            ScriptPubKey::builder().push_int_unchecked(0).push_slice(hash.to_byte_array());
        let script_hash = builder.as_script().script_hash().expect("script is less than 520 bytes");
        Ok(Self::p2sh_from_hash(script_hash, network))
    }

    /// Constructs a new P2WSH-512 [`Address`] from a 64-byte SHA-512 script hash.
    ///
    /// Uses the PQ HRP namespace (`q`, `tq`, `rq`) appropriate for the given network.
    pub fn p2wsh512(script_hash: [u8; 64], network: Network) -> Self {
        let program = WitnessProgram::p2wsh512(script_hash);
        let hrp = KnownHrp::from_network_pq(network);
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new [`Address`] from an arbitrary [`WitnessProgram`].
    ///
    /// This only exists to support future witness versions. If you are doing normal mainnet things
    /// then you likely do not need this constructor.
    pub fn from_witness_program(program: WitnessProgram, hrp: impl Into<KnownHrp>) -> Self {
        let inner = AddressInner::Segwit { program, hrp: hrp.into() };
        Self::from_inner(inner)
    }

    /// Gets the address type of the [`Address`].
    ///
    /// # Returns
    ///
    /// None if unknown, non-standard or related to the future witness version.
    #[inline]
    pub fn address_type(&self) -> Option<AddressType> {
        match *self.inner() {
            AddressInner::P2pkh { .. } => Some(AddressType::P2pkh),
            AddressInner::P2sh { .. } => Some(AddressType::P2sh),
            AddressInner::Segwit { ref program, hrp: _ } => {
                if program.is_p2wpkh() {
                    Some(AddressType::P2wpkh)
                } else if program.is_p2wsh() {
                    Some(AddressType::P2wsh)
                } else if program.is_p2wsh512() {
                    Some(AddressType::P2wsh512)
                } else {
                    None
                }
            }
        }
    }

    /// Gets the address data from this address.
    pub fn to_address_data(self) -> AddressData {
        use AddressData::*;

        match *self.inner() {
            AddressInner::P2pkh { hash, network: _ } => P2pkh { pubkey_hash: hash },
            AddressInner::P2sh { hash, network: _ } => P2sh { script_hash: hash },
            AddressInner::Segwit { program, hrp: _ } => Segwit { witness_program: program },
        }
    }

    /// Gets the pubkey hash for this address if this is a P2PKH address.
    pub fn pubkey_hash(&self) -> Option<PubkeyHash> {
        use AddressInner::*;

        match *self.inner() {
            P2pkh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Gets the script hash for this address if this is a P2SH address.
    pub fn script_hash(&self) -> Option<ScriptHash> {
        use AddressInner::*;

        match *self.inner() {
            P2sh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Gets the witness program for this address if this is a SegWit address.
    pub fn witness_program(&self) -> Option<WitnessProgram> {
        use AddressInner::*;

        match *self.inner() {
            Segwit { ref program, hrp: _ } => Some(*program),
            _ => None,
        }
    }

    /// Checks whether or not the address is following Tidecoin standardness rules when
    /// *spending* from this address. *NOT* to be called by senders.
    ///
    /// <details>
    /// <summary>Spending Standardness</summary>
    ///
    /// For forward compatibility, the senders must send to any [`Address`]. Receivers
    /// can use this method to check whether or not they can spend from this address.
    ///
    /// SegWit addresses with unassigned witness versions or non-standard program sizes are
    /// considered non-standard.
    /// </details>
    ///
    pub fn is_spend_standard(&self) -> bool {
        self.address_type().is_some()
    }

    /// Constructs a new [`Address`] from an output script (`scriptPubkey`).
    pub fn from_script(
        script: &ScriptPubKey,
        params: impl AsRef<Params>,
    ) -> Result<Self, FromScriptError> {
        let network = params.as_ref().network;
        if script.is_p2pkh() {
            let bytes = script.as_bytes()[3..23].try_into().expect("statically 20B long");
            let hash = PubkeyHash::from_byte_array(bytes);
            Ok(Self::p2pkh(hash, network))
        } else if script.is_p2sh() {
            let bytes = script.as_bytes()[2..22].try_into().expect("statically 20B long");
            let hash = ScriptHash::from_byte_array(bytes);
            Ok(Self::p2sh_from_hash(hash, network))
        } else if script.is_witness_program() {
            let opcode = script.first_opcode().expect("is_witness_program guarantees len > 4");

            let version = WitnessVersion::try_from(opcode)?;
            let program = WitnessProgram::new(version, &script.as_bytes()[2..])?;
            let hrp = if program.is_p2wsh512() {
                KnownHrp::from_network_pq(network)
            } else {
                KnownHrp::from_network(network)
            };
            Ok(Self::from_witness_program(program, hrp))
        } else {
            Err(FromScriptError::UnrecognizedScript)
        }
    }

    /// Generates a script pubkey spending to this address.
    pub fn script_pubkey(&self) -> ScriptPubKeyBuf {
        use AddressInner::*;
        match *self.inner() {
            P2pkh { hash, network: _ } => ScriptPubKeyBuf::new_p2pkh(hash),
            P2sh { hash, network: _ } => ScriptPubKeyBuf::new_p2sh(hash),
            Segwit { ref program, hrp: _ } => {
                let prog = program.program();
                let version = program.version();
                script::new_witness_program_unchecked(version, prog)
            }
        }
    }

    /// Constructs a new URI string *tidecoin:address* optimized to be encoded in QR codes.
    ///
    /// If the address is bech32, the address becomes uppercase.
    /// If the address is base58, the address is left mixed case.
    ///
    /// Quoting BIP 173 "inside QR codes uppercase SHOULD be used, as those permit the use of
    /// alphanumeric mode, which is 45% more compact than the normal byte mode."
    ///
    /// If you want to avoid allocation you can use alternate display instead:
    /// ```no_run
    /// # use core::fmt::Write;
    /// # use tidecoin::Address;
    /// # let address = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf"
    /// #     .parse::<Address<_>>()
    /// #     .unwrap()
    /// #     .assume_checked();
    /// # let mut writer = String::new();
    /// write!(writer, "{:#}", address).unwrap();
    /// ```
    pub fn to_qr_uri(self) -> String {
        format!("tidecoin:{:#}", self)
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script: &ScriptPubKey) -> bool {
        use AddressInner::*;
        match *self.inner() {
            P2pkh { ref hash, network: _ } if script.is_p2pkh() => {
                &script.as_bytes()[3..23] == <PubkeyHash as AsRef<[u8; 20]>>::as_ref(hash)
            }
            P2sh { ref hash, network: _ } if script.is_p2sh() => {
                &script.as_bytes()[2..22] == <ScriptHash as AsRef<[u8; 20]>>::as_ref(hash)
            }
            Segwit { ref program, hrp: _ } if script.is_witness_program() => {
                script.as_bytes()[0] == Opcode::from(program.version()).to_u8()
                    && &script.as_bytes()[2..] == program.program().as_bytes()
            }
            P2pkh { .. } | P2sh { .. } | Segwit { .. } => false,
        }
    }
}

/// Methods that can be called only on `Address<NetworkUnchecked>`.
impl Address<NetworkUnchecked> {
    /// Returns a reference to the checked address.
    ///
    /// This function is dangerous in case the address is not a valid checked address.
    pub fn assume_checked_ref(&self) -> &Address {
        Address::from_inner_ref(self.inner())
    }

    /// Parsed addresses do not always have *one* network. For example, callers may create a
    /// legacy address from [`NetworkKind::Test`], which intentionally canonicalizes to testnet.
    /// When exact network matching matters use this function instead of comparing only
    /// [`NetworkKind`].
    pub fn is_valid_for_network(&self, n: Network) -> bool {
        use AddressInner::*;
        match *self.inner() {
            P2pkh { hash: _, ref network } => network.network() == n,
            P2sh { hash: _, ref network } => network.network() == n,
            Segwit { program: _, ref hrp } => {
                *hrp == KnownHrp::from_network(n) || *hrp == KnownHrp::from_network_pq(n)
            }
        }
    }

    /// Checks whether network of this address is as required.
    ///
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    ///
    /// # Errors
    ///
    /// This function only ever returns the [`ParseError::NetworkValidation`] variant of
    /// `ParseError`. This is not how we normally implement errors in this library but
    /// `require_network` is not a typical function, it is conceptually part of string parsing.
    ///
    ///  # Examples
    ///
    /// ```no_run
    /// use tidecoin::address::{NetworkChecked, NetworkUnchecked, ParseError};
    /// use tidecoin::{Address, Network};
    ///
    /// fn parse_and_validate_address(addr: &str, network: Network) -> Result<Address, ParseError> {
    ///     let address = addr.parse::<Address<_>>()?
    ///                       .require_network(network)?;
    ///     Ok(address)
    /// }
    /// ```
    #[inline]
    pub fn require_network(self, required: Network) -> Result<Address, ParseError> {
        if self.is_valid_for_network(required) {
            Ok(self.assume_checked())
        } else {
            Err(NetworkValidationError { required, address: self }.into())
        }
    }

    /// Marks, without any additional checks, network of this address as checked.
    ///
    /// Improper use of this method may lead to loss of funds. Reader will most likely prefer
    /// [`require_network`](Address<NetworkUnchecked>::require_network) as a safe variant.
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    #[inline]
    pub fn assume_checked(self) -> Address {
        Address::from_inner(self.to_inner())
    }

    /// Parses a bech32 Address string
    pub fn from_bech32_str(s: &str) -> Result<Self, Bech32Error> {
        let lower = s.to_lowercase();
        let is_pq = ["q1", "tq1", "rq1"].iter().any(|&p| lower.starts_with(p));

        if is_pq {
            Self::from_bech32_pq(s)
        } else {
            let (hrp, witness_version, data) = bech32::segwit::decode(s)
                .map_err(|e| Bech32Error::ParseBech32(ParseBech32Error(e)))?;
            let version = WitnessVersion::try_from(witness_version.to_u8())?;
            let program = WitnessProgram::new(version, &data)?;

            let hrp = KnownHrp::from_hrp(hrp)?;
            validate_hrp_namespace(hrp, &program)?;
            let inner = AddressInner::Segwit { program, hrp };
            Ok(Self::from_inner(inner))
        }
    }

    /// Parses a PQ (post-quantum) bech32m address, bypassing the standard
    /// 90-character bech32 length limit.
    fn from_bech32_pq(s: &str) -> Result<Self, Bech32Error> {
        use bech32::primitives::decode::SegwitHrpstringError;

        let unchecked = UncheckedHrpstring::new(s)
            .map_err(|e| pq_decode_err(SegwitHrpstringError::Unchecked(e)))?;

        let mut checked = unchecked
            .validate_and_remove_checksum::<Bech32m>()
            .map_err(|e| pq_decode_err(SegwitHrpstringError::Checksum(e)))?;

        let witness_version = checked
            .remove_witness_version()
            .ok_or_else(|| pq_decode_err(SegwitHrpstringError::NoData))?;

        let version = WitnessVersion::try_from(witness_version.to_u8())?;
        let data: alloc::vec::Vec<u8> = checked.byte_iter().collect();
        let program = WitnessProgram::new(version, &data)?;

        let hrp = KnownHrp::from_hrp(checked.hrp())?;
        validate_hrp_namespace(hrp, &program)?;
        let inner = AddressInner::Segwit { program, hrp };
        Ok(Self::from_inner(inner))
    }

    /// Parses a base58 Address string
    pub fn from_base58_str(s: &str) -> Result<Self, Base58Error> {
        if s.len() > 50 {
            return Err(LegacyAddressTooLongError { length: s.len() }.into());
        }
        let data = base58::decode_check(s)?;
        let data: &[u8; 21] = (&*data)
            .try_into()
            .map_err(|_| InvalidBase58PayloadLengthError { length: data.len() })?;

        let (prefix, &data) = data.split_first();

        let inner = match *prefix {
            PUBKEY_ADDRESS_PREFIX_MAIN => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: LegacyAddressNetwork::Mainnet }
            }
            PUBKEY_ADDRESS_PREFIX_TEST => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: LegacyAddressNetwork::Testnet }
            }
            PUBKEY_ADDRESS_PREFIX_REGTEST => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: LegacyAddressNetwork::Regtest }
            }
            SCRIPT_ADDRESS_PREFIX_MAIN => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: LegacyAddressNetwork::Mainnet }
            }
            SCRIPT_ADDRESS_PREFIX_MAIN_ALT => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: LegacyAddressNetwork::Mainnet }
            }
            SCRIPT_ADDRESS_PREFIX_TEST => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: LegacyAddressNetwork::Testnet }
            }
            SCRIPT_ADDRESS_PREFIX_TEST_ALT => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: LegacyAddressNetwork::Testnet }
            }
            SCRIPT_ADDRESS_PREFIX_REGTEST => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: LegacyAddressNetwork::Regtest }
            }
            SCRIPT_ADDRESS_PREFIX_REGTEST_ALT => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: LegacyAddressNetwork::Regtest }
            }
            invalid => return Err(InvalidLegacyPrefixError { invalid }.into()),
        };

        Ok(Self::from_inner(inner))
    }
}

impl From<Address> for ScriptPubKeyBuf {
    fn from(a: Address) -> Self {
        a.script_pubkey()
    }
}

// Alternate formatting `{:#}` is used to return an uppercase version of bech32 addresses which should
// be used in QR codes, see [`Address::to_qr_uri`].
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner(), fmt)
    }
}

impl<V: NetworkValidation> fmt::Debug for Address<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if V::IS_CHECKED {
            fmt::Display::fmt(&self.inner(), f)
        } else {
            write!(f, "Address<NetworkUnchecked>(")?;
            fmt::Display::fmt(&self.inner(), f)?;
            write!(f, ")")
        }
    }
}

/// Address can be parsed only with `NetworkUnchecked`.
///
/// SegWit bech32 addresses prefixed with `tbc`, `ttbc` or `rtbc` and legacy base58 addresses
/// with Tidecoin prefixes are supported.
///
/// # Errors
///
/// - [`ParseError::Bech32`] if the SegWit address begins with a known HRP and is not a
///   valid bech32 address.
///
/// - [`ParseError::Base58`] if the legacy address begins with a known prefix character and is
///   not a valid base58 address.
///
/// - [`UnknownHrpError`] if the address does not begin with one of the above SegWit or
///   legacy prefixes.
impl<U: NetworkValidationUnchecked> FromStr for Address<U> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let lower = s.to_lowercase();
        if ["tbc1", "ttbc1", "rtbc1", "q1", "tq1", "rq1"]
            .iter()
            .any(|&prefix| lower.starts_with(prefix))
        {
            let address = Address::from_bech32_str(s)?;
            Ok(Self::from_inner(address.to_inner()))
        } else {
            // Try base58 for everything else; from_base58_str validates the prefix byte.
            match Address::from_base58_str(s) {
                Ok(address) => Ok(Self::from_inner(address.to_inner())),
                Err(_) => {
                    let hrp = match s.rfind('1') {
                        Some(pos) => &s[..pos],
                        None => s,
                    };
                    Err(UnknownHrpError(hrp.to_owned()).into())
                }
            }
        }
    }
}

fn validate_hrp_namespace(hrp: KnownHrp, program: &WitnessProgram) -> Result<(), Bech32Error> {
    let pq_hrp = matches!(hrp, KnownHrp::PqMainnet | KnownHrp::PqTestnets | KnownHrp::PqRegtest);
    let pq_program = program.is_p2wsh512();
    if pq_hrp == pq_program {
        return Ok(());
    }

    let expected = if pq_hrp {
        "p2wsh512 witness-v1 64-byte programs"
    } else {
        "legacy segwit witness-v0 programs"
    };
    Err(InvalidSegwitHrpError { hrp: hrp.to_hrp().to_lowercase(), expected }.into())
}

fn encode_pq_bech32m(
    f: &mut fmt::Formatter,
    hrp: Hrp,
    version: Fe32,
    program: &[u8],
    uppercase: bool,
) -> fmt::Result {
    let iter = program
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .with_witness_version(version)
        .chars();
    for c in iter {
        let c = if uppercase { c.to_ascii_uppercase() } else { c };
        write!(f, "{}", c)?;
    }
    Ok(())
}

fn pq_decode_err(e: bech32::primitives::decode::SegwitHrpstringError) -> Bech32Error {
    Bech32Error::ParseBech32(ParseBech32Error(bech32::segwit::DecodeError::from(e)))
}

#[cfg(test)]
mod tests {
    use alloc::string::{String, ToString};
    use core::str::FromStr;

    use bech32::primitives::gf32::Fe32;
    use bech32::primitives::iter::{ByteIterExt as _, Fe32IterExt as _};
    use bech32::Bech32m;
    use hashes::sha512;

    use super::*;
    use crate::network::Network::Tidecoin;
    use crate::script::WitnessScriptBuf;

    fn roundtrips(addr: &Address, network: Network) {
        assert_eq!(
            addr.to_string().parse::<Address<_>>().unwrap().assume_checked(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), network)
                .expect("failed to create inner address from script_pubkey"),
            *addr,
            "script round-trip failed for {}",
            addr,
        );

        #[cfg(feature = "serde")]
        {
            let ser = serde_json::to_string(addr).expect("failed to serialize address");
            let back: Address<NetworkUnchecked> =
                serde_json::from_str(&ser).expect("failed to deserialize address");
            assert_eq!(back.assume_checked(), *addr, "serde round-trip failed for {}", addr)
        }
    }

    fn encode_pq_address(hrp: KnownHrp, version: u8, program: &[u8]) -> String {
        let version_fe = Fe32::try_from(version).unwrap();
        let hrp_value = hrp.to_hrp();
        let chars = program
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp_value)
            .with_witness_version(version_fe)
            .chars();
        let mut encoded = hrp_value.to_string();
        encoded.push('1');
        encoded.extend(chars);
        encoded
    }

    #[test]
    fn p2pkh_address_58() {
        let hash = "162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse::<PubkeyHash>().unwrap();
        let addr = Address::p2pkh(hash, NetworkKind::Main);

        assert_eq!(
            addr.script_pubkey(),
            ScriptPubKeyBuf::from_hex_no_length_prefix(
                "76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac"
            )
            .unwrap()
        );
        assert_eq!(&addr.to_string(), "EKB9WfgyJsUYoSur9BAoPDkt3BbE6dYkYA");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Tidecoin);
    }

    #[test]
    fn p2wpkh_and_p2shwpkh_from_hashes_roundtrip() {
        let hash = WPubkeyHash::from_byte_array([0x11; 20]);

        let native = Address::p2wpkh(hash, KnownHrp::Mainnet);
        assert_eq!(native.address_type(), Some(AddressType::P2wpkh));
        assert!(native.to_string().starts_with("tbc1q"));
        roundtrips(&native, Tidecoin);

        let wrapped = Address::p2shwpkh(hash, Network::Tidecoin);
        assert_eq!(wrapped.address_type(), Some(AddressType::P2sh));
        assert!(wrapped.to_string().starts_with('T'));
        roundtrips(&wrapped, Tidecoin);
    }

    #[test]
    fn p2wsh_and_p2wsh512_roundtrip() {
        let witness_script = WitnessScriptBuf::from_hex_no_length_prefix("5121aa51ae").unwrap();
        let p2wsh = Address::p2wsh(&witness_script, KnownHrp::Mainnet).unwrap();
        assert_eq!(p2wsh.address_type(), Some(AddressType::P2wsh));
        roundtrips(&p2wsh, Tidecoin);

        let hash = sha512::Hash::hash(witness_script.as_bytes()).to_byte_array();
        let p2wsh512 = Address::p2wsh512(hash, Network::Tidecoin);
        assert_eq!(p2wsh512.address_type(), Some(AddressType::P2wsh512));
        assert!(p2wsh512.to_string().starts_with("q1"));
        roundtrips(&p2wsh512, Tidecoin);
    }

    #[test]
    fn address_type_detection_is_tidecoin_specific() {
        let witness_script = WitnessScriptBuf::from_hex_no_length_prefix("51").unwrap();
        let hash = sha512::Hash::hash(witness_script.as_bytes()).to_byte_array();
        let pq = Address::p2wsh512(hash, Network::Tidecoin).to_string();

        let addresses = [
            ("EKB9WfgyJsUYoSur9BAoPDkt3BbE6dYkYA", Some(AddressType::P2pkh)),
            ("TBzT29EC2eJayKNcvbpzuEU4BKqQt4QGvz", Some(AddressType::P2sh)),
            (
                "tbc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxs0479ga",
                Some(AddressType::P2wsh),
            ),
            (&pq, Some(AddressType::P2wsh512)),
            ("tbc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqhqlyfv", None),
        ];

        for (address, expected_type) in addresses {
            let addr =
                address.parse::<Address<_>>().unwrap().require_network(Network::Tidecoin).unwrap();
            assert_eq!(addr.address_type(), expected_type);
        }
    }

    #[test]
    fn valid_and_invalid_address_types_parse() {
        assert_eq!("p2wsh".parse::<AddressType>().unwrap(), AddressType::P2wsh);
        assert_eq!(
            "invalid".parse::<AddressType>(),
            Err(UnknownAddressTypeError("invalid".to_owned()))
        );
    }

    #[test]
    fn regtest_legacy_decoding_reencodes_to_canonical_node_prefixes() {
        let p2pkh =
            Address::<NetworkUnchecked>::from_str("p76p8nAKz7uyGorcGP4ShgLAYimASoxSJq").unwrap();
        assert!(p2pkh.is_valid_for_network(Network::Regtest));
        assert!(!p2pkh.is_valid_for_network(Network::Testnet));
        assert_eq!(p2pkh.assume_checked_ref().to_string(), "p76p8nAKz7uyGorcGP4ShgLAYimASoxSJq");

        let noncanonical_p2sh =
            Address::<NetworkUnchecked>::from_str("2Htyg1M1ptaatHp24Md8b8LbZtEA3eMfM4t").unwrap();
        assert!(noncanonical_p2sh.is_valid_for_network(Network::Regtest));
        assert!(!noncanonical_p2sh.is_valid_for_network(Network::Testnet));
        assert_eq!(
            noncanonical_p2sh.assume_checked_ref().to_string(),
            "r9M4zPwPT2vox56WnmpC6KBDbwfg8X4QD8"
        );
    }

    #[test]
    fn pq_bech32_namespace_matches_node_rules() {
        let witness_script = WitnessScriptBuf::from_hex_no_length_prefix("51").unwrap();
        let hash = sha512::Hash::hash(witness_script.as_bytes()).to_byte_array();
        let addr = Address::p2wsh512(hash, Network::Tidecoin);
        assert!(addr.to_string().starts_with("q1"));
        let parsed = addr
            .to_string()
            .parse::<Address<_>>()
            .unwrap()
            .require_network(Network::Tidecoin)
            .unwrap();
        assert_eq!(parsed.address_type(), Some(AddressType::P2wsh512));

        let pq_v0 = encode_pq_address(KnownHrp::PqMainnet, 0, &[0x42; 20]);
        assert!(Address::<NetworkUnchecked>::from_bech32_str(&pq_v0).is_err());

        let legacy_v1 = encode_pq_address(KnownHrp::Mainnet, 1, &[0x11; 64]);
        assert!(Address::<NetworkUnchecked>::from_bech32_str(&legacy_v1).is_err());
    }

    #[test]
    fn pq_bech32_roundtrips_all_supported_networks() {
        let witness_script = WitnessScriptBuf::from_hex_no_length_prefix("51").unwrap();
        let hash = sha512::Hash::hash(witness_script.as_bytes()).to_byte_array();

        for (network, prefix) in
            [(Network::Tidecoin, "q1"), (Network::Testnet, "tq1"), (Network::Regtest, "rq1")]
        {
            let address = Address::p2wsh512(hash, network);
            assert!(address.to_string().starts_with(prefix));
            roundtrips(&address, network);
            assert_eq!(Address::from_script(&address.script_pubkey(), network).unwrap(), address);
        }
    }

    #[test]
    fn bech32_checksum_errors_reject_legacy_and_pq_namespaces() {
        let corrupt_last = |mut s: String| {
            let replacement = if s.ends_with('q') { 'p' } else { 'q' };
            s.pop();
            s.push(replacement);
            s
        };

        let legacy = "tbc1qqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp";
        assert!(matches!(
            Address::<NetworkUnchecked>::from_bech32_str(&corrupt_last(legacy.to_owned())),
            Err(Bech32Error::ParseBech32(_))
        ));

        let pq = Address::p2wsh512([0x22; 64], Network::Tidecoin).to_string();
        assert!(matches!(
            Address::<NetworkUnchecked>::from_bech32_str(&corrupt_last(pq)),
            Err(Bech32Error::ParseBech32(_))
        ));
    }
}
