// SPDX-License-Identifier: CC0-1.0

//! # Tidecoin network
//!
//! The term "network" is overloaded, here [`Network`] refers to the specific
//! Tidecoin network we are operating on e.g., testnet, regtest. The terms
//! "network" and "chain" are often used interchangeably for this concept.

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serde")]
pub extern crate serde;

use core::fmt;
use core::str::FromStr;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::error::InputString;
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

/// What kind of network we are on.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetworkKind {
    /// The Tidecoin mainnet network.
    Main,
    /// Some kind of testnet network (testnet, regtest).
    Test,
}

impl NetworkKind {
    /// Returns true if this is real mainnet tidecoin.
    pub const fn is_mainnet(self) -> bool {
        matches!(self, Self::Main)
    }
}

impl From<Network> for NetworkKind {
    fn from(network: Network) -> Self {
        match network {
            Network::Tidecoin => Self::Main,
            Network::Testnet | Network::Regtest => Self::Test,
        }
    }
}

/// The cryptocurrency network to act on.
///
/// This is an exhaustive enum, meaning that we cannot add any future networks without defining a
/// new, incompatible version of this type. If you are using this type directly and wish to support the
/// new network, this will be a breaking change to your APIs and likely require changes in your code.
///
/// If you are concerned about forward compatibility, consider using `T: Into<Params>` instead of
/// this type as a parameter to functions in your public API, or directly using the `Params` type.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
pub enum Network {
    /// Mainnet Tidecoin.
    Tidecoin,
    /// Tidecoin's testnet network.
    Testnet,
    /// Tidecoin's regtest network.
    Regtest,
}

#[cfg(feature = "serde")]
impl Serialize for Network {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_display_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Network {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NetworkVisitor;

        impl Visitor<'_> for NetworkVisitor {
            type Value = Network;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid network identifier")
            }

            fn visit_str<E>(self, value: &str) -> Result<Network, E>
            where
                E: serde::de::Error,
            {
                Network::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(NetworkVisitor)
    }
}

impl Network {
    /// Converts a `Network` to its equivalent `-chain` argument name.
    ///
    /// Allowed values: main, test, regtest
    pub fn to_core_arg(self) -> &'static str {
        match self {
            Self::Tidecoin => "main",
            Self::Testnet => "test",
            Self::Regtest => "regtest",
        }
    }

    /// Converts a `-chain` argument name to its equivalent `Network`.
    ///
    /// # Errors
    ///
    /// Errors if input is not exactly one of:
    /// * `main`
    /// * `test`
    /// * `regtest`
    pub fn from_core_arg(core_arg: &str) -> Result<Self, ParseNetworkError> {
        let network = match core_arg {
            "main" => Self::Tidecoin,
            "test" => Self::Testnet,
            "regtest" => Self::Regtest,
            _ => return Err(ParseNetworkError(InputString::from(core_arg))),
        };
        Ok(network)
    }

    /// Returns a string representation of the `Network` enum variant.
    const fn as_display_str(self) -> &'static str {
        match self {
            Self::Tidecoin => "tidecoin",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.as_display_str())
    }
}

#[cfg(feature = "serde")]
pub mod as_core_arg {
    //! Module for serialization/deserialization of network variants into/from core values

    // No need to document these functions, they are well known.
    #![allow(missing_docs)]
    #![allow(clippy::missing_errors_doc)]

    use crate::Network;

    #[allow(clippy::trivially_copy_pass_by_ref)] // `serde` controls the API.
    pub fn serialize<S>(network: &Network, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(network.to_core_arg())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Network, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NetworkVisitor;

        impl serde::de::Visitor<'_> for NetworkVisitor {
            type Value = Network;

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Network::from_core_arg(s).map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Str(s),
                        &"tidecoin network encoded as a string (either main, test, or regtest)",
                    )
                })
            }

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(
                    formatter,
                    "tidecoin network encoded as a string (either main, test, or regtest)"
                )
            }
        }

        deserializer.deserialize_str(NetworkVisitor)
    }
}

/// An error in parsing network string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseNetworkError(InputString);

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Outputs 'failed to parse <input string> as network'.
        write!(f, "{}", self.0.display_cannot_parse("network"))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl FromStr for Network {
    type Err = ParseNetworkError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tidecoin" | "main" => Ok(Self::Tidecoin),
            "testnet" | "test" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(ParseNetworkError(InputString::from(s))),
        }
    }
}

impl AsRef<Self> for Network {
    fn as_ref(&self) -> &Self {
        self
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for NetworkKind {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match bool::arbitrary(u)? {
            true => Ok(Self::Main),
            false => Ok(Self::Test),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::string::ToString;

    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};

    use super::Network;

    #[test]
    #[cfg(feature = "std")]
    fn string() {
        assert_eq!(Network::Tidecoin.to_string(), "tidecoin");
        assert_eq!(Network::Testnet.to_string(), "testnet");
        assert_eq!(Network::Regtest.to_string(), "regtest");

        assert_eq!("tidecoin".parse::<Network>().unwrap(), Network::Tidecoin);
        assert_eq!("main".parse::<Network>().unwrap(), Network::Tidecoin);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("test".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert!("fakenet".parse::<Network>().is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    #[cfg(feature = "std")]
    fn serde_roundtrip() {
        use std::{format, vec};

        use Network::*;
        let tests = vec![(Tidecoin, "tidecoin"), (Testnet, "testnet"), (Regtest, "regtest")];

        for tc in tests {
            let network = tc.0;

            let want = format!("\"{}\"", tc.1);
            let got = serde_json::to_string(&tc.0).expect("failed to serialize network");
            assert_eq!(got, want);

            let back: Network = serde_json::from_str(&got).expect("failed to deserialize network");
            assert_eq!(back, network);
        }
    }

    #[test]
    fn from_to_core_arg() {
        let expected_pairs = [
            (Network::Tidecoin, "main"),
            (Network::Testnet, "test"),
            (Network::Regtest, "regtest"),
        ];

        for (net, core_arg) in &expected_pairs {
            assert_eq!(Network::from_core_arg(core_arg), Ok(*net));
            assert_eq!(net.to_core_arg(), *core_arg);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_as_core_arg() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "crate::as_core_arg")]
            pub network: Network,
        }

        serde_test::assert_tokens(
            &T { network: Network::Tidecoin },
            &[
                serde_test::Token::Struct { name: "T", len: 1 },
                serde_test::Token::Str("network"),
                serde_test::Token::Str("main"),
                serde_test::Token::StructEnd,
            ],
        );
    }
}
