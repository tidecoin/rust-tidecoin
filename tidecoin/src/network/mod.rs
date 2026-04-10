// SPDX-License-Identifier: CC0-1.0

//! Tidecoin network.
//!
//! The term "network" is overloaded, here [`Network`] refers to the specific
//! Tidecoin network we are operating on e.g., testnet, regtest. The terms
//! "network" and "chain" are often used interchangeably for this concept.

pub mod params;

use core::fmt;

use crate::constants::ChainHash;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::params::Params;
#[doc(no_inline)]
pub use network::ParseNetworkError;
#[doc(inline)]
pub use network::{Network, NetworkKind};

/// Extension functionality for the [`Network`] type.
pub trait NetworkExt: sealed::Sealed {
    /// Return the network's chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tidecoin::Network;
    /// use tidecoin::network::NetworkExt as _;
    /// use tidecoin::constants::ChainHash;
    ///
    /// let network = Network::Tidecoin;
    /// assert_eq!(network.chain_hash(), ChainHash::TIDECOIN);
    /// ```
    fn chain_hash(self) -> ChainHash;

    /// Constructs a new `Network` from the chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tidecoin::Network;
    /// use tidecoin::network::NetworkExt as _;
    /// use tidecoin::constants::ChainHash;
    ///
    /// assert_eq!(Ok(Network::Tidecoin), Network::try_from(ChainHash::TIDECOIN));
    /// ```
    fn from_chain_hash(chain_hash: ChainHash) -> Option<Self>;

    /// Returns the associated network parameters.
    fn params(self) -> &'static Params;
}

impl NetworkExt for Network {
    fn chain_hash(self) -> ChainHash {
        ChainHash::using_genesis_block_const(self)
    }

    fn from_chain_hash(chain_hash: ChainHash) -> Option<Self> {
        Self::try_from(chain_hash).ok()
    }

    fn params(self) -> &'static Params {
        match self {
            Self::Tidecoin => &Params::MAINNET,
            Self::Testnet => &Params::TESTNET,
            Self::Regtest => &Params::REGTEST,
        }
    }
}

mod sealed {
    pub trait Sealed: Sized {}
    impl Sealed for super::Network {}
}

/// Error in parsing network from chain hash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownChainHashError(ChainHash);

impl fmt::Display for UnknownChainHashError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unknown chain hash: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownChainHashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl TryFrom<ChainHash> for Network {
    type Error = UnknownChainHashError;

    fn try_from(chain_hash: ChainHash) -> Result<Self, Self::Error> {
        match chain_hash {
            // Tidecoin mainnet and testnet share the same genesis block hash;
            // we default to mainnet when resolving by chain hash alone.
            ChainHash::TIDECOIN => Ok(Self::Tidecoin),
            ChainHash::REGTEST => Ok(Self::Regtest),
            _ => Err(UnknownChainHashError(chain_hash)),
        }
    }
}

#[cfg(test)]
mod tests {}
