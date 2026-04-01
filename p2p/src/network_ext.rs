// SPDX-License-Identifier: CC0-1.0

//! This module implements an extension trait for [`Network`]
//! with getter methods for the default P2P port and default
//! network [`Magic`] bytes.

use network::Network;

use crate::Magic;

/// Trait that extends [`Network`] by adding getter methods for the default P2P ports and [`Magic`] bytes.
pub trait NetworkExt {
    /// The default P2P port for a given [`Network`].
    fn default_p2p_port(self) -> u16;

    /// The default network [`Magic`] for a given [`Network`].
    fn default_network_magic(self) -> Magic;
}

impl NetworkExt for Network {
    /// The default P2P port for a given [`Network`].
    fn default_p2p_port(self) -> u16 {
        match &self {
            Self::Tidecoin => 8755,
            Self::Testnet => 18755,
            Self::Regtest => 18778,
        }
    }

    /// The default network [`Magic`] for a given [`Network`].
    fn default_network_magic(self) -> Magic {
        match &self {
            Self::Tidecoin => Magic::TIDECOIN,
            Self::Testnet => Magic::TESTNET,
            Self::Regtest => Magic::REGTEST,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn default_p2p_port() {
        let networks = [
            Network::Tidecoin,
            Network::Testnet,
            Network::Regtest,
        ];

        let p2p_ports = vec![8755, 18755, 18778];

        for (network, p2p_port) in networks.iter().zip(p2p_ports) {
            assert_eq!(network.default_p2p_port(), p2p_port);
        }
    }

    #[test]
    fn default_network_magic() {
        let networks = [
            Network::Tidecoin,
            Network::Testnet,
            Network::Regtest,
        ];

        let network_magics =
            vec![Magic::TIDECOIN, Magic::TESTNET, Magic::REGTEST];

        for (network, network_magic) in networks.iter().zip(network_magics) {
            assert_eq!(network.default_network_magic(), network_magic);
        }
    }
}
