//! Tests what a user can do when pattern matching on `Network` and associated types.

use tidecoin::network::{Network, NetworkKind};

#[test]
fn can_match_exhaustively_on_network() {
    fn is_mainnet(n: Network) -> bool {
        matches!(n, Network::Tidecoin)
    }

    assert!(is_mainnet(Network::Tidecoin));
}

#[test]
fn can_match_on_testnet() {
    fn is_testnet(n: Network) -> bool {
        matches!(n, Network::Testnet)
    }

    assert!(is_testnet(Network::Testnet));
}

#[test]
fn can_use_network_kind() {
    fn is_mainnet(n: Network) -> bool {
        NetworkKind::from(n).is_mainnet()
    }

    fn is_testnet(n: Network) -> bool {
        !NetworkKind::from(n).is_mainnet()
    }

    assert!(is_mainnet(Network::Tidecoin));
    assert!(!is_testnet(Network::Tidecoin));

    assert!(is_testnet(Network::Testnet));
    assert!(!is_mainnet(Network::Testnet));
}
