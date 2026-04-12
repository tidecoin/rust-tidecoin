// SPDX-License-Identifier: CC0-1.0

//! Tidecoin block subsidy schedule.

use crate::network::Params;
use crate::{Amount, BlockHeight};

/// Computes the maximum block subsidy for `height` under Tidecoin consensus parameters.
///
/// Tidecoin starts at 40 TDC, quarters the subsidy at each schedule step, and
/// doubles the interval after every step. This mirrors the Tidecoin node's
/// `GetBlockSubsidy` logic.
pub fn block_subsidy(height: BlockHeight, params: impl AsRef<Params>) -> Amount {
    let interval = u64::from(params.as_ref().subsidy_initial_interval);
    if interval == 0 {
        return Amount::ZERO;
    }

    let mut halvings = 0u32;
    let mut high = 0u64;
    let mut step_interval = interval;
    let height = u64::from(height.to_u32());

    for _ in 0..=64 {
        high = high.saturating_add(step_interval);
        if height >= high {
            halvings += 1;
        } else {
            break;
        }
        step_interval = step_interval.saturating_mul(2);
    }

    let shift = halvings.saturating_mul(2);
    if shift >= 64 {
        return Amount::ZERO;
    }

    Amount::from_sat(Amount::FORTY_TDC.to_sat() >> shift)
        .expect("right-shifted block subsidy remains in range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;

    fn subsidy_sat(height: u32, network: Network) -> u64 {
        block_subsidy(BlockHeight::from_u32(height), Params::new(network)).to_sat()
    }

    #[test]
    fn mainnet_subsidy_matches_node_doubling_interval_schedule() {
        let interval = crate::blockdata::constants::SUBSIDY_INITIAL_INTERVAL;

        assert_eq!(subsidy_sat(0, Network::Tidecoin), 4_000_000_000);
        assert_eq!(subsidy_sat(interval - 1, Network::Tidecoin), 4_000_000_000);
        assert_eq!(subsidy_sat(interval, Network::Tidecoin), 1_000_000_000);
        assert_eq!(subsidy_sat(interval * 3 - 1, Network::Tidecoin), 1_000_000_000);
        assert_eq!(subsidy_sat(interval * 3, Network::Tidecoin), 250_000_000);
    }

    #[test]
    fn regtest_subsidy_uses_node_short_interval() {
        assert_eq!(subsidy_sat(0, Network::Regtest), 4_000_000_000);
        assert_eq!(subsidy_sat(19, Network::Regtest), 4_000_000_000);
        assert_eq!(subsidy_sat(20, Network::Regtest), 1_000_000_000);
        assert_eq!(subsidy_sat(59, Network::Regtest), 1_000_000_000);
        assert_eq!(subsidy_sat(60, Network::Regtest), 250_000_000);
        assert_eq!(subsidy_sat(139, Network::Regtest), 250_000_000);
        assert_eq!(subsidy_sat(140, Network::Regtest), 62_500_000);
    }
}
