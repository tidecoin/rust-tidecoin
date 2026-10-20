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

    fn subsidy_sat_with_interval(height: u32, interval: u32) -> u64 {
        let mut params = Params::MAINNET;
        params.subsidy_initial_interval = interval;
        block_subsidy(BlockHeight::from_u32(height), params).to_sat()
    }

    fn assert_subsidy_transitions(interval: u32) {
        assert!(interval > 0);

        let mut previous_subsidy = Amount::FORTY_TDC.to_sat();
        let mut step_interval = u64::from(interval);
        let mut boundary = step_interval;

        assert_eq!(subsidy_sat_with_interval(0, interval), previous_subsidy);

        for _ in 0..=64 {
            if boundary > u64::from(u32::MAX) {
                break;
            }

            let boundary_height = boundary as u32;
            let expected = previous_subsidy >> 2;
            if boundary_height > 0 {
                assert_eq!(
                    subsidy_sat_with_interval(boundary_height - 1, interval),
                    previous_subsidy
                );
            }
            assert_eq!(subsidy_sat_with_interval(boundary_height, interval), expected);

            previous_subsidy = expected;
            if previous_subsidy == 0 {
                break;
            }

            step_interval =
                step_interval.checked_mul(2).expect("test interval doubling stays within u64");
            boundary = boundary.checked_add(step_interval).expect("test boundary stays within u64");
        }
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
    fn subsidy_transition_boundaries_match_node_unit_test_shape() {
        assert_subsidy_transitions(crate::blockdata::constants::SUBSIDY_INITIAL_INTERVAL);
        assert_subsidy_transitions(20);
        assert_subsidy_transitions(150);
        assert_subsidy_transitions(1000);
    }

    #[test]
    fn subsidy_total_to_fixed_height_matches_node_unit_test() {
        const MAX_HEIGHT: u64 = 14_000_000;
        const EXPECTED_TOTAL: u128 = 2_059_564_062_500_000;

        let interval0 = u64::from(crate::blockdata::constants::SUBSIDY_INITIAL_INTERVAL);
        let mut sum = 0u128;
        let mut subsidy = u128::from(Amount::FORTY_TDC.to_sat());
        let mut height = 0u64;
        let mut interval = interval0;
        let mut next_change = interval0;

        while height < MAX_HEIGHT {
            let end = core::cmp::min(MAX_HEIGHT, next_change);
            let blocks = end - height;
            assert!(subsidy <= u128::from(Amount::FORTY_TDC.to_sat()));

            sum += subsidy * u128::from(blocks);
            height = end;
            if height >= MAX_HEIGHT {
                break;
            }

            subsidy >>= 2;
            interval = interval.checked_mul(2).expect("interval doubling stays within u64");
            next_change = next_change.checked_add(interval).expect("next change stays within u64");
            if subsidy == 0 {
                break;
            }
        }

        assert_eq!(sum, EXPECTED_TOTAL);
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

    #[test]
    #[cfg(feature = "tidecoin-node-validation")]
    fn subsidy_schedule_matches_tidecoin_node_bridge() {
        let harness = match node_parity::TidecoinNodeHarness::optional_from_env() {
            Some(harness) => harness,
            None => {
                return;
            }
        };

        let cases = [
            (Network::Tidecoin, 0, 0),
            (Network::Tidecoin, 0, 262_799),
            (Network::Tidecoin, 0, 262_800),
            (Network::Tidecoin, 0, 788_399),
            (Network::Tidecoin, 0, 788_400),
            (Network::Testnet, 1, 262_800),
            (Network::Regtest, 2, 19),
            (Network::Regtest, 2, 20),
            (Network::Regtest, 2, 59),
            (Network::Regtest, 2, 60),
            (Network::Regtest, 2, 139),
            (Network::Regtest, 2, 140),
        ];

        for (network, network_id, height) in cases {
            let rust = subsidy_sat(height, network);
            let node = harness
                .block_subsidy(network_id, height as i32)
                .expect("node block subsidy bridge");

            assert_eq!(rust, node, "network={network:?} height={height}");
        }

        for (network, network_id) in
            [(Network::Tidecoin, 0), (Network::Testnet, 1), (Network::Regtest, 2)]
        {
            let interval = u64::from(Params::new(network).subsidy_initial_interval);
            let mut step_interval = interval;
            let mut boundary = interval;

            for _ in 0..=64 {
                if boundary > i32::MAX as u64 {
                    break;
                }

                let boundary_height = boundary as u32;
                for height in [boundary_height.saturating_sub(1), boundary_height] {
                    let rust = subsidy_sat(height, network);
                    let node = harness
                        .block_subsidy(network_id, height as i32)
                        .expect("node block subsidy bridge");
                    assert_eq!(rust, node, "network={network:?} height={height}");
                }

                step_interval =
                    step_interval.checked_mul(2).expect("test interval doubling stays within u64");
                boundary =
                    boundary.checked_add(step_interval).expect("test boundary stays within u64");
            }
        }
    }
}
