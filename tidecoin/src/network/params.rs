// SPDX-License-Identifier: CC0-1.0

//! Tidecoin consensus parameters.
//!
//! This module provides a predefined set of parameters for different Tidecoin
//! chains (mainnet, testnet, regtest).
//!
//! # Custom Parameters Example
//!
//! In various places in this crate we take `AsRef<Params>` as a parameter, in order to create a
//! custom type that can be used in such places you might want to do the following:
//!
//! ```
//! use tidecoin::network::Params;
//! use tidecoin::{Network, Target};
//!
//! const POW_TARGET_SPACING: u32 = 120; // Two minutes.
//!
//! pub struct CustomParams {
//!     params: Params,
//! }
//!
//! impl CustomParams {
//!     /// Constructs a new custom params.
//!     pub fn new() -> Self {
//!         let mut params = Params::new(Network::Testnet);
//!         params.pow_target_spacing = POW_TARGET_SPACING;
//!
//!         Self {
//!             params,
//!         }
//!     }
//! }
//!
//! impl AsRef<Params> for CustomParams {
//!     fn as_ref(&self) -> &Params { &self.params }
//! }
//!
//! impl Default for CustomParams {
//!     fn default() -> Self { Self::new() }
//! }
//!
//! # { // Just check the code above is usable.
//! #    let target = Target::MAX_ATTAINABLE_MAINNET;
//! #
//! #    let mainnet = Params::MAINNET;
//! #    let _ = target.difficulty(mainnet);
//! #
//! #    let custom = CustomParams::new();
//! #    let _ = target.difficulty(custom);
//! # }
//! ```

use super::{Network, NetworkExt as _};
#[cfg(doc)]
use crate::pow::CompactTarget;
use crate::pow::Target;
use crate::{BlockHeight, BlockHeightInterval};

/// Parameters that influence chain consensus.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Params {
    /// Network for which parameters are valid.
    pub network: Network,
    /// Time when pay-to-script-hash validation becomes active.
    pub bip16_time: u32,
    /// Block height at which coinbase height validation becomes active.
    pub bip34_height: BlockHeight,
    /// Block height at which CHECKLOCKTIMEVERIFY validation becomes active.
    pub bip65_height: BlockHeight,
    /// Block height at which strict signature encoding validation becomes active.
    pub bip66_height: BlockHeight,
    /// Block height at which auxpow activates, if any.
    pub auxpow_start_height: Option<BlockHeight>,
    /// Auxpow chain ID encoded into header version bits.
    pub auxpow_chain_id: u32,
    /// Enforce Tidecoin block storm mitigation.
    pub enforce_bip94: bool,
    /// Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
    /// (nPowTargetTimespan / nPowTargetSpacing).
    /// Examples: 1916 for 95%, 1512 for testchains.
    pub rule_change_activation_threshold: BlockHeightInterval,
    /// Number of blocks with the same set of rules.
    pub miner_confirmation_window: BlockHeightInterval,
    /// The maximum **attainable** target value for these params.
    ///
    /// Not all target values are attainable because consensus code uses the compact format to
    /// represent targets (see [`CompactTarget`]).
    ///
    /// Tidecoin node consensus compares compact-encoded targets. This field stores the largest
    /// target value that is exactly representable by the compact target format for the network.
    pub max_attainable_target: Target,
    /// Expected amount of time to mine one block.
    pub pow_target_spacing: u32,
    /// Difficulty recalculation interval.
    pub pow_target_timespan: u32,
    /// Determines whether minimal difficulty may be used for blocks or not.
    pub allow_min_difficulty_blocks: bool,
    /// Determines whether retargeting is disabled for this network or not.
    pub no_pow_retargeting: bool,
}

/// The mainnet parameters.
///
/// Use this for a static reference e.g., `&params::MAINNET`.
///
/// For more on static vs const see The Rust Reference [using-statics-or-consts] section.
///
/// [using-statics-or-consts]: <https://doc.rust-lang.org/reference/items/static-items.html#using-statics-or-consts>
pub static MAINNET: Params = Params::MAINNET;
/// The testnet parameters.
pub static TESTNET: Params = Params::TESTNET;
/// The regtest parameters.
pub static REGTEST: Params = Params::REGTEST;

impl Params {
    /// The mainnet parameters.
    pub const MAINNET: Self = Self {
        network: Network::Tidecoin,
        bip16_time: 0,
        bip34_height: BlockHeight::from_u32(1),
        bip65_height: BlockHeight::from_u32(1),
        bip66_height: BlockHeight::from_u32(1),
        auxpow_start_height: None,
        auxpow_chain_id: 8,
        enforce_bip94: false,
        rule_change_activation_threshold: BlockHeightInterval::from_u32(6048),
        miner_confirmation_window: BlockHeightInterval::from_u32(8064),
        max_attainable_target: Target::MAX_ATTAINABLE_MAINNET,
        pow_target_spacing: 60,
        pow_target_timespan: 432_000,
        allow_min_difficulty_blocks: false,
        no_pow_retargeting: false,
    };

    /// The testnet parameters.
    pub const TESTNET: Self = Self {
        network: Network::Testnet,
        bip16_time: 0,
        bip34_height: BlockHeight::from_u32(1),
        bip65_height: BlockHeight::from_u32(1),
        bip66_height: BlockHeight::from_u32(1),
        auxpow_start_height: Some(BlockHeight::from_u32(1000)),
        auxpow_chain_id: 8,
        enforce_bip94: false,
        rule_change_activation_threshold: BlockHeightInterval::from_u32(6048),
        miner_confirmation_window: BlockHeightInterval::from_u32(8064),
        max_attainable_target: Target::MAX_ATTAINABLE_MAINNET,
        pow_target_spacing: 60,
        pow_target_timespan: 432_000,
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: false,
    };

    /// The regtest parameters.
    pub const REGTEST: Self = Self {
        network: Network::Regtest,
        bip16_time: 0,
        bip34_height: BlockHeight::from_u32(1),
        bip65_height: BlockHeight::from_u32(1),
        bip66_height: BlockHeight::from_u32(1),
        auxpow_start_height: Some(BlockHeight::from_u32(0)),
        auxpow_chain_id: 8,
        enforce_bip94: true,
        rule_change_activation_threshold: BlockHeightInterval::from_u32(108),
        miner_confirmation_window: BlockHeightInterval::from_u32(144),
        max_attainable_target: Target::MAX_ATTAINABLE_REGTEST,
        pow_target_spacing: 60,
        pow_target_timespan: 14_400,
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: true,
    };

    /// Constructs parameters set for the given network.
    pub const fn new(network: Network) -> Self {
        match network {
            Network::Tidecoin => Self::MAINNET,
            Network::Testnet => Self::TESTNET,
            Network::Regtest => Self::REGTEST,
        }
    }

    /// Calculates the number of blocks between difficulty adjustments.
    pub fn difficulty_adjustment_interval(&self) -> u32 {
        self.pow_target_timespan / self.pow_target_spacing
    }
}

impl From<Network> for Params {
    fn from(value: Network) -> Self {
        Self::new(value)
    }
}

impl From<&Network> for Params {
    fn from(value: &Network) -> Self {
        Self::new(*value)
    }
}

impl From<Network> for &'static Params {
    fn from(value: Network) -> Self {
        value.params()
    }
}

impl From<&Network> for &'static Params {
    fn from(value: &Network) -> Self {
        value.params()
    }
}

impl AsRef<Self> for Params {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<Params> for Network {
    fn as_ref(&self) -> &Params {
        Self::params(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockdata::constants::genesis_block;
    use crate::pow::Target;

    fn assert_chainparam_sanity(params: &'static Params) {
        assert_eq!(params.pow_target_timespan % params.pow_target_spacing, 0);

        let genesis_target = Target::from(genesis_block(params).header().bits);
        assert!(genesis_target <= params.max_attainable_target);
    }

    #[test]
    fn mainnet_chainparams_sanity() {
        assert_chainparam_sanity(&Params::MAINNET);
    }

    #[test]
    fn testnet_chainparams_sanity() {
        assert_chainparam_sanity(&Params::TESTNET);
    }

    #[test]
    fn regtest_chainparams_sanity() {
        assert_chainparam_sanity(&Params::REGTEST);
    }
}
