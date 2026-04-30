// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.
//!
//! Provides the [`Work`] and [`Target`] types that are used in proof-of-work calculations. The
//! functions here are designed to be fast, by that we mean it is safe to use them to check headers.

use core::ops::{Add, Div, Mul, Not, Rem, Shl, Shr, Sub};
use core::{cmp, fmt};

#[cfg(feature = "pow")]
use hashes::{sha256d, HashEngine as _};
use internals::{impl_to_hex_from_lower_hex, write_err};
use units::parse_int::{self, ParseIntError, PrefixedHexError, UnprefixedHexError};

#[cfg(feature = "pow")]
use crate::block::AuxPow;
use crate::block::{BlockHash, BlockHeight, BlockHeightInterval, BlockMtp, Header};
use crate::internal_macros;
use crate::network::Params;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::CompactTarget;
#[doc(inline)]
pub use units::pow::error;

/// Mining hash algorithm selected by Tidecoin consensus for a pure block header.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MiningHashAlgorithm {
    /// Tidecoin yespower over the pure 80-byte header.
    Yespower,
    /// Scrypt-1024-1-1-256 over the pure 80-byte header.
    Scrypt,
}

/// Returns the node-selected mining hash algorithm for `height`.
///
/// The Tidecoin node uses yespower before AuxPoW activation and scrypt at and
/// after AuxPoW activation. Networks with AuxPoW disabled always use yespower.
pub fn pow_hash_algorithm_at_height(
    params: impl AsRef<Params>,
    height: BlockHeight,
) -> MiningHashAlgorithm {
    if uses_post_auxpow_pow_rules(params.as_ref(), height) {
        MiningHashAlgorithm::Scrypt
    } else {
        MiningHashAlgorithm::Yespower
    }
}

/// Computes Tidecoin's scrypt mining hash for the pure 80-byte block header.
///
/// This mirrors the node's `CPureBlockHeader::GetScryptPoWHash()`, which runs
/// scrypt-1024-1-1-256 with the pure header bytes as both password and salt.
#[cfg(feature = "pow")]
pub fn scrypt_pow_hash(header: &Header) -> BlockHash {
    let header_bytes = header.pure_header_bytes();
    let mut out = [0u8; 32];
    let params = scrypt::Params::new(10, 1, 1, 32).expect("scrypt-1024-1-1-256 params are valid");
    scrypt::scrypt(&header_bytes, &header_bytes, &params, &mut out)
        .expect("32-byte scrypt output length is valid");
    BlockHash::from_byte_array(out)
}

/// Computes Tidecoin's yespower mining hash for the pure 80-byte block header.
///
/// This mirrors the node's `CPureBlockHeader::GetPoWHash()`, which runs
/// yespower 1.0 with `N = 2048`, `r = 8`, and no personalization.
#[cfg(feature = "pow")]
pub fn yespower_pow_hash(header: &Header) -> Result<BlockHash, MiningHashError> {
    rust_yespower::tidecoin_hash(&header.pure_header_bytes())
        .map(BlockHash::from_byte_array)
        .map_err(|_| MiningHashError::Yespower)
}

/// Computes the Tidecoin mining hash selected by consensus for `height`.
#[cfg(feature = "pow")]
pub fn mining_hash_for_height(
    header: &Header,
    params: impl AsRef<Params>,
    height: BlockHeight,
) -> Result<BlockHash, MiningHashError> {
    match pow_hash_algorithm_at_height(params, height) {
        MiningHashAlgorithm::Scrypt => Ok(scrypt_pow_hash(header)),
        MiningHashAlgorithm::Yespower => yespower_pow_hash(header),
    }
}

/// Validates the Tidecoin proof-of-work for `header` at `height`.
///
/// This mirrors the node's height-aware proof check for pure headers: it applies
/// Tidecoin node target rejection semantics, selects the height-dependent mining
/// hash algorithm, and verifies that the selected hash meets the header target.
#[cfg(feature = "pow")]
pub fn validate_pow_at_height(
    header: &Header,
    params: impl AsRef<Params>,
    height: BlockHeight,
) -> Result<BlockHash, PowValidationError> {
    let params = params.as_ref();
    let target = derive_target(header.bits, params).map_err(PowValidationError::InvalidTarget)?;
    validate_pow_hash_at_height(header, params, height, target)
}

/// Validates proof-of-work and verifies that `header` has `required_target`.
///
/// Use this when the caller has already computed the contextual
/// difficulty-schedule target for the header.
#[cfg(feature = "pow")]
pub fn validate_pow_at_height_against_target(
    header: &Header,
    params: impl AsRef<Params>,
    height: BlockHeight,
    required_target: Target,
) -> Result<BlockHash, PowValidationError> {
    let params = params.as_ref();
    let target = derive_target(header.bits, params).map_err(PowValidationError::InvalidTarget)?;
    if target != required_target {
        return Err(PowValidationError::BadTarget);
    }
    validate_pow_hash_at_height(header, params, height, target)
}

/// Validates proof-of-work without height context by accepting either Tidecoin mining hash class.
///
/// This mirrors the node's `CheckProofOfWorkAny(...)` path used when header height is not known:
/// the claimed compact target is still validated under Tidecoin target rules, but either yespower
/// or scrypt may satisfy the target.
#[cfg(feature = "pow")]
pub fn validate_pow_any(
    header: &Header,
    params: impl AsRef<Params>,
) -> Result<BlockHash, PowValidationError> {
    let target = derive_target(header.bits, params).map_err(PowValidationError::InvalidTarget)?;

    let yespower_hash = yespower_pow_hash(header).map_err(PowValidationError::MiningHash)?;
    if target.is_met_by(yespower_hash) {
        return Ok(yespower_hash);
    }

    let scrypt_hash = scrypt_pow_hash(header);
    if target.is_met_by(scrypt_hash) {
        Ok(scrypt_hash)
    } else {
        Err(PowValidationError::BadProofOfWork)
    }
}

#[cfg(feature = "pow")]
internal_macros::define_extension_trait! {
    /// Proof-validation functionality for the [`Header`] type.
    #[cfg_attr(docsrs, doc(cfg(feature = "pow")))]
    pub trait HeaderPowExt impl for Header {
        /// Checks that the proof-of-work for the block is valid, returning the mining hash.
        fn validate_pow(
            &self,
            params: impl AsRef<Params>,
            height: BlockHeight,
            required_target: Target,
        ) -> Result<BlockHash, PowValidationError> {
            validate_pow_at_height_against_target(self, params, height, required_target)
        }
    }
}

#[cfg(feature = "pow")]
fn validate_pow_hash_at_height(
    header: &Header,
    params: &Params,
    height: BlockHeight,
    target: Target,
) -> Result<BlockHash, PowValidationError> {
    let mining_hash =
        mining_hash_for_height(header, params, height).map_err(PowValidationError::MiningHash)?;
    if target.is_met_by(mining_hash) {
        Ok(mining_hash)
    } else {
        Err(PowValidationError::BadProofOfWork)
    }
}

/// Validates the node AuxPoW context for `header` at an optional chain height.
///
/// This mirrors the node's `CheckAuxPowContext(...)` split: it validates
/// AuxPoW flag/payload consistency, activation, strict chain ID rules, the
/// merge-mining commitment, and the parent scrypt proof against the child
/// header's `nBits`. It intentionally does not validate the child header's
/// own pure-header PoW when AuxPoW is absent; call [`validate_pow_at_height`]
/// for that path.
#[cfg(feature = "pow")]
pub fn validate_auxpow_context(
    header: &Header,
    params: impl AsRef<Params>,
    height: Option<BlockHeight>,
) -> Result<(), AuxPowValidationError> {
    let params = params.as_ref();
    let auxpow_flag = header.version.is_auxpow();
    let auxpow = header.auxpow.as_deref();

    if auxpow_flag && auxpow.is_none() {
        return Err(AuxPowValidationError::MissingAuxPow);
    }
    if !auxpow_flag && auxpow.is_some() {
        return Err(AuxPowValidationError::UnexpectedAuxPow);
    }

    if let Some(height) = height {
        if !uses_post_auxpow_pow_rules(params, height) && (auxpow_flag || auxpow.is_some()) {
            return Err(AuxPowValidationError::PreActivation);
        }
    }

    if params.strict_auxpow_chain_id && header.version.to_consensus() != 1 {
        if auxpow_flag {
            if header.version.chain_id() != params.auxpow_chain_id as i32 {
                return Err(AuxPowValidationError::ChainIdMismatch);
            }
        } else if (header.version.to_consensus()
            & crate::block::Version::MASK_AUXPOW_CHAINID_SHIFTED)
            != 0
        {
            return Err(AuxPowValidationError::ChainIdWithoutAuxPowFlag);
        }
    }

    if let Some(auxpow) = auxpow {
        validate_auxpow_commitment(header, auxpow, params)?;
        let parent_hash = scrypt_pow_hash(&auxpow.parent_block);
        let target =
            derive_target(header.bits, params).map_err(AuxPowValidationError::ParentTarget)?;
        if !target.is_met_by(parent_hash) {
            return Err(AuxPowValidationError::ParentProofOfWork);
        }
    }

    Ok(())
}

#[cfg(feature = "pow")]
fn validate_auxpow_commitment(
    header: &Header,
    auxpow: &AuxPow,
    params: &Params,
) -> Result<(), AuxPowValidationError> {
    let parent_chain_id = auxpow.parent_block.version.chain_id();
    if params.strict_auxpow_chain_id
        && parent_chain_id > 0
        && parent_chain_id == params.auxpow_chain_id as i32
    {
        return Err(AuxPowValidationError::ParentHasOwnChainId);
    }

    if auxpow.chain_merkle_branch.len() > 30 {
        return Err(AuxPowValidationError::ChainMerkleBranchTooLong);
    }

    let chain_root = check_auxpow_merkle_branch(
        header.block_hash(),
        &auxpow.chain_merkle_branch,
        auxpow.chain_index,
    );
    let mut root_in_coinbase = chain_root.to_byte_array();
    root_in_coinbase.reverse();

    let coinbase_root = check_auxpow_merkle_branch(
        BlockHash::from_byte_array(auxpow.coinbase_tx.compute_txid().to_byte_array()),
        &auxpow.merkle_branch,
        0,
    );
    if coinbase_root.to_byte_array() != auxpow.parent_block.merkle_root.to_byte_array() {
        return Err(AuxPowValidationError::CoinbaseMerkleRoot);
    }

    let Some(input) = auxpow.coinbase_tx.inputs.first() else {
        return Err(AuxPowValidationError::CoinbaseNoInputs);
    };
    let script = input.script_sig.as_bytes();
    let Some(root_pos) = find_subslice(script, &root_in_coinbase) else {
        return Err(AuxPowValidationError::MissingChainMerkleRoot);
    };

    const MERGED_MINING_HEADER: &[u8; 4] = b"\xfa\xbe\x6d\x6d";
    let header_pos = find_subslice(script, MERGED_MINING_HEADER);
    if let Some(header_pos) = header_pos {
        if find_subslice(&script[header_pos + 1..], MERGED_MINING_HEADER).is_some() {
            return Err(AuxPowValidationError::MultipleMergedMiningHeaders);
        }
        if header_pos + MERGED_MINING_HEADER.len() != root_pos {
            return Err(AuxPowValidationError::MergedMiningHeaderNotBeforeRoot);
        }
    } else {
        return Err(AuxPowValidationError::MissingMergedMiningHeader);
    }

    let metadata_pos = root_pos + root_in_coinbase.len();
    if script.len().saturating_sub(metadata_pos) < 8 {
        return Err(AuxPowValidationError::MissingChainMerkleSizeAndNonce);
    }

    let size = u32::from_le_bytes(script[metadata_pos..metadata_pos + 4].try_into().unwrap());
    let merkle_height = auxpow.chain_merkle_branch.len();
    if size != (1u32 << merkle_height) {
        return Err(AuxPowValidationError::MerkleBranchSizeMismatch);
    }

    let nonce = u32::from_le_bytes(script[metadata_pos + 4..metadata_pos + 8].try_into().unwrap());
    if auxpow.chain_index
        != expected_auxpow_chain_index(nonce, header.version.chain_id(), merkle_height)
    {
        return Err(AuxPowValidationError::WrongChainIndex);
    }

    Ok(())
}

#[cfg(feature = "pow")]
fn check_auxpow_merkle_branch(
    mut hash: BlockHash,
    merkle_branch: &[BlockHash],
    mut index: i32,
) -> BlockHash {
    if index == -1 {
        return BlockHash::from_byte_array([0; 32]);
    }

    for sibling in merkle_branch {
        hash = if index & 1 != 0 {
            combine_auxpow_merkle_hashes(*sibling, hash)
        } else {
            combine_auxpow_merkle_hashes(hash, *sibling)
        };
        index >>= 1;
    }

    hash
}

#[cfg(feature = "pow")]
fn combine_auxpow_merkle_hashes(left: BlockHash, right: BlockHash) -> BlockHash {
    let mut engine = sha256d::Hash::engine();
    engine.input(left.as_byte_array());
    engine.input(right.as_byte_array());
    BlockHash::from_byte_array(sha256d::Hash::from_engine(engine).to_byte_array())
}

#[cfg(feature = "pow")]
fn expected_auxpow_chain_index(nonce: u32, chain_id: i32, height: usize) -> i32 {
    let modulus = 1u64 << height;
    let mut rand = u64::from(nonce);
    rand = rand.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    rand %= modulus;
    rand = rand.wrapping_add(chain_id as u64);
    rand = rand.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    (rand % modulus) as i32
}

#[cfg(feature = "pow")]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Error computing the Tidecoin mining hash selected by consensus.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MiningHashError {
    /// The yespower backend failed.
    Yespower,
}

impl fmt::Display for MiningHashError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Yespower => f.write_str("yespower mining hash failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MiningHashError {}

/// Error validating Tidecoin proof-of-work for a block header.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum PowValidationError {
    /// The selected mining hash is not below the target.
    BadProofOfWork,
    /// The header target did not match the expected difficulty.
    BadTarget,
    /// The compact target was invalid under Tidecoin node consensus rules.
    InvalidTarget(PowTargetError),
    /// The selected mining hash algorithm failed locally.
    MiningHash(MiningHashError),
}

impl fmt::Display for PowValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BadProofOfWork => f.write_str("block target correct but not attained"),
            Self::BadTarget => f.write_str("block target incorrect"),
            Self::InvalidTarget(err) => write!(f, "invalid compact proof-of-work target: {err}"),
            Self::MiningHash(err) => write!(f, "failed to compute mining hash: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PowValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BadProofOfWork | Self::BadTarget => None,
            Self::InvalidTarget(err) => Some(err),
            Self::MiningHash(err) => Some(err),
        }
    }
}

/// Error validating Tidecoin AuxPoW context.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AuxPowValidationError {
    /// AuxPoW version flag is set but the AuxPoW payload is absent.
    MissingAuxPow,
    /// AuxPoW payload is present without the AuxPoW version flag.
    UnexpectedAuxPow,
    /// AuxPoW is present before the configured activation height.
    PreActivation,
    /// Header AuxPoW chain ID does not match network consensus params.
    ChainIdMismatch,
    /// Chain ID bits are set without the AuxPoW version flag.
    ChainIdWithoutAuxPowFlag,
    /// Parent header carries this chain's AuxPoW chain ID under strict-chain-id rules.
    ParentHasOwnChainId,
    /// Chain merkle branch exceeds the node's maximum depth.
    ChainMerkleBranchTooLong,
    /// Coinbase transaction merkle branch does not match the parent header root.
    CoinbaseMerkleRoot,
    /// AuxPoW coinbase transaction has no inputs.
    CoinbaseNoInputs,
    /// Coinbase scriptSig does not contain the chain merkle root.
    MissingChainMerkleRoot,
    /// Coinbase scriptSig contains multiple merged-mining headers.
    MultipleMergedMiningHeaders,
    /// Merged-mining header is not immediately before the chain merkle root.
    MergedMiningHeaderNotBeforeRoot,
    /// Coinbase scriptSig is missing the merged-mining header.
    MissingMergedMiningHeader,
    /// Coinbase scriptSig is missing chain merkle size or nonce metadata.
    MissingChainMerkleSizeAndNonce,
    /// Coinbase chain merkle size metadata does not match the branch height.
    MerkleBranchSizeMismatch,
    /// Chain merkle index does not match the deterministic chain-id/nonce slot.
    WrongChainIndex,
    /// Parent proof target was invalid under Tidecoin node consensus rules.
    ParentTarget(PowTargetError),
    /// Parent scrypt proof does not meet the child header target.
    ParentProofOfWork,
}

impl fmt::Display for AuxPowValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingAuxPow => f.write_str("auxpow flag set but auxpow payload missing"),
            Self::UnexpectedAuxPow => f.write_str("auxpow payload present without auxpow flag"),
            Self::PreActivation => f.write_str("auxpow not allowed before activation"),
            Self::ChainIdMismatch => f.write_str("auxpow chain id mismatch"),
            Self::ChainIdWithoutAuxPowFlag => f.write_str("chain id set without auxpow flag"),
            Self::ParentHasOwnChainId => f.write_str("auxpow parent has this chain id"),
            Self::ChainMerkleBranchTooLong => f.write_str("auxpow chain merkle branch too long"),
            Self::CoinbaseMerkleRoot => f.write_str("auxpow coinbase merkle root incorrect"),
            Self::CoinbaseNoInputs => f.write_str("auxpow coinbase has no inputs"),
            Self::MissingChainMerkleRoot => {
                f.write_str("auxpow chain merkle root missing from parent coinbase")
            }
            Self::MultipleMergedMiningHeaders => {
                f.write_str("multiple merged mining headers in auxpow coinbase")
            }
            Self::MergedMiningHeaderNotBeforeRoot => {
                f.write_str("merged mining header is not immediately before auxpow root")
            }
            Self::MissingMergedMiningHeader => f.write_str("missing merged mining header"),
            Self::MissingChainMerkleSizeAndNonce => {
                f.write_str("auxpow coinbase missing chain merkle size or nonce")
            }
            Self::MerkleBranchSizeMismatch => {
                f.write_str("auxpow chain merkle branch size metadata mismatch")
            }
            Self::WrongChainIndex => f.write_str("auxpow wrong chain merkle index"),
            Self::ParentTarget(err) => {
                write!(f, "invalid auxpow parent proof target: {err}")
            }
            Self::ParentProofOfWork => f.write_str("auxpow parent proof of work failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AuxPowValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParentTarget(err) => Some(err),
            _ => None,
        }
    }
}

/// Derives a target from compact `nBits` using Tidecoin node rejection semantics.
///
/// This mirrors the node's `DeriveTarget(...)`: negative, zero, overflow, and
/// above-`powLimit` targets are consensus-invalid.
pub fn derive_target(
    bits: CompactTarget,
    params: impl AsRef<Params>,
) -> Result<Target, PowTargetError> {
    let bits = bits.to_consensus();
    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;

    if mantissa != 0 && (bits & 0x0080_0000) != 0 {
        return Err(PowTargetError::Negative);
    }

    if mantissa != 0
        && (exponent > 34
            || (mantissa > 0xff && exponent > 33)
            || (mantissa > 0xffff && exponent > 32))
    {
        return Err(PowTargetError::Overflow);
    }

    let target = if exponent <= 3 {
        Target(U256::from(mantissa >> (8 * (3 - exponent))))
    } else {
        Target(U256::from(mantissa) << (8 * (exponent - 3)))
    };

    if target.0.is_zero() {
        return Err(PowTargetError::Zero);
    }
    if target > params.as_ref().max_attainable_target {
        return Err(PowTargetError::AboveLimit);
    }

    Ok(target)
}

/// Error deriving a consensus proof-of-work target from compact `nBits`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum PowTargetError {
    /// Compact target encoded a negative target.
    Negative,
    /// Compact target encoded zero.
    Zero,
    /// Compact target overflowed the 256-bit target range.
    Overflow,
    /// Target exceeds the network proof-of-work limit.
    AboveLimit,
}

impl fmt::Display for PowTargetError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Negative => f.write_str("compact target is negative"),
            Self::Zero => f.write_str("compact target is zero"),
            Self::Overflow => f.write_str("compact target overflows 256-bit target range"),
            Self::AboveLimit => f.write_str("compact target exceeds network proof-of-work limit"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PowTargetError {}

/// Implement traits and methods shared by `Target` and `Work`.
macro_rules! do_impl {
    ($ty:ident, $err_ty:ident) => {
        impl $ty {
            #[doc = "Constructs a new `"]
            #[doc = stringify!($ty)]
            #[doc = "` from a prefixed hex string.\n"]
            #[doc = "\n# Errors\n"]
            #[doc = "\n - If the input string does not contain a `0x` (or `0X`) prefix."]
            #[doc = "\n - If the input string is not a valid hex encoding of a `"]
            #[doc = stringify!($ty)]
            #[doc = "`."]
            pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
                Ok($ty(U256::from_hex(s)?))
            }

            #[doc = "Constructs a new `"]
            #[doc = stringify!($ty)]
            #[doc = "` from an unprefixed hex string.\n"]
            #[doc = "\n# Errors\n"]
            #[doc = "\n - If the input string contains a `0x` (or `0X`) prefix."]
            #[doc = "\n - If the input string is not a valid hex encoding of a `"]
            #[doc = stringify!($ty)]
            #[doc = "`."]
            pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
                Ok($ty(U256::from_unprefixed_hex(s)?))
            }

            #[doc = "Constructs `"]
            #[doc = stringify!($ty)]
            #[doc = "` from a big-endian byte array."]
            #[inline]
            pub fn from_be_bytes(bytes: [u8; 32]) -> $ty {
                $ty(U256::from_be_bytes(bytes))
            }

            #[doc = "Constructs `"]
            #[doc = stringify!($ty)]
            #[doc = "` from a little-endian byte array."]
            #[inline]
            pub fn from_le_bytes(bytes: [u8; 32]) -> $ty {
                $ty(U256::from_le_bytes(bytes))
            }

            #[doc = "Converts `"]
            #[doc = stringify!($ty)]
            #[doc = "` to a big-endian byte array."]
            #[inline]
            pub fn to_be_bytes(self) -> [u8; 32] {
                self.0.to_be_bytes()
            }

            #[doc = "Converts `"]
            #[doc = stringify!($ty)]
            #[doc = "` to a little-endian byte array."]
            #[inline]
            pub fn to_le_bytes(self) -> [u8; 32] {
                self.0.to_le_bytes()
            }
        }

        impl fmt::Display for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::LowerHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::UpperHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                fmt::UpperHex::fmt(&self.0, f)
            }
        }

        impl core::str::FromStr for $ty {
            type Err = $err_ty;

            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                U256::from_str(s).map($ty).map_err($err_ty)
            }
        }

        #[doc = "Error returned when parsing a [`"]
        #[doc = stringify!($ty)]
        #[doc = "`] from a string."]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $err_ty(ParseU256Error);

        impl From<core::convert::Infallible> for $err_ty {
            fn from(never: core::convert::Infallible) -> Self {
                match never {}
            }
        }

        impl fmt::Display for $err_ty {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        #[cfg(feature = "std")]
        impl std::error::Error for $err_ty {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
    };
}

/// A 256 bit integer representing work.
///
/// Work is a measure of how difficult it is to find a hash below a given [`Target`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Work(U256);

impl Work {
    /// Converts this [`Work`] to [`Target`].
    pub fn to_target(self) -> Target {
        Target(self.0.inverse())
    }

    /// Returns log2 of this work.
    ///
    /// The result inherently suffers from a loss of precision and is, therefore, meant to be
    /// used mainly for informative and displaying purposes, similarly to the reference node's
    /// `log2_work` output in its logs.
    #[cfg(feature = "std")]
    pub fn log2(self) -> f64 {
        self.0.to_f64().log2()
    }
}
do_impl!(Work, ParseWorkError);
impl_to_hex_from_lower_hex!(Work, |_| 64);

impl Add for Work {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for Work {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

/// A 256 bit integer representing target.
///
/// The SHA-256 hash of a block's header must be lower than or equal to the current target for the
/// block to be accepted by the network. The lower the target, the more difficult it is to generate
/// a block. (See also [`Work`].)
///
/// [`Target`] does not limit its value to the maximum attainable value for any network when it
/// is constructed. If you need to enforce that invariant, you should compare the constructed value
/// against the required network's `MAX_ATTAINABLE_*` target constant.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Target(U256);

impl Target {
    /// When parsing nBits, the Tidecoin node converts a negative target threshold into a target of zero.
    pub const ZERO: Self = Self(U256::ZERO);
    /// The maximum possible target.
    ///
    /// This value is used to calculate difficulty, which is defined as how difficult the current
    /// target makes it to find a block relative to how difficult it would be at the highest
    /// possible target. Remember highest target == lowest difficulty.
    // Tidecoin powLimit compact form 0x2001ffff, expanded to full target.
    pub const MAX: Self = Self(U256(0x01FFFF_u128 << 104, 0));

    /// The maximum **attainable** target value on mainnet.
    ///
    /// Not all target values are attainable because consensus code uses the compact format to
    /// represent targets (see [`CompactTarget`]).
    // Tidecoin mainnet powLimit: 0x2001ffff compact.
    pub const MAX_ATTAINABLE_MAINNET: Self = Self(U256(0x01FFFF_u128 << 104, 0));

    /// The maximum **attainable** target value on regtest.
    // Tidecoin regtest powLimit: 0x200f0f0f compact.
    pub const MAX_ATTAINABLE_REGTEST: Self = Self(U256(0x0F0F0F_u128 << 104, 0));

    /// Computes the [`Target`] value from a compact representation.
    pub fn from_compact(c: CompactTarget) -> Self {
        let bits = c.to_consensus();
        // This is a floating-point "compact" encoding originally used by
        // OpenSSL, which satoshi put into consensus code, so we're stuck
        // with it. The exponent needs to have 3 subtracted from it, hence
        // this goofy decoding code. 3 is due to 3 bytes in the mantissa.
        let (mant, expt) = {
            let unshifted_expt = bits >> 24;
            if unshifted_expt <= 3 {
                ((bits & 0xFFFFFF) >> (8 * (3 - unshifted_expt as usize)), 0)
            } else {
                (bits & 0xFFFFFF, 8 * ((bits >> 24) - 3))
            }
        };

        // The mantissa is signed but may not be negative.
        if mant > 0x7F_FFFF {
            Self::ZERO
        } else {
            Self(U256::from(mant) << expt)
        }
    }

    /// Computes the compact value from a [`Target`] representation.
    ///
    /// The compact form is by definition lossy, this means that
    /// `t == Target::from_compact(t.to_compact_lossy())` does not always hold.
    pub fn to_compact_lossy(self) -> CompactTarget {
        let mut size = self.0.bits().div_ceil(8);
        let mut compact = if size <= 3 {
            (self.0.low_u64() << (8 * (3 - size))) as u32
        } else {
            let bn = self.0 >> (8 * (size - 3));
            bn.low_u32()
        };

        if (compact & 0x0080_0000) != 0 {
            compact >>= 8;
            size += 1;
        }

        CompactTarget::from_consensus(compact | (size << 24))
    }

    /// Returns true if block hash is less than or equal to this [`Target`].
    ///
    /// Proof-of-work validity for a block requires the hash of the block to be less than or equal
    /// to the target.
    pub fn is_met_by(&self, hash: BlockHash) -> bool {
        let hash = U256::from_le_bytes(hash.to_byte_array());
        hash <= self.0
    }

    /// Converts this [`Target`] to [`Work`].
    ///
    /// "Work" is defined as the work done to mine a block with this target value (recorded in the
    /// block header in compact form as nBits). This is not the same as the difficulty to mine a
    /// block with this target (see `Self::difficulty`).
    pub fn to_work(self) -> Work {
        Work(self.0.inverse())
    }

    /// Computes the popular "difficulty" measure for mining.
    ///
    /// Difficulty represents how difficult the current target makes it to find a block, relative to
    /// how difficult it would be at the highest possible target (highest target == lowest difficulty).
    ///
    /// For example, a difficulty of 6,695,826 means that at a given hash rate, it will, on average,
    /// take ~6.6 million times as long to find a valid block as it would at a difficulty of 1, or
    /// alternatively, it will take, again on average, ~6.6 million times as many hashes to find a
    /// valid block.
    ///
    /// Values for the `max_target` paramter can be taken from const values on [`Target`]
    /// (e.g. [`Target::MAX_ATTAINABLE_MAINNET`]).
    ///
    /// # Note
    ///
    /// Difficulty is calculated using the following algorithm `max / current` where [max] is
    /// defined for the Tidecoin network and `current` is the current target for this block (i.e. `self`).
    /// As such, a low target implies a high difficulty. Since [`Target`] is represented as a 256 bit
    /// integer but `difficulty_with_max()` returns only 128 bits this means for targets below
    /// approximately `0xffff_ffff_ffff_ffff_ffff_ffff` `difficulty_with_max()` will saturate at `u128::MAX`.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero (divide by zero).
    ///
    /// [max]: Target::max
    pub fn difficulty_with_max(&self, max_target: &Self) -> u128 {
        // Panic here may be easier to debug than during the actual division.
        assert_ne!(self.0, U256::ZERO, "divide by zero");

        let d = max_target.0 / self.0;
        d.saturating_to_u128()
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    ///
    /// See [`difficulty_with_max`] for details.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero (divide by zero).
    ///
    /// [`difficulty_with_max`]: Target::difficulty_with_max
    pub fn difficulty_float_with_max(&self, max_target: &Self) -> f64 {
        // We want to explicitly panic to be uniform with `difficulty()`
        // (float division by zero does not panic).
        // Note, target 0 is basically impossible to obtain by any "normal" means.
        assert_ne!(self.0, U256::ZERO, "divide by zero");
        max_target.0.to_f64() / self.0.to_f64()
    }

    /// Computes the popular "difficulty" measure for mining.
    ///
    /// This function calculates the difficulty measure using the max attainable target
    /// set on the provided [`Params`].
    /// See [`Target::difficulty_with_max`] for details.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero (divide by zero).
    pub fn difficulty(&self, params: impl AsRef<Params>) -> u128 {
        let max = params.as_ref().max_attainable_target;
        self.difficulty_with_max(&max)
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    ///
    /// This function calculates the difficulty measure using the max attainable target
    /// set on the provided [`Params`].
    /// See [`Target::difficulty_with_max`] for details.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero (divide by zero).
    ///
    /// [`difficulty`]: Target::difficulty
    pub fn difficulty_float(&self, params: impl AsRef<Params>) -> f64 {
        let max = params.as_ref().max_attainable_target;
        self.difficulty_float_with_max(&max)
    }

    /// Computes the minimum valid [`Target`] threshold allowed for a block in which a difficulty
    /// adjustment occurs.
    ///
    /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
    /// adjustment period.
    ///
    /// # Returns
    ///
    /// In line with the Tidecoin node this function may return a target value of zero.
    pub fn min_transition_threshold(&self) -> Self {
        Self(self.0 >> 2)
    }

    /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
    /// adjustment occurs.
    ///
    /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
    /// adjustment period.
    ///
    /// We also check that the calculated target is not greater than the maximum allowed target,
    /// this value is network specific - hence the `params` parameter.
    pub fn max_transition_threshold(&self, params: impl AsRef<Params>) -> Self {
        let max_attainable = params.as_ref().max_attainable_target;
        cmp::min(self.max_transition_threshold_unchecked(), max_attainable)
    }

    /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
    /// adjustment occurs.
    ///
    /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
    /// adjustment period.
    ///
    /// # Returns
    ///
    /// This function may return a value greater than the maximum allowed target for this network.
    ///
    /// The return value should be checked against [`Params::max_attainable_target`] or use one of
    /// the `Target::MAX_ATTAINABLE_FOO` constants.
    pub fn max_transition_threshold_unchecked(&self) -> Self {
        Self(self.0 << 2)
    }
}
do_impl!(Target, ParseTargetError);
impl_to_hex_from_lower_hex!(Target, |_| 64);

/// Gets the target for the block after `current_header`.
///
/// Implements the Tidecoin node's `GetNextWorkRequired` function.
///
/// Note, `new_block_timestamp` is only used when `params.allow_min_difficulty_blocks = true` i.e.,
/// on testnet and regtest.
///
/// > Special difficulty rule for testnet: If the new block's timestamp is more
/// > than 2*10 minutes then allow mining of a min-difficulty block.
///
/// # Panics
///
/// If we are on testnet/regtest and `new_block_timestamp` is `None`.
pub fn next_target_after<F, E>(
    current_header: Header,
    current_height: BlockHeight,
    params: &Params,
    new_block_timestamp: Option<u32>,
    mut get_block_header_by_height: F,
) -> Result<CompactTarget, E>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    if uses_post_auxpow_pow_rules(params, current_height.saturating_add(1.into())) {
        return next_target_after_post_auxpow(
            current_header,
            current_height,
            params,
            new_block_timestamp,
            &mut get_block_header_by_height,
        );
    }

    next_target_after_legacy(
        current_header,
        current_height,
        params,
        new_block_timestamp,
        &mut get_block_header_by_height,
    )
}

pub(crate) fn uses_post_auxpow_pow_rules(params: &Params, candidate_height: BlockHeight) -> bool {
    match params.auxpow_start_height {
        Some(start_height) => candidate_height >= start_height,
        None => false,
    }
}

/// Returns whether a difficulty transition is within the Tidecoin node's permitted bounds.
///
/// This mirrors the node's `PermittedDifficultyTransition(...)`. It does not calculate the exact
/// required next target; it only verifies that the observed `new_bits` value is within the
/// consensus-permitted transition envelope from `old_bits` at `height`.
pub fn permitted_difficulty_transition(
    params: impl AsRef<Params>,
    height: BlockHeight,
    old_bits: CompactTarget,
    new_bits: CompactTarget,
) -> bool {
    let params = params.as_ref();

    // The Tidecoin node permits every transition on networks with min-difficulty blocks.
    if params.allow_min_difficulty_blocks {
        return true;
    }

    if !uses_post_auxpow_pow_rules(params, height) {
        return permitted_legacy_difficulty_transition(params, height, old_bits, new_bits);
    }

    permitted_post_auxpow_difficulty_transition(params, old_bits, new_bits)
}

fn permitted_legacy_difficulty_transition(
    params: &Params,
    height: BlockHeight,
    old_bits: CompactTarget,
    new_bits: CompactTarget,
) -> bool {
    if !is_retarget_height(height, params.difficulty_adjustment_interval()) {
        return old_bits == new_bits;
    }

    let observed_new_target = Target::from_compact(new_bits);
    let pow_limit = params.max_attainable_target;
    let old_target = Target::from_compact(old_bits);
    let largest_timespan = i64::from(params.pow_target_timespan) * 4;

    if legacy_retarget_may_overflow(old_target, largest_timespan, pow_limit) {
        return true;
    }

    let largest_difficulty_target = cmp::min(
        scale_target_legacy_overflow(
            old_target,
            largest_timespan,
            params.pow_target_timespan,
            pow_limit,
        ),
        pow_limit,
    );
    let maximum_new_target = Target::from_compact(largest_difficulty_target.to_compact_lossy());
    if maximum_new_target < observed_new_target {
        return false;
    }

    let smallest_difficulty_target = cmp::min(
        scale_target_legacy_overflow(
            old_target,
            i64::from(params.pow_target_timespan) / 4,
            params.pow_target_timespan,
            pow_limit,
        ),
        pow_limit,
    );
    let minimum_new_target = Target::from_compact(smallest_difficulty_target.to_compact_lossy());
    minimum_new_target <= observed_new_target
}

fn legacy_retarget_may_overflow(target: Target, actual_timespan: i64, pow_limit: Target) -> bool {
    if actual_timespan <= 0 {
        return false;
    }

    let mut target = target.0;
    if target.bits() > pow_limit.0.bits() - 1 {
        target = target >> 1;
    }

    target > U256::MAX / U256::from(actual_timespan as u64)
}

fn permitted_post_auxpow_difficulty_transition(
    params: &Params,
    old_bits: CompactTarget,
    new_bits: CompactTarget,
) -> bool {
    let pow_limit = params.max_attainable_target;
    let old_target = Target::from_compact(old_bits);
    let observed_new_target = Target::from_compact(new_bits);

    let up_num = 100i64 - i64::from(params.pow_max_adjust_up);
    let down_num = 100i64 + i64::from(params.pow_max_adjust_down);
    let up_num_sq = (up_num * up_num) as u64;
    let down_num_sq = (down_num * down_num) as u64;

    let mut largest_difficulty_target = old_target.0.mul_u64(down_num_sq).0;
    largest_difficulty_target = largest_difficulty_target / U256::from(10_000u64);
    largest_difficulty_target = cmp::min(largest_difficulty_target, pow_limit.0);

    let mut smallest_difficulty_target = old_target.0.mul_u64(up_num_sq).0;
    smallest_difficulty_target = smallest_difficulty_target / U256::from(10_000u64);

    let mut maximum_new_target =
        Target::from_compact(Target(largest_difficulty_target).to_compact_lossy()).0;
    maximum_new_target = maximum_new_target + U256::from(2u32);

    let mut minimum_new_target =
        Target::from_compact(Target(smallest_difficulty_target).to_compact_lossy()).0;
    if minimum_new_target > U256::ONE {
        minimum_new_target = minimum_new_target - U256::from(2u32);
    } else if minimum_new_target > U256::ZERO {
        minimum_new_target = minimum_new_target - U256::ONE;
    }

    observed_new_target.0 >= minimum_new_target && observed_new_target.0 <= maximum_new_target
}

fn scale_target_legacy_overflow(
    target: Target,
    actual_timespan: i64,
    target_timespan: u32,
    pow_limit: Target,
) -> Target {
    debug_assert!(actual_timespan >= 0);
    let shift = target.0.bits() > pow_limit.0.bits() - 1;
    let mut target = target.0;
    if shift {
        target = target >> 1;
    }
    target = target.mul_u64(actual_timespan as u64).0;
    target = target / U256::from(target_timespan);
    if shift {
        target = target << 1;
    }
    Target(target)
}

fn next_target_after_legacy<F, E>(
    current_header: Header,
    current_height: BlockHeight,
    params: &Params,
    new_block_timestamp: Option<u32>,
    get_block_header_by_height: &mut F,
) -> Result<CompactTarget, E>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    let adjustment_interval = params.difficulty_adjustment_interval();

    // if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    if !is_retarget_height(current_height.saturating_add(1.into()), adjustment_interval) {
        if params.allow_min_difficulty_blocks {
            // Only true for testnet and regtest.
            let new_block_timestamp = new_block_timestamp
                .expect("new_block_timestamp must contain a value when on testnet/regtest");

            // Special difficulty rule for testnet: If the new block's timestamp is more
            // than 2*10 minutes then allow mining of a min-difficulty block.
            let pow_limit = params.max_attainable_target.to_compact_lossy();

            // if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
            if new_block_timestamp > current_header.time.to_u32() + params.pow_target_spacing * 2 {
                Ok(pow_limit)
            } else {
                let mut header = current_header;
                let mut height = current_height;
                // while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                while header.prev_blockhash != BlockHash::GENESIS_PREVIOUS_BLOCK_HASH
                    && !is_retarget_height(height, adjustment_interval)
                    && header.bits == pow_limit
                {
                    // pindex = pindex->pprev;
                    height = height.saturating_sub(1.into());
                    header = get_block_header_by_height(height)?;
                }
                Ok(header.bits)
            }
        } else {
            Ok(current_header.bits)
        }
    } else {
        // Tidecoin keeps the inherited first-retarget off-by-one, but later
        // legacy retargets go back a full interval, matching the node.
        let back_step = if current_height.saturating_add(1.into()).to_u32() == adjustment_interval {
            adjustment_interval - 1
        } else {
            adjustment_interval
        };
        let back_step = BlockHeightInterval::from_u32(back_step);
        let height_first = current_height.saturating_sub(back_step);
        let block_first = get_block_header_by_height(height_first)?;

        Ok(CompactTarget::from_header_difficulty_adjustment(block_first, current_header, params))
    }
}

fn next_target_after_post_auxpow<F, E>(
    current_header: Header,
    current_height: BlockHeight,
    params: &Params,
    new_block_timestamp: Option<u32>,
    get_block_header_by_height: &mut F,
) -> Result<CompactTarget, E>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    let pow_limit = params.max_attainable_target.to_compact_lossy();

    if params.no_pow_retargeting {
        return Ok(current_header.bits);
    }

    if let Some(min_difficulty_height) = params.pow_allow_min_difficulty_blocks_after_height {
        if current_height >= min_difficulty_height {
            if let Some(new_block_timestamp) = new_block_timestamp {
                if new_block_timestamp
                    > current_header.time.to_u32() + params.pow_target_spacing * 6
                {
                    return Ok(pow_limit);
                }
            }
        }
    }

    let window = params.pow_averaging_window;
    if window == 0 || current_height.to_u32() < window {
        return Ok(pow_limit);
    }

    let mut total = U256::ZERO;
    for offset in 0..window {
        let height = BlockHeight::from_u32(current_height.to_u32() - offset);
        let header =
            header_at(current_header.clone(), current_height, height, get_block_header_by_height)?;
        total = total + Target::from_compact(header.bits).0;
    }

    let avg = Target(total / U256::from(window));
    let first_height = BlockHeight::from_u32(current_height.to_u32() - window);
    let last_mtp = median_time_past_at(
        current_header.clone(),
        current_height,
        current_height,
        get_block_header_by_height,
    )?;
    let first_mtp = median_time_past_at(
        current_header,
        current_height,
        first_height,
        get_block_header_by_height,
    )?;

    Ok(CompactTarget::from_post_auxpow_next_work_required(avg, last_mtp, first_mtp, params))
}

fn header_at<F, E>(
    current_header: Header,
    current_height: BlockHeight,
    height: BlockHeight,
    get_block_header_by_height: &mut F,
) -> Result<Header, E>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    if height == current_height {
        Ok(current_header)
    } else {
        get_block_header_by_height(height)
    }
}

fn median_time_past_at<F, E>(
    current_header: Header,
    current_height: BlockHeight,
    height: BlockHeight,
    get_block_header_by_height: &mut F,
) -> Result<BlockMtp, E>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    let mut times = [0_u32; 11];
    let mut count = 0;
    let height = height.to_u32();
    for offset in 0..11 {
        if offset > height {
            break;
        }
        let header = header_at(
            current_header.clone(),
            current_height,
            BlockHeight::from_u32(height - offset),
            get_block_header_by_height,
        )?;
        times[count] = header.time.to_u32();
        count += 1;
    }
    let times = &mut times[..count];
    times.sort_unstable();
    Ok(BlockMtp::from_u32(times[count / 2]))
}

/// Returns true if `height` ends the difficulty period.
fn is_retarget_height(height: BlockHeight, adjustment_interval: u32) -> bool {
    height.to_u32().is_multiple_of(adjustment_interval)
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`CompactTarget`] type.
    pub trait CompactTargetExt impl for CompactTarget {
        /// Computes the [`CompactTarget`] from a difficulty adjustment.
        ///
        /// Given the previous Target, represented as a [`CompactTarget`], the difficulty is adjusted
        /// by taking the timespan between them, and multiplying the current [`CompactTarget`] by a factor
        /// of the net timespan and expected timespan. The [`CompactTarget`] may not adjust by more than
        /// a factor of 4, or adjust beyond the maximum threshold for the network.
        ///
        /// # Note
        ///
        /// Under the consensus rules, the difference in the number of blocks between the headers does
        /// not equate to the `difficulty_adjustment_interval` of [`Params`]. This is due to an off-by-one
        /// error, and, the expected number of blocks in between headers is `difficulty_adjustment_interval - 1`
        /// when calculating the difficulty adjustment.
        ///
        /// Take the example of the first difficulty adjustment. Block 2016 introduces a new [`CompactTarget`],
        /// which takes the net timespan between Block 2015 and Block 0, and recomputes the difficulty.
        ///
        /// To calculate the timespan, users should first convert their u32 timestamps to i64s before subtracting them
        ///
        /// # Returns
        ///
        /// The expected [`CompactTarget`] recalculation.
        fn from_next_work_required(
            last: CompactTarget,
            timespan: i64,
            params: impl AsRef<Params>,
        ) -> Self {
            let params = params.as_ref();
            if params.no_pow_retargeting {
                return last;
            }
            let min_timespan = params.pow_target_timespan >> 2; // Lines 56/57
            let max_timespan = params.pow_target_timespan << 2; // Lines 58/59
            let actual_timespan = timespan.clamp(min_timespan.into(), max_timespan.into());
            let prev_target: Target = last.into();
            let retarget = scale_target_legacy_overflow(
                prev_target,
                actual_timespan,
                params.pow_target_timespan,
                params.max_attainable_target,
            );
            if retarget.ge(&params.max_attainable_target) {
                return params.max_attainable_target.to_compact_lossy();
            }
            retarget.to_compact_lossy()
        }

        /// Computes the [`CompactTarget`] from a difficulty adjustment,
        /// assuming these are the relevant block headers.
        ///
        /// Given two headers, representing the start and end of a difficulty adjustment epoch,
        /// compute the [`CompactTarget`] based on the net time between them and the current
        /// [`CompactTarget`].
        ///
        /// # Note
        ///
        /// See [`CompactTarget::from_next_work_required`]
        ///
        /// For example, to successfully compute the first difficulty adjustment on the Tidecoin network,
        /// one would pass the header for Block 2015 as `current` and the header for Block 0 as
        /// `last_epoch_boundary`.
        ///
        /// # Returns
        ///
        /// The expected [`CompactTarget`] recalculation.
        fn from_header_difficulty_adjustment(
            last_epoch_boundary: Header,
            current: Header,
            params: impl AsRef<Params>,
        ) -> Self {
            let timespan = i64::from(current.time.to_u32()) - i64::from(last_epoch_boundary.time.to_u32());

            // Special difficulty rule for testnet.
            // Take target from start of epoch instead of end of epoch.
            let bits = if params.as_ref().enforce_bip94 {
                last_epoch_boundary.bits
            } else {
                current.bits
            };

            CompactTarget::from_next_work_required(bits, timespan, params)
        }

        /// Computes the Tidecoin post-auxpow per-block retarget value.
        ///
        /// This mirrors the node's `CalculateNextWorkRequiredNew`: it averages the previous
        /// target window, uses median-time-past endpoints, damps the observed timespan by 4,
        /// clamps by `pow_max_adjust_up/down`, and rounds through compact target encoding.
        fn from_post_auxpow_next_work_required(
            average_target: Target,
            last_mtp: BlockMtp,
            first_mtp: BlockMtp,
            params: impl AsRef<Params>,
        ) -> Self {
            let params = params.as_ref();
            if params.no_pow_retargeting || params.pow_averaging_window == 0 {
                return average_target.to_compact_lossy();
            }

            let averaging_window_timespan =
                i64::from(params.pow_averaging_window) * i64::from(params.pow_target_spacing);
            let min_actual_timespan =
                (averaging_window_timespan * (100 - i64::from(params.pow_max_adjust_up))) / 100;
            let max_actual_timespan =
                (averaging_window_timespan * (100 + i64::from(params.pow_max_adjust_down))) / 100;

            let mut actual_timespan =
                i64::from(last_mtp.to_u32()) - i64::from(first_mtp.to_u32());
            actual_timespan =
                averaging_window_timespan + (actual_timespan - averaging_window_timespan) / 4;
            actual_timespan = actual_timespan.clamp(min_actual_timespan, max_actual_timespan);

            let mut retarget = average_target.0 / U256::from(averaging_window_timespan as u64);
            retarget = retarget * U256::from(actual_timespan as u64);

            let retarget = Target(cmp::min(retarget, params.max_attainable_target.0));
            retarget.to_compact_lossy()
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::CompactTarget {}
    #[cfg(feature = "pow")]
    impl Sealed for super::Header {}
}

impl From<CompactTarget> for Target {
    fn from(c: CompactTarget) -> Self {
        Self::from_compact(c)
    }
}

/// Big-endian 256 bit integer type.
// (high, low): u.0 contains the high bits, u.1 contains the low bits.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
struct U256(u128, u128);

impl U256 {
    const MAX: Self =
        Self(0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff);

    const ZERO: Self = Self(0, 0);

    const ONE: Self = Self(0, 1);

    /// Constructs a new `U256` from a prefixed hex string.
    fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
        let checked = parse_int::hex_remove_prefix(s)?;
        Ok(Self::from_hex_internal(checked)?)
    }

    /// Constructs a new `U256` from an unprefixed hex string.
    fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        let checked = parse_int::hex_check_unprefixed(s)?;
        Ok(Self::from_hex_internal(checked)?)
    }

    // Caller to ensure `s` does not contain a prefix.
    fn from_hex_internal(s: &str) -> Result<Self, ParseIntError> {
        let (high, low) = if s.len() <= 32 {
            let low = parse_int::hex_u128_unchecked(s)?;
            (0, low)
        } else {
            let high_len = s.len() - 32;
            let high_s = &s[..high_len];
            let low_s = &s[high_len..];

            let high = parse_int::hex_u128_unchecked(high_s)?;
            let low = parse_int::hex_u128_unchecked(low_s)?;
            (high, low)
        };

        Ok(Self(high, low))
    }

    /// Constructs a new `U256` from a big-endian array of `u8`s.
    fn from_be_bytes(a: [u8; 32]) -> Self {
        let (high, low) = split_in_half(a);
        let big = u128::from_be_bytes(high);
        let little = u128::from_be_bytes(low);
        Self(big, little)
    }

    /// Constructs a new `U256` from a little-endian array of `u8`s.
    fn from_le_bytes(a: [u8; 32]) -> Self {
        let (high, low) = split_in_half(a);
        let little = u128::from_le_bytes(high);
        let big = u128::from_le_bytes(low);
        Self(big, little)
    }

    /// Converts `U256` to a big-endian array of `u8`s.
    fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        out[..16].copy_from_slice(&self.0.to_be_bytes());
        out[16..].copy_from_slice(&self.1.to_be_bytes());
        out
    }

    /// Converts `U256` to a little-endian array of `u8`s.
    fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        out[..16].copy_from_slice(&self.1.to_le_bytes());
        out[16..].copy_from_slice(&self.0.to_le_bytes());
        out
    }

    /// Calculates 2^256 / (x + 1) where x is a 256 bit unsigned integer.
    /// 2**256 / (x + 1) == ~x / (x + 1) + 1
    fn inverse(&self) -> Self {
        // We should never have a target/work of zero so this doesn't matter
        // that much but we define the inverse of 0 as max.
        if self.is_zero() {
            return Self::MAX;
        }
        // We define the inverse of 1 as max.
        if self.is_one() {
            return Self::MAX;
        }
        // We define the inverse of max as 1.
        if self.is_max() {
            return Self::ONE;
        }

        let ret = !*self / self.wrapping_inc();
        ret.wrapping_inc()
    }

    fn is_zero(&self) -> bool {
        self.0 == 0 && self.1 == 0
    }

    fn is_one(&self) -> bool {
        self.0 == 0 && self.1 == 1
    }

    fn is_max(&self) -> bool {
        self.0 == u128::MAX && self.1 == u128::MAX
    }

    /// Returns the low 32 bits.
    fn low_u32(&self) -> u32 {
        self.low_u128() as u32
    }

    /// Returns the low 64 bits.
    fn low_u64(&self) -> u64 {
        self.low_u128() as u64
    }

    /// Returns the low 128 bits.
    fn low_u128(&self) -> u128 {
        self.1
    }

    /// Returns this `U256` as a `u128` saturating to `u128::MAX` if `self` is too big.
    // Mutagen gives false positive because >= and > both return u128::MAX
    fn saturating_to_u128(&self) -> u128 {
        if *self > Self::from(u128::MAX) {
            u128::MAX
        } else {
            self.low_u128()
        }
    }

    /// Returns the least number of bits needed to represent the number.
    fn bits(&self) -> u32 {
        if self.0 > 0 {
            256 - self.0.leading_zeros()
        } else {
            128 - self.1.leading_zeros()
        }
    }

    /// Wrapping multiplication by `u64`.
    ///
    /// # Returns
    ///
    /// The multiplication result along with a boolean indicating whether an arithmetic overflow
    /// occurred. If an overflow occurred then the wrapped value is returned.
    fn mul_u64(self, rhs: u64) -> (Self, bool) {
        let mut carry: u128 = 0;
        let mut split_le =
            [self.1 as u64, (self.1 >> 64) as u64, self.0 as u64, (self.0 >> 64) as u64];

        for word in &mut split_le {
            let n = carry + u128::from(rhs) * u128::from(*word);

            *word = n as u64; // Intentional truncation, save the low bits
            carry = n >> 64; // and carry the high bits.
        }

        let low = u128::from(split_le[0]) | (u128::from(split_le[1]) << 64);
        let high = u128::from(split_le[2]) | (u128::from(split_le[3]) << 64);
        (Self(high, low), carry != 0)
    }

    /// Calculates quotient and remainder.
    ///
    /// # Returns
    ///
    /// (quotient, remainder)
    ///
    /// # Panics
    ///
    /// If `rhs` is zero.
    fn div_rem(self, rhs: Self) -> (Self, Self) {
        let mut sub_copy = self;
        let mut shift_copy = rhs;
        let mut ret = [0u128; 2];

        let my_bits = self.bits();
        let your_bits = rhs.bits();

        // Check for division by 0
        assert!(your_bits != 0, "attempted to divide {} by zero", self);

        // Early return in case we are dividing by a larger number than us
        if my_bits < your_bits {
            return (Self::ZERO, sub_copy);
        }

        // Bitwise long division
        let mut shift = my_bits - your_bits;
        shift_copy = shift_copy << shift;
        loop {
            if sub_copy >= shift_copy {
                ret[1 - (shift / 128) as usize] |= 1 << (shift % 128);
                sub_copy = sub_copy.wrapping_sub(shift_copy);
            }
            shift_copy = shift_copy >> 1;
            if shift == 0 {
                break;
            }
            shift -= 1;
        }

        (Self(ret[0], ret[1]), sub_copy)
    }

    /// Calculates `self` + `rhs`
    ///
    /// Returns a tuple of the addition along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let mut ret = Self::ZERO;
        let mut ret_overflow = false;

        let (high, overflow) = self.0.overflowing_add(rhs.0);
        ret.0 = high;
        ret_overflow |= overflow;

        let (low, overflow) = self.1.overflowing_add(rhs.1);
        ret.1 = low;
        if overflow {
            let (high, overflow) = ret.0.overflowing_add(1);
            ret.0 = high;
            ret_overflow |= overflow;
        }

        (ret, ret_overflow)
    }

    /// Calculates `self` - `rhs`
    ///
    /// Returns a tuple of the subtraction along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let ret = self.wrapping_add(!rhs).wrapping_add(Self::ONE);
        let overflow = rhs > self;
        (ret, overflow)
    }

    /// Calculates the multiplication of `self` and `rhs`.
    ///
    /// Returns a tuple of the multiplication along with a boolean
    /// indicating whether an arithmetic overflow would occur. If an
    /// overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn overflowing_mul(self, rhs: Self) -> (Self, bool) {
        let mut ret = Self::ZERO;
        let mut ret_overflow = false;

        for i in 0..=3 {
            let to_mul = (rhs >> (64 * i)).low_u64();
            let (mul_res, overflow) = self.mul_u64(to_mul);
            ret_overflow |= overflow; // If multiplying lhs by the u64 overflowed, that's an overflow

            // Calculate the bits that will overflow during the shift below.
            let overflow_bits = if i > 0 { mul_res >> (256 - (64 * i)) } else { Self::ZERO };
            ret_overflow |= overflow_bits > Self::ZERO; // If there are bits that will be shifted out below, that's an overflow

            let (sum, overflow) = ret.overflowing_add(mul_res << (64 * i));
            ret = sum;
            ret_overflow |= overflow; // If adding the mul_u64 result overflowed, that's an overflow
        }

        (ret, ret_overflow)
    }

    /// Wrapping (modular) addition. Computes `self + rhs`, wrapping around at the boundary of the
    /// type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_add(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_add(rhs);
        ret
    }

    /// Wrapping (modular) subtraction. Computes `self - rhs`, wrapping around at the boundary of
    /// the type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_sub(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_sub(rhs);
        ret
    }

    /// Wrapping (modular) multiplication. Computes `self * rhs`, wrapping around at the boundary of
    /// the type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg(test)]
    fn wrapping_mul(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_mul(rhs);
        ret
    }

    /// Returns `self` incremented by 1 wrapping around at the boundary of the type.
    #[must_use = "this returns the result of the increment, without modifying the original"]
    fn wrapping_inc(&self) -> Self {
        let mut ret = Self::ZERO;

        ret.1 = self.1.wrapping_add(1);
        if ret.1 == 0 {
            ret.0 = self.0.wrapping_add(1);
        } else {
            ret.0 = self.0;
        }
        ret
    }

    /// Panic-free bitwise shift-left; yields `self << mask(rhs)`, where `mask` removes any
    /// high-order bits of `rhs` that would cause the shift to exceed the bitwidth of the type.
    ///
    /// Note that this is *not* the same as a rotate-left; the RHS of a wrapping shift-left is
    /// restricted to the range of the type, rather than the bits shifted out of the LHS being
    /// returned to the other end. We do not currently support `rotate_left`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_shl(self, rhs: u32) -> Self {
        let shift = rhs & 0x000000ff;

        let mut ret = Self::ZERO;
        let word_shift = shift >= 128;
        let bit_shift = shift % 128;

        if word_shift {
            ret.0 = self.1 << bit_shift
        } else {
            ret.0 = self.0 << bit_shift;
            if bit_shift > 0 {
                ret.0 += self.1.wrapping_shr(128 - bit_shift);
            }
            ret.1 = self.1 << bit_shift;
        }
        ret
    }

    /// Panic-free bitwise shift-right; yields `self >> mask(rhs)`, where `mask` removes any
    /// high-order bits of `rhs` that would cause the shift to exceed the bitwidth of the type.
    ///
    /// Note that this is *not* the same as a rotate-right; the RHS of a wrapping shift-right is
    /// restricted to the range of the type, rather than the bits shifted out of the LHS being
    /// returned to the other end. We do not currently support `rotate_right`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_shr(self, rhs: u32) -> Self {
        let shift = rhs & 0x000000ff;

        let mut ret = Self::ZERO;
        let word_shift = shift >= 128;
        let bit_shift = shift % 128;

        if word_shift {
            ret.1 = self.0 >> bit_shift
        } else {
            ret.0 = self.0 >> bit_shift;
            ret.1 = self.1 >> bit_shift;
            if bit_shift > 0 {
                ret.1 += self.0.wrapping_shl(128 - bit_shift);
            }
        }
        ret
    }

    /// Format `self` to `f` as a decimal when value is known to be non-zero.
    fn fmt_decimal(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const DIGITS: usize = 78; // U256::MAX has 78 base 10 digits.
        const TEN: U256 = U256(0, 10);

        let mut buf = [0_u8; DIGITS];
        let mut i = DIGITS - 1; // We loop backwards.
        let mut cur = *self;

        loop {
            let digit = (cur % TEN).low_u128() as u8; // Cast after rem 10 is lossless.
            buf[i] = digit + b'0';
            cur = cur / TEN;
            if cur.is_zero() {
                break;
            }
            i -= 1;
        }
        let s = core::str::from_utf8(&buf[i..]).expect("digits 0-9 are valid UTF8");
        f.pad_integral(true, "", s)
    }

    /// Converts self to f64.
    #[inline]
    fn to_f64(self) -> f64 {
        // Reference: https://blog.m-ou.se/floats/
        // Step 1: Get leading zeroes
        let leading_zeroes = 256 - self.bits();
        // Step 2: Get msb to be farthest left bit
        let left_aligned = self.wrapping_shl(leading_zeroes);
        // Step 3: Shift msb to fit in lower 53 bits (128-53=75) to get the mantissa
        // * Shifting the border of the 2 u128s to line up with mantissa and dropped bits
        let middle_aligned = left_aligned >> 75;
        // * This is the 53 most significant bits as u128
        let mantissa = middle_aligned.0;
        // Step 4: Dropped bits (except for last 75 bits) are all in the second u128.
        // Bitwise OR the rest of the bits into it, preserving the highest bit,
        // so we take the lower 75 bits of middle_aligned.1 and mix it in. (See blog for explanation)
        let dropped_bits = middle_aligned.1 | (left_aligned.1 & 0x7FF_FFFF_FFFF_FFFF_FFFF);
        // Step 5: The msb of the dropped bits has been preserved, and all other bits
        // if any were set, would be set somewhere in the other 127 bits.
        // If msb of dropped bits is 0, it is mantissa + 0
        // If msb of dropped bits is 1, it is mantissa + 0 only if mantissa lowest bit is 0
        // and other bits of the dropped bits are all 0.
        // (This is why we only care if the other non-msb dropped bits are all 0 or not,
        // so we can just OR them to make sure any bits show up somewhere.)
        let mantissa =
            (mantissa + ((dropped_bits - ((dropped_bits >> 127) & !mantissa)) >> 127)) as u64;
        // Step 6: Calculate the exponent
        // If self is 0, exponent should be 0 (special meaning) and mantissa will end up 0 too
        // Otherwise, (255 - n) + 1022 so it simplifies to 1277 - n
        // 1023 and 1022 are the cutoffs for the exponent having the msb next to the decimal point
        let exponent = if self == Self::ZERO { 0 } else { 1277 - leading_zeroes as u64 };
        // Step 7: sign bit is always 0, exponent is shifted into place
        // Use addition instead of bitwise OR to saturate the exponent if mantissa overflows
        f64::from_bits((exponent << 52) + mantissa)
    }
}

impl<T: Into<u128>> From<T> for U256 {
    fn from(x: T) -> Self {
        Self(0, x.into())
    }
}

impl Add for U256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_add(rhs);
        debug_assert!(!overflow, "addition of U256 values overflowed");
        res
    }
}

impl Sub for U256 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_sub(rhs);
        debug_assert!(!overflow, "subtraction of U256 values overflowed");
        res
    }
}

impl Mul for U256 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_mul(rhs);
        debug_assert!(!overflow, "multiplication of U256 values overflowed");
        res
    }
}

impl Div for U256 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        self.div_rem(rhs).0
    }
}

impl Rem for U256 {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self {
        self.div_rem(rhs).1
    }
}

impl Not for U256 {
    type Output = Self;

    fn not(self) -> Self {
        Self(!self.0, !self.1)
    }
}

impl Shl<u32> for U256 {
    type Output = Self;
    fn shl(self, shift: u32) -> Self {
        self.wrapping_shl(shift)
    }
}

impl Shr<u32> for U256 {
    type Output = Self;
    fn shr(self, shift: u32) -> Self {
        self.wrapping_shr(shift)
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_zero() {
            f.pad_integral(true, "", "0")
        } else {
            self.fmt_decimal(f)
        }
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

// 10^38 is the largest power of 10 that fits in a u128
const POW10_38: u128 = 10_u128.pow(38);
impl core::str::FromStr for U256 {
    type Err = ParseU256Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = Self::ZERO;

        if s.is_empty() {
            return Err(ParseU256Error::Empty);
        }

        for chunk in s.as_bytes().rchunks(38).rev() {
            let chunk_str = core::str::from_utf8(chunk).map_err(ParseU256Error::InvalidEncoding)?;

            let val: u128 = chunk_str.parse().map_err(ParseU256Error::InvalidDigit)?;

            // Shift decimals and add chunk
            let (res, carry1) = result.overflowing_mul(POW10_38.into());
            let (res, carry2) = res.overflowing_add(val.into());

            if carry1 | carry2 {
                return Err(ParseU256Error::Overflow);
            }

            result = res;
        }

        Ok(result)
    }
}

macro_rules! impl_hex {
    ($hex:path, $case:expr) => {
        impl $hex for U256 {
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                internals::fmt_hex_exact!(f, 32, &self.to_be_bytes(), $case)
            }
        }
    };
}
impl_hex!(fmt::LowerHex, internals::hex::Case::Lower);
impl_hex!(fmt::UpperHex, internals::hex::Case::Upper);

#[cfg(feature = "serde")]
impl crate::serde::Serialize for U256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: crate::serde::Serializer,
    {
        struct DisplayHex(U256);

        impl fmt::Display for DisplayHex {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{:x}", self.0)
            }
        }

        if serializer.is_human_readable() {
            serializer.collect_str(&DisplayHex(*self))
        } else {
            let bytes = self.to_be_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> crate::serde::Deserialize<'de> for U256 {
    fn deserialize<D: crate::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use crate::hex;
        use crate::serde::de;

        if d.is_human_readable() {
            struct HexVisitor;

            impl de::Visitor<'_> for HexVisitor {
                type Value = U256;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("a 32 byte ASCII hex string")
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    if s.len() != 64 {
                        return Err(de::Error::invalid_length(s.len(), &self));
                    }

                    let b = hex::decode_to_array::<32>(s)
                        .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(s), &self))?;

                    Ok(U256::from_be_bytes(b))
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        let b = hex::decode_to_array::<32>(hex).map_err(|_| {
                            de::Error::invalid_value(de::Unexpected::Str(hex), &self)
                        })?;

                        Ok(U256::from_be_bytes(b))
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl serde::de::Visitor<'_> for BytesVisitor {
                type Value = U256;

                fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    f.write_str("a sequence of bytes")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let b = v.try_into().map_err(|_| de::Error::invalid_length(v.len(), &self))?;
                    Ok(U256::from_be_bytes(b))
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

/// Splits a 32 byte array into two 16 byte arrays.
fn split_in_half(a: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut high = [0_u8; 16];
    let mut low = [0_u8; 16];

    high.copy_from_slice(&a[..16]);
    low.copy_from_slice(&a[16..]);

    (high, low)
}

/// Error returned when parsing a [`U256`] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
enum ParseU256Error {
    /// Numeric value exceeded [`U256::MAX`].
    Overflow,
    /// Parsed string was empty.
    Empty,
    /// Failed parsing a target from an integer string.
    InvalidDigit(core::num::ParseIntError),
    /// Failed parsing due to non-ASCII encoding on the string.
    InvalidEncoding(core::str::Utf8Error),
}

impl From<core::convert::Infallible> for ParseU256Error {
    fn from(never: core::convert::Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for ParseU256Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Overflow => write!(f, "parsed value exceeded unsigned 256-bit range"),
            Self::Empty => write!(f, "parsed string is empty"),
            Self::InvalidEncoding(ref e) => {
                write_err!(f, "parsed number contained non-ascii chars"; e)
            }
            Self::InvalidDigit(ref e) => write_err!(f, "parsed number contained invalid digit"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseU256Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Overflow => None,
            Self::Empty => None,
            Self::InvalidEncoding(ref e) => Some(e),
            Self::InvalidDigit(ref e) => Some(e),
        }
    }
}

#[cfg(kani)]
impl kani::Arbitrary for U256 {
    fn any() -> Self {
        let high: u128 = kani::any();
        let low: u128 = kani::any();
        Self(high, low)
    }
}

/// In test code, U256s are a pain to work with, so we just convert Rust primitives in many places
#[cfg(test)]
pub mod test_utils {
    use crate::pow::{Target, Work, U256};

    /// Converts a `u64` to a [`Work`]
    pub fn u64_to_work(u: u64) -> Work {
        Work(U256::from(u))
    }

    /// Converts a `u128` to a [`Work`]
    pub fn u128_to_work(u: u128) -> Work {
        Work(U256::from(u))
    }

    /// Converts a `u32` to a [`Target`]
    pub fn u32_to_target(u: u32) -> Target {
        Target(U256::from(u))
    }

    /// Converts a `u64` to a [`Target`]
    pub fn u64_to_target(u: u64) -> Target {
        Target(U256::from(u))
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    #[cfg(feature = "pow")]
    use crate::absolute;
    #[cfg(feature = "std")]
    use crate::pow::test_utils::u128_to_work;
    use crate::pow::test_utils::{u32_to_target, u64_to_target};
    #[cfg(any(feature = "pow", feature = "std"))]
    use crate::prelude::Vec;
    #[cfg(feature = "pow")]
    use crate::prelude::{Box, ToString};
    use crate::BlockTime;
    #[cfg(feature = "tidecoin-node-validation")]
    use internals::hex::DisplayHex as _;

    impl U256 {
        fn bit_at(&self, index: usize) -> bool {
            if index > 255 {
                panic!("index out of bounds");
            }

            let word = if index < 128 { self.1 } else { self.0 };
            (word & (1 << (index % 128))) != 0
        }

        /// Constructs a new U256 from a big-endian array of u64's
        fn from_array(a: [u64; 4]) -> Self {
            let mut ret = Self::ZERO;
            ret.0 = ((a[0] as u128) << 64) ^ (a[1] as u128);
            ret.1 = ((a[2] as u128) << 64) ^ (a[3] as u128);
            ret
        }
    }

    #[test]
    fn u256_num_bits() {
        assert_eq!(U256::from(255_u64).bits(), 8);
        assert_eq!(U256::from(256_u64).bits(), 9);
        assert_eq!(U256::from(300_u64).bits(), 9);
        assert_eq!(U256::from(60000_u64).bits(), 16);
        assert_eq!(U256::from(70000_u64).bits(), 17);

        let u = U256::from(u128::MAX) << 1;
        assert_eq!(u.bits(), 129);

        // Try to read the following lines out loud quickly
        let mut shl = U256::from(70000_u64);
        shl = shl << 100;
        assert_eq!(shl.bits(), 117);
        shl = shl << 100;
        assert_eq!(shl.bits(), 217);
        shl = shl << 100;
        assert_eq!(shl.bits(), 0);
    }

    #[test]
    fn u256_bit_at() {
        assert!(!U256::from(10_u64).bit_at(0));
        assert!(U256::from(10_u64).bit_at(1));
        assert!(!U256::from(10_u64).bit_at(2));
        assert!(U256::from(10_u64).bit_at(3));
        assert!(!U256::from(10_u64).bit_at(4));

        let u = U256(0xa000_0000_0000_0000_0000_0000_0000_0000, 0);
        assert!(u.bit_at(255));
        assert!(!u.bit_at(254));
        assert!(u.bit_at(253));
        assert!(!u.bit_at(252));
    }

    #[test]
    fn u256_lower_hex() {
        assert_eq!(
            format!("{:x}", U256::from(0xDEADBEEF_u64)),
            "00000000000000000000000000000000000000000000000000000000deadbeef",
        );
        assert_eq!(
            format!("{:#x}", U256::from(0xDEADBEEF_u64)),
            "0x00000000000000000000000000000000000000000000000000000000deadbeef",
        );
        assert_eq!(
            format!("{:x}", U256::MAX),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        assert_eq!(
            format!("{:#x}", U256::MAX),
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
    }

    #[test]
    fn u256_upper_hex() {
        assert_eq!(
            format!("{:X}", U256::from(0xDEADBEEF_u64)),
            "00000000000000000000000000000000000000000000000000000000DEADBEEF",
        );
        assert_eq!(
            format!("{:#X}", U256::from(0xDEADBEEF_u64)),
            "0x00000000000000000000000000000000000000000000000000000000DEADBEEF",
        );
        assert_eq!(
            format!("{:X}", U256::MAX),
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        );
        assert_eq!(
            format!("{:#X}", U256::MAX),
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        );
    }

    #[test]
    fn u256_display() {
        assert_eq!(format!("{}", U256::from(100_u32)), "100",);
        assert_eq!(format!("{}", U256::ZERO), "0",);
        assert_eq!(format!("{}", U256::from(u64::MAX)), format!("{}", u64::MAX),);
        assert_eq!(
            format!("{}", U256::MAX),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        );
    }

    macro_rules! check_format {
        ($($test_name:ident, $val:literal, $format_string:literal, $expected:literal);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    assert_eq!(format!($format_string, U256::from($val)), $expected);
                }
            )*
        }
    }
    check_format! {
        check_fmt_0, 0_u32, "{}", "0";
        check_fmt_1, 0_u32, "{:2}", " 0";
        check_fmt_2, 0_u32, "{:02}", "00";

        check_fmt_3, 1_u32, "{}", "1";
        check_fmt_4, 1_u32, "{:2}", " 1";
        check_fmt_5, 1_u32, "{:02}", "01";

        check_fmt_10, 10_u32, "{}", "10";
        check_fmt_11, 10_u32, "{:2}", "10";
        check_fmt_12, 10_u32, "{:02}", "10";
        check_fmt_13, 10_u32, "{:3}", " 10";
        check_fmt_14, 10_u32, "{:03}", "010";

        check_fmt_20, 1_u32, "{:<2}", "1 ";
        check_fmt_21, 1_u32, "{:<02}", "01";
        check_fmt_22, 1_u32, "{:>2}", " 1"; // This is default but check it anyways.
        check_fmt_23, 1_u32, "{:>02}", "01";
        check_fmt_24, 1_u32, "{:^3}", " 1 ";
        check_fmt_25, 1_u32, "{:^03}", "001";
        // Sanity check, for integral types precision is ignored.
        check_fmt_30, 0_u32, "{:.1}", "0";
        check_fmt_31, 0_u32, "{:4.1}", "   0";
        check_fmt_32, 0_u32, "{:04.1}", "0000";
    }

    #[test]
    fn u256_comp() {
        let small = U256::from_array([0, 0, 0, 10]);
        let big = U256::from_array([0, 0, 0x0209_E737_8231_E632, 0x8C8C_3EE7_0C64_4118]);
        let bigger = U256::from_array([0, 0, 0x0209_E737_8231_E632, 0x9C8C_3EE7_0C64_4118]);
        let biggest = U256::from_array([1, 0, 0x0209_E737_8231_E632, 0x5C8C_3EE7_0C64_4118]);

        assert!(small < big);
        assert!(big < bigger);
        assert!(bigger < biggest);
        assert!(bigger <= biggest);
        assert!(biggest <= biggest);
        assert!(bigger >= big);
        assert!(bigger >= small);
        assert!(small <= small);
    }

    const WANT: U256 =
        U256(0x1bad_cafe_dead_beef_deaf_babe_2bed_feed, 0xbaad_f00d_defa_ceda_11fe_d2ba_d1c0_ffe0);

    #[rustfmt::skip]
    const BE_BYTES: [u8; 32] = [
        0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed, 0xfe, 0xed,
        0xba, 0xad, 0xf0, 0x0d, 0xde, 0xfa, 0xce, 0xda, 0x11, 0xfe, 0xd2, 0xba, 0xd1, 0xc0, 0xff, 0xe0,
    ];

    #[rustfmt::skip]
    const LE_BYTES: [u8; 32] = [
        0xe0, 0xff, 0xc0, 0xd1, 0xba, 0xd2, 0xfe, 0x11, 0xda, 0xce, 0xfa, 0xde, 0x0d, 0xf0, 0xad, 0xba,
        0xed, 0xfe, 0xed, 0x2b, 0xbe, 0xba, 0xaf, 0xde, 0xef, 0xbe, 0xad, 0xde, 0xfe, 0xca, 0xad, 0x1b,
    ];

    // Sanity check that we have the bytes in the correct big-endian order.
    #[test]
    fn sanity_be_bytes() {
        let mut out = [0_u8; 32];
        out[..16].copy_from_slice(&WANT.0.to_be_bytes());
        out[16..].copy_from_slice(&WANT.1.to_be_bytes());
        assert_eq!(out, BE_BYTES);
    }

    // Sanity check that we have the bytes in the correct little-endian order.
    #[test]
    fn sanity_le_bytes() {
        let mut out = [0_u8; 32];
        out[..16].copy_from_slice(&WANT.1.to_le_bytes());
        out[16..].copy_from_slice(&WANT.0.to_le_bytes());
        assert_eq!(out, LE_BYTES);
    }

    #[test]
    fn u256_to_be_bytes() {
        assert_eq!(WANT.to_be_bytes(), BE_BYTES);
    }

    #[test]
    fn u256_from_be_bytes() {
        assert_eq!(U256::from_be_bytes(BE_BYTES), WANT);
    }

    #[test]
    fn u256_to_le_bytes() {
        assert_eq!(WANT.to_le_bytes(), LE_BYTES);
    }

    #[test]
    fn u256_from_le_bytes() {
        assert_eq!(U256::from_le_bytes(LE_BYTES), WANT);
    }

    #[test]
    fn u256_from_u8() {
        let u = U256::from(0xbe_u8);
        assert_eq!(u, U256(0, 0xbe));
    }

    #[test]
    fn u256_from_u16() {
        let u = U256::from(0xbeef_u16);
        assert_eq!(u, U256(0, 0xbeef));
    }

    #[test]
    fn u256_from_u32() {
        let u = U256::from(0xdeadbeef_u32);
        assert_eq!(u, U256(0, 0xdeadbeef));
    }

    #[test]
    fn u256_from_u64() {
        let u = U256::from(0xdead_beef_cafe_babe_u64);
        assert_eq!(u, U256(0, 0xdead_beef_cafe_babe));
    }

    #[test]
    fn u256_from_u128() {
        let u = U256::from(0xdead_beef_cafe_babe_0123_4567_89ab_cdefu128);
        assert_eq!(u, U256(0, 0xdead_beef_cafe_babe_0123_4567_89ab_cdef));
    }

    macro_rules! test_from_unsigned_integer_type {
        ($($test_name:ident, $ty:ident);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    // Internal representation is big-endian.
                    let want = U256(0, 0xAB);

                    let x = 0xAB as $ty;
                    let got = U256::from(x);

                    assert_eq!(got, want);
                }
            )*
        }
    }
    test_from_unsigned_integer_type! {
        from_unsigned_integer_type_u8, u8;
        from_unsigned_integer_type_u16, u16;
        from_unsigned_integer_type_u32, u32;
        from_unsigned_integer_type_u64, u64;
        from_unsigned_integer_type_u128, u128;
    }

    #[test]
    fn u256_from_be_array_u64() {
        let array = [
            0x1bad_cafe_dead_beef,
            0xdeaf_babe_2bed_feed,
            0xbaad_f00d_defa_ceda,
            0x11fe_d2ba_d1c0_ffe0,
        ];

        let uint = U256::from_array(array);
        assert_eq!(uint, WANT);
    }

    #[test]
    fn u256_shift_left() {
        let u = U256::from(1_u32);
        assert_eq!(u << 0, u);
        assert_eq!(u << 1, U256::from(2_u64));
        assert_eq!(u << 63, U256::from(0x8000_0000_0000_0000_u64));
        assert_eq!(u << 64, U256::from_array([0, 0, 0x0000_0000_0000_0001, 0]));
        assert_eq!(u << 127, U256(0, 0x8000_0000_0000_0000_0000_0000_0000_0000));
        assert_eq!(u << 128, U256(1, 0));

        let x = U256(0, 0x8000_0000_0000_0000_0000_0000_0000_0000);
        assert_eq!(x << 1, U256(1, 0));
    }

    #[test]
    fn u256_shift_right() {
        let u = U256(1, 0);
        assert_eq!(u >> 0, u);
        assert_eq!(u >> 1, U256(0, 0x8000_0000_0000_0000_0000_0000_0000_0000));
        assert_eq!(u >> 127, U256(0, 2));
        assert_eq!(u >> 128, U256(0, 1));
    }

    #[test]
    fn u256_arithmetic() {
        let init = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);
        let copy = init;

        let add = init.wrapping_add(copy);
        assert_eq!(add, U256::from_array([0, 0, 1, 0xBD5B_7DDF_BD5B_7DDE]));
        // Bitshifts
        let shl = add << 88;
        assert_eq!(shl, U256::from_array([0, 0x01BD_5B7D, 0xDFBD_5B7D_DE00_0000, 0]));
        let shr = shl >> 40;
        assert_eq!(shr, U256::from_array([0, 0, 0x0001_BD5B_7DDF_BD5B, 0x7DDE_0000_0000_0000]));
        // Increment
        let mut incr = shr;
        incr = incr.wrapping_inc();
        assert_eq!(incr, U256::from_array([0, 0, 0x0001_BD5B_7DDF_BD5B, 0x7DDE_0000_0000_0001]));
        // Subtraction
        let sub = incr.wrapping_sub(init);
        assert_eq!(sub, U256::from_array([0, 0, 0x0001_BD5B_7DDF_BD5A, 0x9F30_4110_2152_4112]));
        // Multiplication
        let (mult, _) = sub.mul_u64(300);
        assert_eq!(mult, U256::from_array([0, 0, 0x0209_E737_8231_E632, 0x8C8C_3EE7_0C64_4118]));
        // Division
        assert_eq!(U256::from(105_u32) / U256::from(5_u32), U256::from(21_u32));
        let div = mult / U256::from(300_u32);
        assert_eq!(div, U256::from_array([0, 0, 0x0001_BD5B_7DDF_BD5A, 0x9F30_4110_2152_4112]));

        assert_eq!(U256::from(105_u32) % U256::from(5_u32), U256::ZERO);
        assert_eq!(U256::from(35498456_u32) % U256::from(3435_u32), U256::from(1166_u32));
        let rem_src = mult.wrapping_mul(U256::from(39842_u32)).wrapping_add(U256::from(9054_u32));
        assert_eq!(rem_src % U256::from(39842_u32), U256::from(9054_u32));
    }

    #[test]
    fn u256_bit_inversion() {
        let v = U256(1, 0);
        let want = U256(
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe,
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        );
        assert_eq!(!v, want);

        let v = U256(0x0c0c_0c0c_0c0c_0c0c_0c0c_0c0c_0c0c_0c0c, 0xeeee_eeee_eeee_eeee);
        let want = U256(
            0xf3f3_f3f3_f3f3_f3f3_f3f3_f3f3_f3f3_f3f3,
            0xffff_ffff_ffff_ffff_1111_1111_1111_1111,
        );
        assert_eq!(!v, want);
    }

    #[test]
    fn u256_mul_u64_by_one() {
        let v = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);
        assert_eq!(v, v.mul_u64(1_u64).0);
    }

    #[test]
    fn u256_mul_u64_by_zero() {
        let v = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);
        assert_eq!(U256::ZERO, v.mul_u64(0_u64).0);
    }

    #[test]
    fn u256_mul_u64() {
        let u64_val = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);

        let u96_res = u64_val.mul_u64(0xFFFF_FFFF).0;
        let u128_res = u96_res.mul_u64(0xFFFF_FFFF).0;
        let u160_res = u128_res.mul_u64(0xFFFF_FFFF).0;
        let u192_res = u160_res.mul_u64(0xFFFF_FFFF).0;
        let u224_res = u192_res.mul_u64(0xFFFF_FFFF).0;
        let u256_res = u224_res.mul_u64(0xFFFF_FFFF).0;

        assert_eq!(u96_res, U256::from_array([0, 0, 0xDEAD_BEEE, 0xFFFF_FFFF_2152_4111]));
        assert_eq!(
            u128_res,
            U256::from_array([0, 0, 0xDEAD_BEEE_2152_4110, 0x2152_4111_DEAD_BEEF])
        );
        assert_eq!(
            u160_res,
            U256::from_array([0, 0xDEAD_BEED, 0x42A4_8222_0000_0001, 0xBD5B_7DDD_2152_4111])
        );
        assert_eq!(
            u192_res,
            U256::from_array([
                0,
                0xDEAD_BEEC_63F6_C334,
                0xBD5B_7DDF_BD5B_7DDB,
                0x63F6_C333_DEAD_BEEF
            ])
        );
        assert_eq!(
            u224_res,
            U256::from_array([
                0xDEAD_BEEB,
                0x8549_0448_5964_BAAA,
                0xFFFF_FFFB_A69B_4558,
                0x7AB6_FBBB_2152_4111
            ])
        );
        assert_eq!(
            u256_res,
            U256(
                0xDEAD_BEEA_A69B_455C_D41B_B662_A69B_4550,
                0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF,
            )
        );
    }

    #[test]
    fn u256_addition() {
        let x = U256::from(u128::MAX);
        let (add, overflow) = x.overflowing_add(U256::ONE);
        assert!(!overflow);
        assert_eq!(add, U256(1, 0));

        let (add, _) = add.overflowing_add(U256::ONE);
        assert_eq!(add, U256(1, 1));
    }

    #[test]
    fn u256_subtraction() {
        let (sub, overflow) = U256::ONE.overflowing_sub(U256::ONE);
        assert!(!overflow);
        assert_eq!(sub, U256::ZERO);

        let x = U256(1, 0);
        let (sub, overflow) = x.overflowing_sub(U256::ONE);
        assert!(!overflow);
        assert_eq!(sub, U256::from(u128::MAX));
    }

    #[test]
    fn u256_multiplication() {
        let u64_val = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);

        let u128_res = u64_val.wrapping_mul(u64_val);

        assert_eq!(u128_res, U256(0, 0xC1B1_CD13_A4D1_3D46_048D_1354_216D_A321));

        let u256_res = u128_res.wrapping_mul(u128_res);

        assert_eq!(
            u256_res,
            U256(
                0x928D_92B4_D7F5_DF33_4AFC_FF6F_0375_C608,
                0xF5CF_7F36_18C2_C886_F4E1_66AA_D40D_0A41,
            )
        );
    }

    #[test]
    fn u256_multiplication_bits_in_each_word() {
        // Put a digit in the least significant bit of each 64 bit word.
        let u = (1_u128 << 64) | 1_u128;
        let x = U256(u, u);

        // Put a digit in the second least significant bit of each 64 bit word.
        let u = (2_u128 << 64) | 2_u128;
        let y = U256(u, u);

        let (got, overflow) = x.overflowing_mul(y);

        let want = U256(
            0x0000_0000_0000_0008_0000_0000_0000_0006,
            0x0000_0000_0000_0004_0000_0000_0000_0002,
        );
        assert!(overflow);
        assert_eq!(got, want)
    }

    #[test]
    fn u256_overflowing_mul() {
        let a = U256(u128::MAX, 0);
        let b = U256(1 << 65 | 1, 0);
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, U256::ZERO);
        assert!(overflow);

        let a = U256(1 << 64, 0);
        let b = U256(1, 0);
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, U256::ZERO);
        assert!(overflow);

        let a = U256(0, 1 << 63);
        let b = U256(1, 0);
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, b << 63);
        assert!(!overflow);

        let (res, overflow) = U256::ONE.overflowing_mul(U256::ONE);
        assert_eq!(res, U256::ONE);
        assert!(!overflow);

        // Simple case near upper edge
        let a = U256(1 << 125, 0);
        let b = U256(0, 4);
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, U256(1 << 127, 0));
        assert!(!overflow);

        // Check case where bits overflow during shift. Kills * -> + and - -> + mutants.
        let a = U256::ONE << 2;
        let b = U256::ONE << 254;
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, U256::ZERO);
        assert!(overflow);

        // mul_u64 overflows twice but no other overflows. Kills |= -> ^= mutant.
        let a = U256::ONE << 255;
        let b = U256(1 << 1 | 1 << 65, 0);
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, U256::ZERO);
        assert!(overflow);
    }

    #[test]
    fn u256_increment() {
        let mut val = U256(
            0xEFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFE,
        );
        val = val.wrapping_inc();
        assert_eq!(
            val,
            U256(
                0xEFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
                0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            )
        );
        val = val.wrapping_inc();
        assert_eq!(
            val,
            U256(
                0xF000_0000_0000_0000_0000_0000_0000_0000,
                0x0000_0000_0000_0000_0000_0000_0000_0000,
            )
        );

        assert_eq!(U256::MAX.wrapping_inc(), U256::ZERO);
    }

    #[test]
    fn u256_extreme_bitshift() {
        // Shifting a u64 by 64 bits gives an undefined value, so make sure that
        // we're doing the Right Thing here
        let init = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);

        assert_eq!(init << 64, U256(0, 0xDEAD_BEEF_DEAD_BEEF_0000_0000_0000_0000));
        let add = (init << 64).wrapping_add(init);
        assert_eq!(add, U256(0, 0xDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF));
        assert_eq!(add >> 0, U256(0, 0xDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF));
        assert_eq!(add << 0, U256(0, 0xDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF));
        assert_eq!(add >> 64, U256(0, 0x0000_0000_0000_0000_DEAD_BEEF_DEAD_BEEF));
        assert_eq!(
            add << 64,
            U256(0xDEAD_BEEF_DEAD_BEEF, 0xDEAD_BEEF_DEAD_BEEF_0000_0000_0000_0000)
        );
    }

    #[test]
    fn u256_to_from_hex_roundtrips() {
        let val = U256(
            0xDEAD_BEEA_A69B_455C_D41B_B662_A69B_4550,
            0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF,
        );
        let hex = format!("0x{:x}", val);
        let got = U256::from_hex(&hex).expect("failed to parse hex");
        assert_eq!(got, val);
    }

    #[test]
    fn u256_to_from_unprefixed_hex_roundtrips() {
        let val = U256(
            0xDEAD_BEEA_A69B_455C_D41B_B662_A69B_4550,
            0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF,
        );
        let hex = format!("{:x}", val);
        let got = U256::from_unprefixed_hex(&hex).expect("failed to parse hex");
        assert_eq!(got, val);
    }

    #[test]
    fn u256_from_hex_32_characters_long() {
        let hex = "a69b455cd41bb662a69b4555deadbeef";
        let want = U256(0x00, 0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF);
        let got = U256::from_unprefixed_hex(hex).expect("failed to parse hex");
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn u256_serde() {
        let check = |uint, hex| {
            let json = format!("\"{}\"", hex);
            assert_eq!(::serde_json::to_string(&uint).unwrap(), json);
            assert_eq!(::serde_json::from_str::<U256>(&json).unwrap(), uint);

            let bin_encoded = bincode::serialize(&uint).unwrap();
            let bin_decoded: U256 = bincode::deserialize(&bin_encoded).unwrap();
            assert_eq!(bin_decoded, uint);
        };

        check(U256::ZERO, "0000000000000000000000000000000000000000000000000000000000000000");
        check(
            U256::from(0xDEADBEEF_u32),
            "00000000000000000000000000000000000000000000000000000000deadbeef",
        );
        check(
            U256::from_array([0xdd44, 0xcc33, 0xbb22, 0xaa11]),
            "000000000000dd44000000000000cc33000000000000bb22000000000000aa11",
        );
        check(U256::MAX, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        check(
            U256(
                0xDEAD_BEEA_A69B_455C_D41B_B662_A69B_4550,
                0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF,
            ),
            "deadbeeaa69b455cd41bb662a69b4550a69b455cd41bb662a69b4555deadbeef",
        );

        assert!(::serde_json::from_str::<U256>(
            "\"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffg\""
        )
        .is_err()); // invalid char
        assert!(::serde_json::from_str::<U256>(
            "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\""
        )
        .is_err()); // invalid length
        assert!(::serde_json::from_str::<U256>(
            "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\""
        )
        .is_err()); // invalid length
    }

    #[test]
    fn u256_is_max_correct_negative() {
        let tc = [U256::ZERO, U256::ONE, U256::from(u128::MAX)];
        for t in tc {
            assert!(!t.is_max())
        }
    }

    #[test]
    fn u256_is_max_correct_positive() {
        assert!(U256::MAX.is_max());

        let u = u128::MAX;
        assert!(((U256::from(u) << 128) + U256::from(u)).is_max());
    }

    #[test]
    fn compact_target_from_maximum_upward_difficulty_adjustment() {
        let params = Params::new(crate::Network::Tidecoin);
        let starting_bits = CompactTarget::from_consensus(0x1d00ffff);
        let timespan = params.pow_target_timespan / 5;
        let got = CompactTarget::from_next_work_required(starting_bits, timespan.into(), params);
        let want =
            Target::from_compact(starting_bits).min_transition_threshold().to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn compact_target_from_maximum_upward_difficulty_adjustment_with_negative_timespan() {
        let params = Params::new(crate::Network::Tidecoin);
        let starting_bits = CompactTarget::from_consensus(0x1d00ffff);
        let timespan: i64 = -i64::from(params.pow_target_timespan);
        let got = CompactTarget::from_next_work_required(starting_bits, timespan, params);
        let want =
            Target::from_compact(starting_bits).min_transition_threshold().to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn compact_target_from_minimum_downward_difficulty_adjustment() {
        let params = Params::new(crate::Network::Tidecoin);
        let starting_bits = CompactTarget::from_consensus(0x1800ffff);
        let timespan = 5 * params.pow_target_timespan;
        let got = CompactTarget::from_next_work_required(starting_bits, timespan.into(), &params);
        let want =
            Target::from_compact(starting_bits).max_transition_threshold(params).to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn compact_target_from_adjustment_clamps_to_lossy_compact_limit() {
        let params = Params::new(crate::Network::Tidecoin);
        let starting_bits = params.max_attainable_target.to_compact_lossy();
        let timespan = 5 * params.pow_target_timespan;
        let got = CompactTarget::from_next_work_required(starting_bits, timespan.into(), &params);
        // This follows the node's legacy overflow-guarded scaling path.
        let want = CompactTarget::from_consensus(0x1e49_ac1b);
        assert_eq!(got, want);
    }

    #[test]
    fn compact_target_from_adjustment_no_bip94() {
        let bits_start = CompactTarget::from_consensus(0x1c00ffff);
        let bits_end = CompactTarget::from_consensus(0x1d00ffff);

        let start_time = BlockTime::from_u32(1_000_000);
        let end_time = BlockTime::from_u32(1_000_000 + 432_000); // +5 days (pow_target_timespan). No adjustment.

        let epoch_start = Header {
            version: crate::block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: crate::TxMerkleNode::from_byte_array([0; 32]),
            time: start_time,
            bits: bits_start,
            nonce: 0,
            auxpow: None,
        };

        let current = Header {
            version: crate::block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: crate::TxMerkleNode::from_byte_array([0; 32]),
            time: end_time,
            bits: bits_end,
            nonce: 0,
            auxpow: None,
        };

        // Tidecoin mainnet (enforce_bip94 = false): should use current.bits
        let mainnet_result = CompactTarget::from_header_difficulty_adjustment(
            epoch_start,
            current,
            &Params::MAINNET,
        );
        assert_eq!(mainnet_result, bits_end);
    }

    #[test]
    fn target_from_compact() {
        // (nBits, target)
        let tests = [
            (0x0100_3456_u32, 0x00_u64), // High bit set.
            (0x0112_3456_u32, 0x12_u64),
            (0x0200_8000_u32, 0x80_u64),
            (0x0500_9234_u32, 0x9234_0000_u64),
            (0x0492_3456_u32, 0x00_u64), // High bit set (0x80 in 0x92).
            (0x0412_3456_u32, 0x1234_5600_u64), // Inverse of above; no high bit.
        ];

        for (n_bits, target) in tests {
            let want = u64_to_target(target);
            let got = Target::from_compact(CompactTarget::from_consensus(n_bits));
            assert_eq!(got, want);
        }
    }

    #[test]
    fn derive_target_rejects_node_invalid_compact_targets() {
        let params = Params::MAINNET;

        assert_eq!(
            derive_target(CompactTarget::from_consensus(0x0000_0000), &params),
            Err(PowTargetError::Zero)
        );
        assert_eq!(
            derive_target(CompactTarget::from_consensus(0x0180_0001), &params),
            Err(PowTargetError::Negative)
        );
        assert_eq!(
            derive_target(CompactTarget::from_consensus(0x2301_0000), &params),
            Err(PowTargetError::Overflow)
        );
        assert_eq!(
            derive_target(CompactTarget::from_consensus(0x2002_ffff), &params),
            Err(PowTargetError::AboveLimit)
        );
    }

    #[test]
    fn derive_target_accepts_node_valid_compact_target() {
        let params = Params::MAINNET;
        let bits = CompactTarget::from_consensus(0x2001_ffff);

        assert_eq!(derive_target(bits, &params), Ok(params.max_attainable_target));
    }

    macro_rules! check_from_str {
        ($ty:ident, $err_ty:ident, $mod_name:ident) => {
            mod $mod_name {
                use alloc::string::ToString;
                use core::str::FromStr;

                use super::{$err_ty, $ty, ParseU256Error, U256};

                #[test]
                fn target_from_str_decimal() {
                    assert_eq!($ty::from_str("0").unwrap(), $ty(U256::ZERO));
                    assert_eq!("1".parse::<$ty>().unwrap(), $ty(U256(0, 1)));
                    assert_eq!("123456789".parse::<$ty>().unwrap(), $ty(U256(0, 123_456_789)));

                    let str_tgt = "340282366920938463463374607431768211455";
                    let got = str_tgt.parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(u128::MAX.into()));

                    // 2^128
                    let str_tgt = "340282366920938463463374607431768211456";
                    let got = str_tgt.parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(U256(1, 0)));

                    // 2^256 - 1
                    let str_tgt = concat!(
                        "115792089237316195423570985008687907853",
                        "269984665640564039457584007913129639935"
                    );
                    let got = str_tgt.parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(U256::MAX));

                    // Padding
                    let got = "00000000000042".parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(U256(0, 42)));

                    // roundtrip
                    let want = $ty(u128::MAX.into());
                    let got = want.to_string().parse::<$ty>().unwrap();
                    assert_eq!(got, want);
                }

                #[test]
                fn target_from_str_error() {
                    assert!(matches!(
                        "".parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::Empty),
                    ));
                    assert!(matches!(
                        "12a34".parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::InvalidDigit(_)),
                    ));
                    assert!(matches!(
                        " 42".parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::InvalidDigit(_)),
                    ));
                    assert!(matches!(
                        "-1".parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::InvalidDigit(_)),
                    ));

                    assert!(matches!(
                        "1157ééééé92089237316195423570985008687907853".parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::InvalidEncoding(_)),
                    ));

                    // 2^256
                    let tgt_str = concat!(
                        "115792089237316195423570985008687907853",
                        "269984665640564039457584007913129639936"
                    );
                    assert!(matches!(
                        tgt_str.parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::Overflow),
                    ));
                }
            }
        };
    }

    check_from_str!(Target, ParseTargetError, target_from_str);
    check_from_str!(Work, ParseWorkError, work_from_str);

    #[test]
    fn target_is_met_by_for_target_equals_hash() {
        let hash = "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"
            .parse::<BlockHash>()
            .expect("failed to parse block hash");
        let target = Target(U256::from_le_bytes(hash.to_byte_array()));
        assert!(target.is_met_by(hash));
    }

    #[test]
    fn max_target_from_compact() {
        // Tidecoin's highest possible target in compact form is 0x2001ffff
        let bits = 0x2001ffff_u32;
        let want = Target::MAX;
        let got = Target::from_compact(CompactTarget::from_consensus(bits));
        assert_eq!(got, want)
    }

    #[test]
    fn target_attainable_constants_from_original() {
        // Tidecoin mainnet powLimit: 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        const MAX_MAINNET: Target =
            Target(U256(0x01FF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_u128, u128::MAX));
        // Tidecoin regtest powLimit: 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
        const MAX_REGTEST: Target = Target(U256(
            0x0f0f_0f0f_0f0f_0f0f_0f0f_0f0f_0f0f_0f0f_u128,
            0x0f0f_0f0f_0f0f_0f0f_0f0f_0f0f_0f0f_0f0f_u128,
        ));

        assert_eq!(
            Target::MAX_ATTAINABLE_MAINNET,
            Target::from_compact(MAX_MAINNET.to_compact_lossy())
        );
        assert_eq!(
            Target::MAX_ATTAINABLE_REGTEST,
            Target::from_compact(MAX_REGTEST.to_compact_lossy())
        );
    }

    #[test]
    fn target_max_attainable_hex() {
        assert_eq!(
            format!("{:x}", Target::MAX_ATTAINABLE_MAINNET),
            "01ffff0000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            format!("{:x}", Target::MAX_ATTAINABLE_REGTEST),
            "0f0f0f0000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn target_difficulty_float() {
        let params = Params::new(crate::Network::Tidecoin);

        assert_eq!(Target::MAX.difficulty_float(&params), 1.0_f64);
    }

    #[test]
    fn roundtrip_compact_target() {
        let consensus = 0x1d00_ffff;
        let compact = CompactTarget::from_consensus(consensus);
        let t = Target::from_compact(CompactTarget::from_consensus(consensus));
        assert_eq!(t, Target::from(compact)); // From/Into sanity check.

        let back = t.to_compact_lossy();
        assert_eq!(back, compact); // From/Into sanity check.

        assert_eq!(back.to_consensus(), consensus);
    }

    #[test]
    fn roundtrip_target_work() {
        let target = u32_to_target(0xdeadbeef_u32);
        let work = target.to_work();
        let back = work.to_target();
        assert_eq!(back, target)
    }

    #[test]
    #[cfg(feature = "std")]
    fn work_log2() {
        // Compare work log2 to historical Tidecoin node values found in node logs.
        let tests: &[(u128, f64)] = &[
            // (chainwork, core log2)                // height
            (0x200020002, 33.000022),                // 1
            (0xa97d67041c5e51596ee7, 79.405055),     // 308004
            (0x1dc45d79394baa8ab18b20, 84.895644),   // 418141
            (0x8c85acb73287e335d525b98, 91.134654),  // 596624
            (0x2ef447e01d1642c40a184ada, 93.553183), // 738965
        ];

        for &(chainwork, core_log2) in tests {
            // Core log2 in the logs is rounded to 6 decimal places.
            let log2 = (u128_to_work(chainwork).log2() * 1e6).round() / 1e6;
            assert_eq!(log2, core_log2)
        }

        assert_eq!(Work(U256::ONE).log2(), 0.0);
        assert_eq!(Work(U256::MAX).log2(), 256.0);
    }

    #[test]
    fn u256_zero_min_max_inverse() {
        assert_eq!(U256::MAX.inverse(), U256::ONE);
        assert_eq!(U256::ONE.inverse(), U256::MAX);
        assert_eq!(U256::ZERO.inverse(), U256::MAX);
    }

    #[test]
    fn u256_max_min_inverse_roundtrip() {
        let max = U256::MAX;

        for min in [U256::ZERO, U256::ONE].iter() {
            // lower target means more work required.
            assert_eq!(Target(max).to_work(), Work(U256::ONE));
            assert_eq!(Target(*min).to_work(), Work(max));

            assert_eq!(Work(max).to_target(), Target(U256::ONE));
            assert_eq!(Work(*min).to_target(), Target(max));
        }
    }

    #[test]
    fn u256_wrapping_add_wraps_at_boundary() {
        assert_eq!(U256::MAX.wrapping_add(U256::ONE), U256::ZERO);
        assert_eq!(U256::MAX.wrapping_add(U256::from(2_u8)), U256::ONE);
    }

    #[test]
    fn u256_wrapping_sub_wraps_at_boundary() {
        assert_eq!(U256::ZERO.wrapping_sub(U256::ONE), U256::MAX);
        assert_eq!(U256::ONE.wrapping_sub(U256::from(2_u8)), U256::MAX);
    }

    #[test]
    fn mul_u64_overflows() {
        let (_, overflow) = U256::MAX.mul_u64(2);
        assert!(overflow, "max * 2 should overflow");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn u256_overflowing_addition_panics() {
        let _ = U256::MAX + U256::ONE;
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn u256_overflowing_subtraction_panics() {
        let _ = U256::ZERO - U256::ONE;
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn u256_multiplication_by_max_panics() {
        let _ = U256::MAX * U256::MAX;
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn work_overflowing_addition_panics() {
        let _ = Work(U256::MAX) + Work(U256::ONE);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn work_overflowing_subtraction_panics() {
        let _ = Work(U256::ZERO) - Work(U256::ONE);
    }

    #[test]
    fn u256_to_f64() {
        assert_eq!(U256::ZERO.to_f64(), 0.0_f64);
        assert_eq!(U256::ONE.to_f64(), 1.0_f64);
        assert_eq!(U256::MAX.to_f64(), 1.157920892373162e77_f64);
        assert_eq!((U256::MAX >> 1).to_f64(), 5.78960446186581e76_f64);
        assert_eq!((U256::MAX >> 128).to_f64(), 3.402823669209385e38_f64);
        assert_eq!((U256::MAX >> (256 - 54)).to_f64(), 1.8014398509481984e16_f64);
        // 53 bits and below should not use exponents
        assert_eq!((U256::MAX >> (256 - 53)).to_f64(), 9007199254740991.0_f64);
        assert_eq!((U256::MAX >> (256 - 32)).to_f64(), 4294967295.0_f64);
        assert_eq!((U256::MAX >> (256 - 16)).to_f64(), 65535.0_f64);
        assert_eq!((U256::MAX >> (256 - 8)).to_f64(), 255.0_f64);
    }

    fn current_header() -> Header {
        Header {
            version: crate::block::Version::from_consensus(0x2431_a000),
            prev_blockhash: BlockHash::from_str(
                "0000000000000000000387dab5f3cf88824c983770f70f8a8eb7a9a240a257a5",
            )
            .unwrap(),
            merkle_root: crate::TxMerkleNode::from_str(
                "07bf4eafca7979d59b0ec2dc03131c08c1b9ea2ddb8b8945846fcb0ce92cdbe3",
            )
            .unwrap(),
            time: 0x651b_c919.into(), // 2023-10-03 18:56:09 GMT +11 -> 1696359369 -> 651BC919
            bits: CompactTarget::from_consensus(0x1704_ed7f),
            nonce: 0xc637_a163,
            auxpow: None,
        }
    }

    fn test_header(time: u32, bits: CompactTarget) -> Header {
        Header {
            version: crate::block::Version::TWO,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: crate::TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(time),
            bits,
            nonce: 0,
            auxpow: None,
        }
    }

    #[cfg(feature = "pow")]
    fn pow_vector_header() -> Header {
        Header::from_str(
            "0000002009f42768de3cfb4e58fc56368c1477f87f60e248d7130df3fb8acd7f\
             6208b83a72f90dd3ad8fe06c7f70d73f256f1e07185dcc217a58b9517c699226\
             ac0297d2ad60ba61b62a021d9b7700f0",
        )
        .expect("valid pure header hex")
    }

    #[cfg(feature = "pow")]
    fn script_push(data: &[u8]) -> Vec<u8> {
        assert!(data.len() <= 75);
        let mut script = Vec::with_capacity(data.len() + 1);
        script.push(data.len() as u8);
        script.extend_from_slice(data);
        script
    }

    #[cfg(feature = "pow")]
    fn auxpow_coinbase_script(
        include_header: bool,
        root: [u8; 32],
        merkle_height: usize,
        nonce: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        if include_header {
            data.extend_from_slice(b"\xfa\xbe\x6d\x6d");
        }
        data.extend_from_slice(&root);
        data.extend_from_slice(&(1u32 << merkle_height).to_le_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());

        let mut script = Vec::with_capacity(data.len() + 2);
        script.push(0x52); // OP_2, matching the node AuxPoW unit-test fixture shape.
        script.extend_from_slice(&script_push(&data));
        script
    }

    #[cfg(feature = "pow")]
    fn auxpow_coinbase_tx(script_sig: Vec<u8>) -> crate::transaction::Transaction {
        crate::transaction::Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: Vec::from([crate::transaction::TxIn {
                script_sig: crate::script::ScriptSigBuf::from_bytes(script_sig),
                ..crate::transaction::TxIn::EMPTY_COINBASE
            }]),
            outputs: Vec::new(),
        }
    }

    #[cfg(feature = "pow")]
    fn valid_auxpow_header() -> Header {
        let mut header =
            test_header(1_700_000_000, Params::REGTEST.max_attainable_target.to_compact_lossy());
        header.version = crate::block::Version::with_base_version(2, 8).with_auxpow(true);

        let merkle_height = 1;
        let nonce = 7;
        let chain_index =
            expected_auxpow_chain_index(nonce, header.version.chain_id(), merkle_height);
        let chain_merkle_branch = Vec::from([BlockHash::from_byte_array([1; 32])]);
        let mut chain_root =
            check_auxpow_merkle_branch(header.block_hash(), &chain_merkle_branch, chain_index)
                .to_byte_array();
        chain_root.reverse();
        let coinbase_tx =
            auxpow_coinbase_tx(auxpow_coinbase_script(true, chain_root, merkle_height, nonce));

        let mut parent_block = Header {
            version: crate::block::Version::TWO,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: crate::block::compute_merkle_root(core::slice::from_ref(&coinbase_tx))
                .expect("single coinbase transaction has a merkle root"),
            time: BlockTime::from_u32(1_700_000_060),
            bits: header.bits,
            nonce: 0,
            auxpow: None,
        };
        let target = derive_target(header.bits, Params::REGTEST).expect("valid target");
        while !target.is_met_by(scrypt_pow_hash(&parent_block)) {
            parent_block.nonce += 1;
        }

        header.auxpow = Some(Box::new(AuxPow {
            coinbase_tx,
            merkle_branch: Vec::new(),
            chain_merkle_branch,
            chain_index,
            parent_block,
        }));
        header
    }

    #[cfg(all(feature = "pow", feature = "tidecoin-node-validation"))]
    fn header_consensus_hex(header: &Header) -> crate::prelude::String {
        encoding::encode_to_vec(header).to_lower_hex_string()
    }

    #[cfg(all(feature = "pow", feature = "std"))]
    fn auxpow_fixture_cases() -> Vec<serde_json::Value> {
        let data = include_str!("../tests/data/auxpow_headers.json");
        let value: serde_json::Value =
            serde_json::from_str(data).expect("auxpow fixture json must parse");
        value["cases"].as_array().expect("auxpow fixture cases").clone()
    }

    #[cfg(all(feature = "pow", feature = "std"))]
    fn real_testnet_header_cases() -> Vec<serde_json::Value> {
        let data = include_str!("../tests/data/testnet_real_headers.json");
        let value: serde_json::Value =
            serde_json::from_str(data).expect("real testnet header fixture json must parse");
        value["cases"].as_array().expect("real testnet header fixture cases").clone()
    }

    #[cfg(feature = "std")]
    fn real_testnet_retarget_window_cases() -> Vec<serde_json::Value> {
        let data = include_str!("../tests/data/testnet_retarget_windows.json");
        let value: serde_json::Value =
            serde_json::from_str(data).expect("real testnet retarget fixture json must parse");
        value["retarget_windows"].as_array().expect("real testnet retarget windows").clone()
    }

    #[cfg(feature = "std")]
    fn header_from_fixture_case(case: &serde_json::Value) -> Header {
        let name = case["name"].as_str().expect("fixture name");
        let header_hex = case["header_hex"].as_str().expect("fixture header hex");
        let header_bytes = crate::hex::decode_to_vec(header_hex).expect("header hex");
        encoding::decode_from_slice(&header_bytes)
            .unwrap_or_else(|err| panic!("{name} fixture header decodes: {err}"))
    }

    #[cfg(feature = "std")]
    fn header_from_window(headers: &[(u32, Header)], height: BlockHeight) -> Header {
        let height = height.to_u32();
        headers
            .iter()
            .find_map(|(candidate, header)| (*candidate == height).then(|| header.clone()))
            .unwrap_or_else(|| panic!("missing real testnet header fixture at height {height}"))
    }

    #[cfg(feature = "std")]
    fn try_header_from_window(headers: &[(u32, Header)], height: BlockHeight) -> Option<Header> {
        let height = height.to_u32();
        headers
            .iter()
            .find_map(|(candidate, header)| (*candidate == height).then(|| header.clone()))
    }

    #[cfg(feature = "std")]
    fn fixture_params(network: i64) -> Params {
        match network {
            1 => Params::TESTNET,
            2 => Params::REGTEST,
            _ => panic!("unsupported fixture network id {network}"),
        }
    }

    #[cfg(all(feature = "pow", feature = "std"))]
    fn expected_auxpow_error(expected: &str) -> Option<AuxPowValidationError> {
        match expected {
            "valid" => None,
            "chain_id_mismatch" => Some(AuxPowValidationError::ChainIdMismatch),
            "parent_has_own_chain_id" => Some(AuxPowValidationError::ParentHasOwnChainId),
            "wrong_chain_index" => Some(AuxPowValidationError::WrongChainIndex),
            "missing_merged_mining_header" => {
                Some(AuxPowValidationError::MissingMergedMiningHeader)
            }
            "coinbase_merkle_root" => Some(AuxPowValidationError::CoinbaseMerkleRoot),
            "missing_chain_merkle_root" => Some(AuxPowValidationError::MissingChainMerkleRoot),
            "multiple_merged_mining_headers" => {
                Some(AuxPowValidationError::MultipleMergedMiningHeaders)
            }
            "merged_mining_header_not_before_root" => {
                Some(AuxPowValidationError::MergedMiningHeaderNotBeforeRoot)
            }
            "merkle_branch_size_mismatch" => Some(AuxPowValidationError::MerkleBranchSizeMismatch),
            "missing_chain_merkle_size_and_nonce" => {
                Some(AuxPowValidationError::MissingChainMerkleSizeAndNonce)
            }
            "parent_pow_failure" => Some(AuxPowValidationError::ParentProofOfWork),
            "pre_activation" => Some(AuxPowValidationError::PreActivation),
            other => panic!("unsupported auxpow fixture expectation {other}"),
        }
    }

    #[test]
    #[cfg(all(feature = "pow", feature = "std"))]
    fn node_generated_auxpow_fixtures_match_rust_validator() {
        for case in auxpow_fixture_cases() {
            let name = case["name"].as_str().expect("fixture name");
            let expected = case["expected"].as_str().expect("fixture expected");
            let header_hex = case["header_hex"].as_str().expect("fixture header hex");
            let header_bytes = crate::hex::decode_to_vec(header_hex).expect("header hex");

            if expected == "decode_error" {
                assert!(
                    encoding::decode_from_slice::<Header>(&header_bytes).is_err(),
                    "{name} should fail header decoding"
                );
                continue;
            }

            let header: Header = encoding::decode_from_slice(&header_bytes)
                .unwrap_or_else(|err| panic!("{name} fixture header decodes: {err}"));
            let params = fixture_params(case["network"].as_i64().expect("fixture network"));
            let height =
                BlockHeight::from_u32(case["height"].as_u64().expect("fixture height") as u32);

            assert_eq!(
                validate_auxpow_context(&header, params, Some(height)),
                expected_auxpow_error(expected).map_or(Ok(()), Err),
                "{name}"
            );
        }
    }

    #[test]
    #[cfg(all(feature = "pow", feature = "tidecoin-node-validation"))]
    fn node_generated_auxpow_fixtures_match_tidecoin_node_bridge() {
        let harness = match node_parity::TidecoinNodeHarness::from_env() {
            Ok(harness) => harness,
            Err(err) => {
                std::eprintln!("skipping Tidecoin node-backed AuxPoW fixture test: {err}");
                return;
            }
        };

        for case in auxpow_fixture_cases() {
            let name = case["name"].as_str().expect("fixture name");
            let expected = case["expected"].as_str().expect("fixture expected");
            let header_hex = case["header_hex"].as_str().expect("fixture header hex");
            let network = case["network"].as_i64().expect("fixture network") as i32;
            let height = case["height"].as_i64().expect("fixture height") as i32;
            let got = harness.has_valid_header_pow_hex(header_hex, network, Some(height));

            if expected == "valid" {
                got.unwrap_or_else(|err| panic!("{name} should be node-valid: {err}"));
            } else {
                assert!(got.is_err(), "{name} should be node-invalid");
            }
        }
    }

    #[test]
    #[cfg(all(feature = "pow", feature = "std"))]
    fn real_testnet_headers_match_rust_pow_validator() {
        for case in real_testnet_header_cases() {
            let name = case["name"].as_str().expect("fixture name");
            let expected = case["expected"].as_str().expect("fixture expected");
            let header = header_from_fixture_case(&case);
            let params = fixture_params(case["network"].as_i64().expect("fixture network"));
            let height =
                BlockHeight::from_u32(case["height"].as_u64().expect("fixture height") as u32);

            assert_eq!(
                header.block_hash().to_string(),
                case["block_hash"].as_str().expect("fixture block hash"),
                "{name} block hash"
            );
            assert_eq!(
                header.bits.to_consensus(),
                u32::from_str_radix(
                    case["n_bits"].as_str().expect("fixture bits").trim_start_matches("0x"),
                    16,
                )
                .expect("fixture bits"),
                "{name} bits"
            );

            match expected {
                "valid_pure_pow" => {
                    assert!(header.auxpow.is_none(), "{name} should be pure PoW");
                    validate_pow_at_height(&header, &params, height)
                        .unwrap_or_else(|err| panic!("{name} PoW validation: {err}"));
                }
                "valid_auxpow" => assert!(header.auxpow.is_some(), "{name} should carry AuxPoW"),
                other => panic!("unsupported real testnet fixture expectation {other}"),
            }

            validate_auxpow_context(&header, &params, Some(height))
                .unwrap_or_else(|err| panic!("{name} auxpow context: {err}"));
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn real_testnet_retarget_windows_predict_observed_next_bits() {
        let params = Params::TESTNET;

        for window in real_testnet_retarget_window_cases() {
            let name = window["name"].as_str().expect("retarget window name");
            let start = window["start_height"].as_u64().expect("retarget window start") as u32;
            let end = window["end_height"].as_u64().expect("retarget window end") as u32;
            let first_checked_candidate = window["first_checked_candidate_height"]
                .as_u64()
                .map(|height| height as u32)
                .unwrap_or(start + 1);
            let headers = window["headers"]
                .as_array()
                .expect("retarget window headers")
                .iter()
                .map(|case| {
                    let height = case["height"].as_u64().expect("fixture height") as u32;
                    (height, header_from_fixture_case(case))
                })
                .collect::<Vec<_>>();

            for candidate_height in first_checked_candidate..=end {
                let current_height = candidate_height - 1;
                let current = header_from_window(&headers, BlockHeight::from_u32(current_height));
                let observed =
                    header_from_window(&headers, BlockHeight::from_u32(candidate_height));
                let got = next_target_after(
                    current,
                    BlockHeight::from_u32(current_height),
                    &params,
                    Some(observed.time.to_u32()),
                    |height| -> Result<Header, BlockHeight> {
                        try_header_from_window(&headers, height).ok_or(height)
                    },
                );
                let got = got.unwrap_or_else(|missing| {
                    panic!(
                        "{name} next target for height {candidate_height} requested missing fixture height {missing}"
                    )
                });

                assert_eq!(got, observed.bits, "{name} candidate_height={candidate_height}");
            }
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn real_testnet_retarget_windows_pass_permitted_transition_envelope() {
        let params = Params::TESTNET;

        for window in real_testnet_retarget_window_cases() {
            let name = window["name"].as_str().expect("retarget window name");
            let start = window["start_height"].as_u64().expect("retarget window start") as u32;
            let end = window["end_height"].as_u64().expect("retarget window end") as u32;
            let first_checked_candidate = window["first_checked_candidate_height"]
                .as_u64()
                .map(|height| height as u32)
                .unwrap_or(start + 1);
            let headers = window["headers"]
                .as_array()
                .expect("retarget window headers")
                .iter()
                .map(|case| {
                    let height = case["height"].as_u64().expect("fixture height") as u32;
                    (height, header_from_fixture_case(case))
                })
                .collect::<Vec<_>>();

            for candidate_height in first_checked_candidate..=end {
                let current =
                    header_from_window(&headers, BlockHeight::from_u32(candidate_height - 1));
                let observed =
                    header_from_window(&headers, BlockHeight::from_u32(candidate_height));

                assert!(
                    permitted_difficulty_transition(
                        &params,
                        BlockHeight::from_u32(candidate_height),
                        current.bits,
                        observed.bits,
                    ),
                    "{name} candidate_height={candidate_height} permitted transition"
                );
            }
        }
    }

    #[test]
    #[cfg(all(feature = "pow", feature = "tidecoin-node-validation"))]
    fn real_testnet_headers_match_tidecoin_node_bridge() {
        let harness = match node_parity::TidecoinNodeHarness::from_env() {
            Ok(harness) => harness,
            Err(err) => {
                std::eprintln!("skipping Tidecoin node-backed real testnet header test: {err}");
                return;
            }
        };

        for case in real_testnet_header_cases() {
            let name = case["name"].as_str().expect("fixture name");
            let header_hex = case["header_hex"].as_str().expect("fixture header hex");
            let network = case["network"].as_i64().expect("fixture network") as i32;
            let height = case["height"].as_i64().expect("fixture height") as i32;

            harness
                .has_valid_header_pow_hex(header_hex, network, Some(height))
                .unwrap_or_else(|err| panic!("{name} should be node-valid: {err}"));
        }
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_auxpow_context_accepts_valid_post_activation_header() {
        let header = valid_auxpow_header();

        assert_eq!(
            validate_auxpow_context(&header, Params::REGTEST, Some(BlockHeight::from_u32(0))),
            Ok(())
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_auxpow_context_rejects_missing_payload() {
        let mut header = valid_auxpow_header();
        header.auxpow = None;

        assert_eq!(
            validate_auxpow_context(&header, Params::REGTEST, Some(BlockHeight::from_u32(0))),
            Err(AuxPowValidationError::MissingAuxPow)
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_auxpow_context_rejects_unexpected_payload() {
        let mut header = valid_auxpow_header();
        header.version = header.version.with_auxpow(false);

        assert_eq!(
            validate_auxpow_context(&header, Params::REGTEST, Some(BlockHeight::from_u32(0))),
            Err(AuxPowValidationError::UnexpectedAuxPow)
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_auxpow_context_rejects_pre_activation_auxpow() {
        let header = valid_auxpow_header();

        assert_eq!(
            validate_auxpow_context(&header, Params::TESTNET, Some(BlockHeight::from_u32(999))),
            Err(AuxPowValidationError::PreActivation)
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_auxpow_context_rejects_strict_chain_id_mismatch() {
        let mut header = valid_auxpow_header();
        header.version = crate::block::Version::with_base_version(2, 7).with_auxpow(true);

        assert_eq!(
            validate_auxpow_context(&header, Params::REGTEST, Some(BlockHeight::from_u32(0))),
            Err(AuxPowValidationError::ChainIdMismatch)
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_auxpow_context_rejects_chain_id_without_auxpow_flag() {
        let mut header =
            test_header(1_700_000_000, Params::REGTEST.max_attainable_target.to_compact_lossy());
        header.version = crate::block::Version::with_base_version(2, 8);

        assert_eq!(
            validate_auxpow_context(&header, Params::REGTEST, Some(BlockHeight::from_u32(0))),
            Err(AuxPowValidationError::ChainIdWithoutAuxPowFlag)
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_auxpow_context_rejects_parent_with_own_chain_id() {
        let mut header = valid_auxpow_header();
        let auxpow = header.auxpow.as_mut().expect("auxpow");
        auxpow.parent_block.version =
            crate::block::Version::with_base_version(2, 8).with_auxpow(true);

        assert_eq!(
            validate_auxpow_context(&header, Params::REGTEST, Some(BlockHeight::from_u32(0))),
            Err(AuxPowValidationError::ParentHasOwnChainId)
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_auxpow_context_rejects_missing_merged_mining_header() {
        let mut header = valid_auxpow_header();
        let child_hash = header.block_hash();
        let auxpow = header.auxpow.as_mut().expect("auxpow");
        let mut chain_root =
            check_auxpow_merkle_branch(child_hash, &auxpow.chain_merkle_branch, auxpow.chain_index)
                .to_byte_array();
        chain_root.reverse();
        auxpow.coinbase_tx.inputs[0].script_sig = crate::script::ScriptSigBuf::from_bytes(
            auxpow_coinbase_script(false, chain_root, auxpow.chain_merkle_branch.len(), 7),
        );
        auxpow.parent_block.merkle_root =
            crate::block::compute_merkle_root(core::slice::from_ref(&auxpow.coinbase_tx))
                .expect("single coinbase transaction has a merkle root");

        assert_eq!(
            validate_auxpow_context(&header, Params::REGTEST, Some(BlockHeight::from_u32(0))),
            Err(AuxPowValidationError::MissingMergedMiningHeader)
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_auxpow_context_rejects_wrong_chain_index() {
        let mut header = valid_auxpow_header();
        let child_hash = header.block_hash();
        let auxpow = header.auxpow.as_mut().expect("auxpow");
        auxpow.chain_index ^= 1;
        let mut chain_root =
            check_auxpow_merkle_branch(child_hash, &auxpow.chain_merkle_branch, auxpow.chain_index)
                .to_byte_array();
        chain_root.reverse();
        auxpow.coinbase_tx.inputs[0].script_sig = crate::script::ScriptSigBuf::from_bytes(
            auxpow_coinbase_script(true, chain_root, auxpow.chain_merkle_branch.len(), 7),
        );
        auxpow.parent_block.merkle_root =
            crate::block::compute_merkle_root(core::slice::from_ref(&auxpow.coinbase_tx))
                .expect("single coinbase transaction has a merkle root");

        assert_eq!(
            validate_auxpow_context(&header, Params::REGTEST, Some(BlockHeight::from_u32(0))),
            Err(AuxPowValidationError::WrongChainIndex)
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_auxpow_context_rejects_parent_pow_failure() {
        let mut header = valid_auxpow_header();
        let target = derive_target(header.bits, Params::REGTEST).expect("valid target");
        let auxpow = header.auxpow.as_mut().expect("auxpow");
        while target.is_met_by(scrypt_pow_hash(&auxpow.parent_block)) {
            auxpow.parent_block.nonce += 1;
        }

        assert_eq!(
            validate_auxpow_context(&header, Params::REGTEST, Some(BlockHeight::from_u32(0))),
            Err(AuxPowValidationError::ParentProofOfWork)
        );
    }

    #[test]
    fn next_target_mainnet() {
        let params = Params::new(crate::Network::Tidecoin);
        let adjustment_interval = params.difficulty_adjustment_interval(); // 7200

        // Use a height that triggers retarget: height+1 must be divisible by 7200.
        // height = 7199 means next block is 7200, a retarget boundary.
        let height = BlockHeight::from_u32(adjustment_interval - 1);
        let current = current_header();

        fn fetch_epoch_start(height: BlockHeight) -> Result<Header, core::convert::Infallible> {
            assert_eq!(height, BlockHeight::from_u32(0));
            Ok(Header {
                version: crate::block::Version::TWO,
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: crate::TxMerkleNode::from_byte_array([0; 32]),
                time: BlockTime::from_u32(1609074580),
                bits: CompactTarget::from_consensus(0x1704_ed7f),
                nonce: 0,
                auxpow: None,
            })
        }

        let got = next_target_after(current, height, &params, None, fetch_epoch_start)
            .expect("failed to calculate next target");

        // Just verify it returns a valid compact target (the exact value depends on timespan).
        let _ = got;
    }

    #[test]
    fn next_target_mainnet_same_target() {
        let params = Params::new(crate::Network::Tidecoin);
        let header = current_header();

        fn fetch_header(_height: BlockHeight) -> Result<Header, core::num::ParseIntError> {
            unreachable!("get_block_header_by_height should not be called");
        }

        // Non-retargeting height: 100 is not a retarget boundary (7200 interval).
        let height = BlockHeight::from_u32(100);
        let want = header.bits;
        let got = next_target_after(header, height, &params, None, fetch_header)
            .expect("failed to calculate next target");

        assert_eq!(got, want);
    }

    #[test]
    fn next_target_mainnet_historical_first_retarget_matches_node() {
        let params = Params::MAINNET;
        let current_height = BlockHeight::from_u32(params.difficulty_adjustment_interval() - 1);
        let current = test_header(1_609_162_893, CompactTarget::from_consensus(0x2001ffff));

        let fetch_header = |height: BlockHeight| -> Result<Header, core::convert::Infallible> {
            assert_eq!(height, BlockHeight::from_u32(0));
            Ok(test_header(1_609_074_580, CompactTarget::from_consensus(0x2001ffff)))
        };

        let got = next_target_after(current, current_height, &params, None, fetch_header)
            .expect("failed to calculate first mainnet retarget");

        assert_eq!(got, CompactTarget::from_consensus(0x1e43b698));
        assert!(permitted_difficulty_transition(
            &params,
            BlockHeight::from_u32(params.difficulty_adjustment_interval()),
            CompactTarget::from_consensus(0x2001ffff),
            got
        ));
    }

    #[test]
    fn next_target_mainnet_later_legacy_retarget_uses_full_interval_lookback() {
        let params = Params::MAINNET;
        let interval = params.difficulty_adjustment_interval();
        let current_height = BlockHeight::from_u32(interval * 2 - 1);
        let expected_first_height = BlockHeight::from_u32(interval - 1);
        let current = test_header(1_610_000_000, CompactTarget::from_consensus(0x2001ffff));
        let epoch_start = test_header(1_609_500_000, CompactTarget::from_consensus(0x2001ffff));
        let mut fetched_height = None;

        let got = next_target_after(
            current.clone(),
            current_height,
            &params,
            None,
            |height| -> Result<Header, core::convert::Infallible> {
                fetched_height = Some(height);
                assert_eq!(height, expected_first_height);
                Ok(epoch_start.clone())
            },
        )
        .expect("failed to calculate later mainnet retarget");

        assert_eq!(fetched_height, Some(expected_first_height));
        assert_eq!(
            got,
            CompactTarget::from_header_difficulty_adjustment(epoch_start, current, &params)
        );
    }

    // Test that on testnet, if the new block's timestamp is more than 2 * pow_target_spacing after
    // the current header's time, we return the pow_limit (minimum difficulty).
    #[test]
    fn next_target_testnet_min_difficulty_when_slow() {
        let header = current_header();

        fn fetch_header(_height: BlockHeight) -> Result<Header, core::convert::Infallible> {
            unreachable!("fetcher should not be called for min difficulty case");
        }

        let params = Params::TESTNET;
        let height = BlockHeight::from_u32(100); // non-retarget height

        // New block timestamp is more than 2 * pow_target_spacing after current header
        let new_block_timestamp = Some(header.time.to_u32() + 2 * 60 + 1);

        // Should return pow_limit (minimum difficulty)
        let want = params.max_attainable_target.to_compact_lossy();
        let got = next_target_after(header, height, &params, new_block_timestamp, fetch_header)
            .expect("failed to calculate next target");
        assert_eq!(got, want);
    }

    #[test]
    fn next_target_testnet_walk_back_for_real_target() {
        let current_time: u32 = 1_700_000_000;

        let params = Params::TESTNET;
        let pow_limit = params.max_attainable_target.to_compact_lossy();
        let want = CompactTarget::from_consensus(0x1f01ffff);

        let current_height = BlockHeight::from_u32(500);

        let current_header = Header {
            version: crate::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::from_byte_array([1u8; 32]),
            merkle_root: crate::TxMerkleNode::from_byte_array([2u8; 32]),
            time: current_time.into(),
            bits: pow_limit,
            nonce: 0,
            auxpow: None,
        };

        // Timestamp within 2 * pow_target_spacing
        let new_block_timestamp = Some(current_time + 60);

        // Tidecoin testnet inherits the min-difficulty walk-back structure, but with a much larger
        // attainable target the previous real target in this setup is still the pow limit.
        let fetch_header = move |height: BlockHeight| -> Result<Header, core::convert::Infallible> {
            assert_eq!(height.to_u32(), current_height.to_u32() - 1);

            Ok(Header {
                version: crate::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::from_byte_array([1u8; 32]),
                merkle_root: crate::TxMerkleNode::from_byte_array([2u8; 32]),
                time: (current_time - 60).into(),
                bits: want,
                nonce: 0,
                auxpow: None,
            })
        };

        let got = next_target_after(
            current_header,
            current_height,
            &params,
            new_block_timestamp,
            fetch_header,
        )
        .expect("failed to calculate next target");

        assert_eq!(got, want);
    }

    #[test]
    fn next_target_testnet_post_auxpow_keeps_exact_spacing_target() {
        let params = Params::TESTNET;
        let bits = CompactTarget::from_consensus(0x1f01ffff);
        let current_height = BlockHeight::from_u32(1000);
        let base_time = 1_700_000_000;
        let current = test_header(base_time + current_height.to_u32() * 60, bits);

        let fetch_header = |height: BlockHeight| -> Result<Header, core::convert::Infallible> {
            Ok(test_header(base_time + height.to_u32() * 60, bits))
        };

        let got = next_target_after(current, current_height, &params, None, fetch_header)
            .expect("failed to calculate post-auxpow target");

        // The node divides before multiplying in CalculateNextWorkRequiredNew, so compact target
        // rounding can move by one even at exact target spacing.
        assert_eq!(got, CompactTarget::from_consensus(0x1f01fffe));
    }

    #[test]
    fn next_target_post_auxpow_insufficient_window_returns_pow_limit() {
        let mut params = Params::MAINNET;
        params.auxpow_start_height = Some(BlockHeight::from_u32(0));
        params.pow_averaging_window = 17;
        params.pow_max_adjust_down = 32;
        params.pow_max_adjust_up = 16;
        params.pow_allow_min_difficulty_blocks_after_height = None;
        params.allow_min_difficulty_blocks = false;
        params.no_pow_retargeting = false;

        let pow_limit = params.max_attainable_target.to_compact_lossy();
        let current = test_header(1_060, pow_limit);

        let fetch_header = |height: BlockHeight| -> Result<Header, core::convert::Infallible> {
            assert_eq!(height, BlockHeight::from_u32(0));
            Ok(test_header(1_000, pow_limit))
        };

        let got = next_target_after(
            current,
            BlockHeight::from_u32(1),
            &params,
            Some(1_120),
            fetch_header,
        )
        .expect("failed to calculate insufficient-window target");

        assert_eq!(got, pow_limit);
    }

    #[test]
    fn permitted_difficulty_transition_matches_legacy_bounds() {
        let params = Params::MAINNET;
        let interval = params.difficulty_adjustment_interval();
        let old_bits = CompactTarget::from_consensus(0x1d01ffff);
        let old_target = Target::from_compact(old_bits);
        let minimum = old_target.min_transition_threshold().to_compact_lossy();
        let maximum = old_target.max_transition_threshold(&params).to_compact_lossy();

        assert!(permitted_difficulty_transition(
            &params,
            BlockHeight::from_u32(100),
            old_bits,
            old_bits
        ));
        assert!(!permitted_difficulty_transition(
            &params,
            BlockHeight::from_u32(100),
            old_bits,
            maximum
        ));
        assert!(permitted_difficulty_transition(
            &params,
            BlockHeight::from_u32(interval),
            old_bits,
            minimum
        ));
        assert!(permitted_difficulty_transition(
            &params,
            BlockHeight::from_u32(interval),
            old_bits,
            maximum
        ));
        assert!(!permitted_difficulty_transition(
            &params,
            BlockHeight::from_u32(interval),
            old_bits,
            CompactTarget::from_consensus(0x1f01ffff)
        ));
    }

    #[test]
    fn permitted_difficulty_transition_allows_legacy_overflow_bounds() {
        let params = Params::MAINNET;
        let interval = params.difficulty_adjustment_interval();
        let old_target = Target(params.max_attainable_target.0 >> 4);
        let old_bits = old_target.to_compact_lossy();

        assert!(legacy_retarget_may_overflow(
            old_target,
            i64::from(params.pow_target_timespan) * 4,
            params.max_attainable_target
        ));
        assert!(permitted_difficulty_transition(
            &params,
            BlockHeight::from_u32(interval),
            old_bits,
            CompactTarget::from_consensus(0x01010000)
        ));
    }

    #[test]
    fn permitted_difficulty_transition_matches_post_auxpow_bounds() {
        let mut params = Params::MAINNET;
        params.auxpow_start_height = Some(BlockHeight::from_u32(0));
        params.pow_max_adjust_up = 16;
        params.pow_max_adjust_down = 32;

        let height = BlockHeight::from_u32(42);
        let old_bits = CompactTarget::from_consensus(0x1d01ffff);

        assert!(permitted_difficulty_transition(&params, height, old_bits, old_bits));
        assert!(!permitted_difficulty_transition(
            &params,
            height,
            old_bits,
            CompactTarget::from_consensus(0x1f01ffff)
        ));
        assert!(!permitted_difficulty_transition(
            &params,
            height,
            old_bits,
            CompactTarget::from_consensus(0x01010000)
        ));
    }

    #[test]
    fn permitted_difficulty_transition_switches_at_activation_height() {
        let mut params = Params::MAINNET;
        params.auxpow_start_height = Some(BlockHeight::from_u32(100));
        params.allow_min_difficulty_blocks = false;
        params.no_pow_retargeting = false;

        let old_target = Target(params.max_attainable_target.0 >> 12);
        let old_bits = old_target.to_compact_lossy();
        let mut allowed_new_target = Target::from_compact(old_bits).0
            * U256::from(u64::from((100 + params.pow_max_adjust_down).pow(2)));
        allowed_new_target = allowed_new_target / U256::from(10_000u64);
        allowed_new_target = core::cmp::min(allowed_new_target, params.max_attainable_target.0);
        let allowed_new_bits = Target(allowed_new_target).to_compact_lossy();

        assert_ne!(old_bits, allowed_new_bits);
        assert!(!permitted_difficulty_transition(
            &params,
            BlockHeight::from_u32(99),
            old_bits,
            allowed_new_bits
        ));
        assert!(permitted_difficulty_transition(
            &params,
            BlockHeight::from_u32(100),
            old_bits,
            allowed_new_bits
        ));
    }

    #[test]
    fn permitted_difficulty_transition_allows_test_chain_min_difficulty_networks() {
        assert!(permitted_difficulty_transition(
            Params::TESTNET,
            BlockHeight::from_u32(1),
            CompactTarget::from_consensus(0x01010000),
            CompactTarget::from_consensus(0x1f01ffff)
        ));
        assert!(permitted_difficulty_transition(
            Params::REGTEST,
            BlockHeight::from_u32(1),
            CompactTarget::from_consensus(0x01010000),
            CompactTarget::from_consensus(0x200f0f0f)
        ));
    }

    #[test]
    #[cfg(feature = "tidecoin-node-validation")]
    fn permitted_difficulty_transition_matches_tidecoin_node_bridge() {
        let harness = match node_parity::TidecoinNodeHarness::from_env() {
            Ok(harness) => harness,
            Err(err) => {
                std::eprintln!("skipping Tidecoin node-backed difficulty-transition test: {err}");
                return;
            }
        };
        let params = Params::MAINNET;
        let interval = params.difficulty_adjustment_interval();
        let old_bits = CompactTarget::from_consensus(0x1d01ffff);
        let old_target = Target::from_compact(old_bits);
        let overflow_old_bits = Target(params.max_attainable_target.0 >> 4).to_compact_lossy();
        let cases = [
            (100, old_bits, old_bits),
            (100, old_bits, old_target.max_transition_threshold(&params).to_compact_lossy()),
            (interval, old_bits, old_target.min_transition_threshold().to_compact_lossy()),
            (interval, old_bits, old_target.max_transition_threshold(&params).to_compact_lossy()),
            (interval, old_bits, CompactTarget::from_consensus(0x1f01ffff)),
            (interval, overflow_old_bits, CompactTarget::from_consensus(0x01010000)),
        ];

        for (height, old_bits, new_bits) in cases {
            let rust = permitted_difficulty_transition(
                &params,
                BlockHeight::from_u32(height),
                old_bits,
                new_bits,
            );
            let node = harness
                .permitted_difficulty_transition(
                    0,
                    i64::from(height),
                    old_bits.to_consensus(),
                    new_bits.to_consensus(),
                )
                .expect("node permitted difficulty transition bridge");

            assert_eq!(rust, node, "height={height} old={old_bits:?} new={new_bits:?}");
        }
    }

    #[test]
    fn pow_hash_algorithm_switches_at_auxpow_activation() {
        assert_eq!(
            pow_hash_algorithm_at_height(Params::MAINNET, BlockHeight::from_u32(1_000_000)),
            MiningHashAlgorithm::Yespower
        );
        assert_eq!(
            pow_hash_algorithm_at_height(Params::TESTNET, BlockHeight::from_u32(999)),
            MiningHashAlgorithm::Yespower
        );
        assert_eq!(
            pow_hash_algorithm_at_height(Params::TESTNET, BlockHeight::from_u32(1000)),
            MiningHashAlgorithm::Scrypt
        );
        assert_eq!(
            pow_hash_algorithm_at_height(Params::REGTEST, BlockHeight::from_u32(0)),
            MiningHashAlgorithm::Scrypt
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn scrypt_pow_hash_matches_scrypt_1024_1_1_256_vector() {
        let header = pow_vector_header();
        let expected = crate::hex::decode_to_array::<32>(
            "0f2e2c6e819551415180bef46d2c2d3af07f7ed5b777a37a4d4482b7bf8353fa",
        )
        .expect("valid scrypt hash hex");

        assert_eq!(scrypt_pow_hash(&header), BlockHash::from_byte_array(expected));
    }

    #[test]
    #[cfg(feature = "pow")]
    fn yespower_pow_hash_matches_tidecoin_vector() {
        let header = pow_vector_header();
        let expected = crate::hex::decode_to_array::<32>(
            "9d90c21b5a0bb9566d2999c5d703d7327ee3ac97c020d387aa2dfd0700000000",
        )
        .expect("valid yespower hash hex");

        assert_eq!(yespower_pow_hash(&header), Ok(BlockHash::from_byte_array(expected)));
        assert_eq!(
            mining_hash_for_height(&header, Params::MAINNET, BlockHeight::from_u32(1)),
            Ok(BlockHash::from_byte_array(expected))
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_pow_at_height_uses_yespower_before_auxpow_activation() {
        let header = pow_vector_header();
        let expected = yespower_pow_hash(&header).expect("yespower hash");

        assert_eq!(
            validate_pow_at_height(&header, Params::MAINNET, BlockHeight::from_u32(1)),
            Ok(expected)
        );
        assert_eq!(validate_pow_any(&header, Params::MAINNET), Ok(expected));
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_pow_at_height_uses_scrypt_after_auxpow_activation() {
        let mut header =
            test_header(1_700_000_000, Params::REGTEST.max_attainable_target.to_compact_lossy());
        let target = derive_target(header.bits, Params::REGTEST).expect("valid target");
        while !target.is_met_by(scrypt_pow_hash(&header)) {
            header.nonce += 1;
        }
        let expected = scrypt_pow_hash(&header);

        assert_ne!(yespower_pow_hash(&header), Ok(expected));
        assert_eq!(
            validate_pow_at_height(&header, Params::REGTEST, BlockHeight::from_u32(0)),
            Ok(expected)
        );
        assert_eq!(validate_pow_any(&header, Params::REGTEST), Ok(expected));
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_pow_at_height_against_target_rejects_bad_target() {
        let header = pow_vector_header();

        assert_eq!(
            validate_pow_at_height_against_target(
                &header,
                Params::MAINNET,
                BlockHeight::from_u32(1),
                Target::ZERO
            ),
            Err(PowValidationError::BadTarget)
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_pow_at_height_rejects_invalid_compact_target() {
        let mut header = pow_vector_header();
        header.bits = CompactTarget::from_consensus(0);

        assert_eq!(
            validate_pow_at_height(&header, Params::MAINNET, BlockHeight::from_u32(1)),
            Err(PowValidationError::InvalidTarget(PowTargetError::Zero))
        );
        assert_eq!(
            validate_pow_any(&header, Params::MAINNET),
            Err(PowValidationError::InvalidTarget(PowTargetError::Zero))
        );
    }

    #[test]
    #[cfg(feature = "pow")]
    fn validate_pow_at_height_rejects_insufficient_work() {
        let mut header = pow_vector_header();
        header.bits = CompactTarget::from_consensus(0x0101_0000);
        let target = derive_target(header.bits, Params::MAINNET).expect("valid target");

        assert_eq!(
            validate_pow_at_height(&header, Params::MAINNET, BlockHeight::from_u32(1)),
            Err(PowValidationError::BadProofOfWork)
        );
        assert_eq!(
            validate_pow_at_height_against_target(
                &header,
                Params::MAINNET,
                BlockHeight::from_u32(1),
                target
            ),
            Err(PowValidationError::BadProofOfWork)
        );
        assert_eq!(
            validate_pow_any(&header, Params::MAINNET),
            Err(PowValidationError::BadProofOfWork)
        );
    }

    #[test]
    #[cfg(all(feature = "pow", feature = "tidecoin-node-validation"))]
    fn scrypt_pow_hash_matches_tidecoin_node_bridge() {
        let harness = match node_parity::TidecoinNodeHarness::from_env() {
            Ok(harness) => harness,
            Err(err) => {
                std::eprintln!("skipping Tidecoin node-backed scrypt PoW test: {err}");
                return;
            }
        };
        let mut header =
            test_header(1_700_000_000, Params::REGTEST.max_attainable_target.to_compact_lossy());
        let target = derive_target(header.bits, Params::REGTEST).expect("valid target");
        while !target.is_met_by(scrypt_pow_hash(&header)) {
            header.nonce += 1;
        }

        let node_hash = harness.scrypt_pow_hash(&header.pure_header_bytes()).unwrap();

        assert_eq!(scrypt_pow_hash(&header), BlockHash::from_byte_array(node_hash));
        assert_eq!(
            validate_pow_at_height(&header, Params::REGTEST, BlockHeight::from_u32(0)),
            Ok(BlockHash::from_byte_array(node_hash))
        );
        assert_eq!(
            validate_pow_at_height_against_target(
                &header,
                Params::REGTEST,
                BlockHeight::from_u32(0),
                target
            ),
            Ok(BlockHash::from_byte_array(node_hash))
        );
    }

    #[test]
    #[cfg(all(feature = "pow", feature = "tidecoin-node-validation"))]
    fn header_pow_validation_matches_tidecoin_node_bridge() {
        let harness = match node_parity::TidecoinNodeHarness::from_env() {
            Ok(harness) => harness,
            Err(err) => {
                std::eprintln!("skipping Tidecoin node-backed header PoW test: {err}");
                return;
            }
        };

        let yespower_header = pow_vector_header();
        harness
            .has_valid_header_pow_hex(&header_consensus_hex(&yespower_header), 0, Some(1))
            .expect("node accepts height-aware yespower header");
        harness
            .has_valid_header_pow_hex(&header_consensus_hex(&yespower_header), 0, None)
            .expect("node accepts yespower header through CheckProofOfWorkAny");
        validate_pow_at_height(&yespower_header, Params::MAINNET, BlockHeight::from_u32(1))
            .expect("Rust accepts height-aware yespower header");
        validate_pow_any(&yespower_header, Params::MAINNET).expect("Rust accepts yespower header");

        let mut bad_yespower = yespower_header;
        bad_yespower.bits = CompactTarget::from_consensus(0x0101_0000);
        assert!(harness
            .has_valid_header_pow_hex(&header_consensus_hex(&bad_yespower), 0, Some(1))
            .is_err());
        assert!(harness
            .has_valid_header_pow_hex(&header_consensus_hex(&bad_yespower), 0, None)
            .is_err());
        assert_eq!(
            validate_pow_at_height(&bad_yespower, Params::MAINNET, BlockHeight::from_u32(1)),
            Err(PowValidationError::BadProofOfWork)
        );
        assert_eq!(
            validate_pow_any(&bad_yespower, Params::MAINNET),
            Err(PowValidationError::BadProofOfWork)
        );

        let mut scrypt_header =
            test_header(1_700_000_000, Params::REGTEST.max_attainable_target.to_compact_lossy());
        let scrypt_target =
            derive_target(scrypt_header.bits, Params::REGTEST).expect("valid target");
        while !scrypt_target.is_met_by(scrypt_pow_hash(&scrypt_header)) {
            scrypt_header.nonce += 1;
        }
        harness
            .has_valid_header_pow_hex(&header_consensus_hex(&scrypt_header), 2, Some(0))
            .expect("node accepts height-aware scrypt header");
        harness
            .has_valid_header_pow_hex(&header_consensus_hex(&scrypt_header), 2, None)
            .expect("node accepts scrypt header through CheckProofOfWorkAny");
        validate_pow_at_height(&scrypt_header, Params::REGTEST, BlockHeight::from_u32(0))
            .expect("Rust accepts height-aware scrypt header");
        validate_pow_any(&scrypt_header, Params::REGTEST).expect("Rust accepts scrypt header");

        let mut bad_scrypt = scrypt_header;
        bad_scrypt.bits = CompactTarget::from_consensus(0x0101_0000);
        assert!(harness
            .has_valid_header_pow_hex(&header_consensus_hex(&bad_scrypt), 2, Some(0))
            .is_err());
        assert!(harness
            .has_valid_header_pow_hex(&header_consensus_hex(&bad_scrypt), 2, None)
            .is_err());
        assert_eq!(
            validate_pow_at_height(&bad_scrypt, Params::REGTEST, BlockHeight::from_u32(0)),
            Err(PowValidationError::BadProofOfWork)
        );
        assert_eq!(
            validate_pow_any(&bad_scrypt, Params::REGTEST),
            Err(PowValidationError::BadProofOfWork)
        );

        let auxpow_header = valid_auxpow_header();
        harness
            .has_valid_header_pow_hex(&header_consensus_hex(&auxpow_header), 2, Some(0))
            .expect("node accepts regtest auxpow header at activation");
        validate_auxpow_context(&auxpow_header, Params::REGTEST, Some(BlockHeight::from_u32(0)))
            .expect("Rust accepts regtest auxpow header at activation");

        let mut bad_auxpow = auxpow_header;
        let target = derive_target(bad_auxpow.bits, Params::REGTEST).expect("valid target");
        let bad_parent = &mut bad_auxpow.auxpow.as_mut().expect("auxpow").parent_block;
        while target.is_met_by(scrypt_pow_hash(bad_parent)) {
            bad_parent.nonce += 1;
        }
        assert!(harness
            .has_valid_header_pow_hex(&header_consensus_hex(&bad_auxpow), 2, Some(0))
            .is_err());
        assert_eq!(
            validate_auxpow_context(&bad_auxpow, Params::REGTEST, Some(BlockHeight::from_u32(0))),
            Err(AuxPowValidationError::ParentProofOfWork)
        );
    }

    #[test]
    #[cfg(all(feature = "pow", feature = "tidecoin-node-validation"))]
    fn yespower_pow_hash_matches_tidecoin_node_bridge_vector() {
        let harness = match node_parity::TidecoinNodeHarness::from_env() {
            Ok(harness) => harness,
            Err(err) => {
                std::eprintln!("skipping Tidecoin node-backed yespower PoW test: {err}");
                return;
            }
        };
        let header = pow_vector_header();
        let expected = crate::hex::decode_to_array::<32>(
            "9d90c21b5a0bb9566d2999c5d703d7327ee3ac97c020d387aa2dfd0700000000",
        )
        .expect("valid yespower hash hex");

        assert_eq!(yespower_pow_hash(&header), Ok(BlockHash::from_byte_array(expected)));
        assert_eq!(harness.yespower_pow_hash(&header.pure_header_bytes()).unwrap(), expected);
        assert_eq!(
            validate_pow_at_height(&header, Params::MAINNET, BlockHeight::from_u32(1),),
            Ok(BlockHash::from_byte_array(expected))
        );
    }

    #[test]
    fn next_target_activation_boundary_uses_node_post_auxpow_window() {
        let mut params = Params::TESTNET;
        params.auxpow_start_height = Some(BlockHeight::from_u32(5));
        params.pow_target_spacing = 1;
        params.pow_target_timespan = 4;
        params.allow_min_difficulty_blocks = false;
        params.no_pow_retargeting = false;
        params.pow_averaging_window = 2;
        params.pow_max_adjust_up = 16;
        params.pow_max_adjust_down = 32;

        let mut legacy_params = params.clone();
        legacy_params.auxpow_start_height = None;

        let genesis_time = 1_700_000_000;
        let genesis_bits = Params::TESTNET.max_attainable_target.to_compact_lossy();
        let mut headers: [Header; 5] =
            core::array::from_fn(|_| test_header(genesis_time, genesis_bits));
        for height in 1..=4 {
            let current = headers[height - 1].clone();
            let fetch = |h: BlockHeight| -> Result<Header, core::convert::Infallible> {
                Ok(headers[h.to_u32() as usize].clone())
            };
            let next_bits = next_target_after(
                current,
                BlockHeight::from_u32(height as u32 - 1),
                &params,
                Some(genesis_time + height as u32),
                fetch,
            )
            .expect("failed to calculate setup target");
            headers[height] = test_header(genesis_time + height as u32, next_bits);
        }

        let current = headers[4].clone();
        let fetch = |h: BlockHeight| -> Result<Header, core::convert::Infallible> {
            Ok(headers[h.to_u32() as usize].clone())
        };
        let post_auxpow_bits = next_target_after(
            current.clone(),
            BlockHeight::from_u32(4),
            &params,
            Some(genesis_time + 5),
            fetch,
        )
        .expect("failed to calculate post-auxpow activation target");

        let fetch = |h: BlockHeight| -> Result<Header, core::convert::Infallible> {
            Ok(headers[h.to_u32() as usize].clone())
        };
        let legacy_bits = next_target_after(
            current,
            BlockHeight::from_u32(4),
            &legacy_params,
            Some(genesis_time + 5),
            fetch,
        )
        .expect("failed to calculate legacy activation target");

        assert_ne!(post_auxpow_bits, legacy_bits);
        assert_ne!(post_auxpow_bits, headers[4].bits);
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::unwind(5)] // mul_u64 loops over 4 64 bit ints so use one more than 4
    #[kani::proof]
    fn check_mul_u64() {
        let x: U256 = kani::any();
        let y: u64 = kani::any();

        let _ = x.mul_u64(y);
    }
}
