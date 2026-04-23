// SPDX-License-Identifier: CC0-1.0

//! Tidecoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.

use core::convert::Infallible;
use core::fmt;

use crate::merkle_tree::{TxMerkleNode, WitnessMerkleNode};
use crate::network::Params;
#[cfg(feature = "pow")]
use crate::pow;
use crate::pow::{MiningHashError, PowTargetError, PowValidationError};
use crate::prelude::Vec;
use crate::script::ScriptIntError;
use crate::transaction::{Coinbase, Transaction};
use crate::{internal_macros, Target, Weight, Work};
#[cfg(test)]
use crate::{prelude::Box, BlockTime};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::block::{
    AuxPow, Block, BlockDecoder, BlockEncoder, BlockHash, BlockHashDecoder, BlockHashEncoder,
    Checked, Unchecked, Validation, Version, VersionDecoder, VersionEncoder, Header,
    HeaderDecoder, HeaderEncoder, WitnessCommitment, check_block_sanity, compute_merkle_root,
    compute_witness_root,
};
#[doc(no_inline)]
pub use primitives::block::{
    BlockDecoderError, BlockHashDecoderError, BlockSanityError, HeaderDecoderError,
    InvalidBlockError, ParseBlockError, ParseHeaderError, VersionDecoderError,
};
#[doc(inline)]
pub use units::block::{
    error, BlockHeight, BlockHeightDecoder, BlockHeightEncoder, BlockHeightInterval, BlockMtp,
    BlockMtpInterval,
};
#[doc(no_inline)]
pub use units::block::{BlockHeightDecoderError, TooBigForRelativeHeightError};

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Header`] type.
    pub trait HeaderExt impl for Header {
        /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
        fn target(&self) -> Target { self.bits.into() }

        /// Computes the popular "difficulty" measure for mining.
        ///
        /// Difficulty represents how difficult the current target makes it to find a block, relative to
        /// how difficult it would be at the highest possible target (highest target == lowest difficulty).
        fn difficulty(&self, params: impl AsRef<Params>) -> u128 {
            self.target().difficulty(params)
        }

        /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
        fn difficulty_float(&self, params: impl AsRef<Params>) -> f64 {
            self.target().difficulty_float(params)
        }

        /// Checks that the proof-of-work for the block is valid, returning the mining hash.
        ///
        /// Requires the `pow` feature.
        fn validate_pow(
            &self,
            params: impl AsRef<Params>,
            height: BlockHeight,
            required_target: Target,
        ) -> Result<BlockHash, ValidationError> {
            #[cfg(feature = "pow")]
            return pow::validate_pow_at_height_against_target(self, params, height, required_target)
                .map_err(Into::into);
            #[cfg(not(feature = "pow"))]
            {
                let _ = (params, height, required_target);
                panic!("validate_pow requires the `pow` feature")
            }
        }

        /// Returns the total work of the block.
        fn work(&self) -> Work { self.target().to_work() }
    }
}

/// Extension functionality for the [`Block<Checked>`] type.
pub trait BlockCheckedExt: sealed::Sealed {
    /// Constructs a new [`Block`].
    ///
    /// # Returns
    ///
    /// Return the block if it is valid, `None` if not. See [`Block::validate`].
    fn new_checked(
        header: Header,
        transactions: Vec<Transaction>,
    ) -> Result<Block<Checked>, InvalidBlockError>;

    /// Returns the transaction Merkle root.
    fn merkle_root(&self) -> TxMerkleNode;

    /// Returns the Merkle root of transactions hashed for witness.
    ///
    /// This value was computed during block validation and was cached at that time.
    fn witness_root(&mut self) -> Option<WitnessMerkleNode>;

    /// Returns the weight of the block.
    ///
    /// > Block weight is defined as Base size * 3 + Total size.
    fn weight(&self) -> Weight;

    /// Returns the base block size, with transaction witness data stripped.
    fn base_size(&self) -> usize;

    /// Returns the total block size.
    ///
    /// > Total size is the block size in bytes with transactions serialized with witness data,
    /// > including base data and witness data.
    ///
    /// # Panics
    ///
    /// If the size calculation overflows.
    fn total_size(&self) -> usize;

    /// Returns the coinbase transaction.
    ///
    /// This method is infallible for checked blocks because validation ensures
    /// that a valid coinbase transaction is always present.
    fn coinbase(&self) -> &Coinbase;

    /// Returns the block height encoded in the coinbase transaction.
    fn bip34_block_height(&self) -> Result<u64, Bip34Error>;
}

impl BlockCheckedExt for Block<Checked> {
    fn new_checked(
        header: Header,
        transactions: Vec<Transaction>,
    ) -> Result<Self, InvalidBlockError> {
        let block = Block::new_unchecked(header, transactions);
        block.validate()
    }

    fn merkle_root(&self) -> TxMerkleNode {
        self.header().merkle_root
    }

    fn witness_root(&mut self) -> Option<WitnessMerkleNode> {
        self.cached_witness_root()
    }

    fn weight(&self) -> Weight {
        let block: &Self = self;
        block.weight()
    }

    fn base_size(&self) -> usize {
        let block: &Self = self;
        block.base_size()
    }

    fn total_size(&self) -> usize {
        let block: &Self = self;
        block.total_size()
    }

    fn coinbase(&self) -> &Coinbase {
        let first_tx = &self.transactions()[0];
        Coinbase::assume_coinbase_ref(first_tx)
    }

    /// Returns the block height encoded in the coinbase transaction.
    fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Tidecoin version-2+ blocks encode height as the first minimally
        // encoded script number in the coinbase transaction's scriptSig.

        if self.header().version < Version::TWO {
            return Err(Bip34Error::Unsupported);
        }

        let cb = self.coinbase();
        let input = cb.first_input();
        let push = input
            .script_sig
            .instructions_minimal()
            .next()
            .ok_or(Bip34Error::NotPresent)?
            .map_err(to_bip34_error)?;
        match (push.script_num(), push.push_bytes().map(|b| b.read_scriptint())) {
            (Some(num), Some(Ok(_)) | None) => {
                Ok(num.try_into().map_err(|_| Bip34Error::NegativeHeight)?)
            }
            (_, Some(Err(err))) => Err(err.into()),
            (None, _) => Err(Bip34Error::NotPresent),
        }
    }
}

mod sealed {
    /// Seals the extension traits.
    pub trait Sealed {}
    impl Sealed for super::Header {}
    impl<V: super::Validation> Sealed for super::Block<V> {}
}

/// An error when looking up a coinbase-encoded block height.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip34Error {
    /// The block does not support coinbase height encoding yet.
    Unsupported,
    /// No push was present where the coinbase height push was expected.
    NotPresent,
    /// The coinbase height push was not minimally encoded.
    NonMinimalPush,
    /// The coinbase height push was negative.
    NegativeHeight,
}

impl From<Infallible> for Bip34Error {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "block doesn't support coinbase height encoding"),
            Self::NotPresent => write!(f, "height push not present in block's coinbase"),
            Self::NonMinimalPush => write!(f, "byte push not minimally encoded"),
            Self::NegativeHeight => write!(f, "negative coinbase height"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip34Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unsupported | Self::NotPresent | Self::NonMinimalPush | Self::NegativeHeight => {
                None
            }
        }
    }
}

impl From<ScriptIntError> for Bip34Error {
    #[inline]
    fn from(err: ScriptIntError) -> Self {
        match err {
            ScriptIntError::NonMinimal => Self::NonMinimalPush,
            _ => Self::NotPresent,
        }
    }
}

#[inline]
fn to_bip34_error(err: primitives::script::Error) -> Bip34Error {
    match err {
        primitives::script::Error::NonMinimalPush => Bip34Error::NonMinimalPush,
        _ => Bip34Error::NotPresent,
    }
}

/// A block validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// The header hash is not below the target.
    BadProofOfWork,
    /// The `target` field of a block header did not match the expected difficulty.
    BadTarget,
    /// The compact target was invalid under Tidecoin node consensus rules.
    InvalidTarget(PowTargetError),
    /// The selected mining hash algorithm is not available locally.
    MiningHash(MiningHashError),
}

impl From<Infallible> for ValidationError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl From<PowValidationError> for ValidationError {
    fn from(err: PowValidationError) -> Self {
        match err {
            PowValidationError::BadProofOfWork => Self::BadProofOfWork,
            PowValidationError::BadTarget => Self::BadTarget,
            PowValidationError::InvalidTarget(err) => Self::InvalidTarget(err),
            PowValidationError::MiningHash(err) => Self::MiningHash(err),
        }
    }
}

impl fmt::Display for ValidationError {
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
impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BadProofOfWork | Self::BadTarget => None,
            Self::InvalidTarget(err) => Some(err),
            Self::MiningHash(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use internals::hex_lit as hex;
    use internals::ToU64 as _;

    use super::*;
    use crate::pow::test_utils::u128_to_work;
    use crate::script::{ScriptPubKeyBuf, ScriptSigBuf};
    use crate::transaction::{OutPoint, Transaction, TxIn, TxOut, Txid};
    use crate::{block, Amount, CompactTarget, Network, Sequence, Witness, Wtxid};

    fn synthetic_segwit_block() -> Block<Checked> {
        const RESERVED_VALUE: [u8; 32] = [0; 32];

        let mut coinbase_input = TxIn::EMPTY_COINBASE;
        coinbase_input.script_sig = ScriptSigBuf::from_bytes(vec![0x01, 0x00]);
        coinbase_input.witness.push(RESERVED_VALUE);

        let coinbase_placeholder = Transaction {
            version: primitives::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![coinbase_input],
            outputs: vec![TxOut {
                amount: Amount::from_sat(5_000_000_000).expect("coinbase amount"),
                script_pubkey: ScriptPubKeyBuf::new(),
            }],
        };

        let mut spend_witness = Witness::new();
        spend_witness.push([0x30; 71]);
        spend_witness.push([0x02; 33]);

        let spend = Transaction {
            version: primitives::transaction::Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: coinbase_placeholder.compute_txid(), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: spend_witness,
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat_u32(1_000),
                script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0x51]),
            }],
        };

        let placeholder_header = Header {
            version: Version::TWO,
            prev_blockhash: BlockHash::from_byte_array([0x11; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(1_700_000_000),
            bits: Params::REGTEST.max_attainable_target.to_compact_lossy(),
            nonce: 0,
            auxpow: None,
        };

        let block = Block::new_unchecked(
            placeholder_header.clone(),
            vec![coinbase_placeholder.clone(), spend.clone()],
        );
        let (_, commitment) =
            block.compute_witness_commitment(&RESERVED_VALUE).expect("witness commitment");

        let mut commitment_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment_script.extend_from_slice(&commitment.to_byte_array());

        let coinbase = Transaction {
            outputs: vec![TxOut {
                amount: Amount::from_sat(5_000_000_000).expect("coinbase amount"),
                script_pubkey: ScriptPubKeyBuf::from_bytes(commitment_script),
            }],
            ..coinbase_placeholder
        };

        let transactions = vec![coinbase, spend];

        let mut header = Header {
            merkle_root: block::compute_merkle_root(&transactions).expect("merkle root"),
            ..placeholder_header
        };

        while header
            .validate_pow(Params::REGTEST, BlockHeight::from_u32(0), header.target())
            .is_err()
        {
            header.nonce += 1;
        }

        let block = Block::new_unchecked(header, transactions);
        let (witness_commitment_matches, witness_root) = block.check_witness_commitment();
        assert!(witness_commitment_matches);
        assert!(witness_root.is_some());
        block.assume_checked(witness_root)
    }

    #[test]
    fn static_vector() {
        // Node bench fixture `src/bench/data/block413567.raw`.
        let raw_block = include_bytes!("../../tests/data/node_block_413567.raw");
        let block: Block =
            encoding::decode_from_slice(&raw_block[..]).expect("failed to deserialize block");
        assert!(block.check_merkle_root());

        let (header, transactions) = block.into_parts();
        let block = Block::new_unchecked(header, transactions).assume_checked(None);

        // Same as `block.check_merkle_root` but do it explicitly.
        let hashes_iter = block.transactions().iter().map(|obj| obj.compute_txid());
        let from_iter = TxMerkleNode::calculate_root(hashes_iter.clone());
        assert_eq!(from_iter, Some(block.header().merkle_root));
    }

    #[test]
    fn coinbase_and_bip34() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = encoding::decode_from_slice(&hex!(BLOCK_HEX)).unwrap();
        let block = block.assume_checked(None);

        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(block.coinbase().compute_txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // block with 3-byte bip34 push for height 0x03010000 (non-minimal 1)
        const BAD_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703010000000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let bad: Block = encoding::decode_from_slice(&hex!(BAD_HEX)).unwrap();
        let bad = bad.assume_checked(None);

        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::NonMinimalPush));

        // Block 15 on Testnet4 has height of 0x5f (15 PUSHNUM)
        const BLOCK_HEX_SMALL_HEIGHT_15: &str = "000000200fd8c4c1e88f313b561b2724542ff9be1bc54a7dab8db8ef6359d48a00000000705bf9145e6d3c413702cc61f32e4e7bfe3117b1eb928071a59adcf75694a3fb07d83866ffff001dcf4c5e8401010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff095f00062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = encoding::decode_from_slice(&hex!(BLOCK_HEX_SMALL_HEIGHT_15)).unwrap();
        let block = block.assume_checked(None);

        assert_eq!(block.bip34_block_height(), Ok(15));

        // Block 42 on Testnet4 has height of 0x012a (42)
        const BLOCK_HEX_SMALL_HEIGHT_42: &str = "000000202803addb5a3f42f3e8d6c8536598b2d872b04f3b4f0698c26afdb17300000000463dd9a37a5d3d5c05f9c80a1485b41f1f513dee00338bbc33f5a6e836fce0345dda3866ffff001d872b9def01010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff09012a062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = encoding::decode_from_slice(&hex!(BLOCK_HEX_SMALL_HEIGHT_42)).unwrap();
        let block = block.assume_checked(None);

        assert_eq!(block.bip34_block_height(), Ok(42));

        // Block 42 on Testnet4 using OP_PUSHDATA1 0x4c012a (42) instead of 0x012a (42)
        const BLOCK_HEX_SMALL_HEIGHT_42_WRONG: &str = "000000202803addb5a3f42f3e8d6c8536598b2d872b04f3b4f0698c26afdb17300000000463dd9a37a5d3d5c05f9c80a1485b41f1f513dee00338bbc33f5a6e836fce0345dda3866ffff001d872b9def01010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0a4c012a062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block =
            encoding::decode_from_slice(&hex!(BLOCK_HEX_SMALL_HEIGHT_42_WRONG)).unwrap();
        let block = block.assume_checked(None);

        assert_eq!(block.bip34_block_height(), Err(super::Bip34Error::NonMinimalPush));

        // Block with a 5 byte height properly minimally encoded
        // this is an overflow for ScriptNum (i32) parsing
        const BLOCK_HEX_5_BYTE_HEIGHT: &str = "000000202803addb5a3f42f3e8d6c8536598b2d872b04f3b4f0698c26afdb17300000000463dd9a37a5d3d5c05f9c80a1485b41f1f513dee00338bbc33f5a6e836fce0345dda3866ffff001d872b9def01010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0d052a2a2a2a2a062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = encoding::decode_from_slice(&hex!(BLOCK_HEX_5_BYTE_HEIGHT)).unwrap();
        let block = block.assume_checked(None);

        assert_eq!(block.bip34_block_height(), Err(super::Bip34Error::NotPresent));
    }

    #[test]
    fn block() {
        let params = Params::new(Network::Tidecoin);
        // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        let some_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000");
        let cutoff_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac");

        let prevhash = hex!("4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000");
        let merkle = hex!("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c");
        let work = u128_to_work(0x100010001_u128);

        let decode: Result<Block, _> = encoding::decode_from_slice(&some_block);
        let bad_decode: Result<Block, _> = encoding::decode_from_slice(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());

        let block = decode.unwrap();
        // should be also ok for a non-witness block as commitment is optional in that case
        let (witness_commitment_matches, witness_root) = block.check_witness_commitment();
        assert!(witness_commitment_matches);

        let (header, transactions) = block.into_parts();
        let real_decode =
            Block::new_unchecked(header, transactions.clone()).assume_checked(witness_root);

        assert_eq!(real_decode.header().version, Version::from_consensus(1));
        assert_eq!(encoding::encode_to_vec(&real_decode.header().prev_blockhash), prevhash);
        assert_eq!(
            real_decode.header().merkle_root,
            block::compute_merkle_root(&transactions).unwrap()
        );
        assert_eq!(encoding::encode_to_vec(&real_decode.header().merkle_root), merkle);
        assert_eq!(real_decode.header().time, BlockTime::from_u32(1231965655));
        assert_eq!(real_decode.header().bits, CompactTarget::from_consensus(486604799));
        assert_eq!(real_decode.header().nonce, 2067413810);
        assert_eq!(real_decode.header().work(), work);

        assert_eq!(real_decode.header().difficulty(&params), 33_554_688);
        assert_eq!(real_decode.header().difficulty_float(&params), 33_554_688.00390631);

        assert_eq!(real_decode.header().block_hash(), real_decode.block_hash());
        assert_eq!(real_decode.total_size(), some_block.len());
        assert_eq!(real_decode.base_size(), some_block.len());
        assert_eq!(real_decode.weight(), Weight::from_vb_unchecked(some_block.len().to_u64()));

        assert_eq!(encoding::encode_to_vec(&real_decode), some_block);
    }

    // Check that a witness block round-trips correctly under Tidecoin's difficulty parameters.
    #[test]
    fn segwit_block() {
        let segwit_block = encoding::encode_to_vec(&synthetic_segwit_block());

        let decode: Result<Block, _> = encoding::decode_from_slice(&segwit_block);

        assert!(decode.is_ok());

        let block = decode.unwrap();
        let (witness_commitment_matches, witness_root) = block.check_witness_commitment();
        assert!(witness_commitment_matches);

        let (header, transactions) = block.into_parts();
        let real_decode =
            Block::new_unchecked(header, transactions.clone()).assume_checked(witness_root);

        assert_eq!(real_decode.header().version, Version::TWO);
        assert_eq!(real_decode.header().prev_blockhash, BlockHash::from_byte_array([0x11; 32]));
        assert_eq!(
            real_decode.header().merkle_root,
            block::compute_merkle_root(&transactions).unwrap()
        );
        assert_eq!(real_decode.header().time, BlockTime::from_u32(1_700_000_000));
        assert_eq!(
            real_decode.header().bits,
            Params::REGTEST.max_attainable_target.to_compact_lossy()
        );
        assert_eq!(real_decode.header().work(), real_decode.header().target().to_work());

        assert_eq!(
            real_decode
                .header()
                .validate_pow(
                    Params::REGTEST,
                    BlockHeight::from_u32(0),
                    real_decode.header().target()
                )
                .unwrap(),
            pow::scrypt_pow_hash(real_decode.header())
        );
        assert_eq!(real_decode.total_size(), segwit_block.len());
        assert!(real_decode.base_size() < segwit_block.len());
        assert!(real_decode.weight() < Weight::from_wu((segwit_block.len() * 4) as u64));

        assert_eq!(encoding::encode_to_vec(&real_decode), segwit_block);
    }

    #[test]
    fn block_version() {
        let make_block = |version| {
            encoding::encode_to_vec(&Block::new_unchecked(
                Header {
                    version,
                    prev_blockhash: BlockHash::from_byte_array([0; 32]),
                    merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                    time: BlockTime::from_u32(0),
                    bits: CompactTarget::from_consensus(0),
                    nonce: 0,
                    auxpow: None,
                },
                Vec::new(),
            ))
        };

        let block = make_block(Version::from_consensus(0x7fff_fe00));
        let decode: Result<Block, _> = encoding::decode_from_slice(&block);
        assert!(decode.is_ok());

        let real_decode = decode.unwrap().assume_checked(None);
        assert_eq!(real_decode.header().version, Version::from_consensus(0x7fff_fe00));

        let block2 = make_block(Version::from_consensus(-2147483648));
        let decode2: Result<Block, _> = encoding::decode_from_slice(&block2);
        assert!(decode2.is_ok());
        let real_decode2 = decode2.unwrap().assume_checked(None);
        assert_eq!(real_decode2.header().version, Version::from_consensus(-2147483648));
    }

    #[test]
    fn auxpow_roundtrip_with_flag() {
        let mut header = Header {
            version: Version::with_base_version(1, 8).with_auxpow(true),
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(1),
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 2,
            auxpow: None,
        };
        header.auxpow = Some(Box::new(AuxPow::minimal_for_header(&header)));

        let encoded = encoding::encode_to_vec(&header);
        let decoded: Header =
            encoding::decode_from_slice(&encoded).expect("auxpow header should roundtrip");

        assert!(decoded.version.is_auxpow());
        assert!(decoded.auxpow.is_some());
        assert_eq!(decoded.version, header.version);
        assert_eq!(
            decoded.auxpow.as_ref().unwrap().parent_block.block_hash(),
            header.auxpow.as_ref().unwrap().parent_block.block_hash()
        );
    }

    #[test]
    fn no_auxpow_roundtrip_clears_ptr() {
        let header = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(3),
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 4,
            auxpow: None,
        };

        let encoded = encoding::encode_to_vec(&header);
        let decoded: Header =
            encoding::decode_from_slice(&encoded).expect("plain header should roundtrip");

        assert!(!decoded.version.is_auxpow());
        assert!(decoded.auxpow.is_none());
        assert_eq!(decoded.version, header.version);
    }

    #[test]
    fn auxpow_block_total_size_counts_header_payload() {
        let mut header = Header {
            version: Version::with_base_version(1, 8).with_auxpow(true),
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(5),
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 6,
            auxpow: None,
        };
        header.auxpow = Some(Box::new(AuxPow::minimal_for_header(&header)));
        let tx = Transaction {
            version: primitives::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![TxIn::EMPTY_COINBASE],
            outputs: vec![],
        };
        let block = Block::new_unchecked(header, vec![tx]).assume_checked(None);

        assert_eq!(block.total_size(), encoding::encode_to_vec(&block).len());
    }

    #[test]
    fn validate_pow() {
        let mut some_header = Header {
            version: Version::TWO,
            prev_blockhash: BlockHash::from_byte_array([0x11; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0x22; 32]),
            time: BlockTime::from_u32(1_700_000_000),
            bits: Params::REGTEST.max_attainable_target.to_compact_lossy(),
            nonce: 0,
            auxpow: None,
        };
        while !some_header.target().is_met_by(pow::scrypt_pow_hash(&some_header)) {
            some_header.nonce += 1;
        }
        let target = pow::derive_target(some_header.bits, Params::REGTEST).unwrap();
        assert_eq!(
            some_header.validate_pow(Params::REGTEST, BlockHeight::from_u32(0), target).unwrap(),
            pow::scrypt_pow_hash(&some_header)
        );

        // test with zero target
        match some_header.validate_pow(Params::REGTEST, BlockHeight::from_u32(0), Target::ZERO) {
            Err(ValidationError::BadTarget) => (),
            _ => panic!("unexpected result from validate_pow"),
        }

        let mut invalid_header: Header = some_header;
        invalid_header.bits = CompactTarget::from_consensus(0x0101_0000);
        let hard_target = pow::derive_target(invalid_header.bits, Params::REGTEST).unwrap();
        match invalid_header.validate_pow(Params::REGTEST, BlockHeight::from_u32(0), hard_target) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    fn header() -> Header {
        let header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");
        encoding::decode_from_slice(&header).expect("can't deserialize correct block header")
    }

    #[test]
    fn compact_roundtrip() {
        let header = header();
        assert_eq!(header.bits, header.target().to_compact_lossy());
    }

    #[test]
    fn header_block_hash_regression() {
        let header = header();
        let block_hash = "00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7";

        let want = block_hash.parse::<BlockHash>().unwrap();
        let got = header.block_hash();
        assert_eq!(got, want)
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x20000000u32 ^ (1 << i)) as i32;
            let version = Version::from_consensus(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version::from_consensus(0x20000000 ^ (1 << 1));
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }

    #[test]
    fn block_validation_success_with_coinbase() {
        use crate::constants;

        // Use the genesis block which has a valid coinbase
        let genesis = constants::genesis_block(Network::Tidecoin);

        let header = genesis.header().clone();
        let transactions = genesis.transactions().to_vec();

        let unchecked_block = Block::new_unchecked(header, transactions);
        let validated_block = unchecked_block.validate();

        assert!(validated_block.is_ok(), "Genesis block should validate successfully");
    }

    #[test]
    fn checked_block_coinbase_method() {
        use crate::constants;

        let genesis = constants::genesis_block(Network::Tidecoin);
        let coinbase = genesis.coinbase();

        // Test that coinbase method returns the expected transaction
        let expected_txid = genesis.transactions()[0].compute_txid();
        assert_eq!(coinbase.compute_txid(), expected_txid);
        assert_eq!(coinbase.wtxid(), Wtxid::COINBASE);

        // Test that as_inner() returns the correct transaction
        assert_eq!(coinbase.as_transaction(), &genesis.transactions()[0]);
    }

    #[test]
    fn block_new_checked_validation() {
        use crate::constants;

        // Test successful validation with genesis block
        let genesis = constants::genesis_block(Network::Tidecoin);
        let header = genesis.header().clone();
        let transactions = genesis.transactions().to_vec();

        let checked_block = Block::new_checked(header.clone(), transactions);
        assert!(checked_block.is_ok(), "Genesis block should validate via new_checked");

        // Test validation failure with empty transactions
        let empty_result = Block::new_checked(header.clone(), Vec::new());
        match empty_result {
            Err(InvalidBlockError::NoTransactions) => (),
            other => panic!("Expected NoTransactions error, got: {:?}", other),
        }

        // Test validation failure with invalid coinbase
        let non_coinbase_tx = Transaction {
            version: primitives::transaction::Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1; 32]), // Not all zeros
                    vout: 0,
                },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_AND_RBF,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ONE_TDC, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let invalid_coinbase_result = Block::new_checked(header, vec![non_coinbase_tx]);
        match invalid_coinbase_result {
            Err(InvalidBlockError::InvalidCoinbase) => (),
            other => panic!("Expected InvalidCoinbase error, got: {:?}", other),
        }
    }

    #[test]
    fn coinbase_bip34_height_with_coinbase_type() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = encoding::decode_from_slice(&hex!(BLOCK_HEX)).unwrap();
        let block = block.assume_checked(None);

        // Test that coinbase height extraction works with the Coinbase type.
        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // Test that coinbase method returns a Coinbase type
        let coinbase = block.coinbase();
        assert!(coinbase.as_transaction().is_coinbase());

        // Test that the coinbase transaction ID matches expected
        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(coinbase.compute_txid().to_string(), cb_txid);
    }
}
