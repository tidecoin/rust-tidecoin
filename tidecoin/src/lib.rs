// SPDX-License-Identifier: CC0-1.0

//! # Rust Tidecoin Library
//!
//! This is a library that supports the Tidecoin network protocol and associated primitives. It is
//! designed for Rust programs built to work with the Tidecoin network.
//!
//! This library is written entirely in Rust and illustrates the benefits of strong type safety,
//! including ownership and lifetime, for financial and cryptographic software.
//!
//! See README.md for detailed documentation about development and supported environments.
//!
//! # Cargo features
//!
//! * `arbitrary` (dependency) - arbitrary type implementations for testing.
//! * `default` - enables `std` and `rand`.
//! * `rand` - enables OS-random convenience APIs for PQ key generation, signing, and KEM
//!   encapsulation. Without this feature callers can still use deterministic APIs or provide their
//!   own RNG.
//! * `serde` (dependency) - implements `serde`-based serialization and deserialization.
//! * `std` - the usual dependency on `std`.

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_notable_trait))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Instead of littering the codebase for non-fuzzing and bench code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)]
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::incompatible_msrv)] // Has FPs and we're testing it which is more reliable anyway.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

// We only support machines with index size of 4 bytes or more.
//
// Tidecoin consensus code relies on being able to have containers with more than 65536 (2^16)
// entries in them, so consensus logic does not support machines with only 16-bit memory addresses.
//
// We specifically do not use `target_pointer_width` because of the possibility that pointer width
// does not equal index size.
internals::const_assert!(
    core::mem::size_of::<usize>() >= 4;
    "platforms that have usize less than 32 bits are not supported"
);

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "arbitrary")]
pub extern crate arbitrary;

pub extern crate base58;
pub extern crate bech32;
pub extern crate encoding;
pub extern crate hashes;
pub extern crate hex_stable as hex;
pub extern crate io;
pub extern crate primitives;

#[cfg(feature = "serde")]
#[macro_use]
pub extern crate serde;

mod internal_macros;

pub mod ext {
    //! Re-export all the extension traits so downstream can use wildcard imports.
    //!
    //! As part of stabilizing `primitives` and `units` we created a bunch of extension traits in
    //! `rust-tidecoin` to hold all the API that we are not yet ready to stabilize. This module
    //! re-exports all of them to improve ergonomics for users comfortable with wildcard imports.
    //!
    //! # Examples
    //!
    //! ```
    //! # #![allow(unused_imports)] // Because that is what we are demoing.
    //! // Wildcard import all of the extension traits.
    //! use tidecoin::ext::*;
    //!
    //! // If, for some reason, you want the name to be in scope access it via the module. E.g.
    //! use tidecoin::script::ScriptSigExt;
    //! ```
    #[rustfmt::skip] // Use terse custom grouping.
    pub use crate::{
        block::{BlockCheckedExt, HeaderExt},
        pow::CompactTargetExt,
        script::{ScriptExt, ScriptBufExt, ScriptPubKeyExt, ScriptPubKeyBufExt, WitnessScriptExt, ScriptSigExt},
        transaction::{TxInExt, TxOutExt, TransactionExt as TransactionWeightExt},
        witness::WitnessExt,
    };
    pub use crate::consensus_validation::{
        ScriptPubKeyExt as ConsensusScriptPubKeyValidationExt,
        TransactionExt as ConsensusTransactionValidationExt,
    };
}
pub mod address;
pub mod block_validation;
pub mod blockdata;
pub mod compact_filter;
pub mod consensus_validation;
// Private until we either make this a crate or flatten it - still to be decided.
pub(crate) mod crypto;
pub mod key_expression;
pub mod merkle_tree;
pub mod network;
pub mod policy;
pub mod pow;
pub mod pqhd;

#[doc(inline)]
pub use primitives::{
    block::{
        compute_merkle_root, compute_witness_root, Block, BlockHash, Checked as BlockChecked,
        Header as BlockHeader, InvalidBlockError, Unchecked as BlockUnchecked,
        Validation as BlockValidation, Version as BlockVersion, WitnessCommitment,
    },
    merkle_tree::{TxMerkleNode, WitnessMerkleNode},
    script::{
        RedeemScript, RedeemScriptBuf, RedeemScriptTag, ScriptHashableTag, ScriptPubKey,
        ScriptPubKeyBuf, ScriptPubKeyTag, ScriptSig, ScriptSigBuf, ScriptSigTag, Tag,
        WitnessScript, WitnessScriptBuf, WitnessScriptTag,
    },
    transaction::{OutPoint, Transaction, TxIn, TxOut, Txid, Version as TransactionVersion, Wtxid},
    witness::Witness,
};
#[doc(inline)]
pub use units::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::FeeRate,
    parse_int,
    pow::CompactTarget,
    result::{self, NumOpResult},
    sequence::{self, Sequence},
    time::{self, BlockTime, BlockTimeDecoder, BlockTimeDecoderError},
    weight::Weight,
};

#[doc(inline)]
pub use crate::{
    address::{Address, AddressType, KnownHrp},
    crypto::key::{
        self, FromPqWifError, MismatchedPqPublicKeyError, PqWifFormat, PqWifKey, PubkeyHash,
        UnsupportedLegacyWifSchemeError, WPubkeyHash,
    },
    crypto::pq::{
        MlKem512Ciphertext, MlKem512Keypair, MlKem512PublicKey, MlKem512SecretKey,
        MlKem512SharedSecret, PqError, PqPublicKey, PqScheme, PqSchemeCryptoExt, PqSecretKey,
        PqSignature,
    },
    key_expression::{
        KeyIndex, PqhdDescriptor, PqhdKeyExpression, PqhdKeyPathInfo, WalletOutputType,
    },
    network::params::{self, Params},
    network::{Network, NetworkKind},
    pow::{Target, Work},
    pqhd::{LeafMaterialV1 as PqhdLeafMaterialV1, Node as PqhdNode, SeedId as PqhdSeedId},
};
#[doc(inline)]
pub use consensus_core::{
    InputsIndexError, LegacySighash, NonStandardSighashTypeError, SegwitV0Sighash, Sighash512,
    SighashTypeParseError, TxSighashType,
};
// Re-export all modules from `blockdata`, users should never need to use `blockdata` directly.
#[doc(inline)]
pub use crate::{
    // Also, re-export types and modules from `blockdata` that don't come from `primitives`.
    blockdata::locktime::{absolute, relative},
    blockdata::opcodes::{self, Opcode},
    blockdata::script::witness_program::{self, WitnessProgram},
    blockdata::script::witness_version::{self, WitnessVersion},
    // These modules also re-export all the respective `primitives` types.
    blockdata::{block, constants, fee_rate, locktime, script, transaction, weight, witness},
};

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(not(feature = "std"))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(all(not(feature = "std"), target_has_atomic = "ptr"))]
    pub use alloc::sync;

    #[cfg(feature = "std")]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, rc, sync};

    #[cfg(not(feature = "std"))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(feature = "std")]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    pub use crate::io::sink;

    pub use internals::hex::DisplayHex;
}

pub mod amount {
    //! Tidecoin amounts.
    //!
    //! This module mainly introduces the [`Amount`] and [`SignedAmount`] types.
    //! We refer to the documentation on the types for more information.

    #[rustfmt::skip]            // Keep public re-exports separate.
    #[cfg(feature = "serde")]
    pub use units::amount::serde;
    #[doc(inline)]
    pub use units::amount::{Amount, SignedAmount};
    #[doc(no_inline)]
    pub use units::amount::{
        Denomination, Display, OutOfRangeError, ParseAmountError, ParseDenominationError,
        ParseError,
    };

    /// Error types for Tidecoin amounts.
    pub mod error {
        pub use units::amount::error::{
            InputTooLargeError, InvalidCharacterError, MissingDenominationError,
            MissingDigitsError, OutOfRangeError, ParseAmountError, ParseDenominationError,
            ParseError, PossiblyConfusingDenominationError, TooPreciseError,
            UnknownDenominationError,
        };
    }
}
