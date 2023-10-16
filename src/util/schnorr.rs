// Rust Tidecoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Schnorr Tidecoin keys.
//!
//! This module provides Schnorr keys used in Tidecoin, reexporting Secp256k1
//! Schnorr key types.
//!

use core::fmt;
use prelude::*;

use secp256k1::{XOnlyPublicKey as _XOnlyPublicKey};

use secp256k1;
use hashes::Hash;
use SchnorrSighashType;

/// Deprecated re-export of [`secp256k1::XOnlyPublicKey`]
#[deprecated(since = "0.28.0", note = "Please use `util::key::XOnlyPublicKey` instead")]
pub type XOnlyPublicKey = _XOnlyPublicKey;



/// A BIP340-341 serialized schnorr signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SchnorrSig {
    /// The underlying schnorr signature
    pub sig: secp256k1::schnorr::Signature,
    /// The corresponding hash type
    pub hash_ty: SchnorrSighashType,
}

impl SchnorrSig {
    /// Deserialize from slice
    pub fn from_slice(sl: &[u8]) -> Result<Self, SchnorrSigError> {
        match sl.len() {
            64 => {
                // default type
                let sig = secp256k1::schnorr::Signature::from_slice(sl)
                    .map_err(SchnorrSigError::Secp256k1)?;
                return Ok( SchnorrSig { sig, hash_ty : SchnorrSighashType::Default });
            },
            65 => {
                let (hash_ty, sig) = sl.split_last().expect("Slice len checked == 65");
                let hash_ty = SchnorrSighashType::from_u8(*hash_ty)
                    .map_err(|_| SchnorrSigError::InvalidSighashType(*hash_ty))?;
                let sig = secp256k1::schnorr::Signature::from_slice(sig)
                    .map_err(SchnorrSigError::Secp256k1)?;
                Ok(SchnorrSig { sig, hash_ty })
            }
            len => {
                Err(SchnorrSigError::InvalidSchnorrSigSize(len))
            }
        }
    }

    /// Serialize SchnorrSig
    pub fn to_vec(&self) -> Vec<u8> {
        // TODO: add support to serialize to a writer to SerializedSig
        let mut ser_sig = self.sig.as_ref().to_vec();
        if self.hash_ty == SchnorrSighashType::Default {
            // default sighash type, don't add extra sighash byte
        } else {
            ser_sig.push(self.hash_ty as u8);
        }
        ser_sig
    }

}

/// A schnorr sig related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum SchnorrSigError {
    /// Base58 encoding error
    InvalidSighashType(u8),
    /// Signature has valid size but does not parse correctly
    Secp256k1(secp256k1::Error),
    /// Invalid schnorr signature size
    InvalidSchnorrSigSize(usize),
}


impl fmt::Display for SchnorrSigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SchnorrSigError::InvalidSighashType(hash_ty) =>
                write!(f, "Invalid signature hash type {}", hash_ty),
            SchnorrSigError::Secp256k1(ref e) =>
                write!(f, "Schnorr Signature has correct len, but is malformed : {}", e),
            SchnorrSigError::InvalidSchnorrSigSize(sz) =>
                write!(f, "Invalid Schnorr signature size: {}", sz),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for SchnorrSigError {}

impl From<secp256k1::Error> for SchnorrSigError {

    fn from(e: secp256k1::Error) -> SchnorrSigError {
        SchnorrSigError::Secp256k1(e)
    }
}
