// SPDX-License-Identifier: CC0-1.0

//! The `ScriptHash` type.

use core::convert::Infallible;
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::hash160;

use crate::script::{Script, ScriptHashableTag, MAX_REDEEM_SCRIPT_SIZE};

/// A 160-bit hash of Tidecoin script bytecode.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScriptHash(hash160::Hash);

super::impl_debug!(ScriptHash);

impl ScriptHash {
    /// Constructs a new `ScriptHash` after first checking the script size.
    ///
    /// # 520-byte limitation on serialized script size
    ///
    /// > Tidecoin P2SH evaluation hashes the serialized script and then pushes that script onto the
    /// > stack for execution, so the serialized script is subject to the same rules as any other
    /// > PUSHDATA operation. No pushed data item may exceed 520 bytes, so a P2SH output cannot be
    /// > spent if the redemption script it refers to is larger than 520 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the script exceeds 520 bytes.
    #[inline]
    pub fn from_script<T>(redeem_script: &Script<T>) -> Result<Self, RedeemScriptSizeError>
    where
        T: ScriptHashableTag,
    {
        if redeem_script.len() > MAX_REDEEM_SCRIPT_SIZE {
            return Err(RedeemScriptSizeError { size: redeem_script.len() });
        }

        // We've just checked the length
        Ok(Self::from_script_unchecked(redeem_script))
    }

    /// Constructs a new `ScriptHash` from any script irrespective of script size.
    ///
    /// If you hash a script that exceeds 520 bytes in size and use it to create a P2SH output
    /// then the output will be unspendable.
    #[inline]
    pub fn from_script_unchecked<T>(script: &Script<T>) -> Self {
        Self(hash160::Hash::hash(script.as_bytes()))
    }
}

/// Error while hashing a redeem script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemScriptSizeError {
    /// Invalid redeem script size (cannot exceed 520 bytes).
    size: usize,
}

impl RedeemScriptSizeError {
    /// Returns the invalid redeem script size.
    pub fn invalid_size(&self) -> usize {
        self.size
    }
}

impl From<Infallible> for RedeemScriptSizeError {
    #[inline]
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for RedeemScriptSizeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "redeem script size exceeds {} bytes: {}", MAX_REDEEM_SCRIPT_SIZE, self.size)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RedeemScriptSizeError {}

// The new hash wrapper type.
type HashType = ScriptHash;
// The inner hash type from `hashes`.
type Inner = hash160::Hash;

include!("./generic.rs");
