// SPDX-License-Identifier: CC0-1.0

//! Tidecoin scripts.
//!
//! This module provides the structures and functions needed to support scripts.
//!
//! <details>
//! <summary>What is Tidecoin script</summary>
//!
//! Scripts define Tidecoin's transaction authorization scheme: a signature is formed
//! from a script (the second half of which is defined by a coin to be spent,
//! and the first half provided by the spending transaction), and is valid if and only if
//! the script leaves `TRUE` on the stack after being evaluated. Tidecoin's
//! script is a stack-based assembly language similar in spirit to [Forth].
//!
//! Script is represented as a sequence of bytes on the wire, each byte representing an operation,
//! or data to be pushed on the stack.
//!
//! [Forth]: https://en.wikipedia.org/wiki/Forth_(programming_language)
//! </details>
//!
//! In this library we chose to keep the byte representation in memory and decode opcodes only when
//! processing the script. This is similar to Rust choosing to represent strings as UTF-8-encoded
//! bytes rather than slice of `char`s. In both cases the individual items can have different sizes
//! and forcing them to be larger would waste memory and, in case of Tidecoin script, even some
//! performance (forcing allocations).
//!
//! # `Script` vs `ScriptBuf` vs `Builder`
//!
//! These are the most important types in this module and they are quite similar, so it may seem
//! confusing what the differences are. `Script` is an unsized type much like `str` or `Path` are
//! and `ScriptBuf` is an owned counterpart to `Script` just like `String` is an owned counterpart
//! to `str`.
//!
//! However it is common to construct an owned script and then pass it around. For this case a
//! builder API is more convenient. To support this we provide `Builder` type which is very similar
//! to `ScriptBuf` but its methods take `self` instead of `&mut self` and return `Self`. It also
//! contains a cache that may make some modifications faster. This cache is usually not needed
//! outside of creating the script.
//!
//! At the time of writing there's only one operation using the cache - `push_verify`, so the cache
//! is minimal but we may extend it in the future if needed.

mod borrowed;
mod builder;
mod owned;
mod push_bytes;
pub mod witness_program;
pub mod witness_version;

use core::convert::Infallible;
use core::fmt;

use self::witness_version::WitnessVersion;
use crate::key::WPubkeyHash;
use crate::opcodes::all::*;
use crate::OutPoint;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    borrowed::{ScriptExt, ScriptPubKeyExt, WitnessScriptExt, ScriptSigExt},
    builder::Builder,
    owned::{ScriptBufExt, ScriptPubKeyBufExt},
    push_bytes::PushBytesErrorReport,
};
#[doc(no_inline)]
pub use primitives::script::ScriptBufDecoderError;
#[doc(inline)]
pub use primitives::script::{
    read_scriptbool, read_scriptint_non_minimal, write_scriptint, Instruction, InstructionIndices,
    Instructions, PushBytes, PushBytesBuf, PushBytesError, RedeemScript, RedeemScriptBuf,
    RedeemScriptSizeError, RedeemScriptTag, Script, ScriptBuf, ScriptBufDecoder, ScriptEncoder,
    ScriptHash, ScriptHashableTag, ScriptIntError, ScriptPubKey, ScriptPubKeyBuf, ScriptPubKeyTag,
    ScriptSig, ScriptSigBuf, ScriptSigTag, Tag, WScriptHash, WitnessScript, WitnessScriptBuf,
    WitnessScriptSizeError, WitnessScriptTag,
};

/// Constructs a new [`WitnessScriptBuf`] containing the script code used for spending a P2WPKH output.
///
/// The `scriptCode` follows the witness-v0 signature-hash template.
///
/// While the type returned is [`WitnessScriptBuf`], this is **not** a witness script and
/// should not be used as one. It is a Tidecoin witness-v0 script-code template used
/// in place of a witness script for purposes of sighash computation.
pub fn p2wpkh_script_code(wpkh: WPubkeyHash) -> WitnessScriptBuf {
    Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(wpkh)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Generates witness-program scriptPubkey with a given [`WitnessVersion`] and the program bytes.
/// Does not do any checks on version or program length.
///
/// Convenience method used by `new_p2a`, `new_p2wpkh`, `new_p2wsh`, and `new_p2wsh512`.
pub(crate) fn new_witness_program_unchecked<T: AsRef<[u8]>, Tg>(
    version: WitnessVersion,
    program: T,
) -> ScriptBuf<Tg> {
    let program =
        <&PushBytes>::try_from(program.as_ref()).expect("witness program length fits PushBytes");
    debug_assert!(program.len() >= 2 && program.len() <= 64);
    // In SegWit v0, the program must be either 20 bytes (P2WPKH) or 32 bytes (P2WSH) long.
    debug_assert!(version != WitnessVersion::V0 || program.len() == 20 || program.len() == 32);
    Builder::new().push_opcode(version.into()).push_slice(program).into_script()
}

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Something did a non-minimal push.
    NonMinimalPush,
    /// Some opcode expected a parameter but it was missing or truncated.
    EarlyEndOfScript,
    /// Tried to read an array off the stack as a number when it was more than 4 bytes.
    NumericOverflow,
    /// Cannot find the spent output.
    UnknownSpentOutput(OutPoint),
    /// Cannot serialize the spending transaction.
    Serialization,
}

impl From<Infallible> for Error {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NonMinimalPush => f.write_str("non-minimal datapush"),
            Self::EarlyEndOfScript => f.write_str("unexpected end of script"),
            Self::NumericOverflow => {
                f.write_str("numeric overflow (number on stack larger than 4 bytes)")
            }
            Self::UnknownSpentOutput(ref point) => write!(f, "unknown spent output: {}", point),
            Self::Serialization => {
                f.write_str("can not serialize the spending transaction in Transaction::verify()")
            }
        }
    }
}

impl From<primitives::script::Error> for Error {
    fn from(err: primitives::script::Error) -> Self {
        match err {
            primitives::script::Error::NonMinimalPush => Self::NonMinimalPush,
            primitives::script::Error::EarlyEndOfScript => Self::EarlyEndOfScript,
            primitives::script::Error::NumericOverflow => Self::NumericOverflow,
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NonMinimalPush
            | Self::EarlyEndOfScript
            | Self::NumericOverflow
            | Self::UnknownSpentOutput(_)
            | Self::Serialization => None,
        }
    }
}
