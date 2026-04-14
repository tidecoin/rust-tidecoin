// SPDX-License-Identifier: CC0-1.0

#[cfg(all(feature = "hex", feature = "alloc"))]
use alloc::string::String;
use core::marker::PhantomData;
use core::ops::{
    Bound, Index, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive,
};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{BytesEncoder, CompactSizeEncoder, Encodable, Encoder2};

use super::{InstructionIndices, Instructions, ScriptBuf};
use crate::opcodes::all::{
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY,
};
use crate::prelude::{Box, ToOwned, Vec};

internals::transparent_newtype! {
    /// Tidecoin script slice.
    ///
    /// *[See also the `script` module](super).*
    ///
    /// `Script` is a script slice, the most primitive script type. It's usually seen in its borrowed
    /// form `&Script`. It is always encoded as a series of bytes representing the opcodes and data
    /// pushes.
    ///
    /// # Validity
    ///
    /// `Script` does not have any validity invariants - it's essentially just a marked slice of
    /// bytes. This is similar to [`Path`](std::path::Path) vs [`OsStr`](std::ffi::OsStr) where they
    /// are trivially cast-able to each-other and `Path` doesn't guarantee being a usable FS path but
    /// having a newtype still has value because of added methods, readability and basic type checking.
    ///
    /// Although at least data pushes could be checked not to overflow the script, bad scripts are
    /// allowed to be in a transaction (outputs just become unspendable) and there even are such
    /// transactions in the chain. Thus we must allow such scripts to be placed in the transaction.
    ///
    /// # Slicing safety
    ///
    /// Slicing is similar to how `str` works: some ranges may be incorrect and indexing by
    /// `usize` is not supported. However, as opposed to `std`, we have no way of checking
    /// correctness without causing linear complexity so there are **no panics on invalid
    /// ranges!** If you supply an invalid range, you'll get a garbled script.
    ///
    /// The range is considered valid if it's at a boundary of instruction. Care must be taken
    /// especially with push operations because you could get a reference to arbitrary
    /// attacker-supplied bytes that look like a valid script.
    ///
    /// It is recommended to use `.instructions()` method to get an iterator over script
    /// instructions and work with that instead.
    ///
    /// # Memory safety
    ///
    /// The type is `#[repr(transparent)]` for internal purposes only!
    /// No consumer crate may rely on the representation of the struct!
    ///
    /// # Hexadecimal strings
    ///
    /// Scripts are consensus encoded with a length prefix and as a result of this in some places in
    /// the ecosystem one will encounter hex strings that include the prefix while in other places
    /// the prefix is excluded. To support parsing and formatting scripts as hex we provide a bunch
    /// of different APIs and trait implementations. Please see [`examples/script.rs`] for a
    /// thorough example of all the APIs.
    ///
    #[derive(PartialOrd, Ord, PartialEq, Eq, Hash)]
    pub struct Script<T>(PhantomData<T>, [u8]);

    impl<T> Script<T> {
        /// Treat byte slice as `Script`
        pub const fn from_bytes(bytes: &_) -> &Self;

        /// Treat mutable byte slice as `Script`
        pub fn from_bytes_mut(bytes: &mut _) -> &mut Self;

        pub(crate) fn from_boxed_bytes(bytes: Box<_>) -> Box<Self>;
        pub(crate) fn from_rc_bytes(bytes: Rc<_>) -> Rc<Self>;
        pub(crate) fn from_arc_bytes(bytes: Arc<_>) -> Arc<Self>;
    }
}

impl<T: 'static> Default for &Script<T> {
    #[inline]
    fn default() -> Self {
        Script::new()
    }
}

impl<T> ToOwned for Script<T> {
    type Owned = ScriptBuf<T>;

    #[inline]
    fn to_owned(&self) -> Self::Owned {
        ScriptBuf::from_bytes(self.to_vec())
    }
}

impl<T> Script<T> {
    /// Constructs a new empty script.
    #[inline]
    pub const fn new() -> &'static Self {
        Self::from_bytes(&[])
    }

    /// Returns the script data as a byte slice.
    ///
    /// This is just the script bytes **not** consensus encoding (which includes a length prefix).
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.1
    }

    /// Returns the script data as a mutable byte slice.
    ///
    /// This is just the script bytes **not** consensus encoding (which includes a length prefix).
    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.1
    }

    /// Returns a copy of the script data.
    ///
    /// This is just the script bytes **not** consensus encoding (which includes a length prefix).
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_owned()
    }

    /// Consensus encodes the script as lower-case hex.
    ///
    /// Consensus encoding includes a length prefix. To hex encode without the length prefix use
    /// `to_hex_string_no_length_prefix`.
    #[cfg(all(feature = "hex", feature = "alloc"))]
    pub fn to_hex_string_prefixed(&self) -> String {
        use internals::hex::{BytesToHexIter, Case};

        let iter = encoding::EncodableByteIter::new(self);
        BytesToHexIter::new(iter, Case::Lower).collect()
    }

    /// Encodes the script as lower-case hex.
    ///
    /// This is **not** consensus encoding. The returned hex string will not include the length
    /// prefix. See `to_hex_string_prefixed`.
    #[cfg(all(feature = "hex", feature = "alloc"))]
    pub fn to_hex_string_no_length_prefix(&self) -> String {
        use internals::hex::DisplayHex as _;

        self.as_bytes().to_lower_hex_string()
    }

    /// Returns the length in bytes of the script.
    #[inline]
    pub const fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Returns whether the script is the empty script.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Converts a [`Box<Script>`](Box) into a [`ScriptBuf`] without copying or allocating.
    #[must_use]
    #[inline]
    pub fn into_script_buf(self: Box<Self>) -> ScriptBuf<T> {
        let rw = Box::into_raw(self) as *mut [u8];
        // SAFETY: copied from `std`
        // The pointer was just created from a box without deallocating
        // Casting a transparent struct wrapping a slice to the slice pointer is sound (same
        // layout).
        let inner = unsafe { Box::from_raw(rw) };
        ScriptBuf::from_bytes(Vec::from(inner))
    }

    /// Iterates over decoded instructions.
    #[inline]
    pub fn instructions(&self) -> Instructions<'_> {
        Instructions::new(self, false)
    }

    /// Iterates over decoded instructions while enforcing minimal pushes.
    #[inline]
    pub fn instructions_minimal(&self) -> Instructions<'_> {
        Instructions::new(self, true)
    }

    /// Counts signature-check operations using accurate multisig counting.
    ///
    /// This is the counting mode used by the node for redeem scripts and
    /// witness scripts. `OP_CHECKSIGADD` is not counted by Tidecoin consensus.
    pub fn count_sigops(&self) -> usize {
        self.count_sigops_internal(true)
    }

    /// Counts signature-check operations using legacy multisig counting.
    ///
    /// This is the counting mode used by the node for scriptSigs and
    /// scriptPubKeys in context-free block sanity checks.
    pub fn count_sigops_legacy(&self) -> usize {
        self.count_sigops_internal(false)
    }

    fn count_sigops_internal(&self, accurate: bool) -> usize {
        let mut count = 0;
        let mut pushnum_cache = None;
        for inst in self.instructions() {
            match inst {
                Ok(super::Instruction::Op(opcode)) => match opcode.to_u8() {
                    x if x == OP_CHECKSIG.to_u8() || x == OP_CHECKSIGVERIFY.to_u8() => {
                        count += 1;
                    }
                    x if x == OP_CHECKMULTISIG.to_u8() || x == OP_CHECKMULTISIGVERIFY.to_u8() => {
                        if accurate {
                            count += pushnum_cache.map_or(20, usize::from);
                        } else {
                            count += 20;
                        }
                    }
                    _ => {
                        pushnum_cache = opcode.decode_pushnum();
                    }
                },
                Ok(super::Instruction::PushBytes(_)) => {
                    pushnum_cache = None;
                }
                Err(_) => break,
            }
        }
        count
    }

    /// Iterates over decoded instructions together with their byte indices.
    #[inline]
    pub fn instruction_indices(&self) -> InstructionIndices<'_> {
        InstructionIndices::new(self, false)
    }

    /// Iterates over decoded instructions and indices while enforcing minimal pushes.
    #[inline]
    pub fn instruction_indices_minimal(&self) -> InstructionIndices<'_> {
        InstructionIndices::new(self, true)
    }

    /// Returns the last opcode if the final instruction is an opcode.
    pub fn last_opcode(&self) -> Option<crate::opcodes::Opcode> {
        match self.instructions().last() {
            Some(Ok(super::Instruction::Op(op))) => Some(op),
            _ => None,
        }
    }

    /// Returns the last pushed byte slice if the final instruction is a data push.
    pub fn last_pushdata(&self) -> Option<&super::PushBytes> {
        match self.instructions().last() {
            Some(Ok(super::Instruction::PushBytes(bytes))) => Some(bytes),
            _ => None,
        }
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`Script<T>`] type.
    pub struct ScriptEncoder<'e>(Encoder2<CompactSizeEncoder, BytesEncoder<'e>>);
}

impl<T> Encodable for Script<T> {
    type Encoder<'e>
        = ScriptEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        ScriptEncoder::new(Encoder2::new(
            CompactSizeEncoder::new(self.as_bytes().len()),
            BytesEncoder::without_length_prefix(self.as_bytes()),
        ))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, T> Arbitrary<'a> for &'a Script<T> {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let v = <&'a [u8]>::arbitrary(u)?;
        Ok(Script::from_bytes(v))
    }
}

macro_rules! delegate_index {
    ($($type:ty),* $(,)?) => {
        $(
            /// Script subslicing operation - read [slicing safety](#slicing-safety)!
            impl<T> Index<$type> for Script<T> {
                type Output = Self;

                #[inline]
                fn index(&self, index: $type) -> &Self::Output {
                    Self::from_bytes(&self.as_bytes()[index])
                }
            }
        )*
    }
}

delegate_index!(
    Range<usize>,
    RangeFrom<usize>,
    RangeTo<usize>,
    RangeFull,
    RangeInclusive<usize>,
    RangeToInclusive<usize>,
    (Bound<usize>, Bound<usize>)
);
