// SPDX-License-Identifier: CC0-1.0

use core::convert::Infallible;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{ByteVecDecoder, ByteVecDecoderError, Encodable};
use internals::write_err;

use super::{encode_scriptnum, Error, Instruction, Script, ScriptEncoder};
#[cfg(feature = "hex")]
use crate::hex;
use crate::opcodes::all::{
    OP_1, OP_1NEGATE, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    OP_EQUAL, OP_EQUALVERIFY, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_PUSHBYTES_0, OP_PUSHDATA1,
    OP_PUSHDATA2, OP_PUSHDATA4, OP_VERIFY,
};
use crate::opcodes::Opcode;
use crate::prelude::{Box, Vec};

/// An owned, growable script.
///
/// `ScriptBuf` is the most common script type that has the ownership over the contents of the
/// script. It has a close relationship with its borrowed counterpart, [`Script`].
///
/// Just as other similar types, this implements [`Deref`], so [deref coercions] apply. Also note
/// that all the safety/validity restrictions that apply to [`Script`] apply to `ScriptBuf` as well.
///
/// # Hexadecimal strings
///
/// Scripts are consensus encoded with a length prefix and as a result of this in some places in the
/// ecosystem one will encounter hex strings that include the prefix while in other places the
/// prefix is excluded. To support parsing and formatting scripts as hex we provide a bunch of
/// different APIs and trait implementations. Please see the
/// [script example](https://github.com/tidecoin/rust-tidecoin/blob/main/tidecoin/examples/script.rs) for a thorough
/// example of all the APIs.
///
/// [deref coercions]: https://doc.rust-lang.org/std/ops/trait.Deref.html#more-on-deref-coercion
///
/// # Panics
///
/// `ScriptBuf` is backed by [`Vec`] and inherits its panic behavior. This means that attempting to
/// construct scripts larger than `isize::MAX` bytes will panic.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct ScriptBuf<T>(PhantomData<T>, Vec<u8>);

impl<T> ScriptBuf<T> {
    /// Constructs a new empty script.
    #[inline]
    pub const fn new() -> Self {
        Self::from_bytes(Vec::new())
    }

    /// Converts byte vector into script.
    ///
    /// This method doesn't (re)allocate. `bytes` is just the script bytes **not** consensus
    /// encoding (i.e no length prefix).
    #[inline]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(PhantomData, bytes)
    }

    /// Constructs a new [`ScriptBuf`] from a hex string.
    ///
    /// The input string is expected to be consensus encoded i.e., includes the length prefix.
    ///
    /// # Errors
    ///
    /// * If `s` cannot be parsed into a vector.
    /// * If the parsed bytes cannot be decoded as a valid script (incl.the length prefix).
    #[cfg(feature = "hex")]
    pub fn from_hex_prefixed(s: &str) -> Result<Self, FromHexError> {
        let v = hex::decode_to_vec(s)?;
        Ok(encoding::decode_from_slice(&v)?)
    }

    /// Constructs a new [`ScriptBuf`] from a hex string.
    ///
    /// This is **not** consensus encoding. If your hex string is a consensus encoded script
    /// then use `ScriptBuf::from_hex_prefixed`.
    ///
    /// There is no script decoding error path because what ever is in the hex input string is
    /// assumed to be the script. This means if you pass a consensus encoded hex string into this
    /// function there will be no error and the script will not be what you expect.
    ///
    /// # Errors
    ///
    /// Errors if `s` cannot be parsed into a vector.
    #[cfg(feature = "hex")]
    pub fn from_hex_no_length_prefix(s: &str) -> Result<Self, hex::DecodeVariableLengthBytesError> {
        let v = hex::decode_to_vec(s)?;
        Ok(Self::from_bytes(v))
    }

    /// Returns a reference to unsized script.
    #[inline]
    pub fn as_script(&self) -> &Script<T> {
        Script::from_bytes(&self.1)
    }

    /// Returns a mutable reference to unsized script.
    #[inline]
    pub fn as_mut_script(&mut self) -> &mut Script<T> {
        Script::from_bytes_mut(&mut self.1)
    }

    /// Converts the script into a byte vector.
    ///
    /// This method doesn't (re)allocate.
    ///
    /// # Returns
    ///
    /// Just the script bytes **not** consensus encoding (which includes a length prefix).
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.1
    }

    /// Converts this `ScriptBuf` into a [boxed](Box) [`Script`].
    ///
    /// This method reallocates if the capacity is greater than length of the script but should not
    /// when they are equal. If you know beforehand that you need to create a script of exact size
    /// use [`reserve_exact`](Self::reserve_exact) before adding data to the script so that the
    /// reallocation can be avoided.
    #[must_use]
    #[inline]
    pub fn into_boxed_script(self) -> Box<Script<T>> {
        Script::from_boxed_bytes(self.into_bytes().into_boxed_slice())
    }

    /// Constructs a new empty script with at least the specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_bytes(Vec::with_capacity(capacity))
    }

    /// Pre-allocates at least `additional_len` bytes if needed.
    ///
    /// Reserves capacity for at least `additional_len` more bytes to be inserted in the given
    /// script. The script may reserve more space to speculatively avoid frequent reallocations.
    /// After calling `reserve`, capacity will be greater than or equal to
    /// `self.len() + additional_len`. Does nothing if capacity is already sufficient.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX bytes`.
    #[inline]
    pub fn reserve(&mut self, additional_len: usize) {
        self.1.reserve(additional_len);
    }

    /// Pre-allocates exactly `additional_len` bytes if needed.
    ///
    /// Unlike `reserve`, this will not deliberately over-allocate to speculatively avoid frequent
    /// allocations. After calling `reserve_exact`, capacity will be greater than or equal to
    /// `self.len() + additional`. Does nothing if the capacity is already sufficient.
    ///
    /// Note that the allocator may give the collection more space than it requests. Therefore,
    /// capacity cannot be relied upon to be precisely minimal. Prefer [`reserve`](Self::reserve)
    /// if future insertions are expected.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX bytes`.
    #[inline]
    pub fn reserve_exact(&mut self, additional_len: usize) {
        self.1.reserve_exact(additional_len);
    }

    pub(crate) fn as_byte_vec(&mut self) -> &mut Vec<u8> {
        &mut self.1
    }

    /// Returns the number of **bytes** available for writing without reallocation.
    ///
    /// It is guaranteed that `script.capacity() >= script.len()` always holds.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.1.capacity()
    }

    /// Returns the encoded length for pushing a slice of bytes.
    pub fn reserved_len_for_slice(len: usize) -> usize {
        len + if len < 0x4c {
            1
        } else if len <= 0xff {
            2
        } else if len <= 0xffff {
            3
        } else {
            5
        }
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(&mut self, opcode: Opcode) {
        self.as_byte_vec().push(opcode.to_u8());
    }

    /// Adds instructions to push an integer onto the stack.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NumericOverflow`] when `n` is outside the minimally encodable range.
    pub fn push_int(&mut self, n: i32) -> Result<(), Error> {
        if n == i32::MIN {
            Err(Error::NumericOverflow)
        } else {
            self.push_int_unchecked(n.into());
            Ok(())
        }
    }

    /// Adds instructions to push an unchecked integer onto the stack.
    pub fn push_int_unchecked(&mut self, n: i64) {
        match n {
            -1 => self.push_opcode(OP_1NEGATE),
            0 => self.push_opcode(OP_PUSHBYTES_0),
            1..=16 => self.push_opcode(Opcode::from(n as u8 + (OP_1.to_u8() - 1))),
            _ => self.push_int_non_minimal(n),
        }
    }

    /// Adds instructions to push an integer without numeric-opcode optimization.
    ///
    /// # Panics
    ///
    /// Panics only if the internally encoded script integer somehow exceeds the `PushBytes` limit.
    pub fn push_int_non_minimal(&mut self, data: i64) {
        let buf = encode_scriptnum(data);
        let len = buf.len();
        self.reserve(Self::reserved_len_for_slice(len));
        self.push_slice_no_opt(
            <&super::PushBytes>::try_from(buf.as_slice()).expect("scriptint bytes fit PushBytes"),
        );
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    pub fn push_slice<D: AsRef<[u8]>>(&mut self, data: D) {
        let bytes = data.as_ref();
        if bytes.len() == 1 {
            match bytes[0] {
                0x81 => self.push_opcode(OP_1NEGATE),
                1..=16 => self.push_opcode(Opcode::from(bytes[0] + (OP_1.to_u8() - 1))),
                _ => self.push_slice_non_minimal(data),
            }
        } else {
            self.push_slice_non_minimal(data);
        }
    }

    /// Adds instructions to push arbitrary data without minimal-push optimization.
    ///
    /// # Panics
    ///
    /// Panics only if `data` exceeds the maximum size supported by `PushBytes`.
    pub fn push_slice_non_minimal<D: AsRef<[u8]>>(&mut self, data: D) {
        let data =
            <&super::PushBytes>::try_from(data.as_ref()).expect("push data length fits PushBytes");
        self.reserve(Self::reserved_len_for_slice(data.len()));
        self.push_slice_no_opt(data);
    }

    /// Adds a single instruction.
    pub fn push_instruction(&mut self, instruction: Instruction<'_>) {
        match instruction {
            Instruction::Op(opcode) => self.push_opcode(opcode),
            Instruction::PushBytes(bytes) => self.push_slice(bytes),
        }
    }

    /// Adds an `OP_VERIFY` or rewrites the last opcode to its VERIFY form when possible.
    pub fn scan_and_push_verify(&mut self) {
        match opcode_to_verify(self.last_opcode()) {
            Some(opcode) => {
                self.as_byte_vec().pop();
                self.push_opcode(opcode);
            }
            None => self.push_opcode(OP_VERIFY),
        }
    }

    fn push_slice_no_opt(&mut self, data: &super::PushBytes) {
        let len = data.len();
        let bytes = self.as_byte_vec();
        match len {
            n if n < OP_PUSHDATA1.to_u8() as usize => bytes.push(n as u8),
            n if n <= 0xff => {
                bytes.push(OP_PUSHDATA1.to_u8());
                bytes.push(n as u8);
            }
            n if n <= 0xffff => {
                bytes.push(OP_PUSHDATA2.to_u8());
                bytes.extend_from_slice(&(n as u16).to_le_bytes());
            }
            n => {
                bytes.push(OP_PUSHDATA4.to_u8());
                bytes.extend_from_slice(&(n as u32).to_le_bytes());
            }
        }
        bytes.extend_from_slice(data.as_bytes());
    }
}

fn opcode_to_verify(opcode: Option<Opcode>) -> Option<Opcode> {
    opcode.and_then(|opcode| match opcode {
        OP_EQUAL => Some(OP_EQUALVERIFY),
        OP_NUMEQUAL => Some(OP_NUMEQUALVERIFY),
        OP_CHECKSIG => Some(OP_CHECKSIGVERIFY),
        OP_CHECKMULTISIG => Some(OP_CHECKMULTISIGVERIFY),
        _ => None,
    })
}

// Cannot derive due to generics.
impl<T> Default for ScriptBuf<T> {
    fn default() -> Self {
        Self(PhantomData, Vec::new())
    }
}

impl<T> Deref for ScriptBuf<T> {
    type Target = Script<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_script()
    }
}

impl<T> DerefMut for ScriptBuf<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_script()
    }
}

impl<T> Encodable for ScriptBuf<T> {
    type Encoder<'e>
        = ScriptEncoder<'e>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        self.as_script().encoder()
    }
}

/// The decoder for the [`ScriptBuf`] type.
pub struct ScriptBufDecoder<T>(ByteVecDecoder, PhantomData<T>);

impl<T> ScriptBufDecoder<T> {
    /// Constructs a new [`ScriptBuf`] decoder.
    pub const fn new() -> Self {
        Self(ByteVecDecoder::new(), PhantomData)
    }
}

impl<T> Default for ScriptBufDecoder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> encoding::Decoder for ScriptBufDecoder<T> {
    type Output = ScriptBuf<T>;
    type Error = ScriptBufDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(ScriptBufDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        Ok(ScriptBuf::from_bytes(self.0.end().map_err(ScriptBufDecoderError)?))
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl<T> encoding::Decodable for ScriptBuf<T> {
    type Decoder = ScriptBufDecoder<T>;
    fn decoder() -> Self::Decoder {
        ScriptBufDecoder(ByteVecDecoder::new(), PhantomData)
    }
}

/// An error consensus decoding a `ScriptBuf<T>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptBufDecoderError(ByteVecDecoderError);

impl From<Infallible> for ScriptBufDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for ScriptBufDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ScriptBufDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// An error parsing a script from hex.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg(feature = "hex")]
pub enum FromHexError {
    /// Error parsing the hex input string.
    Hex(hex::DecodeVariableLengthBytesError),
    /// Error when decoding the script.
    Decoder(encoding::DecodeError<ScriptBufDecoderError>),
}

#[cfg(feature = "hex")]
impl From<Infallible> for FromHexError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

#[cfg(feature = "hex")]
impl fmt::Display for FromHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Hex(ref e) => write_err!(f, "script hex"; e),
            Self::Decoder(ref e) => write_err!(f, "script decoder"; e),
        }
    }
}

#[cfg(all(feature = "std", feature = "hex"))]
impl std::error::Error for FromHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Hex(ref e) => Some(e),
            Self::Decoder(ref e) => Some(e),
        }
    }
}

#[cfg(feature = "hex")]
impl From<hex::DecodeVariableLengthBytesError> for FromHexError {
    fn from(e: hex::DecodeVariableLengthBytesError) -> Self {
        Self::Hex(e)
    }
}

#[cfg(feature = "hex")]
impl From<encoding::DecodeError<ScriptBufDecoderError>> for FromHexError {
    fn from(e: encoding::DecodeError<ScriptBufDecoderError>) -> Self {
        Self::Decoder(e)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, T> Arbitrary<'a> for ScriptBuf<T> {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let v = Vec::<u8>::arbitrary(u)?;
        Ok(Self::from_bytes(v))
    }
}

impl<'a, Tg> core::iter::FromIterator<Instruction<'a>> for ScriptBuf<Tg> {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Instruction<'a>>,
    {
        let mut script = Self::new();
        script.extend(iter);
        script
    }
}

impl<'a, Tg> Extend<Instruction<'a>> for ScriptBuf<Tg> {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = Instruction<'a>>,
    {
        let iter = iter.into_iter();
        if iter.size_hint().1.is_some_and(|max| max < 6) {
            let mut iter = iter.fuse();
            let mut head = [None; 5];
            let mut total_size = 0;
            for (head, instr) in head.iter_mut().zip(&mut iter) {
                total_size += instr.script_serialized_len();
                *head = Some(instr);
            }
            assert!(
                iter.next().is_none(),
                "Buggy implementation of `Iterator` on {} returns invalid upper bound",
                core::any::type_name::<T::IntoIter>()
            );
            self.reserve(total_size);
            for instr in head.iter().copied().flatten() {
                match instr {
                    Instruction::Op(opcode) => self.push_opcode(opcode),
                    Instruction::PushBytes(bytes) => self.push_slice_no_opt(bytes),
                }
            }
        } else {
            for instr in iter {
                self.push_instruction(instr);
            }
        }
    }
}
