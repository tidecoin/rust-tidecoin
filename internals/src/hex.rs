// SPDX-License-Identifier: CC0-1.0

//! Repo-owned hex formatting helpers.
//!
//! `hex-conservative` 1.x intentionally exposes only stable decoding APIs. The workspace still
//! needs a small no-std formatting and test-literal surface, so that surface lives here instead of
//! keeping a second `hex-conservative` version around.

#[cfg(feature = "alloc")]
use alloc::string::String;
use core::borrow::Borrow;
use core::fmt;
use core::fmt::Write as _;
use core::iter::FusedIterator;
use core::str::Bytes;

#[cfg(feature = "alloc")]
pub use hex::decode_to_vec;
pub use hex::{decode_to_array, DecodeFixedLengthBytesError, DecodeVariableLengthBytesError};

/// Hex letter case used by formatting helpers.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Case {
    /// Lowercase hex.
    Lower,
    /// Uppercase hex.
    Upper,
}

impl Case {
    #[inline]
    const fn table(self) -> &'static [u8; 16] {
        match self {
            Self::Lower => b"0123456789abcdef",
            Self::Upper => b"0123456789ABCDEF",
        }
    }

    #[inline]
    fn prefix(self) -> &'static str {
        match self {
            Self::Lower => "0x",
            Self::Upper => "0x",
        }
    }
}

/// Iterator which encodes bytes as hex characters.
#[derive(Debug, Clone)]
pub struct BytesToHexIter<I> {
    iter: I,
    next_low: Option<char>,
    case: Case,
}

impl<I> BytesToHexIter<I>
where
    I: Iterator,
    I::Item: Borrow<u8>,
{
    /// Constructs a hex-character iterator over `iter`.
    #[inline]
    pub fn new(iter: I, case: Case) -> Self {
        Self { iter, next_low: None, case }
    }
}

impl<I> Iterator for BytesToHexIter<I>
where
    I: Iterator,
    I::Item: Borrow<u8>,
{
    type Item = char;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ch) = self.next_low.take() {
            return Some(ch);
        }

        let byte = *self.iter.next()?.borrow();
        let table = self.case.table();
        self.next_low = Some(table[(byte & 0x0f) as usize] as char);
        Some(table[(byte >> 4) as usize] as char)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let pending = usize::from(self.next_low.is_some());
        let (lower, upper) = self.iter.size_hint();
        (lower.saturating_mul(2) + pending, upper.map(|n| n.saturating_mul(2) + pending))
    }
}

impl<I> FusedIterator for BytesToHexIter<I>
where
    I: FusedIterator,
    I::Item: Borrow<u8>,
{
}

/// Error returned by [`HexToBytesIter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexToBytesIterError {
    /// The string has an odd number of hex characters.
    OddLengthString,
    /// A non-hex character was found.
    InvalidChar {
        /// Invalid byte.
        invalid: u8,
        /// Zero-based byte offset in the input.
        pos: usize,
    },
}

impl fmt::Display for HexToBytesIterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OddLengthString => f.write_str("odd-length hex string"),
            Self::InvalidChar { invalid, pos } => {
                write!(f, "invalid hex character 0x{invalid:02x} at byte {pos}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HexToBytesIterError {}

/// Iterator which decodes a hex string into bytes.
#[derive(Debug, Clone)]
pub struct HexToBytesIter<'a> {
    input: Bytes<'a>,
    pos: usize,
}

impl<'a> HexToBytesIter<'a> {
    /// Constructs a byte iterator over `hex`.
    ///
    /// # Errors
    ///
    /// Returns an error if `hex` has an odd number of characters.
    pub fn new(hex: &'a str) -> Result<Self, HexToBytesIterError> {
        if hex.len() % 2 == 1 {
            Err(HexToBytesIterError::OddLengthString)
        } else {
            Ok(Self { input: hex.bytes(), pos: 0 })
        }
    }
}

impl Iterator for HexToBytesIter<'_> {
    type Item = Result<u8, HexToBytesIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        let high_pos = self.pos;
        let high = self.input.next()?;
        let low_pos = high_pos + 1;
        let low = self.input.next().expect("odd length rejected in constructor");
        self.pos += 2;

        let Some(high) = decode_hex_nibble(high) else {
            return Some(Err(HexToBytesIterError::InvalidChar { invalid: high, pos: high_pos }));
        };
        let Some(low) = decode_hex_nibble(low) else {
            return Some(Err(HexToBytesIterError::InvalidChar { invalid: low, pos: low_pos }));
        };

        Some(Ok((high << 4) | low))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.input.len() / 2;
        (len, Some(len))
    }
}

impl FusedIterator for HexToBytesIter<'_> {}

#[inline]
fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Formats an exact-length byte iterator as hex.
///
/// # Errors
///
/// Returns an error if the formatter fails.
pub fn fmt_hex_exact<I>(
    f: &mut fmt::Formatter,
    byte_len: usize,
    bytes: I,
    case: Case,
) -> fmt::Result
where
    I: IntoIterator,
    I::Item: Borrow<u8>,
{
    let write_pad = |f: &mut fmt::Formatter, pad_len: usize| -> fmt::Result {
        for _ in 0..pad_len {
            f.write_char(f.fill())?;
        }
        Ok(())
    };

    let hex_len = byte_len.saturating_mul(2);
    let extra_len = if f.alternate() { 2 } else { 0 };
    let total_len = hex_len + extra_len;
    let pad_width = f.width().unwrap_or(total_len);
    let trunc_width = f.precision().map_or(hex_len, |v| v.saturating_sub(extra_len));
    let pad_diff = pad_width.saturating_sub(total_len);

    let left_pad = match f.align() {
        Some(fmt::Alignment::Left) => 0,
        Some(fmt::Alignment::Center) => pad_diff / 2,
        Some(fmt::Alignment::Right) => pad_diff,
        None => 0,
    };
    write_pad(f, left_pad)?;

    if f.alternate() {
        f.write_str(case.prefix())?;
    }

    for (i, ch) in BytesToHexIter::new(bytes.into_iter(), case).enumerate() {
        if i >= trunc_width {
            break;
        }
        f.write_char(ch)?;
    }

    write_pad(f, pad_diff.saturating_sub(left_pad))
}

/// Display wrapper returned by [`DisplayHex::as_hex`].
#[derive(Debug, Copy, Clone)]
pub struct HexDisplay<'a> {
    bytes: &'a [u8],
}

impl fmt::LowerHex for HexDisplay<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex_exact(f, self.bytes.len(), self.bytes, Case::Lower)
    }
}

impl fmt::UpperHex for HexDisplay<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex_exact(f, self.bytes.len(), self.bytes, Case::Upper)
    }
}

impl fmt::Display for HexDisplay<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

/// Converts byte containers into a hex display wrapper.
pub trait DisplayHex {
    /// Returns a display wrapper for the bytes.
    fn as_hex(&self) -> HexDisplay<'_>;

    /// Encodes the bytes into a lowercase hex string.
    #[cfg(feature = "alloc")]
    fn to_lower_hex_string(&self) -> String {
        use core::fmt::Write as _;

        let mut ret = String::new();
        write!(&mut ret, "{}", self.as_hex()).expect("writing to a string is infallible");
        ret
    }
}

impl DisplayHex for [u8] {
    #[inline]
    fn as_hex(&self) -> HexDisplay<'_> {
        HexDisplay { bytes: self }
    }
}

impl DisplayHex for &[u8] {
    #[inline]
    fn as_hex(&self) -> HexDisplay<'_> {
        HexDisplay { bytes: self }
    }
}

impl<const N: usize> DisplayHex for [u8; N] {
    #[inline]
    fn as_hex(&self) -> HexDisplay<'_> {
        HexDisplay { bytes: self }
    }
}

#[cfg(feature = "alloc")]
impl DisplayHex for alloc::vec::Vec<u8> {
    #[inline]
    fn as_hex(&self) -> HexDisplay<'_> {
        HexDisplay { bytes: self }
    }
}

/// Formats bytes as exact-length hex.
#[macro_export]
macro_rules! fmt_hex_exact {
    ($formatter:expr, $len:expr, $bytes:expr, $case:expr) => {{
        $crate::hex::fmt_hex_exact($formatter, $len, $bytes, $case)
    }};
}

/// Decodes a hex literal into a byte array, or a hex expression into a vector.
#[macro_export]
macro_rules! hex_lit {
    ($hex:literal) => {{
        match $crate::hex::decode_to_array::<{ $hex.len() / 2 }>($hex) {
            Ok(bytes) => bytes,
            Err(_) => panic!("invalid hex literal"),
        }
    }};
    ($hex:expr) => {{
        match $crate::hex::decode_to_vec($hex) {
            Ok(bytes) => bytes,
            Err(_) => panic!("invalid hex expression"),
        }
    }};
}
