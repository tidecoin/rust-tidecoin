// SPDX-License-Identifier: CC0-1.0

use core::fmt;
use core::ops::{
    Bound, Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo,
    RangeToInclusive,
};

use crate::prelude::{Borrow, BorrowMut, ToOwned, Vec};

#[cfg(any(target_pointer_width = "16", target_pointer_width = "32"))]
fn check_limit(_: usize) -> Result<(), PushBytesError> {
    Ok(())
}

#[cfg(not(any(target_pointer_width = "16", target_pointer_width = "32")))]
fn check_limit(len: usize) -> Result<(), PushBytesError> {
    if len < 0x0001_0000_0000 {
        Ok(())
    } else {
        Err(PushBytesError { len })
    }
}

internals::transparent_newtype! {
    /// Byte slices that can be pushed into script.
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct PushBytes([u8]);

    impl PushBytes {
        fn from_slice_unchecked(bytes: &_) -> &Self;
        fn from_mut_slice_unchecked(bytes: &mut _) -> &mut Self;
    }
}

impl PushBytes {
    /// Constructs an empty `&PushBytes`.
    pub fn empty() -> &'static Self {
        Self::from_slice_unchecked(&[])
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the underlying mutable bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the number of bytes in the slice.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Returns whether the slice is empty.
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Decodes a minimal script integer with the standard 4-byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptIntError`] when the encoding is non-minimal or overflows the 4-byte bound.
    ///
    /// # Panics
    ///
    /// Panics only if the internal 4-byte bound invariant is violated.
    pub fn read_scriptint(&self) -> Result<i32, ScriptIntError> {
        let ret = self.read_scriptint_internal(4)?;
        Ok(i32::try_from(ret).expect("4 bytes or less fits in i32"))
    }

    /// Decodes a minimal script integer with the CHECKLOCKTIMEVERIFY 5-byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptIntError`] when the encoding is non-minimal or overflows the 5-byte bound.
    pub fn read_cltv_scriptint(&self) -> Result<i64, ScriptIntError> {
        self.read_scriptint_internal(5)
    }

    fn read_scriptint_internal(&self, max_size: usize) -> Result<i64, ScriptIntError> {
        super::read_scriptnum(self.as_bytes(), true, max_size)
    }
}

macro_rules! delegate_index {
    ($($type:ty),* $(,)?) => {
        $(
            impl Index<$type> for PushBytes {
                type Output = Self;

                #[inline]
                #[track_caller]
                fn index(&self, index: $type) -> &Self::Output {
                    Self::from_slice_unchecked(&self.0[index])
                }
            }

            impl IndexMut<$type> for PushBytes {
                #[inline]
                #[track_caller]
                fn index_mut(&mut self, index: $type) -> &mut Self::Output {
                    Self::from_mut_slice_unchecked(&mut self.0[index])
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

impl Index<usize> for PushBytes {
    type Output = u8;

    #[inline]
    #[track_caller]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for PushBytes {
    #[inline]
    #[track_caller]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a PushBytes {
    type Error = PushBytesError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        check_limit(bytes.len())?;
        Ok(PushBytes::from_slice_unchecked(bytes))
    }
}

impl<'a> TryFrom<&'a mut [u8]> for &'a mut PushBytes {
    type Error = PushBytesError;

    fn try_from(bytes: &'a mut [u8]) -> Result<Self, Self::Error> {
        check_limit(bytes.len())?;
        Ok(PushBytes::from_mut_slice_unchecked(bytes))
    }
}

macro_rules! from_array {
    ($($len:literal),* $(,)?) => {
        $(
            impl<'a> From<&'a [u8; $len]> for &'a PushBytes {
                fn from(bytes: &'a [u8; $len]) -> Self {
                    const _: () = [(); 1][($len >= 0x100000000u64) as usize];
                    PushBytes::from_slice_unchecked(bytes)
                }
            }

            impl<'a> From<&'a mut [u8; $len]> for &'a mut PushBytes {
                fn from(bytes: &'a mut [u8; $len]) -> Self {
                    PushBytes::from_mut_slice_unchecked(bytes)
                }
            }

            impl AsRef<PushBytes> for [u8; $len] {
                fn as_ref(&self) -> &PushBytes { self.into() }
            }

            impl AsMut<PushBytes> for [u8; $len] {
                fn as_mut(&mut self) -> &mut PushBytes { self.into() }
            }

            impl From<[u8; $len]> for PushBytesBuf {
                fn from(bytes: [u8; $len]) -> Self { PushBytesBuf(Vec::from(&bytes)) }
            }

            impl<'a> From<&'a [u8; $len]> for PushBytesBuf {
                fn from(bytes: &'a [u8; $len]) -> Self { PushBytesBuf(Vec::from(bytes)) }
            }
        )*
    }
}

// Sizes up to 76 cover common pubkey/signature pushes and preserve prior Tidecoin ergonomics.
from_array! {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
    71, 72, 73, 74, 75, 76
}

/// Owned script-push bytes.
#[derive(Default, Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PushBytesBuf(Vec<u8>);

impl PushBytesBuf {
    /// Constructs an empty buffer.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Constructs an empty buffer with reserved capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Reserves additional capacity.
    pub fn reserve(&mut self, additional_capacity: usize) {
        self.0.reserve(additional_capacity);
    }

    /// Appends a byte.
    ///
    /// # Errors
    ///
    /// Returns [`PushBytesError`] when the buffer would exceed the maximum supported length.
    pub fn push(&mut self, byte: u8) -> Result<(), PushBytesError> {
        check_limit(self.0.len().saturating_add(1))?;
        self.0.push(byte);
        Ok(())
    }

    /// Appends a slice.
    ///
    /// # Errors
    ///
    /// Returns [`PushBytesError`] when the resulting buffer would exceed the maximum supported length.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), PushBytesError> {
        let len = self.0.len().saturating_add(bytes.len());
        check_limit(len)?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    /// Removes the last byte.
    pub fn pop(&mut self) -> Option<u8> {
        self.0.pop()
    }

    /// Removes the byte at `index`.
    #[track_caller]
    pub fn remove(&mut self, index: usize) -> u8 {
        self.0.remove(index)
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Truncates the buffer.
    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    /// Returns the underlying borrowed form.
    pub fn as_push_bytes(&self) -> &PushBytes {
        PushBytes::from_slice_unchecked(&self.0)
    }

    /// Returns the underlying mutable borrowed form.
    pub fn as_mut_push_bytes(&mut self) -> &mut PushBytes {
        PushBytes::from_mut_slice_unchecked(&mut self.0)
    }

    pub(crate) fn inner(&self) -> &Vec<u8> {
        &self.0
    }

    /// Returns the number of bytes in buffer.
    pub fn len(&self) -> usize {
        self.inner().len()
    }

    /// Returns the number of bytes the buffer can contain without reallocating.
    pub fn capacity(&self) -> usize {
        self.inner().capacity()
    }

    /// Returns whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner().is_empty()
    }
}

impl From<PushBytesBuf> for Vec<u8> {
    fn from(value: PushBytesBuf) -> Self {
        value.0
    }
}

impl TryFrom<Vec<u8>> for PushBytesBuf {
    type Error = PushBytesError;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        let _: &PushBytes = vec.as_slice().try_into()?;
        Ok(Self(vec))
    }
}

impl ToOwned for PushBytes {
    type Owned = PushBytesBuf;

    fn to_owned(&self) -> Self::Owned {
        PushBytesBuf(self.0.to_owned())
    }
}

impl AsRef<[u8]> for PushBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for PushBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl AsRef<Self> for PushBytes {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsMut<Self> for PushBytes {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl AsRef<PushBytes> for PushBytesBuf {
    fn as_ref(&self) -> &PushBytes {
        self.as_push_bytes()
    }
}

impl AsMut<PushBytes> for PushBytesBuf {
    fn as_mut(&mut self) -> &mut PushBytes {
        self.as_mut_push_bytes()
    }
}

impl AsRef<[u8]> for PushBytesBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_push_bytes().as_bytes()
    }
}

impl Deref for PushBytesBuf {
    type Target = PushBytes;

    fn deref(&self) -> &Self::Target {
        self.as_push_bytes()
    }
}

impl DerefMut for PushBytesBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_push_bytes()
    }
}

impl Borrow<PushBytes> for PushBytesBuf {
    fn borrow(&self) -> &PushBytes {
        self.as_push_bytes()
    }
}

impl BorrowMut<PushBytes> for PushBytesBuf {
    fn borrow_mut(&mut self) -> &mut PushBytes {
        self.as_mut_push_bytes()
    }
}

/// Error constructing script push bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushBytesError {
    /// Invalid length.
    pub len: usize,
}

impl fmt::Display for PushBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "attempt to prepare {} bytes to be pushed into script but the limit is 2^32-1",
            self.len
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PushBytesError {}

/// Possible errors that can arise from reading a script integer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScriptIntError {
    /// The result is not in range [-2^31 +1...2^31 -1].
    NumericOverflow,
    /// The resulting encoding is non-minimal.
    NonMinimal,
}

impl fmt::Display for ScriptIntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NumericOverflow => f.write_str("script integer outside of valid range"),
            Self::NonMinimal => f.write_str("non-minimal encoded script integer"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ScriptIntError {}
