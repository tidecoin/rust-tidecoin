// SPDX-License-Identifier: CC0-1.0

//! Compact block filter identity types.

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{ArrayDecoder, ArrayEncoder};
use hashes::{sha256d, HashEngine};
use internals::write_err;

hashes::hash_newtype! {
    /// Filter hash, as defined by the Tidecoin compact-filter protocol.
    pub struct FilterHash(pub sha256d::Hash);
    /// Filter header, as defined by the Tidecoin compact-filter protocol.
    pub struct FilterHeader(pub sha256d::Hash);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(FilterHash, FilterHeader);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(FilterHash, FilterHeader);

impl FilterHash {
    /// Computes the filter hash for serialized compact-filter content.
    pub fn hash_filter_content(content: &[u8]) -> Self {
        Self::from_byte_array(sha256d::Hash::hash(content).to_byte_array())
    }

    /// Computes the filter header from this filter hash and the previous filter header.
    pub fn filter_header(&self, previous_filter_header: FilterHeader) -> FilterHeader {
        let mut engine = sha256d::Hash::engine();
        engine.input(self.as_ref());
        engine.input(previous_filter_header.as_ref());
        FilterHeader(sha256d::Hash::from_engine(engine))
    }
}

encoding::encoder_newtype_exact! {
    /// Encoder type for [`FilterHash`].
    pub struct FilterHashEncoder<'e>(ArrayEncoder<32>);
}

impl encoding::Encodable for FilterHash {
    type Encoder<'e> = FilterHashEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterHashEncoder::new(ArrayEncoder::without_length_prefix(self.to_byte_array()))
    }
}

encoding::encoder_newtype_exact! {
    /// Encoder type for [`FilterHeader`].
    pub struct FilterHeaderEncoder<'e>(ArrayEncoder<32>);
}

impl encoding::Encodable for FilterHeader {
    type Encoder<'e> = FilterHeaderEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterHeaderEncoder::new(ArrayEncoder::without_length_prefix(self.to_byte_array()))
    }
}

type HashInnerDecoder = ArrayDecoder<32>;

/// Decoder for the [`FilterHash`] type.
pub struct FilterHashDecoder(HashInnerDecoder);

impl encoding::Decoder for FilterHashDecoder {
    type Output = FilterHash;
    type Error = FilterHashDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(FilterHashDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let arr = self.0.end().map_err(FilterHashDecoderError)?;
        Ok(FilterHash::from_byte_array(arr))
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for FilterHash {
    type Decoder = FilterHashDecoder;

    fn decoder() -> Self::Decoder {
        FilterHashDecoder(ArrayDecoder::new())
    }
}

/// Errors occurring when decoding a [`FilterHash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterHashDecoderError(<HashInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for FilterHashDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for FilterHashDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "filterhash error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FilterHashDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Decoder for the [`FilterHeader`] type.
pub struct FilterHeaderDecoder(HashInnerDecoder);

impl encoding::Decoder for FilterHeaderDecoder {
    type Output = FilterHeader;
    type Error = FilterHeaderDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(FilterHeaderDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let arr = self.0.end().map_err(FilterHeaderDecoderError)?;
        Ok(FilterHeader::from_byte_array(arr))
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for FilterHeader {
    type Decoder = FilterHeaderDecoder;

    fn decoder() -> Self::Decoder {
        FilterHeaderDecoder(ArrayDecoder::new())
    }
}

/// Errors occurring when decoding a [`FilterHeader`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterHeaderDecoderError(<HashInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for FilterHeaderDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for FilterHeaderDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "filterheader error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FilterHeaderDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterHash {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterHeader {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_byte_array(u.arbitrary()?))
    }
}
