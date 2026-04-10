// SPDX-License-Identifier: CC0-1.0

//! Tidecoin network messages.
//!
//! This module defines the `NetworkMessage` and `V1NetworkMessage` types that
//! are used for (de)serializing Tidecoin objects for transmission on the network.

use alloc::borrow::{Cow, ToOwned};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{
    self, ArrayDecoder, ArrayEncoder, CompactSizeEncoder, Decoder2, Encoder2, SliceEncoder,
    VecDecoder,
};
use hashes::sha256d;
use internals::write_err;
use primitives::block::{self, HeaderDecoder, HeaderEncoder};
use primitives::transaction;
use units::FeeRate;

use crate::address::{AddrV1Message, AddrV2Message};
use crate::merkle_tree::MerkleBlock;
use crate::{
    bip152, message_blockdata, message_bloom, message_compact_blocks, message_filter,
    message_network, Magic,
};

/// The maximum number of [`super::message_blockdata::Inventory`] items in an `inv` message.
///
/// This limit is not currently enforced by this implementation.
pub const MAX_INV_SIZE: usize = 50_000;

/// Maximum size, in bytes, of an encoded message
/// This by necessity should be larger than `MAX_VEC_SIZE`
pub const MAX_MSG_SIZE: usize = 5_000_000;

/// Serializer for command string
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CommandString(Cow<'static, str>);

impl CommandString {
    /// Converts `&'static str` to `CommandString`
    ///
    /// This is more efficient for string literals than non-static conversions because it avoids
    /// allocation.
    ///
    /// # Errors
    ///
    /// Returns an error if, and only if, the string is
    /// larger than 12 characters in length.
    pub fn try_from_static(s: &'static str) -> Result<Self, CommandStringError> {
        Self::try_from_static_cow(s.into())
    }

    fn try_from_static_cow(cow: Cow<'static, str>) -> Result<Self, CommandStringError> {
        if cow.len() > 12 {
            Err(CommandStringError { cow })
        } else {
            Ok(Self(cow))
        }
    }
}

impl TryFrom<String> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(value.into())
    }
}

impl TryFrom<Box<str>> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: Box<str>) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(String::from(value).into())
    }
}

impl<'a> TryFrom<&'a str> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(value.to_owned().into())
    }
}

impl core::str::FromStr for CommandString {
    type Err = CommandStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_static_cow(s.to_owned().into())
    }
}

impl fmt::Display for CommandString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0.as_ref())
    }
}

impl AsRef<str> for CommandString {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl encoding::Encodable for CommandString {
    type Encoder<'e> = CommandStringEncoder;

    fn encoder(&self) -> Self::Encoder<'_> {
        let mut rawbytes = [0u8; 12];
        let strbytes = self.0.as_bytes();
        debug_assert!(strbytes.len() <= 12);
        rawbytes[..strbytes.len()].copy_from_slice(strbytes);
        CommandStringEncoder::without_length_prefix(rawbytes)
    }
}

impl encoding::Decodable for CommandString {
    type Decoder = CommandStringDecoder;

    fn decoder() -> Self::Decoder {
        CommandStringDecoder { inner: encoding::ArrayDecoder::new() }
    }
}

/// Encoder for the [`CommandString`] type
// We can't use the [`encoder_newtype!`] macro due to the lifetime conflicting
// when constructing the encoder in `V1NetworkMessage`.
pub struct CommandStringEncoder(encoding::ArrayEncoder<12>);

impl CommandStringEncoder {
    /// Constructs an encoder which encodes the command string with no length prefix.
    pub const fn without_length_prefix(arr: [u8; 12]) -> Self {
        Self(encoding::ArrayEncoder::without_length_prefix(arr))
    }
}

impl encoding::Encoder for CommandStringEncoder {
    #[inline]
    fn current_chunk(&self) -> &[u8] {
        self.0.current_chunk()
    }

    #[inline]
    fn advance(&mut self) -> bool {
        self.0.advance()
    }
}

impl encoding::ExactSizeEncoder for CommandStringEncoder {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Decoder for [`CommandString`].
pub struct CommandStringDecoder {
    inner: encoding::ArrayDecoder<12>,
}

impl encoding::Decoder for CommandStringDecoder {
    type Output = CommandString;
    type Error = CommandStringDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes).map_err(CommandStringDecoderError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let rawbytes = self.inner.end().map_err(CommandStringDecoderError::UnexpectedEof)?;
        // Trim null padding from the end.
        let trimmed =
            rawbytes.iter().rposition(|&b| b != 0).map_or(&rawbytes[..0], |i| &rawbytes[..=i]);

        if !trimmed.is_ascii() {
            return Err(CommandStringDecoderError::NotAscii);
        }

        Ok(CommandString(Cow::Owned(unsafe { String::from_utf8_unchecked(trimmed.to_vec()) })))
    }

    fn read_limit(&self) -> usize {
        self.inner.read_limit()
    }
}

/// Error decoding a [`CommandString`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandStringDecoderError {
    /// Unexpected end of data.
    UnexpectedEof(encoding::UnexpectedEofError),
    /// Command string contains non-ASCII characters.
    NotAscii,
}

impl fmt::Display for CommandStringDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected end of data: {}", e),
            Self::NotAscii => write!(f, "command string must be ASCII"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CommandStringDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::NotAscii => None,
        }
    }
}

/// Error returned when a command string is invalid.
///
/// This is currently returned for command strings longer than 12.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommandStringError {
    cow: Cow<'static, str>,
}

impl fmt::Display for CommandStringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "the command string '{}' has length {} which is larger than 12",
            self.cow,
            self.cow.len()
        )
    }
}

impl std::error::Error for CommandStringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// A Network message using the v1 p2p protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1NetworkMessage {
    magic: Magic,
    payload: NetworkMessage,
    payload_len: u32,
    checksum: [u8; 4],
}

/// A v1 message header used to describe the incoming payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1MessageHeader {
    /// The network magic, a unique 4 byte sequence.
    pub magic: Magic,
    /// The "command" used to describe the payload.
    pub command: CommandString,
    /// The length of the payload.
    pub length: u32,
    /// A checksum to the aforementioned data.
    pub checksum: [u8; 4],
}

impl encoding::Encodable for V1MessageHeader {
    type Encoder<'e>
        = V1MessageHeaderEncoder<'e>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        let enc = encoding::Encoder4::new(
            self.magic.encoder(),
            self.command.encoder(),
            encoding::ArrayEncoder::without_length_prefix(self.length.to_le_bytes()),
            encoding::ArrayEncoder::without_length_prefix(self.checksum),
        );

        V1MessageHeaderEncoder::new(enc)
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`V1MessageHeader`] type.
    pub struct V1MessageHeaderEncoder<'e>(
        encoding::Encoder4<
            crate::MagicEncoder<'e>,
            CommandStringEncoder,
            encoding::ArrayEncoder<4>,
            encoding::ArrayEncoder<4>
    >);
}

type V1MessageHeaderInnerDecoder = encoding::Decoder4<
    encoding::ArrayDecoder<4>,
    CommandStringDecoder,
    encoding::ArrayDecoder<4>,
    encoding::ArrayDecoder<4>,
>;

/// The Decoder for `V1MessageHeader`
pub struct V1MessageHeaderDecoder(V1MessageHeaderInnerDecoder);

impl encoding::Decoder for V1MessageHeaderDecoder {
    type Output = V1MessageHeader;
    type Error = V1MessageHeaderDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(V1MessageHeaderDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (magic, command, length, checksum) =
            self.0.end().map_err(V1MessageHeaderDecoderError)?;
        Ok(V1MessageHeader {
            magic: Magic(magic),
            command,
            length: u32::from_le_bytes(length),
            checksum,
        })
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for V1MessageHeader {
    type Decoder = V1MessageHeaderDecoder;
    fn decoder() -> Self::Decoder {
        V1MessageHeaderDecoder(encoding::Decoder4::new(
            encoding::ArrayDecoder::<4>::new(),
            CommandString::decoder(),
            encoding::ArrayDecoder::<4>::new(),
            encoding::ArrayDecoder::<4>::new(),
        ))
    }
}

/// An error consensus decoding a [`V1MessageHeaderDecoderError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1MessageHeaderDecoderError(<V1MessageHeaderInnerDecoder as encoding::Decoder>::Error);

impl fmt::Display for V1MessageHeaderDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        internals::write_err!(f, "message header decoder error"; self.0)
    }
}

/// A Network message using the v2 p2p protocol defined in BIP-0324.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2NetworkMessage {
    payload: NetworkMessage,
}

/// A list of inventory items.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InventoryPayload(pub Vec<message_blockdata::Inventory>);

encoding::encoder_newtype! {
    /// The encoder for an [`InventoryPayload`].
    pub struct InventoryPayloadEncoder<'e>(Encoder2<CompactSizeEncoder, SliceEncoder<'e, message_blockdata::Inventory>>);
}

impl encoding::Encodable for InventoryPayload {
    type Encoder<'e>
        = Encoder2<CompactSizeEncoder, SliceEncoder<'e, message_blockdata::Inventory>>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            CompactSizeEncoder::new(self.0.len()),
            SliceEncoder::without_length_prefix(&self.0),
        )
    }
}

type InventoryInnerDecoder = VecDecoder<message_blockdata::Inventory>;

/// Decoder type for [`InventoryPayload`].
pub struct InventoryPayloadDecoder(InventoryInnerDecoder);

impl encoding::Decoder for InventoryPayloadDecoder {
    type Output = InventoryPayload;
    type Error = InventoryPayloadDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(InventoryPayloadDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        Ok(InventoryPayload(self.0.end().map_err(InventoryPayloadDecoderError)?))
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for InventoryPayload {
    type Decoder = InventoryPayloadDecoder;
    fn decoder() -> Self::Decoder {
        InventoryPayloadDecoder(VecDecoder::<message_blockdata::Inventory>::new())
    }
}

/// An error decoding a [`InventoryPayload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryPayloadDecoderError(<InventoryInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for InventoryPayloadDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for InventoryPayloadDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "inventory payload error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InventoryPayloadDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// A list of legacy p2p address messages.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddrPayload(pub Vec<AddrV1Message>);

encoding::encoder_newtype! {
    /// The encoder for an [`AddrPayload`].
    pub struct AddrPayloadEncoder<'e>(Encoder2<CompactSizeEncoder, SliceEncoder<'e, AddrV1Message>>);
}

impl encoding::Encodable for AddrPayload {
    type Encoder<'e> = AddrPayloadEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        AddrPayloadEncoder::new(Encoder2::new(
            CompactSizeEncoder::new(self.0.len()),
            SliceEncoder::without_length_prefix(&self.0),
        ))
    }
}

type AddrPayloadInnerDecoder = VecDecoder<AddrV1Message>;

/// Decoder type for [`AddrPayload`].
pub struct AddrPayloadDecoder(AddrPayloadInnerDecoder);

impl encoding::Decoder for AddrPayloadDecoder {
    type Output = AddrPayload;
    type Error = AddrPayloadDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(AddrPayloadDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        Ok(AddrPayload(self.0.end().map_err(AddrPayloadDecoderError)?))
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for AddrPayload {
    type Decoder = AddrPayloadDecoder;
    fn decoder() -> Self::Decoder {
        AddrPayloadDecoder(VecDecoder::new())
    }
}

/// An error decoding a [`AddrPayload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrPayloadDecoderError(<AddrPayloadInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for AddrPayloadDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for AddrPayloadDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "addrv1 payload error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddrPayloadDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// A list of v2 address messages.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddrV2Payload(pub Vec<AddrV2Message>);

encoding::encoder_newtype! {
    /// The encoder for an [`AddrV2Payload`].
    pub struct AddrV2PayloadEncoder<'e>(Encoder2<CompactSizeEncoder, SliceEncoder<'e, AddrV2Message>>);
}

impl encoding::Encodable for AddrV2Payload {
    type Encoder<'e>
        = Encoder2<CompactSizeEncoder, SliceEncoder<'e, AddrV2Message>>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            CompactSizeEncoder::new(self.0.len()),
            SliceEncoder::without_length_prefix(&self.0),
        )
    }
}

type AddrV2PayloadInnerDecoder = VecDecoder<AddrV2Message>;

/// Decoder type for [`AddrV2Payload`].
pub struct AddrV2PayloadDecoder(AddrV2PayloadInnerDecoder);

impl encoding::Decoder for AddrV2PayloadDecoder {
    type Output = AddrV2Payload;
    type Error = AddrV2PayloadDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(AddrV2PayloadDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        Ok(AddrV2Payload(self.0.end().map_err(AddrV2PayloadDecoderError)?))
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for AddrV2Payload {
    type Decoder = AddrV2PayloadDecoder;
    fn decoder() -> Self::Decoder {
        AddrV2PayloadDecoder(VecDecoder::new())
    }
}

/// An error decoding a [`AddrV2Payload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrV2PayloadDecoderError(<AddrV2PayloadInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for AddrV2PayloadDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for AddrV2PayloadDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "addrv2 payload error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddrV2PayloadDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// The `feefilter` message, wrapper around [`FeeRate`] for P2P wire format encoding.
///
/// This message is used to inform peers about the minimum fee rate for transactions
/// that should be relayed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeeFilter(FeeRate);

impl FeeFilter {
    /// Constructs a new `FeeFilter` from a [`FeeRate`].
    pub const fn new(fee_rate: FeeRate) -> Self {
        Self(fee_rate)
    }

    /// Returns the inner [`FeeRate`].
    pub const fn fee_rate(self) -> FeeRate {
        self.0
    }
}

impl From<FeeRate> for FeeFilter {
    fn from(fee_rate: FeeRate) -> Self {
        Self(fee_rate)
    }
}

impl From<FeeFilter> for FeeRate {
    fn from(filter: FeeFilter) -> Self {
        filter.0
    }
}

encoding::encoder_newtype_exact! {
    /// Encoder for [`FeeFilter`] type.
    pub struct FeeFilterEncoder<'e>(encoding::ArrayEncoder<8>);
}

impl encoding::Encodable for FeeFilter {
    type Encoder<'e> = FeeFilterEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        // Encode as sat/kvB in little-endian (BIP 133 wire format).
        let kvb = self.0.to_sat_per_kvb_ceil();
        FeeFilterEncoder::new(encoding::ArrayEncoder::without_length_prefix(kvb.to_le_bytes()))
    }
}

/// Decoder for [`FeeFilter`] type.
pub struct FeeFilterDecoder(encoding::ArrayDecoder<8>);

impl FeeFilterDecoder {
    /// Constructs a new [`FeeFilter`] decoder.
    pub fn new() -> Self {
        Self(encoding::ArrayDecoder::new())
    }
}

impl Default for FeeFilterDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl encoding::Decoder for FeeFilterDecoder {
    type Output = FeeFilter;
    type Error = encoding::UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let array = self.0.end()?;
        let kvb = u64::from_le_bytes(array);

        // BIP-0133 specifies feefilter as int64_t (signed), but negative values and values
        // exceeding u32::MAX are invalid for fee rates. We saturate both cases to FeeRate::MAX.
        let fee_rate = kvb.try_into().ok().map_or(FeeRate::MAX, FeeRate::from_sat_per_kvb);

        Ok(FeeFilter(fee_rate))
    }

    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for FeeFilter {
    type Decoder = FeeFilterDecoder;

    fn decoder() -> Self::Decoder {
        FeeFilterDecoder::new()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FeeFilter {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=3)?;
        match choice {
            0 => Ok(Self(FeeRate::MIN)),
            1 => Ok(Self(FeeRate::BROADCAST_MIN)),
            2 => Ok(Self(FeeRate::DUST)),
            _ => Ok(Self(FeeRate::from_sat_per_kvb(u.int_in_range(0..=u32::MAX)?))),
        }
    }
}

/// Serializer for Ping
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ping(u64);

impl Ping {
    /// Constructs a new [`Ping`] message from nonce.
    pub fn new(nonce: u64) -> Self {
        Self(nonce)
    }
}

encoding::encoder_newtype! {
    /// The encoder for the [`Ping`] type.
    pub struct PingEncoder<'e>(encoding::ArrayEncoder<8>);
}

impl encoding::Encodable for Ping {
    type Encoder<'e>
        = PingEncoder<'e>
    where
        Self: 'e;
    fn encoder(&self) -> Self::Encoder<'_> {
        let nonce = encoding::ArrayEncoder::without_length_prefix(self.0.to_le_bytes());
        PingEncoder::new(nonce)
    }
}

/// The Decoder for [`Ping`]
pub struct PingDecoder(encoding::ArrayDecoder<8>);

impl encoding::Decoder for PingDecoder {
    type Output = Ping;
    type Error = PingDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(PingDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let nonce = self.0.end().map_err(PingDecoderError)?;
        Ok(Ping(u64::from_le_bytes(nonce)))
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for Ping {
    type Decoder = PingDecoder;
    fn decoder() -> Self::Decoder {
        PingDecoder(encoding::ArrayDecoder::<8>::new())
    }
}

/// An error consensus decoding a [`PingDecoderError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingDecoderError(<encoding::ArrayDecoder<8> as encoding::Decoder>::Error);

impl From<Infallible> for PingDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for PingDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        internals::write_err!(f, "ping decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PingDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Serializer for Pong
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pong(u64);

impl Pong {
    /// Construct a response [`Pong`] given a received [`Ping`].
    pub fn from_ping(ping: &Ping) -> Self {
        let nonce = ping.0;
        Self(nonce)
    }
}

encoding::encoder_newtype! {
    /// The encoder for the [`Pong`] type.
    pub struct PongEncoder<'e>(encoding::ArrayEncoder<8>);
}

impl encoding::Encodable for Pong {
    type Encoder<'e>
        = PongEncoder<'e>
    where
        Self: 'e;
    fn encoder(&self) -> Self::Encoder<'_> {
        let nonce = encoding::ArrayEncoder::without_length_prefix(self.0.to_le_bytes());
        PongEncoder::new(nonce)
    }
}

/// The Decoder for [`Pong`]
pub struct PongDecoder(encoding::ArrayDecoder<8>);

impl encoding::Decoder for PongDecoder {
    type Output = Pong;
    type Error = PongDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(PongDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let nonce = self.0.end().map_err(PongDecoderError)?;
        Ok(Pong(u64::from_le_bytes(nonce)))
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for Pong {
    type Decoder = PongDecoder;
    fn decoder() -> Self::Decoder {
        PongDecoder(encoding::ArrayDecoder::<8>::new())
    }
}

/// An error consensus decoding a [`PongDecoderError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PongDecoderError(<encoding::ArrayDecoder<8> as encoding::Decoder>::Error);

impl From<Infallible> for PongDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for PongDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        internals::write_err!(f, "pong decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PongDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// `sendtxrcncl` message (BIP-0330 transaction reconciliation handshake).
#[derive(PartialEq, Eq, Clone, Debug, Copy, PartialOrd, Ord, Hash)]
pub struct SendTxReconciliation {
    /// Transaction reconciliation protocol version.
    pub version: u32,
    /// Salt used for short-ID derivation with this peer.
    pub salt: u64,
}

encoding::encoder_newtype_exact! {
    /// Encoder type for the [`SendTxReconciliation`] message.
    pub struct SendTxReconciliationEncoder<'e>(Encoder2<ArrayEncoder<4>, ArrayEncoder<8>>);
}

impl encoding::Encodable for SendTxReconciliation {
    type Encoder<'e> = SendTxReconciliationEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        SendTxReconciliationEncoder::new(Encoder2::new(
            ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
            ArrayEncoder::without_length_prefix(self.salt.to_le_bytes()),
        ))
    }
}

type SendTxReconciliationInnerDecoder = Decoder2<ArrayDecoder<4>, ArrayDecoder<8>>;

/// Decoder type for the [`SendTxReconciliation`] message.
pub struct SendTxReconciliationDecoder(SendTxReconciliationInnerDecoder);

impl encoding::Decoder for SendTxReconciliationDecoder {
    type Output = SendTxReconciliation;
    type Error = SendTxReconciliationDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(SendTxReconciliationDecoderError)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let (version, salt) = self.0.end().map_err(SendTxReconciliationDecoderError)?;
        Ok(SendTxReconciliation {
            version: u32::from_le_bytes(version),
            salt: u64::from_le_bytes(salt),
        })
    }

    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for SendTxReconciliation {
    type Decoder = SendTxReconciliationDecoder;

    fn decoder() -> Self::Decoder {
        SendTxReconciliationDecoder(Decoder2::new(ArrayDecoder::new(), ArrayDecoder::new()))
    }
}

/// Errors occurring when decoding a [`SendTxReconciliation`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendTxReconciliationDecoderError(
    <SendTxReconciliationInnerDecoder as encoding::Decoder>::Error,
);

impl From<Infallible> for SendTxReconciliationDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for SendTxReconciliationDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "sendtxrcncl error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SendTxReconciliationDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// A Tidecoin network message payload.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NetworkMessage {
    /// `version`
    Version(message_network::VersionMessage),
    /// `verack`
    Verack,
    /// `addr`
    Addr(AddrPayload),
    /// `inv`
    Inv(InventoryPayload),
    /// `getdata`
    GetData(InventoryPayload),
    /// `notfound`
    NotFound(InventoryPayload),
    /// `getblocks`
    GetBlocks(message_blockdata::GetBlocksMessage),
    /// `getheaders`
    GetHeaders(message_blockdata::GetHeadersMessage),
    /// `mempool`
    MemPool,
    /// tx
    Tx(transaction::Transaction),
    /// `block`
    Block(block::Block),
    /// `headers`
    Headers(HeadersMessage),
    /// `sendheaders`
    SendHeaders,
    /// `getaddr`
    GetAddr,
    /// `ping`
    Ping(u64),
    /// `pong`
    Pong(u64),
    /// `merkleblock`
    MerkleBlock(MerkleBlock),
    /// BIP-0037 `filterload`
    FilterLoad(message_bloom::FilterLoad),
    /// BIP-0037 `filteradd`
    FilterAdd(message_bloom::FilterAdd),
    /// BIP-0037 `filterclear`
    FilterClear,
    /// BIP-0157 getcfilters
    GetCFilters(message_filter::GetCFilters),
    /// BIP-0157 cfilter
    CFilter(message_filter::CFilter),
    /// BIP-0157 getcfheaders
    GetCFHeaders(message_filter::GetCFHeaders),
    /// BIP-0157 cfheaders
    CFHeaders(message_filter::CFHeaders),
    /// BIP-0157 getcfcheckpt
    GetCFCheckpt(message_filter::GetCFCheckpt),
    /// BIP-0157 cfcheckpt
    CFCheckpt(message_filter::CFCheckpt),
    /// BIP-0152 sendcmpct
    SendCmpct(message_compact_blocks::SendCmpct),
    /// BIP-0152 cmpctblock
    CmpctBlock(bip152::HeaderAndShortIds),
    /// BIP-0152 getblocktxn
    GetBlockTxn(bip152::BlockTransactionsRequest),
    /// BIP-0152 blocktxn
    BlockTxn(bip152::BlockTransactions),
    /// `alert`
    Alert(message_network::Alert),
    /// `feefilter`
    FeeFilter(FeeFilter),
    /// `wtxidrelay`
    WtxidRelay,
    /// `addrv2`
    AddrV2(AddrV2Payload),
    /// `sendaddrv2`
    SendAddrV2,
    /// `sendtxrcncl`
    SendTxReconciliation(SendTxReconciliation),

    /// Any other message.
    Unknown {
        /// The command of this message.
        command: CommandString,
        /// The payload of this message.
        payload: Vec<u8>,
    },
}

impl NetworkMessage {
    /// Returns the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [`NetworkMessage::Unknown`],
    /// regardless of the actual command in the unknown message.
    /// Use the [`Self::command`] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str {
        match *self {
            Self::Version(_) => "version",
            Self::Verack => "verack",
            Self::Addr(_) => "addr",
            Self::Inv(_) => "inv",
            Self::GetData(_) => "getdata",
            Self::NotFound(_) => "notfound",
            Self::GetBlocks(_) => "getblocks",
            Self::GetHeaders(_) => "getheaders",
            Self::MemPool => "mempool",
            Self::Tx(_) => "tx",
            Self::Block(_) => "block",
            Self::Headers(_) => "headers",
            Self::SendHeaders => "sendheaders",
            Self::GetAddr => "getaddr",
            Self::Ping(_) => "ping",
            Self::Pong(_) => "pong",
            Self::MerkleBlock(_) => "merkleblock",
            Self::FilterLoad(_) => "filterload",
            Self::FilterAdd(_) => "filteradd",
            Self::FilterClear => "filterclear",
            Self::GetCFilters(_) => "getcfilters",
            Self::CFilter(_) => "cfilter",
            Self::GetCFHeaders(_) => "getcfheaders",
            Self::CFHeaders(_) => "cfheaders",
            Self::GetCFCheckpt(_) => "getcfcheckpt",
            Self::CFCheckpt(_) => "cfcheckpt",
            Self::SendCmpct(_) => "sendcmpct",
            Self::CmpctBlock(_) => "cmpctblock",
            Self::GetBlockTxn(_) => "getblocktxn",
            Self::BlockTxn(_) => "blocktxn",
            Self::Alert(_) => "alert",
            Self::FeeFilter(_) => "feefilter",
            Self::WtxidRelay => "wtxidrelay",
            Self::AddrV2(_) => "addrv2",
            Self::SendAddrV2 => "sendaddrv2",
            Self::SendTxReconciliation(_) => "sendtxrcncl",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// Returns the `CommandString` for the message command.
    ///
    /// # Panics
    ///
    /// Panics if the command string is invalid (should never happen for valid message types).
    pub fn command(&self) -> CommandString {
        match *self {
            Self::Unknown { command: ref c, .. } => c.clone(),
            _ => CommandString::try_from_static(self.cmd()).expect("cmd returns valid commands"),
        }
    }
}

impl V1NetworkMessage {
    /// Constructs a new [`V1NetworkMessage`]
    ///
    /// # Panics
    ///
    /// Panics if message encoding fails or if the payload length exceeds `u32::MAX`.
    pub fn new(magic: Magic, payload: NetworkMessage) -> Self {
        let payload_bytes = encode_network_message_payload(&payload);
        let payload_len = payload_bytes.len();
        let payload_len = u32::try_from(payload_len).expect("network message use u32 as length");
        let checksum = sha2_checksum(&payload_bytes);
        Self { magic, payload, payload_len, checksum }
    }

    /// Consumes the [`V1NetworkMessage`] instance and returns the inner payload.
    pub fn into_payload(self) -> NetworkMessage {
        self.payload
    }

    /// The actual message data
    pub fn payload(&self) -> &NetworkMessage {
        &self.payload
    }

    /// Magic bytes to identify the network these messages are meant for
    pub fn magic(&self) -> &Magic {
        &self.magic
    }

    /// Returns the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [`NetworkMessage::Unknown`],
    /// regardless of the actual command in the unknown message.
    /// Use the [`Self::command`] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str {
        self.payload.cmd()
    }

    /// Returns the `CommandString` for the message command.
    pub fn command(&self) -> CommandString {
        self.payload.command()
    }
}

impl V2NetworkMessage {
    /// Constructs a new [`V2NetworkMessage`].
    pub fn new(payload: NetworkMessage) -> Self {
        Self { payload }
    }

    /// Consumes the [`V2NetworkMessage`] instance and returns the inner payload.
    pub fn into_payload(self) -> NetworkMessage {
        self.payload
    }

    /// The actual message data
    pub fn payload(&self) -> &NetworkMessage {
        &self.payload
    }

    /// Returns the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [`NetworkMessage::Unknown`],
    /// regardless of the actual command in the unknown message.
    /// Use the [`Self::command`] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str {
        self.payload.cmd()
    }

    /// Returns the `CommandString` for the message command.
    pub fn command(&self) -> CommandString {
        self.payload.command()
    }
}

fn encode_network_message_payload(msg: &NetworkMessage) -> Vec<u8> {
    match msg {
        NetworkMessage::Version(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::Addr(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::Inv(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::GetData(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::NotFound(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::GetBlocks(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::GetHeaders(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::Tx(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::Block(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::Headers(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::Ping(ref dat) => encoding::encode_to_vec(&Ping(*dat)),
        NetworkMessage::Pong(ref dat) => encoding::encode_to_vec(&Pong(*dat)),
        NetworkMessage::MerkleBlock(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::FilterLoad(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::FilterAdd(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::GetCFilters(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::CFilter(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::GetCFHeaders(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::CFHeaders(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::GetCFCheckpt(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::CFCheckpt(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::SendCmpct(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::CmpctBlock(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::GetBlockTxn(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::BlockTxn(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::Alert(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::FeeFilter(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::AddrV2(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::SendTxReconciliation(ref dat) => encoding::encode_to_vec(dat),
        NetworkMessage::Verack
        | NetworkMessage::SendHeaders
        | NetworkMessage::MemPool
        | NetworkMessage::GetAddr
        | NetworkMessage::WtxidRelay
        | NetworkMessage::FilterClear
        | NetworkMessage::SendAddrV2 => Vec::new(),
        NetworkMessage::Unknown { payload, .. } => payload.clone(),
    }
}

/// Encoder for [`NetworkMessage`] payloads.
pub struct NetworkMessageEncoder {
    buffer: Vec<u8>,
    exhausted: bool,
}

impl NetworkMessageEncoder {
    fn new(msg: &NetworkMessage) -> Self {
        let buffer = encode_network_message_payload(msg);
        Self { buffer, exhausted: false }
    }
}

impl encoding::Encoder for NetworkMessageEncoder {
    fn current_chunk(&self) -> &[u8] {
        if self.exhausted {
            &[]
        } else {
            &self.buffer
        }
    }

    fn advance(&mut self) -> bool {
        self.exhausted = true;
        false
    }
}

impl encoding::Encodable for NetworkMessage {
    type Encoder<'e> = NetworkMessageEncoder;

    fn encoder(&self) -> Self::Encoder<'_> {
        NetworkMessageEncoder::new(self)
    }
}

encoding::encoder_newtype! {
    /// Encoder for [`V1NetworkMessage`].
    pub struct V1NetworkMessageEncoder<'e>(
        encoding::Encoder2<
            encoding::Encoder4<
                encoding::ArrayEncoder<4>,
                CommandStringEncoder,
                encoding::ArrayEncoder<4>,
                encoding::ArrayEncoder<4>,
            >,
            NetworkMessageEncoder,
        >
    );
}

impl encoding::Encodable for V1NetworkMessage {
    type Encoder<'e> = V1NetworkMessageEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        V1NetworkMessageEncoder::new(encoding::Encoder2::new(
            encoding::Encoder4::new(
                encoding::ArrayEncoder::without_length_prefix(self.magic.to_bytes()),
                self.command().encoder(),
                encoding::ArrayEncoder::without_length_prefix(self.payload_len.to_le_bytes()),
                encoding::ArrayEncoder::without_length_prefix(self.checksum),
            ),
            NetworkMessageEncoder::new(&self.payload),
        ))
    }
}

struct NetworkMessageDecoder {
    command: CommandString,
    payload_len: usize,
    buffer: Vec<u8>,
}

impl NetworkMessageDecoder {
    fn new(command: CommandString, payload_len: usize) -> Self {
        Self { command, payload_len, buffer: Vec::new() }
    }
}

fn decode_payload<T: encoding::Decodable>(
    payload_bytes: &[u8],
) -> Result<T, V1NetworkMessageDecoderError> {
    encoding::decode_from_slice(payload_bytes)
        .map_err(|_| V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Payload))
}

impl encoding::Decoder for NetworkMessageDecoder {
    type Output = NetworkMessage;
    type Error = V1NetworkMessageDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        let remaining = self.payload_len - self.buffer.len();
        let copy_len = bytes.len().min(remaining);

        self.buffer.extend_from_slice(&bytes[..copy_len]);
        *bytes = &bytes[copy_len..];

        Ok(self.buffer.len() < self.payload_len)
    }

    #[allow(clippy::too_many_lines)]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let payload_bytes = self.buffer;

        // Validate payload length matches actual data.
        if payload_bytes.len() != self.payload_len {
            return Err(V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Payload));
        }

        let payload = match self.command.as_ref() {
            "version" => NetworkMessage::Version(decode_payload(&payload_bytes)?),
            "verack" => NetworkMessage::Verack,
            "addr" => NetworkMessage::Addr(decode_payload(&payload_bytes)?),
            "inv" => NetworkMessage::Inv(decode_payload(&payload_bytes)?),
            "getdata" => NetworkMessage::GetData(decode_payload(&payload_bytes)?),
            "notfound" => NetworkMessage::NotFound(decode_payload(&payload_bytes)?),
            "getblocks" => NetworkMessage::GetBlocks(decode_payload(&payload_bytes)?),
            "getheaders" => NetworkMessage::GetHeaders(decode_payload(&payload_bytes)?),
            "mempool" => NetworkMessage::MemPool,
            "block" => NetworkMessage::Block(decode_payload(&payload_bytes)?),
            "headers" => NetworkMessage::Headers(decode_payload(&payload_bytes)?),
            "sendheaders" => NetworkMessage::SendHeaders,
            "getaddr" => NetworkMessage::GetAddr,
            "ping" => NetworkMessage::Ping(decode_payload::<Ping>(&payload_bytes)?.0),
            "pong" => NetworkMessage::Pong(decode_payload::<Pong>(&payload_bytes)?.0),
            "merkleblock" => NetworkMessage::MerkleBlock(decode_payload(&payload_bytes)?),
            "filterload" => NetworkMessage::FilterLoad(decode_payload(&payload_bytes)?),
            "filteradd" => NetworkMessage::FilterAdd(decode_payload(&payload_bytes)?),
            "filterclear" => NetworkMessage::FilterClear,
            "getcfilters" => NetworkMessage::GetCFilters(decode_payload(&payload_bytes)?),
            "cfilter" => NetworkMessage::CFilter(decode_payload(&payload_bytes)?),
            "getcfheaders" => NetworkMessage::GetCFHeaders(decode_payload(&payload_bytes)?),
            "cfheaders" => NetworkMessage::CFHeaders(decode_payload(&payload_bytes)?),
            "getcfcheckpt" => NetworkMessage::GetCFCheckpt(decode_payload(&payload_bytes)?),
            "cfcheckpt" => NetworkMessage::CFCheckpt(decode_payload(&payload_bytes)?),
            "sendcmpct" => NetworkMessage::SendCmpct(decode_payload(&payload_bytes)?),
            "cmpctblock" => NetworkMessage::CmpctBlock(decode_payload(&payload_bytes)?),
            "getblocktxn" => NetworkMessage::GetBlockTxn(decode_payload(&payload_bytes)?),
            "blocktxn" => NetworkMessage::BlockTxn(decode_payload(&payload_bytes)?),
            "tx" => NetworkMessage::Tx(decode_payload(&payload_bytes)?),
            "alert" => NetworkMessage::Alert(decode_payload(&payload_bytes)?),
            "feefilter" => NetworkMessage::FeeFilter(decode_payload(&payload_bytes)?),
            "wtxidrelay" => NetworkMessage::WtxidRelay,
            "addrv2" => NetworkMessage::AddrV2(decode_payload(&payload_bytes)?),
            "sendaddrv2" => NetworkMessage::SendAddrV2,
            "sendtxrcncl" => NetworkMessage::SendTxReconciliation(decode_payload(&payload_bytes)?),
            _ => NetworkMessage::Unknown { command: self.command, payload: payload_bytes },
        };

        Ok(payload)
    }

    fn read_limit(&self) -> usize {
        self.payload_len - self.buffer.len()
    }
}

enum DecoderState {
    ReadingHeader {
        header_decoder: encoding::Decoder4<
            encoding::ArrayDecoder<4>,
            CommandStringDecoder,
            encoding::ArrayDecoder<4>,
            encoding::ArrayDecoder<4>,
        >,
    },
    ReadingPayload {
        magic_bytes: [u8; 4],
        payload_len_bytes: [u8; 4],
        checksum: [u8; 4],
        payload_decoder: NetworkMessageDecoder,
    },
}

/// Decoder for [`V1NetworkMessage`].
///
/// This decoder implements a two-phase decoding process for Tidecoin V1 P2P messages.
/// It first decodes the fixed-sized header. It then uses the payload length information
/// to decode the dynamically sized network message.
pub struct V1NetworkMessageDecoder {
    state: DecoderState,
}

impl encoding::Decoder for V1NetworkMessageDecoder {
    type Output = V1NetworkMessage;
    type Error = V1NetworkMessageDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        match &mut self.state {
            DecoderState::ReadingHeader { header_decoder } => {
                let need_more = header_decoder.push_bytes(bytes).map_err(|_| {
                    V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Header)
                })?;

                if !need_more {
                    // Header complete, extract values and transition to payload state.
                    let old_state = core::mem::replace(
                        &mut self.state,
                        DecoderState::ReadingHeader {
                            header_decoder: encoding::Decoder4::new(
                                encoding::ArrayDecoder::new(),
                                CommandStringDecoder { inner: encoding::ArrayDecoder::new() },
                                encoding::ArrayDecoder::new(),
                                encoding::ArrayDecoder::new(),
                            ),
                        },
                    );

                    let DecoderState::ReadingHeader { header_decoder } = old_state else {
                        unreachable!("we are in ReadingHeader state")
                    };

                    let (magic_bytes, command, payload_len_bytes, checksum) =
                        header_decoder.end().map_err(|_| {
                            V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Header)
                        })?;

                    let payload_len = u32::from_le_bytes(payload_len_bytes) as usize;
                    if payload_len > MAX_MSG_SIZE {
                        return Err(V1NetworkMessageDecoderError(
                            V1NetworkMessageDecoderErrorInner::PayloadTooLarge,
                        ));
                    }

                    let payload_decoder = NetworkMessageDecoder::new(command, payload_len);
                    self.state = DecoderState::ReadingPayload {
                        magic_bytes,
                        payload_len_bytes,
                        checksum,
                        payload_decoder,
                    };

                    // Continue with any remaining bytes.
                    return self.push_bytes(bytes);
                }

                Ok(need_more)
            }
            DecoderState::ReadingPayload { payload_decoder, .. } => {
                payload_decoder.push_bytes(bytes)
            }
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.state {
            DecoderState::ReadingHeader { .. } => {
                Err(V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Header))
            }
            DecoderState::ReadingPayload {
                magic_bytes,
                payload_len_bytes,
                checksum,
                payload_decoder,
                ..
            } => {
                let payload = payload_decoder.end()?;
                let expected_checksum = sha2_checksum(&encode_network_message_payload(&payload));
                if expected_checksum != checksum {
                    return Err(V1NetworkMessageDecoderError(
                        V1NetworkMessageDecoderErrorInner::InvalidChecksum,
                    ));
                }

                Ok(V1NetworkMessage {
                    magic: Magic::from_bytes(magic_bytes),
                    payload,
                    payload_len: u32::from_le_bytes(payload_len_bytes),
                    checksum,
                })
            }
        }
    }

    fn read_limit(&self) -> usize {
        match &self.state {
            DecoderState::ReadingHeader { header_decoder } => header_decoder.read_limit(),
            DecoderState::ReadingPayload { payload_decoder, .. } => payload_decoder.read_limit(),
        }
    }
}

impl encoding::Decodable for V1NetworkMessage {
    type Decoder = V1NetworkMessageDecoder;

    fn decoder() -> Self::Decoder {
        V1NetworkMessageDecoder {
            state: DecoderState::ReadingHeader {
                header_decoder: encoding::Decoder4::new(
                    encoding::ArrayDecoder::new(),
                    CommandStringDecoder { inner: encoding::ArrayDecoder::new() },
                    encoding::ArrayDecoder::new(),
                    encoding::ArrayDecoder::new(),
                ),
            },
        }
    }
}

/// Error decoding a raw network message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
enum V1NetworkMessageDecoderErrorInner {
    /// Error decoding the message header.
    Header,
    /// Payload length exceeds maximum allowed message size.
    PayloadTooLarge,
    /// Payload checksum does not match the header.
    InvalidChecksum,
    /// Error decoding the message payload.
    Payload,
}

impl fmt::Display for V1NetworkMessageDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            V1NetworkMessageDecoderErrorInner::Header => {
                write!(f, "error decoding message header")
            }
            V1NetworkMessageDecoderErrorInner::PayloadTooLarge => {
                write!(f, "payload length exceeds maximum allowed message size")
            }
            V1NetworkMessageDecoderErrorInner::InvalidChecksum => {
                write!(f, "payload checksum mismatch")
            }
            V1NetworkMessageDecoderErrorInner::Payload => {
                write!(f, "error decoding message payload")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V1NetworkMessageDecoderError {}

fn encode_v2_network_message_payload(payload: &NetworkMessage) -> Vec<u8> {
    // A subset of message types use a one-byte command ID; the rest use zero followed by the
    // canonical twelve-byte command string.
    let (command_byte, full_command) = match payload {
        NetworkMessage::Addr(_) => (1u8, None),
        NetworkMessage::Block(_) => (2u8, None),
        NetworkMessage::BlockTxn(_) => (3u8, None),
        NetworkMessage::CmpctBlock(_) => (4u8, None),
        NetworkMessage::FeeFilter(_) => (5u8, None),
        NetworkMessage::FilterAdd(_) => (6u8, None),
        NetworkMessage::FilterClear => (7u8, None),
        NetworkMessage::FilterLoad(_) => (8u8, None),
        NetworkMessage::GetBlocks(_) => (9u8, None),
        NetworkMessage::GetBlockTxn(_) => (10u8, None),
        NetworkMessage::GetData(_) => (11u8, None),
        NetworkMessage::GetHeaders(_) => (12u8, None),
        NetworkMessage::Headers(_) => (13u8, None),
        NetworkMessage::Inv(_) => (14u8, None),
        NetworkMessage::MemPool => (15u8, None),
        NetworkMessage::MerkleBlock(_) => (16u8, None),
        NetworkMessage::NotFound(_) => (17u8, None),
        NetworkMessage::Ping(_) => (18u8, None),
        NetworkMessage::Pong(_) => (19u8, None),
        NetworkMessage::SendCmpct(_) => (20u8, None),
        NetworkMessage::Tx(_) => (21u8, None),
        NetworkMessage::GetCFilters(_) => (22u8, None),
        NetworkMessage::CFilter(_) => (23u8, None),
        NetworkMessage::GetCFHeaders(_) => (24u8, None),
        NetworkMessage::CFHeaders(_) => (25u8, None),
        NetworkMessage::GetCFCheckpt(_) => (26u8, None),
        NetworkMessage::CFCheckpt(_) => (27u8, None),
        NetworkMessage::AddrV2(_) => (28u8, None),
        NetworkMessage::Version(_)
        | NetworkMessage::Verack
        | NetworkMessage::SendHeaders
        | NetworkMessage::GetAddr
        | NetworkMessage::Alert(_)
        | NetworkMessage::WtxidRelay
        | NetworkMessage::SendTxReconciliation(_)
        | NetworkMessage::SendAddrV2
        | NetworkMessage::Unknown { .. } => (0u8, Some(payload.command())),
    };

    let mut buffer = vec![command_byte];
    if let Some(cmd) = full_command {
        buffer.extend(encoding::encode_to_vec(&cmd));
    }
    buffer.extend(encode_network_message_payload(payload));
    buffer
}

/// Encoder for [`V2NetworkMessage`].
pub struct V2NetworkMessageEncoder {
    buffer: Vec<u8>,
    exhausted: bool,
}

impl encoding::Encoder for V2NetworkMessageEncoder {
    fn current_chunk(&self) -> &[u8] {
        if self.exhausted {
            &[]
        } else {
            &self.buffer
        }
    }

    fn advance(&mut self) -> bool {
        self.exhausted = true;
        false
    }
}

impl encoding::Encodable for V2NetworkMessage {
    type Encoder<'e> = V2NetworkMessageEncoder;

    fn encoder(&self) -> Self::Encoder<'_> {
        V2NetworkMessageEncoder {
            buffer: encode_v2_network_message_payload(&self.payload),
            exhausted: false,
        }
    }
}

fn decode_v2_payload<T: encoding::Decodable>(
    payload_bytes: &[u8],
) -> Result<T, V2NetworkMessageDecoderError> {
    encoding::decode_from_slice(payload_bytes).map_err(|_| V2NetworkMessageDecoderError)
}

fn decode_empty_v2_payload(payload_bytes: &[u8]) -> Result<(), V2NetworkMessageDecoderError> {
    if payload_bytes.is_empty() {
        Ok(())
    } else {
        Err(V2NetworkMessageDecoderError)
    }
}

fn decode_v2_network_message(bytes: &[u8]) -> Result<NetworkMessage, V2NetworkMessageDecoderError> {
    let (&short_id, payload_bytes) = bytes.split_first().ok_or(V2NetworkMessageDecoderError)?;
    let payload = match short_id {
        0 => {
            let mut payload_bytes = payload_bytes;
            let cmd: CommandString = encoding::decode_from_slice_unbounded(&mut payload_bytes)
                .map_err(|_| V2NetworkMessageDecoderError)?;
            match cmd.as_ref() {
                "version" => NetworkMessage::Version(decode_v2_payload(payload_bytes)?),
                "verack" => {
                    decode_empty_v2_payload(payload_bytes)?;
                    NetworkMessage::Verack
                }
                "sendheaders" => {
                    decode_empty_v2_payload(payload_bytes)?;
                    NetworkMessage::SendHeaders
                }
                "getaddr" => {
                    decode_empty_v2_payload(payload_bytes)?;
                    NetworkMessage::GetAddr
                }
                "alert" => NetworkMessage::Alert(decode_v2_payload(payload_bytes)?),
                "wtxidrelay" => {
                    decode_empty_v2_payload(payload_bytes)?;
                    NetworkMessage::WtxidRelay
                }
                "sendaddrv2" => {
                    decode_empty_v2_payload(payload_bytes)?;
                    NetworkMessage::SendAddrV2
                }
                "sendtxrcncl" => {
                    NetworkMessage::SendTxReconciliation(decode_v2_payload(payload_bytes)?)
                }
                _ => NetworkMessage::Unknown { command: cmd, payload: payload_bytes.to_vec() },
            }
        }
        1 => NetworkMessage::Addr(decode_v2_payload(payload_bytes)?),
        2 => NetworkMessage::Block(decode_v2_payload(payload_bytes)?),
        3 => NetworkMessage::BlockTxn(decode_v2_payload(payload_bytes)?),
        4 => NetworkMessage::CmpctBlock(decode_v2_payload(payload_bytes)?),
        5 => NetworkMessage::FeeFilter(decode_v2_payload(payload_bytes)?),
        6 => NetworkMessage::FilterAdd(decode_v2_payload(payload_bytes)?),
        7 => {
            decode_empty_v2_payload(payload_bytes)?;
            NetworkMessage::FilterClear
        }
        8 => NetworkMessage::FilterLoad(decode_v2_payload(payload_bytes)?),
        9 => NetworkMessage::GetBlocks(decode_v2_payload(payload_bytes)?),
        10 => NetworkMessage::GetBlockTxn(decode_v2_payload(payload_bytes)?),
        11 => NetworkMessage::GetData(decode_v2_payload(payload_bytes)?),
        12 => NetworkMessage::GetHeaders(decode_v2_payload(payload_bytes)?),
        13 => NetworkMessage::Headers(decode_v2_payload(payload_bytes)?),
        14 => NetworkMessage::Inv(decode_v2_payload(payload_bytes)?),
        15 => {
            decode_empty_v2_payload(payload_bytes)?;
            NetworkMessage::MemPool
        }
        16 => NetworkMessage::MerkleBlock(decode_v2_payload(payload_bytes)?),
        17 => NetworkMessage::NotFound(decode_v2_payload(payload_bytes)?),
        18 => NetworkMessage::Ping(decode_v2_payload::<Ping>(payload_bytes)?.0),
        19 => NetworkMessage::Pong(decode_v2_payload::<Pong>(payload_bytes)?.0),
        20 => NetworkMessage::SendCmpct(decode_v2_payload(payload_bytes)?),
        21 => NetworkMessage::Tx(decode_v2_payload(payload_bytes)?),
        22 => NetworkMessage::GetCFilters(decode_v2_payload(payload_bytes)?),
        23 => NetworkMessage::CFilter(decode_v2_payload(payload_bytes)?),
        24 => NetworkMessage::GetCFHeaders(decode_v2_payload(payload_bytes)?),
        25 => NetworkMessage::CFHeaders(decode_v2_payload(payload_bytes)?),
        26 => NetworkMessage::GetCFCheckpt(decode_v2_payload(payload_bytes)?),
        27 => NetworkMessage::CFCheckpt(decode_v2_payload(payload_bytes)?),
        28 => NetworkMessage::AddrV2(decode_v2_payload(payload_bytes)?),
        _ => return Err(V2NetworkMessageDecoderError),
    };
    Ok(payload)
}

/// Decoder for [`V2NetworkMessage`].
#[derive(Debug, Clone)]
pub struct V2NetworkMessageDecoder {
    buffer: Vec<u8>,
}

impl encoding::Decoder for V2NetworkMessageDecoder {
    type Output = V2NetworkMessage;
    type Error = V2NetworkMessageDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.buffer.extend_from_slice(bytes);
        *bytes = &[];
        Ok(true)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        decode_v2_network_message(&self.buffer).map(V2NetworkMessage::new)
    }

    fn read_limit(&self) -> usize {
        MAX_MSG_SIZE.saturating_sub(self.buffer.len())
    }
}

impl encoding::Decodable for V2NetworkMessage {
    type Decoder = V2NetworkMessageDecoder;

    fn decoder() -> Self::Decoder {
        V2NetworkMessageDecoder { buffer: Vec::new() }
    }
}

/// Error decoding a v2 network message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2NetworkMessageDecoderError;

impl fmt::Display for V2NetworkMessageDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("error decoding v2 network message")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V2NetworkMessageDecoderError {}

/// Network encoded [`Header`](primitives::block::Header) with associated byte for the length of
/// transactions that follow, which is currently always zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkHeader {
    /// Block header.
    pub header: block::Header,
    /// Length of transaction list.
    pub length: u8,
}

impl NetworkHeader {
    /// Create a new [`NetworkHeader`] from underlying block header.
    pub const fn from_header(header: block::Header) -> Self {
        Self { header, length: 0 }
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder type for a [`NetworkHeader`].
    pub struct NetworkHeaderEncoder<'e>(Encoder2<HeaderEncoder<'e>, ArrayEncoder<1>>);
}

impl encoding::Encodable for NetworkHeader {
    type Encoder<'e> = NetworkHeaderEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        NetworkHeaderEncoder::new(Encoder2::new(
            self.header.encoder(),
            ArrayEncoder::without_length_prefix([self.length]),
        ))
    }
}

type NetworkHeaderInnerDecoder = Decoder2<HeaderDecoder, ArrayDecoder<1>>;

/// The decoder type for a [`NetworkHeader`].
pub struct NetworkHeaderDecoder(NetworkHeaderInnerDecoder);

impl encoding::Decoder for NetworkHeaderDecoder {
    type Output = NetworkHeader;
    type Error = NetworkHeaderDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(NetworkHeaderDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (header, length) = self.0.end().map_err(NetworkHeaderDecoderError)?;
        Ok(NetworkHeader { header, length: u8::from_le_bytes(length) })
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for NetworkHeader {
    type Decoder = NetworkHeaderDecoder;

    fn decoder() -> Self::Decoder {
        NetworkHeaderDecoder(Decoder2::new(block::Header::decoder(), ArrayDecoder::new()))
    }
}

/// An error decoding a [`NetworkHeader`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkHeaderDecoderError(<NetworkHeaderInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for NetworkHeaderDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for NetworkHeaderDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "network header error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NetworkHeaderDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// A list of tidecoin block headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersMessage(pub Vec<NetworkHeader>);

impl HeadersMessage {
    /// Does each header point to the previous block hash in the list.
    pub fn is_connected(&self) -> bool {
        self.0
            .iter()
            .zip(self.0.iter().skip(1))
            .all(|(first, second)| first.header.block_hash().eq(&second.header.prev_blockhash))
    }

    /// Take the message as an iterator of [`Header`](primitives::block::Header).
    pub fn into_headers(self) -> impl Iterator<Item = block::Header> {
        self.0.into_iter().map(|network| network.header)
    }
}

encoding::encoder_newtype! {
    /// The encoder type for a [`HeadersMessage`].
    pub struct HeadersMessageEncoder<'e>(Encoder2<CompactSizeEncoder, SliceEncoder<'e, NetworkHeader>>);
}

impl encoding::Encodable for HeadersMessage {
    type Encoder<'e> = HeadersMessageEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        HeadersMessageEncoder::new(Encoder2::new(
            CompactSizeEncoder::new(self.0.len()),
            SliceEncoder::without_length_prefix(&self.0),
        ))
    }
}

type HeadersMessageInnerDecoder = VecDecoder<NetworkHeader>;

/// The decoder type for a [`HeadersMessage`].
pub struct HeadersMessageDecoder(HeadersMessageInnerDecoder);

impl encoding::Decoder for HeadersMessageDecoder {
    type Output = HeadersMessage;
    type Error = HeadersMessageDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(HeadersMessageDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let headers = self.0.end().map_err(HeadersMessageDecoderError)?;
        Ok(HeadersMessage(headers))
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for HeadersMessage {
    type Decoder = HeadersMessageDecoder;

    fn decoder() -> Self::Decoder {
        HeadersMessageDecoder(VecDecoder::new())
    }
}

/// An error decoding a [`HeadersMessage`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersMessageDecoderError(<HeadersMessageInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for HeadersMessageDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for HeadersMessageDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "headersmessage error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HeadersMessageDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Data and a 4-byte checksum.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData {
    data: Vec<u8>,
    checksum: [u8; 4],
}

impl CheckedData {
    /// Constructs a new `CheckedData` computing the checksum of given data.
    pub fn new(data: Vec<u8>) -> Self {
        let checksum = sha2_checksum(&data);
        Self { data, checksum }
    }

    /// Returns a reference to the raw data without the checksum.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the raw data without the checksum.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Returns the checksum of the data.
    pub fn checksum(&self) -> [u8; 4] {
        self.checksum
    }
}

/// Does a double-SHA256 on `data` and returns the first 4 bytes.
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = sha256d::hash(data);
    let checksum = checksum.to_byte_array();
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AddrPayload {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(Vec::<AddrV1Message>::arbitrary(u)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AddrV2Payload {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(Vec::<AddrV2Message>::arbitrary(u)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for InventoryPayload {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(Vec::<message_blockdata::Inventory>::arbitrary(u)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CommandString {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary::<String>()?.into()))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for NetworkHeader {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { header: u.arbitrary()?, length: u.arbitrary()? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for HeadersMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for NetworkMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=36)? {
            0 => Ok(Self::Version(u.arbitrary()?)),
            1 => Ok(Self::Verack),
            2 => Ok(Self::Addr(u.arbitrary()?)),
            3 => Ok(Self::Inv(u.arbitrary()?)),
            4 => Ok(Self::GetData(u.arbitrary()?)),
            5 => Ok(Self::NotFound(u.arbitrary()?)),
            6 => Ok(Self::GetBlocks(u.arbitrary()?)),
            7 => Ok(Self::GetHeaders(u.arbitrary()?)),
            8 => Ok(Self::MemPool),
            9 => Ok(Self::Tx(u.arbitrary()?)),
            10 => Ok(Self::Block(u.arbitrary()?)),
            11 => Ok(Self::Headers(u.arbitrary()?)),
            12 => Ok(Self::SendHeaders),
            13 => Ok(Self::GetAddr),
            14 => Ok(Self::Ping(u.arbitrary()?)),
            15 => Ok(Self::Pong(u.arbitrary()?)),
            16 => Ok(Self::MerkleBlock(u.arbitrary()?)),
            17 => Ok(Self::FilterLoad(u.arbitrary()?)),
            18 => Ok(Self::FilterAdd(u.arbitrary()?)),
            19 => Ok(Self::FilterClear),
            20 => Ok(Self::GetCFilters(u.arbitrary()?)),
            21 => Ok(Self::CFilter(u.arbitrary()?)),
            22 => Ok(Self::GetCFHeaders(u.arbitrary()?)),
            23 => Ok(Self::CFHeaders(u.arbitrary()?)),
            24 => Ok(Self::GetCFCheckpt(u.arbitrary()?)),
            25 => Ok(Self::CFCheckpt(u.arbitrary()?)),
            26 => Ok(Self::SendCmpct(u.arbitrary()?)),
            27 => Ok(Self::CmpctBlock(u.arbitrary()?)),
            28 => Ok(Self::GetBlockTxn(u.arbitrary()?)),
            29 => Ok(Self::BlockTxn(u.arbitrary()?)),
            30 => Ok(Self::Alert(u.arbitrary()?)),
            31 => Ok(Self::FeeFilter(u.arbitrary()?)),
            32 => Ok(Self::WtxidRelay),
            33 => Ok(Self::AddrV2(u.arbitrary()?)),
            34 => Ok(Self::SendAddrV2),
            35 => Ok(Self::SendTxReconciliation(u.arbitrary()?)),
            _ => Ok(Self::Unknown { command: u.arbitrary()?, payload: Vec::<u8>::arbitrary(u)? }),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SendTxReconciliation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { version: u.arbitrary()?, salt: u.arbitrary()? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for V1NetworkMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
    }
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;
    use alloc::vec;
    use std::net::Ipv4Addr;

    use hex_unstable::hex;
    use primitives::transaction::{Transaction, Txid};
    use primitives::{Block, BlockHash};
    use units::BlockHeight;

    use super::*;
    use crate::address::{AddrV2, Address};
    use crate::bip152::BlockTransactionsRequest;
    use crate::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
    use crate::message_bloom::{BloomFlags, FilterAdd, FilterLoad};
    use crate::message_compact_blocks::SendCmpct;
    use crate::message_filter::{
        CFCheckpt, CFHeaders, CFilter, FilterHash, FilterHeader, GetCFCheckpt, GetCFHeaders,
        GetCFilters,
    };
    use crate::message_network::{Alert, Reject, RejectReason, VersionMessage};
    use crate::{ProtocolVersion, ServiceFlags};

    fn decode_prefix<T: encoding::Decodable>(
        data: &[u8],
    ) -> Result<(T, usize), <T::Decoder as encoding::Decoder>::Error> {
        let mut remaining = data;
        let value = encoding::decode_from_slice_unbounded(&mut remaining)?;
        Ok((value, data.len() - remaining.len()))
    }

    fn hash(array: [u8; 32]) -> sha256d::Hash {
        sha256d::Hash::from_byte_array(array)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn full_round_ser_der_raw_network_message() {
        let version_msg: VersionMessage = encoding::decode_from_slice(&hex!("721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001")).unwrap();
        let tx: Transaction = encoding::decode_from_slice(&hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000")).unwrap();
        let block: Block = encoding::decode_from_slice(&hex!("00608e2e094d41aecfbcbf8fe70cb60be57516b07db1bafee4c4de5dad760000000000004aec16eab3be95abe9c54e01cf850c14b8c5cad1bc6b2e73e811db5d5998ada404503e66fcff031b4ebd99d701010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3402983a000404503e6604f1f617271083bc3d6600000000000000000007bb1b0a636b706f6f6c0d506f72746c616e642e484f444cffffffff0200f2052a010000001976a9142ce72b25fe97b52638c199acfaa5e3891ddfed5b88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap();
        let header: block::Header = encoding::decode_from_slice(&hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b")).unwrap();
        let script = &hex!("1976a91431a420903c05a0a7de2de40c9f02ebedbacdc17288ac");
        let merkle_block: MerkleBlock = encoding::decode_from_slice(&hex!("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f19630101")).unwrap();
        let cmptblock = encoding::decode_from_slice(&hex!("00000030d923ad36ff2d955abab07f8a0a6e813bc6e066b973e780c5e36674cad5d1cd1f6e265f2a17a0d35cbe701fe9d06e2c6324cfe135f6233e8b767bfa3fb4479b71115dc562ffff7f2006000000000000000000000000010002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0302ee00ffffffff0100f9029500000000015100000000")).unwrap();
        let blocktxn = encoding::decode_from_slice(&hex!("2e93c0cff39ff605020072d96bc3a8d20b8447e294d08092351c8583e08d9b5a01020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402dc0000ffffffff0200f90295000000001976a9142b4569203694fc997e13f2c0a1383b9e16c77a0d88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap();

        let msgs = [
            NetworkMessage::Version(version_msg),
            NetworkMessage::Verack,
            NetworkMessage::Addr(AddrPayload(vec![AddrV1Message {
                time: 45,
                address: Address::new(&([123, 255, 000, 100], 833).into(), ServiceFlags::NETWORK),
            }])),
            NetworkMessage::Inv(InventoryPayload(vec![Inventory::Block(
                BlockHash::from_byte_array(hash([8u8; 32]).to_byte_array()),
            )])),
            NetworkMessage::GetData(InventoryPayload(vec![Inventory::Transaction(
                Txid::from_byte_array(hash([45u8; 32]).to_byte_array()),
            )])),
            NetworkMessage::NotFound(InventoryPayload(vec![Inventory::Error([0u8; 32])])),
            NetworkMessage::GetBlocks(GetBlocksMessage {
                version: ProtocolVersion::from_nonstandard(70001),
                locator_hashes: vec![
                    BlockHash::from_byte_array(hash([1u8; 32]).to_byte_array()),
                    BlockHash::from_byte_array(hash([4u8; 32]).to_byte_array()),
                ],
                stop_hash: BlockHash::from_byte_array(hash([5u8; 32]).to_byte_array()),
            }),
            NetworkMessage::GetHeaders(GetHeadersMessage {
                version: ProtocolVersion::from_nonstandard(70001),
                locator_hashes: vec![
                    BlockHash::from_byte_array(hash([10u8; 32]).to_byte_array()),
                    BlockHash::from_byte_array(hash([40u8; 32]).to_byte_array()),
                ],
                stop_hash: BlockHash::from_byte_array(hash([50u8; 32]).to_byte_array()),
            }),
            NetworkMessage::MemPool,
            NetworkMessage::Tx(tx),
            NetworkMessage::Block(block),
            NetworkMessage::Headers(HeadersMessage(vec![NetworkHeader { header, length: 0 }])),
            NetworkMessage::SendHeaders,
            NetworkMessage::GetAddr,
            NetworkMessage::Ping(15),
            NetworkMessage::Pong(23),
            NetworkMessage::MerkleBlock(merkle_block),
            NetworkMessage::FilterLoad(FilterLoad {
                filter: hex!("03614e9b050000000000000001").to_vec(),
                hash_funcs: 1,
                tweak: 2,
                flags: BloomFlags::All,
            }),
            NetworkMessage::FilterAdd(FilterAdd { data: script.to_vec() }),
            NetworkMessage::FilterAdd(FilterAdd {
                data: hash([29u8; 32]).as_byte_array().to_vec(),
            }),
            NetworkMessage::FilterClear,
            NetworkMessage::GetCFilters(GetCFilters {
                filter_type: 2,
                start_height: BlockHeight::from(52),
                stop_hash: BlockHash::from_byte_array(hash([42u8; 32]).to_byte_array()),
            }),
            NetworkMessage::CFilter(CFilter {
                filter_type: 7,
                block_hash: BlockHash::from_byte_array(hash([25u8; 32]).to_byte_array()),
                filter: vec![1, 2, 3],
            }),
            NetworkMessage::GetCFHeaders(GetCFHeaders {
                filter_type: 4,
                start_height: BlockHeight::from(102),
                stop_hash: BlockHash::from_byte_array(hash([47u8; 32]).to_byte_array()),
            }),
            NetworkMessage::CFHeaders(CFHeaders {
                filter_type: 13,
                stop_hash: BlockHash::from_byte_array(hash([53u8; 32]).to_byte_array()),
                previous_filter_header: FilterHeader::from_byte_array(
                    hash([12u8; 32]).to_byte_array(),
                ),
                filter_hashes: vec![
                    FilterHash::from_byte_array(hash([4u8; 32]).to_byte_array()),
                    FilterHash::from_byte_array(hash([12u8; 32]).to_byte_array()),
                ],
            }),
            NetworkMessage::GetCFCheckpt(GetCFCheckpt {
                filter_type: 17,
                stop_hash: BlockHash::from_byte_array(hash([25u8; 32]).to_byte_array()),
            }),
            NetworkMessage::CFCheckpt(CFCheckpt {
                filter_type: 27,
                stop_hash: BlockHash::from_byte_array(hash([77u8; 32]).to_byte_array()),
                filter_headers: vec![
                    FilterHeader::from_byte_array(hash([3u8; 32]).to_byte_array()),
                    FilterHeader::from_byte_array(hash([99u8; 32]).to_byte_array()),
                ],
            }),
            NetworkMessage::Alert(Alert::final_alert()),
            NetworkMessage::FeeFilter(FeeFilter::from(FeeRate::BROADCAST_MIN)),
            NetworkMessage::WtxidRelay,
            NetworkMessage::AddrV2(AddrV2Payload(vec![AddrV2Message {
                addr: AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 0,
                services: ServiceFlags::NONE,
                time: 0,
            }])),
            NetworkMessage::SendAddrV2,
            NetworkMessage::SendTxReconciliation(SendTxReconciliation {
                version: 1,
                salt: 0x0102_0304_0506_0708,
            }),
            NetworkMessage::CmpctBlock(cmptblock),
            NetworkMessage::GetBlockTxn(BlockTransactionsRequest::from_indices_unchecked(
                BlockHash::from_byte_array(hash([11u8; 32]).to_byte_array()),
                vec![0, 1, 2, 3, 10, 3002],
            )),
            NetworkMessage::BlockTxn(blocktxn),
            NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 8333 }),
        ];

        for msg in &msgs {
            // V1 messages.
            let raw_msg = V1NetworkMessage::new(Magic::from_bytes([57, 0, 0, 0]), msg.clone());
            assert_eq!(
                encoding::decode_from_slice::<V1NetworkMessage>(&encoding::encode_to_vec(&raw_msg))
                    .unwrap(),
                raw_msg
            );

            // V2 messages.
            let v2_msg = V2NetworkMessage::new(msg.clone());
            assert_eq!(
                encoding::decode_from_slice::<V2NetworkMessage>(&encoding::encode_to_vec(&v2_msg))
                    .unwrap(),
                v2_msg
            );
        }
    }

    #[test]
    fn legacy_alert_decodes_explicitly_and_reject_decodes_as_unknown() {
        let alert_payload = encoding::encode_to_vec(&Alert::final_alert());
        let reject_payload = encoding::encode_to_vec(&Reject {
            message: "tx".into(),
            ccode: RejectReason::Duplicate,
            reason: "Cause".into(),
            hash: hash([255u8; 32]),
        });
        let alert_command = CommandString::try_from_static("alert").unwrap();
        let reject_command = CommandString::try_from_static("reject").unwrap();
        let alert_v1 = V1NetworkMessage::new(
            Magic::from_bytes([57, 0, 0, 0]),
            NetworkMessage::Unknown { command: alert_command, payload: alert_payload },
        );
        let reject_v1 = V1NetworkMessage::new(
            Magic::from_bytes([57, 0, 0, 0]),
            NetworkMessage::Unknown { command: reject_command, payload: reject_payload },
        );

        assert_eq!(
            encoding::decode_from_slice::<V1NetworkMessage>(&encoding::encode_to_vec(&alert_v1))
                .unwrap(),
            V1NetworkMessage::new(
                Magic::from_bytes([57, 0, 0, 0]),
                NetworkMessage::Alert(Alert::final_alert()),
            ),
        );
        assert_eq!(
            encoding::decode_from_slice::<V1NetworkMessage>(&encoding::encode_to_vec(&reject_v1))
                .unwrap(),
            reject_v1
        );
    }

    #[test]
    fn commandstring() {
        // Test converting.
        assert_eq!(
            CommandString::try_from_static("AndrewAndrew").unwrap().as_ref(),
            "AndrewAndrew"
        );
        assert!(CommandString::try_from_static("AndrewAndrewA").is_err());

        // Test serializing.
        let cs = CommandString("Andrew".into());
        assert_eq!(
            encoding::encode_to_vec(&cs),
            [0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]
        );

        // Test deserializing
        let cs: Result<CommandString, _> =
            encoding::decode_from_slice(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.as_ref().unwrap().to_string(), "Andrew".to_owned());
        assert_eq!(cs.unwrap(), CommandString::try_from_static("Andrew").unwrap());

        // Test that embedded null bytes are preserved while trailing nulls are trimmed
        let cs: Result<CommandString, _> =
            encoding::decode_from_slice(&[0, 0x41u8, 0x6e, 0x64, 0, 0x72, 0x65, 0x77, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.as_ref().unwrap().to_string(), "\0And\0rew".to_owned());
        assert_eq!(cs.unwrap(), CommandString::try_from_static("\0And\0rew").unwrap());

        // Invalid CommandString, must be ASCII
        assert!(encoding::decode_from_slice::<CommandString>(&[
            0, 0x41u8, 0x6e, 0xa4, 0, 0x72, 0x65, 0x77, 0, 0, 0, 0
        ])
        .is_err());

        // Invalid CommandString, must be 12 bytes
        assert!(encoding::decode_from_slice::<CommandString>(&[
            0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0
        ])
        .is_err());
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_verack() {
        assert_eq!(encoding::encode_to_vec(&V1NetworkMessage::new(Magic::TIDECOIN, NetworkMessage::Verack)),
                       [0xec, 0xfa, 0xce, 0xa5, 0x76, 0x65, 0x72, 0x61,
                        0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_v2_verack() {
        assert_eq!(
            encoding::encode_to_vec(&V2NetworkMessage::new(NetworkMessage::Verack)),
            [
                0x00, // Full command encoding flag.
                0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn roundtrip_encode_decode_ping() {
        let ping = Ping(314);
        let encoded_ping = encoding::encode_to_vec(&ping);
        let decoded_ping = encoding::decode_from_slice::<Ping>(&encoded_ping).unwrap();
        assert_eq!(decoded_ping, ping);
    }

    #[test]
    fn roundtrip_encode_decode_pong() {
        let pong = Pong(314);
        let encoded_pong = encoding::encode_to_vec(&pong);
        let decoded_pong = encoding::decode_from_slice::<Pong>(&encoded_pong).unwrap();
        assert_eq!(decoded_pong, pong);
    }

    #[test]
    fn pong_from_ping_constructors() {
        let ping = Ping::new(314);
        let pong = Pong::from_ping(&ping);
        assert_eq!(pong.0, 314);
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_mempool() {
        assert_eq!(encoding::encode_to_vec(&V1NetworkMessage::new(Magic::TIDECOIN, NetworkMessage::MemPool)),
                       [0xec, 0xfa, 0xce, 0xa5, 0x6d, 0x65, 0x6d, 0x70,
                        0x6f, 0x6f, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_v2_mempool() {
        assert_eq!(
            encoding::encode_to_vec(&V2NetworkMessage::new(NetworkMessage::MemPool)),
            [
                0x0F, // MemPool command short ID
            ]
        );
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_getaddr() {
        assert_eq!(encoding::encode_to_vec(&V1NetworkMessage::new(Magic::TIDECOIN, NetworkMessage::GetAddr)),
                       [0xec, 0xfa, 0xce, 0xa5, 0x67, 0x65, 0x74, 0x61,
                        0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_v2_getaddr() {
        assert_eq!(
            encoding::encode_to_vec(&V2NetworkMessage::new(NetworkMessage::GetAddr)),
            [
                0x00, // Full command encoding flag.
                0x67, 0x65, 0x74, 0x61, 0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn deserialize_getaddr() {
        #[rustfmt::skip]
        let msg = encoding::decode_from_slice(&[
            0xec, 0xfa, 0xce, 0xa5, 0x67, 0x65, 0x74, 0x61,
            0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2
        ]);
        let preimage = V1NetworkMessage::new(Magic::TIDECOIN, NetworkMessage::GetAddr);
        assert!(msg.is_ok());
        let msg: V1NetworkMessage = msg.unwrap();
        assert_eq!(preimage.magic, msg.magic);
        assert_eq!(preimage.payload, msg.payload);
    }

    #[test]
    fn deserialize_v2_getaddr() {
        let msg = encoding::decode_from_slice(&[
            0x00, // Full command encoding flag
            0x67, 0x65, 0x74, 0x61, 0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let preimage = V2NetworkMessage::new(NetworkMessage::GetAddr);
        assert!(msg.is_ok());
        let msg: V2NetworkMessage = msg.unwrap();
        assert_eq!(preimage, msg);
    }

    #[test]
    fn deserialize_version() {
        #[rustfmt::skip]
        let msg = encoding::decode_from_slice::<V1NetworkMessage>(&[
            0xec, 0xfa, 0xce, 0xa5, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
            0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
            0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01
        ]);

        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.magic, Magic::TIDECOIN);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, ProtocolVersion::INVALID_CB_NO_BAN_VERSION);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::WITNESS
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1_548_554_224);
            assert_eq!(version_msg.nonce, 13_952_548_347_456_104_954);
            assert_eq!(version_msg.user_agent.to_string(), "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560_275);
            assert!(version_msg.relay);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn deserialize_v2_version() {
        #[rustfmt::skip]
        let msg = encoding::decode_from_slice::<V2NetworkMessage>(&[
            0x00, // Full command encoding flag
            0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, // "version" command
            0x7f, 0x11, 0x01, 0x00, // version: 70015
            0x0d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // services
            0xf0, 0x0f, 0x4d, 0x5c, 0x00, 0x00, 0x00, 0x00, // timestamp: 1_548_554_224
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // receiver services: NONE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, // addr_recv
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sender services: NONE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr_from
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1, // nonce
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31, 0x2f, // user_agent: "/Satoshi:0.17.1/"
            0x93, 0x8c, 0x08, 0x00, // start_height: 560_275
            0x01 // relay: true
        ]).unwrap();

        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, ProtocolVersion::INVALID_CB_NO_BAN_VERSION);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::WITNESS
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1_548_554_224);
            assert_eq!(version_msg.nonce, 13_952_548_347_456_104_954);
            assert_eq!(version_msg.user_agent.to_string(), "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560_275);
            assert!(version_msg.relay);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn decode_partial_message() {
        #[rustfmt::skip]
        let data = [
            0xec, 0xfa, 0xce, 0xa5, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
            0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
            0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01, 0x00, 0x00
        ];
        let msg = decode_prefix::<V1NetworkMessage>(&data);
        assert!(msg.is_ok());

        let (msg, consumed) = msg.unwrap();
        assert_eq!(consumed, data.to_vec().len() - 2);
        assert_eq!(msg.magic, Magic::TIDECOIN);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, ProtocolVersion::INVALID_CB_NO_BAN_VERSION);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::WITNESS
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1_548_554_224);
            assert_eq!(version_msg.nonce, 13_952_548_347_456_104_954);
            assert_eq!(version_msg.user_agent.to_string(), "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560_275);
            assert!(version_msg.relay);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn headers_message() {
        let block_900_000 = encoding::decode_from_slice::<block::Header>(
            &hex!("00a0ab20247d4d9f582f9750344cdf62c46d81d046be960340960100000000000000000070f96945530651135839d8adc3f40e595118ec74c7ad81a3d17bb022e554fb0c937f4268743702177ad05f92")
        ).unwrap();
        let block_900_001 = encoding::decode_from_slice::<block::Header>(
            &hex!("00e000208a96960d6d1ca4ee4a283fd83da309b8d5d2bfed380501000000000000000000371c9ffd63d75fb36c57d58eb842d23c0e7ec049daf16d94cc38805c346e9d52e880426874370217973dc83b")
        ).unwrap();
        let block_900_002 = encoding::decode_from_slice::<block::Header>(
            &hex!("0400ff3ffc834fac4e1eb2ae41f1f9776e0f8e24a6090603ffa8010000000000000000002efba7e7280aa60f0a650f29e30332d52e11af57bc58cc6e71f343851f016c676182426874370217e3615653")
        ).unwrap();
        let header_900_000 = NetworkHeader { header: block_900_000, length: 0 };
        let header_900_001 = NetworkHeader { header: block_900_001, length: 0 };
        let header_900_002 = NetworkHeader { header: block_900_002, length: 0 };
        let headers_message = HeadersMessage(vec![header_900_000, header_900_001, header_900_002]);
        assert!(headers_message.is_connected());
    }

    #[test]
    fn network_message_decode() {
        use encoding::Decoder;

        let data = hex!("010101010101");

        let mut decoder =
            NetworkMessageDecoder::new(CommandString::try_from_static("unknown").unwrap(), 6);
        let _ = decoder.push_bytes(&mut data.as_slice());
        let decoded = decoder.end().unwrap();

        let enc = encoding::encode_to_vec(&decoded);
        assert_eq!(data.as_slice(), enc.as_slice());
    }

    #[test]
    fn command_string_encoder() {
        use encoding::{Encodable as _, ExactSizeEncoder as _};

        let cmd = CommandString::try_from_static("version").unwrap();
        let expected_bytes: [u8; 12] = [b'v', b'e', b'r', b's', b'i', b'o', b'n', 0, 0, 0, 0, 0];

        let mut encoder = cmd.encoder();
        assert_eq!(encoder.len(), expected_bytes.len());

        let encoded = encoding::flush_to_vec(&mut encoder);
        assert_eq!(encoder.len(), 0);
        assert_eq!(encoded, expected_bytes);
    }
}
