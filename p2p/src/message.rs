// SPDX-License-Identifier: CC0-1.0

//! Tidecoin network messages.
//!
//! This module defines the `NetworkMessage` and `V1NetworkMessage` types that
//! are used for (de)serializing Tidecoin objects for transmission on the network.

use alloc::borrow::{Cow, ToOwned};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{
    self, ArrayDecoder, ArrayEncoder, CompactSizeEncoder, Decodable as _, Decoder as _, Decoder2,
    Encodable as _, Encoder2, SliceEncoder, VecDecoder,
};
use hashes::{sha256d, HashEngine as _};
use internals::write_err;
use primitives::block::{self, HeaderDecoder, HeaderEncoder};
use primitives::transaction;
use units::FeeRate;

use crate::address::{AddrV1Message, AddrV2Message};
use crate::merkle_tree::MerkleBlock;
use crate::{
    compact_blocks, message_blockdata, message_bloom, message_compact_blocks, message_filter,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct V1PayloadFramePlan {
    len: u32,
    checksum: [u8; 4],
}

impl V1PayloadFramePlan {
    fn from_payload(payload: &NetworkMessage) -> Self {
        Self::from_payload_encoder(NetworkMessageEncoder::new(payload))
    }

    fn from_payload_encoder(mut encoder: impl encoding::Encoder) -> Self {
        let mut len = 0usize;
        let mut engine = sha256d::Hash::engine();

        // V1 headers commit to payload length and checksum before the payload bytes.
        // The canonical no-allocation encoder therefore has one explicit frame-planning
        // pass and one emission pass. Buffering the whole payload would be simpler but
        // would regress large-message memory behavior.
        loop {
            let chunk = encoder.current_chunk();
            len = len.saturating_add(chunk.len());
            engine.input(chunk);
            if !encoder.advance() {
                break;
            }
        }

        let checksum = engine.finalize().to_byte_array();
        let len = u32::try_from(len).expect("network message use u32 as length");
        Self { len, checksum: [checksum[0], checksum[1], checksum[2], checksum[3]] }
    }
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

/// A network message using the Tidecoin v2 p2p protocol.
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
        // Encode as sat/kvB in little-endian Tidecoin wire format.
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

        // The wire format stores feefilter as int64_t (signed), but negative values and values
        // exceeding u32::MAX are invalid for fee rates. Saturate both cases to FeeRate::MAX.
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

/// `sendtxrcncl` transaction reconciliation handshake message.
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
    /// `filterload`
    FilterLoad(message_bloom::FilterLoad),
    /// `filteradd`
    FilterAdd(message_bloom::FilterAdd),
    /// `filterclear`
    FilterClear,
    /// `getcfilters`
    GetCFilters(message_filter::GetCFilters),
    /// `cfilter`
    CFilter(message_filter::CFilter),
    /// `getcfheaders`
    GetCFHeaders(message_filter::GetCFHeaders),
    /// `cfheaders`
    CFHeaders(message_filter::CFHeaders),
    /// `getcfcheckpt`
    GetCFCheckpt(message_filter::GetCFCheckpt),
    /// `cfcheckpt`
    CFCheckpt(message_filter::CFCheckpt),
    /// `sendcmpct`
    SendCmpct(message_compact_blocks::SendCmpct),
    /// `cmpctblock`
    CmpctBlock(compact_blocks::HeaderAndShortIds),
    /// `getblocktxn`
    GetBlockTxn(compact_blocks::BlockTransactionsRequest),
    /// `blocktxn`
    BlockTxn(compact_blocks::BlockTransactions),
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
    /// Panics if the payload length exceeds `u32::MAX`.
    pub fn new(magic: Magic, payload: NetworkMessage) -> Self {
        let metadata = V1PayloadFramePlan::from_payload(&payload);
        Self { magic, payload, payload_len: metadata.len, checksum: metadata.checksum }
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

/// Encoder for [`NetworkMessage`] payloads.
#[doc(hidden)]
pub enum NetworkMessageEncoder<'e> {
    Version(<message_network::VersionMessage as encoding::Encodable>::Encoder<'e>),
    Addr(<AddrPayload as encoding::Encodable>::Encoder<'e>),
    Inv(<InventoryPayload as encoding::Encodable>::Encoder<'e>),
    GetData(<InventoryPayload as encoding::Encodable>::Encoder<'e>),
    NotFound(<InventoryPayload as encoding::Encodable>::Encoder<'e>),
    GetBlocks(<message_blockdata::GetBlocksMessage as encoding::Encodable>::Encoder<'e>),
    GetHeaders(<message_blockdata::GetHeadersMessage as encoding::Encodable>::Encoder<'e>),
    Tx(<transaction::Transaction as encoding::Encodable>::Encoder<'e>),
    Block(<block::Block as encoding::Encodable>::Encoder<'e>),
    Headers(<HeadersMessage as encoding::Encodable>::Encoder<'e>),
    Ping(encoding::ArrayEncoder<8>),
    Pong(encoding::ArrayEncoder<8>),
    MerkleBlock(<MerkleBlock as encoding::Encodable>::Encoder<'e>),
    FilterLoad(<message_bloom::FilterLoad as encoding::Encodable>::Encoder<'e>),
    FilterAdd(<message_bloom::FilterAdd as encoding::Encodable>::Encoder<'e>),
    GetCFilters(<message_filter::GetCFilters as encoding::Encodable>::Encoder<'e>),
    CFilter(<message_filter::CFilter as encoding::Encodable>::Encoder<'e>),
    GetCFHeaders(<message_filter::GetCFHeaders as encoding::Encodable>::Encoder<'e>),
    CFHeaders(<message_filter::CFHeaders as encoding::Encodable>::Encoder<'e>),
    GetCFCheckpt(<message_filter::GetCFCheckpt as encoding::Encodable>::Encoder<'e>),
    CFCheckpt(<message_filter::CFCheckpt as encoding::Encodable>::Encoder<'e>),
    SendCmpct(<message_compact_blocks::SendCmpct as encoding::Encodable>::Encoder<'e>),
    CmpctBlock(<compact_blocks::HeaderAndShortIds as encoding::Encodable>::Encoder<'e>),
    GetBlockTxn(<compact_blocks::BlockTransactionsRequest as encoding::Encodable>::Encoder<'e>),
    BlockTxn(<compact_blocks::BlockTransactions as encoding::Encodable>::Encoder<'e>),
    Alert(<message_network::Alert as encoding::Encodable>::Encoder<'e>),
    FeeFilter(<FeeFilter as encoding::Encodable>::Encoder<'e>),
    AddrV2(<AddrV2Payload as encoding::Encodable>::Encoder<'e>),
    SendTxReconciliation(<SendTxReconciliation as encoding::Encodable>::Encoder<'e>),
    Empty(encoding::BytesEncoder<'e>),
    Unknown(encoding::BytesEncoder<'e>),
}

impl<'e> NetworkMessageEncoder<'e> {
    fn new(msg: &'e NetworkMessage) -> Self {
        match msg {
            NetworkMessage::Version(dat) => Self::Version(dat.encoder()),
            NetworkMessage::Addr(dat) => Self::Addr(dat.encoder()),
            NetworkMessage::Inv(dat) => Self::Inv(dat.encoder()),
            NetworkMessage::GetData(dat) => Self::GetData(dat.encoder()),
            NetworkMessage::NotFound(dat) => Self::NotFound(dat.encoder()),
            NetworkMessage::GetBlocks(dat) => Self::GetBlocks(dat.encoder()),
            NetworkMessage::GetHeaders(dat) => Self::GetHeaders(dat.encoder()),
            NetworkMessage::Tx(dat) => Self::Tx(dat.encoder()),
            NetworkMessage::Block(dat) => Self::Block(dat.encoder()),
            NetworkMessage::Headers(dat) => Self::Headers(dat.encoder()),
            NetworkMessage::Ping(nonce) => {
                Self::Ping(encoding::ArrayEncoder::without_length_prefix(nonce.to_le_bytes()))
            }
            NetworkMessage::Pong(nonce) => {
                Self::Pong(encoding::ArrayEncoder::without_length_prefix(nonce.to_le_bytes()))
            }
            NetworkMessage::MerkleBlock(dat) => Self::MerkleBlock(dat.encoder()),
            NetworkMessage::FilterLoad(dat) => Self::FilterLoad(dat.encoder()),
            NetworkMessage::FilterAdd(dat) => Self::FilterAdd(dat.encoder()),
            NetworkMessage::GetCFilters(dat) => Self::GetCFilters(dat.encoder()),
            NetworkMessage::CFilter(dat) => Self::CFilter(dat.encoder()),
            NetworkMessage::GetCFHeaders(dat) => Self::GetCFHeaders(dat.encoder()),
            NetworkMessage::CFHeaders(dat) => Self::CFHeaders(dat.encoder()),
            NetworkMessage::GetCFCheckpt(dat) => Self::GetCFCheckpt(dat.encoder()),
            NetworkMessage::CFCheckpt(dat) => Self::CFCheckpt(dat.encoder()),
            NetworkMessage::SendCmpct(dat) => Self::SendCmpct(dat.encoder()),
            NetworkMessage::CmpctBlock(dat) => Self::CmpctBlock(dat.encoder()),
            NetworkMessage::GetBlockTxn(dat) => Self::GetBlockTxn(dat.encoder()),
            NetworkMessage::BlockTxn(dat) => Self::BlockTxn(dat.encoder()),
            NetworkMessage::Alert(dat) => Self::Alert(dat.encoder()),
            NetworkMessage::FeeFilter(dat) => Self::FeeFilter(dat.encoder()),
            NetworkMessage::AddrV2(dat) => Self::AddrV2(dat.encoder()),
            NetworkMessage::SendTxReconciliation(dat) => Self::SendTxReconciliation(dat.encoder()),
            NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::MemPool
            | NetworkMessage::GetAddr
            | NetworkMessage::WtxidRelay
            | NetworkMessage::FilterClear
            | NetworkMessage::SendAddrV2 => {
                Self::Empty(encoding::BytesEncoder::without_length_prefix(&[]))
            }
            NetworkMessage::Unknown { payload, .. } => {
                Self::Unknown(encoding::BytesEncoder::without_length_prefix(payload.as_slice()))
            }
        }
    }
}

impl encoding::Encoder for NetworkMessageEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match self {
            Self::Version(inner) => inner.current_chunk(),
            Self::Addr(inner) => inner.current_chunk(),
            Self::Inv(inner) => inner.current_chunk(),
            Self::GetData(inner) => inner.current_chunk(),
            Self::NotFound(inner) => inner.current_chunk(),
            Self::GetBlocks(inner) => inner.current_chunk(),
            Self::GetHeaders(inner) => inner.current_chunk(),
            Self::Tx(inner) => inner.current_chunk(),
            Self::Block(inner) => inner.current_chunk(),
            Self::Headers(inner) => inner.current_chunk(),
            Self::Ping(inner) => inner.current_chunk(),
            Self::Pong(inner) => inner.current_chunk(),
            Self::MerkleBlock(inner) => inner.current_chunk(),
            Self::FilterLoad(inner) => inner.current_chunk(),
            Self::FilterAdd(inner) => inner.current_chunk(),
            Self::GetCFilters(inner) => inner.current_chunk(),
            Self::CFilter(inner) => inner.current_chunk(),
            Self::GetCFHeaders(inner) => inner.current_chunk(),
            Self::CFHeaders(inner) => inner.current_chunk(),
            Self::GetCFCheckpt(inner) => inner.current_chunk(),
            Self::CFCheckpt(inner) => inner.current_chunk(),
            Self::SendCmpct(inner) => inner.current_chunk(),
            Self::CmpctBlock(inner) => inner.current_chunk(),
            Self::GetBlockTxn(inner) => inner.current_chunk(),
            Self::BlockTxn(inner) => inner.current_chunk(),
            Self::Alert(inner) => inner.current_chunk(),
            Self::FeeFilter(inner) => inner.current_chunk(),
            Self::AddrV2(inner) => inner.current_chunk(),
            Self::SendTxReconciliation(inner) => inner.current_chunk(),
            Self::Empty(inner) => inner.current_chunk(),
            Self::Unknown(inner) => inner.current_chunk(),
        }
    }

    fn advance(&mut self) -> bool {
        match self {
            Self::Version(inner) => inner.advance(),
            Self::Addr(inner) => inner.advance(),
            Self::Inv(inner) => inner.advance(),
            Self::GetData(inner) => inner.advance(),
            Self::NotFound(inner) => inner.advance(),
            Self::GetBlocks(inner) => inner.advance(),
            Self::GetHeaders(inner) => inner.advance(),
            Self::Tx(inner) => inner.advance(),
            Self::Block(inner) => inner.advance(),
            Self::Headers(inner) => inner.advance(),
            Self::Ping(inner) => inner.advance(),
            Self::Pong(inner) => inner.advance(),
            Self::MerkleBlock(inner) => inner.advance(),
            Self::FilterLoad(inner) => inner.advance(),
            Self::FilterAdd(inner) => inner.advance(),
            Self::GetCFilters(inner) => inner.advance(),
            Self::CFilter(inner) => inner.advance(),
            Self::GetCFHeaders(inner) => inner.advance(),
            Self::CFHeaders(inner) => inner.advance(),
            Self::GetCFCheckpt(inner) => inner.advance(),
            Self::CFCheckpt(inner) => inner.advance(),
            Self::SendCmpct(inner) => inner.advance(),
            Self::CmpctBlock(inner) => inner.advance(),
            Self::GetBlockTxn(inner) => inner.advance(),
            Self::BlockTxn(inner) => inner.advance(),
            Self::Alert(inner) => inner.advance(),
            Self::FeeFilter(inner) => inner.advance(),
            Self::AddrV2(inner) => inner.advance(),
            Self::SendTxReconciliation(inner) => inner.advance(),
            Self::Empty(inner) => inner.advance(),
            Self::Unknown(inner) => inner.advance(),
        }
    }
}

impl encoding::Encodable for NetworkMessage {
    type Encoder<'e>
        = NetworkMessageEncoder<'e>
    where
        Self: 'e;

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
            NetworkMessageEncoder<'e>,
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

enum NetworkMessagePayloadDecoder {
    Version(<message_network::VersionMessage as encoding::Decodable>::Decoder),
    Addr(<AddrPayload as encoding::Decodable>::Decoder),
    Inv(<InventoryPayload as encoding::Decodable>::Decoder),
    GetData(<InventoryPayload as encoding::Decodable>::Decoder),
    NotFound(<InventoryPayload as encoding::Decodable>::Decoder),
    GetBlocks(<message_blockdata::GetBlocksMessage as encoding::Decodable>::Decoder),
    GetHeaders(<message_blockdata::GetHeadersMessage as encoding::Decodable>::Decoder),
    Tx(<transaction::Transaction as encoding::Decodable>::Decoder),
    Block(<block::Block as encoding::Decodable>::Decoder),
    Headers(<HeadersMessage as encoding::Decodable>::Decoder),
    Ping(<Ping as encoding::Decodable>::Decoder),
    Pong(<Pong as encoding::Decodable>::Decoder),
    MerkleBlock(<MerkleBlock as encoding::Decodable>::Decoder),
    FilterLoad(<message_bloom::FilterLoad as encoding::Decodable>::Decoder),
    FilterAdd(<message_bloom::FilterAdd as encoding::Decodable>::Decoder),
    GetCFilters(<message_filter::GetCFilters as encoding::Decodable>::Decoder),
    CFilter(<message_filter::CFilter as encoding::Decodable>::Decoder),
    GetCFHeaders(<message_filter::GetCFHeaders as encoding::Decodable>::Decoder),
    CFHeaders(<message_filter::CFHeaders as encoding::Decodable>::Decoder),
    GetCFCheckpt(<message_filter::GetCFCheckpt as encoding::Decodable>::Decoder),
    CFCheckpt(<message_filter::CFCheckpt as encoding::Decodable>::Decoder),
    SendCmpct(<message_compact_blocks::SendCmpct as encoding::Decodable>::Decoder),
    CmpctBlock(<compact_blocks::HeaderAndShortIds as encoding::Decodable>::Decoder),
    GetBlockTxn(<compact_blocks::BlockTransactionsRequest as encoding::Decodable>::Decoder),
    BlockTxn(<compact_blocks::BlockTransactions as encoding::Decodable>::Decoder),
    Alert(<message_network::Alert as encoding::Decodable>::Decoder),
    FeeFilter(<FeeFilter as encoding::Decodable>::Decoder),
    AddrV2(<AddrV2Payload as encoding::Decodable>::Decoder),
    SendTxReconciliation(<SendTxReconciliation as encoding::Decodable>::Decoder),
    Empty(NetworkMessage),
    Unknown { command: CommandString, payload: Vec<u8> },
}

impl NetworkMessagePayloadDecoder {
    fn from_command(command: CommandString) -> Self {
        match command.as_ref() {
            "version" => Self::Version(message_network::VersionMessage::decoder()),
            "verack" => Self::Empty(NetworkMessage::Verack),
            "addr" => Self::Addr(AddrPayload::decoder()),
            "inv" => Self::Inv(InventoryPayload::decoder()),
            "getdata" => Self::GetData(InventoryPayload::decoder()),
            "notfound" => Self::NotFound(InventoryPayload::decoder()),
            "getblocks" => Self::GetBlocks(message_blockdata::GetBlocksMessage::decoder()),
            "getheaders" => Self::GetHeaders(message_blockdata::GetHeadersMessage::decoder()),
            "mempool" => Self::Empty(NetworkMessage::MemPool),
            "block" => Self::Block(block::Block::decoder()),
            "headers" => Self::Headers(HeadersMessage::decoder()),
            "sendheaders" => Self::Empty(NetworkMessage::SendHeaders),
            "getaddr" => Self::Empty(NetworkMessage::GetAddr),
            "ping" => Self::Ping(Ping::decoder()),
            "pong" => Self::Pong(Pong::decoder()),
            "merkleblock" => Self::MerkleBlock(MerkleBlock::decoder()),
            "filterload" => Self::FilterLoad(message_bloom::FilterLoad::decoder()),
            "filteradd" => Self::FilterAdd(message_bloom::FilterAdd::decoder()),
            "filterclear" => Self::Empty(NetworkMessage::FilterClear),
            "getcfilters" => Self::GetCFilters(message_filter::GetCFilters::decoder()),
            "cfilter" => Self::CFilter(message_filter::CFilter::decoder()),
            "getcfheaders" => Self::GetCFHeaders(message_filter::GetCFHeaders::decoder()),
            "cfheaders" => Self::CFHeaders(message_filter::CFHeaders::decoder()),
            "getcfcheckpt" => Self::GetCFCheckpt(message_filter::GetCFCheckpt::decoder()),
            "cfcheckpt" => Self::CFCheckpt(message_filter::CFCheckpt::decoder()),
            "sendcmpct" => Self::SendCmpct(message_compact_blocks::SendCmpct::decoder()),
            "cmpctblock" => Self::CmpctBlock(compact_blocks::HeaderAndShortIds::decoder()),
            "getblocktxn" => Self::GetBlockTxn(compact_blocks::BlockTransactionsRequest::decoder()),
            "blocktxn" => Self::BlockTxn(compact_blocks::BlockTransactions::decoder()),
            "tx" => Self::Tx(transaction::Transaction::decoder()),
            "alert" => Self::Alert(message_network::Alert::decoder()),
            "feefilter" => Self::FeeFilter(FeeFilter::decoder()),
            "wtxidrelay" => Self::Empty(NetworkMessage::WtxidRelay),
            "addrv2" => Self::AddrV2(AddrV2Payload::decoder()),
            "sendaddrv2" => Self::Empty(NetworkMessage::SendAddrV2),
            "sendtxrcncl" => Self::SendTxReconciliation(SendTxReconciliation::decoder()),
            _ => Self::Unknown { command, payload: Vec::new() },
        }
    }

    fn from_v2_short_id(short_id: u8) -> Result<Self, ()> {
        Ok(match short_id {
            1 => Self::Addr(AddrPayload::decoder()),
            2 => Self::Block(block::Block::decoder()),
            3 => Self::BlockTxn(compact_blocks::BlockTransactions::decoder()),
            4 => Self::CmpctBlock(compact_blocks::HeaderAndShortIds::decoder()),
            5 => Self::FeeFilter(FeeFilter::decoder()),
            6 => Self::FilterAdd(message_bloom::FilterAdd::decoder()),
            7 => Self::Empty(NetworkMessage::FilterClear),
            8 => Self::FilterLoad(message_bloom::FilterLoad::decoder()),
            9 => Self::GetBlocks(message_blockdata::GetBlocksMessage::decoder()),
            10 => Self::GetBlockTxn(compact_blocks::BlockTransactionsRequest::decoder()),
            11 => Self::GetData(InventoryPayload::decoder()),
            12 => Self::GetHeaders(message_blockdata::GetHeadersMessage::decoder()),
            13 => Self::Headers(HeadersMessage::decoder()),
            14 => Self::Inv(InventoryPayload::decoder()),
            15 => Self::Empty(NetworkMessage::MemPool),
            16 => Self::MerkleBlock(MerkleBlock::decoder()),
            17 => Self::NotFound(InventoryPayload::decoder()),
            18 => Self::Ping(Ping::decoder()),
            19 => Self::Pong(Pong::decoder()),
            20 => Self::SendCmpct(message_compact_blocks::SendCmpct::decoder()),
            21 => Self::Tx(transaction::Transaction::decoder()),
            22 => Self::GetCFilters(message_filter::GetCFilters::decoder()),
            23 => Self::CFilter(message_filter::CFilter::decoder()),
            24 => Self::GetCFHeaders(message_filter::GetCFHeaders::decoder()),
            25 => Self::CFHeaders(message_filter::CFHeaders::decoder()),
            26 => Self::GetCFCheckpt(message_filter::GetCFCheckpt::decoder()),
            27 => Self::CFCheckpt(message_filter::CFCheckpt::decoder()),
            28 => Self::AddrV2(AddrV2Payload::decoder()),
            _ => return Err(()),
        })
    }

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, ()> {
        match self {
            Self::Version(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::Addr(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::Inv(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::GetData(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::NotFound(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::GetBlocks(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::GetHeaders(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::Tx(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::Block(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::Headers(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::Ping(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::Pong(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::MerkleBlock(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::FilterLoad(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::FilterAdd(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::GetCFilters(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::CFilter(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::GetCFHeaders(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::CFHeaders(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::GetCFCheckpt(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::CFCheckpt(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::SendCmpct(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::CmpctBlock(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::GetBlockTxn(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::BlockTxn(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::Alert(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::FeeFilter(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::AddrV2(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::SendTxReconciliation(inner) => inner.push_bytes(bytes).map_err(|_| ()),
            Self::Empty(_) if bytes.is_empty() => Ok(false),
            Self::Empty(_) => Err(()),
            Self::Unknown { payload, .. } => {
                payload.extend_from_slice(bytes);
                *bytes = &[];
                Ok(true)
            }
        }
    }

    fn end(self) -> Result<NetworkMessage, ()> {
        Ok(match self {
            Self::Version(inner) => NetworkMessage::Version(inner.end().map_err(|_| ())?),
            Self::Addr(inner) => NetworkMessage::Addr(inner.end().map_err(|_| ())?),
            Self::Inv(inner) => NetworkMessage::Inv(inner.end().map_err(|_| ())?),
            Self::GetData(inner) => NetworkMessage::GetData(inner.end().map_err(|_| ())?),
            Self::NotFound(inner) => NetworkMessage::NotFound(inner.end().map_err(|_| ())?),
            Self::GetBlocks(inner) => NetworkMessage::GetBlocks(inner.end().map_err(|_| ())?),
            Self::GetHeaders(inner) => NetworkMessage::GetHeaders(inner.end().map_err(|_| ())?),
            Self::Tx(inner) => NetworkMessage::Tx(inner.end().map_err(|_| ())?),
            Self::Block(inner) => NetworkMessage::Block(inner.end().map_err(|_| ())?),
            Self::Headers(inner) => NetworkMessage::Headers(inner.end().map_err(|_| ())?),
            Self::Ping(inner) => NetworkMessage::Ping(inner.end().map_err(|_| ())?.0),
            Self::Pong(inner) => NetworkMessage::Pong(inner.end().map_err(|_| ())?.0),
            Self::MerkleBlock(inner) => NetworkMessage::MerkleBlock(inner.end().map_err(|_| ())?),
            Self::FilterLoad(inner) => NetworkMessage::FilterLoad(inner.end().map_err(|_| ())?),
            Self::FilterAdd(inner) => NetworkMessage::FilterAdd(inner.end().map_err(|_| ())?),
            Self::GetCFilters(inner) => NetworkMessage::GetCFilters(inner.end().map_err(|_| ())?),
            Self::CFilter(inner) => NetworkMessage::CFilter(inner.end().map_err(|_| ())?),
            Self::GetCFHeaders(inner) => NetworkMessage::GetCFHeaders(inner.end().map_err(|_| ())?),
            Self::CFHeaders(inner) => NetworkMessage::CFHeaders(inner.end().map_err(|_| ())?),
            Self::GetCFCheckpt(inner) => NetworkMessage::GetCFCheckpt(inner.end().map_err(|_| ())?),
            Self::CFCheckpt(inner) => NetworkMessage::CFCheckpt(inner.end().map_err(|_| ())?),
            Self::SendCmpct(inner) => NetworkMessage::SendCmpct(inner.end().map_err(|_| ())?),
            Self::CmpctBlock(inner) => NetworkMessage::CmpctBlock(inner.end().map_err(|_| ())?),
            Self::GetBlockTxn(inner) => NetworkMessage::GetBlockTxn(inner.end().map_err(|_| ())?),
            Self::BlockTxn(inner) => NetworkMessage::BlockTxn(inner.end().map_err(|_| ())?),
            Self::Alert(inner) => NetworkMessage::Alert(inner.end().map_err(|_| ())?),
            Self::FeeFilter(inner) => NetworkMessage::FeeFilter(inner.end().map_err(|_| ())?),
            Self::AddrV2(inner) => NetworkMessage::AddrV2(inner.end().map_err(|_| ())?),
            Self::SendTxReconciliation(inner) => {
                NetworkMessage::SendTxReconciliation(inner.end().map_err(|_| ())?)
            }
            Self::Empty(message) => message,
            Self::Unknown { command, payload } => NetworkMessage::Unknown { command, payload },
        })
    }

    fn read_limit(&self) -> usize {
        match self {
            Self::Version(inner) => inner.read_limit(),
            Self::Addr(inner) => inner.read_limit(),
            Self::Inv(inner) => inner.read_limit(),
            Self::GetData(inner) => inner.read_limit(),
            Self::NotFound(inner) => inner.read_limit(),
            Self::GetBlocks(inner) => inner.read_limit(),
            Self::GetHeaders(inner) => inner.read_limit(),
            Self::Tx(inner) => inner.read_limit(),
            Self::Block(inner) => inner.read_limit(),
            Self::Headers(inner) => inner.read_limit(),
            Self::Ping(inner) => inner.read_limit(),
            Self::Pong(inner) => inner.read_limit(),
            Self::MerkleBlock(inner) => inner.read_limit(),
            Self::FilterLoad(inner) => inner.read_limit(),
            Self::FilterAdd(inner) => inner.read_limit(),
            Self::GetCFilters(inner) => inner.read_limit(),
            Self::CFilter(inner) => inner.read_limit(),
            Self::GetCFHeaders(inner) => inner.read_limit(),
            Self::CFHeaders(inner) => inner.read_limit(),
            Self::GetCFCheckpt(inner) => inner.read_limit(),
            Self::CFCheckpt(inner) => inner.read_limit(),
            Self::SendCmpct(inner) => inner.read_limit(),
            Self::CmpctBlock(inner) => inner.read_limit(),
            Self::GetBlockTxn(inner) => inner.read_limit(),
            Self::BlockTxn(inner) => inner.read_limit(),
            Self::Alert(inner) => inner.read_limit(),
            Self::FeeFilter(inner) => inner.read_limit(),
            Self::AddrV2(inner) => inner.read_limit(),
            Self::SendTxReconciliation(inner) => inner.read_limit(),
            Self::Empty(_) => 0,
            Self::Unknown { .. } => usize::MAX,
        }
    }
}

struct NetworkMessageDecoder {
    payload_len: usize,
    consumed: usize,
    inner: NetworkMessagePayloadDecoder,
}

impl NetworkMessageDecoder {
    fn new(command: CommandString, payload_len: usize) -> Self {
        Self {
            payload_len,
            consumed: 0,
            inner: NetworkMessagePayloadDecoder::from_command(command),
        }
    }
}

impl encoding::Decoder for NetworkMessageDecoder {
    type Output = NetworkMessage;
    type Error = V1NetworkMessageDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        let remaining = self.payload_len.saturating_sub(self.consumed);
        let copy_len = bytes.len().min(remaining);
        let mut payload_bytes = &bytes[..copy_len];
        self.inner.push_bytes(&mut payload_bytes).map_err(|()| {
            V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Payload)
        })?;
        let consumed = copy_len - payload_bytes.len();
        self.consumed += consumed;
        *bytes = &bytes[consumed..];

        if consumed < copy_len && self.consumed < self.payload_len {
            return Err(V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Payload));
        }

        Ok(self.consumed < self.payload_len)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        if self.consumed != self.payload_len {
            return Err(V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Payload));
        }
        self.inner
            .end()
            .map_err(|()| V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Payload))
    }

    fn read_limit(&self) -> usize {
        self.payload_len.saturating_sub(self.consumed).min(self.inner.read_limit())
    }
}

#[allow(clippy::large_enum_variant)]
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
        checksum_engine: sha256d::HashEngine,
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
                        checksum_engine: sha256d::Hash::engine(),
                        payload_decoder,
                    };

                    // Continue with any remaining bytes.
                    return self.push_bytes(bytes);
                }

                Ok(need_more)
            }
            DecoderState::ReadingPayload { checksum_engine, payload_decoder, .. } => {
                let input = *bytes;
                let need_more = payload_decoder.push_bytes(bytes)?;
                let consumed = input.len() - bytes.len();
                checksum_engine.input(&input[..consumed]);
                Ok(need_more)
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
                checksum_engine,
                payload_decoder,
                ..
            } => {
                let payload = payload_decoder.end()?;
                let expected_checksum = {
                    let hash = checksum_engine.finalize().to_byte_array();
                    [hash[0], hash[1], hash[2], hash[3]]
                };
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

fn v2_network_message_command(payload: &NetworkMessage) -> (u8, Option<CommandString>) {
    // A subset of message types use a one-byte command ID; the rest use zero followed by the
    // canonical twelve-byte command string.
    match payload {
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
    }
}

type V2NetworkMessageEncoderInner<'e> = encoding::Encoder3<
    encoding::ArrayEncoder<1>,
    Option<CommandStringEncoder>,
    NetworkMessageEncoder<'e>,
>;

/// Encoder for [`V2NetworkMessage`].
pub struct V2NetworkMessageEncoder<'e>(V2NetworkMessageEncoderInner<'e>);

impl<'e> V2NetworkMessageEncoder<'e> {
    fn new(payload: &'e NetworkMessage) -> Self {
        let (command_byte, full_command) = v2_network_message_command(payload);
        Self(encoding::Encoder3::new(
            encoding::ArrayEncoder::without_length_prefix([command_byte]),
            full_command.map(|command| command.encoder()),
            NetworkMessageEncoder::new(payload),
        ))
    }
}

impl encoding::Encoder for V2NetworkMessageEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        self.0.current_chunk()
    }

    fn advance(&mut self) -> bool {
        self.0.advance()
    }
}

impl encoding::Encodable for V2NetworkMessage {
    type Encoder<'e>
        = V2NetworkMessageEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        V2NetworkMessageEncoder::new(&self.payload)
    }
}

#[allow(clippy::large_enum_variant)]
enum V2NetworkMessageDecoderState {
    ShortId,
    Command(CommandStringDecoder),
    Payload(NetworkMessagePayloadDecoder),
}

/// Decoder for [`V2NetworkMessage`].
pub struct V2NetworkMessageDecoder {
    read: usize,
    state: V2NetworkMessageDecoderState,
}

impl encoding::Decoder for V2NetworkMessageDecoder {
    type Output = V2NetworkMessage;
    type Error = V2NetworkMessageDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        loop {
            match &mut self.state {
                V2NetworkMessageDecoderState::ShortId => {
                    if bytes.is_empty() {
                        return Ok(true);
                    }
                    let (&short_id, rest) =
                        bytes.split_first().ok_or(V2NetworkMessageDecoderError)?;
                    self.read = self.read.saturating_add(1);
                    *bytes = rest;
                    self.state = if short_id == 0 {
                        V2NetworkMessageDecoderState::Command(CommandStringDecoder {
                            inner: encoding::ArrayDecoder::new(),
                        })
                    } else {
                        V2NetworkMessageDecoderState::Payload(
                            NetworkMessagePayloadDecoder::from_v2_short_id(short_id)
                                .map_err(|()| V2NetworkMessageDecoderError)?,
                        )
                    };
                }
                V2NetworkMessageDecoderState::Command(command_decoder) => {
                    let before = bytes.len();
                    let need_more = command_decoder
                        .push_bytes(bytes)
                        .map_err(|_| V2NetworkMessageDecoderError)?;
                    self.read = self.read.saturating_add(before - bytes.len());
                    if need_more {
                        return Ok(true);
                    }

                    let old_state =
                        core::mem::replace(&mut self.state, V2NetworkMessageDecoderState::ShortId);
                    let V2NetworkMessageDecoderState::Command(command_decoder) = old_state else {
                        unreachable!("we are in ReadingCommand state")
                    };
                    let command =
                        command_decoder.end().map_err(|_| V2NetworkMessageDecoderError)?;
                    self.state = V2NetworkMessageDecoderState::Payload(
                        NetworkMessagePayloadDecoder::from_command(command),
                    );
                }
                V2NetworkMessageDecoderState::Payload(payload_decoder) => {
                    let before = bytes.len();
                    let need_more = payload_decoder
                        .push_bytes(bytes)
                        .map_err(|()| V2NetworkMessageDecoderError)?;
                    self.read = self.read.saturating_add(before - bytes.len());
                    return Ok(need_more);
                }
            }
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.state {
            V2NetworkMessageDecoderState::Payload(payload_decoder) => payload_decoder
                .end()
                .map(V2NetworkMessage::new)
                .map_err(|()| V2NetworkMessageDecoderError),
            V2NetworkMessageDecoderState::ShortId | V2NetworkMessageDecoderState::Command(_) => {
                Err(V2NetworkMessageDecoderError)
            }
        }
    }

    fn read_limit(&self) -> usize {
        let frame_limit = MAX_MSG_SIZE.saturating_sub(self.read);
        match &self.state {
            V2NetworkMessageDecoderState::ShortId => frame_limit.min(1),
            V2NetworkMessageDecoderState::Command(decoder) => frame_limit.min(decoder.read_limit()),
            V2NetworkMessageDecoderState::Payload(decoder) => frame_limit.min(decoder.read_limit()),
        }
    }
}

impl encoding::Decodable for V2NetworkMessage {
    type Decoder = V2NetworkMessageDecoder;

    fn decoder() -> Self::Decoder {
        V2NetworkMessageDecoder { read: 0, state: V2NetworkMessageDecoderState::ShortId }
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
    sha2_checksum_encoder(encoding::BytesEncoder::without_length_prefix(data))
}

fn sha2_checksum_encoder(mut encoder: impl encoding::Encoder) -> [u8; 4] {
    let mut engine = sha256d::Hash::engine();
    loop {
        engine.input(encoder.current_chunk());
        if !encoder.advance() {
            break;
        }
    }

    let checksum = engine.finalize().to_byte_array();
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

    use internals::hex_lit as hex;
    use primitives::locktime::absolute;
    use primitives::merkle_tree::TxMerkleNode;
    use primitives::transaction::{self, Transaction, Txid};
    use primitives::{
        Amount, Block, BlockHash, BlockTime, CompactTarget, OutPoint, ScriptPubKeyBuf,
        ScriptSigBuf, Sequence, TxIn, TxOut, Witness,
    };
    use units::BlockHeight;

    use super::*;
    use crate::address::{AddrV2, Address};
    use crate::compact_blocks::BlockTransactionsRequest;
    use crate::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
    use crate::message_bloom::{BloomFlags, FilterAdd, FilterLoad};
    use crate::message_compact_blocks::SendCmpct;
    use crate::message_filter::{
        CFCheckpt, CFHeaders, CFilter, FilterHash, FilterHeader, GetCFCheckpt, GetCFHeaders,
        GetCFilters,
    };
    use crate::message_network::{
        Alert, ClientSoftwareVersion, Reject, RejectReason, UserAgent, UserAgentVersion,
        VersionMessage,
    };
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

    fn generic_tx(seed: u8) -> Transaction {
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([seed; 32]),
                    vout: seed.into(),
                },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence(seed.into()),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        }
    }

    fn generic_header(seed: u8) -> block::Header {
        block::Header {
            version: block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([seed; 32]),
            merkle_root: TxMerkleNode::from_byte_array([seed.wrapping_add(1); 32]),
            time: BlockTime::from_u32(seed.into()),
            bits: CompactTarget::from_consensus(seed.into()),
            nonce: seed.into(),
            auxpow: None,
        }
    }

    fn generic_block(seed: u8) -> Block {
        Block::new_unchecked(generic_header(seed), vec![generic_tx(seed), generic_tx(seed + 1)])
    }

    fn generic_version_message() -> VersionMessage {
        let mut message = VersionMessage::new(
            ProtocolVersion::INVALID_CB_NO_BAN_VERSION,
            ServiceFlags::NETWORK
                | ServiceFlags::BLOOM
                | ServiceFlags::WITNESS
                | ServiceFlags::NETWORK_LIMITED,
            1_548_554_224,
            Address::new(&([91, 240, 140, 128], 46269).into(), ServiceFlags::NONE),
            Address::new(&([0, 0, 0, 0], 0).into(), ServiceFlags::NONE),
            13_952_548_347_456_104_954,
            UserAgent::new(
                "TidecoinCore",
                &UserAgentVersion::new(ClientSoftwareVersion::SemVer {
                    major: 0,
                    minor: 17,
                    revision: 1,
                }),
            ),
            560_275,
        );
        message.relay = true;
        message
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn full_round_ser_der_raw_network_message() {
        let version_msg = VersionMessage::new(
            ProtocolVersion::from_nonstandard(70002),
            ServiceFlags::NETWORK,
            1_713_657_600,
            Address::new(&([127, 0, 0, 1], 8333).into(), ServiceFlags::NETWORK),
            Address::new(&([127, 0, 0, 2], 8333).into(), ServiceFlags::NETWORK),
            0x0102_0304_0506_0708,
            UserAgent::from_nonstandard(&"/tidecoin-test:0.0.0/"),
            42,
        );
        let tx = generic_tx(0x11);
        let block = generic_block(0x21);
        let header = generic_header(0x31);
        let script = &hex!("1976a91431a420903c05a0a7de2de40c9f02ebedbacdc17288ac");
        let merkle_txids = [generic_tx(0x41).compute_txid(), generic_tx(0x42).compute_txid()];
        let merkle_block =
            MerkleBlock::from_header_txids_with_predicate(&header, &merkle_txids, |txid| {
                *txid == merkle_txids[1]
            });
        let merkle_block: MerkleBlock =
            encoding::decode_from_slice(&encoding::encode_to_vec(&merkle_block)).unwrap();
        let checked_block = block.clone().assume_checked(None);
        let cmptblock = crate::compact_blocks::HeaderAndShortIds::from_block(
            &checked_block,
            0x0102_0304,
            1,
            &[],
        )
        .unwrap();
        let blocktxn = crate::compact_blocks::BlockTransactions {
            block_hash: checked_block.block_hash(),
            transactions: vec![generic_tx(0x43)],
        };

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
        let expected = V1NetworkMessage::new(
            Magic::TIDECOIN,
            NetworkMessage::Version(generic_version_message()),
        );
        let encoded = encoding::encode_to_vec(&expected);
        let msg = encoding::decode_from_slice::<V1NetworkMessage>(&encoded).unwrap();

        assert_eq!(msg, expected);
    }

    #[test]
    fn deserialize_v2_version() {
        let expected = V2NetworkMessage::new(NetworkMessage::Version(generic_version_message()));
        let encoded = encoding::encode_to_vec(&expected);
        let msg = encoding::decode_from_slice::<V2NetworkMessage>(&encoded).unwrap();

        assert_eq!(msg, expected);
    }

    #[test]
    fn decode_partial_message() {
        let expected = V1NetworkMessage::new(
            Magic::TIDECOIN,
            NetworkMessage::Version(generic_version_message()),
        );
        let mut data = encoding::encode_to_vec(&expected);
        data.extend_from_slice(&[0x00, 0x00]);
        let (msg, consumed) = decode_prefix::<V1NetworkMessage>(&data).unwrap();

        assert_eq!(consumed, data.len() - 2);
        assert_eq!(msg, expected);
    }

    #[test]
    fn headers_message() {
        let first = generic_header(0x80);
        let second = block::Header { prev_blockhash: first.block_hash(), ..generic_header(0x81) };
        let third = block::Header { prev_blockhash: second.block_hash(), ..generic_header(0x82) };

        let headers_message = HeadersMessage(vec![
            NetworkHeader { header: first, length: 0 },
            NetworkHeader { header: second, length: 0 },
            NetworkHeader { header: third, length: 0 },
        ]);
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
