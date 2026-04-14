// SPDX-License-Identifier: CC0-1.0

//! Tidecoin transactions.
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.

use core::convert::Infallible;
use core::fmt;
#[cfg(feature = "alloc")]
use core::{cmp, mem};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{ArrayEncoder, BytesEncoder, Encoder2, UnexpectedEofError};
#[cfg(feature = "alloc")]
use encoding::{
    CompactSizeEncoder, Decoder as _, Decoder2, Decoder3, Encodable as _, Encoder3, Encoder4,
    Encoder6, SliceEncoder, VecDecoder, VecDecoderError,
};
#[cfg(feature = "alloc")]
use hashes::sha256d;
#[cfg(feature = "alloc")]
use hashes::HashEngine as _;
use internals::array::ArrayExt as _;
use internals::write_err;
#[cfg(feature = "alloc")]
use internals::ToU64 as _;
#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
#[cfg(all(feature = "hex", feature = "alloc"))]
use units::parse_int;

#[cfg(feature = "alloc")]
use crate::amount::{AmountDecoder, AmountEncoder};
#[cfg(all(feature = "hex", feature = "alloc"))]
use crate::hex_codec::{HexPrimitive, ParsePrimitiveError};
#[cfg(feature = "alloc")]
use crate::locktime::absolute::{LockTimeDecoder, LockTimeDecoderError, LockTimeEncoder};
#[cfg(feature = "alloc")]
use crate::prelude::Vec;
#[cfg(feature = "alloc")]
use crate::script::{ScriptEncoder, ScriptPubKeyBufDecoder, ScriptSigBufDecoder};
#[cfg(feature = "alloc")]
use crate::sequence::{SequenceDecoder, SequenceEncoder};
#[cfg(feature = "alloc")]
use crate::witness::{WitnessDecoder, WitnessDecoderError, WitnessEncoder};
#[cfg(feature = "alloc")]
use crate::{absolute, Amount, ScriptPubKeyBuf, ScriptSigBuf, Sequence, Weight, Witness};

#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(inline)]
pub use crate::hash_types::{Ntxid, Txid, Wtxid, BlockHashDecoder};
#[doc(no_inline)]
pub use crate::hash_types::BlockHashDecoderError;

/// Tidecoin transaction.
///
/// An authenticated movement of coins.
///
/// # Serialization notes
///
/// If any inputs have nonempty witnesses, the entire transaction is serialized
/// in the Tidecoin witness format, which includes a list of witnesses. If all
/// inputs have empty witnesses, the transaction is serialized without witness
/// data.
///
/// There is one major exception to this: to avoid deserialization ambiguity,
/// if a caller constructs a transaction with no inputs, it is serialized in
/// witness style. Such a transaction is invalid under Tidecoin consensus sanity
/// rules and will be rejected by consensus decoding.
///
/// The specific ambiguity is that witness serialization uses the flag bytes `0001` where an old
/// serializer would read the number of transaction inputs. The old serializer
/// would interpret this as "no inputs, one output", which means the transaction
/// is invalid, and simply reject it. Witness serialization further specifies that this encoding
/// should *only* be used when some input has a nonempty witness; that is,
/// witness-less transactions should be encoded in the traditional format.
///
/// We therefore always use the Tidecoin witness encoding
/// for constructed 0-input transactions, which results in unambiguously parseable
/// bytes before consensus sanity rejection.
///
/// # A note on ordering
///
/// This type implements `Ord`, even though it contains a locktime, which is not
/// itself `Ord`. This was done to simplify applications that may need to hold
/// transactions inside a sorted container. We have ordered the locktimes based
/// on their representation as a `u32`, which is not a semantically meaningful
/// order, and therefore the ordering on `Transaction` itself is not semantically
/// meaningful either.
///
/// The ordering is, however, consistent with the ordering present in this library
/// before this change, so users should not notice any breakage (here) when
/// transitioning from 0.29 to 0.30.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
#[cfg(feature = "alloc")]
pub struct Transaction {
    /// The protocol version, currently expected to be 1, 2, or 3 by Tidecoin policy.
    pub version: Version,
    /// Block height or timestamp. Transaction cannot be included in a block until this height/time.
    ///
    /// Uses the lock-time semantics active on the Tidecoin network.
    pub lock_time: absolute::LockTime,
    /// List of transaction inputs.
    pub inputs: Vec<TxIn>,
    /// List of transaction outputs.
    pub outputs: Vec<TxOut>,
}

#[cfg(feature = "alloc")]
impl Transaction {
    /// Computes a "normalized TXID" which does not include any signatures.
    ///
    /// This function is needed only for legacy (pre-Segwit or P2SH-wrapped segwit version 0)
    /// applications. This method clears the `script_sig` field of each input, which in Segwit
    /// transactions is already empty, so for Segwit transactions the ntxid will be equal to the
    /// txid, and you should simply use the latter.
    ///
    /// This gives a way to identify a transaction that is "the same" as another in the sense of
    /// having the same inputs and outputs.
    #[doc(alias = "ntxid")]
    pub fn compute_ntxid(&self) -> Ntxid {
        let normalized = Self {
            version: self.version,
            lock_time: self.lock_time,
            inputs: self
                .inputs
                .iter()
                .map(|txin| TxIn {
                    script_sig: ScriptSigBuf::new(),
                    witness: Witness::default(),
                    ..*txin
                })
                .collect(),
            outputs: self.outputs.clone(),
        };
        Ntxid::from_byte_array(normalized.compute_txid().to_byte_array())
    }

    /// Computes the [`Txid`].
    ///
    /// Hashes the transaction **excluding** the SegWit data (i.e. the marker, flag bytes, and the
    /// witness fields themselves). For non-SegWit transactions which do not have any SegWit data,
    /// this will be equal to [`Transaction::compute_wtxid()`].
    #[doc(alias = "txid")]
    #[inline]
    pub fn compute_txid(&self) -> Txid {
        let hash = sha256d_hash_encoder(self.base_encoder());
        Txid::from_byte_array(hash.to_byte_array())
    }

    /// Computes the SegWit version of the transaction id.
    ///
    /// Hashes the transaction **including** all SegWit data (i.e. the marker, flag bytes, and the
    /// witness fields themselves). For non-SegWit transactions which do not have any SegWit data,
    /// this will be equal to [`Transaction::compute_txid()`].
    #[doc(alias = "wtxid")]
    #[inline]
    pub fn compute_wtxid(&self) -> Wtxid {
        let hash = hashes::encode_to_engine(self, sha256d::Hash::engine()).finalize();
        Wtxid::from_byte_array(hash.to_byte_array())
    }

    /// Returns whether to serialize the transaction with witness data.
    #[inline]
    pub fn uses_segwit_serialization(&self) -> bool {
        if self.inputs.iter().any(|input| !input.witness.is_empty()) {
            return true;
        }
        // To avoid serialization ambiguity, no inputs means we use witness serialization (see
        // `Transaction` docs for full explanation).
        self.inputs.is_empty()
    }

    /// Returns the weight of this transaction.
    ///
    /// Transaction weight is base transaction size multiplied by three plus total transaction size.
    #[inline]
    pub fn weight(&self) -> Weight {
        Weight::from_wu((self.base_size() * 3 + self.total_size()).to_u64())
    }

    /// Returns the base transaction size, with witness data stripped.
    #[inline]
    pub fn base_size(&self) -> usize {
        let mut size = Version::SIZE;

        size += CompactSizeEncoder::encoded_size(self.inputs.len());
        size += self.inputs.iter().map(TxIn::base_size).sum::<usize>();

        size += CompactSizeEncoder::encoded_size(self.outputs.len());
        size += self.outputs.iter().map(TxOut::size).sum::<usize>();

        size + absolute::LockTime::SIZE
    }

    /// Returns the total transaction size under canonical transaction serialization.
    #[inline]
    pub fn total_size(&self) -> usize {
        let mut size = Version::SIZE;
        let uses_segwit = self.uses_segwit_serialization();

        if uses_segwit {
            size += 2; // marker and flag
        }

        size += CompactSizeEncoder::encoded_size(self.inputs.len());
        size += self
            .inputs
            .iter()
            .map(|input| if uses_segwit { input.total_size() } else { input.base_size() })
            .sum::<usize>();

        size += CompactSizeEncoder::encoded_size(self.outputs.len());
        size += self.outputs.iter().map(TxOut::size).sum::<usize>();

        size + absolute::LockTime::SIZE
    }

    /// Returns the virtual transaction size, rounded up from weight units.
    #[inline]
    pub fn vsize(&self) -> usize {
        self.weight().to_vbytes_ceil() as usize
    }

    /// Checks if this is a coinbase transaction.
    ///
    /// The first transaction in the block distributes the mining reward and is called the coinbase
    /// transaction. It is impossible to check if the transaction is first in the block, so this
    /// function checks the structure of the transaction instead - the previous output must be
    /// all-zeros (creates satoshis "out of thin air").
    #[doc(alias = "is_coin_base")] // method previously had this name
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_output == OutPoint::COINBASE_PREVOUT
    }

    fn base_encoder(&self) -> BaseTransactionEncoder<'_> {
        let inputs = Encoder2::new(
            CompactSizeEncoder::new(self.inputs.len()),
            SliceEncoder::without_length_prefix(self.inputs.as_ref()),
        );
        let outputs = Encoder2::new(
            CompactSizeEncoder::new(self.outputs.len()),
            SliceEncoder::without_length_prefix(self.outputs.as_ref()),
        );

        BaseTransactionEncoder::new(Encoder4::new(
            self.version.encoder(),
            inputs,
            outputs,
            self.lock_time.encoder(),
        ))
    }
}

/// Checks Tidecoin context-free transaction sanity rules.
///
/// This mirrors the node's `CheckTransaction` checks that only depend on the
/// transaction itself. It intentionally does not validate UTXO availability,
/// input scripts, finality, fees, or other contextual rules.
///
/// # Errors
///
/// Returns [`TransactionSanityError`] when the transaction violates a
/// context-free Tidecoin transaction sanity rule.
#[cfg(feature = "alloc")]
pub fn check_transaction_sanity(tx: &Transaction) -> Result<(), TransactionSanityError> {
    validate_transaction_has_inputs(tx)?;
    validate_transaction_has_outputs(tx)?;
    validate_transaction_base_size(tx)?;
    validate_output_value_sum(tx)?;
    validate_unique_inputs(tx)?;
    validate_coinbase_script_sig_len(tx)?;
    validate_non_coinbase_prevouts(tx)?;
    Ok(())
}

#[cfg(feature = "alloc")]
impl cmp::PartialOrd for Transaction {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "alloc")]
impl cmp::Ord for Transaction {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.version
            .cmp(&other.version)
            .then(self.lock_time.to_consensus_u32().cmp(&other.lock_time.to_consensus_u32()))
            .then(self.inputs.cmp(&other.inputs))
            .then(self.outputs.cmp(&other.outputs))
    }
}

#[cfg(feature = "alloc")]
impl From<Transaction> for Txid {
    #[inline]
    fn from(tx: Transaction) -> Self {
        tx.compute_txid()
    }
}

#[cfg(feature = "alloc")]
impl From<&Transaction> for Txid {
    #[inline]
    fn from(tx: &Transaction) -> Self {
        tx.compute_txid()
    }
}

#[cfg(feature = "alloc")]
impl From<Transaction> for Wtxid {
    #[inline]
    fn from(tx: Transaction) -> Self {
        tx.compute_wtxid()
    }
}

#[cfg(feature = "alloc")]
impl From<&Transaction> for Wtxid {
    #[inline]
    fn from(tx: &Transaction) -> Self {
        tx.compute_wtxid()
    }
}

/// Trait that abstracts over a transaction identifier i.e., `Txid` and `Wtxid`.
pub(crate) trait TxIdentifier: AsRef<[u8]> {}

impl TxIdentifier for Txid {}
impl TxIdentifier for Wtxid {}

#[cfg(feature = "alloc")]
fn sha256d_hash_encoder(mut encoder: impl encoding::Encoder) -> sha256d::Hash {
    let mut enc = sha256d::Hash::engine();
    loop {
        enc.input(encoder.current_chunk());
        if !encoder.advance() {
            break;
        }
    }

    enc.finalize()
}

#[cfg(feature = "alloc")]
type BaseTransactionEncoderInner<'e> = Encoder4<
    VersionEncoder<'e>,
    Encoder2<CompactSizeEncoder, SliceEncoder<'e, TxIn>>,
    Encoder2<CompactSizeEncoder, SliceEncoder<'e, TxOut>>,
    LockTimeEncoder<'e>,
>;

#[cfg(feature = "alloc")]
encoding::encoder_newtype_exact! {
    /// The encoder for transaction data without witnesses.
    pub struct BaseTransactionEncoder<'e>(BaseTransactionEncoderInner<'e>);
}

#[cfg(feature = "alloc")]
type TransactionEncoderInner<'e> = Encoder6<
    VersionEncoder<'e>,
    Option<ArrayEncoder<2>>,
    Encoder2<CompactSizeEncoder, SliceEncoder<'e, TxIn>>,
    Encoder2<CompactSizeEncoder, SliceEncoder<'e, TxOut>>,
    Option<WitnessesEncoder<'e>>,
    LockTimeEncoder<'e>,
>;

#[cfg(feature = "alloc")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`Transaction`] type.
    pub struct TransactionEncoder<'e>(TransactionEncoderInner<'e>);
}

#[cfg(feature = "alloc")]
impl encoding::Encodable for Transaction {
    type Encoder<'e>
        = TransactionEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        let version = self.version.encoder();
        let inputs = Encoder2::new(
            CompactSizeEncoder::new(self.inputs.len()),
            SliceEncoder::without_length_prefix(self.inputs.as_ref()),
        );
        let outputs = Encoder2::new(
            CompactSizeEncoder::new(self.outputs.len()),
            SliceEncoder::without_length_prefix(self.outputs.as_ref()),
        );
        let lock_time = self.lock_time.encoder();

        if self.uses_segwit_serialization() {
            let segwit = ArrayEncoder::without_length_prefix([0x00, 0x01]);
            let witnesses = WitnessesEncoder::new(self.inputs.as_slice());
            TransactionEncoder::new(Encoder6::new(
                version,
                Some(segwit),
                inputs,
                outputs,
                Some(witnesses),
                lock_time,
            ))
        } else {
            TransactionEncoder::new(Encoder6::new(version, None, inputs, outputs, None, lock_time))
        }
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl core::str::FromStr for Transaction {
    type Err = ParseTransactionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HexPrimitive::from_str(s).map_err(ParseTransactionError)
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&HexPrimitive(self), f)
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::LowerHex for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&HexPrimitive(self), f)
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::UpperHex for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&HexPrimitive(self), f)
    }
}

/// An error that occurs during parsing of a [`Transaction`] from a hex string.
#[cfg(all(feature = "hex", feature = "alloc"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTransactionError(ParsePrimitiveError<Transaction>);

#[cfg(all(feature = "hex", feature = "alloc"))]
impl From<Infallible> for ParseTransactionError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::Display for ParseTransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "parse transaction error"; self.0)
    }
}

#[cfg(all(feature = "hex", feature = "alloc", feature = "std"))]
impl std::error::Error for ParseTransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// The decoder for the [`Transaction`] type.
#[cfg(feature = "alloc")]
pub struct TransactionDecoder {
    state: TransactionDecoderState,
}

#[cfg(feature = "alloc")]
impl TransactionDecoder {
    /// Constructs a new [`TransactionDecoder`].
    pub const fn new() -> Self {
        Self { state: TransactionDecoderState::Version(VersionDecoder::new()) }
    }
}

#[cfg(feature = "alloc")]
impl Default for TransactionDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl encoding::Decoder for TransactionDecoder {
    type Output = Transaction;
    type Error = TransactionDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.state.push_bytes(bytes)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        self.state.end()
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.state.read_limit()
    }
}

#[cfg(feature = "alloc")]
impl TransactionDecoderState {
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, TransactionDecoderError> {
        loop {
            if self.subdecoder_needs_more_bytes(bytes)? {
                return Ok(true);
            }

            if let Some(done) = self.advance_state(bytes)? {
                return Ok(done);
            }
        }
    }

    fn end(self) -> Result<Transaction, TransactionDecoderError> {
        use TransactionDecoderError as E;
        use TransactionDecoderErrorInner as Inner;

        match self {
            Self::Version(_) => Err(E(Inner::EarlyEnd("version"))),
            Self::Inputs(..) => Err(E(Inner::EarlyEnd("inputs"))),
            Self::SegwitFlag(..) => Err(E(Inner::EarlyEnd("segwit flag"))),
            Self::Outputs(..) => Err(E(Inner::EarlyEnd("outputs"))),
            Self::Witnesses(..) => Err(E(Inner::EarlyEnd("witnesses"))),
            Self::LockTime(..) => Err(E(Inner::EarlyEnd("locktime"))),
            Self::Done(tx) => validate_decoded_transaction(tx),
            Self::Errored => panic!("call to end() after decoder errored"),
        }
    }

    fn read_limit(&self) -> usize {
        match self {
            Self::Version(decoder) => decoder.read_limit(),
            Self::Inputs(_, _, decoder) => decoder.read_limit(),
            Self::SegwitFlag(_) => 1,
            Self::Outputs(_, _, _, decoder) => decoder.read_limit(),
            Self::Witnesses(_, _, _, _, decoder) => decoder.read_limit(),
            Self::LockTime(_, _, _, decoder) => decoder.read_limit(),
            Self::Done(_) => 0,
            // `read_limit` is not documented to panic or return an error, so we
            // return a dummy value if the decoder is in an error state.
            Self::Errored => 0,
        }
    }

    fn subdecoder_needs_more_bytes(
        &mut self,
        bytes: &mut &[u8],
    ) -> Result<bool, TransactionDecoderError> {
        use TransactionDecoderError as E;
        use TransactionDecoderErrorInner as Inner;

        match self {
            Self::Version(decoder) => decoder.push_bytes(bytes).map_err(|e| E(Inner::Version(e))),
            Self::Inputs(_, _, decoder) => {
                decoder.push_bytes(bytes).map_err(|e| E(Inner::Inputs(e)))
            }
            Self::SegwitFlag(_) => Ok(bytes.is_empty()),
            Self::Outputs(_, _, _, decoder) => {
                decoder.push_bytes(bytes).map_err(|e| E(Inner::Outputs(e)))
            }
            Self::Witnesses(_, _, _, _, decoder) => {
                decoder.push_bytes(bytes).map_err(|e| E(Inner::Witness(e)))
            }
            Self::LockTime(_, _, _, decoder) => {
                decoder.push_bytes(bytes).map_err(|e| E(Inner::LockTime(e)))
            }
            Self::Done(..) => Ok(false),
            Self::Errored => panic!("call to push_bytes() after decoder errored"),
        }
    }

    fn advance_state(
        &mut self,
        bytes: &mut &[u8],
    ) -> Result<Option<bool>, TransactionDecoderError> {
        use TransactionDecoderError as E;
        use TransactionDecoderErrorInner as Inner;

        match mem::replace(self, Self::Errored) {
            Self::Version(decoder) => {
                let version = decoder.end().map_err(|e| E(Inner::Version(e)))?;
                *self = Self::Inputs(version, Attempt::First, VecDecoder::<TxIn>::new());
            }
            Self::Inputs(version, attempt, decoder) => {
                let inputs = decoder.end().map_err(|e| E(Inner::Inputs(e)))?;
                *self = next_state_after_inputs(version, attempt, inputs);
            }
            Self::SegwitFlag(version) => {
                let segwit_flag = bytes[0];
                *bytes = &bytes[1..];

                if segwit_flag != 1 {
                    return Err(E(Inner::UnsupportedSegwitFlag(segwit_flag)));
                }
                *self = Self::Inputs(version, Attempt::Second, VecDecoder::<TxIn>::new());
            }
            Self::Outputs(version, inputs, is_segwit, decoder) => {
                let outputs = decoder.end().map_err(|e| E(Inner::Outputs(e)))?;
                *self = next_state_after_outputs(version, inputs, is_segwit, outputs);
            }
            Self::Witnesses(version, mut inputs, outputs, iteration, decoder) => {
                let iteration = iteration.0;

                inputs[iteration].witness = decoder.end().map_err(|e| E(Inner::Witness(e)))?;
                *self = next_state_after_witness(version, inputs, outputs, iteration)?;
            }
            Self::LockTime(version, inputs, outputs, decoder) => {
                let lock_time = decoder.end().map_err(|e| E(Inner::LockTime(e)))?;
                *self = Self::Done(Transaction { version, lock_time, inputs, outputs });
                return Ok(Some(false));
            }
            Self::Done(tx) => {
                *self = Self::Done(tx);
                return Ok(Some(false));
            }
            Self::Errored => unreachable!("checked above"),
        }

        Ok(None)
    }
}

#[cfg(feature = "alloc")]
fn next_state_after_inputs(
    version: Version,
    attempt: Attempt,
    inputs: Vec<TxIn>,
) -> TransactionDecoderState {
    use TransactionDecoderState as State;

    if Attempt::First == attempt && inputs.is_empty() {
        State::SegwitFlag(version)
    } else {
        let is_segwit = if Attempt::First == attempt { IsSegwit::No } else { IsSegwit::Yes };
        State::Outputs(version, inputs, is_segwit, VecDecoder::<TxOut>::new())
    }
}

#[cfg(feature = "alloc")]
fn next_state_after_outputs(
    version: Version,
    inputs: Vec<TxIn>,
    is_segwit: IsSegwit,
    outputs: Vec<TxOut>,
) -> TransactionDecoderState {
    use TransactionDecoderState as State;

    if is_segwit == IsSegwit::Yes && !inputs.is_empty() {
        State::Witnesses(version, inputs, outputs, Iteration(0), WitnessDecoder::new())
    } else {
        State::LockTime(version, inputs, outputs, LockTimeDecoder::new())
    }
}

#[cfg(feature = "alloc")]
fn next_state_after_witness(
    version: Version,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    iteration: usize,
) -> Result<TransactionDecoderState, TransactionDecoderError> {
    use TransactionDecoderError as E;
    use TransactionDecoderErrorInner as Inner;
    use TransactionDecoderState as State;

    if iteration < inputs.len() - 1 {
        return Ok(State::Witnesses(
            version,
            inputs,
            outputs,
            Iteration(iteration + 1),
            WitnessDecoder::new(),
        ));
    }

    if !inputs.is_empty() && inputs.iter().all(|input| input.witness.is_empty()) {
        return Err(E(Inner::NoWitnesses));
    }

    Ok(State::LockTime(version, inputs, outputs, LockTimeDecoder::new()))
}

#[cfg(feature = "alloc")]
fn validate_decoded_transaction(tx: Transaction) -> Result<Transaction, TransactionDecoderError> {
    check_transaction_sanity(&tx)?;
    Ok(tx)
}

#[cfg(feature = "alloc")]
fn validate_transaction_has_inputs(tx: &Transaction) -> Result<(), TransactionSanityError> {
    if tx.inputs.is_empty() {
        return Err(TransactionSanityError::NoInputs);
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn validate_transaction_has_outputs(tx: &Transaction) -> Result<(), TransactionSanityError> {
    if tx.outputs.is_empty() {
        return Err(TransactionSanityError::NoOutputs);
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn validate_transaction_base_size(tx: &Transaction) -> Result<(), TransactionSanityError> {
    let stripped_weight = tx.base_size().to_u64().saturating_mul(Weight::WITNESS_SCALE_FACTOR);
    if stripped_weight > Weight::MAX_BLOCK.to_wu() {
        return Err(TransactionSanityError::Oversize { stripped_weight });
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn validate_non_coinbase_prevouts(tx: &Transaction) -> Result<(), TransactionSanityError> {
    if tx.inputs.len() <= 1 {
        return Ok(());
    }

    for (index, input) in tx.inputs.iter().enumerate() {
        if input.previous_output == OutPoint::COINBASE_PREVOUT {
            return Err(TransactionSanityError::NullPrevoutInNonCoinbase { index });
        }
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn validate_coinbase_script_sig_len(tx: &Transaction) -> Result<(), TransactionSanityError> {
    if !tx.is_coinbase() {
        return Ok(());
    }

    let len = tx.inputs[0].script_sig.len();
    if len < 2 {
        return Err(TransactionSanityError::CoinbaseScriptSigTooSmall { len });
    }
    if len > 106 {
        return Err(TransactionSanityError::CoinbaseScriptSigTooLarge { len });
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn validate_unique_inputs(tx: &Transaction) -> Result<(), TransactionSanityError> {
    let mut outpoints: Vec<_> = tx.inputs.iter().map(|i| i.previous_output).collect();
    outpoints.sort_unstable();
    for pair in outpoints.windows(2) {
        if pair[0] == pair[1] {
            return Err(TransactionSanityError::DuplicateInput(pair[0]));
        }
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn validate_output_value_sum(tx: &Transaction) -> Result<(), TransactionSanityError> {
    let mut total_out: u64 = 0;
    for output in &tx.outputs {
        total_out = total_out.saturating_add(output.amount.to_sat());
        if total_out > Amount::MAX_MONEY.to_sat() {
            return Err(TransactionSanityError::OutputValueSumTooLarge(total_out));
        }
    }
    Ok(())
}

/// Context-free transaction sanity error.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransactionSanityError {
    /// Transaction has no inputs.
    NoInputs,
    /// Transaction has no outputs.
    NoOutputs,
    /// The stripped transaction weight is larger than the consensus block weight limit.
    Oversize {
        /// Stripped transaction weight in weight units.
        stripped_weight: u64,
    },
    /// Null prevout in non-coinbase transaction.
    NullPrevoutInNonCoinbase {
        /// Invalid input index.
        index: usize,
    },
    /// Coinbase scriptSig too small (must be at least 2 bytes).
    CoinbaseScriptSigTooSmall {
        /// Actual scriptSig length.
        len: usize,
    },
    /// Coinbase scriptSig is too large (must be at most 106 bytes).
    CoinbaseScriptSigTooLarge {
        /// Actual scriptSig length.
        len: usize,
    },
    /// Transaction has duplicate inputs.
    DuplicateInput(OutPoint),
    /// Sum of output values exceeds `MAX_MONEY`.
    OutputValueSumTooLarge(u64),
}

#[cfg(feature = "alloc")]
impl fmt::Display for TransactionSanityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInputs => write!(f, "transaction has no inputs"),
            Self::NoOutputs => write!(f, "transaction has no outputs"),
            Self::Oversize { stripped_weight } => write!(
                f,
                "transaction stripped weight {} exceeds max block weight {}",
                stripped_weight,
                Weight::MAX_BLOCK.to_wu()
            ),
            Self::NullPrevoutInNonCoinbase { index } => {
                write!(f, "null prevout in non-coinbase transaction at input {}", index)
            }
            Self::CoinbaseScriptSigTooSmall { len } => {
                write!(f, "coinbase scriptSig too small: {} bytes (min 2)", len)
            }
            Self::CoinbaseScriptSigTooLarge { len } => {
                write!(f, "coinbase scriptSig too large: {} bytes (max 106)", len)
            }
            Self::DuplicateInput(outpoint) => {
                write!(f, "duplicate input: {:?}:{}", outpoint.txid, outpoint.vout)
            }
            Self::OutputValueSumTooLarge(val) => {
                write!(f, "sum of output values {} satoshis exceeds MAX_MONEY", val)
            }
        }
    }
}

#[cfg(all(feature = "alloc", feature = "std"))]
impl std::error::Error for TransactionSanityError {}

#[cfg(feature = "alloc")]
impl encoding::Decodable for Transaction {
    type Decoder = TransactionDecoder;
    fn decoder() -> Self::Decoder {
        TransactionDecoder::new()
    }
}

/// The state of the transiting decoder.
#[cfg(feature = "alloc")]
enum TransactionDecoderState {
    /// Decoding the transaction version.
    Version(VersionDecoder),
    /// Decoding the transaction inputs.
    Inputs(Version, Attempt, VecDecoder<TxIn>),
    /// Decoding the segwit flag.
    SegwitFlag(Version),
    /// Decoding the transaction outputs.
    Outputs(Version, Vec<TxIn>, IsSegwit, VecDecoder<TxOut>),
    /// Decoding the segwit transaction witnesses.
    Witnesses(Version, Vec<TxIn>, Vec<TxOut>, Iteration, WitnessDecoder),
    /// Decoding the transaction lock time.
    LockTime(Version, Vec<TxIn>, Vec<TxOut>, LockTimeDecoder),
    /// Done decoding the [`Transaction`].
    Done(Transaction),
    /// When `end()`ing a sub-decoder, encountered an error which prevented us
    /// from constructing the next sub-decoder.
    Errored,
}

/// Boolean used to track number of times we have attempted to decode the inputs vector.
#[cfg(feature = "alloc")]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Attempt {
    /// First time reading inputs.
    First,
    /// Second time reading inputs.
    Second,
}

/// Boolean used to track whether or not this transaction uses segwit encoding.
#[cfg(feature = "alloc")]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum IsSegwit {
    /// Yes so uses segwit encoding.
    Yes,
    /// No segwit flag, marker, or witnesses.
    No,
}

/// How many times we have state transitioned to encoding a witness (zero-based).
#[cfg(feature = "alloc")]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct Iteration(usize);

/// An error consensus decoding a `Transaction`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDecoderError(TransactionDecoderErrorInner);

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum TransactionDecoderErrorInner {
    /// Error while decoding the `version`.
    Version(VersionDecoderError),
    /// We only support segwit flag value 0x01.
    UnsupportedSegwitFlag(u8),
    /// Error while decoding the `inputs`.
    Inputs(VecDecoderError<TxInDecoderError>),
    /// Error while decoding the `outputs`.
    Outputs(VecDecoderError<TxOutDecoderError>),
    /// Error while decoding one of the witnesses.
    Witness(WitnessDecoderError),
    /// Non-empty Segwit transaction with no witnesses.
    NoWitnesses,
    /// Transaction stripped weight exceeds the consensus block weight limit.
    Oversize { stripped_weight: u64 },
    /// Error while decoding the `lock_time`.
    LockTime(LockTimeDecoderError),
    /// Attempt to call `end()` before the transaction was complete. Holds
    /// a description of the current state.
    EarlyEnd(&'static str),
    /// Null prevout in non-coinbase transaction.
    NullPrevoutInNonCoinbase(usize),
    /// Coinbase scriptSig too small (must be at least 2 bytes).
    CoinbaseScriptSigTooSmall(usize),
    /// Coinbase scriptSig is too large (must be at most 106 bytes).
    CoinbaseScriptSigTooLarge(usize),
    /// Transaction has duplicate inputs (this check prevents CVE-2018-17144 ).
    DuplicateInput(OutPoint),
    /// Sum of output values exceeds `MAX_MONEY`
    OutputValueSumTooLarge(u64),
    /// Transaction has no inputs.
    NoInputs,
    /// Transaction has no outputs.
    NoOutputs,
}

#[cfg(feature = "alloc")]
impl From<Infallible> for TransactionDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

#[cfg(feature = "alloc")]
impl From<TransactionSanityError> for TransactionDecoderError {
    fn from(err: TransactionSanityError) -> Self {
        use TransactionSanityError as E;

        let inner = match err {
            E::NoInputs => TransactionDecoderErrorInner::NoInputs,
            E::NoOutputs => TransactionDecoderErrorInner::NoOutputs,
            E::Oversize { stripped_weight } => {
                TransactionDecoderErrorInner::Oversize { stripped_weight }
            }
            E::NullPrevoutInNonCoinbase { index } => {
                TransactionDecoderErrorInner::NullPrevoutInNonCoinbase(index)
            }
            E::CoinbaseScriptSigTooSmall { len } => {
                TransactionDecoderErrorInner::CoinbaseScriptSigTooSmall(len)
            }
            E::CoinbaseScriptSigTooLarge { len } => {
                TransactionDecoderErrorInner::CoinbaseScriptSigTooLarge(len)
            }
            E::DuplicateInput(outpoint) => TransactionDecoderErrorInner::DuplicateInput(outpoint),
            E::OutputValueSumTooLarge(total) => {
                TransactionDecoderErrorInner::OutputValueSumTooLarge(total)
            }
        };
        Self(inner)
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for TransactionDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use TransactionDecoderErrorInner as E;

        match self.0 {
            E::Version(ref e) => write_err!(f, "transaction decoder error"; e),
            E::UnsupportedSegwitFlag(v) => {
                write!(f, "we only support segwit flag value 0x01: {}", v)
            }
            E::Inputs(ref e) => write_err!(f, "transaction decoder error"; e),
            E::Outputs(ref e) => write_err!(f, "transaction decoder error"; e),
            E::Witness(ref e) => write_err!(f, "transaction decoder error"; e),
            E::NoWitnesses => write!(f, "non-empty Segwit transaction with no witnesses"),
            E::Oversize { stripped_weight } => write!(
                f,
                "transaction stripped weight {} exceeds max block weight {}",
                stripped_weight,
                Weight::MAX_BLOCK.to_wu()
            ),
            E::LockTime(ref e) => write_err!(f, "transaction decoder error"; e),
            E::EarlyEnd(s) => write!(f, "early end of transaction (still decoding {})", s),
            E::NullPrevoutInNonCoinbase(index) => {
                write!(f, "null prevout in non-coinbase transaction at input {}", index)
            }
            E::CoinbaseScriptSigTooSmall(len) => {
                write!(f, "coinbase scriptSig too small: {} bytes (min 2)", len)
            }
            E::CoinbaseScriptSigTooLarge(len) => {
                write!(f, "coinbase scriptSig too large: {} bytes (max 106)", len)
            }
            E::DuplicateInput(ref outpoint) => {
                write!(f, "duplicate input: {:?}:{}", outpoint.txid, outpoint.vout)
            }
            E::OutputValueSumTooLarge(val) => {
                write!(f, "sum of output values {} satoshis exceeds MAX_MONEY", val)
            }
            E::NoInputs => write!(f, "transaction has no inputs"),
            E::NoOutputs => write!(f, "transaction has no outputs"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "alloc")]
impl std::error::Error for TransactionDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TransactionDecoderErrorInner as E;

        match self.0 {
            E::Version(ref e) => Some(e),
            E::UnsupportedSegwitFlag(_) => None,
            E::Inputs(ref e) => Some(e),
            E::Outputs(ref e) => Some(e),
            E::Witness(ref e) => Some(e),
            E::NoWitnesses => None,
            E::Oversize { .. } => None,
            E::LockTime(ref e) => Some(e),
            E::EarlyEnd(_) => None,
            E::NullPrevoutInNonCoinbase(_) => None,
            E::CoinbaseScriptSigTooSmall(_) => None,
            E::CoinbaseScriptSigTooLarge(_) => None,
            E::DuplicateInput(_) => None,
            E::OutputValueSumTooLarge(_) => None,
            E::NoInputs => None,
            E::NoOutputs => None,
        }
    }
}

/// Tidecoin transaction input.
///
/// It contains the location of the previous transaction's output,
/// that it spends and set of scripts that satisfy its spending
/// conditions.
///
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg(feature = "alloc")]
pub struct TxIn {
    /// The reference to the previous output that is being used as an input.
    pub previous_output: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to be accepted.
    pub script_sig: ScriptSigBuf,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behavior cannot be enforced.
    pub sequence: Sequence,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the `TxIn` in
    /// Encodable/Decodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the `TxIn` in other
    /// (de)serialization routines.
    pub witness: Witness,
}

#[cfg(feature = "alloc")]
impl TxIn {
    /// An empty transaction input with the previous output as for a coinbase transaction.
    ///
    /// This has a 0-byte scriptSig which is **invalid** per consensus rules
    /// (coinbase scriptSig must be 2-106 bytes). It is a construction template for
    /// code that fills the coinbase scriptSig before encoding or validation.
    pub const EMPTY_COINBASE: Self = Self {
        previous_output: OutPoint::COINBASE_PREVOUT,
        script_sig: ScriptSigBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };

    /// Returns the base size of this input.
    ///
    /// Base size excludes witness data.
    pub fn base_size(&self) -> usize {
        OutPoint::SIZE
            + CompactSizeEncoder::encoded_size(self.script_sig.len())
            + self.script_sig.len()
            + Sequence::SIZE
    }

    /// Returns the total number of bytes that this input contributes to a transaction.
    ///
    /// Total size includes witness data.
    #[inline]
    pub fn total_size(&self) -> usize {
        self.base_size() + self.witness.size()
    }
}

#[cfg(feature = "alloc")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`TxIn`] type.
    pub struct TxInEncoder<'e>(
        Encoder3<OutPointEncoder<'e>, ScriptEncoder<'e>, SequenceEncoder<'e>>
    );
}

#[cfg(feature = "alloc")]
impl encoding::Encodable for TxIn {
    type Encoder<'e>
        = Encoder3<OutPointEncoder<'e>, ScriptEncoder<'e>, SequenceEncoder<'e>>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder3::new(
            self.previous_output.encoder(),
            self.script_sig.encoder(),
            self.sequence.encoder(),
        )
    }
}

/// Encodes the witnesses from a list of inputs.
#[cfg(feature = "alloc")]
pub struct WitnessesEncoder<'e> {
    inputs: &'e [TxIn],
    /// Encoder for the current witness being encoded.
    cur_enc: Option<WitnessEncoder<'e>>,
}

#[cfg(feature = "alloc")]
impl<'e> WitnessesEncoder<'e> {
    /// Constructs a new encoder for all witnesses in a list of transaction inputs.
    pub fn new(inputs: &'e [TxIn]) -> Self {
        Self { inputs, cur_enc: inputs.first().map(|input| input.witness.encoder()) }
    }
}

#[cfg(feature = "alloc")]
impl encoding::Encoder for WitnessesEncoder<'_> {
    #[inline]
    fn current_chunk(&self) -> &[u8] {
        self.cur_enc.as_ref().map(WitnessEncoder::current_chunk).unwrap_or_default()
    }

    #[inline]
    fn advance(&mut self) -> bool {
        let Some(cur) = self.cur_enc.as_mut() else {
            return false;
        };

        loop {
            // On subsequent calls, attempt to advance the current encoder and return
            // success if this succeeds.
            if cur.advance() {
                return true;
            }
            // self.inputs guaranteed to be non-empty if cur_enc is non-None.
            self.inputs = &self.inputs[1..];

            // If advancing the current encoder failed, attempt to move to the next encoder.
            if let Some(input) = self.inputs.first() {
                *cur = input.witness.encoder();
                if !cur.current_chunk().is_empty() {
                    return true;
                }
            } else {
                self.cur_enc = None; // shortcut the next call to advance()
                return false;
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl encoding::ExactSizeEncoder for WitnessesEncoder<'_> {
    fn len(&self) -> usize {
        let Some(cur_enc) = self.cur_enc.as_ref() else {
            return 0;
        };

        let rest = self
            .inputs
            .get(1..)
            .unwrap_or_default()
            .iter()
            .map(|input| input.witness.encoder().len());
        cur_enc.len() + rest.sum::<usize>()
    }
}

#[cfg(feature = "alloc")]
type TxInInnerDecoder = Decoder3<OutPointDecoder, ScriptSigBufDecoder, SequenceDecoder>;

/// The decoder for the [`TxIn`] type.
#[cfg(feature = "alloc")]
pub struct TxInDecoder(TxInInnerDecoder);

#[cfg(feature = "alloc")]
impl TxInDecoder {
    /// Constructs a new [`TxIn`] decoder.
    pub const fn new() -> Self {
        Self(Decoder3::new(
            OutPointDecoder::new(),
            ScriptSigBufDecoder::new(),
            SequenceDecoder::new(),
        ))
    }
}

#[cfg(feature = "alloc")]
impl Default for TxInDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl encoding::Decoder for TxInDecoder {
    type Output = TxIn;
    type Error = TxInDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(TxInDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (previous_output, script_sig, sequence) = self.0.end().map_err(TxInDecoderError)?;
        Ok(TxIn { previous_output, script_sig, sequence, witness: Witness::default() })
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

#[cfg(feature = "alloc")]
impl encoding::Decodable for TxIn {
    type Decoder = TxInDecoder;
    fn decoder() -> Self::Decoder {
        TxInDecoder(Decoder3::new(
            OutPointDecoder::new(),
            ScriptSigBufDecoder::new(),
            SequenceDecoder::new(),
        ))
    }
}

/// An error consensus decoding a `TxIn`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInDecoderError(<TxInInnerDecoder as encoding::Decoder>::Error);

#[cfg(feature = "alloc")]
impl From<Infallible> for TxInDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for TxInDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "txin decoder error"; self.0)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "std")]
impl std::error::Error for TxInDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Tidecoin transaction output.
///
/// Defines new coins to be created as a result of the transaction,
/// along with spending conditions ("script", aka "output script"),
/// which an input spending it must satisfy.
///
/// An output that is not yet spent by an input is called Unspent Transaction Output ("UTXO").
///
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg(feature = "alloc")]
pub struct TxOut {
    /// The value of the output.
    pub amount: Amount,
    /// The script which must be satisfied for the output to be spent.
    pub script_pubkey: ScriptPubKeyBuf,
}

#[cfg(feature = "alloc")]
impl TxOut {
    /// Returns the weight of this output.
    ///
    /// # Panics
    ///
    /// Panics if the output size cannot be represented as weight. This should not happen for an
    /// output held in memory.
    #[inline]
    pub fn weight(&self) -> Weight {
        Weight::from_vb(self.size().to_u64()).expect("output size cannot overflow weight")
    }

    /// Returns the number of bytes that this output contributes to a transaction.
    #[inline]
    pub fn size(&self) -> usize {
        Amount::SIZE
            + CompactSizeEncoder::encoded_size(self.script_pubkey.len())
            + self.script_pubkey.len()
    }
}

#[cfg(feature = "alloc")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`TxOut`] type.
    pub struct TxOutEncoder<'e>(Encoder2<AmountEncoder<'e>, ScriptEncoder<'e>>);
}

#[cfg(feature = "alloc")]
impl encoding::Encodable for TxOut {
    type Encoder<'e>
        = Encoder2<AmountEncoder<'e>, ScriptEncoder<'e>>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(self.amount.encoder(), self.script_pubkey.encoder())
    }
}

#[cfg(feature = "alloc")]
type TxOutInnerDecoder = Decoder2<AmountDecoder, ScriptPubKeyBufDecoder>;

/// The decoder for the [`TxOut`] type.
#[cfg(feature = "alloc")]
pub struct TxOutDecoder(TxOutInnerDecoder);

#[cfg(feature = "alloc")]
impl TxOutDecoder {
    /// Constructs a new [`TxOut`] decoder.
    pub const fn new() -> Self {
        Self(Decoder2::new(AmountDecoder::new(), ScriptPubKeyBufDecoder::new()))
    }
}

#[cfg(feature = "alloc")]
impl Default for TxOutDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl encoding::Decoder for TxOutDecoder {
    type Output = TxOut;
    type Error = TxOutDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(TxOutDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (amount, script_pubkey) = self.0.end().map_err(TxOutDecoderError)?;
        Ok(TxOut { amount, script_pubkey })
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

#[cfg(feature = "alloc")]
impl encoding::Decodable for TxOut {
    type Decoder = TxOutDecoder;
    fn decoder() -> Self::Decoder {
        TxOutDecoder(Decoder2::new(AmountDecoder::new(), ScriptPubKeyBufDecoder::new()))
    }
}

/// An error consensus decoding a `TxOut`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutDecoderError(<TxOutInnerDecoder as encoding::Decoder>::Error);

#[cfg(feature = "alloc")]
impl From<Infallible> for TxOutDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for TxOutDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "txout decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxOutDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// A reference to a transaction output.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct OutPoint {
    /// The referenced transaction's txid.
    pub txid: Txid,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}

impl OutPoint {
    /// The number of bytes that an outpoint contributes to the size of a transaction.
    pub const SIZE: usize = 32 + 4; // The serialized lengths of txid and vout.

    /// The `OutPoint` used in a coinbase prevout.
    ///
    /// This is used as the dummy input for coinbase transactions because they don't have any
    /// previous outputs. In other words, does not point to a real transaction.
    pub const COINBASE_PREVOUT: Self = Self { txid: Txid::COINBASE_PREVOUT, vout: u32::MAX };
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`OutPoint`] type.
    pub struct OutPointEncoder<'e>(Encoder2<BytesEncoder<'e>, ArrayEncoder<4>>);
}

impl encoding::Encodable for OutPoint {
    type Encoder<'e>
        = OutPointEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        OutPointEncoder::new(Encoder2::new(
            BytesEncoder::without_length_prefix(self.txid.as_byte_array()),
            ArrayEncoder::without_length_prefix(self.vout.to_le_bytes()),
        ))
    }
}

#[cfg(feature = "hex")]
impl fmt::Display for OutPoint {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl core::str::FromStr for OutPoint {
    type Err = ParseOutPointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 75 {
            // 64 + 1 + 10
            return Err(ParseOutPointError::TooLong);
        }
        let find = s.find(':');
        if find.is_none() || find != s.rfind(':') {
            return Err(ParseOutPointError::Format);
        }
        let colon = find.unwrap();
        if colon == 0 || colon == s.len() - 1 {
            return Err(ParseOutPointError::Format);
        }
        Ok(Self {
            txid: s[..colon].parse().map_err(ParseOutPointError::Txid)?,
            vout: parse_vout(&s[colon + 1..])?,
        })
    }
}

/// Parses a string-encoded transaction index (vout).
///
/// Does not permit leading zeroes or non-digit characters.
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
fn parse_vout(s: &str) -> Result<u32, ParseOutPointError> {
    if s.len() > 1 {
        let first = s.chars().next().unwrap();
        if first == '0' || first == '+' {
            return Err(ParseOutPointError::VoutNotCanonical);
        }
    }
    parse_int::int_from_str(s).map_err(ParseOutPointError::Vout)
}

/// The decoder for the [`OutPoint`] type.
// 32 for the txid + 4 for the vout
pub struct OutPointDecoder(encoding::ArrayDecoder<36>);

impl OutPointDecoder {
    /// Constructs a new [`OutPoint`] decoder.
    pub const fn new() -> Self {
        Self(encoding::ArrayDecoder::new())
    }
}

impl Default for OutPointDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl encoding::Decoder for OutPointDecoder {
    type Output = OutPoint;
    type Error = OutPointDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(OutPointDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let encoded = self.0.end().map_err(OutPointDecoderError)?;
        let (txid_buf, vout_buf) = encoded.split_array::<32, 4>();

        let txid = Txid::from_byte_array(*txid_buf);
        let vout = u32::from_le_bytes(*vout_buf);

        Ok(OutPoint { txid, vout })
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for OutPoint {
    type Decoder = OutPointDecoder;
    fn decoder() -> Self::Decoder {
        OutPointDecoder::default()
    }
}

/// Error while decoding an `OutPoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutPointDecoderError(UnexpectedEofError);

impl From<Infallible> for OutPointDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl core::fmt::Display for OutPointDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write_err!(f, "out point decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutPointDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[cfg(feature = "serde")]
impl Serialize for OutPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&self)
        } else {
            use crate::serde::ser::SerializeStruct as _;

            let mut state = serializer.serialize_struct("OutPoint", 2)?;
            // serializing as an array was found in the past to break for some serializers so we use
            // a slice instead. This causes 8 bytes to be prepended for the length (even though this
            // is a bit silly because know the length).
            state.serialize_field("txid", self.txid.as_byte_array().as_slice())?;
            state.serialize_field("vout", &self.vout.to_le_bytes())?;
            state.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for OutPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct StringVisitor;

            impl de::Visitor<'_> for StringVisitor {
                type Value = OutPoint;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a string in format 'txid:vout'")
                }

                fn visit_str<E>(self, value: &str) -> Result<OutPoint, E>
                where
                    E: de::Error,
                {
                    value.parse::<OutPoint>().map_err(de::Error::custom)
                }
            }

            deserializer.deserialize_str(StringVisitor)
        } else {
            #[derive(Deserialize)]
            #[serde(field_identifier, rename_all = "lowercase")]
            enum Field {
                Txid,
                Vout,
            }

            struct OutPointVisitor;

            impl<'de> de::Visitor<'de> for OutPointVisitor {
                type Value = OutPoint;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("OutPoint struct with fields")
                }

                fn visit_seq<V>(self, mut seq: V) -> Result<OutPoint, V::Error>
                where
                    V: de::SeqAccess<'de>,
                {
                    let txid =
                        seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                    let vout =
                        seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;
                    Ok(OutPoint { txid, vout })
                }

                fn visit_map<V>(self, mut map: V) -> Result<OutPoint, V::Error>
                where
                    V: de::MapAccess<'de>,
                {
                    let mut txid = None;
                    let mut vout = None;

                    while let Some(key) = map.next_key()? {
                        match key {
                            Field::Txid => {
                                if txid.is_some() {
                                    return Err(de::Error::duplicate_field("txid"));
                                }
                                let bytes: [u8; 32] = map.next_value()?;
                                txid = Some(Txid::from_byte_array(bytes));
                            }
                            Field::Vout => {
                                if vout.is_some() {
                                    return Err(de::Error::duplicate_field("vout"));
                                }
                                let bytes: [u8; 4] = map.next_value()?;
                                vout = Some(u32::from_le_bytes(bytes));
                            }
                        }
                    }

                    let txid = txid.ok_or_else(|| de::Error::missing_field("txid"))?;
                    let vout = vout.ok_or_else(|| de::Error::missing_field("vout"))?;

                    Ok(OutPoint { txid, vout })
                }
            }

            const FIELDS: &[&str] = &["txid", "vout"];
            deserializer.deserialize_struct("OutPoint", FIELDS, OutPointVisitor)
        }
    }
}

/// An error in parsing an [`OutPoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
pub enum ParseOutPointError {
    /// Error in TXID part.
    Txid(hex::DecodeFixedLengthBytesError),
    /// Error in vout part.
    Vout(parse_int::ParseIntError),
    /// Error in general format.
    Format,
    /// Size exceeds max.
    TooLong,
    /// Vout part is not strictly numeric without leading zeroes.
    VoutNotCanonical,
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl From<Infallible> for ParseOutPointError {
    #[inline]
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl fmt::Display for ParseOutPointError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Txid(ref e) => write_err!(f, "error parsing TXID"; e),
            Self::Vout(ref e) => write_err!(f, "error parsing vout"; e),
            Self::Format => write!(f, "OutPoint not in <txid>:<vout> format"),
            Self::TooLong => write!(f, "vout should be at most 10 digits"),
            Self::VoutNotCanonical => write!(f, "no leading zeroes or + allowed in vout part"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "hex")]
impl std::error::Error for ParseOutPointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Txid(e) => Some(e),
            Self::Vout(e) => Some(e),
            Self::Format | Self::TooLong | Self::VoutNotCanonical => None,
        }
    }
}

/// The transaction version.
///
/// Currently, versions 1, 2, and 3 are considered standard by Tidecoin policy.
///
/// Standardness of the inner `u32` is not an invariant because you are free to create transactions
/// of any version, transactions with non-standard version numbers will not be relayed by the
/// Tidecoin network.
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version(u32);

impl Version {
    /// The number of bytes that a transaction version contributes to the size of a transaction.
    pub const SIZE: usize = 4;

    /// Tidecoin transaction version 1.
    pub const ONE: Self = Self(1);

    /// Tidecoin transaction version 2.
    pub const TWO: Self = Self(2);

    /// Tidecoin transaction version 3.
    pub const THREE: Self = Self(3);

    /// Constructs a potentially non-standard transaction version.
    ///
    /// This can accept both standard and non-standard versions.
    #[inline]
    pub const fn maybe_non_standard(version: u32) -> Self {
        Self(version)
    }

    /// Returns the inner `u32` value of this `Version`.
    #[inline]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    /// Returns true if this transaction version number is considered standard.
    ///
    /// The behavior of this method follows the Tidecoin standardness policy for this release:
    /// versions 1, 2, and 3 are considered standard.
    #[inline]
    pub const fn is_standard(self) -> bool {
        self.0 == Self::ONE.0 || self.0 == Self::TWO.0 || self.0 == Self::THREE.0
    }
}

impl fmt::Display for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Octal for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Octal::fmt(&self.0, f)
    }
}

impl fmt::Binary for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Binary::fmt(&self.0, f)
    }
}

impl From<Version> for u32 {
    #[inline]
    fn from(version: Version) -> Self {
        version.0
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`Version`] type.
    pub struct VersionEncoder<'e>(encoding::ArrayEncoder<4>);
}

impl encoding::Encodable for Version {
    type Encoder<'e> = VersionEncoder<'e>;
    fn encoder(&self) -> Self::Encoder<'_> {
        VersionEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_u32().to_le_bytes(),
        ))
    }
}

/// The decoder for the [`Version`] type.
pub struct VersionDecoder(encoding::ArrayDecoder<4>);

impl VersionDecoder {
    /// Constructs a new [`Version`] decoder.
    pub const fn new() -> Self {
        Self(encoding::ArrayDecoder::new())
    }
}

impl Default for VersionDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl encoding::Decoder for VersionDecoder {
    type Output = Version;
    type Error = VersionDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(VersionDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.0.end().map_err(VersionDecoderError)?;
        let n = u32::from_le_bytes(bytes);
        Ok(Version::maybe_non_standard(n))
    }

    #[inline]
    fn read_limit(&self) -> usize {
        self.0.read_limit()
    }
}

impl encoding::Decodable for Version {
    type Decoder = VersionDecoder;
    fn decoder() -> Self::Decoder {
        VersionDecoder(encoding::ArrayDecoder::<4>::new())
    }
}

/// An error consensus decoding an `Version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDecoderError(encoding::UnexpectedEofError);

impl From<Infallible> for VersionDecoderError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for VersionDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "version decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VersionDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for Transaction {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: Version::arbitrary(u)?,
            lock_time: absolute::LockTime::arbitrary(u)?,
            inputs: Vec::<TxIn>::arbitrary(u)?,
            outputs: Vec::<TxOut>::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for TxIn {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            previous_output: OutPoint::arbitrary(u)?,
            script_sig: ScriptSigBuf::arbitrary(u)?,
            sequence: Sequence::arbitrary(u)?,
            witness: Witness::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for TxOut {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { amount: Amount::arbitrary(u)?, script_pubkey: ScriptPubKeyBuf::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for OutPoint {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { txid: Txid::arbitrary(u)?, vout: u32::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Version {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Equally weight the case of normal version numbers
        let choice = u.int_in_range(0..=3)?;
        match choice {
            0 => Ok(Self::ONE),
            1 => Ok(Self::TWO),
            2 => Ok(Self::THREE),
            _ => Ok(Self(u.arbitrary()?)),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::{format, vec};
    #[cfg(feature = "hex")]
    use core::str::FromStr as _;
    #[cfg(feature = "std")]
    use std::error::Error as _;

    use encoding::{Decodable as _, Decoder as _, Encoder as _};
    #[cfg(feature = "hex")]
    use internals::hex_lit as hex;

    use super::*;
    #[cfg(all(feature = "alloc", feature = "hex"))]
    use crate::absolute::LockTime;

    const TC_TXID_BYTES: [u8; 32] = [
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];
    const TC_VOUT_BYTES: [u8; 4] = [1, 0, 0, 0];
    const TC_SCRIPT_BYTES: [u8; 3] = [1, 2, 3];
    #[cfg(feature = "hex")]
    const TC_SEQ_MAX_BYTES: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
    #[cfg(feature = "hex")]
    const TC_LOCK_TIME_ZERO_BYTES: [u8; 4] = [0, 0, 0, 0];
    const TC_ONE_SAT_BYTES: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
    #[cfg(feature = "hex")]
    const TC_SEGWIT_MARKER_AND_FLAG: [u8; 2] = [0, 1];
    #[cfg(feature = "hex")]
    const TC_WITNESS_ELEM_LEN_AND_DATA: [u8; 4] = [3, 1, 2, 3];

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn transaction_encode_decode_roundtrip() {
        // Create two different inputs to avoid duplicate input rejection
        let tx_in_1 = segwit_tx_in();
        let mut tx_in_2 = segwit_tx_in();
        tx_in_2.previous_output.vout = 2;

        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![tx_in_1, tx_in_2],
            outputs: vec![tx_out(), tx_out()],
        };

        let encoded = encoding::encode_to_vec(&tx);

        let mut decoder = Transaction::decoder();
        let mut slice = encoded.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let decoded = decoder.end().unwrap();

        assert_eq!(tx, decoded);
    }

    #[test]
    fn sanity_check() {
        let version = Version(123);
        assert_eq!(version.to_u32(), 123);
        assert_eq!(u32::from(version), 123);

        assert!(!version.is_standard());
        assert!(Version::ONE.is_standard());
        assert!(Version::TWO.is_standard());
        assert!(Version::THREE.is_standard());
    }

    #[test]
    fn transaction_functions() {
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xAA; 32]), // Arbitrary invalid dummy value.
                vout: 0,
            },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let txout = TxOut {
            amount: Amount::from_sat(123_456_789).unwrap(),
            script_pubkey: ScriptPubKeyBuf::new(),
        };

        let tx_orig = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::from_consensus(1_738_968_231), // The time this was written
            inputs: vec![txin],
            outputs: vec![txout],
        };

        // Test changing the transaction
        let mut tx = tx_orig.clone();
        tx.inputs[0].previous_output.txid = Txid::from_byte_array([0xFF; 32]);
        tx.outputs[0].amount = Amount::from_sat(987_654_321).unwrap();
        assert_eq!(tx.inputs[0].previous_output.txid.to_byte_array(), [0xFF; 32]);
        assert_eq!(tx.outputs[0].amount.to_sat(), 987_654_321);

        // Test uses_segwit_serialization
        assert!(!tx.uses_segwit_serialization());
        tx.inputs[0].witness.push(vec![0xAB, 0xCD, 0xEF]);
        assert!(tx.uses_segwit_serialization());

        // Test partial ord
        assert!(tx > tx_orig);
    }

    #[test]
    #[cfg(feature = "hex")]
    fn transaction_hex_display() {
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xAA; 32]), // Arbitrary invalid dummy value.
                vout: 0,
            },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let txout = TxOut {
            amount: Amount::from_sat(123_456_789).unwrap(),
            script_pubkey: ScriptPubKeyBuf::new(),
        };

        let tx_orig = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::from_consensus(1_765_112_030), // The time this was written
            inputs: vec![txin],
            outputs: vec![txout],
        };

        let encoded_tx = "0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000ffffffff0115cd5b070000000000de783569";
        let lower_hex_tx = format!("{:x}", tx_orig);
        let upper_hex_tx = format!("{:X}", tx_orig);

        // All of these should yield a lowercase hex
        assert_eq!(encoded_tx, lower_hex_tx);
        assert_eq!(encoded_tx, format!("{}", tx_orig));

        // And this should yield uppercase hex
        let upper_encoded = encoded_tx
            .chars()
            .map(|chr| chr.to_ascii_uppercase())
            .collect::<alloc::string::String>();
        assert_eq!(upper_encoded, upper_hex_tx);
    }

    #[test]
    #[cfg(feature = "hex")]
    fn transaction_from_hex_str_round_trip() {
        // Create two different inputs to avoid duplicate input rejection
        let tx_in_1 = segwit_tx_in();
        let mut tx_in_2 = segwit_tx_in();
        tx_in_2.previous_output.vout = 2;

        // Create a transaction and convert it to a hex string
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![tx_in_1, tx_in_2],
            outputs: vec![tx_out(), tx_out()],
        };

        let lower_hex_tx = format!("{:x}", tx);
        let upper_hex_tx = format!("{:X}", tx);

        // Parse the hex strings back into transactions
        let parsed_lower = Transaction::from_str(&lower_hex_tx).unwrap();
        let parsed_upper = Transaction::from_str(&upper_hex_tx).unwrap();

        // The parsed transaction should match the originals
        assert_eq!(tx, parsed_lower);
        assert_eq!(tx, parsed_upper);
    }

    #[test]
    #[cfg(feature = "hex")]
    fn transaction_from_hex_str_error() {
        // OddLengthString error
        let odd = "abc"; // 3 chars, odd length
        let err = Transaction::from_str(odd).unwrap_err();
        assert!(matches!(err, ParseTransactionError(ParsePrimitiveError::OddLengthString(..))));

        // InvalidChar error
        let invalid = "zz";
        let err = Transaction::from_str(invalid).unwrap_err();
        assert!(matches!(err, ParseTransactionError(ParsePrimitiveError::InvalidChar(..))));

        // Decode error
        let bad = "deadbeef00"; // arbitrary even-length hex that will fail decoding
        let err = Transaction::from_str(bad).unwrap_err();
        assert!(matches!(err, ParseTransactionError(ParsePrimitiveError::Decode(..))));
    }

    #[test]
    #[cfg(feature = "hex")]
    fn outpoint_from_str() {
        // Check format errors
        let mut outpoint_str = "0".repeat(64); // No ":"
        let outpoint: Result<OutPoint, ParseOutPointError> = outpoint_str.parse();
        assert_eq!(outpoint, Err(ParseOutPointError::Format));

        outpoint_str.push(':'); // Empty vout
        let outpoint: Result<OutPoint, ParseOutPointError> = outpoint_str.parse();
        assert_eq!(outpoint, Err(ParseOutPointError::Format));

        outpoint_str.push('0'); // Correct format
        let outpoint: OutPoint = outpoint_str.parse().unwrap();
        assert_eq!(outpoint.txid, Txid::from_byte_array([0; 32]));
        assert_eq!(outpoint.vout, 0);

        // Check the number of bytes OutPoint contributes to the transaction is equal to SIZE
        let outpoint_size = outpoint.txid.as_byte_array().len() + outpoint.vout.to_le_bytes().len();
        assert_eq!(outpoint_size, OutPoint::SIZE);
    }

    #[test]
    #[cfg(feature = "hex")]
    fn outpoint_from_str_too_long() {
        // Check edge case: length exactly 75
        let mut outpoint_str = "0".repeat(64);
        outpoint_str.push_str(":1234567890");
        assert_eq!(outpoint_str.len(), 75);
        assert!(outpoint_str.parse::<OutPoint>().is_ok());

        // Check TooLong error (length 76)
        outpoint_str.push('0');
        assert_eq!(outpoint_str.len(), 76);
        let outpoint: Result<OutPoint, ParseOutPointError> = outpoint_str.parse();
        assert_eq!(outpoint, Err(ParseOutPointError::TooLong));
    }

    #[test]
    #[cfg(feature = "hex")]
    fn canonical_vout() {
        assert_eq!(parse_vout("0").unwrap(), 0);
        assert_eq!(parse_vout("1").unwrap(), 1);
        assert!(parse_vout("01").is_err()); // Leading zero not allowed
        assert!(parse_vout("+1").is_err()); // Non digits not allowed
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn outpoint_display_roundtrip() {
        let outpoint_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:1";
        let outpoint: OutPoint = outpoint_str.parse().unwrap();
        assert_eq!(format!("{}", outpoint), outpoint_str);
    }

    #[test]
    fn version_display() {
        let version = Version(123);
        assert_eq!(format!("{}", version), "123");
        assert_eq!(format!("{:x}", version), "7b");
        assert_eq!(format!("{:#x}", version), "0x7b");
        assert_eq!(format!("{:X}", version), "7B");
        assert_eq!(format!("{:#X}", version), "0x7B");
        assert_eq!(format!("{:o}", version), "173");
        assert_eq!(format!("{:#o}", version), "0o173");
        assert_eq!(format!("{:b}", version), "1111011");
        assert_eq!(format!("{:#b}", version), "0b1111011");
    }

    // Creates an arbitrary dummy outpoint.
    #[cfg(any(feature = "hex", feature = "serde"))]
    fn tc_out_point() -> OutPoint {
        let s = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:1";
        s.parse::<OutPoint>().unwrap()
    }

    #[test]
    #[cfg(feature = "serde")]
    fn out_point_serde_deserialize_human_readable() {
        // `sered` serialization is the same as `Display` but includes quotes.
        let ser = "\"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:1\"";
        let got = serde_json::from_str::<OutPoint>(ser).unwrap();
        let want = tc_out_point();

        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn out_point_serde_deserialize_non_human_readable() {
        #[rustfmt::skip]
        let bytes = [
            // Length, prepended by the `serde` infrastructure because we use
            // slice serialization instead of array even though we know the length.
            32, 0, 0, 0, 0, 0, 0, 0,
            // The txid bytes
            32, 31, 30, 29, 28, 27, 26, 25,
            24, 23, 22, 21, 20, 19, 18, 17,
            16, 15, 14, 13, 12, 11, 10, 9,
            8, 7, 6, 5, 4, 3, 2, 1,
            // The vout
            1, 0, 0, 0
        ];

        let got = bincode::deserialize::<OutPoint>(&bytes).unwrap();
        let want = tc_out_point();

        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn out_point_serde_human_readable_rountrips() {
        let out_point = tc_out_point();

        let ser = serde_json::to_string(&out_point).unwrap();
        let got = serde_json::from_str::<OutPoint>(&ser).unwrap();

        assert_eq!(got, out_point);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn out_point_serde_non_human_readable_rountrips() {
        let out_point = tc_out_point();

        let ser = bincode::serialize(&out_point).unwrap();
        let got = bincode::deserialize::<OutPoint>(&ser).unwrap();

        assert_eq!(got, out_point);
    }

    #[cfg(feature = "alloc")]
    fn tx_out() -> TxOut {
        TxOut { amount: Amount::ONE_SAT, script_pubkey: tc_script_pubkey() }
    }

    #[cfg(any(feature = "hex", feature = "serde"))]
    fn segwit_tx_in() -> TxIn {
        let data = [&TC_SCRIPT_BYTES[..]];
        let witness = Witness::from_iter(data);

        TxIn {
            previous_output: tc_out_point(),
            script_sig: tc_script_sig(),
            sequence: Sequence::MAX,
            witness,
        }
    }

    #[cfg(feature = "alloc")]
    fn tc_script_pubkey() -> ScriptPubKeyBuf {
        ScriptPubKeyBuf::from_bytes(TC_SCRIPT_BYTES.to_vec())
    }

    #[cfg(any(feature = "hex", feature = "serde"))]
    fn tc_script_sig() -> ScriptSigBuf {
        ScriptSigBuf::from_bytes(TC_SCRIPT_BYTES.to_vec())
    }

    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn synthetic_non_coinbase_input(tag: u8) -> TxIn {
        TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: tag.into() },
            script_sig: ScriptSigBuf::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn synthetic_output(amount: Amount) -> TxOut {
        TxOut { amount, script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0x51]) }
    }

    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn synthetic_non_coinbase_tx(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![synthetic_non_coinbase_input(0x11)],
            outputs,
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn encode_out_point() {
        let out_point = tc_out_point();
        let mut encoder = out_point.encoder();

        // The txid
        assert_eq!(encoder.current_chunk(), &TC_TXID_BYTES[..]);
        assert!(encoder.advance());

        // The vout
        assert_eq!(encoder.current_chunk(), &TC_VOUT_BYTES[..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn encode_tx_out() {
        let out = tx_out();
        let mut encoder = out.encoder();

        // The amount.
        assert_eq!(encoder.current_chunk(), &TC_ONE_SAT_BYTES[..]);
        assert!(encoder.advance());

        // The script pubkey length prefix.
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());

        // The script pubkey data.
        assert_eq!(encoder.current_chunk(), &TC_SCRIPT_BYTES[..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn encode_tx_in() {
        let txin = segwit_tx_in();
        let mut encoder = txin.encoder();

        // The outpoint (same as tested above).
        assert_eq!(encoder.current_chunk(), &TC_TXID_BYTES[..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_VOUT_BYTES[..]);
        assert!(encoder.advance());

        // The script sig
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_SCRIPT_BYTES[..]);
        assert!(encoder.advance());

        // The sequence
        assert_eq!(encoder.current_chunk(), &TC_SEQ_MAX_BYTES[..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn encode_segwit_transaction() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![segwit_tx_in()],
            outputs: vec![tx_out()],
        };

        let mut encoder = tx.encoder();

        // The version
        assert_eq!(encoder.current_chunk(), &[2u8, 0, 0, 0][..]);
        assert!(encoder.advance());

        // The segwit marker and flag
        assert_eq!(encoder.current_chunk(), &TC_SEGWIT_MARKER_AND_FLAG[..]);
        assert!(encoder.advance());

        // The input (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_TXID_BYTES[..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_VOUT_BYTES[..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_SCRIPT_BYTES[..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_SEQ_MAX_BYTES[..]);
        assert!(encoder.advance());

        // The output (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_ONE_SAT_BYTES[..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_SCRIPT_BYTES[..]);
        assert!(encoder.advance());

        // The witness
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_WITNESS_ELEM_LEN_AND_DATA[..]);
        assert!(encoder.advance());

        // The lock time.
        assert_eq!(encoder.current_chunk(), &TC_LOCK_TIME_ZERO_BYTES[..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn encode_non_segwit_transaction() {
        let mut tx_in = segwit_tx_in();
        tx_in.witness = Witness::default();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![tx_in],
            outputs: vec![tx_out()],
        };

        let mut encoder = tx.encoder();

        // The version
        assert_eq!(encoder.current_chunk(), &[2u8, 0, 0, 0][..]);
        assert!(encoder.advance());

        // Advance past the optional segwit bytes encoder.
        assert!(encoder.advance());

        // The input (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_TXID_BYTES[..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_VOUT_BYTES[..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_SCRIPT_BYTES[..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_SEQ_MAX_BYTES[..]);
        assert!(encoder.advance());

        // The output (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_ONE_SAT_BYTES[..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &TC_SCRIPT_BYTES[..]);
        assert!(encoder.advance());

        // Advance past the optional witnesses encoder.
        assert!(encoder.advance());

        // The lock time.
        assert_eq!(encoder.current_chunk(), &TC_LOCK_TIME_ZERO_BYTES[..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn decode_segwit_transaction() {
        let original = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![segwit_tx_in()],
            outputs: vec![tx_out()],
        };
        let tx_bytes = encoding::encode_to_vec(&original);
        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let tx = decoder.end().unwrap();

        // Attempt various truncations
        for i in [1, tx_bytes.len() / 4, tx_bytes.len() / 2, tx_bytes.len() - 1] {
            let mut decoder = Transaction::decoder();
            let mut slice = &tx_bytes[..tx_bytes.len() - i];
            // push_bytes will not fail because the data is not invalid, just truncated
            decoder.push_bytes(&mut slice).unwrap();
            // ...but end() will fail because we will be in some incomplete state
            decoder.end().unwrap_err();
        }

        assert_eq!(tx, original);
        assert_eq!(tx.version, Version::TWO);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].previous_output.txid, tc_out_point().txid);
        assert_eq!(tx.inputs[0].previous_output.vout, 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.lock_time, absolute::LockTime::ZERO);
        assert_ne!(tx.compute_txid().to_byte_array(), tx.compute_wtxid().to_byte_array());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn decode_nonsegwit_transaction() {
        let mut tx_in = segwit_tx_in();
        tx_in.witness.clear();
        let original = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![tx_in],
            outputs: vec![tx_out()],
        };
        let tx_bytes = encoding::encode_to_vec(&original);

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let tx = decoder.end().unwrap();

        assert_eq!(tx, original);
        assert_eq!(tx.version, Version::ONE);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].previous_output.txid, tc_out_point().txid);
        assert_eq!(tx.inputs[0].previous_output.vout, 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.lock_time, absolute::LockTime::ZERO);
        assert_eq!(tx.compute_txid().to_byte_array(), tx.compute_wtxid().to_byte_array());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn decode_segwit_without_witnesses_errors() {
        // A SegWit-serialized transaction with 1 input but no witnesses for any input.
        let tx_bytes = hex!(
            "02000000\
             0001\
             01\
             0000000000000000000000000000000000000000000000000000000000000000\
             00000000\
             00\
             ffffffff\
             01\
             0100000000000000\
             00\
             00\
             00000000"
        );

        let mut slice = tx_bytes.as_slice();
        let err = Transaction::decoder()
            .push_bytes(&mut slice)
            .expect_err("segwit tx with no witnesses should error");

        assert_eq!(err, TransactionDecoderError(TransactionDecoderErrorInner::NoWitnesses));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn decode_zero_inputs() {
        // Test transaction with no inputs (but with one output to isolate input sanity).
        let block: u32 = 741_521;
        let original_tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::from_height(block).expect("valid height"),
            inputs: vec![],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let encoded = encoding::encode_to_vec(&original_tx);
        let mut decoder = Transaction::decoder();
        let mut slice = encoded.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().expect_err("zero-input transaction should be rejected");

        assert_eq!(err.0, TransactionDecoderErrorInner::NoInputs);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_null_prevout_in_non_coinbase_transaction() {
        // Invalid transaction fixture.
        // "Null txin, but without being a coinbase (because there are two inputs)"
        let tx_bytes = hex!("01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff00010000000000000000000000000000000000000000000000000000000000000000000000ffffffff010000000000000000015100000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().expect_err("null prevout in non-coinbase tx should be rejected");

        assert_eq!(
            err,
            TransactionDecoderError(TransactionDecoderErrorInner::NullPrevoutInNonCoinbase(0))
        );
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_coinbase_scriptsig_too_small() {
        // Invalid transaction fixture.
        // "Coinbase of size 1"
        let tx_bytes = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0151ffffffff010000000000000000015100000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().expect_err("coinbase with 1-byte scriptSig should be rejected");

        assert_eq!(
            err,
            TransactionDecoderError(TransactionDecoderErrorInner::CoinbaseScriptSigTooSmall(1))
        );
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn accept_coinbase_scriptsig_101_valid() {
        // Tidecoin allows 101 bytes; this proves we are not carrying the old 100-byte limit.
        let tx_bytes = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff655151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151ffffffff010000000000000000015100000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let tx = decoder.end().expect("coinbase with 101-byte scriptSig should be accepted");

        assert_eq!(tx.inputs[0].script_sig.len(), 101);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn accept_coinbase_scriptsig_min_valid() {
        // boundary test: 2 bytes is the minimum valid length
        let tx_bytes = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff025151ffffffff010000000000000000015100000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let tx = decoder.end().expect("coinbase with 2-byte scriptSig should be accepted");

        assert_eq!(tx.inputs[0].script_sig.len(), 2);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn accept_coinbase_scriptsig_max_valid() {
        // boundary test: 106 bytes is the maximum valid length.
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE_PREVOUT,
                script_sig: ScriptSigBuf::from_bytes(vec![0x51; 106]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![synthetic_output(Amount::ONE_SAT)],
        };
        let tx_bytes = encoding::encode_to_vec(&tx);

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let tx = decoder.end().expect("coinbase with 106-byte scriptSig should be accepted");

        assert_eq!(tx.inputs[0].script_sig.len(), 106);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_coinbase_scriptsig_too_large() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE_PREVOUT,
                script_sig: ScriptSigBuf::from_bytes(vec![0x51; 107]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![synthetic_output(Amount::ONE_SAT)],
        };
        let tx_bytes = encoding::encode_to_vec(&tx);

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().expect_err("coinbase with 107-byte scriptSig should be rejected");

        assert_eq!(
            err,
            TransactionDecoderError(TransactionDecoderErrorInner::CoinbaseScriptSigTooLarge(107))
        );
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_duplicate_inputs() {
        let duplicate_outpoint = OutPoint { txid: Txid::from_byte_array([0x21; 32]), vout: 7 };
        let mut input = synthetic_non_coinbase_input(0x21);
        input.previous_output = duplicate_outpoint;
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![input.clone(), input],
            outputs: vec![synthetic_output(Amount::ONE_SAT)],
        };
        let tx_bytes = encoding::encode_to_vec(&tx);

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().expect_err("transaction with duplicate inputs should be rejected");

        assert_eq!(
            err,
            TransactionDecoderError(TransactionDecoderErrorInner::DuplicateInput(
                duplicate_outpoint
            ))
        );
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_output_value_sum_too_large() {
        let tx = synthetic_non_coinbase_tx(vec![
            synthetic_output(Amount::MAX_MONEY),
            synthetic_output(Amount::ONE_SAT),
        ]);
        let tx_bytes = encoding::encode_to_vec(&tx);

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().expect_err("sum of output values > MAX_MONEY should be rejected");

        assert!(matches!(err.0, TransactionDecoderErrorInner::OutputValueSumTooLarge(_)));
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn accept_output_value_sum_equal_to_max_money() {
        let tx = synthetic_non_coinbase_tx(vec![synthetic_output(Amount::MAX_MONEY)]);
        let tx_bytes = encoding::encode_to_vec(&tx);

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let tx = decoder.end().expect("sum of output values == MAX_MONEY should be accepted");

        let total: u64 = tx.outputs.iter().map(|o| o.amount.to_sat()).sum();
        assert_eq!(total, Amount::MAX_MONEY.to_sat());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_output_value_greater_than_max_money() {
        let mut tx_bytes =
            encoding::encode_to_vec(&synthetic_non_coinbase_tx(vec![synthetic_output(
                Amount::ONE_SAT,
            )]));
        let invalid_amount = Amount::MAX_MONEY.to_sat() + 1;
        let one_sat = Amount::ONE_SAT.to_sat().to_le_bytes();
        let amount_pos = tx_bytes
            .windows(8)
            .position(|window| window == one_sat)
            .expect("encoded one-satoshi output amount");
        tx_bytes[amount_pos..amount_pos + 8].copy_from_slice(&invalid_amount.to_le_bytes());

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        let result = decoder.push_bytes(&mut slice);
        assert!(result.is_err(), "output value > MAX_MONEY should be rejected during decoding");
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn check_transaction_sanity_rejects_oversize_stripped_transaction() {
        let oversized_script_len = (Weight::MAX_BLOCK.to_wu() / Weight::WITNESS_SCALE_FACTOR + 1)
            .try_into()
            .expect("max block size fits usize");
        let mut tx = synthetic_non_coinbase_tx(vec![synthetic_output(Amount::ONE_SAT)]);
        tx.inputs[0].script_sig = ScriptSigBuf::from_bytes(vec![0x51; oversized_script_len]);

        let err = check_transaction_sanity(&tx).expect_err("oversize transaction should reject");
        assert!(matches!(err, TransactionSanityError::Oversize { .. }));
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_transaction_with_no_outputs() {
        let tx_bytes = encoding::encode_to_vec(&synthetic_non_coinbase_tx(vec![]));

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().unwrap_err();
        assert_eq!(err, TransactionDecoderError(TransactionDecoderErrorInner::NoOutputs));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn compute_ntxid_ignores_script_sig_and_witness() {
        let mut tx_in = TxIn::EMPTY_COINBASE;
        tx_in.script_sig = ScriptSigBuf::from_bytes(vec![1, 2, 3]);
        tx_in.witness = Witness::from_slice(&[&[0xAAu8][..]]);

        let mut tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![tx_in],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let ntxid = tx.compute_ntxid();

        tx.inputs[0].script_sig = ScriptSigBuf::new();
        tx.inputs[0].witness = Witness::default();

        assert_eq!(ntxid, Ntxid::from_byte_array(tx.compute_txid().to_byte_array()));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_push_bytes_after_done_is_false() {
        let tx_bytes = [
            0x01, 0x00, 0x00, 0x00, // version
            0x01, // input count
            // prevout.txid
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // prevout.vout
            0x00, // script_sig len
            0xff, 0xff, 0xff, 0xff, // sequence
            0x01, // output count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value
            0x00, // script_pubkey len
            0x00, 0x00, 0x00, 0x00, // lock_time
        ];

        let mut decoder = TransactionDecoder::new();
        let mut bytes = tx_bytes.as_slice();
        assert!(!decoder.push_bytes(&mut bytes).unwrap());

        let mut empty = [].as_slice();
        assert!(!decoder.push_bytes(&mut empty).unwrap());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_push_bytes_inputs_needs_more() {
        use TransactionDecoderState as S;
        let mut decoder = TransactionDecoder {
            state: S::Inputs(Version::ONE, Attempt::First, VecDecoder::new()),
        };
        let mut bytes = [].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_push_bytes_lock_time_completes() {
        use TransactionDecoderState as S;

        let mut decoder = TransactionDecoder {
            state: S::LockTime(
                Version::ONE,
                vec![TxIn {
                    previous_output: OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 },
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                }],
                vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
                LockTimeDecoder::new(),
            ),
        };
        let mut bytes = [0u8, 0, 0, 0].as_slice();

        assert!(!decoder.push_bytes(&mut bytes).unwrap());
        assert!(bytes.is_empty());

        let tx = decoder.end().unwrap();
        assert_eq!(tx.lock_time, absolute::LockTime::ZERO);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_push_bytes_lock_time_needs_more() {
        use TransactionDecoderState as S;
        let mut decoder = TransactionDecoder {
            state: S::LockTime(
                Version::ONE,
                vec![],
                vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
                LockTimeDecoder::new(),
            ),
        };
        let mut bytes = [].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_push_bytes_outputs_needs_more() {
        use TransactionDecoderState as S;
        let mut decoder = TransactionDecoder {
            state: S::Outputs(Version::ONE, vec![], IsSegwit::No, VecDecoder::new()),
        };
        let mut bytes = [].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_push_bytes_segwit_flag_empty_needs_more() {
        use TransactionDecoderState as S;
        let mut decoder = TransactionDecoder { state: S::SegwitFlag(Version::ONE) };
        let mut bytes = [].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_push_bytes_version_needs_more() {
        let mut decoder = TransactionDecoder::new();
        let mut bytes = [].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_push_bytes_witnesses_needs_more() {
        use TransactionDecoderState as S;
        let tx_in = TxIn::EMPTY_COINBASE;
        let mut decoder = TransactionDecoder {
            state: S::Witnesses(
                Version::ONE,
                vec![tx_in],
                vec![],
                Iteration(0),
                WitnessDecoder::new(),
            ),
        };
        let mut bytes = [].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_rejects_unsupported_segwit_flag() {
        let mut decoder = TransactionDecoder::new();
        let mut bytes = [1u8, 0, 0, 0, 0, 2].as_slice();
        let err = decoder.push_bytes(&mut bytes).unwrap_err();
        assert!(matches!(err.0, TransactionDecoderErrorInner::UnsupportedSegwitFlag(2)));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_end_rejects_null_prevout_at_nonzero_index() {
        use TransactionDecoderState as S;

        let input_0 = TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };
        let input_1 = TxIn {
            previous_output: OutPoint::COINBASE_PREVOUT,
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![input_0, input_1],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let decoder = TransactionDecoder { state: S::Done(tx) };
        let err = decoder.end().unwrap_err();
        assert!(matches!(err.0, TransactionDecoderErrorInner::NullPrevoutInNonCoinbase(1)));
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[allow(clippy::should_panic_without_expect)]
    #[should_panic]
    fn transaction_decoder_end_after_error_panics() {
        use TransactionDecoderState as S;
        let decoder = TransactionDecoder { state: S::Errored };
        let _ = decoder.end();
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[allow(clippy::should_panic_without_expect)]
    #[should_panic]
    fn transaction_decoder_push_bytes_after_error_panics() {
        use TransactionDecoderState as S;

        let mut decoder = TransactionDecoder { state: S::Errored };
        let mut bytes = [].as_slice();
        let _ = decoder.push_bytes(&mut bytes);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn txid_from_transaction_matches_compute_txid() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn::EMPTY_COINBASE],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        assert_eq!(Txid::from(&tx), tx.compute_txid());
        assert_eq!(Txid::from(tx.clone()), tx.compute_txid());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn wtxid_from_transaction_matches_compute_wtxid() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn::EMPTY_COINBASE],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        assert_eq!(Wtxid::from(&tx), tx.compute_wtxid());
        assert_eq!(Wtxid::from(tx.clone()), tx.compute_wtxid());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn witnesses_encoder_advance_switch_path() {
        let tx_in_1 = TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0xAA; 32]), vout: 0 },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[&[0x01u8][..]]),
        };

        let empty = [].as_slice();
        let many = vec![empty; 253];
        let tx_in_2 = TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0xBB; 32]), vout: 1 },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&many),
        };

        let inputs = [tx_in_1, tx_in_2];

        let mut finished = inputs[0].witness.encoder();
        while finished.advance() {}
        assert!(!finished.advance());
        let expected = inputs[1].witness.encoder().current_chunk().to_vec();
        assert!(!expected.is_empty());

        let mut encoder = WitnessesEncoder { inputs: &inputs, cur_enc: Some(finished) };
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), expected.as_slice());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn witnesses_encoder_empty_inputs() {
        let mut encoder = WitnessesEncoder::new(&[]);
        assert!(!encoder.advance());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn witnesses_encoder_switches_to_next_input_with_nonempty_chunk() {
        let input_0 = TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0xAA; 32]), vout: 0 },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let input_1 = TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0xBB; 32]), vout: 2 },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[&[1u8][..]]),
        };

        let inputs = vec![input_0, input_1];
        let mut encoder = WitnessesEncoder::new(&inputs);

        let next = inputs[1].witness.encoder();
        assert!(!next.current_chunk().is_empty());

        let mut exhausted = inputs[0].witness.encoder();
        while exhausted.advance() {}
        encoder.cur_enc = Some(exhausted);

        let advanced = encoder.advance();
        assert!(advanced);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn out_point_decoder_default_read_limit() {
        let decoder_default = OutPointDecoder::default();
        // OutPointDecoder wraps ArrayDecoder<36>: needs 36 bytes.
        assert_eq!(decoder_default.read_limit(), 36);

        let mut decoder = OutPoint::decoder();
        assert_eq!(decoder.read_limit(), 36);

        // Provide 1 byte decreasing the limit by 1.
        let mut bytes = [0u8].as_slice();
        decoder.push_bytes(&mut bytes).unwrap();
        assert_eq!(decoder.read_limit(), 35);

        // Provide the remaining 35 bytes completing the decode.
        let mut bytes = [0u8; 35].as_slice();
        decoder.push_bytes(&mut bytes).unwrap();
        assert_eq!(decoder.read_limit(), 0);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_read_limit() {
        use TransactionDecoderState as S;

        let decoder = TransactionDecoder::default();
        // Default TransactionDecoder starts by decoding version: needs 4 bytes.
        assert_eq!(decoder.read_limit(), 4);

        let decoder = TransactionDecoder {
            state: S::Inputs(Version::ONE, Attempt::First, VecDecoder::<TxIn>::new()),
        };
        // VecDecoder<TxIn>: CompactSize needs 1 byte.
        assert_eq!(decoder.read_limit(), 1);

        let decoder = TransactionDecoder { state: S::SegwitFlag(Version::ONE) };
        // Segwit flag: needs 1 byte.
        assert_eq!(decoder.read_limit(), 1);

        let decoder = TransactionDecoder {
            state: S::Outputs(Version::ONE, vec![], IsSegwit::No, VecDecoder::<TxOut>::new()),
        };
        // VecDecoder<TxOut>: CompactSize needs 1 byte.
        assert_eq!(decoder.read_limit(), 1);

        let decoder = TransactionDecoder {
            state: S::Witnesses(
                Version::ONE,
                vec![TxIn::EMPTY_COINBASE],
                vec![],
                Iteration(0),
                WitnessDecoder::new(),
            ),
        };
        // WitnessDecoder: CompactSize needs 1 byte.
        assert_eq!(decoder.read_limit(), 1);

        let decoder = TransactionDecoder {
            state: S::LockTime(Version::ONE, vec![], vec![], LockTimeDecoder::new()),
        };
        // lock_time: needs 4 bytes.
        assert_eq!(decoder.read_limit(), 4);

        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn::EMPTY_COINBASE],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };
        let decoder = TransactionDecoder { state: S::Done(tx) };
        // Done/Errored: no more bytes needed.
        assert_eq!(decoder.read_limit(), 0);

        let decoder = TransactionDecoder { state: S::Errored };
        assert_eq!(decoder.read_limit(), 0);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn txin_decoder_read_limit() {
        let mut decoder = TxIn::decoder();
        // Decoder3: needs outpoint (36) + script_sig len CompactSize (1) + sequence (4) = 41.
        assert_eq!(decoder.read_limit(), 41);

        // Provide the full outpoint, advancing to script_sig length.
        let mut bytes = [0u8; 36].as_slice();
        decoder.push_bytes(&mut bytes).unwrap();
        // Remaining: needs script_sig len CompactSize (1) + sequence (4) = 5.
        assert_eq!(decoder.read_limit(), 5);

        // Set script_sig length = 0, advancing to sequence.
        let mut bytes = [0x00u8].as_slice();
        decoder.push_bytes(&mut bytes).unwrap();
        // Sequence: needs 4 bytes.
        assert_eq!(decoder.read_limit(), 4);

        // Provide 1 byte of sequence.
        let mut bytes = [0x00u8].as_slice();
        decoder.push_bytes(&mut bytes).unwrap();
        assert_eq!(decoder.read_limit(), 3);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn txout_decoder_read_limit() {
        let mut decoder = TxOut::decoder();
        // Decoder2: needs amount (8) + script_pubkey len CompactSize (1) = 9.
        assert_eq!(decoder.read_limit(), 9);

        // Provide full amount, advancing to script_pubkey length.
        let mut bytes = [0u8; 8].as_slice();
        decoder.push_bytes(&mut bytes).unwrap();
        // script_pubkey length: CompactSize needs 1 byte.
        assert_eq!(decoder.read_limit(), 1);

        // Set script_pubkey length = 0, completing the decode.
        let mut bytes = [0x00u8].as_slice();
        decoder.push_bytes(&mut bytes).unwrap();
        assert_eq!(decoder.read_limit(), 0);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn version_decoder_default_read_limit() {
        let decoder_default = VersionDecoder::default();
        // VersionDecoder wraps ArrayDecoder<4>: needs 4 bytes.
        assert_eq!(decoder_default.read_limit(), 4);

        let mut decoder = Version::decoder();
        assert_eq!(decoder.read_limit(), 4);

        // Provide 1 byte decreasing the limit by 1.
        let mut bytes = [0u8].as_slice();
        decoder.push_bytes(&mut bytes).unwrap();
        assert_eq!(decoder.read_limit(), 3);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn out_point_decoder_error() {
        let mut decoder = OutPoint::decoder();
        let mut slice = &[][..];

        let needs_more = decoder.push_bytes(&mut slice).unwrap();
        assert!(needs_more);

        let err = decoder.end().unwrap_err();
        assert!(matches!(err, OutPointDecoderError(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn parse_out_point_txid_error() {
        let err = ("z".repeat(64) + ":0").parse::<OutPoint>().unwrap_err();
        assert!(matches!(err, ParseOutPointError::Txid(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn parse_out_point_vout_error() {
        let txid = "0".repeat(64);

        let err = format!("{}:{}", txid, "x").parse::<OutPoint>().unwrap_err();
        assert!(matches!(err, ParseOutPointError::Vout(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn parse_out_point_format_error() {
        let txid = "0".repeat(64);
        let err = txid.parse::<OutPoint>().unwrap_err();
        assert!(matches!(err, ParseOutPointError::Format));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn parse_out_point_too_long_error() {
        let txid = "0".repeat(64);
        let err = format!("{}:{}", txid, "12345678900").parse::<OutPoint>().unwrap_err();
        assert!(matches!(err, ParseOutPointError::TooLong));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn parse_out_point_vout_not_canonical_error() {
        let txid = "0".repeat(64);
        let err = format!("{}:{}", txid, "01").parse::<OutPoint>().unwrap_err();
        assert!(matches!(err, ParseOutPointError::VoutNotCanonical));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn version_decoder_error() {
        let mut decoder = Version::decoder();
        let mut slice = &[][..];

        let needs_more = decoder.push_bytes(&mut slice).unwrap();
        assert!(needs_more);

        let err = decoder.end().unwrap_err();
        assert!(matches!(err, VersionDecoderError(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_version_error() {
        let mut decoder = VersionDecoder::new();
        let mut bytes = [0u8, 0, 0].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
        let err = TransactionDecoderError(TransactionDecoderErrorInner::Version(
            decoder.end().unwrap_err(),
        ));
        assert!(matches!(err.0, TransactionDecoderErrorInner::Version(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_unsupported_segwit_flag_error() {
        let mut decoder = TransactionDecoder::new();
        let mut bytes = [1u8, 0, 0, 0, 0, 2].as_slice();
        let err = decoder.push_bytes(&mut bytes).unwrap_err();
        assert!(matches!(err.0, TransactionDecoderErrorInner::UnsupportedSegwitFlag(2)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_inputs_error() {
        let mut decoder = VecDecoder::<TxIn>::new();
        let mut bytes = [1u8].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
        let err = TransactionDecoderError(TransactionDecoderErrorInner::Inputs(
            decoder.end().unwrap_err(),
        ));
        assert!(matches!(err.0, TransactionDecoderErrorInner::Inputs(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_outputs_error() {
        let mut decoder = VecDecoder::<TxOut>::new();
        let mut bytes = [1u8].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
        let err = TransactionDecoderError(TransactionDecoderErrorInner::Outputs(
            decoder.end().unwrap_err(),
        ));
        assert!(matches!(err.0, TransactionDecoderErrorInner::Outputs(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_witness_error() {
        let mut decoder = WitnessDecoder::new();
        let mut bytes = [1u8].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
        let err = TransactionDecoderError(TransactionDecoderErrorInner::Witness(
            decoder.end().unwrap_err(),
        ));
        assert!(matches!(err.0, TransactionDecoderErrorInner::Witness(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_no_witnesses_error() {
        let tx_bytes = [
            0x02, 0x00, 0x00, 0x00, // version
            0x00, 0x01, // segwit marker + flag
            0x01, // input count
            // prevout.txid
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // prevout.vout
            0x00, // script_sig len
            0xff, 0xff, 0xff, 0xff, // sequence
            0x01, // output count
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value (1 sat)
            0x00, // script_pubkey len
            0x00, 0x00, 0x00, 0x00, // lock_time
        ];

        let mut slice = tx_bytes.as_slice();
        let err = Transaction::decoder().push_bytes(&mut slice).unwrap_err();
        assert!(matches!(err.0, TransactionDecoderErrorInner::NoWitnesses));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_lock_time_error() {
        let mut decoder = LockTimeDecoder::new();
        let mut bytes = [0u8, 0, 0].as_slice();
        assert!(decoder.push_bytes(&mut bytes).unwrap());
        let err = TransactionDecoderError(TransactionDecoderErrorInner::LockTime(
            decoder.end().unwrap_err(),
        ));
        assert!(matches!(err.0, TransactionDecoderErrorInner::LockTime(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_early_end_version_error() {
        let err = decode_error_from_bytes(&[0u8, 0, 0]);
        assert!(matches!(err.0, TransactionDecoderErrorInner::EarlyEnd("version")));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_early_end_inputs_error() {
        let bytes = [
            0x01, 0x00, 0x00, 0x00, // version
        ];
        let err = decode_error_from_bytes(&bytes);
        assert!(matches!(err.0, TransactionDecoderErrorInner::EarlyEnd("inputs")));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_early_end_segwit_flag_error() {
        let bytes = [
            0x01, 0x00, 0x00, 0x00, // version
            0x00, // segwit marker (no flag)
        ];
        let err = decode_error_from_bytes(&bytes);
        assert!(matches!(err.0, TransactionDecoderErrorInner::EarlyEnd("segwit flag")));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_early_end_outputs_error() {
        let bytes = [
            0x01, 0x00, 0x00, 0x00, // version
            0x01, // input count
            // prevout.txid
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, // prevout.vout
            0x00, 0x00, 0x00, 0x00, 0x00, // script_sig len
            0xff, 0xff, 0xff, 0xff, // sequence
        ];
        let err = decode_error_from_bytes(&bytes);
        assert!(matches!(err.0, TransactionDecoderErrorInner::EarlyEnd("outputs")));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_early_end_witnesses_error() {
        let tx_bytes = [
            0x01, 0x00, 0x00, 0x00, // version
            0x00, 0x01, // segwit marker + flag
            0x01, // input count
            // prevout.txid
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // prevout.vout
            0x00, 0x00, 0x00, 0x00, 0x00, // script_sig len
            0xff, 0xff, 0xff, 0xff, // sequence
            0x01, // output count
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value (1 sat)
            0x00, // script_pubkey len
        ];

        let err = decode_error_from_bytes(&tx_bytes);
        assert!(matches!(err.0, TransactionDecoderErrorInner::EarlyEnd("witnesses")));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_early_end_locktime_error() {
        let tx_bytes = [
            0x01, 0x00, 0x00, 0x00, // version
            0x01, // input count
            // prevout.txid
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // prevout.vout
            0x00, 0x00, 0x00, 0x00, 0x00, // script_sig len
            0xff, 0xff, 0xff, 0xff, // sequence
            0x01, // output count
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value (1 sat)
            0x00, // script_pubkey len
        ];

        let err = decode_error_from_bytes(&tx_bytes);
        assert!(matches!(err.0, TransactionDecoderErrorInner::EarlyEnd("locktime")));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_null_prevout_in_non_coinbase_error() {
        let input_0 = TxIn::EMPTY_COINBASE;
        let input_1 = TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![input_0, input_1],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let err = decode_error_from_tx(&tx);
        assert!(matches!(err.0, TransactionDecoderErrorInner::NullPrevoutInNonCoinbase(0)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_coinbase_script_sig_too_small_error() {
        let input_0 = TxIn {
            previous_output: OutPoint::COINBASE_PREVOUT,
            script_sig: ScriptSigBuf::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![input_0],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let err = decode_error_from_tx(&tx);
        assert!(matches!(err.0, TransactionDecoderErrorInner::CoinbaseScriptSigTooSmall(1)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_coinbase_script_sig_too_large_error() {
        let input_0 = TxIn {
            previous_output: OutPoint::COINBASE_PREVOUT,
            script_sig: ScriptSigBuf::from_bytes(vec![0x51; 107]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![input_0],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let err = decode_error_from_tx(&tx);
        assert!(matches!(err.0, TransactionDecoderErrorInner::CoinbaseScriptSigTooLarge(107)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_duplicate_input_error() {
        let outpoint = OutPoint { txid: Txid::from_byte_array([2u8; 32]), vout: 1 };
        let input_0 = TxIn {
            previous_output: outpoint,
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };
        let input_1 = input_0.clone();
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![input_0, input_1],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let err = decode_error_from_tx(&tx);
        assert!(matches!(
            err.0,
            TransactionDecoderErrorInner::DuplicateInput(got) if got == outpoint
        ));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_output_value_sum_too_large_error() {
        let expected = Amount::MAX_MONEY.to_sat() + 1;
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![
                TxOut { amount: Amount::MAX_MONEY, script_pubkey: ScriptPubKeyBuf::new() },
                TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() },
            ],
        };

        let err = decode_error_from_tx(&tx);
        assert!(matches!(
            err.0,
            TransactionDecoderErrorInner::OutputValueSumTooLarge(got) if got == expected
        ));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_no_outputs_error() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![],
        };

        let err = decode_error_from_tx(&tx);
        assert!(matches!(err.0, TransactionDecoderErrorInner::NoOutputs));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn transaction_decoder_no_inputs_error() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        };

        let err = decode_error_from_tx(&tx);
        assert!(matches!(err.0, TransactionDecoderErrorInner::NoInputs));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn txin_decoder_first_error() {
        let mut decoder = TxIn::decoder();
        let mut slice = [].as_slice();
        assert!(decoder.push_bytes(&mut slice).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(matches!(err.0, encoding::Decoder3Error::First(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn txin_decoder_second_error() {
        let mut bytes = vec![];
        bytes.extend_from_slice(&TC_TXID_BYTES);
        bytes.extend_from_slice(&TC_VOUT_BYTES);
        bytes.push(1); // scriptSig length = 1

        let mut decoder = TxIn::decoder();
        let mut slice = bytes.as_slice();

        assert!(decoder.push_bytes(&mut slice).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(matches!(err.0, encoding::Decoder3Error::Second(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn txin_decoder_third_error() {
        let mut bytes = vec![];
        bytes.extend_from_slice(&TC_TXID_BYTES);
        bytes.extend_from_slice(&TC_VOUT_BYTES);
        bytes.push(0); // scriptSig length = 0

        let mut decoder = TxIn::decoder();
        let mut slice = bytes.as_slice();

        assert!(decoder.push_bytes(&mut slice).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(matches!(err.0, encoding::Decoder3Error::Third(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn txout_decoder_first_error() {
        let mut decoder = TxOut::decoder();
        let mut slice = [].as_slice();
        assert!(decoder.push_bytes(&mut slice).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(matches!(err.0, encoding::Decoder2Error::First(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn txout_decoder_second_error() {
        let mut bytes = vec![];
        bytes.extend_from_slice(&TC_ONE_SAT_BYTES);
        let mut decoder = TxOut::decoder();
        let mut slice = bytes.as_slice();

        assert!(decoder.push_bytes(&mut slice).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(matches!(err.0, encoding::Decoder2Error::Second(_)));

        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    // Helper function to decode a transaction from bytes and return the decoding error.
    #[cfg(feature = "alloc")]
    fn decode_error_from_bytes(bytes: &[u8]) -> TransactionDecoderError {
        let mut decoder = TransactionDecoder::new();
        let mut slice = bytes;
        decoder.push_bytes(&mut slice).unwrap();
        decoder.end().unwrap_err()
    }

    // Helper function to encode a transaction and decode it to get the decoding error.
    #[cfg(feature = "alloc")]
    fn decode_error_from_tx(tx: &Transaction) -> TransactionDecoderError {
        let tx_bytes = encoding::encode_to_vec(tx);
        decode_error_from_bytes(&tx_bytes)
    }
}
