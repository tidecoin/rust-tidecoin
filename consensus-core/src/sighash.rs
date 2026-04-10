// SPDX-License-Identifier: CC0-1.0

use alloc::string::{String, ToString};
use core::borrow::{Borrow, BorrowMut};
use core::{fmt, str};

use encoding::CompactSizeEncoder;
use hashes::{hash_newtype, sha256, sha256d, sha512};
use io::Write;
use primitives::{script::Script, Amount, ScriptPubKey, Sequence, Transaction};

#[rustfmt::skip]
const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
];

#[rustfmt::skip]
const UINT512_ONE: [u8; 64] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];

hash_newtype! {
    /// Hash of a transaction according to the legacy signature algorithm.
    #[hash_newtype(forward)]
    pub struct LegacySighash(sha256d::Hash);

    /// Hash of a transaction according to the SegWit version 0 signature algorithm.
    #[hash_newtype(forward)]
    pub struct SegwitV0Sighash(sha256d::Hash);

    /// Hash of a transaction according to the Tidecoin witness-v1 SHA-512 algorithm.
    #[hash_newtype(forward)]
    pub struct Sighash512(sha512::Hash);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(LegacySighash, SegwitV0Sighash, Sighash512);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(LegacySighash, SegwitV0Sighash, Sighash512);
#[cfg(not(feature = "hex"))]
hashes::impl_debug_only_for_newtype!(LegacySighash, SegwitV0Sighash, Sighash512);

impl LegacySighash {
    fn engine() -> sha256d::HashEngine {
        sha256d::Hash::engine()
    }

    fn from_engine(e: sha256d::HashEngine) -> Self {
        Self(sha256d::Hash::from_engine(e))
    }
}

impl SegwitV0Sighash {
    fn engine() -> sha256d::HashEngine {
        sha256d::Hash::engine()
    }

    fn from_engine(e: sha256d::HashEngine) -> Self {
        Self(sha256d::Hash::from_engine(e))
    }
}

impl Sighash512 {
    fn engine() -> sha512::HashEngine {
        sha512::Hash::engine()
    }

    fn from_engine(e: sha512::HashEngine) -> Self {
        Self(sha512::Hash::from_engine(e))
    }
}

/// Hashtype of an input's signature, encoded in the last byte of the signature.
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub enum TxSighashType {
    /// 0x1: Sign all outputs.
    All = 0x01,
    /// 0x2: Sign no outputs.
    None = 0x02,
    /// 0x3: Sign the output matching this input index, or `1` if absent.
    Single = 0x03,
    /// 0x81: Sign all outputs and only this input.
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input.
    SinglePlusAnyoneCanPay = 0x83,
}

impl TxSighashType {
    fn split_anyonecanpay_flag(self) -> (Self, bool) {
        match self {
            Self::All => (Self::All, false),
            Self::None => (Self::None, false),
            Self::Single => (Self::Single, false),
            Self::AllPlusAnyoneCanPay => (Self::All, true),
            Self::NonePlusAnyoneCanPay => (Self::None, true),
            Self::SinglePlusAnyoneCanPay => (Self::Single, true),
        }
    }

    /// Checks if the sighash type is `SINGLE`, with or without `ANYONECANPAY`.
    pub fn is_single(&self) -> bool {
        matches!(self, Self::Single | Self::SinglePlusAnyoneCanPay)
    }

    /// Constructs a new sighash type from a raw consensus `u32`.
    pub fn from_consensus(n: u32) -> Self {
        let mask = 0x1f | 0x80;
        match n & mask {
            0x01 => Self::All,
            0x02 => Self::None,
            0x03 => Self::Single,
            0x81 => Self::AllPlusAnyoneCanPay,
            0x82 => Self::NonePlusAnyoneCanPay,
            0x83 => Self::SinglePlusAnyoneCanPay,
            x if x & 0x80 == 0x80 => Self::AllPlusAnyoneCanPay,
            _ => Self::All,
        }
    }

    /// Constructs a sighash type from a standard raw `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error if `n` is a non-standard sighash value.
    pub fn from_standard(n: u32) -> Result<Self, NonStandardSighashTypeError> {
        match n {
            0x01 => Ok(Self::All),
            0x02 => Ok(Self::None),
            0x03 => Ok(Self::Single),
            0x81 => Ok(Self::AllPlusAnyoneCanPay),
            0x82 => Ok(Self::NonePlusAnyoneCanPay),
            0x83 => Ok(Self::SinglePlusAnyoneCanPay),
            non_standard => Err(NonStandardSighashTypeError(non_standard)),
        }
    }

    /// Converts the sighash type to its consensus `u32` value.
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

impl fmt::Display for TxSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::All => "SIGHASH_ALL",
            Self::None => "SIGHASH_NONE",
            Self::Single => "SIGHASH_SINGLE",
            Self::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            Self::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            Self::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for TxSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SIGHASH_ALL" => Ok(Self::All),
            "SIGHASH_NONE" => Ok(Self::None),
            "SIGHASH_SINGLE" => Ok(Self::Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(Self::AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(Self::NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(Self::SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_string() }),
        }
    }
}

#[cfg(feature = "serde")]
internals::serde_string_impl!(TxSighashType, "a TxSighashType data");

/// Error returned for a non-standard sighash type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonStandardSighashTypeError(pub u32);

impl fmt::Display for NonStandardSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "non-standard sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NonStandardSighashTypeError {}

/// Error returned for failure during parsing one of the sighash types.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SighashTypeParseError {}

/// Indexing error while computing a sighash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputsIndexError {
    /// Requested input index.
    pub index: usize,
    /// Total number of inputs.
    pub length: usize,
}

impl fmt::Display for InputsIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "input index {} out of bounds for length {}", self.index, self.length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputsIndexError {}

/// Efficiently calculates signature hash messages needed by consensus verification.
#[derive(Debug)]
pub struct SighashCache<T: Borrow<Transaction>> {
    tx: T,
    common_cache: Option<CommonCache>,
    segwit_cache: Option<SegwitCache>,
    segwit_cache_512: Option<SegwitV1512Cache>,
}

#[derive(Debug)]
struct CommonCache {
    prevouts: sha256::Hash,
    sequences: sha256::Hash,
    outputs: sha256::Hash,
}

#[derive(Debug)]
struct SegwitCache {
    prevouts: sha256d::Hash,
    sequences: sha256d::Hash,
    outputs: sha256d::Hash,
}

#[derive(Debug)]
struct SegwitV1512Cache {
    prevouts: sha512::Hash,
    sequences: sha512::Hash,
    outputs: sha512::Hash,
}

impl<R: Borrow<Transaction>> SighashCache<R> {
    /// Constructs a new sighash cache from a transaction.
    pub fn new(tx: R) -> Self {
        Self { tx, common_cache: None, segwit_cache: None, segwit_cache_512: None }
    }

    /// Returns the transaction cached for sighash computation.
    pub fn transaction(&self) -> &Transaction {
        self.tx.borrow()
    }

    /// Destroys the cache and recovers the stored transaction.
    pub fn into_transaction(self) -> R {
        self.tx
    }

    fn input(&self, input_index: usize) -> Result<&primitives::TxIn, InputsIndexError> {
        self.tx
            .borrow()
            .inputs
            .get(input_index)
            .ok_or(InputsIndexError { index: input_index, length: self.tx.borrow().inputs.len() })
    }

    /// Computes a legacy signature hash from raw script bytes.
    pub fn legacy_signature_hash(
        &self,
        input_index: usize,
        script_bytes: &[u8],
        sighash_type: u32,
    ) -> Result<LegacySighash, InputsIndexError> {
        self.input(input_index)?;

        if is_invalid_use_of_sighash_single(
            sighash_type,
            input_index,
            self.tx.borrow().outputs.len(),
        ) {
            return Ok(LegacySighash::from_byte_array(UINT256_ONE));
        }

        let tx = self.tx.borrow();
        let (sighash, anyone_can_pay) =
            TxSighashType::from_consensus(sighash_type).split_anyonecanpay_flag();

        let mut engine = LegacySighash::engine();
        io::encode_to_writer(&tx.version, &mut engine).expect("hash engine does not fail");

        encode_compact_size(if anyone_can_pay { 1 } else { tx.inputs.len() }, &mut engine)
            .expect("hash engine does not fail");
        if anyone_can_pay {
            let input = &tx.inputs[input_index];
            io::encode_to_writer(&input.previous_output, &mut engine)
                .expect("hash engine does not fail");
            encode_script_bytes(script_bytes, &mut engine).expect("hash engine does not fail");
            io::encode_to_writer(&input.sequence, &mut engine).expect("hash engine does not fail");
        } else {
            for (n, input) in tx.inputs.iter().enumerate() {
                io::encode_to_writer(&input.previous_output, &mut engine)
                    .expect("hash engine does not fail");
                if n == input_index {
                    encode_script_bytes(script_bytes, &mut engine)
                        .expect("hash engine does not fail");
                } else {
                    io::encode_to_writer(ScriptPubKey::new(), &mut engine)
                        .expect("hash engine does not fail");
                }
                if n != input_index
                    && (sighash == TxSighashType::Single || sighash == TxSighashType::None)
                {
                    io::encode_to_writer(&Sequence::ZERO, &mut engine)
                        .expect("hash engine does not fail");
                } else {
                    io::encode_to_writer(&input.sequence, &mut engine)
                        .expect("hash engine does not fail");
                }
            }
        }

        match sighash {
            TxSighashType::All => {
                encode_compact_size(tx.outputs.len(), &mut engine)
                    .expect("hash engine does not fail");
                for output in &tx.outputs {
                    io::encode_to_writer(output, &mut engine).expect("hash engine does not fail");
                }
            }
            TxSighashType::Single => {
                let count = input_index.min(tx.outputs.len() - 1);
                encode_compact_size(count + 1, &mut engine).expect("hash engine does not fail");
                for _ in 0..count {
                    engine
                        .write_all(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])
                        .expect("hash engine does not fail");
                }
                io::encode_to_writer(&tx.outputs[count], &mut engine)
                    .expect("hash engine does not fail");
            }
            TxSighashType::None => {
                encode_compact_size(0, &mut engine).expect("hash engine does not fail");
            }
            _ => unreachable!(),
        }

        io::encode_to_writer(&tx.lock_time, &mut engine).expect("hash engine does not fail");
        engine.write_all(&sighash_type.to_le_bytes()).expect("hash engine does not fail");
        Ok(LegacySighash::from_engine(engine))
    }

    /// Computes a witness-v0 signature hash from raw witness script bytes.
    pub fn p2wsh_signature_hash(
        &mut self,
        input_index: usize,
        witness_script_bytes: &[u8],
        amount: Amount,
        sighash_type: TxSighashType,
    ) -> Result<SegwitV0Sighash, InputsIndexError> {
        let zero_hash = [0; 32];
        let mut engine = SegwitV0Sighash::engine();
        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();
        let prevouts =
            if !anyone_can_pay { Some(self.segwit_cache().prevouts.to_byte_array()) } else { None };
        let sequences = if !anyone_can_pay
            && sighash != TxSighashType::Single
            && sighash != TxSighashType::None
        {
            Some(self.segwit_cache().sequences.to_byte_array())
        } else {
            None
        };
        let outputs = if sighash != TxSighashType::Single && sighash != TxSighashType::None {
            Some(self.segwit_cache().outputs.to_byte_array())
        } else {
            None
        };
        let tx = self.tx.borrow();

        io::encode_to_writer(&tx.version, &mut engine).expect("hash engine does not fail");
        if let Some(prevouts) = prevouts {
            engine.write_all(&prevouts).expect("hash engine does not fail");
        } else {
            engine.write_all(&zero_hash).expect("hash engine does not fail");
        }

        if let Some(sequences) = sequences {
            engine.write_all(&sequences).expect("hash engine does not fail");
        } else {
            engine.write_all(&zero_hash).expect("hash engine does not fail");
        }

        let txin = self.input(input_index)?;
        io::encode_to_writer(&txin.previous_output, &mut engine)
            .expect("hash engine does not fail");
        encode_script_bytes(witness_script_bytes, &mut engine).expect("hash engine does not fail");
        io::encode_to_writer(&amount, &mut engine).expect("hash engine does not fail");
        io::encode_to_writer(&txin.sequence, &mut engine).expect("hash engine does not fail");

        if let Some(outputs) = outputs {
            engine.write_all(&outputs).expect("hash engine does not fail");
        } else if sighash == TxSighashType::Single && input_index < tx.outputs.len() {
            let mut single_enc = LegacySighash::engine();
            single_enc = hashes::encode_to_engine(&tx.outputs[input_index], single_enc);
            let hash = LegacySighash::from_engine(single_enc);
            engine.write_all(hash.as_byte_array()).expect("hash engine does not fail");
        } else {
            engine.write_all(&zero_hash).expect("hash engine does not fail");
        }

        io::encode_to_writer(&tx.lock_time, &mut engine).expect("hash engine does not fail");
        engine.write_all(&sighash_type.to_u32().to_le_bytes()).expect("hash engine does not fail");
        Ok(SegwitV0Sighash::from_engine(engine))
    }

    /// Computes a witness-v1-512 signature hash from raw witness script bytes.
    pub fn p2wsh512_signature_hash(
        &mut self,
        input_index: usize,
        witness_script_bytes: &[u8],
        amount: Amount,
        sighash_type: TxSighashType,
    ) -> Result<Sighash512, InputsIndexError> {
        const TAG: &[u8] = b"TidecoinSighashV1_512";
        let zero_hash = [0; 64];
        let outputs_len = self.tx.borrow().outputs.len();

        if sighash_type.is_single() && input_index >= outputs_len {
            return Ok(Sighash512::from_byte_array(UINT512_ONE));
        }

        let tag_hash = sha512::Hash::hash(TAG);
        let mut engine = Sighash512::engine();
        engine.write_all(tag_hash.as_byte_array()).expect("hash engine does not fail");
        engine.write_all(tag_hash.as_byte_array()).expect("hash engine does not fail");

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();
        let prevouts = if !anyone_can_pay {
            Some(*self.segwit_cache_512().prevouts.as_byte_array())
        } else {
            None
        };
        let sequences = if !anyone_can_pay
            && sighash != TxSighashType::Single
            && sighash != TxSighashType::None
        {
            Some(*self.segwit_cache_512().sequences.as_byte_array())
        } else {
            None
        };
        let outputs = if sighash != TxSighashType::Single && sighash != TxSighashType::None {
            Some(*self.segwit_cache_512().outputs.as_byte_array())
        } else {
            None
        };
        let tx = self.tx.borrow();
        io::encode_to_writer(&tx.version, &mut engine).expect("hash engine does not fail");

        if let Some(prevouts) = prevouts {
            engine.write_all(&prevouts).expect("hash engine does not fail");
        } else {
            engine.write_all(&zero_hash).expect("hash engine does not fail");
        }

        if let Some(sequences) = sequences {
            engine.write_all(&sequences).expect("hash engine does not fail");
        } else {
            engine.write_all(&zero_hash).expect("hash engine does not fail");
        }

        let txin = self.input(input_index)?;
        io::encode_to_writer(&txin.previous_output, &mut engine)
            .expect("hash engine does not fail");
        encode_script_bytes(witness_script_bytes, &mut engine).expect("hash engine does not fail");
        io::encode_to_writer(&amount, &mut engine).expect("hash engine does not fail");
        io::encode_to_writer(&txin.sequence, &mut engine).expect("hash engine does not fail");

        if let Some(outputs) = outputs {
            engine.write_all(&outputs).expect("hash engine does not fail");
        } else if sighash == TxSighashType::Single {
            let mut single_enc = sha512::Hash::engine();
            io::encode_to_writer(&tx.outputs[input_index], &mut single_enc)
                .expect("hash engine does not fail");
            let hash = sha512::Hash::from_engine(single_enc);
            engine.write_all(hash.as_byte_array()).expect("hash engine does not fail");
        } else {
            engine.write_all(&zero_hash).expect("hash engine does not fail");
        }

        io::encode_to_writer(&tx.lock_time, &mut engine).expect("hash engine does not fail");
        engine.write_all(&sighash_type.to_u32().to_le_bytes()).expect("hash engine does not fail");
        Ok(Sighash512::from_engine(engine))
    }

    fn common_cache_minimal_borrow<'a>(
        common_cache: &'a mut Option<CommonCache>,
        tx: &Transaction,
    ) -> &'a CommonCache {
        common_cache.get_or_insert_with(|| {
            let mut enc_prevouts = sha256::Hash::engine();
            let mut enc_sequences = sha256::Hash::engine();
            for txin in &tx.inputs {
                enc_prevouts = hashes::encode_to_engine(&txin.previous_output, enc_prevouts);
                enc_sequences = hashes::encode_to_engine(&txin.sequence, enc_sequences);
            }
            CommonCache {
                prevouts: sha256::Hash::from_engine(enc_prevouts),
                sequences: sha256::Hash::from_engine(enc_sequences),
                outputs: {
                    let mut enc = sha256::Hash::engine();
                    for txout in &tx.outputs {
                        io::encode_to_writer(txout, &mut enc).expect("hash engine does not fail");
                    }
                    sha256::Hash::from_engine(enc)
                },
            }
        })
    }

    fn segwit_cache(&mut self) -> &SegwitCache {
        let common_cache = &mut self.common_cache;
        let tx = self.tx.borrow();
        self.segwit_cache.get_or_insert_with(|| {
            let common_cache = Self::common_cache_minimal_borrow(common_cache, tx);
            SegwitCache {
                prevouts: common_cache.prevouts.hash_again(),
                sequences: common_cache.sequences.hash_again(),
                outputs: common_cache.outputs.hash_again(),
            }
        })
    }

    fn segwit_cache_512(&mut self) -> &SegwitV1512Cache {
        let tx = self.tx.borrow();
        self.segwit_cache_512.get_or_insert_with(|| {
            let mut enc_prevouts = sha512::Hash::engine();
            let mut enc_sequences = sha512::Hash::engine();
            for txin in &tx.inputs {
                enc_prevouts = hashes::encode_to_engine(&txin.previous_output, enc_prevouts);
                enc_sequences = hashes::encode_to_engine(&txin.sequence, enc_sequences);
            }
            SegwitV1512Cache {
                prevouts: sha512::Hash::from_engine(enc_prevouts),
                sequences: sha512::Hash::from_engine(enc_sequences),
                outputs: {
                    let mut enc = sha512::Hash::engine();
                    for txout in &tx.outputs {
                        io::encode_to_writer(txout, &mut enc).expect("hash engine does not fail");
                    }
                    sha512::Hash::from_engine(enc)
                },
            }
        })
    }
}

impl<R: BorrowMut<Transaction>> SighashCache<R> {
    /// Returns mutable access to the cached transaction.
    ///
    /// Callers must not mutate fields that participate in already-computed cache entries.
    pub fn transaction_mut(&mut self) -> &mut Transaction {
        self.tx.borrow_mut()
    }
}

fn is_invalid_use_of_sighash_single(sighash: u32, input_index: usize, outputs_len: usize) -> bool {
    TxSighashType::from_consensus(sighash).is_single() && input_index >= outputs_len
}

fn encode_compact_size<W: Write>(len: usize, writer: &mut W) -> Result<(), io::Error> {
    let mut encoder = CompactSizeEncoder::new(len);
    io::flush_to_writer(&mut encoder, writer)
}

fn encode_script_bytes<W: Write>(bytes: &[u8], writer: &mut W) -> Result<(), io::Error> {
    io::encode_to_writer(Script::<()>::from_bytes(bytes), writer)
}
