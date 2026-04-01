// SPDX-License-Identifier: CC0-1.0

//! Signature hash implementation (used in transaction signing).
//!
//! Efficient implementation of the algorithm to compute the message to be signed according to
//! [BIP-0143] and legacy (before BIP-0143). Taproot-specific signing is disabled in Tidecoin.
//!
//! Computing signature hashes is required to sign a transaction and this module is designed to
//! handle its complexity efficiently. Computing these hashes is as simple as creating
//! [`SighashCache`] and calling its methods.
//!
//! [BIP-0341]: <https://github.com/bitcoin/bips/blob/150ab6f5c3aca9da05fccc5b435e9667853407f4/bip-0341.mediawiki>
//! [BIP-0143]: <https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki>

use core::convert::Infallible;
use core::{fmt, str};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::{hash_newtype, sha256, sha256d};
use internals::write_err;
use io::Write;

use crate::prelude::{Borrow, BorrowMut, String, ToOwned};
use crate::script::{ScriptExt as _, ScriptHashableTag};
use crate::transaction::TransactionExt as _;
use crate::witness::Witness;
use crate::{transaction, Amount, ScriptPubKey, Sequence, Transaction, WitnessScript};

/// Used for signature hash for invalid use of SIGHASH_SINGLE.
#[rustfmt::skip]
pub(crate) const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
];

macro_rules! impl_message_from_hash {
    ($ty:ident) => {
        impl From<$ty> for secp256k1::Message {
            fn from(hash: $ty) -> secp256k1::Message {
                secp256k1::Message::from_digest(hash.to_byte_array())
            }
        }
    };
}

hash_newtype! {
    /// Hash of a transaction according to the legacy signature algorithm.
    #[hash_newtype(forward)]
    pub struct LegacySighash(sha256d::Hash);

    /// Hash of a transaction according to the SegWit version 0 signature algorithm.
    #[hash_newtype(forward)]
    pub struct SegwitV0Sighash(sha256d::Hash);
}

hashes::impl_hex_for_newtype!(LegacySighash, SegwitV0Sighash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(LegacySighash, SegwitV0Sighash);

impl_message_from_hash!(LegacySighash);
impl_message_from_hash!(SegwitV0Sighash);

// Implement private engine/from_engine methods for use within this module;
// but outside of it, it should not be possible to construct these hash
// types from arbitrary data (except by casting via to/from_byte_array).
impl LegacySighash {
    fn engine() -> sha256d::HashEngine { sha256d::Hash::engine() }
    fn from_engine(e: sha256d::HashEngine) -> Self { Self(sha256d::Hash::from_engine(e)) }
}
impl SegwitV0Sighash {
    fn engine() -> sha256d::HashEngine { sha256d::Hash::engine() }
    fn from_engine(e: sha256d::HashEngine) -> Self { Self(sha256d::Hash::from_engine(e)) }
}

/// Efficiently calculates signature hash message for legacy and SegWit inputs.
#[derive(Debug)]
pub struct SighashCache<T: Borrow<Transaction>> {
    /// Access to transaction required for transaction introspection. Moreover, type
    /// `T: Borrow<Transaction>` allows us to use borrowed and mutable borrowed types,
    /// the latter in particular is necessary for [`SighashCache::witness_mut`].
    tx: T,

    /// Common cache for SegWit inputs, `None` for legacy inputs.
    common_cache: Option<CommonCache>,

    /// Cache for SegWit v0 inputs (the result of another round of sha256 on `common_cache`).
    segwit_cache: Option<SegwitCache>,
}

/// Common values cached between SegWit inputs.
#[derive(Debug)]
struct CommonCache {
    prevouts: sha256::Hash,
    sequences: sha256::Hash,

    /// In theory `outputs` could be an `Option` since `SIGHASH_NONE` and `SIGHASH_SINGLE` do not
    /// need it, but since `SIGHASH_ALL` is by far the most used variant we don't bother.
    outputs: sha256::Hash,
}

/// Values cached for SegWit inputs, equivalent to [`CommonCache`] plus another round of `sha256`.
#[derive(Debug)]
struct SegwitCache {
    prevouts: sha256d::Hash,
    sequences: sha256d::Hash,
    outputs: sha256d::Hash,
}

/// Hashtype of an input's signature, encoded in the last byte of the signature.
///
/// Fixed values so they can be cast as integer types for encoding.
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub enum EcdsaSighashType {
    /// 0x1: Sign all outputs.
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay = 0x83,
}
#[cfg(feature = "serde")]
internals::serde_string_impl!(EcdsaSighashType, "a EcdsaSighashType data");

impl fmt::Display for EcdsaSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EcdsaSighashType::*;

        let s = match self {
            All => "SIGHASH_ALL",
            None => "SIGHASH_NONE",
            Single => "SIGHASH_SINGLE",
            AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for EcdsaSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use EcdsaSighashType::*;

        match s {
            "SIGHASH_ALL" => Ok(All),
            "SIGHASH_NONE" => Ok(None),
            "SIGHASH_SINGLE" => Ok(Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_owned() }),
        }
    }
}

impl EcdsaSighashType {
    /// Splits the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean.
    pub(crate) fn split_anyonecanpay_flag(self) -> (Self, bool) {
        use EcdsaSighashType::*;

        match self {
            All => (All, false),
            None => (None, false),
            Single => (Single, false),
            AllPlusAnyoneCanPay => (All, true),
            NonePlusAnyoneCanPay => (None, true),
            SinglePlusAnyoneCanPay => (Single, true),
        }
    }

    /// Checks if the sighash type is [`Self::Single`] or [`Self::SinglePlusAnyoneCanPay`].
    ///
    /// This matches Bitcoin Core's behavior where SIGHASH_SINGLE bug check is based on the base
    /// type (after masking with 0x1f), regardless of the ANYONECANPAY flag.
    ///
    /// See: <https://github.com/bitcoin/bitcoin/blob/e486597/src/script/interpreter.cpp#L1618-L1619>
    pub fn is_single(&self) -> bool { matches!(self, Self::Single | Self::SinglePlusAnyoneCanPay) }

    /// Constructs a new [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// **Note**: this replicates consensus behavior, for current standardness rules correctness
    /// you probably want [`Self::from_standard`].
    ///
    /// This might cause unexpected behavior because it does not roundtrip. That is,
    /// `EcdsaSighashType::from_consensus(n) as u32 != n` for non-standard values of `n`. While
    /// verifying signatures, the user should retain the `n` and use it to compute the signature hash
    /// message.
    pub fn from_consensus(n: u32) -> Self {
        use EcdsaSighashType::*;

        // In Bitcoin Core, the SignatureHash function will mask the (int32) value with
        // 0x1f to (apparently) deactivate ACP when checking for SINGLE and NONE bits.
        // We however want to be matching also against on ACP-masked ALL, SINGLE, and NONE.
        // So here we re-activate ACP.
        let mask = 0x1f | 0x80;
        match n & mask {
            // "real" sighashes
            0x01 => All,
            0x02 => None,
            0x03 => Single,
            0x81 => AllPlusAnyoneCanPay,
            0x82 => NonePlusAnyoneCanPay,
            0x83 => SinglePlusAnyoneCanPay,
            // catchalls
            x if x & 0x80 == 0x80 => AllPlusAnyoneCanPay,
            _ => All,
        }
    }

    /// Constructs a new [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// # Errors
    ///
    /// If `n` is a non-standard sighash value.
    pub fn from_standard(n: u32) -> Result<Self, NonStandardSighashTypeError> {
        use EcdsaSighashType::*;

        match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => Ok(All),
            0x02 => Ok(None),
            0x03 => Ok(Single),
            0x81 => Ok(AllPlusAnyoneCanPay),
            0x82 => Ok(NonePlusAnyoneCanPay),
            0x83 => Ok(SinglePlusAnyoneCanPay),
            non_standard => Err(NonStandardSighashTypeError(non_standard)),
        }
    }

    /// Converts [`EcdsaSighashType`] to a `u32` sighash flag.
    ///
    /// The returned value is guaranteed to be a valid according to standardness rules.
    pub fn to_u32(self) -> u32 { self as u32 }
}

/// This type is consensus valid but an input including it would prevent the transaction from
/// being relayed on today's Bitcoin network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonStandardSighashTypeError(pub u32);

impl fmt::Display for NonStandardSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "non-standard sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NonStandardSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SighashTypeParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl<R: Borrow<Transaction>> SighashCache<R> {
    /// Constructs a new `SighashCache` from an unsigned transaction.
    ///
    /// The sighash components are computed in a lazy manner when required. For the generated
    /// sighashes to be valid, no fields in the transaction may change except for script_sig and
    /// witness.
    pub fn new(tx: R) -> Self {
        Self { tx, common_cache: None, segwit_cache: None }
    }

    /// Returns the reference to the cached transaction.
    pub fn transaction(&self) -> &Transaction { self.tx.borrow() }

    /// Destroys the cache and recovers the stored transaction.
    pub fn into_transaction(self) -> R { self.tx }

    /// Encodes the BIP-0143 signing data for any flag type into a given object implementing the
    /// [`std::io::Write`] trait.
    ///
    /// `script_code` is dependent on the type of the spend transaction. For p2wpkh use
    /// [`WitnessScript::p2wpkh_script_code`], for p2wsh just pass in the witness script. (Also see
    /// [`Self::p2wpkh_signature_hash`] and [`SighashCache::p2wsh_signature_hash`].)
    ///
    /// In order to sign, the data written by this function must be hashed using a double SHA256
    /// hash. This can be achieved either by using the [`hashes::sha256d::Hash`] type or one of the
    /// custom sighash types in this module ([`SegwitV0Sighash`] and [`LegacySighash`]).
    pub fn segwit_v0_encode_signing_data_to<W: Write>(
        &mut self,
        mut writer: W,
        input_index: usize,
        script_code: &WitnessScript,
        amount: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<(), SigningDataError<transaction::InputsIndexError>> {
        let zero_hash = [0; 32];

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        io::encode_to_writer(&self.tx.borrow().version, &mut writer)?;

        if !anyone_can_pay {
            writer.write_all(&self.segwit_cache().prevouts.to_byte_array())?;
        } else {
            writer.write_all(&zero_hash)?;
        }

        if !anyone_can_pay
            && sighash != EcdsaSighashType::Single
            && sighash != EcdsaSighashType::None
        {
            writer.write_all(&self.segwit_cache().sequences.to_byte_array())?;
        } else {
            writer.write_all(&zero_hash)?;
        }

        {
            let txin = &self.tx.borrow().tx_in(input_index).map_err(SigningDataError::sighash)?;
            io::encode_to_writer(&txin.previous_output, &mut writer)?;
            io::encode_to_writer(script_code, &mut writer)?;
            io::encode_to_writer(&amount, &mut writer)?;
            io::encode_to_writer(&txin.sequence, &mut writer)?;
        }

        if sighash != EcdsaSighashType::Single && sighash != EcdsaSighashType::None {
            writer.write_all(&self.segwit_cache().outputs.to_byte_array())?;
        } else if sighash == EcdsaSighashType::Single
            && input_index < self.tx.borrow().outputs.len()
        {
            let mut single_enc = LegacySighash::engine();
            single_enc =
                hashes::encode_to_engine(&self.tx.borrow().outputs[input_index], single_enc);
            let hash = LegacySighash::from_engine(single_enc);
            writer.write_all(hash.as_byte_array())?;
        } else {
            writer.write_all(&zero_hash)?;
        }

        io::encode_to_writer(&self.tx.borrow().lock_time, &mut writer)?;
        writer.write_all(&sighash_type.to_u32().to_le_bytes())?;
        Ok(())
    }

    /// Computes the BIP-0143 sighash to spend a p2wpkh transaction for any flag type.
    ///
    /// `script_pubkey` is the `scriptPubkey` (native SegWit) of the spend transaction
    /// ([`TxOut::script_pubkey`]) or the `redeemScript` (wrapped SegWit).
    pub fn p2wpkh_signature_hash<T: ScriptHashableTag>(
        &mut self,
        input_index: usize,
        script_pubkey: &crate::script::Script<T>,
        amount: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<SegwitV0Sighash, P2wpkhError> {
        let script_code = script_pubkey.p2wpkh_script_code().ok_or(P2wpkhError::NotP2wpkhScript)?;

        let mut enc = SegwitV0Sighash::engine();
        self.segwit_v0_encode_signing_data_to(
            &mut enc,
            input_index,
            &script_code,
            amount,
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(SegwitV0Sighash::from_engine(enc))
    }

    /// Computes the BIP-0143 sighash to spend a p2wsh transaction for any flag type.
    ///
    /// `witness_script` is the script that goes into the [`Witness`],
    /// not the one that goes into `script_pubkey` of a [`TxOut`].
    pub fn p2wsh_signature_hash(
        &mut self,
        input_index: usize,
        witness_script: &WitnessScript,
        amount: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<SegwitV0Sighash, transaction::InputsIndexError> {
        let mut enc = SegwitV0Sighash::engine();
        self.segwit_v0_encode_signing_data_to(
            &mut enc,
            input_index,
            witness_script,
            amount,
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(SegwitV0Sighash::from_engine(enc))
    }

    /// Encodes the legacy signing data from which a signature hash for a given input index with a
    /// given sighash flag can be computed.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// [`EcdsaSighashType`] appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just [`EcdsaSighashType`],
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// # Warning
    ///
    /// - Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    ///   `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    ///   have the information to determine.
    /// - Does NOT handle the sighash single bug (see "Return type" section)
    ///
    /// # Returns
    ///
    /// This function can't handle the SIGHASH_SINGLE bug internally, so it returns [`EncodeSigningDataResult`]
    /// that must be handled by the caller (see [`EncodeSigningDataResult::is_sighash_single_bug`]).
    pub fn legacy_encode_signing_data_to<W: Write, U: Into<u32>, T: ScriptHashableTag>(
        &self,
        mut writer: W,
        input_index: usize,
        script_pubkey: &crate::script::Script<T>,
        sighash_type: U,
    ) -> EncodeSigningDataResult<SigningDataError<transaction::InputsIndexError>> {
        // Validate input_index.
        if let Err(e) = self.tx.borrow().tx_in(input_index) {
            return EncodeSigningDataResult::WriteResult(Err(SigningDataError::Sighash(e)));
        }
        let sighash_type: u32 = sighash_type.into();

        if is_invalid_use_of_sighash_single(
            sighash_type,
            input_index,
            self.tx.borrow().outputs.len(),
        ) {
            // We cannot correctly handle the SIGHASH_SINGLE bug here because usage of this function
            // will result in the data written to the writer being hashed, however the correct
            // handling of the SIGHASH_SINGLE bug is to return the 'one array' - either implement
            // this behavior manually or use `signature_hash()`.
            return EncodeSigningDataResult::SighashSingleBug;
        }

        fn encode_signing_data_to_inner<W: Write, T: ScriptHashableTag>(
            self_: &Transaction,
            mut writer: W,
            input_index: usize,
            script_pubkey: &crate::script::Script<T>,
            sighash_type: u32,
        ) -> Result<(), io::Error> {
            use crate::consensus::encode::WriteExt;

            let (sighash, anyone_can_pay) =
                EcdsaSighashType::from_consensus(sighash_type).split_anyonecanpay_flag();

            io::encode_to_writer(&self_.version, &mut writer)?;
            // Add all inputs necessary..
            if anyone_can_pay {
                writer.emit_compact_size(1u8)?;
                io::encode_to_writer(&self_.inputs[input_index].previous_output, &mut writer)?;
                io::encode_to_writer(script_pubkey, &mut writer)?;
                io::encode_to_writer(&self_.inputs[input_index].sequence, &mut writer)?;
            } else {
                writer.emit_compact_size(self_.inputs.len())?;
                for (n, input) in self_.inputs.iter().enumerate() {
                    io::encode_to_writer(&input.previous_output, &mut writer)?;
                    if n == input_index {
                        io::encode_to_writer(script_pubkey, &mut writer)?;
                    } else {
                        io::encode_to_writer(ScriptPubKey::new(), &mut writer)?;
                    }
                    if n != input_index
                        && (sighash == EcdsaSighashType::Single
                            || sighash == EcdsaSighashType::None)
                    {
                        io::encode_to_writer(&Sequence::ZERO, &mut writer)?;
                    } else {
                        io::encode_to_writer(&input.sequence, &mut writer)?;
                    }
                }
            }
            // ..then all outputs
            match sighash {
                EcdsaSighashType::All => {
                    let mut encoder = encoding::Encoder2::new(
                        encoding::CompactSizeEncoder::new(self_.outputs.len()),
                        encoding::SliceEncoder::without_length_prefix(&self_.outputs),
                    );
                    io::flush_to_writer(&mut encoder, &mut writer)?;
                }
                EcdsaSighashType::Single => {
                    // sign all outputs up to and including this one, but erase
                    // all of them except for this one
                    let count = input_index.min(self_.outputs.len() - 1);
                    writer.emit_compact_size(count + 1)?;
                    for _ in 0..count {
                        // consensus encoding of the "NULL txout" - max amount, empty script_pubkey
                        writer
                            .write_all(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])?;
                    }
                    io::encode_to_writer(&self_.outputs[count], &mut writer)?;
                }
                EcdsaSighashType::None => {
                    writer.emit_compact_size(0u8)?;
                }
                _ => unreachable!(),
            };
            io::encode_to_writer(&self_.lock_time, &mut writer)?;
            writer.write_all(&sighash_type.to_le_bytes())?;
            Ok(())
        }

        EncodeSigningDataResult::WriteResult(
            encode_signing_data_to_inner(
                self.tx.borrow(),
                &mut writer,
                input_index,
                script_pubkey,
                sighash_type,
            )
            .map_err(Into::into),
        )
    }

    /// Computes a legacy signature hash for a given input index with a given sighash flag.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// [`EcdsaSighashType`] appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just [`EcdsaSighashType`],
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// This function correctly handles the sighash single bug by returning the 'one array'. The
    /// sighash single bug becomes exploitable when one tries to sign a transaction with
    /// `SIGHASH_SINGLE` and there is not a corresponding output with the same index as the input.
    ///
    /// # Warning
    ///
    /// Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    /// `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    /// have the information to determine.
    pub fn legacy_signature_hash<T: ScriptHashableTag>(
        &self,
        input_index: usize,
        script_pubkey: &crate::script::Script<T>,
        sighash_type: u32,
    ) -> Result<LegacySighash, transaction::InputsIndexError> {
        let mut engine = LegacySighash::engine();
        match self
            .legacy_encode_signing_data_to(&mut engine, input_index, script_pubkey, sighash_type)
            .is_sighash_single_bug()
        {
            Ok(true) => Ok(LegacySighash::from_byte_array(UINT256_ONE)),
            Ok(false) => Ok(LegacySighash::from_engine(engine)),
            Err(e) => Err(e.unwrap_sighash()),
        }
    }

    fn common_cache_minimal_borrow<'a>(
        common_cache: &'a mut Option<CommonCache>,
        tx: &Transaction,
    ) -> &'a CommonCache {
        common_cache.get_or_insert_with(|| {
            let mut enc_prevouts = sha256::Hash::engine();
            let mut enc_sequences = sha256::Hash::engine();
            for txin in tx.inputs.iter() {
                enc_prevouts = hashes::encode_to_engine(&txin.previous_output, enc_prevouts);
                enc_sequences = hashes::encode_to_engine(&txin.sequence, enc_sequences);
            }
            CommonCache {
                prevouts: sha256::Hash::from_engine(enc_prevouts),
                sequences: sha256::Hash::from_engine(enc_sequences),
                outputs: {
                    let mut enc = sha256::Hash::engine();
                    for txout in tx.outputs.iter() {
                        io::encode_to_writer(txout, &mut enc).unwrap();
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

}

impl<R: BorrowMut<Transaction>> SighashCache<R> {
    /// Allows modification of witnesses.
    ///
    /// As a lint against accidental changes to the transaction that would invalidate the cache and
    /// signatures, `SighashCache` borrows the Transaction so that modifying it is not possible
    /// without hacks with `UnsafeCell` (which is hopefully a strong indication that something is
    /// wrong). However modifying witnesses never invalidates the cache and is actually useful - one
    /// usually wants to put the signature generated for an input into the witness of that input.
    ///
    /// This method allows doing exactly that if the transaction is owned by the `SighashCache` or
    /// borrowed mutably.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # // Example is an incomplete section of code that does not compile by itself
    /// let mut sighasher = SighashCache::new(&mut tx_to_sign);
    /// let sighash = sighasher.p2wpkh_signature_hash(input_index, &utxo.script_pubkey, amount, sighash_type)?;
    ///
    /// let signature = {
    ///     // Sign the sighash using secp256k1
    /// };
    ///
    /// *sighasher.witness_mut(input_index).unwrap() = Witness::p2wpkh(&signature, &pk);
    /// ```
    ///
    /// For full signing code see the [`SegWit v0`] signing example.
    ///
    /// [`SegWit v0`]: <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/examples/sign-tx-segwit-v0.rs>
    pub fn witness_mut(&mut self, input_index: usize) -> Option<&mut Witness> {
        self.tx.borrow_mut().inputs.get_mut(input_index).map(|i| &mut i.witness)
    }
}

/// Error computing a P2WPKH sighash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum P2wpkhError {
    /// Error computing the sighash.
    Sighash(transaction::InputsIndexError),
    /// Script is not a witness program for a p2wpkh output.
    NotP2wpkhScript,
}

impl From<Infallible> for P2wpkhError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<transaction::InputsIndexError> for P2wpkhError {
    fn from(value: transaction::InputsIndexError) -> Self { Self::Sighash(value) }
}

impl fmt::Display for P2wpkhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sighash(ref e) => write_err!(f, "error encoding SegWit v0 signing data"; e),
            Self::NotP2wpkhScript => write!(f, "script is not a script pubkey for a p2wpkh output"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for P2wpkhError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sighash(ref e) => Some(e),
            Self::NotP2wpkhScript => None,
        }
    }
}

fn is_invalid_use_of_sighash_single(sighash: u32, input_index: usize, outputs_len: usize) -> bool {
    let ty = EcdsaSighashType::from_consensus(sighash);
    ty.is_single() && input_index >= outputs_len
}

/// Result of [`SighashCache::legacy_encode_signing_data_to`].
///
/// This type forces the caller to handle SIGHASH_SINGLE bug case.
///
/// This corner case can't be expressed using standard `Result`,
/// in a way that is both convenient and not-prone to accidental
/// mistakes (like calling `.expect("writer never fails")`).
#[must_use]
pub enum EncodeSigningDataResult<E> {
    /// Input data is an instance of `SIGHASH_SINGLE` bug
    SighashSingleBug,
    /// Operation performed normally.
    WriteResult(Result<(), E>),
}

impl<E> EncodeSigningDataResult<E> {
    /// Checks for SIGHASH_SINGLE bug returning error if the writer failed.
    ///
    /// This method is provided for easy and correct handling of the result because
    /// SIGHASH_SINGLE bug is a special case that must not be ignored nor cause panicking.
    /// Since the data is usually written directly into a hasher which never fails,
    /// the recommended pattern to handle this is:
    ///
    /// ```rust
    /// # use tidecoin::consensus::deserialize;
    /// # use tidecoin::hashes::sha256d;
    /// # use tidecoin::sighash::SighashCache;
    /// # use tidecoin::Transaction;
    /// # use tidecoin::hex;
    /// # let mut writer = sha256d::Hash::engine();
    /// # let input_index = 0;
    /// # let script_pubkey = tidecoin::ScriptPubKeyBuf::new();
    /// # let sighash_u32 = 0u32;
    /// # const SOME_TX: &'static str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    /// # let raw_tx = hex::decode_to_vec(SOME_TX).unwrap();
    /// # let tx: Transaction = deserialize(&raw_tx).unwrap();
    /// let cache = SighashCache::new(&tx);
    /// if cache.legacy_encode_signing_data_to(&mut writer, input_index, &script_pubkey, sighash_u32)
    ///         .is_sighash_single_bug()
    ///         .expect("writer can't fail") {
    ///     // use a hash value of "1", instead of computing the actual hash due to SIGHASH_SINGLE bug
    /// } else {
    ///     // use the hash from `writer`
    /// }
    /// ```
    #[allow(clippy::wrong_self_convention)] // Consume self so we can take the error.
    pub fn is_sighash_single_bug(self) -> Result<bool, E> {
        match self {
            Self::SighashSingleBug => Ok(true),
            Self::WriteResult(Ok(())) => Ok(false),
            Self::WriteResult(Err(e)) => Err(e),
        }
    }

    /// Maps a `Result<T, E>` to `Result<T, F>` by applying a function to a
    /// contained [`Err`] value, leaving an [`Ok`] value untouched.
    ///
    /// Like [`Result::map_err`].
    pub fn map_err<E2, F>(self, f: F) -> EncodeSigningDataResult<E2>
    where
        F: FnOnce(E) -> E2,
    {
        match self {
            Self::SighashSingleBug => EncodeSigningDataResult::SighashSingleBug,
            Self::WriteResult(Err(e)) => EncodeSigningDataResult::WriteResult(Err(f(e))),
            Self::WriteResult(Ok(o)) => EncodeSigningDataResult::WriteResult(Ok(o)),
        }
    }
}

/// Error returned when writing signing data fails.
#[derive(Debug)]
pub enum SigningDataError<E> {
    /// Can happen only when using `*_encode_signing_*` methods with custom writers, engines
    /// like those used in `*_signature_hash` methods do not error.
    Io(io::Error),
    /// An argument to the called sighash function was invalid.
    Sighash(E),
}

impl<E> From<Infallible> for SigningDataError<E> {
    fn from(never: Infallible) -> Self { match never {} }
}

impl<E> SigningDataError<E> {
    /// Returns the sighash variant, panicking if it's I/O.
    ///
    /// This is used when encoding to hash engine when we know that I/O doesn't fail.
    fn unwrap_sighash(self) -> E {
        match self {
            Self::Sighash(error) => error,
            Self::Io(error) => panic!("hash engine error {}", error),
        }
    }

    fn sighash<E2: Into<E>>(error: E2) -> Self { Self::Sighash(error.into()) }
}

// We cannot simultaneously impl `From<E>`. it was determined that this alternative requires less
// manual `map_err` calls.
impl<E> From<io::Error> for SigningDataError<E> {
    fn from(value: io::Error) -> Self { Self::Io(value) }
}

impl<E: fmt::Display> fmt::Display for SigningDataError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(error) => write_err!(f, "failed to write sighash data"; error),
            Self::Sighash(error) => write_err!(f, "failed to compute sighash data"; error),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error + 'static> std::error::Error for SigningDataError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sighash(error) => Some(error),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for EcdsaSighashType {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=5)?;
        match choice {
            0 => Ok(Self::All),
            1 => Ok(Self::None),
            2 => Ok(Self::Single),
            3 => Ok(Self::AllPlusAnyoneCanPay),
            4 => Ok(Self::NonePlusAnyoneCanPay),
            _ => Ok(Self::SinglePlusAnyoneCanPay),
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_unstable::hex;

    use super::*;
    use crate::consensus::deserialize;
    use crate::locktime::absolute;
    use crate::script::{ScriptPubKeyBuf, WitnessScriptBuf};
    use crate::{hex, TxIn, TxOut};

    extern crate serde_json;

    const DUMMY_TXOUT: TxOut = TxOut { amount: Amount::MIN, script_pubkey: ScriptPubKeyBuf::new() };

    #[test]
    fn sighash_single_bug() {
        // We need a tx with more inputs than outputs.
        let tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn::EMPTY_COINBASE, TxIn::EMPTY_COINBASE],
            outputs: vec![DUMMY_TXOUT],
        };
        let script = ScriptPubKeyBuf::new();
        let cache = SighashCache::new(&tx);

        let sighash_single = 3;
        let got = cache.legacy_signature_hash(1, &script, sighash_single).expect("sighash");
        let want = LegacySighash::from_byte_array(UINT256_ONE);
        assert_eq!(got, want);

        // https://github.com/rust-bitcoin/rust-bitcoin/issues/4112
        let sighash_single = 131;
        let got = cache.legacy_signature_hash(1, &script, sighash_single).expect("sighash");
        let want = LegacySighash::from_byte_array(UINT256_ONE);
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn legacy_sighash() {
        use serde_json::Value;

        use crate::sighash::SighashCache;

        fn run_test_sighash(
            tx: &str,
            script: &str,
            input_index: usize,
            hash_type: i64,
            expected_result: &str,
        ) {
            let tx: Transaction = deserialize(&hex::decode_to_vec(tx).unwrap()[..]).unwrap();
            let script = ScriptPubKeyBuf::from(hex::decode_to_vec(script).unwrap());
            let mut raw_expected = hex::decode_to_vec(expected_result).unwrap();
            raw_expected.reverse();
            let bytes = <[u8; 32]>::try_from(&raw_expected[..]).unwrap();
            let want = LegacySighash::from_byte_array(bytes);

            let cache = SighashCache::new(&tx);
            let got = cache.legacy_signature_hash(input_index, &script, hash_type as u32).unwrap();

            assert_eq!(got, want);
        }

        // These test vectors were stolen from libbtc, which is Copyright 2014 Jonas Schnelli MIT
        // They were transformed by replacing {...} with run_test_sighash(...), then the ones containing
        // OP_CODESEPARATOR in their pubkeys were removed
        let data = include_str!("../../tests/data/legacy_sighash.json");

        let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
        for t in testdata.iter().skip(1) {
            let tx = t.get(0).unwrap().as_str().unwrap();
            let script = t.get(1).unwrap().as_str().unwrap_or("");
            let input_index = t.get(2).unwrap().as_u64().unwrap();
            let hash_type = t.get(3).unwrap().as_i64().unwrap();
            let expected_sighash = t.get(4).unwrap().as_str().unwrap();
            run_test_sighash(tx, script, input_index as usize, hash_type, expected_sighash);
        }
    }

    #[test]
    fn bip143_p2wpkh() {
        let tx = deserialize::<Transaction>(
            &hex!(
                "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000\
                0000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000\
                00ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093\
                510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
            ),
        ).unwrap();

        let spk = ScriptPubKeyBuf::from_hex_no_length_prefix(
            "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1",
        )
        .unwrap();
        let amount = Amount::from_sat_u32(600_000_000);

        let mut cache = SighashCache::new(&tx);
        assert_eq!(
            cache.p2wpkh_signature_hash(1, &spk, amount, EcdsaSighashType::All).unwrap(),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
                .parse::<SegwitV0Sighash>()
                .unwrap(),
        );

        let cache = cache.segwit_cache();
        // Parse hex into Vec because BIP-0143 test vector displays forwards but our sha256d::Hash displays backwards.
        assert_eq!(
            cache.prevouts.as_byte_array(),
            &hex::decode_to_vec("96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37")
                .unwrap()[..],
        );
        assert_eq!(
            cache.sequences.as_byte_array(),
            &hex::decode_to_vec("52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b")
                .unwrap()[..],
        );
        assert_eq!(
            cache.outputs.as_byte_array(),
            &hex::decode_to_vec("863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5")
                .unwrap()[..],
        );
    }

    #[test]
    fn bip143_p2wpkh_nested_in_p2sh() {
        let tx = deserialize::<Transaction>(
            &hex!(
                "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000\
                0000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac00\
                08af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
            ),
        ).unwrap();

        let spk = ScriptPubKeyBuf::from_hex_no_length_prefix(
            "001479091972186c449eb1ded22b78e40d009bdf0089",
        )
        .unwrap();
        let amount = Amount::from_sat_u32(1_000_000_000);

        let mut cache = SighashCache::new(&tx);
        assert_eq!(
            cache.p2wpkh_signature_hash(0, &spk, amount, EcdsaSighashType::All).unwrap(),
            "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
                .parse::<SegwitV0Sighash>()
                .unwrap(),
        );

        let cache = cache.segwit_cache();
        // Parse hex into Vec because BIP-0143 test vector displays forwards but our sha256d::Hash displays backwards.
        assert_eq!(
            cache.prevouts.as_byte_array(),
            &hex::decode_to_vec("b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a")
                .unwrap()[..],
        );
        assert_eq!(
            cache.sequences.as_byte_array(),
            &hex::decode_to_vec("18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198")
                .unwrap()[..],
        );
        assert_eq!(
            cache.outputs.as_byte_array(),
            &hex::decode_to_vec("de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83")
                .unwrap()[..],
        );
    }

    // Note, if you are looking at the test vectors in BIP-0143 and wondering why there is a `cf`
    // prepended to all the script_code hex it is the length byte, it gets added when we consensus
    // encode a script.
    fn bip143_p2wsh_nested_in_p2sh_data() -> (Transaction, WitnessScriptBuf, Amount) {
        let tx = deserialize::<Transaction>(&hex!(
            "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000\
             ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f\
             05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"
        ))
        .unwrap();

        let witness_script = WitnessScriptBuf::from_hex_no_length_prefix(
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28\
             bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b\
             9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58\
             c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b1486\
             2c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b\
             56ae",
        )
        .unwrap();

        let amount = Amount::from_sat_u32(987_654_321);
        (tx, witness_script, amount)
    }

    #[test]
    fn bip143_p2wsh_nested_in_p2sh_sighash_type_all() {
        let (tx, witness_script, amount) = bip143_p2wsh_nested_in_p2sh_data();
        let mut cache = SighashCache::new(&tx);
        assert_eq!(
            cache.p2wsh_signature_hash(0, &witness_script, amount, EcdsaSighashType::All).unwrap(),
            "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c"
                .parse::<SegwitV0Sighash>()
                .unwrap(),
        );

        // We only test the cache intermediate values for `EcdsaSighashType::All` because they are
        // not the same as the BIP test vectors for all the rest of the sighash types. These fields
        // are private so it does not effect sighash cache usage, we do test against the produced
        // sighash for all sighash types.

        let cache = cache.segwit_cache();
        // Parse hex into Vec because BIP-0143 test vector displays forwards but our sha256d::Hash displays backwards.
        assert_eq!(
            cache.prevouts.as_byte_array(),
            &hex::decode_to_vec("74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0")
                .unwrap()[..],
        );
        assert_eq!(
            cache.sequences.as_byte_array(),
            &hex::decode_to_vec("3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044")
                .unwrap()[..],
        );
        assert_eq!(
            cache.outputs.as_byte_array(),
            &hex::decode_to_vec("bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc")
                .unwrap()[..],
        );
    }

    macro_rules! check_bip143_p2wsh_nested_in_p2sh {
        ($($test_name:ident, $sighash_type:ident, $sighash:literal);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    use EcdsaSighashType::*;

                    let (tx, witness_script, amount) = bip143_p2wsh_nested_in_p2sh_data();
                    let mut cache = SighashCache::new(&tx);
                    assert_eq!(
                        cache
                            .p2wsh_signature_hash(0, &witness_script, amount, $sighash_type)
                            .unwrap(),
                        $sighash
                            .parse::<SegwitV0Sighash>()
                            .unwrap(),
                    );
                }
            )*
        }
    }
    check_bip143_p2wsh_nested_in_p2sh! {
        // EcdsaSighashType::All tested above.
        bip143_p2wsh_nested_in_p2sh_sighash_none, None, "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36";
        bip143_p2wsh_nested_in_p2sh_sighash_single, Single, "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea";
        bip143_p2wsh_nested_in_p2sh_sighash_all_plus_anyonecanpay, AllPlusAnyoneCanPay, "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e";
        bip143_p2wsh_nested_in_p2sh_sighash_none_plus_anyonecanpay, NonePlusAnyoneCanPay, "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a";
        bip143_p2wsh_nested_in_p2sh_sighash_single_plus_anyonecanpay, SinglePlusAnyoneCanPay, "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b";
    }
}
