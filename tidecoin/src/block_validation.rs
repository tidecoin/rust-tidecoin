// SPDX-License-Identifier: CC0-1.0

//! Tidecoin block and header validation with chain context.
//!
//! This module owns validation that cannot be decided from a header or block in
//! isolation. Context-free sanity remains in `primitives`; mining-hash and
//! retarget primitives remain in [`crate::pow`].

use core::convert::Infallible;
use core::fmt;

use crate::block::{
    Bip34Error, Block, BlockCheckedExt as _, BlockHash, BlockHeight, BlockHeightInterval, BlockMtp,
    Header, InvalidBlockError, Unchecked, Version,
};
use crate::network::Params;
use crate::pow::{self, AuxPowValidationError, PowValidationError};
use crate::{BlockTime, CompactTarget, Transaction, Weight};
use units::absolute::LOCK_TIME_THRESHOLD;

/// Maximum timestamp rollback allowed on BIP94 difficulty-adjustment blocks.
pub const MAX_TIMEWARP_SECONDS: u32 = 600;

/// Maximum future timestamp distance accepted by the Tidecoin node.
pub const MAX_FUTURE_BLOCK_TIME_SECONDS: u32 = 2 * 60 * 60;

/// Options for contextual header validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextualHeaderCheck {
    /// Validate the selected Tidecoin PoW class or AuxPoW context.
    pub check_proof: bool,
    /// Optional current node time used for the node's future-timestamp rule.
    ///
    /// When absent, the deterministic library check skips `time-too-new`.
    pub current_time: Option<BlockTime>,
}

impl ContextualHeaderCheck {
    /// Default deterministic contextual header checks.
    pub const DEFAULT: Self = Self { check_proof: true, current_time: None };
}

impl Default for ContextualHeaderCheck {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Error returned by contextual header validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextualHeaderError<E = Infallible> {
    /// The previous block height cannot be advanced by one.
    HeightOverflow,
    /// The candidate header does not commit to the supplied previous header.
    PrevBlockHash {
        /// Expected previous block hash.
        expected: BlockHash,
        /// Actual previous block hash in the candidate header.
        actual: BlockHash,
    },
    /// The caller could not provide a required historical header.
    HeaderLookup {
        /// Requested block height.
        height: BlockHeight,
        /// Underlying lookup error.
        source: E,
    },
    /// The candidate `nBits` does not match the node retarget path.
    BadDiffBits {
        /// Expected compact target.
        expected: CompactTarget,
        /// Actual compact target in the candidate header.
        actual: CompactTarget,
    },
    /// The candidate timestamp is not greater than previous median time past.
    TimeTooOld {
        /// Candidate timestamp.
        block_time: BlockTime,
        /// Previous median time past.
        previous_mtp: BlockMtp,
    },
    /// The candidate timestamp violates the BIP94 timewarp bound.
    Timewarp {
        /// Candidate timestamp.
        block_time: BlockTime,
        /// Minimum timestamp accepted at this difficulty-adjustment boundary.
        min_time: BlockTime,
    },
    /// The candidate timestamp is too far in the future.
    TimeTooNew {
        /// Candidate timestamp.
        block_time: BlockTime,
        /// Maximum accepted timestamp.
        max_time: BlockTime,
    },
    /// The candidate base version is not accepted at this height.
    BadVersion {
        /// Base version after stripping AuxPoW and embedded chain-id bits.
        base_version: i32,
    },
    /// AuxPoW context validation failed.
    AuxPow(AuxPowValidationError),
    /// Pure-header proof-of-work validation failed.
    Pow(PowValidationError),
}

impl<E> fmt::Display for ContextualHeaderError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeightOverflow => write!(f, "block height overflow"),
            Self::PrevBlockHash { expected, actual } => {
                write!(f, "previous block hash mismatch: expected {expected}, got {actual}")
            }
            Self::HeaderLookup { height, .. } => {
                write!(f, "failed to load contextual header at height {height}")
            }
            Self::BadDiffBits { expected, actual } => {
                write!(f, "incorrect proof-of-work target: expected {expected}, got {actual}")
            }
            Self::TimeTooOld { block_time, previous_mtp } => {
                write!(
                    f,
                    "block timestamp {block_time} is not greater than previous median time past {previous_mtp}"
                )
            }
            Self::Timewarp { block_time, min_time } => {
                write!(f, "block timestamp {block_time} is before BIP94 minimum {min_time}")
            }
            Self::TimeTooNew { block_time, max_time } => {
                write!(f, "block timestamp {block_time} is after maximum {max_time}")
            }
            Self::BadVersion { base_version } => {
                write!(f, "rejected block base version {base_version}")
            }
            Self::AuxPow(err) => write!(f, "auxpow validation failed: {err}"),
            Self::Pow(err) => write!(f, "proof-of-work validation failed: {err}"),
        }
    }
}

/// Error returned by contextual block validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextualBlockError<E = Infallible> {
    /// Context-free block sanity failed.
    Sanity(InvalidBlockError),
    /// Contextual header validation failed.
    Header(ContextualHeaderError<E>),
    /// The previous block height cannot be advanced by one.
    HeightOverflow,
    /// A transaction is not final at the candidate height and lock-time cutoff.
    NonFinalTransaction {
        /// Transaction index inside the block.
        index: usize,
    },
    /// Coinbase height extraction failed.
    CoinbaseHeight(Bip34Error),
    /// Coinbase height does not match the candidate block height.
    BadCoinbaseHeight {
        /// Expected block height.
        expected: BlockHeight,
        /// Height committed by the coinbase transaction.
        actual: u64,
    },
    /// Witness data is present before the node's witness activation height.
    UnexpectedWitness {
        /// Transaction index inside the block.
        transaction_index: usize,
        /// Input index inside the transaction.
        input_index: usize,
    },
    /// Witness commitment or reserved value validation failed.
    InvalidWitnessCommitment(InvalidBlockError),
    /// The witness-inclusive block weight exceeds the node consensus limit.
    WeightLimit,
}

impl<E> fmt::Display for ContextualBlockError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sanity(err) => write!(f, "context-free block sanity failed: {err}"),
            Self::Header(err) => write!(f, "contextual header validation failed: {err}"),
            Self::HeightOverflow => write!(f, "block height overflow"),
            Self::NonFinalTransaction { index } => {
                write!(f, "transaction {index} is not final at block height")
            }
            Self::CoinbaseHeight(err) => write!(f, "coinbase height extraction failed: {err}"),
            Self::BadCoinbaseHeight { expected, actual } => {
                write!(f, "coinbase height mismatch: expected {expected}, got {actual}")
            }
            Self::UnexpectedWitness { transaction_index, input_index } => write!(
                f,
                "unexpected witness before activation at transaction {transaction_index}, input {input_index}"
            ),
            Self::InvalidWitnessCommitment(err) => {
                write!(f, "witness commitment validation failed: {err}")
            }
            Self::WeightLimit => write!(f, "block weight limit failed"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for ContextualBlockError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sanity(err) => Some(err),
            Self::Header(err) => Some(err),
            Self::CoinbaseHeight(err) => Some(err),
            Self::InvalidWitnessCommitment(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for ContextualHeaderError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HeaderLookup { source, .. } => Some(source),
            Self::AuxPow(err) => Some(err),
            Self::Pow(err) => Some(err),
            _ => None,
        }
    }
}

/// Contextually validates a block header against its previous header.
///
/// This uses [`ContextualHeaderCheck::default`]. Use
/// [`contextual_check_block_header_with_options`] when the caller wants to
/// disable PoW checks or supply a deterministic current time.
pub fn contextual_check_block_header<F, E>(
    params: impl AsRef<Params>,
    previous_header: &Header,
    previous_height: BlockHeight,
    header: &Header,
    get_header_by_height: F,
) -> Result<(), ContextualHeaderError<E>>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    contextual_check_block_header_with_options(
        params,
        previous_header,
        previous_height,
        header,
        get_header_by_height,
        ContextualHeaderCheck::default(),
    )
}

/// Contextually validates a block header with explicit validation options.
pub fn contextual_check_block_header_with_options<F, E>(
    params: impl AsRef<Params>,
    previous_header: &Header,
    previous_height: BlockHeight,
    header: &Header,
    mut get_header_by_height: F,
    options: ContextualHeaderCheck,
) -> Result<(), ContextualHeaderError<E>>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    let params = params.as_ref();
    let height = previous_height
        .checked_add(BlockHeightInterval::from_u32(1))
        .ok_or(ContextualHeaderError::HeightOverflow)?;

    let expected_prev_hash = previous_header.block_hash();
    if header.prev_blockhash != expected_prev_hash {
        return Err(ContextualHeaderError::PrevBlockHash {
            expected: expected_prev_hash,
            actual: header.prev_blockhash,
        });
    }

    let expected_bits = pow::next_target_after(
        previous_header.clone(),
        previous_height,
        params,
        Some(header.time.to_u32()),
        |height| {
            get_header_by_height(height)
                .map_err(|source| ContextualHeaderError::HeaderLookup { height, source })
        },
    )?;
    if header.bits != expected_bits {
        return Err(ContextualHeaderError::BadDiffBits {
            expected: expected_bits,
            actual: header.bits,
        });
    }

    let previous_mtp =
        median_time_past(previous_header, previous_height, &mut get_header_by_height)?;
    if header.time.to_u32() <= previous_mtp.to_u32() {
        return Err(ContextualHeaderError::TimeTooOld { block_time: header.time, previous_mtp });
    }

    if params.enforce_bip94
        && height.to_u32().is_multiple_of(params.difficulty_adjustment_interval())
    {
        let min_time = previous_header.time.to_u32().saturating_sub(MAX_TIMEWARP_SECONDS);
        if header.time.to_u32() < min_time {
            return Err(ContextualHeaderError::Timewarp {
                block_time: header.time,
                min_time: BlockTime::from_u32(min_time),
            });
        }
    }

    if let Some(current_time) = options.current_time {
        let max_time = current_time.to_u32().saturating_add(MAX_FUTURE_BLOCK_TIME_SECONDS);
        if header.time.to_u32() > max_time {
            return Err(ContextualHeaderError::TimeTooNew {
                block_time: header.time,
                max_time: BlockTime::from_u32(max_time),
            });
        }
    }

    check_base_version(params, height, header.version)?;

    if options.check_proof {
        pow::validate_auxpow_context(header, params, Some(height))
            .map_err(ContextualHeaderError::AuxPow)?;
        if !header.version.is_auxpow() {
            pow::validate_pow_at_height(header, params, height)
                .map_err(ContextualHeaderError::Pow)?;
        }
    }

    Ok(())
}

/// Contextually validates a block against its previous header.
///
/// This performs context-free block sanity plus non-UTXO contextual checks that
/// mirror the node's `ContextualCheckBlock`: header context, transaction
/// finality, coinbase height, and pre-activation witness rejection.
pub fn contextual_check_block<F, E>(
    params: impl AsRef<Params>,
    previous_header: &Header,
    previous_height: BlockHeight,
    block: &Block<Unchecked>,
    get_header_by_height: F,
) -> Result<(), ContextualBlockError<E>>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    contextual_check_block_with_options(
        params,
        previous_header,
        previous_height,
        block,
        get_header_by_height,
        ContextualHeaderCheck::default(),
    )
}

/// Contextually validates a block with explicit validation options.
pub fn contextual_check_block_with_options<F, E>(
    params: impl AsRef<Params>,
    previous_header: &Header,
    previous_height: BlockHeight,
    block: &Block<Unchecked>,
    mut get_header_by_height: F,
    options: ContextualHeaderCheck,
) -> Result<(), ContextualBlockError<E>>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    let params = params.as_ref();
    let height = previous_height
        .checked_add(BlockHeightInterval::from_u32(1))
        .ok_or(ContextualBlockError::HeightOverflow)?;

    crate::block::check_block_sanity(block)
        .map_err(InvalidBlockError::from)
        .map_err(ContextualBlockError::Sanity)?;
    let (header, transactions) = block.as_parts();
    contextual_check_block_header_with_options(
        params,
        previous_header,
        previous_height,
        header,
        &mut get_header_by_height,
        options,
    )
    .map_err(ContextualBlockError::Header)?;

    let previous_mtp =
        median_time_past(previous_header, previous_height, &mut get_header_by_height)
            .map_err(ContextualBlockError::Header)?;
    let lock_time_cutoff =
        if height >= params.csv_height { previous_mtp.to_u32() } else { header.time.to_u32() };

    for (index, tx) in transactions.iter().enumerate() {
        if !is_final_transaction(tx, height, lock_time_cutoff) {
            return Err(ContextualBlockError::NonFinalTransaction { index });
        }
    }

    if height >= params.bip34_height {
        let coinbase_height = block
            .clone()
            .assume_checked(None)
            .bip34_block_height()
            .map_err(ContextualBlockError::CoinbaseHeight)?;
        if coinbase_height != u64::from(height.to_u32()) {
            return Err(ContextualBlockError::BadCoinbaseHeight {
                expected: height,
                actual: coinbase_height,
            });
        }
    }

    if height < params.segwit_height {
        for (transaction_index, tx) in transactions.iter().enumerate() {
            for (input_index, input) in tx.inputs.iter().enumerate() {
                if !input.witness.is_empty() {
                    return Err(ContextualBlockError::UnexpectedWitness {
                        transaction_index,
                        input_index,
                    });
                }
            }
        }
    } else {
        let (witness_commitment_valid, _) = block.check_witness_commitment();
        if !witness_commitment_valid {
            return Err(ContextualBlockError::InvalidWitnessCommitment(
                InvalidBlockError::InvalidWitnessCommitment,
            ));
        }
    }

    if block.weight().to_wu() > Weight::MAX_BLOCK.to_wu() {
        return Err(ContextualBlockError::WeightLimit);
    }

    Ok(())
}

fn check_base_version<E>(
    params: &Params,
    height: BlockHeight,
    version: Version,
) -> Result<(), ContextualHeaderError<E>> {
    let base_version = version.base_version();
    if (base_version < 2 && height >= params.bip34_height)
        || (base_version < 3 && height >= params.bip66_height)
        || (base_version < 4 && height >= params.bip65_height)
        || (pow::uses_post_auxpow_pow_rules(params, height)
            && !Version::is_valid_base_version(base_version))
    {
        return Err(ContextualHeaderError::BadVersion { base_version });
    }

    Ok(())
}

fn is_final_transaction(tx: &Transaction, height: BlockHeight, lock_time_cutoff: u32) -> bool {
    let lock_time = tx.lock_time.to_consensus_u32();
    if lock_time == 0 {
        return true;
    }

    let threshold =
        if lock_time < LOCK_TIME_THRESHOLD { height.to_u32() } else { lock_time_cutoff };
    if lock_time < threshold {
        return true;
    }

    tx.inputs.iter().all(|input| input.sequence.is_final())
}

fn median_time_past<F, E>(
    previous_header: &Header,
    previous_height: BlockHeight,
    get_header_by_height: &mut F,
) -> Result<BlockMtp, ContextualHeaderError<E>>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    let mut times = [0_u32; 11];
    let mut count = 0;
    let previous_height = previous_height.to_u32();
    for offset in 0..11 {
        if offset > previous_height {
            break;
        }
        let height = BlockHeight::from_u32(previous_height - offset);
        let header = if offset == 0 {
            previous_header.clone()
        } else {
            get_header_by_height(height)
                .map_err(|source| ContextualHeaderError::HeaderLookup { height, source })?
        };
        times[count] = header.time.to_u32();
        count += 1;
    }
    let times = &mut times[..count];
    times.sort_unstable();
    Ok(BlockMtp::from_u32(times[count / 2]))
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::*;
    use crate::block::compute_merkle_root;
    use crate::script::{ScriptPubKeyBuf, ScriptSigBuf};
    use crate::{absolute, Amount, OutPoint, Sequence, TxIn, TxMerkleNode, TxOut, Txid, Witness};
    #[cfg(feature = "tidecoin-node-validation")]
    use internals::hex::DisplayHex as _;
    #[cfg(feature = "tidecoin-node-validation")]
    use node_parity::TidecoinNodeHarness;

    fn retarget_windows() -> alloc::vec::Vec<serde_json::Value> {
        let data = include_str!("../tests/data/testnet_retarget_windows.json");
        let value: serde_json::Value =
            serde_json::from_str(data).expect("real testnet retarget fixture json must parse");
        value["retarget_windows"].as_array().expect("real testnet retarget windows").clone()
    }

    fn header_from_fixture(case: &serde_json::Value) -> Header {
        let name = case["name"].as_str().expect("fixture name");
        let header_hex = case["header_hex"].as_str().expect("fixture header hex");
        let header_bytes = crate::hex::decode_to_vec(header_hex)
            .unwrap_or_else(|err| panic!("{name} header hex decodes: {err}"));
        encoding::decode_from_slice(&header_bytes)
            .unwrap_or_else(|err| panic!("{name} fixture header decodes: {err}"))
    }

    fn headers_from_window(name: &str) -> alloc::vec::Vec<(BlockHeight, Header)> {
        let window = retarget_windows()
            .into_iter()
            .find(|window| window["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing retarget window {name}"));
        window["headers"]
            .as_array()
            .expect("retarget window headers")
            .iter()
            .map(|case| {
                let height = BlockHeight::from_u32(case["height"].as_u64().expect("height") as u32);
                (height, header_from_fixture(case))
            })
            .collect()
    }

    fn header_at(headers: &[(BlockHeight, Header)], height: BlockHeight) -> Header {
        headers
            .iter()
            .find_map(|(candidate_height, header)| {
                (*candidate_height == height).then(|| header.clone())
            })
            .unwrap_or_else(|| panic!("missing header fixture at height {height}"))
    }

    fn regtest_bits() -> CompactTarget {
        Params::REGTEST.max_attainable_target.to_compact_lossy()
    }

    fn synthetic_context_headers() -> alloc::vec::Vec<(BlockHeight, Header)> {
        (0..=10)
            .map(|height| {
                (
                    BlockHeight::from_u32(height),
                    Header {
                        version: Version::from_consensus(4),
                        prev_blockhash: BlockHash::from_byte_array([height as u8; 32]),
                        merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                        time: BlockTime::from_u32(1_700_000_000 + height * 60),
                        bits: regtest_bits(),
                        nonce: 0,
                        auxpow: None,
                    },
                )
            })
            .collect()
    }

    fn coinbase_tx(height: u8) -> Transaction {
        let mut input = TxIn::EMPTY_COINBASE;
        let height_opcode = match height {
            0 => 0x00,
            1..=16 => 0x50 + height,
            _ => panic!("synthetic coinbase height helper only supports small heights"),
        };
        input.script_sig = ScriptSigBuf::from_bytes(vec![height_opcode, 0x51]);
        Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![input],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        }
    }

    fn spend_tx(tag: u8, lock_time: absolute::LockTime, sequence: Sequence) -> Transaction {
        Transaction {
            version: crate::transaction::Version::ONE,
            lock_time,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        }
    }

    #[cfg(feature = "tidecoin-node-validation")]
    fn spend_txs(
        range: core::ops::RangeInclusive<u8>,
        lock_time: absolute::LockTime,
        sequence: Sequence,
    ) -> alloc::vec::Vec<Transaction> {
        range.map(|tag| spend_tx(tag, lock_time, sequence)).collect()
    }

    fn synthetic_block(
        previous: &Header,
        height: BlockHeight,
        transactions: alloc::vec::Vec<Transaction>,
    ) -> Block<Unchecked> {
        Block::new_unchecked(
            Header {
                version: Version::from_consensus(4),
                prev_blockhash: previous.block_hash(),
                merkle_root: compute_merkle_root(&transactions).expect("transactions are nonempty"),
                time: BlockTime::from_u32(1_700_000_000 + height.to_u32() * 60),
                bits: previous.bits,
                nonce: 0,
                auxpow: None,
            },
            transactions,
        )
    }

    #[cfg(feature = "tidecoin-node-validation")]
    fn synthetic_witness_block_with_spend_witness(
        previous: &Header,
        height: BlockHeight,
        spend_witness: alloc::vec::Vec<u8>,
    ) -> Block<Unchecked> {
        const RESERVED_VALUE: [u8; 32] = [0; 32];

        let mut coinbase = coinbase_tx(height.to_u32() as u8);
        coinbase.inputs[0].witness.push(RESERVED_VALUE);

        let mut spend = spend_tx(2, absolute::LockTime::ZERO, Sequence::MAX);
        spend.inputs[0].witness.push(spend_witness);

        let placeholder = synthetic_block(previous, height, vec![coinbase.clone(), spend.clone()]);
        let (_, commitment) = placeholder
            .compute_witness_commitment(&RESERVED_VALUE)
            .expect("synthetic witness block has a witness root");

        let mut commitment_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment_script.extend_from_slice(&commitment.to_byte_array());
        coinbase.outputs[0].script_pubkey = ScriptPubKeyBuf::from_bytes(commitment_script);

        synthetic_block(previous, height, vec![coinbase, spend])
    }

    #[cfg(feature = "tidecoin-node-validation")]
    fn synthetic_witness_block(previous: &Header, height: BlockHeight) -> Block<Unchecked> {
        synthetic_witness_block_with_spend_witness(previous, height, vec![0x42])
    }

    #[cfg(feature = "tidecoin-node-validation")]
    fn with_bad_witness_reserved_value(block: Block<Unchecked>) -> Block<Unchecked> {
        let (header, mut transactions) = block.into_parts();
        transactions[0].inputs[0].witness.clear();
        transactions[0].inputs[0].witness.push([1; 32]);
        Block::new_unchecked(header, transactions)
    }

    fn contextual_block_options() -> ContextualHeaderCheck {
        ContextualHeaderCheck { check_proof: false, current_time: None }
    }

    #[cfg(feature = "tidecoin-node-validation")]
    fn node_harness_available() -> bool {
        match TidecoinNodeHarness::from_env() {
            Ok(_) => true,
            Err(err) => {
                std::eprintln!("skipping Tidecoin node-backed block validation test: {err}");
                false
            }
        }
    }

    #[cfg(feature = "tidecoin-node-validation")]
    macro_rules! require_node_harness {
        () => {
            if !node_harness_available() {
                return;
            }
        };
    }

    #[cfg(feature = "tidecoin-node-validation")]
    fn encode_consensus_hex<T: encoding::Encodable + ?Sized>(value: &T) -> alloc::string::String {
        encoding::encode_to_vec(value).to_lower_hex_string()
    }

    #[test]
    fn real_testnet_contextual_header_accepts_activation_boundary() {
        let headers = headers_from_window("activation");
        let previous_height = BlockHeight::from_u32(999);
        let previous = header_at(&headers, previous_height);
        let candidate = header_at(&headers, BlockHeight::from_u32(1000));

        contextual_check_block_header(
            Params::TESTNET,
            &previous,
            previous_height,
            &candidate,
            |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
        )
        .expect("real testnet activation header should validate");
    }

    #[test]
    fn real_testnet_contextual_header_accepts_auxpow_header() {
        let headers = headers_from_window("first_auxpow");
        let previous_height = BlockHeight::from_u32(1100);
        let previous = header_at(&headers, previous_height);
        let candidate = header_at(&headers, BlockHeight::from_u32(1101));

        contextual_check_block_header(
            Params::TESTNET,
            &previous,
            previous_height,
            &candidate,
            |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
        )
        .expect("real testnet AuxPoW header should validate");
    }

    #[test]
    fn real_testnet_contextual_header_windows_validate_contiguously() {
        for window in retarget_windows() {
            let name = window["name"].as_str().expect("retarget window name");
            let start = window["start_height"].as_u64().expect("retarget window start") as u32;
            let end = window["end_height"].as_u64().expect("retarget window end") as u32;
            let first_checked_candidate = window["first_checked_candidate_height"]
                .as_u64()
                .map(|height| height as u32)
                .unwrap_or(start + 1);
            let headers = window["headers"]
                .as_array()
                .expect("retarget window headers")
                .iter()
                .map(|case| {
                    let height =
                        BlockHeight::from_u32(case["height"].as_u64().expect("height") as u32);
                    (height, header_from_fixture(case))
                })
                .collect::<alloc::vec::Vec<_>>();

            let mut checked = 0usize;
            for candidate_height in first_checked_candidate..=end {
                let current_height = candidate_height - 1;
                let previous_height = BlockHeight::from_u32(current_height);
                let previous = header_at(&headers, previous_height);
                let candidate = header_at(&headers, BlockHeight::from_u32(candidate_height));

                let result = contextual_check_block_header(
                    Params::TESTNET,
                    &previous,
                    previous_height,
                    &candidate,
                    |height| -> Result<Header, BlockHeight> {
                        headers
                            .iter()
                            .find_map(|(candidate_height, header)| {
                                (*candidate_height == height).then(|| header.clone())
                            })
                            .ok_or(height)
                    },
                );
                if let Err(err) = result {
                    panic!("{name} contextual header at height {candidate_height}: {err}");
                }
                checked += 1;
            }

            assert!(checked > 0, "{name} should contain at least one checkable header");
        }
    }

    #[test]
    fn contextual_header_rejects_bad_diffbits() {
        let headers = headers_from_window("first_auxpow");
        let previous_height = BlockHeight::from_u32(1101);
        let previous = header_at(&headers, previous_height);
        let mut candidate = header_at(&headers, BlockHeight::from_u32(1102));
        candidate.bits = previous.bits;

        let err = contextual_check_block_header_with_options(
            Params::TESTNET,
            &previous,
            previous_height,
            &candidate,
            |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
            ContextualHeaderCheck { check_proof: false, current_time: None },
        )
        .expect_err("bad nBits should fail");

        assert!(matches!(err, ContextualHeaderError::BadDiffBits { .. }));
    }

    #[test]
    fn contextual_header_rejects_prev_hash_mismatch() {
        let headers = headers_from_window("first_auxpow");
        let previous_height = BlockHeight::from_u32(1100);
        let previous = header_at(&headers, previous_height);
        let mut candidate = header_at(&headers, BlockHeight::from_u32(1101));
        candidate.prev_blockhash = BlockHash::from_byte_array([1; 32]);

        let err = contextual_check_block_header_with_options(
            Params::TESTNET,
            &previous,
            previous_height,
            &candidate,
            |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
            ContextualHeaderCheck { check_proof: false, current_time: None },
        )
        .expect_err("bad prev hash should fail");

        assert!(matches!(err, ContextualHeaderError::PrevBlockHash { .. }));
    }

    #[test]
    fn contextual_header_rejects_time_equal_to_previous_mtp() {
        let headers = headers_from_window("first_auxpow");
        let previous_height = BlockHeight::from_u32(1101);
        let previous = header_at(&headers, previous_height);
        let mut candidate = header_at(&headers, BlockHeight::from_u32(1102));
        let mtp = median_time_past(&previous, previous_height, &mut |height| -> Result<
            Header,
            Infallible,
        > {
            Ok(header_at(&headers, height))
        })
        .expect("fixture has MTP history");
        candidate.time = BlockTime::from_u32(mtp.to_u32());

        let err = contextual_check_block_header_with_options(
            Params::TESTNET,
            &previous,
            previous_height,
            &candidate,
            |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
            ContextualHeaderCheck { check_proof: false, current_time: None },
        )
        .expect_err("time equal to previous MTP should fail");

        assert!(matches!(err, ContextualHeaderError::TimeTooOld { .. }));
    }

    #[test]
    fn synthetic_contextual_block_accepts_final_bip34_block() {
        let headers = synthetic_context_headers();
        let previous_height = BlockHeight::from_u32(10);
        let height = BlockHeight::from_u32(11);
        let previous = header_at(&headers, previous_height);
        let block = synthetic_block(&previous, height, vec![coinbase_tx(11)]);

        contextual_check_block_with_options(
            Params::REGTEST,
            &previous,
            previous_height,
            &block,
            |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
            contextual_block_options(),
        )
        .expect("synthetic final BIP34 block should validate");
    }

    #[test]
    fn synthetic_contextual_block_rejects_nonfinal_transaction() {
        let headers = synthetic_context_headers();
        let previous_height = BlockHeight::from_u32(10);
        let height = BlockHeight::from_u32(11);
        let previous = header_at(&headers, previous_height);
        let lock_time = absolute::LockTime::from_height(height.to_u32()).expect("height locktime");
        let block = synthetic_block(
            &previous,
            height,
            vec![coinbase_tx(11), spend_tx(1, lock_time, Sequence::ZERO)],
        );

        let err = contextual_check_block_with_options(
            Params::REGTEST,
            &previous,
            previous_height,
            &block,
            |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
            contextual_block_options(),
        )
        .expect_err("block with non-final transaction should fail");

        assert!(matches!(err, ContextualBlockError::NonFinalTransaction { index: 1 }));
    }

    #[test]
    fn synthetic_contextual_block_rejects_bad_coinbase_height() {
        let headers = synthetic_context_headers();
        let previous_height = BlockHeight::from_u32(10);
        let height = BlockHeight::from_u32(11);
        let previous = header_at(&headers, previous_height);
        let block = synthetic_block(&previous, height, vec![coinbase_tx(10)]);

        let err = contextual_check_block_with_options(
            Params::REGTEST,
            &previous,
            previous_height,
            &block,
            |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
            contextual_block_options(),
        )
        .expect_err("block with mismatched coinbase height should fail");

        assert!(matches!(
            err,
            ContextualBlockError::BadCoinbaseHeight {
                expected,
                actual: 10,
            } if expected == height
        ));
    }

    #[cfg(feature = "tidecoin-node-validation")]
    #[test]
    fn contextual_block_finality_and_bip34_match_node_bridge() {
        require_node_harness!();

        let headers = synthetic_context_headers();
        let previous_height = BlockHeight::from_u32(10);
        let height = BlockHeight::from_u32(11);
        let previous = header_at(&headers, previous_height);
        let previous_mtp = median_time_past(&previous, previous_height, &mut |height| -> Result<
            Header,
            Infallible,
        > {
            Ok(header_at(&headers, height))
        })
        .expect("synthetic headers have MTP history");
        let lock_time = absolute::LockTime::from_height(height.to_u32()).expect("height locktime");
        let mut large_final_transactions = vec![coinbase_tx(11)];
        large_final_transactions.extend(spend_txs(1..=64, absolute::LockTime::ZERO, Sequence::MAX));
        let mut large_nonfinal_transactions = vec![coinbase_tx(11)];
        large_nonfinal_transactions.extend(spend_txs(
            1..=63,
            absolute::LockTime::ZERO,
            Sequence::MAX,
        ));
        large_nonfinal_transactions.push(spend_tx(64, lock_time, Sequence::ZERO));

        let cases = [
            ("valid", synthetic_block(&previous, height, vec![coinbase_tx(11)]), true),
            ("large_final", synthetic_block(&previous, height, large_final_transactions), true),
            (
                "nonfinal",
                synthetic_block(
                    &previous,
                    height,
                    vec![coinbase_tx(11), spend_tx(1, lock_time, Sequence::ZERO)],
                ),
                false,
            ),
            (
                "bad_coinbase_height",
                synthetic_block(&previous, height, vec![coinbase_tx(10)]),
                false,
            ),
            (
                "large_nonfinal",
                synthetic_block(&previous, height, large_nonfinal_transactions),
                false,
            ),
        ];

        let harness = TidecoinNodeHarness::from_env().expect("TidecoinNodeHarness::from_env");
        for (name, block, expected_valid) in cases {
            let block_hex = encode_consensus_hex(&block);
            let node_valid = harness
                .check_contextual_block_hex(
                    &block_hex,
                    2,
                    height.to_u32() as i32,
                    previous_mtp.to_u32().into(),
                    true,
                    true,
                )
                .is_ok();
            let rust_valid = contextual_check_block_with_options(
                Params::REGTEST,
                &previous,
                previous_height,
                &block,
                |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
                contextual_block_options(),
            )
            .is_ok();

            assert_eq!(node_valid, expected_valid, "{name} node contextual block");
            assert_eq!(rust_valid, expected_valid, "{name} Rust contextual block");
        }
    }

    #[cfg(feature = "tidecoin-node-validation")]
    #[test]
    fn contextual_block_witness_and_weight_match_node_bridge() {
        require_node_harness!();

        let headers = synthetic_context_headers();
        let previous_height = BlockHeight::from_u32(10);
        let height = BlockHeight::from_u32(11);
        let previous = header_at(&headers, previous_height);
        let previous_mtp = median_time_past(&previous, previous_height, &mut |height| -> Result<
            Header,
            Infallible,
        > {
            Ok(header_at(&headers, height))
        })
        .expect("synthetic headers have MTP history");

        let valid_witness = synthetic_witness_block(&previous, height);
        let bad_witness_commitment =
            with_bad_witness_reserved_value(synthetic_witness_block(&previous, height));
        let overweight_witness = synthetic_witness_block_with_spend_witness(
            &previous,
            height,
            vec![0x42; Weight::MAX_BLOCK.to_wu() as usize],
        );
        let (_, overweight_transactions) = overweight_witness.as_parts();
        assert!(
            overweight_transactions[1].inputs[0].witness.size()
                > Weight::MAX_BLOCK.to_wu() as usize,
            "synthetic overweight witness item was not retained: got {}",
            overweight_transactions[1].inputs[0].witness.size()
        );
        assert!(
            overweight_witness.weight().to_wu() > Weight::MAX_BLOCK.to_wu(),
            "synthetic overweight fixture must exceed the block limit: got {}, max {}",
            overweight_witness.weight().to_wu(),
            Weight::MAX_BLOCK.to_wu()
        );

        let cases = [
            ("valid_witness", valid_witness, true),
            ("bad_witness_commitment", bad_witness_commitment, false),
            ("overweight_witness", overweight_witness, false),
        ];

        let harness = TidecoinNodeHarness::from_env().expect("TidecoinNodeHarness::from_env");
        for (name, block, expected_contextual_valid) in cases {
            let block_hex = encode_consensus_hex(&block);
            assert!(
                harness.check_block_hex(&block_hex, 2, false, true).is_ok(),
                "{name} should pass node CheckBlock before contextual witness checks"
            );
            assert!(
                crate::block::check_block_sanity(&block).is_ok(),
                "{name} should pass Rust CheckBlock-style sanity before contextual witness checks"
            );

            let node_valid = harness
                .check_contextual_block_hex(
                    &block_hex,
                    2,
                    height.to_u32() as i32,
                    previous_mtp.to_u32().into(),
                    true,
                    true,
                )
                .is_ok();
            let rust_valid = contextual_check_block_with_options(
                Params::REGTEST,
                &previous,
                previous_height,
                &block,
                |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
                contextual_block_options(),
            )
            .is_ok();

            assert_eq!(node_valid, expected_contextual_valid, "{name} node contextual block");
            assert_eq!(rust_valid, expected_contextual_valid, "{name} Rust contextual block");
        }
    }

    #[cfg(feature = "tidecoin-node-validation")]
    #[test]
    fn contextual_block_pre_activation_witness_matches_node_bridge() {
        require_node_harness!();

        let headers = synthetic_context_headers();
        let previous_height = BlockHeight::from_u32(10);
        let height = BlockHeight::from_u32(11);
        let previous = header_at(&headers, previous_height);
        let previous_mtp = median_time_past(&previous, previous_height, &mut |height| -> Result<
            Header,
            Infallible,
        > {
            Ok(header_at(&headers, height))
        })
        .expect("synthetic headers have MTP history");

        let block = synthetic_witness_block(&previous, height);
        let mut pre_segwit_params = Params::REGTEST;
        pre_segwit_params.segwit_height = BlockHeight::from_u32(height.to_u32() + 1);

        let block_hex = encode_consensus_hex(&block);
        let harness = TidecoinNodeHarness::from_env().expect("TidecoinNodeHarness::from_env");
        let node_valid = harness
            .check_contextual_block_hex(
                &block_hex,
                2,
                height.to_u32() as i32,
                previous_mtp.to_u32().into(),
                true,
                false,
            )
            .is_ok();
        let rust_valid = contextual_check_block_with_options(
            pre_segwit_params,
            &previous,
            previous_height,
            &block,
            |height| -> Result<Header, Infallible> { Ok(header_at(&headers, height)) },
            contextual_block_options(),
        )
        .is_ok();

        assert!(!node_valid, "node should reject pre-activation witness");
        assert!(!rust_valid, "Rust should reject pre-activation witness");
    }
}
