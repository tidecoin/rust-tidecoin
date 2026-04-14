// SPDX-License-Identifier: CC0-1.0

//! Tidecoin relay and standardness policy helpers.
//!
//! This module exposes policy constants and helpers mirrored from the Tidecoin node. These are not
//! consensus rules and may change as node policy evolves.

use core::cmp;
use core::fmt;

use consensus_core::{
    VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_CLEANSTACK,
    VERIFY_CONST_SCRIPTCODE, VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, VERIFY_MINIMALDATA, VERIFY_MINIMALIF,
    VERIFY_NULLDUMMY, VERIFY_NULLFAIL, VERIFY_P2SH, VERIFY_PQ_STRICT, VERIFY_SHA512,
    VERIFY_WITNESS, VERIFY_WITNESS_V1_512,
};
use encoding::CompactSizeEncoder;

use super::constants::{MAX_BLOCK_SIGOPS_COST, WITNESS_SCALE_FACTOR};
use crate::network::Params;
use crate::script::{
    Instruction, ScriptExt as _, ScriptPubKey, ScriptPubKeyExt as _, ScriptSigExt as _,
};
use crate::transaction::{
    check_transaction_sanity, InputWeightPrediction, OutPoint, Transaction, TransactionExt,
    TransactionSanityError, TxOut, Version,
};
use crate::{Amount, BlockHeight, FeeRate, PqPublicKey, Witness, WitnessVersion};

/// Maximum weight of a transaction for it to be relayed by most nodes on the network.
pub const MAX_STANDARD_TX_WEIGHT: u32 = 800_000;

/// Minimum non-witness size for a standard transaction, set to 65 bytes.
pub const MIN_STANDARD_TX_NONWITNESS_SIZE: u32 = 65;

/// Maximum number of sigops in an IsStandard() P2SH script.
pub const MAX_P2SH_SIGOPS: usize = 15;

/// The maximum number of sigops we're willing to relay/mine in a single tx.
pub const MAX_STANDARD_TX_SIGOPS_COST: u32 = MAX_BLOCK_SIGOPS_COST as u32 / 5;

/// The maximum number of potentially executed legacy signature operations in a single standard tx.
pub const MAX_TX_LEGACY_SIGOPS: usize = 2_500;

/// The minimum incremental *feerate* (despite the name), in sats per virtual kilobyte for RBF.
pub const DEFAULT_INCREMENTAL_RELAY_FEE: u32 = 100;

/// The number of bytes equivalent per signature operation. Affects transaction relay through the
/// virtual size computation.
pub const DEFAULT_BYTES_PER_SIGOP: u32 = 20;

/// Default for `permit_bare_multisig`.
pub const DEFAULT_PERMIT_BAREMULTISIG: bool = false;

/// The maximum number of witness stack items in a standard P2WSH or P2WSH-512 script.
pub const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;

/// The maximum size in bytes of each witness stack item in a standard P2WSH or P2WSH-512 script.
pub const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 5_000;

/// The maximum size in bytes of a standard witness script.
pub const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 65_536;

/// The maximum size of a standard scriptSig.
pub const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 8_192;

/// Min feerate for defining dust.
pub const DUST_RELAY_TX_FEE: u32 = 3_000;

/// Default minimum relay fee.
pub const DEFAULT_MIN_RELAY_TX_FEE: u32 = 100;

/// Default transaction version range accepted by node policy.
pub const TX_MIN_STANDARD_VERSION: Version = Version::ONE;
/// Default transaction version range accepted by node policy.
pub const TX_MAX_STANDARD_VERSION: Version = Version::THREE;

/// Tidecoin node TRUC transaction version.
pub const TRUC_VERSION: Version = Version::THREE;
/// Maximum sigop-adjusted virtual size for a stateless TRUC transaction.
pub const TRUC_MAX_VSIZE: i64 = 10_000;
/// Maximum sigop-adjusted virtual size for a TRUC child spending unconfirmed TRUC parents.
///
/// This requires mempool ancestor state and is exposed for higher validation layers.
pub const TRUC_CHILD_MAX_VSIZE: i64 = 4_000;

/// Maximum number of ephemeral dust outputs permitted in a standard transaction.
pub const MAX_DUST_OUTPUTS_PER_TX: usize = 1;

pub(crate) const MAX_OP_RETURN_RELAY: usize =
    MAX_STANDARD_TX_WEIGHT as usize / WITNESS_SCALE_FACTOR;

/// Mandatory script verification flags used by Tidecoin node relay policy.
pub const MANDATORY_SCRIPT_VERIFY_FLAGS: u32 = VERIFY_P2SH
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS;

/// Standard script verification flags used by Tidecoin node relay policy before AuxPoW PQ flags.
pub const STANDARD_SCRIPT_VERIFY_FLAGS: u32 = MANDATORY_SCRIPT_VERIFY_FLAGS
    | VERIFY_MINIMALDATA
    | VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    | VERIFY_CLEANSTACK
    | VERIFY_MINIMALIF
    | VERIFY_NULLFAIL
    | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | VERIFY_CONST_SCRIPTCODE;

/// Standard but not mandatory script verification flags used by Tidecoin node relay policy.
pub const STANDARD_NOT_MANDATORY_VERIFY_FLAGS: u32 =
    STANDARD_SCRIPT_VERIFY_FLAGS & !MANDATORY_SCRIPT_VERIFY_FLAGS;

/// Returns the Tidecoin node's standard policy script flags for the next block height.
pub fn standard_policy_script_flags(
    params: impl AsRef<Params>,
    next_block_height: BlockHeight,
) -> u32 {
    let mut flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    if params.as_ref().auxpow_start_height.is_some_and(|height| next_block_height >= height) {
        flags |= VERIFY_PQ_STRICT | VERIFY_WITNESS_V1_512 | VERIFY_SHA512;
    }
    flags
}

/// Standard transaction policy error reasons, mirroring Tidecoin node strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StandardTxError {
    /// Transaction version is outside the standard relay range.
    Version,
    /// Transaction weight exceeds the standard relay limit.
    TxSize,
    /// An input scriptSig is too large.
    ScriptSigSize,
    /// An input scriptSig contains non-push opcodes.
    ScriptSigNotPushOnly,
    /// An output scriptPubKey is not a standard Tidecoin form.
    ScriptPubKey,
    /// Total OP_RETURN payload exceeds the standard data-carrier budget.
    DataCarrier,
    /// Bare multisig output is rejected by policy.
    BareMultisig,
    /// Transaction contains too many dust outputs.
    Dust,
}

/// Standard relay-precheck policy configuration mirrored from Tidecoin node defaults.
///
/// This covers only stateless and caller-supplied-UTXO standard relay prechecks. It does not model
/// dynamic mempool policy such as fee admission, conflicts, package limits, RBF, or package
/// ephemeral-dust spending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardRelayPrecheckPolicy {
    /// Maximum OP_RETURN scriptPubKey bytes allowed across null-data outputs.
    pub max_datacarrier_bytes: Option<usize>,
    /// Whether bare multisig outputs are accepted by relay policy.
    pub permit_bare_multisig: bool,
    /// Dust relay feerate used for dust threshold calculation.
    pub dust_relay_fee: FeeRate,
}

impl StandardRelayPrecheckPolicy {
    /// Tidecoin node default standard relay-precheck policy.
    pub const DEFAULT: Self = Self {
        max_datacarrier_bytes: Some(MAX_OP_RETURN_RELAY),
        permit_bare_multisig: DEFAULT_PERMIT_BAREMULTISIG,
        dust_relay_fee: FeeRate::DUST,
    };
}

impl Default for StandardRelayPrecheckPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Error returned by [`check_standard_relay_prechecks`].
///
/// These errors mirror the node's standard relay-policy reason strings where this stateless helper
/// overlaps with the node mempool pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StandardRelayPrecheckError {
    /// Context-free transaction sanity failed before policy checks.
    TransactionSanity(TransactionSanityError),
    /// Coinbase transactions are only valid inside blocks, not as loose relay transactions.
    Coinbase,
    /// Transaction-local `IsStandardTx` policy failed.
    StandardTx(StandardTxError),
    /// Witness version 1 outputs are not standard before AuxPoW activation.
    WitnessV1PreAuxpow,
    /// Non-witness serialized transaction size is below the node relay floor.
    TxSizeSmall,
    /// UTXO-aware non-witness input standardness failed.
    InputsNotStandard,
    /// UTXO-aware witness standardness failed.
    WitnessNotStandard,
    /// Standard transaction sigop cost exceeds the node relay limit.
    TooManySigops {
        /// Computed sigop cost.
        cost: usize,
    },
    /// TRUC transaction sigop-adjusted virtual size exceeds the stateless node limit.
    TrucTxSize {
        /// Computed sigop-adjusted virtual size.
        vsize: i64,
    },
}

impl StandardRelayPrecheckError {
    /// Returns the Tidecoin node-compatible reason string for this policy failure.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::TransactionSanity(_) => "transaction-sanity",
            Self::Coinbase => "coinbase",
            Self::StandardTx(err) => err.reason(),
            Self::WitnessV1PreAuxpow => "witness-v1-pre-auxpow",
            Self::TxSizeSmall => "tx-size-small",
            Self::InputsNotStandard => "bad-txns-nonstandard-inputs",
            Self::WitnessNotStandard => "bad-witness-nonstandard",
            Self::TooManySigops { .. } => "bad-txns-too-many-sigops",
            Self::TrucTxSize { .. } => "TRUC-violation",
        }
    }
}

impl From<TransactionSanityError> for StandardRelayPrecheckError {
    fn from(err: TransactionSanityError) -> Self {
        Self::TransactionSanity(err)
    }
}

impl From<StandardTxError> for StandardRelayPrecheckError {
    fn from(err: StandardTxError) -> Self {
        Self::StandardTx(err)
    }
}

impl fmt::Display for StandardRelayPrecheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransactionSanity(err) => {
                write!(f, "{}: {err}", self.reason())
            }
            Self::TooManySigops { cost } => {
                write!(f, "{}: {} exceeds {}", self.reason(), cost, MAX_STANDARD_TX_SIGOPS_COST)
            }
            Self::TrucTxSize { vsize } => {
                write!(
                    f,
                    "{}: version=3 tx is too big: {} > {}",
                    self.reason(),
                    vsize,
                    TRUC_MAX_VSIZE
                )
            }
            _ => f.write_str(self.reason()),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StandardRelayPrecheckError {}

impl StandardTxError {
    /// Returns the Tidecoin node-compatible reason string.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::TxSize => "tx-size",
            Self::ScriptSigSize => "scriptsig-size",
            Self::ScriptSigNotPushOnly => "scriptsig-not-pushonly",
            Self::ScriptPubKey => "scriptpubkey",
            Self::DataCarrier => "datacarrier",
            Self::BareMultisig => "bare-multisig",
            Self::Dust => "dust",
        }
    }
}

impl fmt::Display for StandardTxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StandardTxError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandardScriptType {
    NullData,
    Multisig,
    Standard,
}

pub(crate) fn dust_threshold(
    script_pubkey: &ScriptPubKey,
    dust_relay_fee: FeeRate,
) -> Option<Amount> {
    if script_pubkey.is_op_return() {
        return Amount::from_sat(0).ok();
    }

    let mut size = 8usize
        .checked_add(CompactSizeEncoder::encoded_size(script_pubkey.len()))?
        .checked_add(script_pubkey.len())?;

    if script_pubkey.is_witness_program() {
        let witness_cost = if script_pubkey.is_p2wpkh() {
            InputWeightPrediction::MAX_KNOWN_PQ_P2WPKH.witness_stack_size() / WITNESS_SCALE_FACTOR
        } else {
            InputWeightPrediction::MAX_KNOWN_PQ_WITNESS_SCRIPT_KEY_SPEND.witness_stack_size()
                / WITNESS_SCALE_FACTOR
        };
        size = size.checked_add(32 + 4 + 1 + witness_cost + 4)?;
    } else {
        let script_sig_size = InputWeightPrediction::MAX_KNOWN_PQ_NON_WITNESS_DUST_SCRIPT_SIG_SIZE;
        size = size.checked_add(32 + 4 + script_sig_size + 4)?;
    }

    Amount::from_sat((dust_relay_fee.to_sat_per_kvb_ceil()).checked_mul(size as u64)? / 1000).ok()
}

fn classify_multisig(script_pubkey: &ScriptPubKey) -> Option<(u8, u8)> {
    let mut instructions = script_pubkey.instructions();
    let required_sigs = match instructions.next()? {
        Ok(Instruction::Op(op)) => op.decode_pushnum()?,
        _ => return None,
    };

    let mut num_pubkeys = 0u8;
    loop {
        match instructions.next()? {
            Ok(Instruction::PushBytes(pubkey))
                if PqPublicKey::from_prefixed_slice(pubkey.as_bytes()).is_ok() =>
            {
                num_pubkeys = num_pubkeys.saturating_add(1);
            }
            Ok(Instruction::PushBytes(_)) => return None,
            Ok(Instruction::Op(op)) => {
                if op.decode_pushnum()? != num_pubkeys {
                    return None;
                }
                break;
            }
            Err(_) => return None,
        }
    }

    match instructions.next() {
        Some(Ok(Instruction::Op(op))) if op == crate::opcodes::all::OP_CHECKMULTISIG => {}
        _ => return None,
    }

    instructions.next().is_none().then_some((required_sigs, num_pubkeys))
}

fn is_p2pk(script_pubkey: &ScriptPubKey) -> bool {
    let mut instructions = script_pubkey.instructions();
    matches!(
        (instructions.next(), instructions.next(), instructions.next()),
        (Some(Ok(Instruction::PushBytes(pubkey))), Some(Ok(Instruction::Op(op))), None)
            if op == crate::opcodes::all::OP_CHECKSIG
                && PqPublicKey::from_prefixed_slice(pubkey.as_bytes()).is_ok()
    )
}

fn is_standard_null_data(script_pubkey: &ScriptPubKey) -> bool {
    if !script_pubkey.is_op_return() {
        return false;
    }

    let mut instructions = script_pubkey.instructions();
    match instructions.next() {
        Some(Ok(Instruction::Op(op))) if op == crate::opcodes::all::OP_RETURN => {}
        _ => return false,
    }

    instructions.all(|instruction| matches!(instruction, Ok(Instruction::PushBytes(_))))
}

fn classify_standard_script(script_pubkey: &ScriptPubKey) -> Option<StandardScriptType> {
    if script_pubkey.is_p2pkh()
        || script_pubkey.is_p2sh()
        || is_p2pk(script_pubkey)
        || script_pubkey.is_p2wpkh()
        || script_pubkey.is_p2wsh()
        || script_pubkey.is_p2wsh512()
    {
        return Some(StandardScriptType::Standard);
    }

    if let Some((m, n)) = classify_multisig(script_pubkey) {
        if (1..=3).contains(&n) && (1..=n).contains(&m) {
            return Some(StandardScriptType::Multisig);
        }
        return None;
    }

    if is_standard_null_data(script_pubkey) {
        return Some(StandardScriptType::NullData);
    }

    None
}

fn count_legacy_sigops_for_input(
    prevout: &TxOut,
    txin_script_sig: &crate::script::ScriptSig,
) -> usize {
    if prevout.script_pubkey.is_p2sh() {
        txin_script_sig.redeem_script().map(|redeem| redeem.count_sigops()).unwrap_or(0)
    } else {
        prevout.script_pubkey.count_sigops()
    }
}

/// Returns whether all outputs in the transaction are standard under Tidecoin policy.
pub fn is_standard_tx(
    tx: &Transaction,
    max_datacarrier_bytes: Option<usize>,
    permit_bare_multisig: bool,
    dust_relay_fee: FeeRate,
) -> Result<(), StandardTxError> {
    if tx.version.to_u32() < TX_MIN_STANDARD_VERSION.to_u32()
        || tx.version.to_u32() > TX_MAX_STANDARD_VERSION.to_u32()
    {
        return Err(StandardTxError::Version);
    }

    if tx.weight().to_wu() > MAX_STANDARD_TX_WEIGHT as u64 {
        return Err(StandardTxError::TxSize);
    }

    for txin in &tx.inputs {
        if txin.script_sig.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(StandardTxError::ScriptSigSize);
        }
        if !txin.script_sig.is_push_only() {
            return Err(StandardTxError::ScriptSigNotPushOnly);
        }
    }

    let mut datacarrier_bytes_left = max_datacarrier_bytes.unwrap_or(0);
    for txout in &tx.outputs {
        match classify_standard_script(&txout.script_pubkey) {
            Some(StandardScriptType::Standard) => {}
            Some(StandardScriptType::NullData) => {
                let size = txout.script_pubkey.len();
                if size > datacarrier_bytes_left {
                    return Err(StandardTxError::DataCarrier);
                }
                datacarrier_bytes_left -= size;
            }
            Some(StandardScriptType::Multisig) => {
                if !permit_bare_multisig {
                    return Err(StandardTxError::BareMultisig);
                }
            }
            None => return Err(StandardTxError::ScriptPubKey),
        }
    }

    let dust_outputs = tx
        .outputs
        .iter()
        .filter(|txout| {
            txout
                .script_pubkey
                .minimal_non_dust_custom(dust_relay_fee)
                .is_some_and(|min| txout.amount < min)
        })
        .count();
    if dust_outputs > MAX_DUST_OUTPUTS_PER_TX {
        return Err(StandardTxError::Dust);
    }

    Ok(())
}

/// Checks the standard-relay precheck subset of the Tidecoin node mempool path.
///
/// This deliberately mirrors the part of `MemPoolAccept::PreChecks` that can be evaluated from a
/// transaction, chain parameters, the next block height, and supplied spent outputs:
///
/// - context-free transaction sanity and loose-transaction coinbase rejection,
/// - `IsStandardTx`,
/// - pre-AuxPoW witness-v1 output policy,
/// - minimum non-witness transaction size,
/// - `AreInputsStandard`,
/// - `IsWitnessStandard`,
/// - standard transaction sigop-cost limit.
/// - stateless TRUC transaction virtual-size limit.
///
/// It does **not** perform full mempool acceptance. Fee admission, conflicts, RBF, ancestor and
/// descendant limits, package ephemeral-dust spending, input existence, coinbase maturity, and
/// `CheckTxInputs`-style value checks require mempool/UTXO state and belong to a higher validation
/// layer.
pub fn check_standard_relay_prechecks<S>(
    tx: &Transaction,
    params: impl AsRef<Params>,
    next_block_height: BlockHeight,
    spent: S,
    policy: StandardRelayPrecheckPolicy,
) -> Result<(), StandardRelayPrecheckError>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    check_transaction_sanity(tx)?;

    if tx.is_coinbase() {
        return Err(StandardRelayPrecheckError::Coinbase);
    }

    is_standard_tx(
        tx,
        policy.max_datacarrier_bytes,
        policy.permit_bare_multisig,
        policy.dust_relay_fee,
    )?;

    let params = params.as_ref();
    let witness_v1_allowed =
        params.auxpow_start_height.is_some_and(|height| next_block_height >= height);
    if !witness_v1_allowed
        && tx
            .outputs
            .iter()
            .any(|txout| txout.script_pubkey.witness_version() == Some(WitnessVersion::V1))
    {
        return Err(StandardRelayPrecheckError::WitnessV1PreAuxpow);
    }

    if tx.base_size() < MIN_STANDARD_TX_NONWITNESS_SIZE as usize {
        return Err(StandardRelayPrecheckError::TxSizeSmall);
    }

    let mut spent = spent;
    if !are_inputs_standard(tx, &mut spent) {
        return Err(StandardRelayPrecheckError::InputsNotStandard);
    }

    if tx.inputs.iter().any(|input| !input.witness.is_empty())
        && !is_witness_standard(tx, &mut spent)
    {
        return Err(StandardRelayPrecheckError::WitnessNotStandard);
    }

    let sigop_cost = tx.total_sigop_cost(&mut spent);
    if sigop_cost > MAX_STANDARD_TX_SIGOPS_COST as usize {
        return Err(StandardRelayPrecheckError::TooManySigops { cost: sigop_cost });
    }

    if tx.version == TRUC_VERSION {
        let vsize = get_virtual_tx_size(tx.weight().to_wu() as i64, sigop_cost as i64);
        if vsize > TRUC_MAX_VSIZE {
            return Err(StandardRelayPrecheckError::TrucTxSize { vsize });
        }
    }

    Ok(())
}

/// Checks whether all non-witness inputs are standard under Tidecoin policy.
pub fn are_inputs_standard<S>(tx: &Transaction, mut spent: S) -> bool
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    if tx.is_coinbase() {
        return true;
    }

    let mut sigops = 0usize;
    for txin in &tx.inputs {
        let Some(prevout) = spent(&txin.previous_output) else {
            return false;
        };
        sigops = sigops.saturating_add(txin.script_sig.count_sigops());
        sigops = sigops.saturating_add(count_legacy_sigops_for_input(&prevout, &txin.script_sig));
        if sigops > MAX_TX_LEGACY_SIGOPS {
            return false;
        }

        if classify_standard_script(&prevout.script_pubkey).is_none() {
            return false;
        }

        if prevout.script_pubkey.is_p2sh() {
            let Some(redeem_script) = txin.script_sig.redeem_script() else {
                return false;
            };
            if redeem_script.count_sigops() > MAX_P2SH_SIGOPS {
                return false;
            }
        }
    }

    true
}

/// Checks whether all witness inputs obey Tidecoin node standardness limits.
pub fn is_witness_standard<S>(tx: &Transaction, mut spent: S) -> bool
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    if tx.is_coinbase() {
        return true;
    }

    for txin in &tx.inputs {
        if txin.witness.is_empty() {
            continue;
        }

        let Some(prevout) = spent(&txin.previous_output) else {
            return false;
        };

        let witness_ok = if prevout.script_pubkey.is_p2sh() {
            let Some(redeem_script) = txin.script_sig.redeem_script() else {
                return false;
            };
            witness_standard_for_program(redeem_script, &txin.witness)
        } else {
            witness_standard_for_program(&prevout.script_pubkey, &txin.witness)
        };

        if !witness_ok {
            return false;
        }
    }

    true
}

/// Returns whether the transaction spends any non-anchor witness program.
pub fn spends_non_anchor_witness_program<S>(tx: &Transaction, mut spent: S) -> bool
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    if tx.is_coinbase() {
        return false;
    }

    for txin in &tx.inputs {
        let Some(prevout) = spent(&txin.previous_output) else {
            continue;
        };

        if prevout.script_pubkey.witness_version() == Some(WitnessVersion::V0) {
            return true;
        }

        if prevout.script_pubkey.is_p2sh()
            && txin.script_sig.redeem_script().and_then(|redeem| redeem.witness_version())
                == Some(WitnessVersion::V0)
        {
            return true;
        }
    }

    false
}

/// The virtual transaction size, as computed by the Tidecoin node.
pub fn get_virtual_tx_size(weight: i64, n_sigops: i64) -> i64 {
    (cmp::max(weight, n_sigops * DEFAULT_BYTES_PER_SIGOP as i64) + WITNESS_SCALE_FACTOR as i64 - 1)
        / WITNESS_SCALE_FACTOR as i64
}

/// Returns the virtual size of a native PQ P2WPKH input for the provided signature and pubkey sizes.
pub fn pq_p2wpkh_input_vsize(sig_len: usize, pubkey_len: usize) -> i64 {
    let prediction = InputWeightPrediction::pq_p2wpkh_with_sizes(sig_len, pubkey_len);
    get_virtual_tx_size(prediction.total_weight().to_wu() as i64, 0)
}

/// Returns the virtual size of a P2SH-wrapped PQ P2WPKH input for the provided signature and pubkey sizes.
pub fn pq_p2sh_p2wpkh_input_vsize(sig_len: usize, pubkey_len: usize) -> i64 {
    let prediction = InputWeightPrediction::pq_nested_p2wpkh_with_sizes(sig_len, pubkey_len);
    get_virtual_tx_size(prediction.total_weight().to_wu() as i64, 0)
}

fn witness_standard_for_program<T: crate::script::ScriptHashableTag>(
    script: &crate::script::Script<T>,
    witness: &Witness,
) -> bool {
    if script.witness_version().is_none() {
        return false;
    }
    if script.is_p2wpkh() {
        return true;
    }
    if script.is_p2wsh() || script.is_p2wsh512() {
        let Some(witness_script) = witness.last() else {
            return false;
        };
        if witness_script.len() > MAX_STANDARD_P2WSH_SCRIPT_SIZE {
            return false;
        }
        let stack_items = witness.len().saturating_sub(1);
        if stack_items > MAX_STANDARD_P2WSH_STACK_ITEMS {
            return false;
        }
        if witness
            .iter()
            .take(stack_items)
            .any(|item| item.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
        {
            return false;
        }
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use hashes::{sha256, sha512};

    use super::*;
    use crate::blockdata::script::{Builder, PushBytesBuf, ScriptBufExt as _};
    use crate::crypto::pq::{PqScheme, PqSchemeCryptoExt as _};
    use crate::prelude::Vec;
    use crate::script::{RedeemScriptBuf, ScriptPubKeyBuf, ScriptSigBuf, WitnessScriptBuf};
    use crate::transaction::{Transaction, TxIn, TxOut, Txid};
    use crate::witness::Witness;
    use crate::{absolute, Address, Network, PubkeyHash, Sequence};

    fn prevout(script_pubkey: ScriptPubKeyBuf, amount_sat: u64) -> TxOut {
        TxOut { amount: Amount::from_sat(amount_sat).unwrap(), script_pubkey }
    }

    fn tx_with_single_input(script_sig: ScriptSigBuf, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([1; 32]), vout: 0 },
                script_sig,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs,
        }
    }

    fn witness_from_items(items: Vec<Vec<u8>>) -> Witness {
        Witness::from_slice(&items)
    }

    fn p2wsh_script_pubkey(witness_script: &WitnessScriptBuf) -> ScriptPubKeyBuf {
        ScriptPubKeyBuf::builder()
            .push_int_unchecked(0)
            .push_slice(sha256::Hash::hash(witness_script.as_bytes()).to_byte_array())
            .into_script()
    }

    fn p2wsh512_script_pubkey(witness_script: &WitnessScriptBuf) -> ScriptPubKeyBuf {
        ScriptPubKeyBuf::builder()
            .push_int_unchecked(1)
            .push_slice(sha512::Hash::hash(witness_script.as_bytes()).to_byte_array())
            .into_script()
    }

    fn p2sh_wrapped_witness_program_script_sig(witness_program: &ScriptPubKeyBuf) -> ScriptSigBuf {
        Builder::new()
            .push_slice(PushBytesBuf::try_from(witness_program.as_bytes().to_vec()).unwrap())
            .into_script()
    }

    fn tx_with_witness(script_sig: ScriptSigBuf, witness: Witness) -> Transaction {
        let mut tx =
            tx_with_single_input(script_sig, vec![prevout(ScriptPubKeyBuf::new(), 30_000)]);
        tx.inputs[0].witness = witness;
        tx
    }

    fn node_sized_witness_script(drop_count: usize) -> WitnessScriptBuf {
        let mut builder = Builder::new();
        for _ in 0..13 {
            builder = builder.push_slice(vec![1u8; MAX_STANDARD_P2WSH_STACK_ITEM_SIZE]);
        }
        builder = builder.push_slice(vec![1u8; 479]);
        for _ in 0..drop_count {
            builder = builder.push_opcode(crate::opcodes::all::OP_DROP);
        }
        builder.into_script()
    }

    fn assert_witness_standard_for_native_and_wrapped(
        witness_program: ScriptPubKeyBuf,
        witness: Witness,
        expected: bool,
    ) {
        let native_tx = tx_with_witness(ScriptSigBuf::new(), witness.clone());
        assert_eq!(
            is_witness_standard(&native_tx, |_| Some(prevout(witness_program.clone(), 1))),
            expected,
            "native witness program standardness mismatch"
        );

        let wrapped_tx =
            tx_with_witness(p2sh_wrapped_witness_program_script_sig(&witness_program), witness);
        assert_eq!(
            is_witness_standard(&wrapped_tx, |_| Some(prevout(
                witness_program.to_p2sh().unwrap(),
                1
            ))),
            expected,
            "P2SH-wrapped witness program standardness mismatch"
        );
    }

    fn deterministic_pubkey(scheme: PqScheme, tag: u8) -> crate::crypto::pq::PqPublicKey {
        let seed: Vec<u8> = (0..scheme.deterministic_seed_len())
            .map(|i| tag ^ (i as u8).wrapping_mul(131))
            .collect();
        scheme.generate_keypair_from_seed(&seed).unwrap().0
    }

    fn pq_p2pk_script() -> ScriptPubKeyBuf {
        let pubkey = deterministic_pubkey(PqScheme::MlDsa87, 0x87);
        ScriptPubKeyBuf::builder()
            .push_slice(PushBytesBuf::try_from(pubkey.to_prefixed_bytes()).unwrap())
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .into_script()
    }

    fn pq_bare_multisig_script(
        required_sigs: i32,
        pubkeys: &[crate::crypto::pq::PqPublicKey],
    ) -> ScriptPubKeyBuf {
        let mut builder = ScriptPubKeyBuf::builder().push_int(required_sigs).unwrap();
        for pubkey in pubkeys {
            builder =
                builder.push_slice(PushBytesBuf::try_from(pubkey.to_prefixed_bytes()).unwrap());
        }
        builder
            .push_int(pubkeys.len() as i32)
            .unwrap()
            .push_opcode(crate::opcodes::all::OP_CHECKMULTISIG)
            .into_script()
    }

    #[test]
    fn dust_thresholds_match_tidecoin_node_pq_proxies() {
        let p2pk = pq_p2pk_script();
        let p2pkh = ScriptPubKeyBuf::builder()
            .push_opcode(crate::opcodes::all::OP_DUP)
            .push_opcode(crate::opcodes::all::OP_HASH160)
            .push_slice([42u8; 20])
            .push_opcode(crate::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .into_script();
        let p2sh = ScriptPubKeyBuf::builder()
            .push_opcode(crate::opcodes::all::OP_HASH160)
            .push_slice([43u8; 20])
            .push_opcode(crate::opcodes::all::OP_EQUAL)
            .into_script();
        let p2wpkh =
            ScriptPubKeyBuf::builder().push_int_unchecked(0).push_slice([44u8; 20]).into_script();
        let p2wsh =
            ScriptPubKeyBuf::builder().push_int_unchecked(0).push_slice([45u8; 32]).into_script();
        let p2wsh512 =
            ScriptPubKeyBuf::builder().push_int_unchecked(1).push_slice([46u8; 64]).into_script();

        assert_eq!(p2pk.minimal_non_dust(), Amount::from_sat(29_628).unwrap());
        assert_eq!(p2pkh.minimal_non_dust(), Amount::from_sat(21_906).unwrap());
        assert_eq!(p2sh.minimal_non_dust(), Amount::from_sat(21_900).unwrap());
        assert_eq!(p2wpkh.minimal_non_dust(), Amount::from_sat(5_637).unwrap());
        assert_eq!(p2wsh.minimal_non_dust(), Amount::from_sat(5_676).unwrap());
        assert_eq!(p2wsh512.minimal_non_dust(), Amount::from_sat(5_772).unwrap());
    }

    #[test]
    fn is_standard_tx_matches_node_p2pk_classification() {
        let p2pk = pq_p2pk_script();
        let tx = tx_with_single_input(ScriptSigBuf::new(), vec![prevout(p2pk, 30_000)]);
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Ok(())
        );

        let invalid_p2pk = ScriptPubKeyBuf::builder()
            .push_slice([0x42u8; 33])
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .into_script();
        let tx = tx_with_single_input(ScriptSigBuf::new(), vec![prevout(invalid_p2pk, 30_000)]);
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Err(StandardTxError::ScriptPubKey)
        );
    }

    #[test]
    fn is_standard_tx_matches_node_multisig_pubkey_validation() {
        let keys = [
            deterministic_pubkey(PqScheme::Falcon512, 0x41),
            deterministic_pubkey(PqScheme::Falcon512, 0x42),
        ];
        let valid_multisig = pq_bare_multisig_script(2, &keys);
        let tx = tx_with_single_input(ScriptSigBuf::new(), vec![prevout(valid_multisig, 30_000)]);
        assert_eq!(is_standard_tx(&tx, Some(MAX_OP_RETURN_RELAY), true, FeeRate::DUST), Ok(()));
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Err(StandardTxError::BareMultisig)
        );

        let invalid_multisig = ScriptPubKeyBuf::builder()
            .push_int(1)
            .unwrap()
            .push_slice([0x43u8; 33])
            .push_int(1)
            .unwrap()
            .push_opcode(crate::opcodes::all::OP_CHECKMULTISIG)
            .into_script();
        let tx = tx_with_single_input(ScriptSigBuf::new(), vec![prevout(invalid_multisig, 30_000)]);
        assert_eq!(
            is_standard_tx(&tx, Some(MAX_OP_RETURN_RELAY), true, FeeRate::DUST),
            Err(StandardTxError::ScriptPubKey)
        );
    }

    #[test]
    fn is_standard_tx_reasons_match_node_policy() {
        let output = prevout(
            ScriptPubKeyBuf::builder()
                .push_opcode(crate::opcodes::all::OP_DUP)
                .push_opcode(crate::opcodes::all::OP_HASH160)
                .push_slice([1u8; 20])
                .push_opcode(crate::opcodes::all::OP_EQUALVERIFY)
                .push_opcode(crate::opcodes::all::OP_CHECKSIG)
                .into_script(),
            30_000,
        );
        let mut tx = tx_with_single_input(ScriptSigBuf::new(), vec![output]);

        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Ok(())
        );

        tx.version = Version::maybe_non_standard(0);
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Err(StandardTxError::Version)
        );

        tx.version = Version::ONE;
        tx.inputs[0].script_sig =
            Builder::new().push_opcode(crate::opcodes::all::OP_VERIFY).into_script();
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Err(StandardTxError::ScriptSigNotPushOnly)
        );

        tx.inputs[0].script_sig = ScriptSigBuf::new();
        tx.outputs[0].amount = Amount::from_sat(1).unwrap();
        tx.outputs.push(prevout(tx.outputs[0].script_pubkey.clone(), 1));
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Err(StandardTxError::Dust)
        );

        tx.outputs.truncate(1);
        let pubkey = deterministic_pubkey(PqScheme::Falcon512, 0x31);
        tx.outputs[0].script_pubkey = pq_bare_multisig_script(1, &[pubkey]);
        tx.outputs[0].amount = Amount::from_sat(30_000).unwrap();
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Err(StandardTxError::BareMultisig)
        );
    }

    #[test]
    fn spends_non_anchor_witness_program_matches_node_policy() {
        let prev_script =
            ScriptPubKeyBuf::builder().push_int_unchecked(0).push_slice([42u8; 20]).into_script();
        let tx =
            tx_with_single_input(ScriptSigBuf::new(), vec![prevout(ScriptPubKeyBuf::new(), 0)]);
        assert!(spends_non_anchor_witness_program(&tx, |_| Some(prevout(prev_script.clone(), 1))));

        let prev_script_v1 =
            ScriptPubKeyBuf::builder().push_int_unchecked(1).push_slice([43u8; 64]).into_script();
        assert!(!spends_non_anchor_witness_program(&tx, |_| Some(prevout(
            prev_script_v1.clone(),
            1
        ))));
    }

    #[test]
    fn spends_non_anchor_witness_program_covers_node_output_types() {
        let pubkey = deterministic_pubkey(PqScheme::Falcon512, 0x51);
        let p2pk = ScriptPubKeyBuf::builder()
            .push_slice(PushBytesBuf::try_from(pubkey.to_prefixed_bytes()).unwrap())
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .into_script();
        let p2pkh = ScriptPubKeyBuf::builder()
            .push_opcode(crate::opcodes::all::OP_DUP)
            .push_opcode(crate::opcodes::all::OP_HASH160)
            .push_slice(pubkey.key_id().to_byte_array())
            .push_opcode(crate::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .into_script();
        let native_p2wsh =
            ScriptPubKeyBuf::builder().push_int_unchecked(0).push_slice([0x11; 32]).into_script();
        let native_p2wpkh =
            ScriptPubKeyBuf::builder().push_int_unchecked(0).push_slice([0x22; 20]).into_script();
        let wrapped_p2wsh = native_p2wsh.to_p2sh().unwrap();
        let wrapped_p2wpkh = native_p2wpkh.to_p2sh().unwrap();

        let mut tx =
            tx_with_single_input(ScriptSigBuf::new(), vec![prevout(ScriptPubKeyBuf::new(), 0)]);

        assert!(!spends_non_anchor_witness_program(&tx, |_| Some(prevout(p2pk.clone(), 1))));
        assert!(!spends_non_anchor_witness_program(&tx, |_| Some(prevout(p2pkh.clone(), 1))));

        let redeem_script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(native_p2wsh.as_bytes().to_vec()).unwrap())
            .into_script();
        tx.inputs[0].script_sig = redeem_script_sig;
        assert!(spends_non_anchor_witness_program(&tx, |_| Some(prevout(
            wrapped_p2wsh.clone(),
            1
        ))));
        tx.inputs[0].script_sig = ScriptSigBuf::new();
        assert!(!spends_non_anchor_witness_program(&tx, |_| Some(prevout(
            wrapped_p2wsh.clone(),
            1
        ))));

        assert!(spends_non_anchor_witness_program(&tx, |_| Some(prevout(native_p2wsh.clone(), 1))));
        assert!(spends_non_anchor_witness_program(&tx, |_| Some(prevout(
            native_p2wpkh.clone(),
            1
        ))));

        let redeem_script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(native_p2wpkh.as_bytes().to_vec()).unwrap())
            .into_script();
        tx.inputs[0].script_sig = redeem_script_sig;
        assert!(spends_non_anchor_witness_program(&tx, |_| Some(prevout(
            wrapped_p2wpkh.clone(),
            1
        ))));
        tx.inputs[0].script_sig = ScriptSigBuf::new();
        assert!(!spends_non_anchor_witness_program(&tx, |_| Some(prevout(
            wrapped_p2wpkh.clone(),
            1
        ))));
    }

    #[test]
    fn are_inputs_standard_enforces_p2sh_sigop_limit() {
        let redeem_script: RedeemScriptBuf = Builder::new()
            .push_slice([0u8; 0])
            .push_slice([2u8; 33])
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_NOT)
            .into_script();
        let p2sh_prevout = prevout(redeem_script.to_p2sh().unwrap(), 1);
        let script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(redeem_script.as_bytes().to_vec()).unwrap())
            .into_script();

        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([7; 32]), vout: 0 },
                script_sig,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![prevout(ScriptPubKeyBuf::new(), 0)],
        };

        assert!(are_inputs_standard(&tx, |_| Some(p2sh_prevout.clone())));

        let too_many_sigops: RedeemScriptBuf = Builder::new()
            .push_slice([0u8; 0])
            .push_slice([2u8; 33])
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_2DUP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_DROP)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_NOT)
            .into_script();
        let script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(too_many_sigops.as_bytes().to_vec()).unwrap())
            .into_script();
        let tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([8; 32]), vout: 0 },
                script_sig,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![prevout(ScriptPubKeyBuf::new(), 0)],
        };
        assert!(!are_inputs_standard(&tx, |_| Some(prevout(
            too_many_sigops.to_p2sh().unwrap(),
            1
        ))));
    }

    #[test]
    fn are_inputs_standard_allows_exact_max_legacy_sigops_and_rejects_one_more() {
        let fake_pubkey = [2u8; 33];
        let mut builder = Builder::new().push_slice([0u8; 0]).push_slice(fake_pubkey);
        for _ in 0..(MAX_P2SH_SIGOPS - 1) {
            builder = builder
                .push_opcode(crate::opcodes::all::OP_2DUP)
                .push_opcode(crate::opcodes::all::OP_CHECKSIG)
                .push_opcode(crate::opcodes::all::OP_DROP);
        }
        let redeem_script: RedeemScriptBuf = builder
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .push_opcode(crate::opcodes::all::OP_NOT)
            .into_script();
        assert_eq!(redeem_script.count_sigops(), MAX_P2SH_SIGOPS);
        let redeem_script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(redeem_script.as_bytes().to_vec()).unwrap())
            .into_script();
        let p2sh_prevout = prevout(redeem_script.to_p2sh().unwrap(), 1);

        let p2pkh_prevout = prevout(
            Address::p2pkh(PubkeyHash::from_byte_array([0x22; 20]), Network::Tidecoin)
                .script_pubkey(),
            1,
        );

        let mut tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: Vec::new(),
            outputs: vec![prevout(ScriptPubKeyBuf::new(), 0)],
        };

        for vout in 0..166u32 {
            tx.inputs.push(TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x55; 32]), vout },
                script_sig: redeem_script_sig.clone(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            });
        }
        for vout in 166u32..176u32 {
            tx.inputs.push(TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x66; 32]), vout },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            });
        }

        let spent = |outpoint: &OutPoint| {
            if outpoint.txid == Txid::from_byte_array([0x55; 32]) {
                Some(p2sh_prevout.clone())
            } else if outpoint.txid == Txid::from_byte_array([0x66; 32]) {
                Some(p2pkh_prevout.clone())
            } else {
                None
            }
        };
        assert!(are_inputs_standard(&tx, spent));

        tx.inputs.push(TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0x66; 32]), vout: 176 },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        assert!(!are_inputs_standard(&tx, spent));
    }

    #[test]
    fn is_witness_standard_accepts_v1_512_and_rejects_oversized_items() {
        let witness_script: WitnessScriptBuf =
            Builder::new().push_opcode(crate::opcodes::all::OP_TRUE).into_script();
        let prev_script =
            ScriptPubKeyBuf::builder().push_int_unchecked(1).push_slice([9u8; 64]).into_script();
        let mut tx =
            tx_with_single_input(ScriptSigBuf::new(), vec![prevout(ScriptPubKeyBuf::new(), 0)]);
        tx.inputs[0].witness.push(&[1u8][..]);
        tx.inputs[0].witness.push(witness_script.as_bytes());

        assert!(is_witness_standard(&tx, |_| Some(prevout(prev_script.clone(), 1))));

        tx.inputs[0].witness.clear();
        tx.inputs[0].witness.push(vec![0u8; MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1]);
        tx.inputs[0].witness.push(witness_script.as_bytes());
        assert!(!is_witness_standard(&tx, |_| Some(prevout(prev_script.clone(), 1))));
    }

    #[test]
    fn is_witness_standard_rejects_oversized_witness_script() {
        let prev_script =
            ScriptPubKeyBuf::builder().push_int_unchecked(0).push_slice([0x33; 32]).into_script();
        let mut tx =
            tx_with_single_input(ScriptSigBuf::new(), vec![prevout(ScriptPubKeyBuf::new(), 0)]);
        tx.inputs[0].witness.push(&[1u8][..]);
        tx.inputs[0].witness.push(vec![0x51; MAX_STANDARD_P2WSH_SCRIPT_SIZE + 1]);

        assert!(!is_witness_standard(&tx, |_| Some(prevout(prev_script.clone(), 1))));
    }

    #[test]
    fn is_witness_standard_matches_node_native_and_wrapped_p2wsh_boundaries() {
        let simple_script: WitnessScriptBuf =
            Builder::new().push_opcode(crate::opcodes::all::OP_TRUE).into_script();
        let p2wsh = p2wsh_script_pubkey(&simple_script);

        let mut limit_items = vec![vec![1u8]; MAX_STANDARD_P2WSH_STACK_ITEMS];
        limit_items.push(simple_script.as_bytes().to_vec());
        assert_witness_standard_for_native_and_wrapped(
            p2wsh.clone(),
            witness_from_items(limit_items),
            true,
        );

        let mut too_many_items = vec![vec![1u8]; MAX_STANDARD_P2WSH_STACK_ITEMS + 1];
        too_many_items.push(simple_script.as_bytes().to_vec());
        assert_witness_standard_for_native_and_wrapped(
            p2wsh,
            witness_from_items(too_many_items),
            false,
        );

        let item_limit_script: WitnessScriptBuf =
            Builder::new().push_opcode(crate::opcodes::all::OP_DROP).into_script();
        let item_limit_spk = p2wsh_script_pubkey(&item_limit_script);
        assert_witness_standard_for_native_and_wrapped(
            item_limit_spk.clone(),
            witness_from_items(vec![
                vec![1u8; MAX_STANDARD_P2WSH_STACK_ITEM_SIZE],
                item_limit_script.as_bytes().to_vec(),
            ]),
            true,
        );
        assert_witness_standard_for_native_and_wrapped(
            item_limit_spk,
            witness_from_items(vec![
                vec![1u8; MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1],
                item_limit_script.as_bytes().to_vec(),
            ]),
            false,
        );

        let max_script = node_sized_witness_script(15);
        assert_eq!(max_script.len(), MAX_STANDARD_P2WSH_SCRIPT_SIZE);
        assert_witness_standard_for_native_and_wrapped(
            p2wsh_script_pubkey(&max_script),
            witness_from_items(vec![vec![1u8], vec![1u8], max_script.as_bytes().to_vec()]),
            true,
        );

        let oversized_script = node_sized_witness_script(16);
        assert_eq!(oversized_script.len(), MAX_STANDARD_P2WSH_SCRIPT_SIZE + 1);
        assert_witness_standard_for_native_and_wrapped(
            p2wsh_script_pubkey(&oversized_script),
            witness_from_items(vec![
                vec![1u8],
                vec![1u8],
                vec![1u8],
                oversized_script.as_bytes().to_vec(),
            ]),
            false,
        );
    }

    #[test]
    fn is_witness_standard_matches_node_p2wsh512_boundaries() {
        let simple_script: WitnessScriptBuf =
            Builder::new().push_opcode(crate::opcodes::all::OP_TRUE).into_script();
        let p2wsh512 = p2wsh512_script_pubkey(&simple_script);

        let mut limit_items = vec![vec![1u8]; MAX_STANDARD_P2WSH_STACK_ITEMS];
        limit_items.push(simple_script.as_bytes().to_vec());
        assert_witness_standard_for_native_and_wrapped(
            p2wsh512.clone(),
            witness_from_items(limit_items),
            true,
        );

        let mut too_many_items = vec![vec![1u8]; MAX_STANDARD_P2WSH_STACK_ITEMS + 1];
        too_many_items.push(simple_script.as_bytes().to_vec());
        assert_witness_standard_for_native_and_wrapped(
            p2wsh512,
            witness_from_items(too_many_items),
            false,
        );

        let item_limit_script: WitnessScriptBuf =
            Builder::new().push_opcode(crate::opcodes::all::OP_DROP).into_script();
        let item_limit_spk = p2wsh512_script_pubkey(&item_limit_script);
        assert_witness_standard_for_native_and_wrapped(
            item_limit_spk.clone(),
            witness_from_items(vec![
                vec![1u8; MAX_STANDARD_P2WSH_STACK_ITEM_SIZE],
                item_limit_script.as_bytes().to_vec(),
            ]),
            true,
        );
        assert_witness_standard_for_native_and_wrapped(
            item_limit_spk,
            witness_from_items(vec![
                vec![1u8; MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1],
                item_limit_script.as_bytes().to_vec(),
            ]),
            false,
        );

        let max_script = node_sized_witness_script(15);
        assert_witness_standard_for_native_and_wrapped(
            p2wsh512_script_pubkey(&max_script),
            witness_from_items(vec![vec![1u8], vec![1u8], max_script.as_bytes().to_vec()]),
            true,
        );

        let oversized_script = node_sized_witness_script(16);
        assert_witness_standard_for_native_and_wrapped(
            p2wsh512_script_pubkey(&oversized_script),
            witness_from_items(vec![
                vec![1u8],
                vec![1u8],
                vec![1u8],
                oversized_script.as_bytes().to_vec(),
            ]),
            false,
        );
    }

    #[test]
    fn pq_witness_item_policy_boundary_is_stricter_than_consensus_push_boundary() {
        let scheme = PqScheme::MlDsa87;
        let pubkey = deterministic_pubkey(scheme, 0x87);
        let witness_script: WitnessScriptBuf = Builder::new()
            .push_slice(PushBytesBuf::try_from(pubkey.to_prefixed_bytes()).unwrap())
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .into_script();
        let prev_script = p2wsh_script_pubkey(&witness_script);

        let policy_limit_tx = tx_with_witness(
            ScriptSigBuf::new(),
            witness_from_items(vec![
                vec![0x42; MAX_STANDARD_P2WSH_STACK_ITEM_SIZE],
                witness_script.as_bytes().to_vec(),
            ]),
        );
        assert!(is_witness_standard(&policy_limit_tx, |_| Some(prevout(prev_script.clone(), 1))));

        let policy_reject_tx = tx_with_witness(
            ScriptSigBuf::new(),
            witness_from_items(vec![
                vec![0x42; MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1],
                witness_script.as_bytes().to_vec(),
            ]),
        );
        assert!(!is_witness_standard(&policy_reject_tx, |_| Some(prevout(prev_script.clone(), 1))));

        let consensus_push_limit_tx = tx_with_witness(
            ScriptSigBuf::new(),
            witness_from_items(vec![vec![0x42; 8192], witness_script.as_bytes().to_vec()]),
        );
        assert!(!is_witness_standard(&consensus_push_limit_tx, |_| Some(prevout(
            prev_script.clone(),
            1
        ))));
    }

    #[test]
    fn is_standard_tx_covers_additional_node_cases() {
        let output_script = ScriptPubKeyBuf::builder()
            .push_opcode(crate::opcodes::all::OP_DUP)
            .push_opcode(crate::opcodes::all::OP_HASH160)
            .push_slice([1u8; 20])
            .push_opcode(crate::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(crate::opcodes::all::OP_CHECKSIG)
            .into_script();
        let mut tx =
            tx_with_single_input(ScriptSigBuf::new(), vec![prevout(output_script, 30_000)]);

        tx.inputs[0].script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(vec![0u8; MAX_STANDARD_SCRIPTSIG_SIZE - 3]).unwrap())
            .into_script();
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Ok(())
        );

        tx.inputs[0].script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(vec![0u8; MAX_STANDARD_SCRIPTSIG_SIZE - 2]).unwrap())
            .into_script();
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Err(StandardTxError::ScriptSigSize)
        );

        tx.inputs[0].script_sig = ScriptSigBuf::new();
        tx.outputs[0].script_pubkey = ScriptPubKeyBuf::builder()
            .push_opcode(crate::opcodes::all::OP_RETURN)
            .push_slice(PushBytesBuf::try_from(vec![0u8; 81]).unwrap())
            .into_script();
        assert_eq!(
            is_standard_tx(&tx, Some(84), DEFAULT_PERMIT_BAREMULTISIG, FeeRate::DUST),
            Ok(())
        );
        assert_eq!(
            is_standard_tx(&tx, Some(83), DEFAULT_PERMIT_BAREMULTISIG, FeeRate::DUST),
            Err(StandardTxError::DataCarrier)
        );

        tx.outputs[0].script_pubkey = ScriptPubKeyBuf::builder()
            .push_opcode(crate::opcodes::all::OP_RETURN)
            .push_opcode(crate::opcodes::all::OP_RETURN)
            .into_script();
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Err(StandardTxError::ScriptPubKey)
        );

        let pubkey = deterministic_pubkey(PqScheme::Falcon512, 0x32);
        tx.outputs[0].script_pubkey = pq_bare_multisig_script(1, &[pubkey]);
        assert_eq!(is_standard_tx(&tx, Some(MAX_OP_RETURN_RELAY), true, FeeRate::DUST), Ok(()));

        tx.outputs[0].script_pubkey = ScriptPubKeyBuf::builder()
            .push_opcode(crate::opcodes::all::OP_RETURN)
            .push_slice([0u8; 19])
            .into_script();
        tx.inputs = (0..20_000u32)
            .map(|vout| TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x77; 32]), vout },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect();
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Err(StandardTxError::TxSize)
        );
    }

    #[test]
    fn standard_relay_prechecks_reject_small_non_witness_transaction_after_is_standard_tx() {
        let mut tx = tx_with_single_input(
            ScriptSigBuf::new(),
            vec![prevout(
                ScriptPubKeyBuf::builder()
                    .push_opcode(crate::opcodes::all::OP_RETURN)
                    .into_script(),
                0,
            )],
        );
        tx.inputs[0].previous_output =
            OutPoint { txid: Txid::from_byte_array([0x91; 32]), vout: 0 };

        assert!(tx.base_size() < MIN_STANDARD_TX_NONWITNESS_SIZE as usize);
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Ok(())
        );
        assert_eq!(
            check_standard_relay_prechecks(
                &tx,
                Params::REGTEST,
                BlockHeight::from_u32(0),
                |_| Some(prevout(ScriptPubKeyBuf::new(), 1)),
                StandardRelayPrecheckPolicy::default(),
            ),
            Err(StandardRelayPrecheckError::TxSizeSmall)
        );
    }

    #[test]
    fn standard_relay_prechecks_reject_witness_v1_outputs_before_auxpow() {
        let script_pubkey =
            ScriptPubKeyBuf::builder().push_int_unchecked(1).push_slice([0x61; 64]).into_script();
        let tx = tx_with_single_input(ScriptSigBuf::new(), vec![prevout(script_pubkey, 10_000)]);
        let input_prevout = prevout(
            Address::p2pkh(PubkeyHash::from_byte_array([0x62; 20]), Network::Testnet)
                .script_pubkey(),
            10_000,
        );
        let spent = |_: &OutPoint| Some(input_prevout.clone());

        assert_eq!(
            check_standard_relay_prechecks(
                &tx,
                Params::TESTNET,
                BlockHeight::from_u32(999),
                spent,
                StandardRelayPrecheckPolicy::default(),
            ),
            Err(StandardRelayPrecheckError::WitnessV1PreAuxpow)
        );
        assert_eq!(
            check_standard_relay_prechecks(
                &tx,
                Params::TESTNET,
                BlockHeight::from_u32(1000),
                |_| Some(input_prevout.clone()),
                StandardRelayPrecheckPolicy::default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn standard_policy_script_flags_match_node_auxpow_activation() {
        let base = STANDARD_SCRIPT_VERIFY_FLAGS;
        assert_eq!(standard_policy_script_flags(Params::TESTNET, BlockHeight::from_u32(999)), base);
        assert_eq!(
            standard_policy_script_flags(Params::TESTNET, BlockHeight::from_u32(1000)),
            base | VERIFY_PQ_STRICT | VERIFY_WITNESS_V1_512 | VERIFY_SHA512
        );
        assert_eq!(
            standard_policy_script_flags(Params::MAINNET, BlockHeight::from_u32(u32::MAX)),
            base
        );
    }

    #[test]
    fn standard_relay_prechecks_enforce_stateless_truc_vsize_limit() {
        let mut tx = tx_with_single_input(
            ScriptSigBuf::new(),
            vec![prevout(
                ScriptPubKeyBuf::builder()
                    .push_opcode(crate::opcodes::all::OP_DUP)
                    .push_opcode(crate::opcodes::all::OP_HASH160)
                    .push_slice([0x71; 20])
                    .push_opcode(crate::opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(crate::opcodes::all::OP_CHECKSIG)
                    .into_script(),
                30_000,
            )],
        );
        tx.version = TRUC_VERSION;
        tx.inputs[0].witness.push(vec![0x42; (TRUC_MAX_VSIZE as usize * 4) + 1]);

        let input_prevout = prevout(
            ScriptPubKeyBuf::builder().push_int_unchecked(0).push_slice([0x72; 20]).into_script(),
            30_000,
        );
        let Err(StandardRelayPrecheckError::TrucTxSize { vsize }) = check_standard_relay_prechecks(
            &tx,
            Params::REGTEST,
            BlockHeight::from_u32(0),
            |_| Some(input_prevout.clone()),
            StandardRelayPrecheckPolicy::default(),
        ) else {
            panic!("oversized TRUC transaction should fail stateless relay prechecks");
        };
        assert!(vsize > TRUC_MAX_VSIZE);
    }

    #[test]
    fn standard_relay_prechecks_enforce_standard_sigop_cost_limit() {
        let pubkey = deterministic_pubkey(PqScheme::Falcon512, 0x63);
        let bare_multisig = pq_bare_multisig_script(1, &[pubkey]);
        let outputs = (0..=MAX_STANDARD_TX_SIGOPS_COST / 80)
            .map(|_| prevout(bare_multisig.clone(), 30_000))
            .collect();
        let tx = tx_with_single_input(ScriptSigBuf::new(), outputs);
        let input_prevout = prevout(
            Address::p2pkh(PubkeyHash::from_byte_array([0x64; 20]), Network::Regtest)
                .script_pubkey(),
            10_000,
        );
        let policy = StandardRelayPrecheckPolicy {
            permit_bare_multisig: true,
            ..StandardRelayPrecheckPolicy::default()
        };

        let Err(StandardRelayPrecheckError::TooManySigops { cost }) =
            check_standard_relay_prechecks(
                &tx,
                Params::REGTEST,
                BlockHeight::from_u32(0),
                |_| Some(input_prevout.clone()),
                policy,
            )
        else {
            panic!("too many standard sigops should be rejected");
        };
        assert!(cost > MAX_STANDARD_TX_SIGOPS_COST as usize);
    }

    #[test]
    fn pq_input_vsize_matches_node_formulas_all_schemes() {
        for scheme in PqScheme::KNOWN {
            let sig_len = scheme.max_sig_len_in_script();
            let pubkey_len = scheme.prefixed_pubkey_len();

            let witness_bytes = CompactSizeEncoder::encoded_size(2)
                + CompactSizeEncoder::encoded_size(sig_len)
                + sig_len
                + CompactSizeEncoder::encoded_size(pubkey_len)
                + pubkey_len;
            let native_weight = (41 * WITNESS_SCALE_FACTOR + witness_bytes) as i64;
            let nested_weight = (64 * WITNESS_SCALE_FACTOR + witness_bytes) as i64;

            assert_eq!(pq_p2wpkh_input_vsize(sig_len, pubkey_len), (native_weight + 3) / 4);
            assert_eq!(pq_p2sh_p2wpkh_input_vsize(sig_len, pubkey_len), (nested_weight + 3) / 4);
        }
    }

    #[test]
    #[cfg(feature = "tidecoin-node-validation")]
    fn pq_input_vsize_matches_tidecoin_node_bridge_all_schemes() {
        let harness = match node_parity::TidecoinNodeHarness::from_env() {
            Ok(harness) => harness,
            Err(err) => {
                std::eprintln!("skipping Tidecoin node-backed txsize test: {err}");
                return;
            }
        };

        for scheme in PqScheme::KNOWN {
            let sig_len = scheme.max_sig_len_in_script();
            let pubkey_len = scheme.prefixed_pubkey_len();

            assert_eq!(
                pq_p2wpkh_input_vsize(sig_len, pubkey_len),
                harness.pq_p2wpkh_input_vsize(sig_len, pubkey_len).unwrap()
            );
            assert_eq!(
                pq_p2sh_p2wpkh_input_vsize(sig_len, pubkey_len),
                harness.pq_p2sh_p2wpkh_input_vsize(sig_len, pubkey_len).unwrap()
            );
        }
    }

    #[test]
    fn pq_bare_multisig_is_non_standard() {
        let keys: Vec<_> = (0..2)
            .map(|idx| {
                PqScheme::Falcon512
                    .generate_keypair_from_seed(&vec![
                        idx as u8 + 1;
                        PqScheme::Falcon512.deterministic_seed_len()
                    ])
                    .unwrap()
                    .0
            })
            .collect();
        let script_pubkey = pq_bare_multisig_script(2, &keys);
        let tx = tx_with_single_input(ScriptSigBuf::new(), vec![prevout(script_pubkey, 30_000)]);

        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Err(StandardTxError::BareMultisig)
        );
    }

    #[test]
    fn pq_mldsa87_20_of_20_weight_stays_standard() {
        let scheme = PqScheme::MlDsa87;
        let pubkeys: Vec<_> = (0..20)
            .map(|idx| {
                let seed = vec![0x55 ^ idx as u8; scheme.deterministic_seed_len()];
                scheme.generate_keypair_from_seed(&seed).unwrap().0
            })
            .collect();
        let mut witness_builder = Builder::new().push_int(20).unwrap();
        for pubkey in &pubkeys {
            witness_builder = witness_builder
                .push_slice(PushBytesBuf::try_from(pubkey.to_prefixed_bytes()).unwrap());
        }
        let witness_script: WitnessScriptBuf = witness_builder
            .push_int(20)
            .unwrap()
            .push_opcode(crate::opcodes::all::OP_CHECKMULTISIG)
            .into_script();
        let prev_script = ScriptPubKeyBuf::builder()
            .push_int_unchecked(0)
            .push_slice(sha256::Hash::hash(witness_script.as_bytes()).to_byte_array())
            .into_script();
        let output_script =
            ScriptPubKeyBuf::builder().push_int_unchecked(0).push_slice([0x44; 20]).into_script();
        let mut tx =
            tx_with_single_input(ScriptSigBuf::new(), vec![prevout(output_script, 30_000)]);
        tx.inputs[0].witness.push(Vec::<u8>::new());
        for _ in 0..20 {
            tx.inputs[0].witness.push(vec![0x30; scheme.max_sig_len_in_script()]);
        }
        tx.inputs[0].witness.push(witness_script.as_bytes());

        assert!(tx.weight().to_wu() <= MAX_STANDARD_TX_WEIGHT as u64);
        assert_eq!(
            is_standard_tx(
                &tx,
                Some(MAX_OP_RETURN_RELAY),
                DEFAULT_PERMIT_BAREMULTISIG,
                FeeRate::DUST
            ),
            Ok(())
        );
        assert!(is_witness_standard(&tx, |_| Some(prevout(prev_script.clone(), 1))));
    }
}
