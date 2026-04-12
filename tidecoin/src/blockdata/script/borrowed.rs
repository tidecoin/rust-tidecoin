// SPDX-License-Identifier: CC0-1.0

use primitives::script::{
    ParsedWitnessProgram, WitnessProgramClass as PrimitiveWitnessProgramClass,
};

use super::witness_version::WitnessVersion;
use super::{
    Builder, Instruction, InstructionIndices, Instructions, RedeemScript, RedeemScriptSizeError,
    Script, ScriptHash, ScriptHashableTag, ScriptPubKey, ScriptSig, WScriptHash, WitnessScript,
    WitnessScriptSizeError,
};
use crate::key::WPubkeyHash;
use crate::opcodes::all::*;
use crate::opcodes::Opcode;
use crate::policy::{DUST_RELAY_TX_FEE, MAX_OP_RETURN_RELAY};
use crate::script::{self, ScriptPubKeyBufExt as _};
use crate::{internal_macros, Amount, FeeRate, ScriptPubKeyBuf, WitnessScriptBuf};

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Script`] type.
    pub trait ScriptExt<T> impl<T> for Script<T> {
        /// Constructs a new script builder
        fn builder() -> Builder<T> { Builder::new() }

        /// Counts the sigops for this Script using accurate counting.
        ///
        /// In the reference node, there are two ways to count sigops, "accurate" and "legacy".
        /// This method uses "accurate" counting. This means that OP_CHECKMULTISIG and its
        /// verify variant count for N sigops where N is the number of pubkeys used in the
        /// multisig. However, it will count for 20 sigops if CHECKMULTISIG is not preceded by an
        /// OP_PUSHNUM from 1 - 16 (this would be an invalid script)
        ///
        /// The reference node uses accurate counting for sigops contained within redeemScripts (P2SH)
        /// and witnessScripts (P2WSH) only. It uses legacy for sigops in scriptSigs and scriptPubkeys.
        ///
        /// Witness-v1 outputs are not part of Tidecoin's recognized script types.
        /// This function does not count `OP_CHECKSIGADD`.
        fn count_sigops(&self) -> usize { self.count_sigops_internal(true) }

        /// Counts the sigops for this Script using legacy counting.
        ///
        /// In the reference node, there are two ways to count sigops, "accurate" and "legacy".
        /// This method uses "legacy" counting. This means that OP_CHECKMULTISIG and its
        /// verify variant count for 20 sigops.
        ///
        /// The reference node uses legacy counting for sigops contained within scriptSigs and
        /// scriptPubkeys. It uses accurate for redeemScripts (P2SH) and witnessScripts (P2WSH).
        ///
        /// Witness-v1 outputs are not part of Tidecoin's recognized script types.
        /// This function does not count `OP_CHECKSIGADD`.
        fn count_sigops_legacy(&self) -> usize { self.count_sigops_internal(false) }

        /// Checks whether a script is push only.
        ///
        /// Note: `OP_RESERVED` (`0x50`) and all the OP_PUSHNUM operations
        /// are considered push operations.
        #[inline]
        fn is_push_only(&self) -> bool {
            for inst in self.instructions() {
                match inst {
                    Err(_) => return false,
                    Ok(Instruction::PushBytes(_)) => {}
                    Ok(Instruction::Op(op)) if op.to_u8() <= 0x60 => {}
                    // From the reference node.
                    // if (opcode > OP_PUSHNUM_16 (0x60)) return false
                    Ok(Instruction::Op(_)) => return false,
                }
            }
            true
        }

        /// Returns an iterator over script bytes.
        #[inline]
        fn bytes(&self) -> Bytes<'_> { Bytes(self.as_bytes().iter().copied()) }

        /// Iterates over the script instructions.
        ///
        /// Each returned item is a nested enum covering opcodes, datapushes and errors.
        /// At most one error will be returned and then the iterator will end. To instead iterate over
        /// the script as sequence of bytes call the [`bytes`](Self::bytes) method.
        ///
        /// To force minimal pushes, use [`instructions_minimal`](Self::instructions_minimal).
        #[inline]
        fn instructions(&self) -> Instructions<'_> {
            primitives::script::Script::instructions(self)
        }

        /// Iterates over the script instructions while enforcing minimal pushes.
        ///
        /// This is similar to [`instructions`](Self::instructions) but an error is returned if a push
        /// is not minimal.
        #[inline]
        fn instructions_minimal(&self) -> Instructions<'_> {
            primitives::script::Script::instructions_minimal(self)
        }

        /// Iterates over the script instructions and their indices.
        ///
        /// Unless the script contains an error, the returned item consists of an index pointing to the
        /// position in the script where the instruction begins and the decoded instruction - either an
        /// opcode or data push.
        ///
        /// To force minimal pushes, use [`Self::instruction_indices_minimal`].
        #[inline]
        fn instruction_indices(&self) -> InstructionIndices<'_> {
            primitives::script::Script::instruction_indices(self)
        }

        /// Iterates over the script instructions and their indices while enforcing minimal pushes.
        ///
        /// This is similar to [`instruction_indices`](Self::instruction_indices) but an error is
        /// returned if a push is not minimal.
        #[inline]
        fn instruction_indices_minimal(&self) -> InstructionIndices<'_> {
            primitives::script::Script::instruction_indices_minimal(self)
        }

        /// Returns the first opcode of the script (if there is any).
        fn first_opcode(&self) -> Option<Opcode> {
            self.as_bytes().first().copied().map(From::from)
        }

        // These methods only exist for scriptPubKey and redeemScript, as indicated by the
        // where clauses on them.

        /// Returns 160-bit hash of the script for P2SH outputs.
        #[inline]
        fn script_hash(&self) -> Result<ScriptHash, RedeemScriptSizeError>
        where T: ScriptHashableTag
        {
            ScriptHash::from_script(self)
        }

        /// Computes the P2SH output corresponding to this redeem script.
        fn to_p2sh(&self) -> Result<ScriptPubKeyBuf, RedeemScriptSizeError>
        where T: ScriptHashableTag
        {
            self.script_hash().map(ScriptPubKeyBuf::new_p2sh)
        }

        /// Returns the script code used for spending a P2WPKH output if this script is a script pubkey
        /// for a P2WPKH output.
        ///
        /// While the type returned is [`WitnessScriptBuf`], this is **not** a witness script and
        /// should not be used as one. It is the Tidecoin witness-v0 script-code template used
        /// in place of a witness script for purposes of sighash computation.
        fn p2wpkh_script_code(&self) -> Option<WitnessScriptBuf>
        where T: ScriptHashableTag
        {
            if self.is_p2wpkh() {
                // The `self` script is 0x00, 0x14, <pubkey_hash>
                let bytes = <[u8; 20]>::try_from(&self.as_bytes()[2..]).expect("length checked in is_p2wpkh()");
                let wpkh = WPubkeyHash::from_byte_array(bytes);
                Some(script::p2wpkh_script_code(wpkh))
            } else {
                None
            }
        }

        /// Returns witness version of the script, if any, assuming the script is a `scriptPubkey`.
        ///
        /// # Returns
        ///
        /// The witness version if this script is found to conform to the Tidecoin witness rules:
        ///
        /// > A script pubkey consisting of a 1-byte push opcode (for 0 to 16) followed by a data
        /// > push between 2 and 64 bytes is a witness program. The value of the first push is the
        /// > version byte, and the following byte vector is the witness program.
        #[inline]
        fn witness_version(&self) -> Option<WitnessVersion>
        where T: ScriptHashableTag
        {
            let program = ParsedWitnessProgram::parse_script_pubkey(self.as_bytes())?;
            WitnessVersion::try_from(program.version()).ok()
        }

        /// Checks whether a script pubkey is a P2WSH output.
        #[inline]
        fn is_p2wsh(&self) -> bool
        where T: ScriptHashableTag
        {
            ParsedWitnessProgram::parse_script_pubkey(self.as_bytes())
                .is_some_and(|program| program.class() == PrimitiveWitnessProgramClass::P2wsh)
        }

        /// Checks whether a script pubkey is a P2WPKH output.
        #[inline]
        fn is_p2wpkh(&self) -> bool
        where T: ScriptHashableTag
        {
            ParsedWitnessProgram::parse_script_pubkey(self.as_bytes())
                .is_some_and(|program| program.class() == PrimitiveWitnessProgramClass::P2wpkh)
        }

        /// Checks whether a script pubkey is a P2WSH-512 output (witness v1, 64-byte SHA-512 hash).
        #[inline]
        fn is_p2wsh512(&self) -> bool
        where T: ScriptHashableTag
        {
            ParsedWitnessProgram::parse_script_pubkey(self.as_bytes())
                .is_some_and(|program| program.class() == PrimitiveWitnessProgramClass::P2wsh512)
        }
    }
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`WitnessScript`] type.
    pub trait WitnessScriptExt impl for WitnessScript {
        /// Returns 256-bit hash of the script for P2WSH outputs.
        #[inline]
        fn wscript_hash(&self) -> Result<WScriptHash, WitnessScriptSizeError> {
            WScriptHash::from_script(self)
        }

        /// Computes the P2WSH output corresponding to this witnessScript (aka the "witness redeem
        /// script").
        fn to_p2wsh(&self) -> Result<ScriptPubKeyBuf, WitnessScriptSizeError> {
            self.wscript_hash().map(ScriptPubKeyBuf::new_p2wsh)
        }
    }
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`ScriptPubKey`] type.
    pub trait ScriptPubKeyExt impl for ScriptPubKey {
        /// Checks whether a script pubkey is a P2SH output.
        #[inline]
        fn is_p2sh(&self) -> bool {
            self.len() == 23
                && self.as_bytes()[0] == OP_HASH160.to_u8()
                && self.as_bytes()[1] == OP_PUSHBYTES_20.to_u8()
                && self.as_bytes()[22] == OP_EQUAL.to_u8()
        }

        /// Checks whether a script pubkey is a P2PKH output.
        #[inline]
        fn is_p2pkh(&self) -> bool {
            self.len() == 25
                && self.as_bytes()[0] == OP_DUP.to_u8()
                && self.as_bytes()[1] == OP_HASH160.to_u8()
                && self.as_bytes()[2] == OP_PUSHBYTES_20.to_u8()
                && self.as_bytes()[23] == OP_EQUALVERIFY.to_u8()
                && self.as_bytes()[24] == OP_CHECKSIG.to_u8()
        }

        /// Checks whether a script pubkey is a bare multisig output.
        ///
        /// In a bare multisig pubkey script the keys are not hashed, the script
        /// is of the form:
        ///
        ///    `2 <pubkey1> <pubkey2> <pubkey3> 3 OP_CHECKMULTISIG`
        #[inline]
        fn is_multisig(&self) -> bool {
            let required_sigs;

            let mut instructions = self.instructions();
            if let Some(Ok(Instruction::Op(op))) = instructions.next() {
                if let Some(pushnum) = op.decode_pushnum() {
                    required_sigs = pushnum;
                } else {
                    return false;
                }
            } else {
                return false;
            }

            let mut num_pubkeys: u8 = 0;
            while let Some(Ok(instruction)) = instructions.next() {
                match instruction {
                    Instruction::PushBytes(_) => {
                        num_pubkeys += 1;
                    }
                    Instruction::Op(op) => {
                        if let Some(pushnum) = op.decode_pushnum() {
                            if pushnum != num_pubkeys {
                                return false;
                            }
                        }
                        break;
                    }
                }
            }

            if required_sigs > num_pubkeys {
                return false;
            }

            if let Some(Ok(Instruction::Op(op))) = instructions.next() {
                if op.to_u8() != OP_CHECKMULTISIG.to_u8() {
                    return false;
                }
            } else {
                return false;
            }

            instructions.next().is_none()
        }

        /// Checks whether a script pubkey is a Segregated Witness (SegWit) program.
        #[inline]
        fn is_witness_program(&self) -> bool { self.witness_version().is_some() }

        /// Checks whether a script pubkey is a P2A output.
        #[inline]
        fn is_p2a(&self) -> bool {
            ParsedWitnessProgram::parse_script_pubkey(self.as_bytes())
                .is_some_and(|program| program.class() == PrimitiveWitnessProgramClass::P2a)
        }

        /// Check if this is a consensus-valid OP_RETURN output.
        ///
        /// To validate if the OP_RETURN obeys the Tidecoin node's current standardness policy, use
        /// [`is_standard_op_return()`](Self::is_standard_op_return) instead.
        #[inline]
        fn is_op_return(&self) -> bool {
            self.as_bytes().first().is_some_and(|&b| b == OP_RETURN.to_u8())
        }

        /// Check if this is an OP_RETURN that obeys the Tidecoin node's standardness policy.
        ///
        /// What this function considers to be standard may change without warning pending Tidecoin node
        /// changes.
        #[inline]
        fn is_standard_op_return(&self) -> bool { self.is_op_return() && self.len() <= MAX_OP_RETURN_RELAY }

        /// Returns the minimum value an output with this script should have in order to be
        /// broadcastable on today's Tidecoin network.
        ///
        /// Dust depends on the `-dustrelayfee` value of the Tidecoin node you are broadcasting to.
        /// This function uses the default value of 0.00003 TDC/kB (3 tidoshi/vByte).
        ///
        /// To use a custom value, use [`minimal_non_dust_custom`].
        ///
        /// [`minimal_non_dust_custom`]: Self::minimal_non_dust_custom
        fn minimal_non_dust(&self) -> Amount {
            self.minimal_non_dust_internal(DUST_RELAY_TX_FEE.into())
                .expect("dust_relay_fee or script length should not be absurdly large")
        }

        /// Returns the minimum value an output with this script should have in order to be
        /// broadcastable on today's Tidecoin network.
        ///
        /// Dust depends on the `-dustrelayfee` value of the Tidecoin node you are broadcasting to.
        /// This function lets you set the fee rate used in dust calculation.
        ///
        /// The current default value in Tidecoin node policy is 3 tidoshi/vByte.
        ///
        /// To use the default Tidecoin node value, use [`minimal_non_dust`].
        ///
        /// [`minimal_non_dust`]: Self::minimal_non_dust
        fn minimal_non_dust_custom(&self, dust_relay: FeeRate) -> Option<Amount> {
            self.minimal_non_dust_internal(dust_relay.to_sat_per_kvb_ceil())
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl<T> Sealed for super::Script<T> {}
}

internal_macros::define_extension_trait! {
    pub(crate) trait ScriptExtPriv<T> impl<T> for Script<T> {
        fn count_sigops_internal(&self, accurate: bool) -> usize {
            let mut n = 0;
            let mut pushnum_cache = None;
            for inst in self.instructions() {
                match inst {
                    Ok(Instruction::Op(opcode)) => {
                        match opcode.to_u8() {
                            // p2pk, p2pkh
                            x if x == OP_CHECKSIG.to_u8() || x == OP_CHECKSIGVERIFY.to_u8() => {
                                n += 1;
                            }
                            x if x == OP_CHECKMULTISIG.to_u8()
                                || x == OP_CHECKMULTISIGVERIFY.to_u8() =>
                            {
                                match (accurate, pushnum_cache) {
                                    (true, Some(pushnum)) => {
                                        // Add the number of pubkeys in the multisig as sigop count
                                        n += usize::from(pushnum);
                                    }
                                    _ => {
                                        // MAX_PUBKEYS_PER_MULTISIG from the reference node.
                                        n += 20;
                                    }
                                }
                            }
                            _ => {
                                pushnum_cache = opcode.decode_pushnum();
                            }
                        }
                    }
                    Ok(Instruction::PushBytes(_)) => {
                        pushnum_cache = None;
                    }
                    // In the reference node it does `if (!GetOp(pc, opcode)) break;`
                    Err(_) => break,
                }
            }

            n
        }

    }
}

internal_macros::define_extension_trait! {
    pub(crate) trait ScriptPubKeyExtPriv impl for ScriptPubKey {
        fn minimal_non_dust_internal(&self, dust_relay_fee_rate_per_kvb: u64) -> Option<Amount> {
            let fee_rate = u32::try_from(dust_relay_fee_rate_per_kvb).ok().map(FeeRate::from_sat_per_kvb)?;
            crate::policy::dust_threshold(self, fee_rate)
        }
    }
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`ScriptSig`] type.
    pub trait ScriptSigExt impl for ScriptSig {
        /// Get the redeem script following Tidecoin P2SH spending rules.
        ///
        /// This does not guarantee that this represents a P2SH input [`ScriptSig`].
        /// It merely gets the last push of the script.
        ///
        /// Use [`ScriptPubKey::is_p2sh`] on the scriptPubKey to check whether it is actually a P2SH script.
        fn redeem_script(&self) -> Option<&RedeemScript> {
            // Script must consist entirely of pushes.
            if self.instructions().any(|i| i.is_err() || i.unwrap().push_bytes().is_none()) {
                return None;
            }

            if let Some(Ok(Instruction::PushBytes(b))) = self.instructions().last() {
                Some(RedeemScript::from_bytes(b.as_bytes()))
            } else {
                None
            }
        }
    }
}

/// Iterator over bytes of a script
pub struct Bytes<'a>(core::iter::Copied<core::slice::Iter<'a, u8>>);

impl Iterator for Bytes<'_> {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth(n)
    }
}

impl DoubleEndedIterator for Bytes<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth_back(n)
    }
}

impl ExactSizeIterator for Bytes<'_> {}
impl core::iter::FusedIterator for Bytes<'_> {}
