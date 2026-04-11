// SPDX-License-Identifier: CC0-1.0

use super::{Builder, Error, Instruction, ScriptBuf, ScriptPubKeyBuf};
use crate::internal_macros;
use crate::key::{PubkeyHash, WPubkeyHash};
use crate::script::witness_program::{WitnessProgram, P2A_PROGRAM};
use crate::script::witness_version::WitnessVersion;
use crate::script::{self, ScriptHash, WScriptHash};

mod sealed {
    pub trait Sealed {}
    impl<T> Sealed for super::ScriptBuf<T> {}
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`ScriptBuf`] type.
    pub trait ScriptBufExt<T> impl<T> for ScriptBuf<T> {
        /// Constructs a new script builder.
        fn builder() -> Builder<T> { Builder::new() }

        /// Adds instructions to push an integer onto the stack.
        fn push_int(&mut self, n: i32) -> Result<(), Error> {
            primitives::script::ScriptBuf::push_int(self, n).map_err(Into::into)
        }

        /// Adds instructions to push an unchecked integer onto the stack.
        fn push_int_unchecked(&mut self, n: i64) {
            primitives::script::ScriptBuf::push_int_unchecked(self, n)
        }

        /// Adds instructions to push an integer onto the stack without optimization.
        fn push_int_non_minimal(&mut self, data: i64) {
            primitives::script::ScriptBuf::push_int_non_minimal(self, data)
        }

        /// Adds a single opcode to the script.
        fn push_opcode(&mut self, data: crate::opcodes::Opcode) {
            primitives::script::ScriptBuf::push_opcode(self, data)
        }

        /// Adds instructions to push some arbitrary data onto the stack.
        fn push_slice<D: AsRef<[u8]>>(&mut self, data: D) {
            primitives::script::ScriptBuf::push_slice(self, data)
        }

        /// Adds instructions to push some arbitrary data onto the stack without minimality.
        fn push_slice_non_minimal<D: AsRef<[u8]>>(&mut self, data: D) {
            primitives::script::ScriptBuf::push_slice_non_minimal(self, data)
        }

        /// Adds a single instruction to the script.
        fn push_instruction(&mut self, instruction: Instruction<'_>) {
            primitives::script::ScriptBuf::push_instruction(self, instruction)
        }

        /// Adds an `OP_VERIFY` to the script or replaces the last opcode with VERIFY form.
        fn scan_and_push_verify(&mut self) {
            primitives::script::ScriptBuf::scan_and_push_verify(self)
        }

        /// Generates P2WPKH-type of scriptPubkey.
        fn new_p2wpkh(pubkey_hash: WPubkeyHash) -> Self {
            script::new_witness_program_unchecked(WitnessVersion::V0, pubkey_hash.to_byte_array())
        }
    }
}

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for the [`ScriptPubKeyBuf`] type.
    pub trait ScriptPubKeyBufExt impl for ScriptPubKeyBuf {
        /// Generates OP_RETURN-type of scriptPubkey for the given data.
        fn new_op_return<T: AsRef<[u8]>>(data: T) -> Self {
            Builder::new().push_opcode(crate::opcodes::all::OP_RETURN).push_slice(data).into_script()
        }

        /// Generates P2PKH-type of scriptPubkey.
        fn new_p2pkh(pubkey_hash: PubkeyHash) -> Self {
            Builder::new()
                .push_opcode(crate::opcodes::all::OP_DUP)
                .push_opcode(crate::opcodes::all::OP_HASH160)
                .push_slice(pubkey_hash)
                .push_opcode(crate::opcodes::all::OP_EQUALVERIFY)
                .push_opcode(crate::opcodes::all::OP_CHECKSIG)
                .into_script()
        }

        /// Generates P2SH-type of scriptPubkey with a given hash of the redeem script.
        fn new_p2sh(script_hash: ScriptHash) -> Self {
            Builder::new()
                .push_opcode(crate::opcodes::all::OP_HASH160)
                .push_slice(script_hash.to_byte_array())
                .push_opcode(crate::opcodes::all::OP_EQUAL)
                .into_script()
        }

        /// Generates P2WSH-type of scriptPubkey with a given hash of the redeem script.
        fn new_p2wsh(script_hash: WScriptHash) -> Self {
            script::new_witness_program_unchecked(WitnessVersion::V0, script_hash.to_byte_array())
        }

        /// Generates pay-to-anchor output.
        fn new_p2a() -> Self {
            script::new_witness_program_unchecked(WitnessVersion::V1, P2A_PROGRAM)
        }

        /// Generates P2WSH-type of scriptPubkey with a given [`WitnessProgram`].
        fn new_witness_program(witness_program: &WitnessProgram) -> Self {
            Builder::new()
                .push_opcode(witness_program.version().into())
                .push_slice(witness_program.program())
                .into_script()
        }
    }
}
