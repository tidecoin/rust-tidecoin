// SPDX-License-Identifier: CC0-1.0

use consensus_core::PqPublicKey;

use crate::opcodes::all::OP_SHA512;
use crate::opcodes::Opcode;
use crate::script::{Instruction, Script, ScriptExt as _, ScriptPubKey, WitnessScript};
use crate::transaction::Transaction;
use crate::witness::Witness;

pub(crate) fn should_use_tidecoin_validation(
    script_pubkey: &ScriptPubKey,
    tx: &Transaction,
    index: usize,
    _flags: u32,
) -> bool {
    if script_pubkey.is_p2wsh512()
        || script_contains_pq_material(script_pubkey)
        || script_contains_opcode(script_pubkey, OP_SHA512)
    {
        return true;
    }

    let Some(input) = tx.inputs.get(index) else {
        return false;
    };

    script_contains_pq_material(&input.script_sig)
        || witness_contains_pq_material(&input.witness)
        || witness_contains_opcode_script(&input.witness, OP_SHA512)
}

fn script_contains_opcode<T>(script: &Script<T>, opcode: Opcode) -> bool {
    script.instructions().any(|ins| matches!(ins, Ok(Instruction::Op(op)) if op == opcode))
}

fn script_contains_pq_material<T>(script: &Script<T>) -> bool {
    script.instructions().any(|ins| match ins {
        Ok(Instruction::PushBytes(bytes)) => {
            PqPublicKey::from_prefixed_slice(bytes.as_bytes()).is_ok()
        }
        _ => false,
    })
}

fn witness_contains_pq_material(witness: &Witness) -> bool {
    witness.iter().any(|item| PqPublicKey::from_prefixed_slice(item).is_ok())
}

fn witness_contains_opcode_script(witness: &Witness, opcode: Opcode) -> bool {
    witness
        .last()
        .map(WitnessScript::from_bytes)
        .is_some_and(|script| script_contains_opcode(script, opcode))
}
