// SPDX-License-Identifier: CC0-1.0

//! Shared Tidecoin witness-program parsing and validation helpers.

use alloc::vec::Vec;

use crate::{ScriptError, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, VERIFY_WITNESS_V1_512};
use hashes::{sha256, sha512};
use primitives::{
    opcodes::all,
    script::{
        Builder as ScriptBuilderT, ParsedWitnessProgram, PushBytesBuf,
        WitnessProgramClass as PrimitiveWitnessProgramClass,
    },
    Witness,
};

type Builder = ScriptBuilderT<()>;

/// Consensus classification for a parsed witness program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessProgramClass {
    /// Native witness-v0 key-hash program.
    P2wpkh,
    /// Native witness-v0 script-hash program.
    P2wsh,
    /// Tidecoin witness-v1-512 program.
    WitnessV1_512,
    /// Future/upgradable witness version that is currently treated as no-op.
    Upgradable,
}

/// Signature-hash mode used by witness execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessSigVersion {
    /// Segwit v0 signature hashing.
    V0,
    /// Tidecoin witness-v1-512 signature hashing.
    V1_512,
}

/// Sigop accounting mode required before executing a witness script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessSigops {
    /// No extra sigops need to be accounted for before execution.
    None,
    /// A fixed number of sigops should be added.
    Fixed(u32),
    /// Sigops should be counted from the executed script.
    CountExecutedScript,
}

/// Shared execution plan for a validated witness program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessExecutionPlan {
    /// Upgradable witness program versions are accepted as no-op under current flags.
    Upgradable,
    /// Execute the provided script with the prepared witness stack.
    Execute {
        /// Signature-hash mode to use while executing the script.
        sigversion: WitnessSigVersion,
        /// Script bytes to execute.
        script_bytes: Vec<u8>,
        /// Initial witness stack items, excluding the executed script when present.
        stack_items: Vec<Vec<u8>>,
        /// Additional sigop accounting required before execution.
        sigops: WitnessSigops,
    },
}

/// Parsed witness program view over a scriptPubKey byte slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessProgram<'a>(ParsedWitnessProgram<'a>);

impl<'a> WitnessProgram<'a> {
    /// Creates a witness program view from an already-parsed version and program.
    pub fn parse_program(version: u8, program: &'a [u8]) -> Self {
        Self(ParsedWitnessProgram::from_program(version, program))
    }

    /// Parses a witness program from scriptPubKey bytes.
    pub fn parse(script_bytes: &'a [u8]) -> Option<Self> {
        ParsedWitnessProgram::parse_script_pubkey(script_bytes).map(Self)
    }

    /// Returns the witness version.
    pub fn version(self) -> u8 {
        self.0.version()
    }

    /// Returns the witness program bytes.
    pub fn program(self) -> &'a [u8] {
        self.0.program()
    }

    /// Returns whether the script is a Tidecoin witness-v1-512 program.
    pub fn is_v1_512(script_bytes: &'a [u8]) -> bool {
        Self::parse(script_bytes)
            .is_some_and(|program| program.0.class() == PrimitiveWitnessProgramClass::P2wsh512)
    }

    /// Classifies the parsed witness program under the provided verification flags.
    pub fn classify(self, flags: u32) -> Result<WitnessProgramClass, ScriptError> {
        match self.version() {
            0 => match self.0.class() {
                PrimitiveWitnessProgramClass::P2wpkh => Ok(WitnessProgramClass::P2wpkh),
                PrimitiveWitnessProgramClass::P2wsh => Ok(WitnessProgramClass::P2wsh),
                PrimitiveWitnessProgramClass::P2wsh512
                | PrimitiveWitnessProgramClass::P2a
                | PrimitiveWitnessProgramClass::Upgradable => {
                    Err(ScriptError::WitnessProgramWrongLength)
                }
            },
            1 => {
                if flags & VERIFY_WITNESS_V1_512 == 0 {
                    if flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM != 0 {
                        Err(ScriptError::DiscourageUpgradableWitnessProgram)
                    } else {
                        Ok(WitnessProgramClass::Upgradable)
                    }
                } else {
                    match self.0.class() {
                        PrimitiveWitnessProgramClass::P2wsh512 => {
                            Ok(WitnessProgramClass::WitnessV1_512)
                        }
                        PrimitiveWitnessProgramClass::P2wpkh
                        | PrimitiveWitnessProgramClass::P2wsh
                        | PrimitiveWitnessProgramClass::P2a
                        | PrimitiveWitnessProgramClass::Upgradable => {
                            Err(ScriptError::WitnessProgramWrongLength)
                        }
                    }
                }
            }
            2..=16 => {
                if flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM != 0 {
                    Err(ScriptError::DiscourageUpgradableWitnessProgram)
                } else {
                    Ok(WitnessProgramClass::Upgradable)
                }
            }
            _ => Ok(WitnessProgramClass::Upgradable),
        }
    }

    /// Builds an execution plan for this witness program and witness stack.
    pub fn execution_plan(
        self,
        flags: u32,
        witness: &Witness,
    ) -> Result<WitnessExecutionPlan, ScriptError> {
        match self.classify(flags)? {
            WitnessProgramClass::P2wpkh => build_p2wpkh_plan(self.program(), witness),
            WitnessProgramClass::P2wsh => build_p2wsh_plan(self.program(), witness),
            WitnessProgramClass::WitnessV1_512 => {
                build_witness_v1_512_plan(self.program(), witness)
            }
            WitnessProgramClass::Upgradable => Ok(WitnessExecutionPlan::Upgradable),
        }
    }
}

fn build_p2wpkh_plan(
    program: &[u8],
    witness: &Witness,
) -> Result<WitnessExecutionPlan, ScriptError> {
    if witness.len() != 2 {
        return Err(ScriptError::WitnessProgramMismatch);
    }

    let program_bytes = PushBytesBuf::try_from(program.to_vec())
        .map_err(|_| ScriptError::WitnessProgramWrongLength)?;
    let script = Builder::new()
        .push_opcode(all::OP_DUP)
        .push_opcode(all::OP_HASH160)
        .push_slice(program_bytes)
        .push_opcode(all::OP_EQUALVERIFY)
        .push_opcode(all::OP_CHECKSIG)
        .into_script();

    Ok(WitnessExecutionPlan::Execute {
        sigversion: WitnessSigVersion::V0,
        script_bytes: script.into_bytes(),
        stack_items: witness_items(witness, witness.len()),
        sigops: WitnessSigops::Fixed(1),
    })
}

fn build_p2wsh_plan(
    program: &[u8],
    witness: &Witness,
) -> Result<WitnessExecutionPlan, ScriptError> {
    if witness.is_empty() {
        return Err(ScriptError::WitnessProgramWitnessEmpty);
    }

    let witness_script_bytes = witness[witness.len() - 1].as_ref();
    let script_hash = sha256::Hash::hash(witness_script_bytes);
    let hash_bytes: &[u8] = script_hash.as_ref();
    if hash_bytes != program {
        return Err(ScriptError::WitnessProgramMismatch);
    }

    Ok(WitnessExecutionPlan::Execute {
        sigversion: WitnessSigVersion::V0,
        script_bytes: witness_script_bytes.to_vec(),
        stack_items: witness_items(witness, witness.len() - 1),
        sigops: WitnessSigops::CountExecutedScript,
    })
}

fn build_witness_v1_512_plan(
    program: &[u8],
    witness: &Witness,
) -> Result<WitnessExecutionPlan, ScriptError> {
    if witness.is_empty() {
        return Err(ScriptError::WitnessProgramWitnessEmpty);
    }

    let exec_script_bytes = witness[witness.len() - 1].as_ref();
    let script_hash = sha512::Hash::hash(exec_script_bytes);
    if script_hash.as_byte_array() != program {
        return Err(ScriptError::WitnessProgramMismatch);
    }

    Ok(WitnessExecutionPlan::Execute {
        sigversion: WitnessSigVersion::V1_512,
        script_bytes: exec_script_bytes.to_vec(),
        stack_items: witness_items(witness, witness.len() - 1),
        sigops: WitnessSigops::None,
    })
}

fn witness_items(witness: &Witness, end: usize) -> Vec<Vec<u8>> {
    witness.iter().take(end).map(|elem| elem.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{
        WitnessExecutionPlan, WitnessProgram, WitnessProgramClass, WitnessSigVersion, WitnessSigops,
    };
    use crate::{ScriptError, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, VERIFY_WITNESS_V1_512};
    use hashes::sha512;
    use primitives::Witness;

    #[test]
    fn parses_witness_v0_program() {
        let script = [
            0x00, 0x20, 1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let program = WitnessProgram::parse(&script).expect("witness program");
        assert_eq!(program.version(), 0);
        assert_eq!(program.program().len(), 32);
    }

    #[test]
    fn detects_tidecoin_witness_v1_512_program() {
        let mut script = vec![0x51, 64];
        script.extend_from_slice(&[7u8; 64]);
        let program = WitnessProgram::parse(&script).expect("witness program");
        assert_eq!(program.version(), 1);
        assert_eq!(program.program(), &[7u8; 64]);
        assert!(WitnessProgram::is_v1_512(&script));
    }

    #[test]
    fn rejects_noncanonical_push_length() {
        let script = [0x51, 0x4c, 0x40];
        assert!(WitnessProgram::parse(&script).is_none());
    }

    #[test]
    fn classifies_witness_v0_program_lengths() {
        let p2wpkh = WitnessProgram::parse(&[
            0x00, 20, 9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .expect("p2wpkh");
        assert_eq!(p2wpkh.classify(0).expect("classify"), WitnessProgramClass::P2wpkh);

        let mut p2wsh_bytes = vec![0x00, 32];
        p2wsh_bytes.extend_from_slice(&[5u8; 32]);
        let p2wsh = WitnessProgram::parse(&p2wsh_bytes).expect("p2wsh");
        assert_eq!(p2wsh.classify(0).expect("classify"), WitnessProgramClass::P2wsh);
    }

    #[test]
    fn witness_v1_512_requires_feature_flag() {
        let mut script = vec![0x51, 64];
        script.extend_from_slice(&[1u8; 64]);
        let witness_program = WitnessProgram::parse(&script).expect("witness v1");

        assert_eq!(
            witness_program.classify(0).expect("upgradable"),
            WitnessProgramClass::Upgradable
        );
        assert_eq!(
            witness_program.classify(VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM),
            Err(ScriptError::DiscourageUpgradableWitnessProgram)
        );
        assert_eq!(
            witness_program.classify(VERIFY_WITNESS_V1_512).expect("v1 enabled"),
            WitnessProgramClass::WitnessV1_512
        );
    }

    #[test]
    fn builds_p2wpkh_execution_plan() {
        let mut script = vec![0x00, 20];
        script.extend_from_slice(&[3u8; 20]);
        let witness_program = WitnessProgram::parse(&script).expect("p2wpkh");
        let witness = Witness::from(vec![vec![1u8; 64], vec![2u8; 33]]);
        let plan = witness_program.execution_plan(0, &witness).expect("plan");

        match plan {
            WitnessExecutionPlan::Execute { sigversion, script_bytes, stack_items, sigops } => {
                assert_eq!(sigversion, WitnessSigVersion::V0);
                assert_eq!(sigops, WitnessSigops::Fixed(1));
                assert_eq!(stack_items.len(), 2);
                assert!(!script_bytes.is_empty());
            }
            WitnessExecutionPlan::Upgradable => panic!("unexpected upgradable plan"),
        }
    }

    #[test]
    fn builds_witness_v1_512_execution_plan() {
        let exec_script = vec![0x51];
        let program_hash = sha512::Hash::hash(&exec_script);
        let mut script = vec![0x51, 64];
        script.extend_from_slice(program_hash.as_byte_array());
        let witness_program = WitnessProgram::parse(&script).expect("witness v1");
        let witness = Witness::from(vec![vec![1u8], exec_script.clone()]);
        let plan = witness_program.execution_plan(VERIFY_WITNESS_V1_512, &witness).expect("plan");

        match plan {
            WitnessExecutionPlan::Execute { sigversion, script_bytes, stack_items, sigops } => {
                assert_eq!(sigversion, WitnessSigVersion::V1_512);
                assert_eq!(sigops, WitnessSigops::None);
                assert_eq!(script_bytes, exec_script);
                assert_eq!(stack_items, vec![vec![1u8]]);
            }
            WitnessExecutionPlan::Upgradable => panic!("unexpected upgradable plan"),
        }
    }
}
