//! The Tidecoin segregated witness program.
//!
//! > A script pubkey consisting of a 1-byte push opcode (for 0 to 16) followed by a data push
//! > between 2 and 64 bytes is a witness program. The value of the first push is the "version
//! > byte"; the following byte vector is the witness program.
//!
use internals::array_vec::ArrayVec;
use primitives::script::{
    validate_witness_program, ParsedWitnessProgram, WitnessProgramClass as PrimitiveClass,
};

use super::witness_version::WitnessVersion;
use super::{PushBytes, WScriptHash, WitnessScript, WitnessScriptSizeError};
use crate::crypto::key::WPubkeyHash;
use crate::script::WitnessScriptExt as _;

/// The minimum byte size of a segregated witness program.
pub const MIN_SIZE: usize = primitives::script::WITNESS_PROGRAM_MIN_SIZE;

/// The maximum byte size of a segregated witness program.
pub const MAX_SIZE: usize = primitives::script::WITNESS_PROGRAM_MAX_SIZE;

/// The P2A program which is given by 0x4e73.
pub(crate) use primitives::script::P2A_PROGRAM;

/// The segregated witness program.
///
/// The segregated witness program is technically only the program bytes _excluding_ the witness
/// version, however we maintain length invariants on the `program` that are governed by the version
/// number, therefore we carry the version number around along with the program bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessProgram {
    /// The SegWit version associated with this witness program.
    version: WitnessVersion,
    /// The witness program (between 2 and 64 bytes).
    program: ArrayVec<u8, MAX_SIZE>,
}

impl WitnessProgram {
    /// Constructs a new witness program, copying the content from the given byte slice.
    pub fn new(version: WitnessVersion, bytes: &[u8]) -> Result<Self, Error> {
        validate_witness_program(version.to_num(), bytes.len())?;

        let program = ArrayVec::from_slice(bytes);
        Ok(Self { version, program })
    }

    /// Constructs a new [`WitnessProgram`] from a 20 byte pubkey hash.
    fn new_p2wpkh(program: [u8; 20]) -> Self {
        Self { version: WitnessVersion::V0, program: ArrayVec::from_slice(&program) }
    }

    /// Constructs a new [`WitnessProgram`] from a 32 byte script hash.
    fn new_p2wsh(program: [u8; 32]) -> Self {
        Self { version: WitnessVersion::V0, program: ArrayVec::from_slice(&program) }
    }

    /// Constructs a new [`WitnessProgram`] from a 64-byte SHA-512 script hash (P2WSH-512).
    fn new_p2wsh512(program: [u8; 64]) -> Self {
        Self { version: WitnessVersion::V1, program: ArrayVec::from_slice(&program) }
    }

    /// Constructs a new [`WitnessProgram`] from a witness pubkey hash for a P2WPKH output.
    pub fn p2wpkh(pubkey_hash: WPubkeyHash) -> Self {
        Self::new_p2wpkh(pubkey_hash.to_byte_array())
    }

    /// Constructs a new [`WitnessProgram`] from `script` for a P2WSH output.
    pub fn p2wsh(script: &WitnessScript) -> Result<Self, WitnessScriptSizeError> {
        script.wscript_hash().map(Self::p2wsh_from_hash)
    }

    /// Constructs a new [`WitnessProgram`] from a script hash for a P2WSH output.
    pub fn p2wsh_from_hash(hash: WScriptHash) -> Self {
        Self::new_p2wsh(hash.to_byte_array())
    }

    /// Constructs a new [`WitnessProgram`] from a 64-byte SHA-512 script hash for a P2WSH-512 output.
    pub fn p2wsh512(hash: [u8; 64]) -> Self {
        Self::new_p2wsh512(hash)
    }

    /// Constructs a new [`WitnessProgram`] for a P2A output.
    pub const fn p2a() -> Self {
        Self { version: WitnessVersion::V1, program: ArrayVec::from_slice(&P2A_PROGRAM) }
    }

    /// Returns the witness program version.
    pub fn version(&self) -> WitnessVersion {
        self.version
    }

    /// Returns the witness program.
    pub fn program(&self) -> &PushBytes {
        self.program
            .as_slice()
            .try_into()
            .expect("witness programs are always smaller than max size of PushBytes")
    }

    /// Returns true if this witness program is for a P2WPKH output.
    pub fn is_p2wpkh(&self) -> bool {
        self.class() == PrimitiveClass::P2wpkh
    }

    /// Returns true if this witness program is for a P2WSH output.
    pub fn is_p2wsh(&self) -> bool {
        self.class() == PrimitiveClass::P2wsh
    }

    /// Returns true if this witness program is for a P2WSH-512 output.
    pub fn is_p2wsh512(&self) -> bool {
        self.class() == PrimitiveClass::P2wsh512
    }

    /// Returns true if this witness program is for a P2A output.
    pub fn is_p2a(&self) -> bool {
        self.class() == PrimitiveClass::P2a
    }

    fn class(&self) -> PrimitiveClass {
        ParsedWitnessProgram::from_program(self.version.to_num(), self.program.as_slice()).class()
    }
}

/// Witness program error.
pub type Error = primitives::script::WitnessProgramError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_program_is_too_short() {
        let arbitrary_bytes = [0x00; MIN_SIZE - 1];
        assert!(WitnessProgram::new(WitnessVersion::V15, &arbitrary_bytes).is_err());
        // Arbitrary version
    }

    #[test]
    fn witness_program_is_too_long() {
        let arbitrary_bytes = [0x00; MAX_SIZE + 1];
        assert!(WitnessProgram::new(WitnessVersion::V15, &arbitrary_bytes).is_err());
        // Arbitrary version
    }

    #[test]
    fn valid_v0_witness_programs() {
        let arbitrary_bytes = [0x00; MAX_SIZE];

        for size in MIN_SIZE..=40 {
            let program = WitnessProgram::new(WitnessVersion::V0, &arbitrary_bytes[..size]);

            if size == 20 {
                assert!(program.expect("valid witness program").is_p2wpkh());
                continue;
            }
            if size == 32 {
                assert!(program.expect("valid witness program").is_p2wsh());
                continue;
            }
            assert!(program.is_err());
        }
    }

    #[test]
    fn valid_v1_witness_programs() {
        let p2a_bytes = [78, 115];
        assert!(WitnessProgram::new(WitnessVersion::V1, &p2a_bytes)
            .expect("valid witness program")
            .is_p2a());

        let arbitrary_64 = [0x00; 64];
        assert!(WitnessProgram::new(WitnessVersion::V1, &arbitrary_64)
            .expect("valid witness program")
            .is_p2wsh512());
    }

    #[test]
    fn v1_32_byte_program_remains_unclassified() {
        let arbitrary_bytes = [0x00; 32];
        let program = WitnessProgram::new(WitnessVersion::V1, &arbitrary_bytes)
            .expect("valid witness program");

        assert_eq!(program.version(), WitnessVersion::V1);
        assert!(!program.is_p2a());
        assert!(!program.is_p2wsh512());
    }
}
