// SPDX-License-Identifier: CC0-1.0

//! Primitive witness-program parsing and classification.

use core::convert::Infallible;
use core::fmt;

/// Minimum byte size of a witness program.
pub const WITNESS_PROGRAM_MIN_SIZE: usize = 2;
/// Maximum byte size of a witness program.
pub const WITNESS_PROGRAM_MAX_SIZE: usize = 64;
/// The Tidecoin pay-to-anchor witness-v1 program.
pub const P2A_PROGRAM: [u8; 2] = [78, 115];

/// Primitive witness-program class independent of consensus activation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessProgramClass {
    /// Native witness-v0 key-hash program.
    P2wpkh,
    /// Native witness-v0 script-hash program.
    P2wsh,
    /// Tidecoin witness-v1 SHA-512 script-hash program.
    P2wsh512,
    /// Tidecoin pay-to-anchor program.
    P2a,
    /// Any currently unassigned witness program.
    Upgradable,
}

/// Witness-program shape error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WitnessProgramError {
    /// The witness program must be between 2 and 64 bytes in length.
    InvalidLength(usize),
    /// A v0 witness program must be either 20 or 32 bytes.
    InvalidSegwitV0Length(usize),
}

impl From<Infallible> for WitnessProgramError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for WitnessProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(len) => {
                write!(f, "witness program must be between 2 and 64 bytes: length={}", len)
            }
            Self::InvalidSegwitV0Length(len) => {
                write!(f, "a v0 witness program must be either 20 or 32 bytes: length={}", len)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessProgramError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidLength(_) | Self::InvalidSegwitV0Length(_) => None,
        }
    }
}

/// Parsed witness-program view over a scriptPubKey byte slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedWitnessProgram<'a> {
    version: u8,
    program: &'a [u8],
}

impl<'a> ParsedWitnessProgram<'a> {
    /// Creates a witness-program view from an already parsed version and program.
    pub fn from_program(version: u8, program: &'a [u8]) -> Self {
        Self { version, program }
    }

    /// Parses a canonical direct-push witness program from scriptPubKey bytes.
    pub fn parse_script_pubkey(script_bytes: &'a [u8]) -> Option<Self> {
        if script_bytes.len() < WITNESS_PROGRAM_MIN_SIZE + 2 {
            return None;
        }

        let version = match script_bytes[0] {
            0x00 => 0,
            0x51..=0x60 => script_bytes[0] - 0x50,
            _ => return None,
        };
        let push_len = parse_direct_push_len(script_bytes.get(1).copied())?;
        if script_bytes.len() != push_len + 2 {
            return None;
        }

        Some(Self { version, program: &script_bytes[2..] })
    }

    /// Returns the witness version number.
    pub fn version(self) -> u8 {
        self.version
    }

    /// Returns the witness program bytes.
    pub fn program(self) -> &'a [u8] {
        self.program
    }

    /// Classifies this witness program without applying consensus activation flags.
    pub fn class(self) -> WitnessProgramClass {
        classify_witness_program(self.version, self.program)
    }
}

/// Validates address/output-level witness-program length rules.
///
/// # Errors
///
/// Returns [`WitnessProgramError::InvalidLength`] when the program is outside the canonical
/// 2-byte to 64-byte witness-program range, and [`WitnessProgramError::InvalidSegwitV0Length`]
/// when a witness-v0 program is not 20 or 32 bytes.
pub fn validate_witness_program(
    version: u8,
    program_len: usize,
) -> Result<(), WitnessProgramError> {
    if !(WITNESS_PROGRAM_MIN_SIZE..=WITNESS_PROGRAM_MAX_SIZE).contains(&program_len) {
        return Err(WitnessProgramError::InvalidLength(program_len));
    }
    if version == 0 && program_len != 20 && program_len != 32 {
        return Err(WitnessProgramError::InvalidSegwitV0Length(program_len));
    }
    Ok(())
}

/// Classifies a witness program without applying consensus activation flags.
pub fn classify_witness_program(version: u8, program: &[u8]) -> WitnessProgramClass {
    match (version, program.len()) {
        (0, 20) => WitnessProgramClass::P2wpkh,
        (0, 32) => WitnessProgramClass::P2wsh,
        (1, 64) => WitnessProgramClass::P2wsh512,
        (1, 2) if program == P2A_PROGRAM => WitnessProgramClass::P2a,
        _ => WitnessProgramClass::Upgradable,
    }
}

fn parse_direct_push_len(opcode: Option<u8>) -> Option<usize> {
    let value = opcode?;
    if value <= 75 {
        Some(value as usize)
    } else {
        None
    }
}
