// SPDX-License-Identifier: CC0-1.0

//! Tidecoin post-quantum scheme identifiers and wire metadata.
//!
//! This module is intentionally crypto-backend free. It owns the consensus
//! scheme identity table used by primitives, consensus-core, and the high-level
//! `tidecoin` crate.

/// Identifies which post-quantum signature scheme a key or signature belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PqScheme {
    /// Falcon-512 (prefix `0x07`).
    Falcon512 = 0x07,
    /// Falcon-1024 (prefix `0x08`).
    Falcon1024 = 0x08,
    /// ML-DSA-44 (prefix `0x09`).
    MlDsa44 = 0x09,
    /// ML-DSA-65 (prefix `0x0A`).
    MlDsa65 = 0x0A,
    /// ML-DSA-87 (prefix `0x0B`).
    MlDsa87 = 0x0B,
}

impl PqScheme {
    /// All PQ signature schemes currently known to Tidecoin policy and consensus code.
    pub const KNOWN: [Self; 5] =
        [Self::Falcon512, Self::Falcon1024, Self::MlDsa44, Self::MlDsa65, Self::MlDsa87];

    /// Resolves a scheme from its on-wire prefix byte.
    pub const fn from_prefix(byte: u8) -> Option<Self> {
        match byte {
            0x07 => Some(Self::Falcon512),
            0x08 => Some(Self::Falcon1024),
            0x09 => Some(Self::MlDsa44),
            0x0A => Some(Self::MlDsa65),
            0x0B => Some(Self::MlDsa87),
            _ => None,
        }
    }

    /// Returns the on-wire prefix byte for this scheme.
    pub const fn prefix(self) -> u8 {
        self as u8
    }

    /// Raw public key length in bytes, without the one-byte scheme prefix.
    pub const fn pubkey_len(self) -> usize {
        match self {
            Self::Falcon512 => 897,
            Self::Falcon1024 => 1793,
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Secret key length in bytes, without the one-byte scheme prefix.
    pub const fn seckey_len(self) -> usize {
        match self {
            Self::Falcon512 => 1281,
            Self::Falcon1024 => 2305,
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// Maximum signature length in bytes, without the trailing sighash byte.
    pub const fn max_sig_len(self) -> usize {
        match self {
            Self::Falcon512 => 752,
            Self::Falcon1024 => 1462,
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// Maximum detached signature returned by the rc3 local signer.
    /// External signatures may be longer; verification uses its own bounds.
    pub const fn local_signing_max_sig_len(self) -> usize {
        match self {
            Self::Falcon512 => 666,
            Self::Falcon1024 => 1280,
            _ => self.max_sig_len(),
        }
    }

    /// Maximum serialized script signature length including the trailing sighash byte.
    pub const fn max_sig_len_in_script(self) -> usize {
        self.max_sig_len() + 1
    }

    /// Public key length including the one-byte scheme prefix.
    pub const fn prefixed_pubkey_len(self) -> usize {
        self.pubkey_len() + 1
    }

    /// Secret key length including the one-byte scheme prefix.
    pub const fn prefixed_seckey_len(self) -> usize {
        self.seckey_len() + 1
    }

    /// Deterministic keygen seed length used by Tidecoin PQHD v1.
    pub const fn deterministic_seed_len(self) -> usize {
        match self {
            Self::Falcon512 | Self::Falcon1024 => 48,
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => 32,
        }
    }

    /// Returns whether this scheme is allowed for the given auxpow activation state.
    ///
    /// Tidecoin permits only Falcon-512 before auxpow activation. Once auxpow is active,
    /// all current PQ schemes are allowed.
    pub const fn is_allowed_at_height(self, height: u32, auxpow_start_height: Option<u32>) -> bool {
        match auxpow_start_height {
            Some(start_height) if height >= start_height => true,
            _ => matches!(self, Self::Falcon512),
        }
    }
}
