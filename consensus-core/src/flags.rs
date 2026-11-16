// SPDX-License-Identifier: CC0-1.0

/// No verification flags.
pub const VERIFY_NONE: u32 = 0;
/// Verify pay-to-script-hash rules.
pub const VERIFY_P2SH: u32 = 1 << 0;
/// Require minimal push encodings.
pub const VERIFY_MINIMALDATA: u32 = 1 << 3;
/// Require a null multisig dummy argument.
pub const VERIFY_NULLDUMMY: u32 = 1 << 1;
/// Require push-only `scriptSig` data.
pub const VERIFY_SIGPUSHONLY: u32 = 1 << 2;
/// Require a single true stack item after execution.
pub const VERIFY_CLEANSTACK: u32 = 1 << 5;
/// Enforce `MINIMALIF`.
pub const VERIFY_MINIMALIF: u32 = 1 << 10;
/// Enforce `NULLFAIL`.
pub const VERIFY_NULLFAIL: u32 = 1 << 11;
/// Enforce `CHECKLOCKTIMEVERIFY`.
pub const VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 6;
/// Enforce `CHECKSEQUENCEVERIFY`.
pub const VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 7;
/// Enable witness-v0 validation.
pub const VERIFY_WITNESS: u32 = 1 << 8;
/// Discourage upgradable NOPs.
pub const VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 1 << 4;
/// Discourage unknown witness program versions.
pub const VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: u32 = 1 << 9;
/// Forbid mutating the script code during signature evaluation.
pub const VERIFY_CONST_SCRIPTCODE: u32 = 1 << 12;
/// Reject legacy Falcon-512 signatures.
pub const VERIFY_PQ_STRICT: u32 = 1 << 13;
/// Enable native Tidecoin witness-v1-512 validation.
pub const VERIFY_WITNESS_V1_512: u32 = 1 << 14;
/// Enable Tidecoin `OP_SHA512`.
pub const VERIFY_SHA512: u32 = 1 << 15;

/// Require one of the six defined hash bytes for nonempty signatures.
/// This is relay policy for legacy/v0; active witness v1 enforces it independently.
pub const VERIFY_DEFINED_HASHTYPE: u32 = 1 << 16;

/// Tidecoin's default verification flags.
pub const VERIFY_ALL_TIDECOIN: u32 = VERIFY_P2SH
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_PQ_STRICT
    | VERIFY_WITNESS_V1_512
    | VERIFY_SHA512;

/// Relay-only rejection of noncanonical historical Falcon-512 encodings.
/// Inactive with PQ_STRICT; not part of consensus or shared signing flags.
pub const VERIFY_FALCON_CANONICAL: u32 = 1 << 17;
