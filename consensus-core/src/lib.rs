// SPDX-License-Identifier: CC0-1.0

//! Shared Tidecoin consensus-validation core types.
//!
//! This crate is the shared validation/engine layer used by higher-level
//! Tidecoin crates.
//!
//! In particular, similarly named PQ and validation-side types may exist in
//! both `tidecoin` and `consensus-core`:
//!
//! - `tidecoin::*` is the normal product-facing Rust API
//! - `consensus-core::*` is the lower-level shared verifier/engine API
//!
//! Most downstream application code should start with `tidecoin`. Reach for
//! `consensus-core` directly when you intentionally need shared validation,
//! sighash, or lower-level engine building blocks.

#![no_std]
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod error;
mod flags;
mod interpreter;
mod pq;
mod sighash;
mod tx;
mod verify;
mod witness;

#[doc(inline)]
pub use self::error::{ScriptError, TidecoinValidationError};
#[doc(inline)]
pub use self::flags::{
    VERIFY_ALL_TIDECOIN, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_CLEANSTACK,
    VERIFY_CONST_SCRIPTCODE, VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, VERIFY_MINIMALDATA, VERIFY_MINIMALIF,
    VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_NULLFAIL, VERIFY_P2SH, VERIFY_PQ_STRICT, VERIFY_SHA512,
    VERIFY_SIGPUSHONLY, VERIFY_WITNESS, VERIFY_WITNESS_V1_512,
};
#[doc(inline)]
pub use self::interpreter::{Interpreter, ScriptFlags, ScriptStack, SpendContext};
#[doc(inline)]
pub use self::pq::{PqError, PqPublicKey, PqSignature};
#[doc(inline)]
pub use self::sighash::{
    InputsIndexError, LegacySighash, NonStandardSighashTypeError, SegwitV0Sighash, Sighash512,
    SighashCache, SighashTypeParseError, TxSighashType,
};
#[doc(inline)]
pub use self::tx::{PrecomputedTransactionData, SpentOutputs, TransactionContext};
#[doc(inline)]
pub use self::verify::{
    validate_verification_flags, verify_script_input, verify_script_input_detailed,
    VerificationFailure,
};
#[doc(inline)]
pub use self::witness::{
    WitnessExecutionPlan, WitnessProgram, WitnessProgramClass, WitnessSigVersion, WitnessSigops,
};
pub use primitives::PqScheme;
