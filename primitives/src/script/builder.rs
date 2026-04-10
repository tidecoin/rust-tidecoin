// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use super::{Error, Script, ScriptBuf};
use crate::opcodes::all::{
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_EQUAL,
    OP_EQUALVERIFY, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_VERIFY,
};
use crate::opcodes::Opcode;
use crate::prelude::Vec;

/// Script builder.
#[derive(PartialEq, Eq, Clone)]
pub struct Builder<T>(ScriptBuf<T>, Option<Opcode>);

impl<T> Builder<T> {
    /// Creates a new empty builder.
    pub const fn new() -> Self {
        Self(ScriptBuf::new(), None)
    }

    /// Creates a builder with reserved capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(ScriptBuf::with_capacity(capacity), None)
    }

    /// Returns the script length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the builder is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Pushes an integer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NumericOverflow`] when `n` is outside the minimally encodable range.
    pub fn push_int(mut self, n: i32) -> Result<Self, Error> {
        self.0.push_int(n)?;
        self.1 = None;
        Ok(self)
    }

    /// Pushes an integer without range checking.
    #[must_use]
    pub fn push_int_unchecked(mut self, n: i64) -> Self {
        self.0.push_int_unchecked(n);
        self.1 = None;
        self
    }

    /// Pushes an integer without numeric-opcode optimization.
    #[must_use]
    pub fn push_int_non_minimal(mut self, data: i64) -> Self {
        self.0.push_int_non_minimal(data);
        self.1 = None;
        self
    }

    /// Pushes a slice.
    #[must_use]
    pub fn push_slice<D: AsRef<[u8]>>(mut self, data: D) -> Self {
        self.0.push_slice(data);
        self.1 = None;
        self
    }

    /// Pushes a slice without minimal-push optimization.
    #[must_use]
    pub fn push_slice_non_minimal<D: AsRef<[u8]>>(mut self, data: D) -> Self {
        self.0.push_slice_non_minimal(data);
        self.1 = None;
        self
    }

    /// Pushes an opcode.
    #[must_use]
    pub fn push_opcode(mut self, opcode: Opcode) -> Self {
        self.0.push_opcode(opcode);
        self.1 = Some(opcode);
        self
    }

    /// Adds `OP_VERIFY` or rewrites the most recent opcode to its VERIFY form when possible.
    #[must_use]
    pub fn push_verify(mut self) -> Self {
        match opcode_to_verify(self.1) {
            Some(opcode) => {
                self.0.as_byte_vec().pop();
                self.push_opcode(opcode)
            }
            None => self.push_opcode(OP_VERIFY),
        }
    }

    /// Converts into a script.
    pub fn into_script(self) -> ScriptBuf<T> {
        self.0
    }

    /// Converts into raw bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    /// Returns the current script.
    pub fn as_script(&self) -> &Script<T> {
        self.0.as_script()
    }

    /// Returns the raw script bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<T> Default for Builder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> From<Vec<u8>> for Builder<T> {
    fn from(v: Vec<u8>) -> Self {
        let script = ScriptBuf::from_bytes(v);
        let last_op = script.last_opcode();
        Self(script, last_op)
    }
}

impl<T> fmt::Display for Builder<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<T> fmt::Debug for Builder<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

fn opcode_to_verify(opcode: Option<Opcode>) -> Option<Opcode> {
    opcode.and_then(|opcode| match opcode {
        OP_EQUAL => Some(OP_EQUALVERIFY),
        OP_NUMEQUAL => Some(OP_NUMEQUALVERIFY),
        OP_CHECKSIG => Some(OP_CHECKSIGVERIFY),
        OP_CHECKMULTISIG => Some(OP_CHECKMULTISIGVERIFY),
        _ => None,
    })
}
