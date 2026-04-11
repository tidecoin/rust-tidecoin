// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use primitives::script::Builder as PrimitiveBuilder;

use super::{Error, Script, ScriptBuf};
use crate::locktime::absolute;
use crate::relative;

/// An object used to construct scripts piece by piece.
#[derive(PartialEq, Eq, Clone)]
pub struct Builder<T>(PrimitiveBuilder<T>);

impl<T> Builder<T> {
    /// Constructs a new empty script.
    #[inline]
    pub const fn new() -> Self {
        Self(PrimitiveBuilder::new())
    }

    /// Constructs a new empty script builder with at least the specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(PrimitiveBuilder::with_capacity(capacity))
    }

    /// Returns the length in bytes of the script.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Checks whether the script is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Adds instructions to push an integer onto the stack.
    pub fn push_int(self, n: i32) -> Result<Self, Error> {
        self.0.push_int(n).map(Self).map_err(Into::into)
    }

    /// Adds instructions to push an unchecked integer onto the stack.
    pub fn push_int_unchecked(self, n: i64) -> Self {
        Self(self.0.push_int_unchecked(n))
    }

    /// Adds instructions to push an integer onto the stack without optimization.
    pub(in crate::blockdata) fn push_int_non_minimal(self, data: i64) -> Self {
        Self(self.0.push_int_non_minimal(data))
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    pub fn push_slice<D: AsRef<[u8]>>(self, data: D) -> Self {
        Self(self.0.push_slice(data))
    }

    /// Adds instructions to push some arbitrary data onto the stack without minimality.
    pub fn push_slice_non_minimal<D: AsRef<[u8]>>(self, data: D) -> Self {
        Self(self.0.push_slice_non_minimal(data))
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(self, data: crate::opcodes::Opcode) -> Self {
        Self(self.0.push_opcode(data))
    }

    /// Adds an `OP_VERIFY` to the script or rewrites the last opcode to VERIFY form.
    pub fn push_verify(self) -> Self {
        Self(self.0.push_verify())
    }

    /// Adds instructions to push an absolute lock time onto the stack.
    pub fn push_lock_time(self, lock_time: absolute::LockTime) -> Self {
        self.push_int_unchecked(lock_time.to_consensus_u32().into())
    }

    /// Adds instructions to push a relative lock time onto the stack.
    pub fn push_relative_lock_time(self, lock_time: relative::LockTime) -> Self {
        self.push_int_unchecked(lock_time.to_consensus_u32().into())
    }

    /// Converts the `Builder` into `ScriptBuf`.
    pub fn into_script(self) -> ScriptBuf<T> {
        self.0.into_script()
    }

    /// Converts the `Builder` into script bytes.
    pub fn into_bytes(self) -> crate::prelude::Vec<u8> {
        self.0.into_bytes()
    }

    /// Returns the internal script.
    pub fn as_script(&self) -> &Script<T> {
        self.0.as_script()
    }

    /// Returns script bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<T> Default for Builder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> From<crate::prelude::Vec<u8>> for Builder<T> {
    fn from(v: crate::prelude::Vec<u8>) -> Self {
        Self(PrimitiveBuilder::from(v))
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
