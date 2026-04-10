// SPDX-License-Identifier: CC0-1.0

use internals::script::{self, PushDataLenLen};

use super::{Error, PushBytes, Script, ScriptBuf};
use crate::opcodes::{all, Opcode};

/// Parsed script instruction.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Instruction<'a> {
    /// Pushed bytes.
    PushBytes(&'a PushBytes),
    /// Opcode.
    Op(Opcode),
}

impl Instruction<'_> {
    /// Returns opcode if this is an opcode instruction.
    pub fn opcode(&self) -> Option<Opcode> {
        match self {
            Self::Op(op) => Some(*op),
            Self::PushBytes(_) => None,
        }
    }

    /// Returns the pushed bytes if this is a push instruction.
    pub fn push_bytes(&self) -> Option<&PushBytes> {
        match self {
            Self::Op(_) => None,
            Self::PushBytes(bytes) => Some(bytes),
        }
    }

    /// Returns the numeric value represented by the instruction, if any.
    pub fn script_num(&self) -> Option<i64> {
        match self {
            Self::Op(op) => {
                let v = op.to_u8();
                match v {
                    0x51..=0x60 => Some(i64::from(v) - 0x50),
                    0x4f => Some(-1),
                    _ => None,
                }
            }
            Self::PushBytes(bytes) => {
                super::read_scriptint_non_minimal(bytes.as_bytes()).ok().map(i64::from)
            }
        }
    }

    /// Returns the numeric value interpreted with CLTV-compatible bounds, if any.
    pub fn read_int(&self) -> Option<i64> {
        match self {
            Self::Op(op) => {
                let v = op.to_u8();
                match v {
                    0x51..=0x60 => Some(i64::from(v) - 0x50),
                    0x4f => Some(-1),
                    _ => None,
                }
            }
            Self::PushBytes(bytes) => bytes.read_cltv_scriptint().ok(),
        }
    }

    pub(crate) fn script_serialized_len(&self) -> usize {
        match self {
            Self::Op(_) => 1,
            Self::PushBytes(bytes) => ScriptBuf::<()>::reserved_len_for_slice(bytes.len()),
        }
    }
}

/// Iterator over parsed script instructions.
#[derive(Debug, Clone)]
pub struct Instructions<'a> {
    pub(crate) data: core::slice::Iter<'a, u8>,
    pub(crate) enforce_minimal: bool,
}

impl<'a> Instructions<'a> {
    /// Creates a new instruction iterator.
    pub fn new<T>(script: &'a Script<T>, enforce_minimal: bool) -> Self {
        Self { data: script.as_bytes().iter(), enforce_minimal }
    }

    /// Views the remaining bytes as a script.
    pub fn as_script<T>(&self) -> &'a Script<T> {
        Script::from_bytes(self.data.as_slice())
    }

    fn remaining_bytes(&self) -> usize {
        self.data.as_slice().len()
    }

    fn kill(&mut self) {
        let len = self.data.len();
        self.data.nth(len.max(1) - 1);
    }

    fn take_slice_or_kill(&mut self, len: u32) -> Result<&'a PushBytes, Error> {
        let len = len as usize;
        if self.data.len() >= len {
            let slice = &self.data.as_slice()[..len];
            if len > 0 {
                self.data.nth(len - 1);
            }
            Ok(slice.try_into().expect("u32-sized slice length always fits PushBytes"))
        } else {
            self.kill();
            Err(Error::EarlyEndOfScript)
        }
    }

    fn next_push_data_len(
        &mut self,
        len: PushDataLenLen,
        min_push_len: usize,
    ) -> Result<Instruction<'a>, Error> {
        let Ok(n) = script::read_push_data_len(&mut self.data, len) else {
            self.kill();
            return Err(Error::EarlyEndOfScript);
        };
        if self.enforce_minimal && n < min_push_len {
            self.kill();
            return Err(Error::NonMinimalPush);
        }
        n.try_into()
            .map_err(|_| Error::NumericOverflow)
            .and_then(|n| self.take_slice_or_kill(n))
            .map(Instruction::PushBytes)
    }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = Result<Instruction<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let &byte = self.data.next()?;

        match byte {
            0x00..=0x4b => {
                let n = u32::from(byte);
                let op_byte = self.data.as_slice().first();
                match (self.enforce_minimal, op_byte, n) {
                    (true, Some(&op_byte), 1)
                        if op_byte == 0x81 || (op_byte > 0 && op_byte <= 16) =>
                    {
                        self.kill();
                        Some(Err(Error::NonMinimalPush))
                    }
                    (_, None, 0) => Some(Ok(Instruction::PushBytes(PushBytes::empty()))),
                    _ => Some(self.take_slice_or_kill(n).map(Instruction::PushBytes)),
                }
            }
            x if x == all::OP_PUSHDATA1.to_u8() => {
                Some(self.next_push_data_len(PushDataLenLen::One, 76))
            }
            x if x == all::OP_PUSHDATA2.to_u8() => {
                Some(self.next_push_data_len(PushDataLenLen::Two, 0x100))
            }
            x if x == all::OP_PUSHDATA4.to_u8() => {
                Some(self.next_push_data_len(PushDataLenLen::Four, 0x10000))
            }
            _ => Some(Ok(Instruction::Op(Opcode::from(byte)))),
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.data.as_slice().is_empty() {
            (0, Some(0))
        } else {
            (1, Some(self.data.len()))
        }
    }
}

impl core::iter::FusedIterator for Instructions<'_> {}

/// Iterator over script instructions with byte offsets.
#[derive(Debug, Clone)]
pub struct InstructionIndices<'a> {
    instructions: Instructions<'a>,
    pos: usize,
}

impl<'a> InstructionIndices<'a> {
    /// Creates a new iterator from a script.
    pub fn new<T>(script: &'a Script<T>, enforce_minimal: bool) -> Self {
        Self { instructions: Instructions::new(script, enforce_minimal), pos: 0 }
    }

    /// Views the remaining bytes as a script.
    pub fn as_script<T>(&self) -> &'a Script<T> {
        self.instructions.as_script()
    }

    fn remaining_bytes(&self) -> usize {
        self.instructions.remaining_bytes()
    }

    fn next_with<F: FnOnce(&mut Self) -> Option<Result<Instruction<'a>, Error>>>(
        &mut self,
        next_fn: F,
    ) -> Option<<Self as Iterator>::Item> {
        let prev_remaining = self.remaining_bytes();
        let prev_pos = self.pos;
        let instruction = next_fn(self)?;
        let consumed = prev_remaining - self.remaining_bytes();
        self.pos += consumed;
        Some(instruction.map(move |instruction| (prev_pos, instruction)))
    }
}

impl<'a> Iterator for InstructionIndices<'a> {
    type Item = Result<(usize, Instruction<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_with(|this| this.instructions.next())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.instructions.size_hint()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.next_with(|this| this.instructions.nth(n))
    }
}

impl core::iter::FusedIterator for InstructionIndices<'_> {}
