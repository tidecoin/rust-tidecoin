// SPDX-License-Identifier: CC0-1.0

use primitives::script::PushBytesError;

/// Reports information about failed conversion into `PushBytes`.
pub trait PushBytesErrorReport {
    /// How many bytes the input had.
    fn input_len(&self) -> usize;
}

impl PushBytesErrorReport for core::convert::Infallible {
    #[inline]
    fn input_len(&self) -> usize {
        match *self {}
    }
}

impl PushBytesErrorReport for PushBytesError {
    #[inline]
    fn input_len(&self) -> usize {
        self.len
    }
}
