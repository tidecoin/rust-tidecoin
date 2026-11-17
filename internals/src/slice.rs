//! Contains extensions related to slices.

#![forbid(unsafe_code)]

/// Extension trait for slice.
pub trait SliceExt {
    /// The item type the slice is storing.
    type Item;

    /// Splits up the slice into a slice of arrays and a remainder.
    ///
    /// Note that `N` must not be zero:
    ///
    /// ```compile_fail
    /// # use tidecoin_internals::slice::SliceExt;
    /// let slice = [1, 2, 3];
    /// let _fail = slice.as_nonzero_chunks::<0>(); // Fails to compile
    /// ```
    fn as_nonzero_chunks<const N: usize>(&self) -> (&[[Self::Item; N]], &[Self::Item]);

    /// Splits up the slice into a slice of arrays and a remainder.
    ///
    /// Note that `N` must not be zero:
    ///
    /// ```compile_fail
    /// # use tidecoin_internals::slice::SliceExt;
    /// let mut slice = [1, 2, 3];
    /// let _fail = slice.as_nonzero_chunks_mut::<0>(); // Fails to compile
    /// ```
    fn as_nonzero_chunks_mut<const N: usize>(
        &mut self,
    ) -> (&mut [[Self::Item; N]], &mut [Self::Item]);

    /// Tries to access a sub-array of length `ARRAY_LEN` at the specified `offset`.
    ///
    /// Returns `None` in case of out-of-bounds access.
    fn get_array<const ARRAY_LEN: usize>(&self, offset: usize) -> Option<&[Self::Item; ARRAY_LEN]>;

    /// Splits the slice into an array and remainder if it's long enough.
    ///
    /// Returns `None` if the slice is shorter than `ARRAY_LEN`
    #[allow(clippy::type_complexity)] // it's not really complex and redefining would make it
                                      // harder to understand
    fn split_first_chunk<const ARRAY_LEN: usize>(
        &self,
    ) -> Option<(&[Self::Item; ARRAY_LEN], &[Self::Item])>;

    /// Splits the slice into a remainder and an array if it's long enough.
    ///
    /// Returns `None` if the slice is shorter than `ARRAY_LEN`
    #[allow(clippy::type_complexity)] // it's not really complex and redefining would make it
                                      // harder to understand
    fn split_last_chunk<const ARRAY_LEN: usize>(
        &self,
    ) -> Option<(&[Self::Item], &[Self::Item; ARRAY_LEN])>;
}

impl<T> SliceExt for [T] {
    type Item = T;

    fn as_nonzero_chunks<const N: usize>(&self) -> (&[[Self::Item; N]], &[Self::Item]) {
        #[allow(clippy::let_unit_value)]
        let () = Hack::<N>::IS_NONZERO;

        self.as_chunks::<N>()
    }

    fn as_nonzero_chunks_mut<const N: usize>(
        &mut self,
    ) -> (&mut [[Self::Item; N]], &mut [Self::Item]) {
        #[allow(clippy::let_unit_value)]
        let () = Hack::<N>::IS_NONZERO;

        self.as_chunks_mut::<N>()
    }

    fn get_array<const ARRAY_LEN: usize>(&self, offset: usize) -> Option<&[Self::Item; ARRAY_LEN]> {
        self.get(offset..(offset + ARRAY_LEN)).map(|slice| {
            slice
                .try_into()
                .expect("the arguments to `get` evaluate to the same length the return type uses")
        })
    }

    fn split_first_chunk<const ARRAY_LEN: usize>(
        &self,
    ) -> Option<(&[Self::Item; ARRAY_LEN], &[Self::Item])> {
        if self.len() < ARRAY_LEN {
            return None;
        }
        let (first, remainder) = self.split_at(ARRAY_LEN);
        Some((first.try_into().expect("we're passing `ARRAY_LEN` to `split_at` above"), remainder))
    }

    fn split_last_chunk<const ARRAY_LEN: usize>(
        &self,
    ) -> Option<(&[Self::Item], &[Self::Item; ARRAY_LEN])> {
        if self.len() < ARRAY_LEN {
            return None;
        }
        let (remainder, last) = self.split_at(self.len() - ARRAY_LEN);
        Some((
            remainder,
            last.try_into().expect("we're passing `self.len() - ARRAY_LEN` to `split_at` above"),
        ))
    }
}

struct Hack<const N: usize>;

impl<const N: usize> Hack<N> {
    const IS_NONZERO: () = {
        assert!(N != 0);
    };
}

#[cfg(test)]
mod tests {
    use super::SliceExt;

    // some comparisons require type annotations
    const EMPTY: &[i32] = &[];

    #[test]
    fn one_to_one() {
        let slice = [1];
        let (left, right) = slice.as_nonzero_chunks::<1>();
        assert_eq!(left, &[[1]]);
        assert_eq!(right, EMPTY);
    }

    #[test]
    fn one_to_two() {
        const EMPTY_LEFT: &[[i32; 2]] = &[];

        let slice = [1i32];
        let (left, right) = slice.as_nonzero_chunks::<2>();
        assert_eq!(left, EMPTY_LEFT);
        assert_eq!(right, &[1]);
    }

    #[test]
    fn two_to_one() {
        let slice = [1, 2];
        let (left, right) = slice.as_nonzero_chunks::<1>();
        assert_eq!(left, &[[1], [2]]);
        assert_eq!(right, EMPTY);
    }

    #[test]
    fn two_to_two() {
        let slice = [1, 2];
        let (left, right) = slice.as_nonzero_chunks::<2>();
        assert_eq!(left, &[[1, 2]]);
        assert_eq!(right, EMPTY);
    }

    #[test]
    fn three_to_two() {
        let slice = [1, 2, 3];
        let (left, right) = slice.as_nonzero_chunks::<2>();
        assert_eq!(left, &[[1, 2]]);
        assert_eq!(right, &[3]);
    }
}
