//! A Writer that can put its results into an buffer of known byte size without
//! changing that size.
//!
//! TODO: This API is crate-private in tor-cell because tor-cell is the only one
//! to use it -- and only uses it in one place.  Its existence may be an argument
//! for refactoring the Writer API entirely.
//!
//! NOTE: This will likely change or go away in the future.

use thiserror::Error;

use tor_bytes::Writer;

/// An error that occurred while trying to unwrap a SliceWriter.
#[non_exhaustive]
#[derive(Clone, Debug, Error)]
pub(crate) enum SliceWriterError {
    /// We've tried to write more than would fit into a fixed-size slice
    #[error("Tried to write more than would fit into a fixed-size slice.")]
    Truncated,
}

/// An object that supports writing into a byte-slice of fixed size.
///
/// Since the writer API does not allow all `write_*` functions to report errors,
/// this type defers any truncated-data errors until you try to retrieve the
/// inner data.
///
//
// TODO: in theory we could have a version of this that used MaybeUninit, but I
// don't think that would be worth it.
pub(crate) struct SliceWriter<T> {
    /// The object we're writing into.  Must have fewer than usize::LEN bytes.
    data: T,
    /// Our current write position within that object.
    offset: usize,
}

impl<T> Writer for SliceWriter<T>
where
    T: AsMut<[u8]>,
{
    fn write_all(&mut self, b: &[u8]) {
        let new_offset = self.offset.saturating_add(b.len());
        if new_offset <= self.data.as_mut().len() {
            // Note that if we reach this case, the addition was not saturating.
            self.data.as_mut()[self.offset..new_offset].copy_from_slice(b);
            self.offset = new_offset;
        } else {
            self.offset = usize::MAX;
        }
    }
}
impl<T> SliceWriter<T> {
    /// Construct a new SliceWriter
    ///
    /// Typically, you would want to use this on a type that implements
    /// `AsMut<[u8]>`, or else it won't be very useful.
    ///
    /// Preexisting bytes in the `data` object will be unchanged, unless you use
    /// the [`Writer`] API to write to them.
    pub(crate) fn new(data: T) -> Self {
        Self { data, offset: 0 }
    }

    /// Try to extract the data from this `SliceWriter`.
    ///
    /// On success (if we did not write "off the end" of the underlying object),
    /// return the object and the number of bytes we wrote into it.  (Bytes
    /// after that position are unchanged.)
    ///
    /// On failure (if we tried to write too much), return an error.
    pub(crate) fn try_unwrap(self) -> Result<(T, usize), SliceWriterError> {
        let offset = self.offset()?;
        Ok((self.data, offset))
    }

    /// Return the number of bytes written into this `SliceWriter` so far,
    /// or an error if it has overflowed.
    pub(crate) fn offset(&self) -> Result<usize, SliceWriterError> {
        if self.offset != usize::MAX {
            Ok(self.offset)
        } else {
            Err(SliceWriterError::Truncated)
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn basics() {
        let mut w = SliceWriter::new([0_u8; 16]);
        w.write_u8(b'h');
        w.write_u16(0x656c);
        w.write_u32(0x6c6f2077);
        w.write_all(b"orld!");
        let (a, len) = w.try_unwrap().unwrap();

        assert_eq!(a.as_ref(), b"hello world!\0\0\0\0");
        assert_eq!(len, 12);
    }

    #[test]
    fn full_is_ok() {
        let mut w = SliceWriter::new([0_u8; 4]);
        w.write_u8(1);
        w.write_u16(0x0203);
        w.write_u8(4);
        let (a, len) = w.try_unwrap().unwrap();

        assert_eq!(a.as_ref(), [1, 2, 3, 4]);
        assert_eq!(len, 4);
    }

    #[test]
    fn too_full_is_not_ok() {
        let mut w = SliceWriter::new([0_u8; 5]);
        w.write_u32(12);
        w.write_u32(12);
        assert!(matches!(w.try_unwrap(), Err(SliceWriterError::Truncated)));
    }
}
