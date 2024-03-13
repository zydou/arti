//! Define a wrapper for `Vec<u8>` that will act as Writer, but zeroize its
//! contents on drop or reallocation.

use crate::Writer;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A [`Writer`] used for accumulating secret data, which gets cleared on drop.
///
/// Unlike `Zeroizing<Vec<u8>>`, this type makes sure that we always zeroize the
/// contents of the buffer, even if the buffer has to be reallocated in order to
/// grow.
///
/// We use this for cases when we're building the input to a key derivation
/// function (KDF), and want to ensure that we don't expose the values we feed
/// to it.
///
/// This struct is expected to have additional overhead beyond `Vec<u8>` only
/// when it has to grow its capacity.
#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone, Eq, PartialEq)]
pub struct SecretBuf(Vec<u8>);

/// The default size of our buffer.
///
/// This is based on the size of a typical secret input in `tor-proto`.
const DEFAULT_CAPACITY: usize = 384;

impl SecretBuf {
    /// Construct a new empty [`SecretBuf`]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Construct a new empty [`SecretBuf`] with a specified capacity.
    ///
    /// This buffer will not have to be reallocated until it uses `capacity`
    /// bytes.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Truncate this buffer to a given length.
    pub fn truncate(&mut self, new_len: usize) {
        self.0.truncate(new_len);
    }

    /// Add all the bytes from `slice` to the end of this vector.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let new_len = self.0.len() + slice.len();
        if new_len >= self.0.capacity() {
            // We will need to reallocate.  But in doing so we might reallocate,
            // which neglects to zero the previous contents.  So instead,
            // explicitly make a new vector and zeroize the old one.

            // Make sure we always at least double our capacity.
            let new_capacity = std::cmp::max(self.0.capacity() * 2, new_len);
            let mut new_vec = Vec::with_capacity(new_capacity);
            new_vec.extend_from_slice(&self.0[..]);

            let mut old_vec = std::mem::replace(&mut self.0, new_vec);
            old_vec.zeroize();
        }
        self.0.extend_from_slice(slice);
        debug_assert_eq!(self.0.len(), new_len);
    }
}

impl From<Vec<u8>> for SecretBuf {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl Default for SecretBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl AsMut<[u8]> for SecretBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

// It's okay to implement `Deref` since all operations taking an _immutable_
// reference are still right here.
impl std::ops::Deref for SecretBuf {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Writer for SecretBuf {
    fn write_all(&mut self, b: &[u8]) {
        self.extend_from_slice(b);
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
    fn simple_case() -> crate::EncodeResult<()> {
        // Sadly, there is no way in safe rust to test that the zeroization
        // actually happened.  All we can test is that the data is correct.

        let mut buf1 = SecretBuf::default();
        let mut buf2 = Vec::new();
        let xyz = b"Nine hundred pounds of sifted flax";

        // This is enough to be sure that we'll reallocate.
        for _ in 0..200 {
            buf1.write(xyz)?;
            buf2.write(xyz)?;
        }
        assert_eq!(&buf1[..], &buf2[..]);

        Ok(())
    }
}
