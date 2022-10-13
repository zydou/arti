//! Internal: Declare the Writer type for tor-bytes

use std::marker::PhantomData;

use educe::Educe;

use crate::EncodeError;
use crate::EncodeResult;
use crate::Writeable;
use crate::WriteableOnce;

/// A byte-oriented trait for writing to small arrays.
///
/// Most code will want to use the fact that `Vec<u8>` implements this trait.
/// To define a new implementation, just define the write_all method.
///
/// # Examples
///
/// You can use a Writer to add bytes explicitly:
/// ```
/// use tor_bytes::Writer;
/// let mut w: Vec<u8> = Vec::new(); // Vec<u8> implements Writer.
/// w.write_u32(0x12345);
/// w.write_u8(0x22);
/// w.write_zeros(3);
/// assert_eq!(w, &[0x00, 0x01, 0x23, 0x45, 0x22, 0x00, 0x00, 0x00]);
/// ```
///
/// You can also use a Writer to encode things that implement the
/// Writeable trait:
///
/// ```
/// use tor_bytes::{Writer,Writeable};
/// let mut w: Vec<u8> = Vec::new();
/// w.write(&4_u16); // The unsigned types all implement Writeable.
///
/// // We also provide Writeable implementations for several important types.
/// use std::net::Ipv4Addr;
/// let ip = Ipv4Addr::new(127, 0, 0, 1);
/// w.write(&ip);
///
/// assert_eq!(w, &[0x00, 0x04, 0x7f, 0x00, 0x00, 0x01]);
/// ```
pub trait Writer {
    /// Append a slice to the end of this writer.
    fn write_all(&mut self, b: &[u8]);

    /// Append a single u8 to this writer.
    fn write_u8(&mut self, x: u8) {
        self.write_all(&[x]);
    }
    /// Append a single u16 to this writer, encoded in big-endian order.
    fn write_u16(&mut self, x: u16) {
        self.write_all(&x.to_be_bytes());
    }
    /// Append a single u32 to this writer, encoded in big-endian order.
    fn write_u32(&mut self, x: u32) {
        self.write_all(&x.to_be_bytes());
    }
    /// Append a single u64 to this writer, encoded in big-endian order.
    fn write_u64(&mut self, x: u64) {
        self.write_all(&x.to_be_bytes());
    }
    /// Append a single u128 to this writer, encoded in big-endian order.
    fn write_u128(&mut self, x: u128) {
        self.write_all(&x.to_be_bytes());
    }
    /// Write n bytes to this writer, all with the value zero.
    ///
    /// NOTE: This implementation is somewhat inefficient, since it allocates
    /// a vector.  You should probably replace it if you can.
    fn write_zeros(&mut self, n: usize) {
        let v = vec![0_u8; n];
        self.write_all(&v[..]);
    }

    /// Encode a Writeable object onto this writer, using its
    /// write_onto method.
    fn write<E: Writeable + ?Sized>(&mut self, e: &E) -> EncodeResult<()> {
        // TODO(nickm): should we recover from errors by undoing any partial
        // writes that occurred?
        e.write_onto(self)
    }
    /// Encode a WriteableOnce object onto this writer, using its
    /// write_into method.
    fn write_and_consume<E: WriteableOnce>(&mut self, e: E) -> EncodeResult<()> {
        // TODO(nickm): should we recover from errors by undoing any partial
        // writes that occurred?
        e.write_into(self)
    }
    /// Arranges to write a u8 length, and some data whose encoding is that length
    ///
    /// Prefer to use this function, rather than manual length calculations
    /// and ad-hoc `write_u8`,
    /// Using this facility eliminates the need to separately keep track of the lengths.
    ///
    /// The returned `NestedWriter` should be used to write the contents,
    /// inside the byte-counted section.
    ///
    /// Then you **must** call `finish` to finalise the buffer.
    fn write_nested_u8len(&mut self) -> NestedWriter<'_, Self, u8> {
        write_nested_generic(self)
    }
    /// Arranges to writes a u16 length and some data whose encoding is that length
    fn write_nested_u16len(&mut self) -> NestedWriter<'_, Self, u16> {
        write_nested_generic(self)
    }
    /// Arranges to writes a u32 length and some data whose encoding is that length
    fn write_nested_u32len(&mut self) -> NestedWriter<'_, Self, u32> {
        write_nested_generic(self)
    }
}

/// Work in progress state for writing a nested (length-counted) item
///
/// You must call `finish` !
#[derive(Educe)]
#[educe(Deref, DerefMut)]
pub struct NestedWriter<'w, W, L>
where
    W: ?Sized,
{
    /// Variance doesn't matter since this is local to the module, but for form's sake:
    /// Be invariant in `L`, as maximally conservative.
    length_type: PhantomData<*mut L>,

    /// The outer writer
    outer: &'w mut W,

    /// Our inner buffer
    ///
    /// Caller can use us as `Writer` via `DerefMut`
    ///
    /// (An alternative would be to `impl Writer` but that involves recapitulating
    /// the impl for `Vec` and we do not have the `ambassador` crate to help us.
    /// Exposing this inner `Vec` is harmless.)
    ///
    /// We must allocate here because some `Writer`s are streaming
    #[educe(Deref, DerefMut)]
    inner: Vec<u8>,
}

/// Implementation of `write_nested_*` - generic over the length type
fn write_nested_generic<W, L>(w: &mut W) -> NestedWriter<W, L>
where
    W: Writer + ?Sized,
    L: Default + Copy + Sized + Writeable + TryFrom<usize>,
{
    NestedWriter {
        length_type: PhantomData,
        outer: w,
        inner: vec![],
    }
}

impl<'w, W, L> NestedWriter<'w, W, L>
where
    W: Writer + ?Sized,
    L: Default + Copy + Sized + Writeable + TryFrom<usize> + std::ops::Not<Output = L>,
{
    /// Ends writing the nested data, and updates the length appropriately
    ///
    /// You must check the return value.
    /// It will only be `Err` if the amount you wrote doesn't fit into the length field.
    ///
    /// Sadly, you may well be implementing a `Writeable`, in which case you
    /// will have nothing good to do with the error, and must panic.
    /// In these cases you should have ensured, somehow, that overflow cannot happen.
    /// Ideally, by making your `Writeable` type incapable of holding values
    /// whose encoded length doesn't fit in the length field.
    pub fn finish(self) -> Result<(), EncodeError> {
        let length = self.inner.len();
        let length: L = length.try_into().map_err(|_| EncodeError::BadLengthValue)?;
        self.outer.write(&length)?;
        self.outer.write(&self.inner)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn write_ints() {
        let mut b = bytes::BytesMut::new();
        b.write_u8(1);
        b.write_u16(2);
        b.write_u32(3);
        b.write_u64(4);
        b.write_u128(5);

        assert_eq!(
            &b[..],
            &[
                1, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 5
            ]
        );
    }

    #[test]
    fn write_slice() {
        let mut v = Vec::new();
        v.write_u16(0x5468);
        v.write(&b"ey're good dogs, Bront"[..]).unwrap();

        assert_eq!(&v[..], &b"They're good dogs, Bront"[..]);
    }

    #[test]
    fn writeable() -> EncodeResult<()> {
        struct Sequence(u8);
        impl Writeable for Sequence {
            fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
                for i in 0..self.0 {
                    b.write_u8(i);
                }
                Ok(())
            }
        }

        let mut v = Vec::new();
        v.write(&Sequence(6))?;
        assert_eq!(&v[..], &[0, 1, 2, 3, 4, 5]);

        v.write_and_consume(Sequence(3))?;
        assert_eq!(&v[..], &[0, 1, 2, 3, 4, 5, 0, 1, 2]);
        Ok(())
    }

    #[test]
    fn nested() {
        let mut v: Vec<u8> = b"abc".to_vec();

        let mut w = v.write_nested_u8len();
        w.write_u8(b'x');
        w.finish().unwrap();

        let mut w = v.write_nested_u16len();
        w.write_u8(b'y');
        w.finish().unwrap();

        let mut w = v.write_nested_u32len();
        w.write_u8(b'z');
        w.finish().unwrap();

        assert_eq!(&v, b"abc\x01x\0\x01y\0\0\0\x01z");

        let mut w = v.write_nested_u8len();
        w.write_zeros(256);
        assert!(matches!(
            w.finish().err().unwrap(),
            EncodeError::BadLengthValue
        ));
    }
}
