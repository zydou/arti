//! Internal: Declare the Reader type for tor-bytes

use crate::{Error, Readable, Result};
use std::num::NonZeroUsize;

/// A type for reading messages from a slice of bytes.
///
/// Unlike io::Read, this object has a simpler error type, and is designed
/// for in-memory parsing only.
///
/// The methods in [`Reader`] should never panic, with one exception:
/// the `extract` and `extract_n` methods will panic if the underlying
/// [`Readable`] object's `take_from` method panics.
///
/// # Examples
///
/// You can use a Reader to extract information byte-by-byte:
///
/// ```
/// use tor_bytes::{Reader,Result};
/// let msg = [ 0x00, 0x01, 0x23, 0x45, 0x22, 0x00, 0x00, 0x00 ];
/// let mut b = Reader::from_slice(&msg[..]);
/// // Multi-byte values are always big-endian.
/// assert_eq!(b.take_u32()?, 0x12345);
/// assert_eq!(b.take_u8()?, 0x22);
///
/// // You can check on the length of the message...
/// assert_eq!(b.total_len(), 8);
/// assert_eq!(b.consumed(), 5);
/// assert_eq!(b.remaining(), 3);
/// // then skip over a some bytes...
/// b.advance(3)?;
/// // ... and check that the message is really exhausted.
/// b.should_be_exhausted()?;
/// # Result::Ok(())
/// ```
///
/// You can also use a Reader to extract objects that implement Readable.
/// ```
/// use tor_bytes::{Reader,Result,Readable};
/// use std::net::Ipv4Addr;
/// let msg = [ 0x00, 0x04, 0x7f, 0x00, 0x00, 0x01];
/// let mut b = Reader::from_slice(&msg[..]);
///
/// let tp: u16 = b.extract()?;
/// let ip: Ipv4Addr = b.extract()?;
/// assert_eq!(tp, 4);
/// assert_eq!(ip, Ipv4Addr::LOCALHOST);
/// # Result::Ok(())
/// ```
pub struct Reader<'a> {
    /// The underlying slice that we're reading from
    b: &'a [u8],
    /// The next position in the slice that we intend to read from.
    off: usize,
}

impl<'a> Reader<'a> {
    /// Construct a new Reader from a slice of bytes.
    ///
    /// In tests, prefer [`Reader::from_slice_for_test`].
    pub fn from_slice(slice: &'a [u8]) -> Self {
        Reader { b: slice, off: 0 }
    }
    /// Construct a new Reader from a slice of bytes which may not be complete.
    ///
    /// XXXX the behaviour described here has not yet been implemented
    ///
    /// This can be used to try to deserialise a message received from a protocol stream,
    /// if we don't know how much data we needed to buffer.
    ///
    /// [`Readable`] methods, [`extract`](Reader::extract), and so on,
    /// will return [`Error::Truncated`] if the message is incomplete,
    /// and reading more would help.
    ///
    /// (This is achieved via [`incomplete_error`](Reader::incomplete_error.)
    ///
    /// # Warning about denial of service through excessive memory use
    ///
    /// It is hazardous to use this approach unless the buffer size is limited,
    /// since the sender could send an apparently-very-large message.
    //
    // TODO this name is quite clumsy!
    pub fn from_possibly_incomplete_slice(slice: &'a [u8]) -> Self {
        Reader { b: slice, off: 0 }
    }
    /// Construct a new Reader from a slice of bytes, in tests
    ///
    /// This is equivalent to [`Reader::from_possibly_incomplete_slice`].
    /// It should be used in test cases, because that gives more precise
    /// testing of the generation of incomplete data errors.
    pub fn from_slice_for_test(slice: &'a [u8]) -> Self {
        Self::from_possibly_incomplete_slice(slice)
    }
    /// Construct a new Reader from a 'Bytes' object.
    pub fn from_bytes(b: &'a bytes::Bytes) -> Self {
        Self::from_slice(b.as_ref())
    }
    /// Return the total length of the slice in this reader, including
    /// consumed bytes and remaining bytes.
    pub fn total_len(&self) -> usize {
        self.b.len()
    }
    /// Return the total number of bytes in this reader that have not
    /// yet been read.
    pub fn remaining(&self) -> usize {
        self.b.len() - self.off
    }
    /// Consume this reader, and return a slice containing the remaining
    /// bytes from its slice that it did not consume.
    pub fn into_rest(self) -> &'a [u8] {
        &self.b[self.off..]
    }
    /// Return the total number of bytes in this reader that have
    /// already been read.
    pub fn consumed(&self) -> usize {
        self.off
    }
    /// Skip `n` bytes from the reader.
    ///
    /// Returns Ok on success.  Returns Err(Error::Truncated) if there were
    /// not enough bytes to skip.
    pub fn advance(&mut self, n: usize) -> Result<()> {
        self.peek(n)?;
        self.off += n;
        Ok(())
    }
    /// Check whether this reader is exhausted (out of bytes).
    ///
    /// Return Ok if it is, and Err(Error::ExtraneousBytes)
    /// if there were extra bytes.
    pub fn should_be_exhausted(&self) -> Result<()> {
        if self.remaining() != 0 {
            return Err(Error::ExtraneousBytes);
        }
        Ok(())
    }
    /// Truncate this reader, so that no more than `n` bytes remain.
    ///
    /// Fewer than `n` bytes may remain if there were not enough bytes
    /// to begin with.
    pub fn truncate(&mut self, n: usize) {
        if n < self.remaining() {
            self.b = &self.b[..self.off + n];
        }
    }
    /// Try to return a slice of `n` bytes from this reader without
    /// consuming them.
    ///
    /// On success, returns Ok(slice).  If there are fewer than n
    /// bytes, returns Err(Error::Truncated).
    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        if let Some(deficit) = n
            .checked_sub(self.remaining())
            .and_then(|d| d.try_into().ok())
        {
            return Err(self.incomplete_error(deficit));
        }

        Ok(&self.b[self.off..(n + self.off)])
    }
    /// Try to consume and return a slice of `n` bytes from this reader.
    ///
    /// On success, returns Ok(Slice).  If there are fewer than n
    /// bytes, returns Err(Error::Truncated).
    ///
    /// # Example
    /// ```
    /// use tor_bytes::{Reader,Result};
    /// let m = b"Hello World";
    /// let mut b = Reader::from_slice(m);
    /// assert_eq!(b.take(5)?, b"Hello");
    /// assert_eq!(b.take_u8()?, 0x20);
    /// assert_eq!(b.take(5)?, b"World");
    /// b.should_be_exhausted()?;
    /// # Result::Ok(())
    /// ```
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let b = self.peek(n)?;
        self.advance(n)?;
        Ok(b)
    }
    /// Try to fill a provided buffer with bytes consumed from this reader.
    ///
    /// On success, the buffer will be filled with data from the
    /// reader, the reader will advance by the length of the buffer,
    /// and we'll return Ok(()).  On failure the buffer will be
    /// unchanged.
    ///
    /// # Example
    /// ```
    /// use tor_bytes::Reader;
    /// let m = b"Hello world";
    /// let mut v1 = vec![0; 5];
    /// let mut v2 = vec![0; 5];
    /// let mut b = Reader::from_slice(m);
    /// b.take_into(&mut v1[..])?;
    /// assert_eq!(b.take_u8()?, b' ');
    /// b.take_into(&mut v2[..])?;
    /// assert_eq!(&v1[..], b"Hello");
    /// assert_eq!(&v2[..], b"world");
    /// b.should_be_exhausted()?;
    /// # tor_bytes::Result::Ok(())
    /// ```
    pub fn take_into(&mut self, buf: &mut [u8]) -> Result<()> {
        let n = buf.len();
        let b = self.take(n)?;
        buf.copy_from_slice(b);
        Ok(())
    }
    /// Try to consume and return a u8 from this reader.
    pub fn take_u8(&mut self) -> Result<u8> {
        let b = self.take(1)?;
        Ok(b[0])
    }
    /// Try to consume and return a big-endian u16 from this reader.
    pub fn take_u16(&mut self) -> Result<u16> {
        let b: [u8; 2] = self.extract()?;
        let r = u16::from_be_bytes(b);
        Ok(r)
    }
    /// Try to consume and return a big-endian u32 from this reader.
    pub fn take_u32(&mut self) -> Result<u32> {
        let b: [u8; 4] = self.extract()?;
        let r = u32::from_be_bytes(b);
        Ok(r)
    }
    /// Try to consume and return a big-endian u64 from this reader.
    pub fn take_u64(&mut self) -> Result<u64> {
        let b: [u8; 8] = self.extract()?;
        let r = u64::from_be_bytes(b);
        Ok(r)
    }
    /// Try to consume and return a big-endian u128 from this reader.
    pub fn take_u128(&mut self) -> Result<u128> {
        let b: [u8; 16] = self.extract()?;
        let r = u128::from_be_bytes(b);
        Ok(r)
    }
    /// Try to consume and return bytes from this buffer until we
    /// encounter a terminating byte equal to `term`.
    ///
    /// On success, returns Ok(Slice), where the slice does not
    /// include the terminating byte.  Returns Err(Error::Truncated)
    /// if we do not find the terminating bytes.
    ///
    /// Advances the reader to the point immediately after the terminating
    /// byte.
    ///
    /// # Example
    /// ```
    /// use tor_bytes::{Reader,Result};
    /// let m = b"Hello\0wrld";
    /// let mut b = Reader::from_slice(m);
    /// assert_eq!(b.take_until(0)?, b"Hello");
    /// assert_eq!(b.into_rest(), b"wrld");
    /// # Result::Ok(())
    /// ```
    pub fn take_until(&mut self, term: u8) -> Result<&'a [u8]> {
        let pos = self.b[self.off..]
            .iter()
            .position(|b| *b == term)
            .ok_or(self.incomplete_error(
                //
                1.try_into().expect("1 == 0"),
            ))?;
        let result = self.take(pos)?;
        self.advance(1)?;
        Ok(result)
    }
    /// Consume and return all the remaining bytes, but do not consume the reader
    ///
    /// This can be useful if you need to possibly read either fixed-length data,
    /// or variable length data eating the rest of the `Reader`.
    ///
    /// The `Reader` will be left devoid of further bytes.
    /// Consider using `into_rest()` instead.
    pub fn take_rest(&mut self) -> &'a [u8] {
        self.take(self.remaining())
            .expect("taking remaining failed")
    }
    /// Try to decode and remove a Readable from this reader, using its
    /// take_from() method.
    ///
    /// On failure, consumes nothing.
    pub fn extract<E: Readable>(&mut self) -> Result<E> {
        let off_orig = self.off;
        let result = E::take_from(self);
        if result.is_err() {
            // We encountered an error; we should rewind.
            self.off = off_orig;
        }
        result
    }

    /// Try to decode and remove `n` Readables from this reader, using the
    /// Readable's take_from() method.
    ///
    /// On failure, consumes nothing.
    pub fn extract_n<E: Readable>(&mut self, n: usize) -> Result<Vec<E>> {
        // This `min` will help us defend against a pathological case where an
        // attacker tells us that there are BIGNUM elements forthcoming, and our
        // attempt to allocate `Vec::with_capacity(BIGNUM)` makes us panic.
        //
        // The `min` can be incorrect if E is somehow encodable in zero bytes
        // (!?), but that will only cause our initial allocation to be too
        // small.
        //
        // In practice, callers should always check that `n` is reasonable
        // before calling this function, and protocol designers should not
        // provide e.g. 32-bit counters for object types of which we should
        // never allocate u32::MAX.
        let n_alloc = std::cmp::min(n, self.remaining());
        let mut result = Vec::with_capacity(n_alloc);
        let off_orig = self.off;
        for _ in 0..n {
            match E::take_from(self) {
                Ok(item) => result.push(item),
                Err(e) => {
                    // Encountered an error; we should rewind.
                    self.off = off_orig;
                    return Err(e);
                }
            }
        }
        Ok(result)
    }

    /// Decode something with a `u8` length field
    ///
    /// Prefer to use this function, rather than ad-hoc `take_u8`
    /// and subsequent manual length checks.
    /// Using this facility eliminates the need to separately keep track of the lengths.
    ///
    /// `read_nested` consumes a length field,
    /// and provides the closure `f` with an inner `Reader` that
    /// contains precisely that many bytes -
    /// the bytes which follow the length field in the original reader.
    /// If the closure is successful, `read_nested` checks that that inner reader is exhausted,
    /// i.e. that the inner contents had the same length as was specified.
    ///
    /// The closure should read whatever is inside the nested structure
    /// from the nested reader.
    /// It may well want to use `take_rest`, to consume all of the counted bytes.
    ///
    /// On failure, the amount consumed is not specified.
    pub fn read_nested_u8len<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Reader) -> Result<T>,
    {
        read_nested_generic::<u8, _, _>(self, f)
    }

    /// Start decoding something with a u16 length field
    pub fn read_nested_u16len<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Reader) -> Result<T>,
    {
        read_nested_generic::<u16, _, _>(self, f)
    }

    /// Start decoding something with a u32 length field
    pub fn read_nested_u32len<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Reader) -> Result<T>,
    {
        read_nested_generic::<u32, _, _>(self, f)
    }

    /// Return a cursor object describing the current position of this Reader
    /// within its underlying byte stream.
    ///
    /// The resulting [`Cursor`] can be used with `range`, but nothing else.
    ///
    /// Note that having to use a `Cursor` is typically an anti-pattern: it
    /// tends to indicate that whatever you're parsing could probably have a
    /// better design that would better separate data from metadata.
    /// Unfortunately, there are a few places like that in the Tor  protocols.
    //
    // TODO: This could instead be a function that takes a closure, passes a
    // reader to that closure, and returns the closure's output along with
    // whatever the reader consumed.
    pub fn cursor(&self) -> Cursor<'a> {
        Cursor {
            pos: self.off,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Return the slice of bytes between the start cursor (inclusive) and end
    /// cursor (exclusive).
    ///
    /// If the cursors are not in order, return an empty slice.
    ///
    /// This function is guaranteed not to panic if the inputs were generated
    /// from a different Reader, but if so the byte slice that it returns will
    /// not be meaningful.
    pub fn range(&self, start: Cursor<'a>, end: Cursor<'a>) -> &'a [u8] {
        if start.pos <= end.pos && end.pos <= self.b.len() {
            &self.b[start.pos..end.pos]
        } else {
            &self.b[..0]
        }
    }

    /// Returns the error that should be returned if we ran out of data
    ///
    /// XXXX this is not yet implemented
    ///
    /// For a usual `Reader` this is [`Error::InvalidMessage`].
    /// But it's [`Error::Truncated`] with a reader from
    /// [`Reader::from_possibly_incomplete_slice`].
    pub fn incomplete_error(&self, deficit: NonZeroUsize) -> Error {
        Error::Truncated {
            deficit: deficit.into(),
        }
    }
}

/// A reference to a position within a [`Reader`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Cursor<'a> {
    /// The underlying position within the reader.
    pos: usize,
    /// Used so that we can restrict the cursor to the lifetime of the
    /// underlying byte slice.
    _phantom: std::marker::PhantomData<&'a [u8]>,
}

/// Implementation of `read_nested_*` -- generic
fn read_nested_generic<L, F, T>(b: &mut Reader, f: F) -> Result<T>
where
    F: FnOnce(&mut Reader) -> Result<T>,
    L: Readable + Copy + Sized + TryInto<usize>,
{
    let length: L = b.extract()?;
    let length: usize = length.try_into().map_err(|_| Error::BadLengthValue)?;
    let slice = b.take(length)?;
    let mut inner = Reader::from_slice(slice);
    let out = f(&mut inner)?;
    inner.should_be_exhausted()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::cognitive_complexity)]
    use super::*;
    #[test]
    fn bytecursor_read_ok() {
        let bytes = b"On a mountain halfway between Reno and Rome";
        let mut bc = Reader::from_slice(&bytes[..]);

        assert_eq!(bc.consumed(), 0);
        assert_eq!(bc.remaining(), 43);
        assert_eq!(bc.total_len(), 43);

        assert_eq!(bc.take(3).unwrap(), &b"On "[..]);
        assert_eq!(bc.consumed(), 3);

        assert_eq!(bc.take_u16().unwrap(), 0x6120);
        assert_eq!(bc.take_u8().unwrap(), 0x6d);
        assert_eq!(bc.take_u64().unwrap(), 0x6f756e7461696e20);
        assert_eq!(bc.take_u32().unwrap(), 0x68616c66);
        assert_eq!(bc.consumed(), 18);
        assert_eq!(bc.remaining(), 25);
        assert_eq!(bc.total_len(), 43);

        assert_eq!(bc.peek(7).unwrap(), &b"way bet"[..]);
        assert_eq!(bc.consumed(), 18); // no change
        assert_eq!(bc.remaining(), 25); // no change
        assert_eq!(bc.total_len(), 43); // no change

        assert_eq!(bc.peek(7).unwrap(), &b"way bet"[..]);
        assert_eq!(bc.consumed(), 18); // no change this time either.

        bc.advance(12).unwrap();
        assert_eq!(bc.consumed(), 30);
        assert_eq!(bc.remaining(), 13);

        let rem = bc.into_rest();
        assert_eq!(rem, &b"Reno and Rome"[..]);

        // now let's try consuming right up to the end.
        let mut bc = Reader::from_slice(&bytes[..]);
        bc.advance(22).unwrap();
        assert_eq!(bc.remaining(), 21);
        let rem = bc.take(21).unwrap();
        assert_eq!(rem, &b"between Reno and Rome"[..]);
        assert_eq!(bc.consumed(), 43);
        assert_eq!(bc.remaining(), 0);

        // We can still take a zero-length slice.
        assert_eq!(bc.take(0).unwrap(), &b""[..]);
    }

    #[test]
    fn read_u128() {
        let bytes = bytes::Bytes::from(&b"irreproducibility?"[..]); // 18 bytes
        let mut b = Reader::from_bytes(&bytes);

        assert_eq!(b.take_u8().unwrap(), b'i');
        assert_eq!(b.take_u128().unwrap(), 0x72726570726f6475636962696c697479);
        assert_eq!(b.remaining(), 1);
    }

    #[test]
    fn bytecursor_read_missing() {
        let bytes = b"1234567";
        let mut bc = Reader::from_slice_for_test(&bytes[..]);

        assert_eq!(bc.consumed(), 0);
        assert_eq!(bc.remaining(), 7);
        assert_eq!(bc.total_len(), 7);

        assert_eq!(bc.take_u64(), Err(Error::new_truncated_for_test(1)));
        assert_eq!(bc.take(8), Err(Error::new_truncated_for_test(1)));
        assert_eq!(bc.peek(8), Err(Error::new_truncated_for_test(1)));

        assert_eq!(bc.consumed(), 0);
        assert_eq!(bc.remaining(), 7);
        assert_eq!(bc.total_len(), 7);

        assert_eq!(bc.take_u32().unwrap(), 0x31323334); // get 4 bytes. 3 left.
        assert_eq!(bc.take_u32(), Err(Error::new_truncated_for_test(1)));

        assert_eq!(bc.consumed(), 4);
        assert_eq!(bc.remaining(), 3);
        assert_eq!(bc.total_len(), 7);

        assert_eq!(bc.take_u16().unwrap(), 0x3536); // get 2 bytes. 1 left.
        assert_eq!(bc.take_u16(), Err(Error::new_truncated_for_test(1)));

        assert_eq!(bc.consumed(), 6);
        assert_eq!(bc.remaining(), 1);
        assert_eq!(bc.total_len(), 7);

        assert_eq!(bc.take_u8().unwrap(), 0x37); // get 1 byte. 0 left.
        assert_eq!(bc.take_u8(), Err(Error::new_truncated_for_test(1)));

        assert_eq!(bc.consumed(), 7);
        assert_eq!(bc.remaining(), 0);
        assert_eq!(bc.total_len(), 7);
    }

    #[test]
    fn advance_too_far() {
        let bytes = b"12345";
        let mut b = Reader::from_slice_for_test(&bytes[..]);
        assert_eq!(b.remaining(), 5);
        assert_eq!(b.advance(16), Err(Error::new_truncated_for_test(11)));
        assert_eq!(b.remaining(), 5);
        assert_eq!(b.advance(5), Ok(()));
        assert_eq!(b.remaining(), 0);
    }

    #[test]
    fn truncate() {
        let bytes = b"Hello universe!!!1!";
        let mut b = Reader::from_slice_for_test(&bytes[..]);

        assert_eq!(b.take(5).unwrap(), &b"Hello"[..]);
        assert_eq!(b.remaining(), 14);
        assert_eq!(b.consumed(), 5);
        b.truncate(9);
        assert_eq!(b.remaining(), 9);
        assert_eq!(b.consumed(), 5);
        assert_eq!(b.take_u8().unwrap(), 0x20);
        assert_eq!(b.into_rest(), &b"universe"[..]);
    }

    #[test]
    fn exhaust() {
        let b = Reader::from_slice_for_test(&b""[..]);
        assert_eq!(b.should_be_exhausted(), Ok(()));

        let mut b = Reader::from_slice_for_test(&b"outis"[..]);
        assert_eq!(b.should_be_exhausted(), Err(Error::ExtraneousBytes));
        b.take(4).unwrap();
        assert_eq!(b.should_be_exhausted(), Err(Error::ExtraneousBytes));
        b.take(1).unwrap();
        assert_eq!(b.should_be_exhausted(), Ok(()));
    }

    #[test]
    fn take_rest() {
        let mut b = Reader::from_slice_for_test(b"si vales valeo");
        assert_eq!(b.take(3).unwrap(), b"si ");
        assert_eq!(b.take_rest(), b"vales valeo");
        assert_eq!(b.take_rest(), b"");
    }

    #[test]
    fn take_until() {
        let mut b = Reader::from_slice_for_test(&b"si vales valeo"[..]);
        assert_eq!(b.take_until(b' ').unwrap(), &b"si"[..]);
        assert_eq!(b.take_until(b' ').unwrap(), &b"vales"[..]);
        assert_eq!(b.take_until(b' '), Err(Error::new_truncated_for_test(1)));
    }

    #[test]
    fn truncate_badly() {
        let mut b = Reader::from_slice_for_test(&b"abcdefg"[..]);
        b.truncate(1000);
        assert_eq!(b.total_len(), 7);
        assert_eq!(b.remaining(), 7);
    }

    #[test]
    fn nested_good() {
        let mut b = Reader::from_slice_for_test(b"abc\0\0\x04defghijkl");
        assert_eq!(b.take(3).unwrap(), b"abc");

        b.read_nested_u16len(|s| {
            assert!(s.should_be_exhausted().is_ok());
            Ok(())
        })
        .unwrap();

        b.read_nested_u8len(|s| {
            assert_eq!(s.take(4).unwrap(), b"defg");
            assert!(s.should_be_exhausted().is_ok());
            Ok(())
        })
        .unwrap();

        assert_eq!(b.take(2).unwrap(), b"hi");
    }

    #[test]
    fn nested_bad() {
        let mut b = Reader::from_slice_for_test(b"................");
        assert_eq!(
            read_nested_generic::<u128, _, ()>(&mut b, |_| panic!())
                .err()
                .unwrap(),
            Error::BadLengthValue
        );

        let mut b = Reader::from_slice_for_test(b"................");
        assert_eq!(
            b.read_nested_u32len::<_, ()>(|_| panic!()).err().unwrap(),
            Error::new_truncated_for_test(774778414 - (16 - 4))
        );
    }

    #[test]
    fn nested_inner_bad() {
        let mut b = Reader::from_slice_for_test(&[1, 66]);
        assert_eq!(
            b.read_nested_u8len(|b| b.take_u32()),
            Err(Error::new_truncated_for_test(3)),
        );
    }

    #[test]
    fn extract() {
        // For example purposes, declare a length-then-bytes string type.
        #[derive(Debug)]
        struct LenEnc(Vec<u8>);
        impl Readable for LenEnc {
            fn take_from(b: &mut Reader<'_>) -> Result<Self> {
                let length = b.take_u8()?;
                let content = b.take(length as usize)?.into();
                Ok(LenEnc(content))
            }
        }

        let bytes = b"\x04this\x02is\x09sometimes\x01a\x06string!";
        let mut b = Reader::from_slice_for_test(&bytes[..]);

        let le: LenEnc = b.extract().unwrap();
        assert_eq!(&le.0[..], &b"this"[..]);

        let les: Vec<LenEnc> = b.extract_n(4).unwrap();
        assert_eq!(&les[3].0[..], &b"string"[..]);

        assert_eq!(b.remaining(), 1);

        // Make sure that we don't advance on a failing extract().
        let le: Result<LenEnc> = b.extract();
        assert_eq!(le.unwrap_err(), Error::new_truncated_for_test(33));
        assert_eq!(b.remaining(), 1);

        // Make sure that we don't advance on a failing extract_n()
        let mut b = Reader::from_slice_for_test(&bytes[..]);
        assert_eq!(b.remaining(), 28);
        let les: Result<Vec<LenEnc>> = b.extract_n(10);
        assert_eq!(les.unwrap_err(), Error::new_truncated_for_test(33));
        assert_eq!(b.remaining(), 28);
    }

    #[test]
    fn cursor() -> Result<()> {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz";
        let mut b = Reader::from_slice_for_test(&alphabet[..]);

        let c1 = b.cursor();
        let _ = b.take_u16()?;
        let c2 = b.cursor();
        let c2b = b.cursor();
        b.advance(7)?;
        let c3 = b.cursor();

        assert_eq!(b.range(c1, c2), &b"ab"[..]);
        assert_eq!(b.range(c2, c3), &b"cdefghi"[..]);
        assert_eq!(b.range(c1, c3), &b"abcdefghi"[..]);
        assert_eq!(b.range(c1, c1), &b""[..]);
        assert_eq!(b.range(c3, c1), &b""[..]);
        assert_eq!(c2, c2b);
        assert!(c1 < c2);
        assert!(c2 < c3);

        Ok(())
    }
}
