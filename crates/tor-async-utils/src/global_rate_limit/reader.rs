//! A rate limited async reader.
//!
//! An [`AsyncRead`] wrapper that rate limits the bytes it yields by acquiring bandwidth
//! from a [`crate::bw_pool::BandwidthPool`] before each read. One byte is one token.
//!
//! # Example
//!
//! ```
//! use futures::AsyncReadExt as _;
//! use tor_async_utils::global_rate_limit::GlobalRateLimitedReader;
//! use tor_async_utils::bw_pool::BandwidthPool;
//!
//! futures::executor::block_on(async {
//!     let (pool, _refiller) = BandwidthPool::new(64 * 1024);
//!     let mut reader = GlobalRateLimitedReader::new(&b"hello world"[..], pool.new_acquirer());
//!
//!     // The pool starts full so this is served from the fast path.
//!     let mut buf = [0; 10];
//!     reader.read_exact(&mut buf).await.unwrap();
//! });
//! ```

use futures::AsyncRead;
use pin_project::pin_project;
use std::io::Error;
use std::num::NonZero;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use super::DirectionState;
use crate::bw_pool::BandwidthAcquirer;

/// An [`AsyncRead`] wrapper that acquires bandwidth before yielding bytes.
///
/// Every byte read costs one token from the shared pool. A single
/// [`AsyncRead::poll_read`] is capped to the pool's bandwidth so a large buffer is
/// filled in many chunks.
#[derive(Debug)]
#[pin_project]
pub struct GlobalRateLimitedReader<R> {
    /// The underlying reader bytes are read from.
    #[pin]
    inner: R,
    /// The per-direction state holding an acquirer and permit.
    state: DirectionState,
}

impl<R> GlobalRateLimitedReader<R> {
    /// Construct a reader that spends one token per byte from the `acquirer`'s pool.
    pub fn new(inner: R, acquirer: BandwidthAcquirer) -> Self {
        Self {
            inner,
            state: DirectionState::new(acquirer),
        }
    }

    /// Cap each read to request at most `max_chunk` tokens.
    ///
    /// Without this, a single read can request the buffer length of tokens which can be
    /// arbitrarily large compared to the actual read. Yes the [`crate::bw_pool::Permit`]
    /// would refund but it could starve other requests.
    pub fn with_max_chunk(mut self, max_chunk: NonZero<usize>) -> Self {
        self.state.set_max_chunk(max_chunk);
        self
    }
}

impl<R> AsyncRead for GlobalRateLimitedReader<R>
where
    R: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let this = self.project();
        poll_read_limited(this.inner, this.state, cx, buf)
    }
}

/// Helper: Rate-limited [`AsyncRead::poll_read`] of `inner` using the given read
/// direction `state`. This is used by multiple object hence why in a read helper.
pub(super) fn poll_read_limited<R: AsyncRead>(
    inner: Pin<&mut R>,
    state: &mut DirectionState,
    cx: &mut Context<'_>,
    buf: &mut [u8],
) -> Poll<Result<usize, Error>> {
    // For an empty buffer, just defer to the inner, no need to bother for a permit.
    if buf.is_empty() {
        return inner.poll_read(cx, buf);
    }

    // Acquire or reuse a permit and learn how many bytes we are cleared to read.
    let available = ready!(state.poll_acquire(cx, buf.len()))?;
    let buf = &mut buf[..available];

    match inner.poll_read(cx, buf) {
        Poll::Pending => Poll::Pending,
        // The inner had an error, drop the permit to refund.
        Poll::Ready(Err(e)) => {
            state.refund();
            Poll::Ready(Err(e))
        }
        // Claim what was read and refund the rest.
        Poll::Ready(Ok(read)) => {
            state.commit(read);
            Poll::Ready(Ok(read))
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    use futures::{AsyncReadExt as _, FutureExt as _};

    use crate::bw_pool::BandwidthPool;

    #[test]
    fn fast_path() {
        let (pool, _refiller) = BandwidthPool::new(100);
        let mut reader = GlobalRateLimitedReader::new(&[1_u8; 50][..], pool.new_acquirer());

        // Read 30 bytes hits the fast path.
        let mut buf = [0; 30];
        assert_eq!(reader.read(&mut buf).now_or_never().unwrap().unwrap(), 30);
        assert_eq!(pool.available(), 70);
        assert_eq!(buf, [1; 30]);
    }

    #[test]
    fn capped_pool_capacity() {
        let (pool, _refiller) = BandwidthPool::new(30);
        let mut reader = GlobalRateLimitedReader::new(&[1_u8; 100][..], pool.new_acquirer());

        // Read 100 in a pool of capacity 30 means only 30 is written.
        let mut buf = [0; 100];
        assert_eq!(reader.read(&mut buf).now_or_never().unwrap().unwrap(), 30);
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn max_chunk() {
        let (pool, _refiller) = BandwidthPool::new(100);
        let mut reader = GlobalRateLimitedReader::new(&[1_u8; 50][..], pool.new_acquirer())
            .with_max_chunk(NonZero::new(10).unwrap());

        // Buffer is 30 but max_chunk caps the request to 10 tokens.
        let mut buf = [0; 30];
        assert_eq!(reader.read(&mut buf).now_or_never().unwrap().unwrap(), 10);
        assert_eq!(pool.available(), 90);
    }

    #[test]
    fn pending() {
        let (pool, mut refiller) = BandwidthPool::new(30);
        let mut reader = GlobalRateLimitedReader::new(&[1_u8; 100][..], pool.new_acquirer());

        // Empty the pool with a read of 30.
        let mut buf = [0; 30];
        assert_eq!(reader.read(&mut buf).now_or_never().unwrap().unwrap(), 30);

        // Pool is empty so the next read is Pending until a refill.
        let mut read = reader.read(&mut buf);
        assert!((&mut read).now_or_never().is_none());
        assert_eq!(refiller.refill(30), None);
        assert_eq!((&mut read).now_or_never().unwrap().unwrap(), 30);
    }

    #[test]
    fn pool_closed() {
        let (pool, refiller) = BandwidthPool::new(30);
        let mut reader = GlobalRateLimitedReader::new(&[1_u8; 200][..], pool.new_acquirer());

        // Read 10.
        let mut buf = [0; 10];
        assert_eq!(reader.read(&mut buf).now_or_never().unwrap().unwrap(), 10);

        // Drain the pool then drop the refiller. The next read has to enqueue but it
        // will fail because the pool has been closed due to the refiller closing.
        let mut buf = [0; 20];
        assert_eq!(reader.read(&mut buf).now_or_never().unwrap().unwrap(), 20);
        drop(refiller);
        let mut buf = [0; 10];
        assert!(reader.read(&mut buf).now_or_never().unwrap().is_err());
    }
}
