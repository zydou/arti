//! A rate limited async writer.
//!
//! An [`AsyncWrite`] wrapper that rate limits the bytes it forwards by acquiring bandwidth
//! from a [`crate::bw_pool::BandwidthPool`] before each write. One byte is one token.
//!
//! # Example
//!
//! ```
//! use futures::AsyncWriteExt as _;
//! use tor_async_utils::global_rate_limit::GlobalRateLimitedWriter;
//! use tor_async_utils::bw_pool::BandwidthPool;
//!
//! futures::executor::block_on(async {
//!     let (pool, _refiller) = BandwidthPool::new(64 * 1024);
//!     let mut writer = GlobalRateLimitedWriter::new(Vec::new(), pool.new_acquirer());
//!
//!     // The pool starts full so this is served from the fast path.
//!     writer.write_all(&[0; 512]).await.unwrap();
//! });
//! ```

use futures::AsyncWrite;
use pin_project::pin_project;
use std::io::Error;
use std::num::NonZero;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use super::DirectionState;
use crate::bw_pool::BandwidthAcquirer;

/// An [`AsyncWrite`] wrapper that acquires bandwidth before writing bytes.
///
/// A single byte is one token which we acquire from the shared pool. A single
/// [`AsyncWrite::poll_write`] is capped to the pool's capacity so a large buffer has to
/// go in written several chunks.
#[derive(Debug)]
#[pin_project]
pub struct GlobalRateLimitedWriter<W> {
    /// The underlying writer bytes are forwarded to.
    #[pin]
    inner: W,
    /// The per-direction state holding an acquirer and permit.
    state: DirectionState,
}

impl<W> GlobalRateLimitedWriter<W> {
    /// Constructor.
    ///
    /// This writer is rate limited as 1 byte per token.
    pub fn new(inner: W, acquirer: BandwidthAcquirer) -> Self {
        Self {
            inner,
            state: DirectionState::new(acquirer),
        }
    }

    /// Cap each write to request at most `max_chunk` tokens.
    ///
    /// Without this, a single write can request the buffer length of tokens which can be
    /// arbitrarily large compared to the actual write. Yes the
    /// [`crate::bw_pool::Permit`] would refund but it could starve other requests.
    pub fn with_max_chunk(mut self, max_chunk: NonZero<usize>) -> Self {
        self.state.set_max_chunk(max_chunk);
        self
    }
}

impl<W> AsyncWrite for GlobalRateLimitedWriter<W>
where
    W: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = self.project();
        poll_write_limited(this.inner, this.state, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_close(cx)
    }
}

/// Helper: Rate-limited [`AsyncWrite::poll_write`] of `inner` using the given read
/// direction `state`. This is used by multiple object hence why in a write helper.
pub(super) fn poll_write_limited<W: AsyncWrite>(
    inner: Pin<&mut W>,
    state: &mut DirectionState,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<Result<usize, Error>> {
    // For an empty buffer, just defer to the inner, no need to bother for a permit.
    if buf.is_empty() {
        return inner.poll_write(cx, buf);
    }

    // Acquire (or reuse) a permit and learn how many bytes we are cleared to write.
    let available = ready!(state.poll_acquire(cx, buf.len()))?;
    let buf = &buf[..available];

    match inner.poll_write(cx, buf) {
        Poll::Pending => Poll::Pending,
        // The inner had an error, drop the permit to refund.
        Poll::Ready(Err(e)) => {
            state.refund();
            Poll::Ready(Err(e))
        }
        // Claim what was sent and refund the rest.
        Poll::Ready(Ok(written)) => {
            state.commit(written);
            Poll::Ready(Ok(written))
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

    use futures::{AsyncWriteExt as _, FutureExt as _};

    use crate::bw_pool::BandwidthPool;

    #[test]
    fn fast_path() {
        let (pool, _refiller) = BandwidthPool::new(100);
        let mut writer = GlobalRateLimitedWriter::new(Vec::new(), pool.new_acquirer());

        // Writing 30 bytes hits the fast path.
        assert_eq!(writer.write(&[0; 30]).now_or_never().unwrap().unwrap(), 30);
        assert_eq!(pool.available(), 70);
    }

    #[test]
    fn capped_pool_capacity() {
        let (pool, _refiller) = BandwidthPool::new(30);
        let mut writer = GlobalRateLimitedWriter::new(Vec::new(), pool.new_acquirer());

        // Writing 100 in a pool of capacity 30 means only 30 is written.
        assert_eq!(writer.write(&[0; 100]).now_or_never().unwrap().unwrap(), 30);
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn max_chunk() {
        let (pool, _refiller) = BandwidthPool::new(100);
        let mut writer = GlobalRateLimitedWriter::new(Vec::new(), pool.new_acquirer())
            .with_max_chunk(NonZero::new(10).unwrap());

        // Buffer is 30 but max_chunk caps the request to 10 tokens.
        assert_eq!(writer.write(&[0; 30]).now_or_never().unwrap().unwrap(), 10);
        assert_eq!(pool.available(), 90);
    }

    #[test]
    fn pending() {
        let (pool, mut refiller) = BandwidthPool::new(30);
        let mut writer = GlobalRateLimitedWriter::new(Vec::new(), pool.new_acquirer());

        // Empty the pool with a write of 30.
        assert_eq!(writer.write(&[0; 30]).now_or_never().unwrap().unwrap(), 30);

        // Pool is empty so the next write is Pending until a refill.
        let mut write = writer.write(&[0; 30]);
        assert!((&mut write).now_or_never().is_none());
        assert_eq!(refiller.refill(30), None);
        // Pool is refilled, 30 is written.
        assert_eq!((&mut write).now_or_never().unwrap().unwrap(), 30);
    }

    #[test]
    fn pool_closed() {
        let (pool, refiller) = BandwidthPool::new(30);
        let mut writer = GlobalRateLimitedWriter::new(Vec::new(), pool.new_acquirer());

        // Write 10.
        assert_eq!(writer.write(&[0; 10]).now_or_never().unwrap().unwrap(), 10);

        // Drain the pool then drop the refiller. The next write has to enqueue but it
        // will fail because the pool has been closed due to the refiller closing.
        assert_eq!(writer.write(&[0; 20]).now_or_never().unwrap().unwrap(), 20);
        drop(refiller);
        assert!(writer.write(&[0; 10]).now_or_never().unwrap().is_err());
    }
}
