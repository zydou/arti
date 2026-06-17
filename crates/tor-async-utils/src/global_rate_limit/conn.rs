//! A rate limited async duplex connection.
//!
//! An [`AsyncRead`] and [`AsyncWrite`] wrapper that rate limits both directions of a
//! single bidirectional byte stream such as a TCP or TLS connection, by acquiring
//! bandwidth from a [`super::BandwidthAcquirer`] given for each diection (read and
//! write). One byte is one token.

use futures::{AsyncRead, AsyncWrite};
use pin_project::pin_project;
use std::io::Error;
use std::num::NonZero;
use std::pin::Pin;
use std::task::{Context, Poll};

use tor_rtcompat::StreamOps;

use super::DirectionState;
use crate::bw_pool::BandwidthAcquirer;

/// An [`AsyncRead`] and [`AsyncWrite`] wrapper that rate limits each direction of a single
/// bidirectional byte stream.
///
/// Every byte read or written costs one token per direction pool.
#[derive(Debug)]
#[pin_project]
pub struct GlobalRateLimitedConn<S> {
    /// The underlying stream.
    #[pin]
    inner: S,
    /// Rate-limiting state for the read direction.
    read_state: DirectionState,
    /// Rate-limiting state for the write direction.
    write_state: DirectionState,
}

impl<S> GlobalRateLimitedConn<S> {
    /// Constructor.
    ///
    /// We recommend that the `read_acquirer` and `write_acquirer` comme from different
    /// bandwidth pools so one direction doesn't starve the other side. In a
    /// bidirectional setup, this could be equivalent to unidirectionnal.
    pub fn new(
        inner: S,
        read_acquirer: BandwidthAcquirer,
        write_acquirer: BandwidthAcquirer,
    ) -> Self {
        Self {
            inner,
            read_state: DirectionState::new(read_acquirer),
            write_state: DirectionState::new(write_acquirer),
        }
    }

    /// Cap each IO request direction at most `max_chunk` tokens.
    pub fn with_max_chunk(mut self, max_chunk: NonZero<usize>) -> Self {
        self.read_state.set_max_chunk(max_chunk);
        self.write_state.set_max_chunk(max_chunk);
        self
    }
}

impl<S> AsyncRead for GlobalRateLimitedConn<S>
where
    S: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let this = self.project();
        super::reader::poll_read_limited(this.inner, this.read_state, cx, buf)
    }
}

impl<S> AsyncWrite for GlobalRateLimitedConn<S>
where
    S: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = self.project();
        super::writer::poll_write_limited(this.inner, this.write_state, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_close(cx)
    }
}

/// Implement [`StreamOps`] and forward it to the inner stream.
///
/// Every operation is untouched, rate-limiting is not applied here.
impl<S> StreamOps for GlobalRateLimitedConn<S>
where
    S: StreamOps,
{
    fn set_tcp_notsent_lowat(&self, notsent_lowat: u32) -> std::io::Result<()> {
        self.inner.set_tcp_notsent_lowat(notsent_lowat)
    }

    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        self.inner.new_handle()
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

    use futures::{AsyncReadExt as _, AsyncWriteExt as _, FutureExt as _, io::Cursor};

    use crate::bw_pool::BandwidthPool;

    /// Build a conn over a [`Cursor`] with a 100 bytes length vector.
    fn new_conn(
        read_pool: &BandwidthPool,
        write_pool: &BandwidthPool,
    ) -> GlobalRateLimitedConn<Cursor<Vec<u8>>> {
        GlobalRateLimitedConn::new(
            Cursor::new(vec![1_u8; 100]),
            read_pool.new_acquirer(),
            write_pool.new_acquirer(),
        )
    }

    #[test]
    fn basic_conn() {
        let (read_pool, _rr) = BandwidthPool::new(100);
        let (write_pool, _wr) = BandwidthPool::new(100);
        let mut conn = new_conn(&read_pool, &write_pool);

        // A read of 30 only spends from the read pool.
        let mut buf = [0; 30];
        assert_eq!(conn.read(&mut buf).now_or_never().unwrap().unwrap(), 30);
        assert_eq!(read_pool.available(), 70);
        assert_eq!(write_pool.available(), 100);

        // A write of 40 only spends from the write pool.
        assert_eq!(conn.write(&[1; 40]).now_or_never().unwrap().unwrap(), 40);
        assert_eq!(read_pool.available(), 70);
        assert_eq!(write_pool.available(), 60);
    }

    #[test]
    fn write_no_read_block() {
        let (read_pool, _rr) = BandwidthPool::new(50);
        let (write_pool, _wr) = BandwidthPool::new(50);
        let mut conn = new_conn(&read_pool, &write_pool);

        // Drain the write pool.
        assert_eq!(conn.write(&[1; 50]).now_or_never().unwrap().unwrap(), 50);

        // A further write is Pending until a refill...
        let mut write = conn.write(&[2; 50]);
        assert!((&mut write).now_or_never().is_none());

        // But a read is not blocked.
        let mut buf = [0; 30];
        assert_eq!(conn.read(&mut buf).now_or_never().unwrap().unwrap(), 30);
        assert_eq!(read_pool.available(), 20);
    }
}
