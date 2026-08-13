//! Rate limiter objects backed by a shared [`crate::bw_pool::BandwidthPool`] making them
//! global as in sharable accross multiple thread/tasks.
//!
//! Available in this module is:
//!     * A [`sink::GlobalRateLimitedSink`] that implements [`futures::Sink`].
//!     * A [`writer::GlobalRateLimitedWriter`] that implements [`futures::AsyncWrite`].
//!     * A [`reader::GlobalRateLimitedReader`] that implements [`futures::AsyncRead`].
//!     * A [`conn::GlobalRateLimitedConn`] that implements both [`futures::AsyncRead`] and
//!       [`futures::AsyncWrite`], rate limiting each direction independently.
//!
//! Please read carefully each submodule documentation before using. These can be tricky
//! to operate without a license ;).

mod conn;
mod reader;
mod sink;
mod writer;

pub use conn::GlobalRateLimitedConn;
pub use reader::GlobalRateLimitedReader;
pub use sink::GlobalRateLimitedSink;
pub use writer::GlobalRateLimitedWriter;

use std::io::Error;
use std::num::NonZero;
use std::task::{Context, Poll, ready};

use crate::bw_pool::{BandwidthAcquirer, Permit};

/// Convert a `usize` to `u64`. Infallible on every platform we support.
fn to_u64(x: usize) -> u64 {
    x.try_into().expect("failed usize to u64 conversion")
}

/// Convert a `u64` to `usize`. Infallible on every platform we support.
fn to_usize(x: u64) -> usize {
    x.try_into().expect("failed u64 to usize conversion")
}

/// Rate-limiting state for a single direction.
///
/// It has everything needed to rate limit one direction that is a [`BandwidthAcquirer`]
/// and an optional maximum chunk.
///
/// This is used by the [`GlobalRateLimitedReader`] and [`GlobalRateLimitedWriter`] as
/// they share that same behavior for each direction (read and write).
#[derive(Debug)]
struct DirectionState {
    /// Acquirer used to get a [`Permit`] from the pool for each poll.
    acquirer: BandwidthAcquirer,
    /// Cap on how many tokens a single IO can request.
    ///
    /// An IO requests at most this many tokens as long as the buffer is bigger.
    max_chunk: NonZero<usize>,
}

impl DirectionState {
    /// Constructor.
    fn new(acquirer: BandwidthAcquirer, max_chunk: NonZero<usize>) -> Self {
        Self {
            acquirer,
            max_chunk,
        }
    }

    /// Acquire a permit for an IO of the given amount of `tokens`.
    ///
    /// The request is capped to the state's max chunk. The grant itself is capped
    /// to the pool capacity so the returned [`Permit`] can hold less than `tokens`.
    ///
    /// The [`Permit`] is handed to the caller rather than kept here so that it lives
    /// exactly as long as the IO attempt it is for. If the underlying IO turns out to be
    /// [`Poll::Pending`], the caller drops it and the tokens are refunded to the pool
    /// instead of being parked for as long as the connection is not ready. That matters
    /// with many connections as we don't want to hold off ready connections on already
    /// allocated permits for non ready connections.
    ///
    /// The cost is that the caller re-acquires on the next poll rather than resuming
    /// with what it already had. It is by design.
    fn poll_acquire(&mut self, cx: &mut Context<'_>, tokens: usize) -> Poll<Result<Permit, Error>> {
        let want = tokens.min(self.max_chunk.get());
        let permit = ready!(self.acquirer.poll_acquire(cx, to_u64(want))).map_err(Error::other)?;
        Poll::Ready(Ok(permit))
    }

    /// Claim `tokens` on `permit` after a successful IO.
    ///
    /// The permit is consumed so whatever is left unclaimed is refunded on drop.
    fn commit(mut permit: Permit, tokens: usize) {
        // The claim should always succeed but if the inner misbehaves and reports a bigger
        // value than was granted, we claim it all to avoid refunding what was actually used.
        if permit.claim(to_u64(tokens)).is_ok() {
            permit.claim_all();
        }
    }
}

/// Error returned by the rate limiters in this module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GlobalRateLimitedError<E> {
    /// The bandwidth pool is on error. No more refiller.
    #[error("bandwidth pool error")]
    Pool(#[from] crate::bw_pool::BwPoolError),
    /// The underlying sink failed.
    #[error("underlying sink error")]
    Sink(#[source] E),
    /// No permit
    #[error("no permit when sending")]
    MissingPermit,
}
