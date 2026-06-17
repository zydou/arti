//! Rate limiter objects backed by a shared [`crate::bw_pool::BandwidthPool`] making them
//! global as in sharable accross multiple thread/tasks.
//!
//! Available in this module is:
//!     * A [`sink::GlobalRateLimitedSink`] that implements [`futures::Sink`].
//!
//! Please read carefully each submodule documentation before using. These can be tricky
//! to operate without a license ;).

mod sink;

pub use sink::GlobalRateLimitedSink;

use std::io::Error;
use std::num::NonZero;
use std::task::{Context, Poll, ready};

use crate::bw_pool::{BandwidthAcquirer, Permit};

/// Convert a `usize` to `u64`. Infallible on every platform we support.
fn to_u64(x: usize) -> u64 {
    x.try_into().expect("failed usize to u64 conversion")
}

/// Rate-limiting state for a single direction.
///
/// It has everything needed to rate limit one direction that is a [`BandwidthAcquirer`],
/// the in-flight [`Permit`] and an optional maximum chunk.
///
/// This is used by the [`GlobalRateLimitedReader`] and [`GlobalRateLimitedWriter`] as
/// they share that same behavior for each direction (read and write).
#[derive(Debug)]
struct DirectionState {
    /// Acquirer used to get a [`Permit`] from the pool for each poll.
    acquirer: BandwidthAcquirer,
    /// The permit for the in-flight IO.
    ///
    /// It is kept here across polls so we never request a grant twice for the same
    /// pending IO. Once the IO completes, the claimed bytes are committed and any tokens
    /// left are refunded into the pool.
    permit: Option<Permit>,
    /// Optional cap on how many tokens a single IO can request.
    ///
    /// If set, an IO requests at most this many tokens as long as the buffer is bigger.
    /// `None` bounds the request to the buffer size.
    max_chunk: Option<NonZero<usize>>,
}

impl DirectionState {
    /// Constructor.
    fn new(acquirer: BandwidthAcquirer) -> Self {
        Self {
            acquirer,
            permit: None,
            max_chunk: None,
        }
    }

    /// Cap each IO request at most `max_chunk` tokens.
    ///
    /// Without this, a single poll can request the buffer length of tokens which can be
    /// arbitrarily large compared to the actual IO.
    fn set_max_chunk(&mut self, max_chunk: NonZero<usize>) {
        self.max_chunk = Some(max_chunk);
    }

    /// Acquire or reuse a permit for an IO for the given amount of `tokens`.
    ///
    /// Returns the number of tokens the caller is cleared for. This is always capped to
    /// the state's max chunk. The grant itself is capped to the pool capacity.
    ///
    /// A granted [`Permit`] is kept until [`Self::commit`] is called to indicate how
    /// many tokens were used. It is also dropped when [`Self::refund`] is called.
    ///
    /// This makes it that calling [`Self::poll_acquire`] multiple times is safe and
    /// won't request multiple [`Permit`].
    fn poll_acquire(&mut self, cx: &mut Context<'_>, tokens: usize) -> Poll<Result<usize, Error>> {
        if self.permit.is_none() {
            let want = match self.max_chunk {
                Some(max) => tokens.min(max.get()),
                None => tokens,
            };
            let permit =
                ready!(self.acquirer.poll_acquire(cx, to_u64(want))).map_err(Error::other)?;
            self.permit = Some(permit);
        }
        let permit = self.permit.as_mut().expect("permit just set");

        // Make sure we don't exceed the buffer size. Extra safety measure.
        let available = permit
            .granted()
            .try_into()
            .unwrap_or(usize::MAX)
            .min(tokens);
        Poll::Ready(Ok(available))
    }

    /// Commit `tokens` after a successful IO and refund any leftover tokens.
    fn commit(&mut self, tokens: usize) {
        // Dropped at the end of this function which refunds the leftover.
        let mut permit = self.permit.take().expect("permit disappeared");
        // The claim should always succeed but if the inner misbehaves and reports a bigger
        // value than was granted, we claim it all to avoid refunding what was actually used.
        if !permit.claim(to_u64(tokens)) {
            permit.claim_all();
        }
    }

    /// Simply drop the [`Permit`] we hold (if any) to refund it.
    fn refund(&mut self) {
        self.permit = None;
    }
}

/// Error returned by the rate limiters in this module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GlobalRateLimitedError<E> {
    /// The bandwidth pool was closed. No more refiller.
    #[error("bandwidth pool closed")]
    Pool(#[from] crate::bw_pool::PoolClosed),
    /// The underlying sink failed.
    #[error("underlying sink error")]
    Sink(#[source] E),
    /// No permit
    #[error("no permit when sending")]
    MissingPermit,
}
