//! A rate limited sink.
//!
//! A [`Sink`] wrapper that rate limits the items it forwards by acquiring bandwidth from
//! a [`crate::bw_pool::BandwidthPool`] before each item is sent.
//!
//! # Example
//!
//! ```
//! use futures::{SinkExt as _, channel::mpsc};
//! use tor_async_utils::global_rate_limit::GlobalRateLimitedSink;
//! use tor_async_utils::bw_pool::BandwidthPool;
//!
//! futures::executor::block_on(async {
//!     let (pool, _refiller) = BandwidthPool::new(64 * 1024);
//!     let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
//!     let mut sink = GlobalRateLimitedSink::new(tx, pool.new_acquirer(), 512);
//!
//!     // The pool starts full so this is served from the fast path.
//!     sink.send(vec![0; 512]).await.unwrap();
//! });
//! ```

use futures::Sink;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use crate::bw_pool::{BandwidthAcquirer, Permit};
use crate::global_rate_limit::GlobalRateLimitedError;

/// A [`Sink`] wrapper that acquires bandwidth before forwarding each item.
///
/// Every item costs the same fixed number of `tokens` given to [`Self::new`], so this is
/// intended for sinks whose items are of roughly the same size, such as Tor cells :).
#[derive(Debug)]
#[pin_project]
pub struct GlobalRateLimitedSink<S> {
    /// The underlying sink items are forwarded to.
    #[pin]
    inner: S,
    /// Acquirer used to get a [`Permit`] from the pool for each item.
    acquirer: BandwidthAcquirer,
    /// The number of tokens each item costs, requested from the pool per item.
    tokens: u64,
    /// The permit for the next item acquired by [`Sink::poll_ready`].
    ///
    /// It is kept here across `poll_ready` calls so we never request a grant twice for
    /// the same item. It is consumed by [`Sink::start_send`]. If the sink is dropped
    /// a permit, it is refunded to the pool.
    permit: Option<Permit>,
}

impl<S> GlobalRateLimitedSink<S> {
    /// Construct a sink that spends `tokens` tokens from the `acquirer`'s pool for every
    /// item it forwards.
    pub fn new(inner: S, acquirer: BandwidthAcquirer, tokens: u64) -> Self {
        Self {
            inner,
            acquirer,
            tokens,
            permit: None,
        }
    }
}

impl<S, Item> Sink<Item> for GlobalRateLimitedSink<S>
where
    S: Sink<Item>,
{
    type Error = GlobalRateLimitedError<S::Error>;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        // check the inner sink first so if it is backpressured, don't claim the tokens.
        ready!(this.inner.poll_ready(cx)).map_err(GlobalRateLimitedError::Sink)?;

        // If no permit, get one.
        if this.permit.is_none() {
            let permit = ready!(this.acquirer.poll_acquire(cx, *this.tokens))?;
            *this.permit = Some(permit);
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        let this = self.project();

        // Consume the permit that a successful poll_ready() acquired. We'll then claim
        // all tokens as a permit is for the size of the item. We could use this.tokens
        // but this protects us for the case where the number of tokens changed in
        // between calls. Very unlikely but hey, safety first!
        let mut permit = this
            .permit
            .take()
            .ok_or(GlobalRateLimitedError::MissingPermit)?;
        // TODO(relay): This can't work like this with partial permit. We need to check
        // how many we got and claim that.
        permit.claim_all();

        this.inner
            .start_send(item)
            .map_err(GlobalRateLimitedError::Sink)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .inner
            .poll_flush(cx)
            .map_err(GlobalRateLimitedError::Sink)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .inner
            .poll_close(cx)
            .map_err(GlobalRateLimitedError::Sink)
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

    use futures::channel::mpsc;
    use futures::{FutureExt as _, SinkExt as _, StreamExt as _};

    use crate::bw_pool::BandwidthPool;

    #[test]
    fn fast_path() {
        let (pool, _refiller) = BandwidthPool::new(100);
        let (tx, mut rx) = mpsc::channel::<u64>(4);
        let mut sink = GlobalRateLimitedSink::new(tx, pool.new_acquirer(), 30);

        // The pool starts full: three sends go through the fast path...
        for i in 0..3 {
            sink.send(i).now_or_never().unwrap().unwrap();
        }
        // Three sends means 30 tokens each time (90 total) so 100 - 90 = 10 left.
        assert_eq!(pool.available(), 10);

        // Fourth send, pool is dry so we end up Pending.
        let mut send4 = sink.send(4);
        assert!((&mut send4).now_or_never().is_none());

        // Make sure we got the three initial sends.
        for i in 0..3 {
            assert_eq!(rx.next().now_or_never().unwrap(), Some(i));
        }
    }

    #[test]
    fn fast_path_refill() {
        let (pool, mut refiller) = BandwidthPool::new(30);
        let (tx, mut rx) = mpsc::channel::<u64>(4);
        let mut sink = GlobalRateLimitedSink::new(tx, pool.new_acquirer(), 30);

        // Uses the full pool (30).
        sink.send(1).now_or_never().unwrap().unwrap();

        // Pool is empty. The send is Pending until refill.
        let mut send2 = sink.send(2);
        assert!((&mut send2).now_or_never().is_none());
        assert_eq!(refiller.refill(30), None);
        assert!(matches!((&mut send2).now_or_never(), Some(Ok(()))));
        drop(send2);

        // Make sure we got the two sends.
        for i in 0..2 {
            assert_eq!(rx.next().now_or_never().unwrap(), Some(i + 1));
        }
    }

    #[test]
    fn backpressure() {
        let (pool, _refiller) = BandwidthPool::new(100);
        // Buffer of zero here means the capacity is 1 because 1 sender. That is from the
        // channel() documentation.
        let (tx, mut rx) = mpsc::channel::<u64>(0);
        let mut sink = GlobalRateLimitedSink::new(tx, pool.new_acquirer(), 10);

        // Use feed() so we don't flush. We just want to fill the channel.
        sink.feed(1).now_or_never().unwrap().unwrap();
        assert_eq!(pool.available(), 90);

        // The channel is full. The feed() will be Pending before any tokens are claimed.
        let mut feed2 = sink.feed(2);
        assert!((&mut feed2).now_or_never().is_none());
        drop(feed2);
        assert_eq!(pool.available(), 90);

        // Consuming the channel which should allow the next feed() to claim tokens.
        assert_eq!(rx.next().now_or_never().unwrap(), Some(1));
        sink.feed(2).now_or_never().unwrap().unwrap();
        assert_eq!(pool.available(), 80);
    }

    #[test]
    fn pool_closed() {
        let (pool, refiller) = BandwidthPool::new(10);
        let (tx, _rx) = mpsc::channel::<u64>(4);
        let mut sink = GlobalRateLimitedSink::new(tx, pool.new_acquirer(), 10);

        // Drains the pool.
        sink.send(1).now_or_never().unwrap().unwrap();
        assert_eq!(pool.available(), 0);

        // Without a refiller and no tokens left, the pool is closed and the sink errors.
        drop(refiller);
        assert!(matches!(
            sink.send(2).now_or_never(),
            Some(Err(GlobalRateLimitedError::Pool(_)))
        ));
    }
}
