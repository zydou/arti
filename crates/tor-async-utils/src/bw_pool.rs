//! A shared token pool with a lock-free fast path and FIFO waiting queue ensuring basic
//! fairness.
//!
//! [`BandwidthPool`] is a set of tokens that many tasks can draw from concurrently
//! representing a bandwidth [`Permit`]. Deciding how many tokens become available and
//! when is the job of the [`BandwidthRefiller`] which should be run in a task that has a
//! reference to the pool's token bucket.
//!
//! # Pool
//!
//! The pool holds the bandwidth token balance (bucket) available for any
//! [`BandwidthAcquirer`] to attempt to acquire concurrently.
//!
//! The [`BandwidthPool`] can be shared between an arbitrary amount of tasks and each
//! task needs to get a [`BandwidthAcquirer`] from the [`BandwidthPool::new_acquirer`]
//! method.
//!
//! The acquirer is designed to be allocated once and reused throughout the owner object
//! lifetime, thereby reducing the number of allocations needed at runtime.
//!
//! In order to be granted permission to use a certain number of tokens, the task needs
//! to call [`BandwidthAcquirer::poll_acquire`] with the number of tokens it wants. It
//! has to be called in the context of a task so it can be woken up once it is granted.
//!
//! ## Acquisition Mechanism
//!
//! The pool design is that there is a so called fast-path that is meant to allow a
//! thundering herd to attempt to acquire tokens in an atomic way as long as the pool has
//! available tokens.
//!
//! Once the pool is empty, new acquire requests go into a FIFO queue for fairness and
//! are served as the pool gets refilled by the [`BandwidthRefiller`] task.
//!
//! A [`Permit`] is handed out once the full requested amount has been deducted from the
//! pool as in available. The permit holds the granted tokens and the holder claims what
//! it actually uses with [`Permit::claim`] (or [`Permit::claim_all`]). Whatever is left
//! unclaimed in the permit is refunded to the pool when it is dropped.
//!
//! ## Refund
//!
//! Refunded tokens always go back to the fast-path pool. Fairness is preserved by the
//! fast path being gated on if we have any pending requests. This is so no newcomer
//! jumps the queue. The [`BandwidthRefiller`] reclaims whatever sits in the pool on its
//! next refill and serves the queued requests. Once emptied, the fast path is re-opened.
//!
//! ## Teardown
//!
//! There is deliberately no cancellation mechanism for a queued request. If a
//! [`BandwidthAcquirer`] is torn down while its request is queued, the refiller will
//! eventually fund that request anyway, set its grant flag, and wake a task that no
//! longer exists. The granted tokens are simply forfeited.
//!
//! This is a considered trade-off and we believe in the context of a Tor relay, losing a
//! grant is not significant at all in the large picture of available bandwidth. The
//! trade-off allows us to reduce a lot of complexity.

mod bucket;
mod refiller;

use futures::channel::mpsc;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::bw_pool::bucket::AtomicTokenBucket;
use crate::bw_pool::refiller::RefillWaiter;

// Public export as the outside world needs this.
pub use crate::bw_pool::refiller::BandwidthRefiller;

/// Proof that the requested number of tokens were granted.
///
/// If dropped, any remaining tokens will be refunded hence why there is a reference to
/// the shared bucket.
#[derive(Debug)]
#[must_use = "a Permit are tokens that have already been deducted"]
pub struct Permit {
    /// The bucket the unclaimed tokens are refunded to when this permit is dropped.
    bucket: Arc<AtomicTokenBucket>,
    /// How many granted tokens this permit still has.
    ///
    /// Lowered by the claim methods. What is left is refunded on drop.
    granted: u64,
}

impl Permit {
    /// Construct a permit granting `granted` tokens.
    ///
    /// We keep a reference to the bucket for a refund if any.
    fn new(bucket: Arc<AtomicTokenBucket>, granted: u64) -> Self {
        Self { bucket, granted }
    }

    /// Claim `tokens` from this permit.
    ///
    /// Returns true if the permit had at least `tokens` that are now claimed. Else,
    /// return false and nothing is claimed as in the caller is trying to use more
    /// than it was granted.
    #[must_use]
    pub fn claim(&mut self, tokens: u64) -> bool {
        match self.granted.checked_sub(tokens) {
            Some(left) => {
                self.granted = left;
                true
            }
            None => false,
        }
    }

    /// Claim everything this permit holds.
    ///
    /// Used in the for a Sink implementation that gets its permit in the poll_ready()
    /// which is before the start_send().
    pub fn claim_all(&mut self) {
        let _ = self.claim(self.granted);
    }

    /// How many tokens this permit still has granted a.k.a available.
    pub fn granted(&self) -> u64 {
        self.granted
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        // Refund into the shared pool. Note that the refund will have a no-op on the
        // shared counters if the granted value is zero.
        self.bucket.refund(self.granted);
    }
}

/// Error returned once the pool has been closed as in its [`BandwidthRefiller`] was
/// dropped. We consider the pool closed.
#[derive(Clone, Debug, thiserror::Error)]
#[error("bandwidth pool is closed")]
#[non_exhaustive]
pub struct PoolClosed;

/// A reusable bandwidth acquirer that is designed for an async context (poll).
///
/// The main entry point is [`Self::poll_acquire`] used within the context of a task
/// which, if rate limited, the task gets woken up when the bandwidth usage is granted.
#[derive(Debug)]
pub struct BandwidthAcquirer {
    /// The shared waiter. Reused for every acquire.
    waiter: Arc<RefillWaiter>,
    /// Whether this acquirer currently has a request enqueued with the refiller.
    ///
    /// Prevent multi poll to avoid queuing a duplicate request with a different waker.
    in_flight: bool,
    /// The bandwidth pool attached to this acquirer.
    pool: BandwidthPool,
}

impl BandwidthAcquirer {
    /// Create a reusable [`BandwidthAcquirer`] for the given `pool`.
    ///
    /// This is the only allocation an acquirer makes. It can only be called from
    /// [`BandwidthPool::new_acquirer`].
    ///
    /// The number of tokens to acquire is chosen per [`Self::poll_acquire`] call.
    fn new(pool: BandwidthPool) -> Self {
        Self {
            waiter: Arc::new(RefillWaiter::new()),
            in_flight: false,
            pool,
        }
    }

    /// Build the [`Permit`].
    ///
    /// This sets the `in-flight` to false and reset `needed` as we now grant the permit.
    fn grant_permit(&mut self) -> Permit {
        let granted = self.waiter.needed();
        self.in_flight = false;
        self.waiter.set_needed(0);
        Permit::new(Arc::clone(&self.pool.bucket), granted)
    }

    /// Poll to take `tokens` tokens from the pool, async waiting if the pool is dry.
    ///
    /// The number of `tokens` is per call so the same acquirer can request a different
    /// amount each time.
    ///
    /// If the request is in flight, the `tokens` argument is ignored and the originally
    /// requested amount is used. Only when a [`Permit`] is emitted that a new `tokens`
    /// value can be used.
    ///
    /// Returns a [`BwPoolError::PoolClosed`] error if the [`BandwidthRefiller`] has been
    /// dropped.
    pub fn poll_acquire(
        &mut self,
        cx: &mut Context<'_>,
        tokens: u64,
    ) -> Poll<Result<Permit, PoolClosed>> {
        if !self.in_flight {
            // Cap to the pool capacity as the refiller can never go beyond the burst.
            let tokens = tokens.min(self.pool.capacity());

            // No request in flight. This is the fast path! The thundering herd is allowed,
            // that is, all tasks race to this and their fairness is sub-contracted to their
            // task scheduler.
            //
            // An under-utilized relay with bandwidth limitation will hit this path most
            // of the time.
            if let Some(permit) = self.pool.try_acquire(tokens) {
                return Poll::Ready(Ok(permit));
            }

            // Enqueue the request as it is not in flight and our bw pool is depleted.
            // This is where the caller gets to wait on bw availability and the refilling
            // process is triggered.
            match self.enqueue_request(cx, tokens) {
                Ok(()) => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            };
        }

        // Optimization. Before re-registering the waker (see why below), check if we were
        // granted. This is very cheap to call and avoids the waker registration complexity.
        // However, it is NOT critical to the lockless state of this pool.
        if self.waiter.is_granted() {
            return Poll::Ready(Ok(self.grant_permit()));
        }

        // The async contract here is that even if we registered a previous Waker before,
        // the one given right now is the one that is expected to be woken. Hence, the
        // register() again.
        //
        // We then check again if the tokens were granted because of the documented
        // `AtomicWaker` pattern that goes like this:
        //
        //      sink:     check if granted -> false
        //      refiller: grant the tokens. waker.wake()
        //      sink:     register(new waker). return Pending.
        //
        // That new waker is never woken up because the grant was done just before hence
        // why we re-check the granted tokens.
        self.waiter.set_waker(cx.waker());
        if self.waiter.is_granted() {
            return Poll::Ready(Ok(self.grant_permit()));
        }

        // Check if the refiller is gone. Reason this is done at the end is because we
        // want to avoid this issue:
        //
        //      refiller: grant tokens. waker.wake()
        //      refiller: drop() as in dropped
        //      sink:     poll_acquire() is called and notices the grant.
        //
        // The race shows that we would miss the grant even if the refiller is gone. The
        // end result is that we get to at least send these bytes before the whole arti
        // relay collapses.
        if self.pool.is_closed() {
            // The refiller is gone; nobody will ever serve us.
            self.in_flight = false;
            return Poll::Ready(Err(PoolClosed));
        }

        Poll::Pending
    }

    /// Enqueue a request for `tokens` tokens that is NOT in flight.
    ///
    /// Return a [`PoolClosed`] error if the refiller is gone.
    fn enqueue_request(&mut self, cx: &mut Context<'_>, tokens: u64) -> Result<(), PoolClosed> {
        // Reset the waiter with this new waker.
        self.waiter.reset(cx.waker());
        // Remember the in-flight amount so we can grant the permit later from it.
        self.waiter.set_needed(tokens);
        // Add the waiter before sending to avoid this race:
        //
        //      acquirer: send request
        //      refiller: serve request
        //      acquirer: add waiter <-- without any request.
        //
        // If the send errors, we'll remove the waiter.
        self.pool.bucket.add_waiter();
        // Send the waiter. Notice, this is the only dynamic allocation in this path
        // because it is sent on an unbounded MPSC queue.
        if self
            .pool
            .requests
            .unbounded_send(Arc::clone(&self.waiter))
            .is_err()
        {
            self.pool.bucket.remove_waiter();
            // The refiller is gone, the pool is closed.
            return Err(PoolClosed);
        }
        self.in_flight = true;
        Ok(())
    }
}

/// A shareable bandwidth pool.
///
/// This can be cloned and given to each task requiring bandwidth limitation.
///
/// Each task needs to hold a [`BandwidthAcquirer`] in order to request bandwidth
/// permits from this pool.
#[derive(Clone, Debug)]
pub struct BandwidthPool {
    /// The shared token bucket the fast path claims from.
    bucket: Arc<AtomicTokenBucket>,
    /// Ingress for acquirers that failed the fast path.
    ///
    /// Sending a [`RefillWaiter`] here both enqueues it and wakes the
    /// [`BandwidthRefiller`]
    ///
    /// Unbounded because we never want an acquirer's enqueue to block. the number of
    /// in-flight requests is bounded by the number of acquirers.
    requests: mpsc::UnboundedSender<Arc<RefillWaiter>>,
}

impl BandwidthPool {
    /// Create a new pool that can hold up to `capacity` tokens, and its associated
    /// refiller [`BandwidthRefiller`] that needs to be run in its own task.
    ///
    /// The pool starts full and `capacity` tokens are immediately available to the fast
    /// path.
    pub fn new(capacity: u64) -> (BandwidthPool, BandwidthRefiller) {
        let (tx, rx) = mpsc::unbounded();
        let bucket = Arc::new(AtomicTokenBucket::new(capacity));
        let pool = BandwidthPool {
            bucket: Arc::clone(&bucket),
            requests: tx,
        };
        let refiller = BandwidthRefiller::new(bucket, rx);
        (pool, refiller)
    }

    /// Return a new [`BandwidthAcquirer`] associated to this pool.
    ///
    /// The number of tokens to acquire is chosen per
    /// [`BandwidthAcquirer::poll_acquire`] call, so a single acquirer can be reused for
    /// requests of different sizes.
    ///
    /// It is through an acquirer that one can get permission to use bandwidth. See
    /// [`BandwidthAcquirer::poll_acquire`].
    pub fn new_acquirer(&self) -> BandwidthAcquirer {
        BandwidthAcquirer::new(self.clone())
    }

    /// The maximum number of tokens this pool can hold (its burst).
    pub fn capacity(&self) -> u64 {
        self.bucket.capacity()
    }

    /// Return true iff the refiller is gone, meaning this pool is closed.
    fn is_closed(&self) -> bool {
        self.requests.is_closed()
    }

    /// Try to take `tokens` from the pool without waiting.
    ///
    /// Returns `Some(permit)` if there were enough tokens available right now, or `None`
    /// if the pool is closed or if requests are currently queued. The fast path is gated
    /// by if there are any waiters.
    ///
    /// This never blocks and never enqueues. It is the fast path that the other
    /// acquisition methods use first.
    fn try_acquire(&self, tokens: u64) -> Option<Permit> {
        if self.is_closed() {
            return None;
        }
        // If we have any waiters as in queued requests, the fast path is not available.
        // This prevents new comers from jumping the queue.
        //
        // There is a benign race here: a waiter can enqueue between this and the claim()
        // below. This is equivalent to this call having run entirely before the enqueue,
        // so it is a valid ordering. In other words, the caller will always be before
        // the new waiters and thus accessing the fast path is correct.
        if self.bucket.has_waiters() {
            return None;
        }
        if self.bucket.claim(tokens) {
            Some(Permit::new(Arc::clone(&self.bucket), tokens))
        } else {
            None
        }
    }

    /// Unit tests helper: async acquire wrapping a throwaway [`BandwidthAcquirer`].
    #[cfg(test)]
    pub async fn acquire(&self, tokens: u64) -> Result<Permit, PoolClosed> {
        if let Some(permit) = self.try_acquire(tokens) {
            return Ok(permit);
        }
        let mut acquirer = BandwidthAcquirer::new(self.clone());
        std::future::poll_fn(|cx| acquirer.poll_acquire(cx, tokens)).await
    }

    /// Unit tests helper: The number of tokens currently available to the fast path.
    #[cfg(test)]
    pub(crate) fn available(&self) -> u64 {
        self.bucket.available()
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

    use std::future::Future;
    use std::pin::pin;

    use futures::FutureExt as _;
    use futures::task::noop_waker_ref;

    /// A `Context` backed by a no-op waker, for deterministic manual polling.
    ///
    /// This is a trick so we don't rely on wakeups as grants are committed by a call to
    /// refill() into the waiter's grant flag. So a second poll observes it.
    fn noop_cx() -> Context<'static> {
        Context::from_waker(noop_waker_ref())
    }

    /// Build a [`BandwidthPool`] and drain it so 0 tokens are available.
    fn drained_pool(cap: u64) -> (BandwidthPool, BandwidthRefiller) {
        let (pool, refiller) = BandwidthPool::new(cap);
        let mut permit = pool.try_acquire(cap).expect("a fresh pool starts full");
        permit.claim_all();
        (pool, refiller)
    }

    /// Expect `poll` to be a granted permit and claim all so the drop refunds zero.
    fn expect_granted(poll: Poll<Result<Permit, PoolClosed>>) {
        match poll {
            Poll::Ready(Ok(mut permit)) => permit.claim_all(),
            other => panic!("expected a granted permit, got {other:?}"),
        }
    }

    #[test]
    fn fast_path() {
        let (pool, _refiller) = BandwidthPool::new(100);
        assert_eq!(pool.available(), 100);

        let mut permit = pool.acquire(40).now_or_never().unwrap().unwrap();
        permit.claim_all();
        drop(permit);
        assert_eq!(pool.available(), 60);

        let mut permit = pool.try_acquire(60).unwrap();
        permit.claim_all();
        drop(permit);
        assert_eq!(pool.available(), 0);

        // Nothing left. This should block and the fast path returns nothing.
        assert!(pool.try_acquire(1).is_none());
        assert!(pool.acquire(1).now_or_never().is_none());
    }

    #[test]
    fn acquirer() {
        let (pool, mut refiller) = drained_pool(100);

        // Dummy context so we can poll without a wakeup.
        let mut cx = noop_cx();
        let mut a = pin!(pool.acquire(30));
        // No tokens, it should be pending.
        assert!(a.as_mut().poll(&mut cx).is_pending());

        // Refill to serve it fully.
        assert_eq!(refiller.refill(30), None);
        expect_granted(a.as_mut().poll(&mut cx));
    }

    #[test]
    fn acquirer_reuse() {
        let (pool, mut refiller) = drained_pool(100);

        // Dummy context so we can poll without a wakeup.
        let mut cx = noop_cx();
        let mut acquirer = BandwidthAcquirer::new(pool.clone());

        // First blocked acquire through the acquirer.
        assert!(acquirer.poll_acquire(&mut cx, 30).is_pending());
        assert_eq!(refiller.refill(30), None);
        expect_granted(acquirer.poll_acquire(&mut cx, 30));

        // The same acquirer is reusable with a different amount. No new allocation.
        assert!(acquirer.poll_acquire(&mut cx, 50).is_pending());
        assert_eq!(refiller.refill(50), None);
        expect_granted(acquirer.poll_acquire(&mut cx, 50));
    }

    #[test]
    fn refill_newcomer() {
        let (pool, mut refiller) = drained_pool(100);

        // Dummy context so we can poll without a wakeup.
        let mut cx = noop_cx();
        // Enqueue 30 for A then 50 for B.
        let mut a = pin!(pool.acquire(30));
        assert!(a.as_mut().poll(&mut cx).is_pending());
        let mut b = pin!(pool.acquire(50));
        assert!(b.as_mut().poll(&mut cx).is_pending());

        // Refill of 40: serves A and keeps 10 reserved for B meaning a deficit of 40.
        assert_eq!(refiller.refill(40), Some(40));
        expect_granted(a.as_mut().poll(&mut cx));
        assert!(b.as_mut().poll(&mut cx).is_pending());

        // The 10 reserved tokens are NOT visible to the fast path meaning a newcomer
        // cannot barge ahead of B (deficit of 40 to serve it).
        assert_eq!(pool.available(), 0);
        let mut c = pin!(pool.acquire(5));
        assert!(c.as_mut().poll(&mut cx).is_pending());

        // Second refill of 40 plus held was 10 which is 50 that B needs.
        assert_eq!(refiller.refill(40), Some(5)); // C is the head and 5 is the deficit.
        expect_granted(b.as_mut().poll(&mut cx));
        assert!(c.as_mut().poll(&mut cx).is_pending());

        // And finally C.
        assert_eq!(refiller.refill(5), None);
        expect_granted(c.as_mut().poll(&mut cx));
    }

    #[test]
    fn refill_idle() {
        let (pool, mut refiller) = drained_pool(100);

        // No acquirers. Refill with a large value keeps it cap to the pool capacity.
        assert_eq!(refiller.refill(1000), None);
        assert_eq!(pool.available(), 100);
        assert_eq!(pool.capacity(), 100);

        // Fast path is fine.
        assert!(pool.try_acquire(100).is_some());
    }

    #[test]
    fn close_pool() {
        // Fast path / acquire fail once closed.
        let (pool, refiller) = BandwidthPool::new(0);
        drop(refiller);
        assert!(pool.try_acquire(1).is_none());
        assert!(matches!(
            pool.acquire(10).now_or_never(),
            Some(Err(PoolClosed)),
        ));

        // A blocked acquirer is woken with PoolClosed when the refiller drops.
        let (pool, refiller) = drained_pool(100);
        // Dummy context so we can poll without a wakeup.
        let mut cx = noop_cx();
        let mut a = pin!(pool.acquire(10));
        assert!(a.as_mut().poll(&mut cx).is_pending());
        drop(refiller);
        assert!(matches!(
            a.as_mut().poll(&mut cx),
            Poll::Ready(Err(PoolClosed)),
        ));

        let (pool, mut refiller) = BandwidthPool::new(0);
        drop(pool);
        // No senders left, wait should report closure.
        assert_eq!(refiller.wait().now_or_never(), Some(false));
    }

    #[test]
    fn refiller_wait() {
        let (pool, mut refiller) = drained_pool(100);

        // Dummy context so we can poll without a wakeup.
        let mut cx = noop_cx();
        // Idle: nobody waiting so wait() is pending.
        {
            let mut wait_fut = pin!(refiller.wait());
            assert!(wait_fut.as_mut().poll(&mut cx).is_pending());
        }

        // A blocked acquire enqueues a request (and wakes the refiller)...
        let mut a = pin!(pool.acquire(10));
        assert!(a.as_mut().poll(&mut cx).is_pending());

        // wait() now completes and having taken the request as the head.
        {
            let mut wait_fut = pin!(refiller.wait());
            assert!(matches!(wait_fut.as_mut().poll(&mut cx), Poll::Ready(true)));
        }

        // And refilling serves the head.
        assert_eq!(refiller.refill(10), None);
        expect_granted(a.as_mut().poll(&mut cx));
    }

    #[test]
    fn permit_claim() {
        let (pool, _refiller) = BandwidthPool::new(100);

        // Grab 40 and drop. Should be fully refunded.
        let permit = pool.try_acquire(40).unwrap();
        assert_eq!(pool.available(), 60);
        drop(permit);
        assert_eq!(pool.available(), 100);

        // Claims are cumulative.
        let mut permit = pool.try_acquire(40).unwrap();
        // Can't over claim.
        assert!(!permit.claim(41));
        assert!(permit.claim(10));
        assert!(permit.claim(20));
        // Over claiming by one.
        assert!(!permit.claim(11));
        // 10 remains unclaimed now (claimed: 30, unclaimed: 10, pool: 60)
        drop(permit);
        // Refund the 10 left, pool is now 70.
        assert_eq!(pool.available(), 70);

        // Get what remains.
        let mut permit = pool.try_acquire(70).unwrap();
        // A fully claimed permit refunds nothing.
        permit.claim_all();
        drop(permit);
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn refund_hold() {
        let (pool, mut refiller) = BandwidthPool::new(100);
        let mut cx = noop_cx();

        // Get 60 on the fast path and only use 10 so we keep holding 50.
        let mut permit_hold = pool.try_acquire(60).unwrap();
        assert!(permit_hold.claim(10));
        // Drain the rest so the pool is empty.
        let mut drain = pool.try_acquire(40).unwrap();
        drain.claim_all();
        drop(drain);
        assert_eq!(pool.available(), 0);

        // Task A acquires 50 but gets queued because pool is empty.
        let mut a = pin!(pool.acquire(50));
        assert!(a.as_mut().poll(&mut cx).is_pending());

        // Drop permit which refunds 50 to the fast-path balance. But because A is
        // queued, the fast path is gated. The 50 shows up in the balance. New commer
        // can't get them.
        drop(permit_hold);
        assert_eq!(pool.available(), 50);
        assert!(pool.try_acquire(5).is_none());

        // A refill of 10 reclaims the 50 from the gated fast path, serves A with 50, and
        // publishes the remaining 10 back to the opened fast path.
        assert_eq!(refiller.refill(10), None);
        expect_granted(a.as_mut().poll(&mut cx));
        assert_eq!(pool.available(), 10);
    }
}
