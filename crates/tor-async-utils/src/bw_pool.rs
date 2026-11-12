//! A shared token pool with a lock-free fast path and FIFO waiting queue.
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
//! Refunded tokens always go back to the fast-path pool where they are immediately
//! available. A newcomer can acquire them while another request is queued but before
//! the [`BandwidthRefiller`] drains the pool. This favors keeping the fast path busy
//! over strict fairness between the fast path and the waiting queue.
//!
//! ## Teardown
//!
//! There is deliberately no cancellation mechanism for a queued request. If a
//! [`BandwidthAcquirer`] is torn down while its request is queued, the refiller will
//! eventually fund that request anyway, record the grant, and wake a task that no
//! longer exists. The granted tokens are simply forfeited.
//!
//! This is a considered trade-off and we believe in the context of a Tor relay, losing a
//! grant is not significant at all in the large picture of available bandwidth. The
//! trade-off allows us to reduce a lot of complexity.

mod bucket;
mod refiller;
mod reusable_oneshot;

use futures::channel::mpsc;
use std::num::NonZero;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::warn;

use crate::bw_pool::bucket::AtomicTokenBucket;
use crate::bw_pool::refiller::BwRequest;

// Public export as the outside world needs this.
pub use crate::bw_pool::refiller::BandwidthRefiller;

/// Error returned by this module.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BwPoolError {
    /// Over permit claim.
    #[error("Permit's claim() exceeds the granted tokens")]
    ClaimExceedsGrant,
    /// The bandwidth pool is closed.
    #[error("bandwidth pool is closed")]
    PoolClosed,
    /// A request that can only be granted zero tokens.
    #[error("bandwidth request of zero tokens")]
    ZeroTokens,
    /// An internal error.
    #[error("Internal error")]
    Bug(&'static str),
}

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
    pub fn claim(&mut self, tokens: u64) -> Result<(), BwPoolError> {
        match self.granted.checked_sub(tokens) {
            Some(left) => {
                self.granted = left;
                Ok(())
            }
            None => Err(BwPoolError::ClaimExceedsGrant),
        }
    }

    /// Claim everything this permit holds.
    pub fn claim_all(&mut self) {
        let r = self.claim(self.granted);
        debug_assert!(r.is_ok());
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
        self.bucket.refill(self.granted);
    }
}

/// A reusable bandwidth acquirer that is designed for an async context (poll).
///
/// The main entry point is [`Self::poll_acquire`] used within the context of a task
/// which, if rate limited, the task gets woken up when the bandwidth usage is granted.
#[derive(Debug)]
pub struct BandwidthAcquirer {
    /// The shared waiter. Reused for every acquire.
    waiter: reusable_oneshot::Receiver<NonZero<u64>>,
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
            waiter: reusable_oneshot::Receiver::new(),
            pool,
        }
    }

    /// Build the [`Permit`].
    ///
    /// This sets the `in-flight` to false and takes the granted tokens out of the waiter,
    /// resetting it, as we now hand them to the permit.
    fn grant_permit(&mut self, granted: u64) -> Permit {
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
    /// A request above the pool capacity is clamped to it rather than refused. The
    /// emitted [`Permit`] then holds less than what was asked and so the caller must use
    /// [`Permit::granted`] rather than assume it got `tokens`.
    ///
    /// Returns a [`BwPoolError::PoolClosed`] error if the [`BandwidthRefiller`] has been
    /// dropped.
    ///
    /// Returns a [`BwPoolError::ZeroTokens`] error if `tokens` is zero.
    pub fn poll_acquire(
        &mut self,
        cx: &mut Context<'_>,
        tokens: u64,
    ) -> Poll<Result<Permit, BwPoolError>> {
        // If we can't get a new sender, then we have a request in flight.
        if let Some(sender_guarantee) = self.waiter.guarantee_new_sender() {
            // No request in flight. This is the fast path! The thundering herd is allowed,
            // that is, all tasks race to this and their fairness is sub-contracted to their
            // task scheduler.
            //
            // An under-utilized relay with bandwidth limitation will hit this path most
            // of the time.
            //
            // The fast path is deliberately not gated by queued requests. But there is a
            // fairness race that we accept:
            //
            //      task A: fail the fast path and enqueue
            //      permit: drop and refund enough tokens
            //      task B: claim the refund before the refiller sees queued task A
            //
            // Task B has jumped task A.
            //
            // This is OK because the refiller drains the global bucket before serving
            // the queue and the refill are never done directly into that bucket.
            // Instead, it keeps it locally until all enqueued requests have been served.
            // And so, letting B use the refund(s) keeps the pool active without breaking
            // the rate/burst limits.
            //
            // This prevents a slow enqueuing on one CPU to not block the fast path on
            // another CPU. This logic also applies for a slow refiller task. We
            // essentially compromise almost-strict fairness for high throughput.
            //
            // For the case of a relay, in normal operations, we expect the write side to
            // rarely have refunds and so this race would be rare. On the read side,
            // refunds are much more likely to happen because as a relay we don't know
            // exactly how many bytes we should expect at every recv().
            if let Some(permit) = self.pool.try_acquire(tokens) {
                return Poll::Ready(Ok(permit));
            }

            // We want to get a sender just before we enqueue the request.
            let sender = sender_guarantee.into_sender();

            // Enqueue the request as it is not in flight and our bw pool is depleted.
            // This is where the caller gets to wait on bw availability and the refilling
            // process is triggered.
            match self.enqueue_request(tokens, sender) {
                // We've enqueued the request, but we also need to poll() the waiter at least once
                // to register the waker. We do this below.
                Ok(()) => {}
                Err(e) => {
                    // Failed to enqueue the request, so the sender should have been dropped.
                    // Let's make sure that the waiter is aware of this.
                    match self.waiter.try_recv() {
                        // The waiter is effectively reset now that it has informed us about
                        // the dropped sender.
                        Err(reusable_oneshot::RecvError::SenderDropped) => {}
                        // We shouldn't ever get any of these return values.
                        Ok(Some(_)) | Ok(None) | Err(reusable_oneshot::RecvError::NoSender) => {
                            warn!("Unexpected return val from `waiter.try_recv()`; ignoring");
                        }
                    }
                    // Return the original error.
                    return Poll::Ready(Err(e));
                }
            };
        }

        let recv_fut = match self.waiter.recv() {
            Ok(x) => x,
            Err(reusable_oneshot::NoSender) => {
                // There's no sender so we won't ever receive a result.
                // This shouldn't happen since we created the sender above if there wasn't one.
                return Poll::Ready(Err(BwPoolError::Bug("recv() returned `NoSender`")));
            }
        };

        // Register our current waker and check if we were granted.
        match std::pin::pin!(recv_fut).poll(cx) {
            Poll::Ready(Ok(granted)) => {
                return Poll::Ready(Ok(self.grant_permit(granted.get())));
            }
            Poll::Ready(Err(reusable_oneshot::SenderDropped)) => {
                // The refiller is gone; nobody will ever serve us.
                return Poll::Ready(Err(BwPoolError::PoolClosed));
            }
            Poll::Pending => {}
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
            return Poll::Ready(Err(BwPoolError::PoolClosed));
        }

        Poll::Pending
    }

    /// Enqueue a request for `tokens` tokens that is NOT in flight.
    ///
    /// The amount is sent as it was asked. Clamping it to the pool capacity is the
    /// refiller's job as it is the one holding the tokens by the time this is served.
    /// The clamping is localized to the refiller for correctness.
    ///
    /// Return a [`BwPoolError::PoolClosed`] error if the refiller is gone.
    ///
    /// Return a [`BwPoolError::ZeroTokens`] error if `tokens` is zero.
    fn enqueue_request(
        &mut self,
        tokens: u64,
        sender: reusable_oneshot::Sender<NonZero<u64>>,
    ) -> Result<(), BwPoolError> {
        // Never enqueue a request for zero tokens.
        if tokens == 0 {
            return Err(BwPoolError::ZeroTokens);
        }

        // Send the requested amount along with the waiter. The amount never changes for
        // the lifetime of the request so it doesn't need to live in the shared waiter.
        //
        // Notice, this is the only dynamic allocation in this path because it is sent on
        // an unbounded MPSC queue.
        if self.pool.requests.unbounded_send((tokens, sender)).is_err() {
            // The refiller is gone, the pool is closed.
            return Err(BwPoolError::PoolClosed);
        }
        Ok(())
    }
}

/// A shareable bandwidth pool.
///
/// Use [`Self::share`] to give it to each task requiring bandwidth limitation.
///
/// [`Clone`] is deliberately not implemented so that handing this around can not be
/// mistaken for creating a second pool with its own bandwidth. There is exactly one pool
/// per [`Self::new`] call.
///
/// Each task needs to hold a [`BandwidthAcquirer`] in order to request bandwidth permits
/// from this pool.
#[derive(Debug)]
pub struct BandwidthPool {
    /// The shared token bucket the fast path claims from.
    bucket: Arc<AtomicTokenBucket>,
    /// Ingress for acquirers that failed the fast path.
    ///
    /// Sending a [`BwRequest`] here both enqueues it and wakes the
    /// [`BandwidthRefiller`]
    ///
    /// Unbounded because we never want an acquirer's enqueue to block. the number of
    /// in-flight requests is bounded by the number of acquirers.
    requests: mpsc::UnboundedSender<BwRequest>,
}

impl BandwidthPool {
    /// Create a new pool that can hold up to `capacity` tokens, and its associated
    /// refiller [`BandwidthRefiller`] that needs to be run in its own task.
    ///
    /// The pool starts full and `capacity` tokens are immediately available to the fast
    /// path.
    ///
    /// The fast path never grants a partial [`Permit`] below `min_grant` tokens.
    pub fn new(capacity: NonZero<u64>, min_grant: u64) -> (BandwidthPool, BandwidthRefiller) {
        let (tx, rx) = mpsc::unbounded();
        let bucket = Arc::new(AtomicTokenBucket::new(capacity.get(), min_grant));
        let pool = BandwidthPool {
            bucket: Arc::clone(&bucket),
            requests: tx,
        };
        let refiller = BandwidthRefiller::new(bucket, rx);
        (pool, refiller)
    }

    /// Return another [`BandwidthPool`] that is the same as this one.
    ///
    /// The tokens are not duplicated, this is so you can share the pool with other
    /// tasks/objects.
    pub fn share(&self) -> BandwidthPool {
        BandwidthPool {
            bucket: Arc::clone(&self.bucket),
            requests: self.requests.clone(),
        }
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
        BandwidthAcquirer::new(self.share())
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
    /// The claim is partial: if the pool holds less than `tokens`, the permit gets
    /// everything it holds. The caller learns what it got with [`Permit::granted`].
    ///
    /// Returns `Some(permit)` if there were tokens available right now, or `None` if the
    /// bucket is empty.
    ///
    /// This never blocks and never enqueues. It is the fast path that the other
    /// acquisition methods use first.
    fn try_acquire(&self, tokens: u64) -> Option<Permit> {
        let granted = self.bucket.claim(tokens)?;
        Some(Permit::new(Arc::clone(&self.bucket), granted))
    }

    /// Unit tests helper: async acquire wrapping a throwaway [`BandwidthAcquirer`].
    #[cfg(test)]
    async fn acquire(&self, tokens: u64) -> Result<Permit, BwPoolError> {
        if let Some(permit) = self.try_acquire(tokens) {
            return Ok(permit);
        }
        let mut acquirer = BandwidthAcquirer::new(self.share());
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

    /// Minimum partial grant.
    const MIN_GRANT: u64 = 10;

    /// A `Context` backed by a no-op waker, for deterministic manual polling.
    ///
    /// This is a trick so we don't rely on wakeups as grants are committed by a call to
    /// refill_and_serve() into the waiter's grant flag. So a second poll observes it.
    fn noop_cx() -> Context<'static> {
        Context::from_waker(noop_waker_ref())
    }

    /// Build a [`BandwidthPool`] and drain it so 0 tokens are available.
    fn drained_pool(cap: u64) -> (BandwidthPool, BandwidthRefiller) {
        let (pool, refiller) = BandwidthPool::new(NonZero::new(cap).unwrap(), MIN_GRANT);
        let mut permit = pool.try_acquire(cap).expect("a fresh pool starts full");
        permit.claim_all();
        (pool, refiller)
    }

    /// Expect `poll` to be a granted permit and claim all so the drop refunds zero.
    fn expect_granted(poll: Poll<Result<Permit, BwPoolError>>) {
        match poll {
            Poll::Ready(Ok(mut permit)) => permit.claim_all(),
            other => panic!("expected a granted permit, got {other:?}"),
        }
    }

    #[test]
    fn fast_path() {
        let (pool, _refiller) = BandwidthPool::new(NonZero::new(100).unwrap(), MIN_GRANT);
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
        assert_eq!(refiller.refill_and_serve(30), None);
        expect_granted(a.as_mut().poll(&mut cx));
    }

    #[test]
    fn acquirer_reuse() {
        let (pool, mut refiller) = drained_pool(100);

        // Dummy context so we can poll without a wakeup.
        let mut cx = noop_cx();
        let mut acquirer = BandwidthAcquirer::new(pool.share());

        // First blocked acquire through the acquirer.
        assert!(acquirer.poll_acquire(&mut cx, 30).is_pending());
        assert_eq!(refiller.refill_and_serve(30), None);
        expect_granted(acquirer.poll_acquire(&mut cx, 30));

        // The same acquirer is reusable with a different amount. No new allocation.
        assert!(acquirer.poll_acquire(&mut cx, 50).is_pending());
        assert_eq!(refiller.refill_and_serve(50), None);
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
        assert_eq!(refiller.refill_and_serve(40), Some(40));
        expect_granted(a.as_mut().poll(&mut cx));
        assert!(b.as_mut().poll(&mut cx).is_pending());

        // The 10 reserved tokens are NOT visible to the fast path meaning a newcomer
        // cannot barge ahead of B (deficit of 40 to serve it).
        assert_eq!(pool.available(), 0);
        let mut c = pin!(pool.acquire(5));
        assert!(c.as_mut().poll(&mut cx).is_pending());

        // Second refill of 40 plus held was 10 which is 50 that B needs.
        assert_eq!(refiller.refill_and_serve(40), Some(5)); // C is the head and 5 is the deficit.
        expect_granted(b.as_mut().poll(&mut cx));
        assert!(c.as_mut().poll(&mut cx).is_pending());

        // And finally C.
        assert_eq!(refiller.refill_and_serve(5), None);
        expect_granted(c.as_mut().poll(&mut cx));
    }

    #[test]
    fn refill_idle() {
        let (pool, mut refiller) = drained_pool(100);

        // No acquirers. Refill with a large value keeps it cap to the pool capacity.
        assert_eq!(refiller.refill_and_serve(1000), None);
        assert_eq!(pool.available(), 100);
        assert_eq!(pool.capacity(), 100);

        // Fast path is fine.
        assert!(pool.try_acquire(100).is_some());
    }

    #[test]
    fn close_pool() {
        // Acquire fails once closed and the bucket is dry.
        let (pool, refiller) = drained_pool(100);
        drop(refiller);
        assert!(pool.try_acquire(1).is_none());
        assert!(matches!(
            pool.acquire(10).now_or_never(),
            Some(Err(BwPoolError::PoolClosed)),
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
            Poll::Ready(Err(BwPoolError::PoolClosed)),
        ));

        let (pool, mut refiller) = BandwidthPool::new(NonZero::new(100).unwrap(), MIN_GRANT);
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
        assert_eq!(refiller.refill_and_serve(10), None);
        expect_granted(a.as_mut().poll(&mut cx));
    }

    #[test]
    fn permit_claim() {
        let (pool, _refiller) = BandwidthPool::new(NonZero::new(100).unwrap(), MIN_GRANT);

        // Grab 40 and drop. Should be fully refunded.
        let permit = pool.try_acquire(40).unwrap();
        assert_eq!(pool.available(), 60);
        drop(permit);
        assert_eq!(pool.available(), 100);

        // Claims are cumulative.
        let mut permit = pool.try_acquire(40).unwrap();
        // Can't over claim.
        assert!(matches!(
            permit.claim(41),
            Err(BwPoolError::ClaimExceedsGrant),
        ));
        assert!(permit.claim(10).is_ok());
        assert!(permit.claim(20).is_ok());
        // Over claiming by one.
        assert!(matches!(
            permit.claim(11),
            Err(BwPoolError::ClaimExceedsGrant),
        ));
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
    fn refund_newcomer() {
        let (pool, mut refiller) = BandwidthPool::new(NonZero::new(100).unwrap(), MIN_GRANT);
        let mut cx = noop_cx();

        // Get 60 on the fast path and only use 10 so we keep holding 50.
        let mut permit_hold = pool.try_acquire(60).unwrap();
        assert!(permit_hold.claim(10).is_ok());
        // Drain the rest so the pool is empty.
        let mut drain = pool.try_acquire(40).unwrap();
        drain.claim_all();
        drop(drain);
        assert_eq!(pool.available(), 0);

        // Task A acquires 50 but gets queued because pool is empty.
        let mut a = pin!(pool.acquire(50));
        assert!(a.as_mut().poll(&mut cx).is_pending());

        // Drop permit which refunds 50 to the fast-path balance. A newcomer can claim
        // the refund even though A is already queued.
        drop(permit_hold);
        assert_eq!(pool.available(), 50);
        let mut newcomer = pool.try_acquire(50).unwrap();
        newcomer.claim_all();
        drop(newcomer);
        assert_eq!(pool.available(), 0);

        // A remains queued and is served by subsequent refills.
        assert_eq!(refiller.refill_and_serve(10), Some(40));
        assert!(a.as_mut().poll(&mut cx).is_pending());
        assert_eq!(refiller.refill_and_serve(40), None);
        expect_granted(a.as_mut().poll(&mut cx));
        assert_eq!(pool.available(), 0);
    }
}
