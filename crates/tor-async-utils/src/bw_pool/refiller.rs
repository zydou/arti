//! The refiller code that is the [`BandwidthRefiller`] is a public entity that needs to
//! run into its own task and refill the associated [`super::BandwidthPool`] and serve
//! any `RefillWaiter` pending on the pool to be replenished.
//!
//! # Driving a pool
//!
//! The refiller must live in its own task that owns the clock and the rate. Simply call
//! [`BandwidthRefiller::run`] into a spawned task. It builds a token bucket from the given
//! rate + burst and a [`tor_rtcompat::SleepProvider`].
//!
//! # Example
//!
//! ```ignore
//! let (pool, refiller) = BandwidthPool::new(capacity);
//! let config = TokenBucketConfig { rate, bucket_max: capacity };
//! runtime.spawn(refiller.run(runtime.clone(), config))?;
//! ```

use futures::StreamExt as _;
use futures::channel::mpsc;
use futures::task::AtomicWaker;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::Waker;

use tor_basic_utils::token_bucket::{TokenBucket, TokenBucketConfig};
use tor_rtcompat::SleepProvider;

use super::bucket::AtomicTokenBucket;

/// A refill waiter object through which the [`BandwidthRefiller`] signals a blocked
/// acquirer.
///
/// A [`std::task::Waker`] doesn't carry any information back to the task so this waiter
/// is not indicating how much was granted but rather "was I granted what I asked".
///
/// This lives in a [`super::BandwidthAcquirer`] and is reused at every acquire which
/// means that once the task is launched, the steady state has no extra allocation.
///
/// For sake of simplicity, there is no cancellation path and so any granted bandwidth
/// before cancellation (drop) is forfeited.
#[derive(Debug)]
pub(super) struct RefillWaiter {
    /// Set by the refiller once it has funded this request. Read by the acquirer on each
    /// poll to distinguish a grant from a spurious wakeup.
    ///
    /// Reset by the acquirer (while no request is in flight) before each new request is
    /// sent.
    granted: AtomicBool,
    /// The blocked acquirer's task waker. Re-registered on every poll so it is always
    /// current, and woken by the refiller on grant.
    waker: AtomicWaker,
    /// How many tokens the acquirer is wanting. Set by the acquirer before the waiter is
    /// sent and read by the refiller to decide when it can be funded.
    needed: AtomicU64,
}

impl RefillWaiter {
    /// Constructor.
    pub(super) fn new() -> Self {
        Self {
            granted: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            needed: AtomicU64::new(0),
        }
    }

    /// Return true iff this waiter was granted permission to use the requested
    /// bandwidth.
    ///
    /// See [`Self::set_granted`] for the memory ordering.
    fn is_granted(&self) -> bool {
        self.granted.load(Ordering::Relaxed)
    }

    /// Prepare this waiter for a new request of `tokens` tokens with the given `waker`.
    ///
    /// This must be called before the waiter is enqueued with the refiller.
    pub(super) fn prepare(&self, waker: &Waker, tokens: u64) {
        // Reset the waiter with this new waker.
        self.set_granted(false);
        self.set_waker(waker);
        // Remember the in-flight amount so we can grant the permit later from it.
        self.set_needed(tokens);
    }

    /// Grant a number of tokens for this waiter.
    ///
    /// The `granted` value is given because it might be clamped so we simply set the
    /// needed value to what was granted.
    ///
    /// This function does the atomic work in the proper order the caller doesn't need to
    /// bother about. The concurrency handling logic is contained.
    pub(super) fn grant(&self, granted: u64) {
        // Set the clamped value before the flag so the needed value is correct when the
        // flag is read as true.
        self.set_needed(granted);
        self.set_granted(true);
        // We are granted, wake up the waiter!
        self.wake();
    }

    /// Register the given `waker` and return true iff this waiter was granted.
    ///
    /// Note on the function name, it doesn't return a Poll state but this was done so
    /// the function semantic carries the intent of the context.
    pub(super) fn poll_granted(&self, waker: &Waker) -> bool {
        // Optimization. Before re-registering the waker (see why below), check if we were
        // granted. This is very cheap to call and avoids the waker registration complexity.
        // However, it is NOT critical to the lockless state of this pool.
        if self.is_granted() {
            return true;
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
        self.set_waker(waker);
        self.is_granted()
    }

    /// Take the granted tokens out of this waiter leaving it to zero tokens.
    ///
    /// This is used by the acquirer to build the permit once granted.
    pub(super) fn take_granted(&self) -> u64 {
        let granted = self.needed();
        self.set_needed(0);
        granted
    }

    /// Set atomically the given `val` as the granted value.
    ///
    /// # Ordering
    ///
    /// The grant must survive the "lost wakeup" race where the refiller grants and wakes
    /// before the acquirer has (re-)registered its waker:
    ///
    /// ```text
    ///     refiller:  set_granted(true)      // grant
    ///     refiller:  waker.wake()           // no waker registered yet => wakes nobody
    ///     acquirer:  set_waker(cx)          // register, too late for the wake above
    ///     acquirer:  is_granted() -> ???    // must observe the grant or stuck forever
    /// ```
    ///
    /// The acquirer's re-check after `set_waker` must be forced to observe the grant.
    /// That happens-before is actually provided by the [`AtomicWaker`].
    ///
    /// [`Ordering::Relaxed`] suffices because the flag gates no other memory.
    fn set_granted(&self, val: bool) {
        self.granted.store(val, Ordering::Relaxed);
    }

    /// Register the given `waker` into our atomic waker.
    fn set_waker(&self, waker: &Waker) {
        self.waker.register(waker);
    }

    /// Wake the waker.
    fn wake(&self) {
        self.waker.wake();
    }

    /// Return how many tokens this waiter is wanting.
    fn needed(&self) -> u64 {
        self.needed.load(Ordering::Acquire)
    }

    /// Set how many tokens this waiter needs.
    ///
    /// Stored [`Ordering::Release`] to match with the refiller's [`Ordering::Acquire`]
    /// load. It is not gating any memory but for thoroughness and synchronization
    /// between our methods.
    fn set_needed(&self, val: u64) {
        self.needed.store(val, Ordering::Release);
    }
}

/// A bandwidth refiller is in charge of refilling the associated
/// [`super::BandwidthPool`] and processing any pending RefillWaiter that were enqueued
/// by the pool.
///
/// There is exactly one refiller per pool as it owns the receiving end of the request
/// channel. The channel is a FIFO of waiters.
///
/// Dropping it closes the pool which makes queued and new acquirers fail with
/// [`super::BwPoolError::PoolClosed`].
#[derive(Debug)]
pub struct BandwidthRefiller {
    /// The shared token bucket which comes from the [`super::BandwidthPool`].
    bucket: Arc<AtomicTokenBucket>,
    /// Receiving end of the request channel
    rx: mpsc::UnboundedReceiver<Arc<RefillWaiter>>,
    /// A single request we have taken off the channel to inspect but cannot yet fund. If
    /// only mpsc channels had an "is_empty()".
    ///
    /// This is populated by the [`Self::wait`] function
    head: Option<Arc<RefillWaiter>>,
    /// Tokens that have been drained out of the fast-path bucket or handed in via
    /// [`Self::refill`] but not yet distributed.
    ///
    /// If anything is left at the end of the refill loop, it is published back in the
    /// main pool fast path.
    held: u64,
}

impl BandwidthRefiller {
    /// Constructor.
    pub(super) fn new(
        bucket: Arc<AtomicTokenBucket>,
        rx: mpsc::UnboundedReceiver<Arc<RefillWaiter>>,
    ) -> Self {
        Self {
            bucket,
            rx,
            head: None,
            held: 0,
        }
    }

    /// Start the refiller main loop. This should be run in its own task as it is
    /// blocking until the bandwidth pool closes.
    ///
    /// Using the given [`SleepProvider`], we drive the refill with it along side a
    /// [`TokenBucket`] that is built at the start with the given `config`.
    ///
    /// This waits on new request that comes in when the fast-path is depleted that is a
    /// request waiting for a refill. Once a request is received, a refill is triggered
    /// and then the loop sleeps until the needed deficit is available.
    ///
    /// As an example, if the queue has a request for 10 tokens but only 5 are available
    /// in the pool after an immediate refill, we will sleep the exact time it takes to
    /// get another 5 tokens. Then, it goes on to the next request and so on until the
    /// queue is empty.
    ///
    /// Keen observer will notice that once a request is received, the refiller will have
    /// to empty the entire queue before the fast path could even see 1 token added back
    /// by a refill. That is because each iteration of the loop sleeps the exact amount
    /// of time to fulfill the pending request.
    ///
    /// Returns when the pool is closed or if the config rate is zero or if the requested
    /// amount of token is above the pool capacity.
    pub async fn run<SP: SleepProvider>(mut self, sleep: SP, rate: u64) {
        let config = TokenBucketConfig {
            rate,
            bucket_max: self.bucket.capacity(),
        };
        let mut bucket = TokenBucket::new(&config, sleep.now());
        // Start empty. The pool's first start full. This avoids adding a second burst to
        // the pool after the fast path is depleted.
        let _ = bucket.drain_all();

        loop {
            // Wait on the "doorbell" that is a pending request wanting tokens.
            if !self.wait().await {
                // The pool is closed.
                return;
            }

            // Serve the queue. Sleep for the deficit until queue is empty.
            loop {
                // Refill the bucket with what we can.
                bucket.refill(sleep.now());
                // This will reserve all available tokens from the pool so the fast-path
                // ends up empty and then starts serving queued requests. We use all
                // token from the TokenBucket as well.
                //
                // If everyone is served and we still have tokens, they are put back
                // in the fast path.
                match self.refill(bucket.drain_all()) {
                    // We served everyone, fast-path has the surplus if any. Go back to
                    // the doorbell.
                    None => break,
                    // The pending request wants `deficit` amount of tokens, wait for that
                    // exact value.
                    Some(deficit) => match bucket.tokens_available_at(deficit) {
                        Ok(at) => {
                            let d = at.saturating_duration_since(sleep.now());
                            sleep.sleep(d).await;
                        }
                        // Zero rate or a deficit above the burst. We can never fulfill
                        // that request so error else we are stuck.
                        Err(_) => return,
                    },
                }
            }
        }
    }

    /// Wait until at least one bandwidth request is queued.
    ///
    /// Returns `true` once a request is received or `false` if the pool has been closed
    /// meaning the tx end is closed.
    ///
    /// Returns `true` immediately if a request is already held as the head.
    ///
    /// This should only be used as a "doorbell" that is indicating someone is at the
    /// door with a request rather than waiting for the next request. One should use
    /// `Self::serve` for that.
    #[cfg_attr(feature = "bench", visibility::make(pub))]
    pub(crate) async fn wait(&mut self) -> bool {
        // Avoid overwriting an existing request.
        if self.head.is_some() {
            return true;
        }
        match self.rx.next().await {
            Some(req) => {
                self.head = Some(req);
                true
            }
            // TODO(relay): Need to fix this with partial permit else this will make the
            // whole bucket fail if a request above capacity shows up.
            None => false,
        }
    }

    /// Add `tokens` to the pool and then serve all pending requests if any.
    ///
    /// The very first thing that this function does is drain the pool's fast path tokens
    /// in order to avoid a newcomer jumping the queue.
    ///
    /// Any surplus left will be put back into the pool's fast path.
    ///
    /// Returns `None` if no one is left waiting indicating the pool is now idle and
    /// [`Self::wait`] can be safely used to get notified of a new request.
    ///
    /// Returns `Some(deficit)` if an acquirer is still waiting where `deficit` is how
    /// many more tokens are needed before it can be served. The caller can use this to
    /// decide how long to wait before the next refill.
    #[cfg_attr(feature = "bench", visibility::make(pub))]
    pub(crate) fn refill(&mut self, tokens: u64) -> Option<u64> {
        let capacity = self.bucket.capacity();

        // Reclaim tokens sitting in the fast path.
        let reclaimed = self.bucket.drain();
        self.held = self
            .held
            .saturating_add(reclaimed)
            .saturating_add(tokens)
            .min(capacity);

        // Serve the request queue with the token we are holding.
        self.serve(capacity);

        // If we still have a head, report its deficit, else publish the remaining
        // tokens in the pool's fast path. We use the snapshot capacity here so it is the
        // same value used for the serve.
        match &self.head {
            Some(front) => Some(front.needed().min(capacity).saturating_sub(self.held)),
            None => {
                self.publish_held();
                None
            }
        }
    }

    /// Serve pending requests with the token we are holding.
    ///
    /// The given `capacity` is essentially the maximum we can give a single request.
    ///
    /// If we have a token deficit, the head is updated with the latest request that we
    /// can't serve which indicates the caller we are in deficit.
    fn serve(&mut self, capacity: u64) {
        loop {
            let req = match self.head.take() {
                Some(req) => req,
                None => match self.rx.try_recv() {
                    Ok(req) => req,
                    // Channel is empty or closed. We are done.
                    Err(_) => return,
                },
            };

            let needed = req.needed().min(capacity);
            if needed > self.held {
                // Unable to permit this request, keep it for next round.
                self.head = Some(req);
                return;
            }

            // Commit the permit first and then wake. If the waker (acquirer) was torn
            // down, the grant is forfeited but that is a documented limitation.
            self.held -= needed;
            // Just in case it was clamped.
            req.grant(needed);
            // Remove a waiter from the shared pool.
            self.bucket.remove_waiter();
        }
    }

    /// Publish any held surplus back to the fast-path.
    fn publish_held(&mut self) {
        self.bucket.refill(self.held);
        self.held = 0;
    }
}

impl Drop for BandwidthRefiller {
    /// Wake all queued waiters on teardown so they wake up and get to realize the pool
    /// is closed on their next poll.
    fn drop(&mut self) {
        // Close the receiver so any new waiter gets a pool closed error.
        self.rx.close();
        // The waiter we pulled off the channel as the head but never served.
        if let Some(head) = self.head.take() {
            head.wake();
        }
        // Wake any enqueued waiters.
        while let Ok(waiter) = self.rx.try_recv() {
            waiter.wake();
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

    use futures::FutureExt as _;
    use futures::task::{ArcWake, waker};
    use std::sync::atomic::AtomicUsize;

    /// Build a new drained refiller of `capacity` and the request channel sender used to
    /// enqueue requests.
    fn drained_refiller(
        capacity: u64,
    ) -> (mpsc::UnboundedSender<Arc<RefillWaiter>>, BandwidthRefiller) {
        let (tx, rx) = mpsc::unbounded();
        let bucket = Arc::new(AtomicTokenBucket::new(capacity));
        assert!(bucket.claim(capacity)); // the bucket starts full; empty it
        (tx, BandwidthRefiller::new(bucket, rx))
    }

    /// Enqueue a request for `needed` tokens.
    ///
    /// Return its waiter so the test can observe the grant.
    fn enqueue(tx: &mpsc::UnboundedSender<Arc<RefillWaiter>>, needed: u64) -> Arc<RefillWaiter> {
        let waiter = Arc::new(RefillWaiter::new());
        waiter.set_needed(needed);
        tx.unbounded_send(Arc::clone(&waiter)).unwrap();
        waiter
    }

    /// A waker that counts how many times it is woken.
    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl ArcWake for WakeCount {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn deficit() {
        let (tx, mut r) = drained_refiller(100);
        let w = enqueue(&tx, 50);

        // Partial refills which report the shrinking deficit. No grant as we don't have
        // enough.
        assert_eq!(r.refill(20), Some(30));
        assert_eq!(r.refill(20), Some(10));
        assert!(!w.is_granted());

        // Last refill before reaching what is needed.
        assert_eq!(r.refill(10), None);
        assert!(w.is_granted());
    }

    #[test]
    fn serve_fifo() {
        let (tx, mut r) = drained_refiller(100);
        // Enqueue two acquirers.
        let a = enqueue(&tx, 30);
        let b = enqueue(&tx, 30);

        // Refill with 40 tokens, A should be granted wanting 30.
        assert_eq!(r.refill(40), Some(20));
        assert!(a.is_granted());
        // Not granted, 10 remains for B with a 20 deficit.
        assert!(!b.is_granted());
        assert_eq!(r.bucket.available(), 0);
        // Refill the deficit and B should be granted.
        assert_eq!(r.refill(20), None);
        assert!(b.is_granted());
    }

    #[test]
    fn reclaim_fast_path() {
        // The bucket holds 40 tokens that a failed fast-path attempt for 50 could not claim.
        let (tx, rx) = mpsc::unbounded();
        let bucket = Arc::new(AtomicTokenBucket::new(100));
        assert!(bucket.claim(60));
        // Pool has 40 now. Enqueue a request for 50.
        let mut r = BandwidthRefiller::new(Arc::clone(&bucket), rx);
        let w = enqueue(&tx, 50);

        // A refill of 0 should take those 40 from the fast path and put them in the
        // refiller held reserve returning a deficit of 10 to grant the request of 50.
        assert_eq!(r.refill(0), Some(10));
        assert_eq!(bucket.available(), 0);
        // Refill 20 more, the request should be granted and 10 should be put in the fast
        // path.
        assert_eq!(r.refill(20), None);
        assert!(w.is_granted());
        assert_eq!(bucket.available(), 10);
    }

    #[test]
    fn wake_on_permit() {
        let (tx, mut r) = drained_refiller(100);
        let w = enqueue(&tx, 50);
        let wake_counter = Arc::new(WakeCount::default());
        w.set_waker(&waker(Arc::clone(&wake_counter)));

        // Not enough to wake the waiter. Request wants 50 so deficit is now 30.
        assert_eq!(r.refill(20), Some(30));
        assert_eq!(wake_counter.0.load(Ordering::SeqCst), 0);
        // Refills with the deficit, the waker should wake up and be granted.
        assert_eq!(r.refill(30), None);
        assert_eq!(wake_counter.0.load(Ordering::SeqCst), 1);
        assert!(w.is_granted());
    }

    #[test]
    fn wait_doorbell() {
        let (tx, mut r) = drained_refiller(100);

        // Nothing queued: wait() pends.
        assert_eq!(r.wait().now_or_never(), None);

        // A request rings the doorbell; it is taken as the head and served by
        // the following refill.
        let w = enqueue(&tx, 10);
        assert_eq!(r.wait().now_or_never(), Some(true));
        assert_eq!(r.refill(10), None);
        assert!(w.is_granted());
        // All senders gone, wait() should report that nothing is there.
        drop(tx);
        assert_eq!(r.wait().now_or_never(), Some(false));
    }
}
