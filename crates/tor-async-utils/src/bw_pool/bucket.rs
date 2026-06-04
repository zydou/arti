//! An atomic and shareable token bucket BUT with one caveat, it is without the clock component
//! that is the refill is not taking into account any rate or time tracking.
//!
//! This [`AtomicTokenBucket`] is used within a [`super::BandwidthPool`] to keep track of the
//! available bandwidth.
//!
//! It is refilled through an entity, the [`super::BandwidthRefiller`], which is owned by an
//! independent task built to refill this bucket at the appropriate time.
//!
//! See the [`super`] documentation for more information on how these objects interact with each
//! other.

use std::sync::atomic::{AtomicU64, Ordering};

/// The atomic token bucket minus the clock component.
///
/// This is lock-free and the owner needs to refill it with a specific number of tokens it wants to
/// be distributed across many actors.
#[derive(Debug)]
pub(super) struct AtomicTokenBucket {
    /// Every access to these counters is with [`Ordering::Relaxed`] as they don't
    /// protect any outside data and so we only care about the atomicity action on the
    /// counter.

    /// The current token count.
    available: AtomicU64,
    /// The maximum number of tokens the bucket may hold a.k.a the burst.
    ///
    /// This is atomic because it can be set during runtime. For instance, a config
    /// option reconfigure of a bandwidth rate.
    capacity: u64,
    /// Number of acquire requests currently queued with the refiller.
    ///
    /// Incremented by an acquirer when it enqueues and decremented by the refiller when it
    /// serves the request.
    ///
    /// We use this counter to gate the fast path because every refund goes back to the
    /// available pool. As long as this is non-zero, the fast path can't access the pool.
    waiters: AtomicU64,
}

impl AtomicTokenBucket {
    /// A new bucket capped at `capacity` tokens.
    ///
    /// It starts full.
    pub(super) fn new(capacity: u64) -> Self {
        AtomicTokenBucket {
            available: AtomicU64::new(capacity),
            capacity,
            waiters: AtomicU64::new(0),
        }
    }

    /// Claim all `tokens` from the bucket or nothing if not enough available.
    ///
    /// Returns true if the bucket held at least `tokens` which indicates that they are now granted
    /// to the caller.
    ///
    /// Returns false otherwise, nothing is taken.
    #[must_use]
    pub(super) fn claim(&self, tokens: u64) -> bool {
        // NOTE: fetch_update() is deprecated in 1.99.0 and replaced by try_update()
        // starting in 1.95.0. Our current MSRV is 1.89.0.
        //
        // Relaxed: only the atomic subtract matters, the counter gates no other memory.
        self.available
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                cur.checked_sub(tokens)
            })
            .is_ok()
    }

    /// Add `tokens` to the bucket which is capped at the capacity.
    ///
    /// We use a CAS loop (Compare-And-Swap) because we need to cap the refill to the internal
    /// capacity atomically. A fetch_add + fetch_sub is not possible in order to refill atomically
    /// because of this race:
    ///
    /// ```text
    ///   capacity = 100, available = 90:
    ///     refill: fetch_add(50)  -> available = 140 (above capacity)
    ///     claim:  fetch_sub(140) -> available = 0   (illegal claim, above capacity)
    ///     refill: fetch_sub(40)  -> available underflows (adjust overshoot too late)
    /// ```
    ///
    /// Any tokens that overshoot the capacity are forfeited.
    ///
    /// Finally, the CAS loop is considered ok because the refill is not in the fast path and
    /// should work most of the time on the first iteration.
    pub(super) fn refill(&self, tokens: u64) {
        if tokens == 0 {
            return;
        }

        // NOTE: fetch_update() is deprecated in 1.99.0 and replaced by try_update()
        // starting in 1.95.0. Our current MSRV is 1.89.0.
        //
        // Relaxed: only the atomic add matters, the counter gates no other memory.
        let _ = self
            .available
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                Some(cur.saturating_add(tokens).min(self.capacity))
            });
    }

    /// Take every token out of the bucket and return the amount.
    pub(super) fn drain(&self) -> u64 {
        // Relaxed: only the atomic exchange matters, the counter gates no other memory.
        self.available.swap(0, Ordering::Relaxed)
    }

    /// Refund `tokens` back to the pool.
    ///
    /// The `available` pool fast path is gated by the number of `waiters`.
    pub(super) fn refund(&self, tokens: u64) {
        self.refill(tokens);
    }

    /// Return true iff there is at least one waiter.
    ///
    /// Relaxed: the counter gates no other memory. There is an extremely tiny race here
    /// between the load and the comparison which will make the fast path miss, enqueue
    /// the request. This is so small that we consider it negligible.
    pub(super) fn has_waiters(&self) -> bool {
        self.waiters.load(Ordering::Relaxed) > 0
    }

    /// Record that a new acquirer has queued a request with the refiller.
    pub(super) fn add_waiter(&self) {
        // Relaxed: only the atomic increment matters, the counter gates no other memory.
        self.waiters.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that one queued acquirer has been served by the refiller.
    pub(super) fn remove_waiter(&self) {
        // Let's prevent it from underflowing.
        //
        // Relaxed: only the atomic decrement matters, the counter gates no other memory.
        let _ = self
            .waiters
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |w| {
                Some(w.saturating_sub(1))
            });
    }

    /// Return the capacity.
    pub(super) fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Return the available balance.
    #[cfg(test)]
    pub(super) fn available(&self) -> u64 {
        // Relaxed: we only need the current value of the counter.
        self.available.load(Ordering::Relaxed)
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

    #[test]
    fn claim_and_refill() {
        let b = AtomicTokenBucket::new(100);
        assert_eq!(b.available(), 100);
        assert_eq!(b.capacity(), 100);

        assert!(b.claim(60));
        // Only 40 left. All or nothing.
        assert!(!b.claim(50));
        assert_eq!(b.available(), 40);
        assert!(b.claim(40));
        assert!(!b.claim(1));

        // Refill is capped at capacity.
        b.refill(1000);
        assert_eq!(b.available(), 100);
    }

    #[test]
    fn drain() {
        let b = AtomicTokenBucket::new(100);
        assert!(b.claim(90)); // 10 tokens left

        assert_eq!(b.drain(), 10);
        assert_eq!(b.available(), 0);

        // Draining an empty bucket takes nothing.
        assert_eq!(b.drain(), 0);
    }
}
