//! Implement [`SinkBlocker`], a wrapper type to allow policy-based blocking of
//! a [futures::Sink].

#![cfg_attr(not(feature = "circ-padding"), expect(dead_code))]

mod boolean_policy;
mod counting_policy;

pub(crate) use boolean_policy::BooleanPolicy;
pub(crate) use counting_policy::CountingPolicy;

use std::{
    pin::Pin,
    task::{Context, Poll, Waker},
};

use futures::Sink;
use pin_project::pin_project;
use tor_error::Bug;

/// A wrapper for a [`futures::Sink`] that allows its blocking status to be
/// turned on and off according to a policy.
///
/// While the policy is blocking, attempts to enqueue data on the sink
/// via this `Sink` trait will return [`Poll::Pending`].
/// Later, when the policy is replaced with a nonblocking one via [`Self::update_policy()`]
/// this sink can be written to again.
#[pin_project]
pub(crate) struct SinkBlocker<S, P = BooleanPolicy> {
    /// The inner sink.
    #[pin]
    inner: S,
    /// A policy state object, deciding whether we are blocking or not.
    ///
    /// Invariant: Whenever we try to send with a blocking Policy,
    /// we store the context's waker in self.waker.
    /// If later the policy becomes non-blocking,
    /// we we alert the `Waker`.
    policy: P,
    /// A waker that we should alert when `policy` transitions from
    /// a blocking to a non-blocking state.
    waker: Option<Waker>,
}

/// A policy that describes whether cells can be sent on a [`SinkBlocker`].
///
/// Each `Policy` object can be in different states:
/// some states cause the `SinkBlocker` to block traffic,
/// and some cause the `SinkBlocker` to permit traffic.
///
/// The user of a `SinkBlocker` is expected to call
/// [`update_policy()`](SinkBlocker::update_policy) from time to time,
/// when they need to make a manual change in the `SinkBlocker`'s status.
/// This is the only way for a blocked `SinkBlocker` to become unblocked.
///
/// Invariants:
///  - The state of a `Policy` object may transition from
///    non-blocking to blocking.
///  - The state of a `Policy` object may _not_ transition
///    from blocking to non-blocking.
///  - If [`is_blocking()`](Policy::is_blocking) has returned false,
///    and no intervening changes have been made to the `Policy`,
///    [`take_one()`](Policy::take_one) will succeed.
///
/// Note that because of this last invariant,
/// interior mutability is strongly discouraged for implementations of this trait.
pub(crate) trait Policy {
    /// Returns true if this policy is currently blocking.
    ///
    /// Invariant: If this returns true on a given Policy,
    /// it must always return true on that Policy in the future.
    /// (That is, a Policy may become blocked,
    /// but may not become unblocked.)
    fn is_blocking(&self) -> bool;

    /// Modify this policy in response to having queued one item.
    ///
    /// Requires that `self.is_blocking()` has just returned false.
    /// Returns an error, and does not change `self`, if this _is_ blocked.
    /// (That is, you must only call this function on a non-blocked Policy.)
    //
    // Notes: The above rules mean that `take_one` can transition from
    // unblocking to blocking, but never vice versa.
    fn take_one(&mut self) -> Result<(), Bug>;
}

impl<S, P> SinkBlocker<S, P> {
    /// Construct a new `SinkBlocker` wrapping a given sink, with a given
    /// initial blocking policy.
    pub(crate) fn new(inner: S, policy: P) -> Self {
        SinkBlocker {
            inner,
            policy,
            waker: None,
        }
    }

    /// Return a reference to the inner `Sink` of this object.
    ///
    /// See warnings on `as_inner_mut`.
    pub(crate) fn as_inner(&self) -> &S {
        &self.inner
    }

    /// Return a mutable reference to the inner `Sink` of this object.
    ///
    /// Note that with this method, it is possible to bypass the blocking features
    /// of [`SinkBlocker`].  This is an intentional escape hatch.
    pub(crate) fn as_inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S, P: Policy> SinkBlocker<S, P> {
    /// Replace the current [`Policy`] state object with `new_policy`.
    ///
    /// This method is used to make a blocked `SinkBlocker` unblocked,
    /// or vice versa.
    //
    // Invariants: If we become unblocked, alerts our `Waker`.
    //
    // (This is the only method that can cause us to transition from blocked to
    // unblocked, so this is the only place where we have to alert the waker.)
    pub(crate) fn update_policy(&mut self, new_policy: P) {
        let was_blocking = self.policy.is_blocking();
        let is_blocking = new_policy.is_blocking();
        self.policy = new_policy;
        if was_blocking && !is_blocking {
            if let Some(waker) = self.waker.take() {
                waker.wake();
            }
        }
    }
}

impl<T, S: Sink<T>, P: Policy> Sink<T> for SinkBlocker<S, P> {
    type Error = S::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let self_ = self.project();
        if self_.policy.is_blocking() {
            // We're blocked.  We're going to store the context's Waker,
            // so that we can invoke it later when the policy changes.
            *self_.waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            // If this returns Ready, great!
            // If this returns Pending, it will wake up the context when it is
            // no longer blocked.
            self_.inner.poll_ready(cx)
        }
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let self_ = self.project();
        // We're only allowed to call this method if poll_ready succeeded,
        // so we know that is_blocking() was false.
        let () = self_.inner.start_send(item)?;

        // (Invoke take_one, to account for this item.)
        //
        // Note: Instead of calling expect, perhaps it would be better to have a custom error type
        // that wraps S::Error and also allows for a Bug.  But that might be overkill, since
        // we only expect this error to happen in the event of a bug.
        let _: () = self_.policy.take_one().expect(
            "take_one failed after is_blocking returned false: bug in Policy or SinkBlocker",
        );
        // (Take_one is not allowed to cause us to become unblocked, so we don't
        // need to invoke the waiter.)

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Note that we want to flush the inner sink,
        // even if we are blocking attempts to send onto it.
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;

    use futures::{SinkExt as _, StreamExt as _, channel::mpsc, poll};
    use tor_rtmock::MockRuntime;

    #[test]
    fn block_and_unblock() {
        // Try a few different schedulers, to make sure that our logic works for all of them.
        MockRuntime::test_with_various(|runtime| async move {
            let (tx, mut rx) = mpsc::channel::<u32>(1);
            let tx = SinkBlocker::new(tx, BooleanPolicy::Unblocked);
            let mut tx = tx.buffer(5);

            let blocked = Arc::new(AtomicBool::new(false));
            let n_received = Arc::new(AtomicUsize::new(0));

            let blocked_clone = Arc::clone(&blocked);
            let n_received_clone = Arc::clone(&n_received);
            let n_received_clone2 = Arc::clone(&n_received);

            runtime.spawn_identified("Transmitter", async move {
                tx.send(1).await.unwrap();
                tx.send(2).await.unwrap();
                blocked.store(true, Ordering::SeqCst);
                tx.get_mut().set_blocked();
                // Have to use "feed" here since send would flush, which would block.
                tx.feed(3).await.unwrap();
                tx.feed(4).await.unwrap();
                assert!(dbg!(n_received.load(Ordering::SeqCst)) <= 2);
                // Make sure that we _cannot_ flush right now.
                let flush_future = tx.flush();
                assert!(poll!(flush_future).is_pending());
                // Now note that we're unblocked, and unblock.
                blocked.store(false, Ordering::SeqCst);
                tx.get_mut().set_unblocked();
                // This time we should actually flush.
                tx.flush().await.unwrap();
                tx.close().await.unwrap();
            });

            runtime.spawn_identified("Receiver", async move {
                let n_received = n_received_clone;
                let blocked = blocked_clone;
                let mut expected = 1;
                while let Some(val) = rx.next().await {
                    assert_eq!(val, expected);
                    expected += 1;
                    n_received.fetch_add(1, Ordering::SeqCst);
                    if val >= 3 {
                        assert_eq!(blocked.load(Ordering::SeqCst), false);
                    }
                }
                dbg!(expected);
            });

            runtime.progress_until_stalled().await;

            assert_eq!(dbg!(n_received_clone2.load(Ordering::SeqCst)), 4);
        });
    }
}
