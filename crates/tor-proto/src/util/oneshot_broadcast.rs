//! A oneshot broadcast channel.
//!
//! The motivation for this channel type was to allow multiple
//! receivers to either wait for something to finish,
//! or to have an inexpensive method of checking if it has finished.
//!
//! See [`channel()`].

// NOTE: If we decide to make this public in the future (for example through `tor-async-utils`),
// we should enable the doc tests.

use std::future::{Future, IntoFuture};
use std::ops::Drop;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{ready, Context, Poll, Waker};

use slotmap_careful::DenseSlotMap;

slotmap_careful::new_key_type! { struct WakerKey; }

/// A [oneshot broadcast][crate::util::oneshot_broadcast] sender.
#[derive(Debug)]
pub(crate) struct Sender<T> {
    /// State shared with all [`Receiver`]s.
    shared: Weak<Shared<T>>,
}

/// A [oneshot broadcast][crate::util::oneshot_broadcast] receiver.
///
/// The `Receiver` offers two methods for receiving the message:
///
/// 1. [`Receiver::into_future`]
///     ```rust,ignore
///     let (tx, rx) = channel();
///     tx.send(0);
///     let message: u32 = rx.await.unwrap();
///     ```
///
/// 2. [`Receiver::borrowed`]
///     ```rust,ignore
///     let (tx, rx) = channel();
///     tx.send(0);
///     let message: &u32 = rx.borrowed().await.unwrap();
///     ```
#[derive(Clone, Debug)]
pub(crate) struct Receiver<T> {
    /// State shared with the sender and all other receivers.
    shared: Arc<Shared<T>>,
}

/// State shared between the sender and receivers.
/// Correctness:
///
/// Sending a message:
///  - set the message OnceLock (A)
///  - acquire the wakers Mutex
///  - take all wakers (B)
///  - release the wakers Mutex (C)
///  - wake all wakers
///
/// Polling:
///  - if message was set, return it (fast path)
///  - acquire the wakers Mutex (D)
///  - if message was set, return it (E)
///  - add waker (F)
///  - release the wakers Mutex
///
/// When the wakers Mutex is released at (C), a release-store operation is performed by the Mutex,
/// which means that the message set at (A) will be seen by all future acquire-load operations by
/// that same Mutex. More specifically, after (C) has occurred and when the same mutex is acquired at
/// (D), the message set at (A) is guaranteed to be visible at (E). This means that after the wakers
/// are taken at (B), no future wakers will be added at (F) and no waker will be "lost".
#[derive(Debug)]
struct Shared<T> {
    /// The message sent from the [`Sender`] to the [`Receiver`]s.
    msg: OnceLock<Result<T, SenderDropped>>,
    /// The wakers waiting for a value to be sent.
    /// Will be set to `Err` after the wakers have been woken.
    // the `Result` isn't technically needed here,
    // but we use it to help detect bugs;
    // see `WakersAlreadyWoken` for details
    wakers: Mutex<Result<DenseSlotMap<WakerKey, Waker>, WakersAlreadyWoken>>,
}

/// The future from [`Receiver::borrowed`].
///
/// Will be ready, yielding `&'a T`,
/// when the sender sends a message or is dropped.
#[derive(Debug)]
pub(crate) struct BorrowedReceiverFuture<'a, T> {
    /// State shared with the sender and all other receivers.
    shared: &'a Shared<T>,
    /// The key for any waker that we've added to [`Shared::wakers`].
    waker_key: Option<WakerKey>,
}

/// The future from [`Receiver::into_future`].
///
/// Will be ready, yielding a clone of `T`,
/// when the sender sends a message or is dropped.
// Both `ReceiverFuture` and `BorrowedReceiverFuture` have similar fields
// but there's no nice way to deduplicated them.
// It would have been nice if we could store a `BorrowedReceiverFuture`
// holding a reference to our `Arc<Shared>`,
// but that would be a self-referential struct,
// so we need to duplicate the fields here instead.
#[derive(Debug)]
pub(crate) struct ReceiverFuture<T> {
    /// State shared with the sender and all other receivers.
    shared: Arc<Shared<T>>,
    /// The key for any waker that we've added to [`Shared::wakers`].
    waker_key: Option<WakerKey>,
}

/// The wakers have already been woken.
///
/// This is used to help detect if we're trying to access the wakers after they've already been
/// woken, which likely indicates a bug. For example, it is a bug if a receiver attempts to add a
/// waker after the sender has already sent its message and woken the wakers, since the new waker
/// would never be woken.
#[derive(Copy, Clone, Debug)]
struct WakersAlreadyWoken;

/// The message has already been set, and we can't set it again.
#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("the message was already set")]
struct MessageAlreadySet;

/// The sender was dropped, so the channel is closed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the sender was dropped")]
pub(crate) struct SenderDropped;

/// Create a new oneshot broadcast channel.
///
/// ```rust,ignore
/// let (tx, rx) = channel();
/// let rx_clone = rx.clone();
/// tx.send(0_u8);
/// assert_eq!(rx.await, Ok(0));
/// assert_eq!(rx_clone.await, Ok(0));
/// ```
pub(crate) fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let shared = Arc::new(Shared {
        msg: OnceLock::new(),
        wakers: Mutex::new(Ok(DenseSlotMap::with_key())),
    });

    let sender = Sender {
        shared: Arc::downgrade(&shared),
    };

    let receiver = Receiver { shared };

    (sender, receiver)
}

impl<T> Sender<T> {
    /// Send the message to the [`Receiver`]s.
    ///
    /// The message may be lost if all receivers have been dropped.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn send(self, msg: T) {
        // set the message and inform the wakers
        Self::send_and_wake(&self.shared, Ok(msg))
            // this 'send()` method takes an owned self,
            // and we don't send a message outside of here and the drop handler,
            // so this shouldn't be possible
            .expect("could not set the message");
    }

    /// Send the message, and wake and clear all wakers.
    ///
    /// If all receivers have been dropped, then always returns `Ok`.
    ///
    /// If the message was unable to be set, returns `Err(MessageAlreadySet)`.
    fn send_and_wake(
        shared: &Weak<Shared<T>>,
        msg: Result<T, SenderDropped>,
    ) -> Result<(), MessageAlreadySet> {
        // Even if the `Weak` upgrade is successful,
        // it's possible that the last receiver
        // will be dropped during this `send_and_wake` method,
        // in which case we will be holding the last `Arc`.
        let Some(shared) = shared.upgrade() else {
            // all receivers have dropped; nothing to do
            return Ok(());
        };

        // set the message
        shared.msg.set(msg).or(Err(MessageAlreadySet))?;

        let mut wakers = {
            let mut wakers = shared.wakers.lock().expect("poisoned");
            // Take the wakers and drop the mutex guard, releasing the lock.
            //
            // We could just drain the wakers map in-place here, but instead we replace the map with
            // an explicit `WakersAlreadyWoken` state to help catch bugs if something tries adding a
            // new waker later after we've already woken the wakers.
            //
            // The above `msg.set()` will only ever succeed once,
            // which means that we should only end up here once.
            std::mem::replace(&mut *wakers, Err(WakersAlreadyWoken))
                .expect("wakers were taken more than once")
        };

        // Once we drop the mutex guard, which does a release-store on its own atomic, any other
        // code which later acquires the wakers mutex is guaranteed to see the msg as "set".
        // See comments on `Shared`.

        // Wake while not holding the lock.
        // Since the lock is used in `ReceiverFuture::poll` and `ReceiverFuture::drop` and
        // should not block for long periods of time,
        // we'd prefer not to run third-party waker code here while holding the mutex,
        // even if `wake` should typically be fast.
        for (_key, waker) in wakers.drain() {
            waker.wake();
        }

        Ok(())
    }

    /// Returns `true` if all [`Receiver`]s (and all futures created from the receivers) have been
    /// dropped.
    ///
    /// This can be useful to skip doing extra work to generate the message if the message will be
    /// discarded anyways.
    // This is for external use.
    // It is not always valid to call this internally.
    // For example when we've done a `Weak::upgrade` internally, like in `send_and_wake`,
    // this won't return the correct value.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_cancelled(&self) -> bool {
        self.shared.strong_count() == 0
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        // set an error message to indicate that the sender was dropped and inform the wakers;
        // it's fine if setting the message fails since it might have been set previously during a
        // `send()`
        let _ = Self::send_and_wake(&self.shared, Err(SenderDropped));
    }
}

impl<T> Receiver<T> {
    /// Receive a borrowed message from the [`Sender`].
    ///
    /// This may be more efficient than [`Receiver::into_future`]
    /// and doesn't require `T: Clone`.
    ///
    /// This is cancellation-safe.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn borrowed(&self) -> BorrowedReceiverFuture<'_, T> {
        BorrowedReceiverFuture {
            shared: &self.shared,
            waker_key: None,
        }
    }

    /// The receiver is ready.
    ///
    /// If `true`, the [`Sender`] has either sent its message or been dropped.
    pub(crate) fn is_ready(&self) -> bool {
        self.shared.msg.get().is_some()
    }
}

impl<T: Clone> IntoFuture for Receiver<T> {
    type Output = Result<T, SenderDropped>;
    type IntoFuture = ReceiverFuture<T>;

    /// This future is cancellation-safe.
    fn into_future(self) -> Self::IntoFuture {
        ReceiverFuture {
            shared: self.shared,
            waker_key: None,
        }
    }
}

impl<'a, T> Future for BorrowedReceiverFuture<'a, T> {
    type Output = Result<&'a T, SenderDropped>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let self_ = self.get_mut();
        receiver_fut_poll(self_.shared, &mut self_.waker_key, cx.waker())
    }
}

impl<T> Drop for BorrowedReceiverFuture<'_, T> {
    fn drop(&mut self) {
        receiver_fut_drop(self.shared, &mut self.waker_key);
    }
}

impl<T: Clone> Future for ReceiverFuture<T> {
    type Output = Result<T, SenderDropped>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let self_ = self.get_mut();
        let poll = receiver_fut_poll(&self_.shared, &mut self_.waker_key, cx.waker());
        Poll::Ready(ready!(poll)).map_ok(Clone::clone)
    }
}

impl<T> Drop for ReceiverFuture<T> {
    fn drop(&mut self) {
        receiver_fut_drop(&self.shared, &mut self.waker_key);
    }
}

/// The shared poll implementation for receiver futures.
fn receiver_fut_poll<'a, T>(
    shared: &'a Shared<T>,
    waker_key: &mut Option<WakerKey>,
    new_waker: &Waker,
) -> Poll<Result<&'a T, SenderDropped>> {
    // if the message was already set, return it
    if let Some(msg) = shared.msg.get() {
        return Poll::Ready(msg.as_ref().or(Err(SenderDropped)));
    }

    let mut wakers = shared.wakers.lock().expect("poisoned");

    // check again now that we've acquired the mutex
    if let Some(msg) = shared.msg.get() {
        return Poll::Ready(msg.as_ref().or(Err(SenderDropped)));
    }

    // we have acquired the wakers mutex and checked that the message wasn't set,
    // so we know that wakers have not yet been woken
    // and it's okay to add our waker to the wakers map
    let wakers = wakers.as_mut().expect("wakers were already woken");

    match waker_key {
        // we have added a waker previously
        Some(waker_key) => {
            // replace the old entry
            let waker = wakers
                .get_mut(*waker_key)
                // the waker is only removed from the map by our drop handler,
                // so the waker should never be missing
                .expect("waker key is missing from map");
            waker.clone_from(new_waker);
        }
        // we have never added a waker
        None => {
            // add a new entry
            let new_key = wakers.insert(new_waker.clone());
            *waker_key = Some(new_key);
        }
    }

    Poll::Pending
}

/// The shared drop implementation for receiver futures.
fn receiver_fut_drop<T>(shared: &Shared<T>, waker_key: &mut Option<WakerKey>) {
    if let Some(waker_key) = waker_key.take() {
        let mut wakers = shared.wakers.lock().expect("poisoned");
        if let Ok(wakers) = wakers.as_mut() {
            let waker = wakers.remove(waker_key);
            // this is the only place that removes the waker from the map,
            // so the waker should never be missing
            debug_assert!(waker.is_some(), "the waker key was not found");
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use futures::future::FutureExt;
    use futures::task::SpawnExt;

    impl<T> Shared<T> {
        /// Count the number of wakers.
        fn count_wakers(&self) -> usize {
            self.wakers
                .lock()
                .expect("poisoned")
                .as_ref()
                .map(|x| x.len())
                .unwrap_or(0)
        }
    }

    #[test]
    fn standard_usage() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx) = channel();
            tx.send(0_u8);
            assert_eq!(rx.borrowed().await, Ok(&0));

            let (tx, rx) = channel();
            tx.send(0_u8);
            assert_eq!(rx.await, Ok(0));
        });
    }

    #[test]
    fn immediate_drop() {
        let _ = channel::<()>();

        let (tx, rx) = channel::<()>();
        drop(tx);
        drop(rx);

        let (tx, rx) = channel::<()>();
        drop(rx);
        drop(tx);
    }

    #[test]
    fn drop_sender() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx_1) = channel::<u8>();

            let rx_2 = rx_1.clone();
            drop(tx);
            let rx_3 = rx_1.clone();
            assert_eq!(rx_1.borrowed().await, Err(SenderDropped));
            assert_eq!(rx_2.borrowed().await, Err(SenderDropped));
            assert_eq!(rx_3.borrowed().await, Err(SenderDropped));
        });
    }

    #[test]
    fn clone_before_send() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx_1) = channel();

            let rx_2 = rx_1.clone();
            tx.send(0_u8);
            assert_eq!(rx_1.borrowed().await, Ok(&0));
            assert_eq!(rx_2.borrowed().await, Ok(&0));
        });
    }

    #[test]
    fn clone_after_send() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx_1) = channel();

            tx.send(0_u8);
            let rx_2 = rx_1.clone();
            assert_eq!(rx_1.borrowed().await, Ok(&0));
            assert_eq!(rx_2.borrowed().await, Ok(&0));
        });
    }

    #[test]
    fn clone_after_borrowed() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx_1) = channel();

            tx.send(0_u8);
            assert_eq!(rx_1.borrowed().await, Ok(&0));
            let rx_2 = rx_1.clone();
            assert_eq!(rx_2.borrowed().await, Ok(&0));
        });
    }

    #[test]
    fn drop_one_receiver() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx_1) = channel();

            let rx_2 = rx_1.clone();
            drop(rx_1);
            tx.send(0_u8);
            assert_eq!(rx_2.borrowed().await, Ok(&0));
        });
    }

    #[test]
    fn drop_all_receivers() {
        let (tx, rx_1) = channel();

        let rx_2 = rx_1.clone();
        drop(rx_1);
        drop(rx_2);
        tx.send(0_u8);
    }

    #[test]
    fn drop_fut() {
        let (_tx, rx) = channel::<u8>();
        let fut = rx.borrowed();
        assert_eq!(rx.shared.count_wakers(), 0);
        drop(fut);
        assert_eq!(rx.shared.count_wakers(), 0);

        // drop after sending
        let (tx, rx) = channel();
        tx.send(0_u8);
        let fut = rx.borrowed();
        assert_eq!(rx.shared.count_wakers(), 0);
        drop(fut);
        assert_eq!(rx.shared.count_wakers(), 0);

        // drop after polling once
        let (_tx, rx) = channel::<u8>();
        let mut fut = Box::pin(rx.borrowed());
        assert_eq!(rx.shared.count_wakers(), 0);
        assert_eq!(fut.as_mut().now_or_never(), None);
        assert_eq!(rx.shared.count_wakers(), 1);
        drop(fut);
        assert_eq!(rx.shared.count_wakers(), 0);

        // drop after polling once and send
        let (tx, rx) = channel();
        let mut fut = Box::pin(rx.borrowed());
        assert_eq!(rx.shared.count_wakers(), 0);
        assert_eq!(fut.as_mut().now_or_never(), None);
        assert_eq!(rx.shared.count_wakers(), 1);
        tx.send(0_u8);
        assert_eq!(rx.shared.count_wakers(), 0);
        drop(fut);
    }

    #[test]
    fn drop_owned_fut() {
        let (_tx, rx) = channel::<u8>();
        let fut = rx.clone().into_future();
        assert_eq!(rx.shared.count_wakers(), 0);
        drop(fut);
        assert_eq!(rx.shared.count_wakers(), 0);

        // drop after sending
        let (tx, rx) = channel();
        tx.send(0_u8);
        let fut = rx.clone().into_future();
        assert_eq!(rx.shared.count_wakers(), 0);
        drop(fut);
        assert_eq!(rx.shared.count_wakers(), 0);

        // drop after polling once
        let (_tx, rx) = channel::<u8>();
        let mut fut = Box::pin(rx.clone().into_future());
        assert_eq!(rx.shared.count_wakers(), 0);
        assert_eq!(fut.as_mut().now_or_never(), None);
        assert_eq!(rx.shared.count_wakers(), 1);
        drop(fut);
        assert_eq!(rx.shared.count_wakers(), 0);

        // drop after polling once and send
        let (tx, rx) = channel();
        let mut fut = Box::pin(rx.clone().into_future());
        assert_eq!(rx.shared.count_wakers(), 0);
        assert_eq!(fut.as_mut().now_or_never(), None);
        assert_eq!(rx.shared.count_wakers(), 1);
        tx.send(0_u8);
        assert_eq!(rx.shared.count_wakers(), 0);
        drop(fut);
    }

    #[test]
    fn is_ready_after_send() {
        let (tx, rx_1) = channel();
        assert!(!rx_1.is_ready());
        let rx_2 = rx_1.clone();
        assert!(!rx_2.is_ready());

        tx.send(0_u8);

        assert!(rx_1.is_ready());
        assert!(rx_2.is_ready());

        let rx_3 = rx_1.clone();
        assert!(rx_3.is_ready());
    }

    #[test]
    fn is_ready_after_drop() {
        let (tx, rx_1) = channel::<u8>();
        assert!(!rx_1.is_ready());
        let rx_2 = rx_1.clone();
        assert!(!rx_2.is_ready());

        drop(tx);

        assert!(rx_1.is_ready());
        assert!(rx_2.is_ready());

        let rx_3 = rx_1.clone();
        assert!(rx_3.is_ready());
    }

    #[test]
    fn is_cancelled() {
        let (tx, rx) = channel::<u8>();
        assert!(!tx.is_cancelled());
        drop(rx);
        assert!(tx.is_cancelled());

        let (tx, rx_1) = channel::<u8>();
        assert!(!tx.is_cancelled());
        let rx_2 = rx_1.clone();
        drop(rx_1);
        assert!(!tx.is_cancelled());
        drop(rx_2);
        assert!(tx.is_cancelled());
    }

    #[test]
    fn recv_in_task() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (tx, rx) = channel();

            let join = rt
                .spawn_with_handle(async move {
                    assert_eq!(rx.borrowed().await, Ok(&0));
                    assert_eq!(rx.await, Ok(0));
                })
                .unwrap();

            tx.send(0_u8);

            join.await;
        });
    }

    #[test]
    fn recv_multiple_in_task() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (tx, rx) = channel();
            let rx_1 = rx.clone();
            let rx_2 = rx.clone();

            let join_1 = rt
                .spawn_with_handle(async move {
                    assert_eq!(rx_1.borrowed().await, Ok(&0));
                })
                .unwrap();
            let join_2 = rt
                .spawn_with_handle(async move {
                    assert_eq!(rx_2.await, Ok(0));
                })
                .unwrap();

            tx.send(0_u8);

            join_1.await;
            join_2.await;
            assert_eq!(rx.borrowed().await, Ok(&0));
        });
    }

    #[test]
    fn recv_multiple_times() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx) = channel();

            tx.send(0_u8);
            assert_eq!(rx.borrowed().await, Ok(&0));
            assert_eq!(rx.borrowed().await, Ok(&0));
            assert_eq!(rx.clone().await, Ok(0));
            assert_eq!(rx.await, Ok(0));
        });
    }

    #[test]
    fn stress() {
        // In general we don't have control over the runtime and where/when tasks are scheduled,
        // so we try as best as possible to send the message while simultaneously creating new
        // receivers and waiting on them.
        // It's possible this might be entirely ineffective since we don't enforce any specific
        // scheduler behaviour here,
        // but in the worst case it's still a test with multiple receivers on different tasks,
        // so is useful to have.
        //
        // The `test_with_various` helper uses `MockExecutor` with two different deterministic
        // scheduling policies.
        // At least at the time of writing,
        // when this test uses `MockExecutor` with its "queue" scheduling policy
        // the "send" occurs after 20 of the tasks have begun waiting.
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (tx, rx) = channel();

            rt.spawn(async move {
                // this tries to delay the send a little bit
                // to give time for some of the receiver tasks to start
                for _ in 0..20 {
                    tor_rtcompat::task::yield_now().await;
                }
                tx.send(0_u8);
            })
            .unwrap();

            let mut joins = vec![];
            for _ in 0..100 {
                let rx_clone = rx.clone();
                let join = rt
                    .spawn_with_handle(async move { rx_clone.borrowed().await.cloned() })
                    .unwrap();
                joins.push(join);
                // allows the send task to make progress if single-threaded
                tor_rtcompat::task::yield_now().await;
            }

            for join in joins {
                assert!(matches!(join.await, Ok(0)));
            }
        });
    }
}
