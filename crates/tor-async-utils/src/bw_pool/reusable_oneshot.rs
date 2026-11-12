//! A reusable async oneshot channel.
//!
//! This is a oneshot channel that can be reinitialized without needing to allocate new memory,
//! which can be useful when you need to repeatedly initialize a new oneshot channel after a
//! previous channel is used.

use std::ops::Drop;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use futures::task::AtomicWaker;

/// The transmitting end of the oneshot channel.
#[derive(Debug)]
pub(crate) struct Sender<T> {
    /// State shared with the [`Receiver`].
    shared: Option<Weak<Shared<T>>>,
}

/// The receiving end of the oneshot channel.
#[derive(Debug)]
pub(crate) struct Receiver<T> {
    /// State shared with the [`Sender`].
    shared: Arc<Shared<T>>,
    /// Are we still waiting to receive the message?
    is_waiting_for_msg: bool,
}

/// State shared by a [`Sender`] and [`Receiver`].
#[derive(Debug)]
struct Shared<T> {
    /// The message sent from the [`Sender`] to the [`Receiver`].
    ///
    /// This is a [`Mutex`], but we only ever use [`try_lock()`](Mutex::try_lock)
    /// so this will never block.
    /// An `AtomicRefCell` would be nicer, but a `Mutex` with `try_lock()` does
    /// effectively the same thing without the extra dependency.
    /// Other more-performant alternatives are a `OnceLock` (requires an additional spinloop around
    /// an `Arc::get_mut()`) or `UnsafeCell` (requires unsafe).
    msg: Mutex<Option<Result<T, SenderDropped>>>,
    /// Whether the `msg` field is set.
    ///
    /// We could just check `msg` directly for a `Some` value,
    /// but that requires two atomic CAS operations per check
    /// (one to lock and another to unlock).
    /// Instead we use this atomic so that there is only a single atomic load.
    is_msg_set: AtomicBool,
    /// The receiver's waker.
    waker: AtomicWaker,
}

impl<T> Receiver<T> {
    /// A new receiver without a [`Sender`].
    pub(crate) fn new() -> Self {
        let shared = Shared {
            msg: Mutex::new(None),
            is_msg_set: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        };
        let shared = Arc::new(shared);

        Receiver {
            shared,
            is_waiting_for_msg: false,
        }
    }

    /// Is this receiver waiting for a message?
    ///
    /// This is true if the receiver has a [`Sender`] that it has not read a message from yet.
    ///
    /// If this returns false, then a
    /// [new `Sender`](Receiver::new_sender) can be successfully created.
    // Is currently unused.
    #[expect(unused)]
    pub(crate) fn is_waiting_for_msg(&self) -> bool {
        self.is_waiting_for_msg
    }

    /// Create a new [`Sender`].
    /// Can only have one sender at a time.
    ///
    /// Returns `None` if we've previously created a sender and we haven't read its message yet.
    // Is currently only used in tests.
    #[cfg_attr(not(test), expect(unused))]
    pub(crate) fn new_sender(&mut self) -> Option<Sender<T>> {
        Some(self.guarantee_new_sender()?.into_sender())
    }

    /// Provides a type that can be converted into a new [`Sender`].
    ///
    /// This can be useful if you don't want a new `Sender` yet,
    /// but you want a guarantee that a sender can be created later.
    ///
    /// Returns `None` if we've previously created a sender and we haven't read its message yet.
    pub(crate) fn guarantee_new_sender(&mut self) -> Option<SenderGuarantee<'_, T>> {
        // If we're still waiting for a message from the last sender,
        // don't allow the creation of a new sender.
        if self.is_waiting_for_msg {
            return None;
        }

        Some(SenderGuarantee(self))
    }

    /// Receive the message.
    pub(crate) fn recv<'a>(&'a mut self) -> Result<ReceiverFuture<'a, T>, NoSender> {
        // If we're not waiting for a message, then there will never be a message.
        if !self.is_waiting_for_msg {
            return Err(NoSender);
        }

        Ok(ReceiverFuture { receiver: self })
    }

    /// Try to receive a message without blocking.
    // Is currently only used in tests.
    #[cfg_attr(not(test), expect(unused))]
    pub(crate) fn try_recv(&mut self) -> Result<Option<T>, RecvError> {
        // If we're not waiting for a message, then there will never be a message.
        if !self.is_waiting_for_msg {
            return Err(RecvError::NoSender);
        }

        self.recv_impl().transpose().map_err(Into::into)
    }

    /// The shared implementation to receive the message.
    ///
    /// The "message has not yet been set" path is quick (just an atomic load)
    /// so its cheap to check.
    ///
    /// Returns `None` if there's no update.
    /// Returns `Some` if we have the message or the sender was dropped.
    fn recv_impl(&mut self) -> Option<Result<T, SenderDropped>> {
        // An acquire-load so that the `Some` value for `self.shared.msg` as set by
        // `Sender::send_impl()` is visible here.
        if !self.shared.is_msg_set.load(Ordering::Acquire) {
            return None;
        }

        // There won't ever be contention on the lock, so we can `try_lock().expect()`.
        let msg = self
            .shared
            .msg
            .try_lock()
            .expect("msg lock")
            .take()
            .expect("msg was set but no msg available");

        // We removed the message, so reset the flag.
        //
        // A relaxed-store since the `take()` above doesn't need to be visible to any other
        // threads (the sender is gone now that it sent the one value).
        self.shared.is_msg_set.store(false, Ordering::Relaxed);

        self.is_waiting_for_msg = false;

        Some(msg)
    }
}

/// Future returned by [`Receiver::recv()`].
#[derive(Debug)]
pub(crate) struct ReceiverFuture<'a, T> {
    /// The receiver.
    receiver: &'a mut Receiver<T>,
}

impl<'a, T> Future for ReceiverFuture<'a, T> {
    type Output = Result<T, SenderDropped>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let self_ = self.get_mut();

        let check_fn = |receiver: &mut Receiver<T>| {
            // If there was something to receive,
            // then we return it from the future.
            if let Some(msg) = receiver.recv_impl() {
                Poll::Ready(msg)
            } else {
                Poll::Pending
            }
        };

        // Initial check is for performance, since the check is quick.
        match check_fn(self_.receiver) {
            Poll::Ready(msg) => return Poll::Ready(msg),
            Poll::Pending => {}
        }

        self_.receiver.shared.waker.register(cx.waker());

        // Must recheck after registering the waker.
        //
        // > Consumers should call `register` before checking the result of a computation and
        // > producers should call `wake` after producing the computation (this differs from the
        // > usual `thread::park` pattern).
        check_fn(self_.receiver)
    }
}

impl<T> Sender<T> {
    /// Send the message.
    pub(crate) fn send(mut self, msg: T) {
        // Shouldn't panic because `shared` is only taken here in `send()` or `drop()`.
        let shared = self.shared.take().expect("shared is missing");

        // Send the message.
        Self::send_impl(shared, Ok(msg));
    }

    /// The shared implementation to send the message.
    ///
    /// It's assumed that a message has not yet been set.
    /// Otherwise this code will panic.
    // Semantically it makes more sense to take an owned `Weak` here since we don't want the caller
    // to keep it. (The caller could clone it, but we're not trying to be foolproof here.)
    #[allow(clippy::needless_pass_by_value)]
    fn send_impl(shared: Weak<Shared<T>>, msg: Result<T, SenderDropped>) {
        let Some(shared) = shared.upgrade() else {
            // All receivers have dropped; nothing to do.
            return;
        };

        // Set the message.
        {
            // There won't ever be contention on the lock, so we can `try_lock().expect()`.
            let mut msg_store = shared.msg.try_lock().expect("msg lock");

            if msg_store.is_some() {
                // Our channel logic is broken. Not much we can do here but panic.
                // See the contract in the doc comment of `send_impl()`.
                panic!("trying to send a message, but msg was already set");
            }

            *msg_store = Some(msg);
        }

        // A release-store since the message set above should be visible after the
        // acquire-load in `Receiver::recv_impl()`.
        let _ = shared
            .is_msg_set
            .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)
            .expect("msg was unset, but is_msg_set was true");

        // At this point it's possible that the receiver will see that `is_msg_set` is true,
        // read the value, and even create a new sender. But this is fine because below the only
        // thing we do is a `wake()`, which in that case would only cause a spurious wake of the
        // new sender.

        // Must wake after setting the message.
        //
        // > Consumers should call `register` before checking the result of a computation and
        // > producers should call `wake` after producing the computation (this differs from the
        // > usual `thread::park` pattern).
        shared.waker.wake();
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let Some(shared) = self.shared.take() else {
            // Already sent a message.
            return;
        };

        // Send a notification that the sender was dropped.
        Self::send_impl(shared, Err(SenderDropped));
    }
}

/// A guarantee that a new sender can be created.
///
/// Returned from [`Receiver::guarantee_new_sender()`].
/// The guarantee will be voided if this handle is dropped.
///
/// Note: Due to non-lexical lifetimes,
/// it's possible to have multiple different `SenderGuarantee`s at the same time.
/// But this is okay since the compiler will only allow you to use the latest one.
pub(crate) struct SenderGuarantee<'a, T>(&'a mut Receiver<T>);

impl<'a, T> SenderGuarantee<'a, T> {
    /// Convert the guarantee into a new [`Sender`].
    pub(crate) fn into_sender(self) -> Sender<T> {
        // Now we're creating a new sender,
        // which we'll be waiting for a message from.
        self.0.is_waiting_for_msg = true;

        Sender {
            shared: Some(Arc::downgrade(&self.0.shared)),
        }
    }
}

/// A sender existed, but was dropped before sending a message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SenderDropped;

/// The receiver does not have a sender.
///
/// Have not yet created a new sender (see [`Receiver::new_sender()`]),
/// or we've already read the message from the last sender.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NoSender;

/// An error when attempting to receive a message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecvError {
    /// See [`NoSender`].
    NoSender,
    /// See [`SenderDropped`].
    SenderDropped,
}

impl From<SenderDropped> for RecvError {
    fn from(_: SenderDropped) -> Self {
        Self::SenderDropped
    }
}

#[cfg(test)]
mod tests {
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

    use std::time::Duration;

    use futures::FutureExt as _;
    use tor_rtcompat::SleepProvider as _;
    use tor_rtcompat::SpawnExt as _;

    #[test]
    fn simple() {
        // New receiver.
        let mut receiver = Receiver::<u8>::new();

        // New sender, send message, and receive message.
        let sender = receiver.new_sender().unwrap();
        sender.send(5);
        assert_eq!(receiver.recv().unwrap().now_or_never().unwrap(), Ok(5));

        // New sender, send message, and receive message.
        let sender = receiver.new_sender().unwrap();
        sender.send(10);
        assert_eq!(receiver.recv().unwrap().now_or_never().unwrap(), Ok(10));

        // New sender, send message, and try-receive message.
        let sender = receiver.new_sender().unwrap();
        sender.send(15);
        assert_eq!(receiver.try_recv(), Ok(Some(15)));
    }

    #[test]
    fn no_senders() {
        // New receiver without a sender, can't receive a message.
        let mut receiver = Receiver::<u8>::new();
        assert_eq!(receiver.recv().unwrap_err(), NoSender);
        assert_eq!(receiver.try_recv(), Err(RecvError::NoSender));

        // New sender, send message, and receive message.
        let sender = receiver.new_sender().unwrap();
        sender.send(5);
        assert_eq!(receiver.recv().unwrap().now_or_never().unwrap(), Ok(5));

        // New sender, send message, and receive message.
        let sender = receiver.new_sender().unwrap();
        sender.send(10);
        assert_eq!(receiver.try_recv(), Ok(Some(10)));

        // Sent and received a value above, so it has no sender again.
        assert_eq!(receiver.recv().unwrap_err(), NoSender);
        assert_eq!(receiver.try_recv(), Err(RecvError::NoSender));
    }

    #[test]
    fn two_senders() {
        // New receiver.
        let mut receiver = Receiver::<u8>::new();

        // New sender.
        let sender = receiver.new_sender().unwrap();

        // Cannot get second sender.
        assert!(receiver.new_sender().is_none());

        // Send message and receive message.
        sender.send(5);
        assert_eq!(receiver.recv().unwrap().now_or_never().unwrap(), Ok(5));

        // Can get a sender again now that the first sender sent a message and we received it.
        let _sender = receiver.new_sender().unwrap();
    }

    #[test]
    fn sender_drop() {
        // New receiver.
        let mut receiver = Receiver::<u8>::new();

        // New sender, drop sender, and receive message tells us that the sender was dropped.
        let sender = receiver.new_sender().unwrap();
        drop(sender);
        assert_eq!(
            receiver.recv().unwrap().now_or_never().unwrap(),
            Err(SenderDropped),
        );
        assert_eq!(receiver.recv().unwrap_err(), NoSender);

        // New sender, drop sender, and receive message tells us that the sender was dropped.
        let sender = receiver.new_sender().unwrap();
        drop(sender);
        assert_eq!(receiver.try_recv(), Err(RecvError::SenderDropped));
        assert_eq!(receiver.try_recv(), Err(RecvError::NoSender));

        // New sender, send message, and receive message.
        let sender = receiver.new_sender().unwrap();
        sender.send(5);
        assert_eq!(receiver.recv().unwrap().now_or_never().unwrap(), Ok(5));

        // New sender, send message, and receive message.
        let sender = receiver.new_sender().unwrap();
        sender.send(10);
        assert_eq!(receiver.try_recv(), Ok(Some(10)));
    }

    #[test]
    fn sender_guarantee() {
        // New receiver.
        let mut receiver = Receiver::<u8>::new();

        // We don't have a sender, so we should get a guarantee.
        let _sender_guarantee_1 = receiver.guarantee_new_sender().unwrap();

        // Due to non-lexical lifetimes, rust allows us to get another guarantee.
        // But this is okay because it won't allow us to use the first again.
        let sender_guarantee_2 = receiver.guarantee_new_sender().unwrap();

        let _sender = sender_guarantee_2.into_sender();

        // Now that we have a sender, we can't get a new guarantee.
        assert!(receiver.guarantee_new_sender().is_none());
    }

    #[test]
    fn test_async() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            // Have time advance automatically.
            rt.spawn({
                let rt = rt.clone();
                async move { rt.advance_until_stalled().await }
            })
            .unwrap();

            let mut receiver = Receiver::<u8>::new();

            // In a new task, wait 100 ms and then send the message.
            rt.spawn({
                let sender = receiver.new_sender().unwrap();
                let rt = rt.clone();
                async move {
                    rt.sleep(Duration::from_millis(100)).await;
                    sender.send(10);
                }
            })
            .unwrap();

            // Wait for the message to arrive.
            assert_eq!(receiver.recv().unwrap().await, Ok(10));

            // In a new task, wait 2000 ms and then send the message.
            rt.spawn({
                let sender = receiver.new_sender().unwrap();
                let rt = rt.clone();
                async move {
                    rt.sleep(Duration::from_millis(2000)).await;
                    sender.send(20);
                }
            })
            .unwrap();

            // Wait for the message to arrive.
            assert_eq!(receiver.recv().unwrap().await, Ok(20));

            // In a new task, wait 2000 ms and then drop the sender.
            rt.spawn({
                let sender = receiver.new_sender().unwrap();
                let rt = rt.clone();
                async move {
                    rt.sleep(Duration::from_millis(2000)).await;
                    drop(sender);
                }
            })
            .unwrap();

            // Wait to be notified that the sender was dropped.
            assert_eq!(receiver.recv().unwrap().await, Err(SenderDropped));
        });
    }
}
