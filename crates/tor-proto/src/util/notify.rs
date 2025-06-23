//! An async notification channel.
//!
//! This channel allows one task to notify another. No data is passed from the sender to receiver. A
//! [`NotifySender`] may send multiple notifications and a [`NotifyReceiver`] may receive multiple
//! notifications. Notifications will be coalesced, so if a `NotifySender` sends multiple
//! notifications, the `NotifyReceiver` may or may not receive all of the notifications. If there
//! are multiple `NotifyReceiver`s, each will be notified.
//!
//! An optional type can be attached to the `NotifySender` and `NotifyReceiver` to identify the
//! purpose of the notifications and to provide type checking.

// TODO(arti#534): we expect to use this for flow control, so we should remove this later
#![cfg_attr(not(test), expect(dead_code))]

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use educe::Educe;
use futures::stream::{Fuse, FusedStream};
use futures::{Stream, StreamExt};
use pin_project::pin_project;
use postage::watch;

/// A [`NotifySender`] which can notify [`NotifyReceiver`]s.
///
/// See the [module documentation](self) for details.
#[derive(Educe)]
#[educe(Debug)]
pub(crate) struct NotifySender<T = ()> {
    /// The "sender" we use to implement the async behaviour.
    sender: watch::Sender<()>,
    /// Allows the user to optionally attach a type marker to identify the purpose of the
    /// notifications.
    #[educe(Debug(ignore))]
    _marker: PhantomData<fn() -> T>,
}

/// A [`NotifyReceiver`] which can receive notifications from a [`NotifySender`].
///
/// See the [module documentation](self) for details.
// We should theoretically be able to impl `Clone`, but `Fuse` does not implement `Clone` so we'd
// have to implement something manually. If we do want `Clone` in the future, be careful about the
// initial state of the new `NotifyReceiver` (see the `try_recv` in `NotifySender::subscribe`).
#[derive(Educe)]
#[educe(Debug)]
#[pin_project]
pub(crate) struct NotifyReceiver<T = ()> {
    /// The "receiver" we use to implement the async behaviour.
    #[pin]
    receiver: Fuse<watch::Receiver<()>>,
    /// Allows the user to optionally attach a type marker to identify the purpose of the
    /// notifications.
    #[educe(Debug(ignore))]
    _marker: PhantomData<fn() -> T>,
}

impl NotifySender {
    /// Create a new untyped [`NotifySender`].
    pub(crate) fn new() -> Self {
        Self::new_typed()
    }
}

impl<T> NotifySender<T> {
    /// Create a new typed [`NotifySender<T>`].
    pub(crate) fn new_typed() -> Self {
        let (sender, _receiver) = watch::channel();
        Self {
            sender,
            _marker: Default::default(),
        }
    }

    /// Notify all [`NotifyReceiver`]s.
    pub(crate) fn notify(&mut self) {
        // from `postage::watch::Sender`:
        // > Mutably borrows the contained value, blocking the channel while the borrow is held.
        // > After the borrow is released, receivers will be notified of a new value.
        self.sender.borrow_mut();
    }

    /// Create a new [`NotifyReceiver`] for this [`NotifySender`].
    ///
    /// A new `NotifyReceiver` will not see any past notifications.
    pub(crate) fn subscribe(&mut self) -> NotifyReceiver<T> {
        let mut receiver = self.sender.subscribe();

        // a `watch::Receiver` will always return the existing status of the `watch::Sender` as the
        // first stream item, so we need to recv and discard it so that this `NotifyReceiver` begins
        // in the "pending" state
        use postage::stream::Stream as PostageStream;
        use postage::stream::TryRecvError;
        assert_eq!(PostageStream::try_recv(&mut receiver), Ok(()));
        assert_eq!(
            PostageStream::try_recv(&mut receiver),
            Err(TryRecvError::Pending),
        );

        NotifyReceiver {
            receiver: receiver.fuse(),
            _marker: Default::default(),
        }
    }
}

impl<T> Stream for NotifyReceiver<T> {
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().receiver.poll_next(cx)
    }
}

// the `NotifyReceiver` stores a `Fuse`
impl<T> FusedStream for NotifyReceiver<T> {
    fn is_terminated(&self) -> bool {
        self.receiver.is_terminated()
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use futures::FutureExt;

    #[test]
    fn notify() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let mut sender = NotifySender::new();
            let mut receiver = sender.subscribe();

            // receivers should initially wait for a notification
            assert_eq!(receiver.next().now_or_never(), None);
            assert_eq!(receiver.next().now_or_never(), None);

            sender.notify();

            // we should receive a single notification
            assert_eq!(receiver.next().now_or_never(), Some(Some(())));
            assert_eq!(receiver.next().now_or_never(), None);

            sender.notify();
            sender.notify();
            sender.notify();

            // we should still receive a single notification
            assert_eq!(receiver.next().now_or_never(), Some(Some(())));
            assert_eq!(receiver.next().now_or_never(), None);

            sender.notify();
            drop(sender);

            // we should see the last notification, and then since we dropped the sender, the stream
            // should indicate that it's finished
            assert_eq!(receiver.next().now_or_never(), Some(Some(())));
            assert_eq!(receiver.next().now_or_never(), Some(None));
            assert_eq!(receiver.next().now_or_never(), Some(None));
        });
    }

    #[test]
    fn notify_multiple_receivers() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let mut sender = NotifySender::new();
            let mut receiver_1 = sender.subscribe();
            let mut receiver_2 = sender.subscribe();

            sender.notify();

            let mut receiver_3 = sender.subscribe();

            // first two receivers should each receive a notification
            assert_eq!(receiver_1.next().now_or_never(), Some(Some(())));
            assert_eq!(receiver_2.next().now_or_never(), Some(Some(())));

            // third receiver should not receive a notification since it was created after the
            // notification was generated
            assert_eq!(receiver_3.next().now_or_never(), None);
        });
    }
}
