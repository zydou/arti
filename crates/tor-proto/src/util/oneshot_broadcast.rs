//! A oneshot broadcast channel.
//!
//! The motivation for this channel type was to allow multiple
//! receivers to either wait for something to finish,
//! or to have an inexpensive method of checking if it has finished.
//!
//! See [`channel()`].

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::FusedFuture;
use futures::FutureExt as _;
use oneshot_fused_workaround as oneshot;

/// A cloneable receiver for a oneshot broadcast channel.
///
/// Warning: You must not both clone this receiver and poll the new receiver
/// after this receiver has already been polled to completion
/// (`futures::future::Shared` panics if you do this).
#[derive(Clone, Debug)]
pub(crate) struct Receiver<T> {
    /// Reads this value to know whether the [`Sender`] has sent its message or been dropped.
    ready: Arc<AtomicBool>,
    /// The shared receiver.
    receiver: futures::future::Shared<oneshot::Receiver<T>>,
}

/// A sender for a oneshot broadcast channel.
#[derive(Debug)]
pub(crate) struct Sender<T> {
    /// Writes `true` to this value when it its message has been sent or has been dropped.
    ready: Arc<AtomicBool>,
    /// The sender.
    sender: Option<oneshot::Sender<T>>,
}

impl<T> Future for Receiver<T>
where
    T: Clone,
{
    // note: this exposes the error type of `oneshot::Receiver`,
    // but this is fine since this module is non-pub
    type Output = <oneshot::Receiver<T> as Future>::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.receiver).poll(cx)
    }
}

impl<T> FusedFuture for Receiver<T>
where
    T: Clone,
{
    fn is_terminated(&self) -> bool {
        self.receiver.is_terminated()
    }
}

impl<T> Receiver<T> {
    /// Returns `true` if the receiver will be ready to poll.
    ///
    /// If `true`, it means that the paired [`Sender`] either sent its value,
    /// or was dropped.
    pub(crate) fn is_ready(&self) -> bool {
        // note: relaxed since we're not synchronizing memory accesses
        self.ready.load(Ordering::Relaxed)
    }
}

impl<T> std::ops::Drop for Sender<T> {
    fn drop(&mut self) {
        // we're about to drop the sender, so the receiver will become ready

        // note: relaxed since we're not synchronizing memory accesses
        self.ready.store(true, Ordering::Relaxed);
    }
}

impl<T> Sender<T> {
    /// Send the message to all receivers.
    ///
    /// If all receivers were dropped,
    /// then this will return the message as an `Err`.
    // this isn't currently used, but we may want it in the future if we want to return a status
    // message to anything waiting for a `crate::channel::Channel` to close
    #[allow(dead_code)]
    pub(crate) fn send(mut self, message: T) -> Result<(), T> {
        // We're about to drop the sender, so regardless of if the message gets sent or not,
        // the receiver will become ready.
        //
        // We could wait and let the drop handler set this to `true` for us, but setting it first
        // means that there's no race condition where a `receiver.await` gets the message and checks
        // `receiver.is_ready()` which briefly returns `false`.

        // note: relaxed since we're not synchronizing memory accesses
        self.ready.store(true, Ordering::Relaxed);

        // there's no way for `sender` to be `None` here, and if it is we definitely don't want to
        // hide the error
        self.sender
            .take()
            .expect("oneshot broadcast sender is missing")
            .send(message)
    }
}

/// Creates a oneshot broadcast channel.
///
/// The message [sent](Sender::send) by the [`Sender`] will be received by each [`Receiver`].
/// If the `Sender` is dropped before sending a message,
/// each receiver will return an error.
pub(crate) fn channel<T: Clone>() -> (Sender<T>, Receiver<T>) {
    let (tx, rx) = oneshot::channel();
    let rx = rx.shared();
    let ready = Arc::new(AtomicBool::new(false));

    let tx = Sender {
        ready: Arc::clone(&ready),
        sender: Some(tx),
    };
    let rx = Receiver {
        ready,
        receiver: rx,
    };

    (tx, rx)
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn standard_use_case() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx1) = channel();

            let rx2 = rx1.clone();
            tx.send(0_u32).unwrap();
            assert_eq!(rx1.await, Ok(0));
            assert_eq!(rx2.await, Ok(0));
        });
    }

    #[test]
    fn immediate_drop() {
        let (_tx, _rx) = channel::<()>();

        let (tx, rx) = channel::<()>();
        drop(tx);
        drop(rx);

        let (tx, rx) = channel::<()>();
        drop(rx);
        drop(tx);
    }

    #[test]
    fn clone_after_send() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx1) = channel();

            tx.send(0_u32).unwrap();
            let rx2 = rx1.clone();
            assert_eq!(rx1.await, Ok(0));
            assert_eq!(rx2.await, Ok(0));
        });
    }

    #[test]
    fn drop_sender() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx1) = channel::<u32>();

            let rx2 = rx1.clone();
            drop(tx);
            let rx3 = rx1.clone();
            assert!(rx1.await.is_err());
            assert!(rx2.await.is_err());
            assert!(rx3.await.is_err());
        });
    }

    #[test]
    fn drop_one_receiver() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx1) = channel();

            let rx2 = rx1.clone();
            drop(rx1);
            tx.send(0_u32).unwrap();
            assert_eq!(rx2.await, Ok(0));
        });
    }

    #[test]
    fn drop_all_receivers() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx1) = channel();

            let rx2 = rx1.clone();
            drop(rx1);
            drop(rx2);
            assert_eq!(tx.send(0_u32), Err(0_u32));
        });
    }

    #[test]
    fn is_ready_after_send() {
        let (tx, rx1) = channel::<u32>();
        assert!(!rx1.is_ready());
        let rx2 = rx1.clone();
        assert!(!rx2.is_ready());

        tx.send(0_u32).unwrap();

        assert!(rx1.is_ready());
        assert!(rx2.is_ready());

        let rx3 = rx1.clone();
        assert!(rx3.is_ready());
    }

    #[test]
    fn is_ready_after_drop() {
        let (tx, rx1) = channel::<u32>();
        assert!(!rx1.is_ready());
        let rx2 = rx1.clone();
        assert!(!rx2.is_ready());

        drop(tx);

        assert!(rx1.is_ready());
        assert!(rx2.is_ready());

        let rx3 = rx1.clone();
        assert!(rx3.is_ready());
    }
}
