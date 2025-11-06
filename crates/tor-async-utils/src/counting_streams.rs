//! A facility for an MPSC channel that counts the number of outstanding entries on the channel.
//
// (Tokio makes this possible by default, but we don't require tokio.  Crossbeam channels also allow
// this, but they aren't async, and they're MPMC. If a future version of the
// `futures` crate adds this functionality, we can use that instead. )

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::ready,
    task::{Context, Poll},
};

use futures::{Stream, sink::Sink, stream::FusedStream};
use pin_project::pin_project;

/// A wrapper around an arbitrary [`Sink`], to count the items inserted.
#[derive(Clone, Debug)]
#[pin_project]
pub struct CountingSink<S> {
    /// The inner sink whose items we're counting.
    #[pin]
    inner: S,
    /// A shared counter for items inserted into the channel
    ///
    /// We add 1 every time we enqueue an item.
    count: Arc<AtomicUsize>,
}

/// A wrapper around an arbitrary [`Stream`], to count the items inserted.
#[derive(Clone, Debug)]
#[pin_project]
pub struct CountingStream<S> {
    /// The inner stream whose items we're counting.
    #[pin]
    inner: S,
    /// A shared counter for items inserted into the channel.
    ///
    /// We remove 1 every time we dequeue an item.
    count: Arc<AtomicUsize>,
}

impl<T, S: Sink<T>> Sink<T> for CountingSink<S> {
    type Error = S::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let self_ = self.project();
        let r = self_.inner.start_send(item);
        if r.is_ok() {
            // We successfully sent an item, so we increment the counter.
            //
            // Using `Relaxed` ensures that the operation is atomic, but does not guarantee its
            // order with respect to operations on other locations.
            self_.count.fetch_add(1, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

impl<S: Stream> Stream for CountingStream<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let self_ = self.project();
        let next = ready!(self_.inner.poll_next(cx));
        if next.is_some() {
            // We got an item, so we'll decrement the counter.
            //
            // See note above about "Relaxed" ordering.
            self_.count.fetch_sub(1, Ordering::Relaxed);
        }
        Poll::Ready(next)
    }
}

impl<S: FusedStream> FusedStream for CountingStream<S> {
    fn is_terminated(&self) -> bool {
        self.inner.is_terminated()
    }
}

impl<S> CountingStream<S> {
    /// Return an approximate count of the number of items currently on this channel.
    ///
    /// This count is necessarily approximate because the count can be changed by any of this
    /// channel's Senders or Receivers between when the caller
    /// gets the count and when the caller uses the count.
    pub fn approx_count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Return a reference to the inner stream.
    ///
    /// If the stream has interior mutability, the caller must take care
    /// not to do anything with the stream that would invalidate the current counter.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Return a mutable reference to the inner stream.
    ///
    /// If the stream has interior mutability, the caller must take care
    /// not to do anything with the stream that would invalidate the current counter.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S> CountingSink<S> {
    /// Return an approximate count of the number of items currently on this channel.
    ///
    /// This count is necessarily approximate because the count can be changed by any of this
    /// channel's Senders or Receivers between when the caller
    /// gets the count and when the caller uses the count.
    pub fn approx_count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Return a reference to the inner sink.
    ///
    /// If the sink has interior mutability, the caller must take care
    /// not to do anything with the sink that would invalidate the current counter.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Return a mutable reference to the inner sink.
    ///
    /// If the sink has interior mutability, the caller must take care
    /// not to do anything with the sink that would invalidate the current counter.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

/// Wrap a [`Sink`]/[`Stream`] pair into a [`CountingSink`] and [`CountingStream`] pair.
///
/// # Correctness
///
/// The sink and the stream should match and form a channel:
/// items sent on the sink should be received from the stream.
///
/// There should be no other handles in use for adding or removing items from the channel.
///
/// If these requirements aren't met, then the counts returned by the sink and stream
/// will not be accurate.
pub fn channel<T, U>(tx: T, rx: U) -> (CountingSink<T>, CountingStream<U>) {
    let count = Arc::new(AtomicUsize::new(0));
    let new_tx = CountingSink {
        inner: tx,
        count: Arc::clone(&count),
    };
    let new_rx = CountingStream { inner: rx, count };
    (new_tx, new_rx)
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

    use futures::{SinkExt as _, StreamExt as _};

    #[test]
    fn send_only_onetask() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (tx, rx) = futures::channel::mpsc::unbounded::<usize>();
            let (mut tx, rx) = super::channel(tx, rx);
            for n in 1..10 {
                tx.send(n).await.unwrap();
                assert_eq!(tx.approx_count(), n);
                assert_eq!(rx.approx_count(), n);
            }
        });
    }

    #[test]
    fn send_only_twotasks() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (tx, rx) = futures::channel::mpsc::unbounded::<usize>();
            let (mut tx, rx) = super::channel(tx, rx);

            let mut tx2 = tx.clone();
            let j1 = rt.spawn_join("thread1", async move {
                for n in 1..=10 {
                    tx.send(n).await.unwrap();
                    assert!(tx.approx_count() >= n);
                }
            });

            let j2 = rt.spawn_join("thread2", async move {
                for n in 1..=10 {
                    tx2.send(n).await.unwrap();
                    assert!(tx2.approx_count() >= n);
                }
            });
            j1.await;
            j2.await;
            assert_eq!(rx.approx_count(), 20);
        });
    }

    #[test]
    fn send_and_receive() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (tx, rx) = futures::channel::mpsc::unbounded::<usize>();
            let (mut tx, mut rx) = super::channel(tx, rx);
            const MAX: usize = 10000;

            let mut tx2 = tx.clone();
            let j1 = rt.spawn_join("thread1", async move {
                for n in 1..=MAX {
                    tx.send(n).await.unwrap();
                }
            });

            let j2 = rt.spawn_join("thread2", async move {
                for n in 1..=MAX {
                    tx2.send(n).await.unwrap();
                }
            });

            let j3 = rt.spawn_join("receiver", async move {
                let mut total = 0;
                while let Some(x) = rx.next().await {
                    total += x; // spot check
                    let count = rx.approx_count();
                    assert!(count <= MAX * 2);
                }
                assert_eq!(total, MAX * (MAX + 1)); // two senders, so no "/2".
                rx
            });

            j1.await;
            j2.await;
            let rx = j3.await;
            assert_eq!(rx.approx_count(), 0);
        });
    }
}
