//! [`StreamUnobtrusivePeeker`]
//!
//! The memory tracker needs a way to look at the next item of a stream
//! (if there is one, or there can immediately be one),
//! *without* getting involved with the async tasks.

use educe::Educe;
use futures::Stream;
use futures::stream::FusedStream;
use pin_project::pin_project;

use crate::peekable_stream::{PeekableStream, UnobtrusivePeekableStream};

use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Poll::*, Waker};

/// Wraps [`Stream`] and provides `\[poll_]peek` and `unobtrusive_peek`
///
/// [`unobtrusive_peek`](StreamUnobtrusivePeeker::unobtrusive_peek)
/// is callable in sync contexts, outside the reading task.
///
/// Like [`futures::stream::Peekable`],
/// this has an async `peek` method, and `poll_peek`,
/// for use from the task that is also reading (via the [`Stream`] impl).
/// But, that type doesn't have `unobtrusive_peek`.
///
/// One way to conceptualise this is that `StreamUnobtrusivePeeker` is dual-ported:
/// the two sets of APIs, while provided on the same type,
/// are typically called from different contexts.
//
// It wasn't particularly easy to think of a good name for this type.
// We intend, probably:
//     struct StreamUnobtrusivePeeker
//     trait StreamUnobtrusivePeekable
//     trait StreamPeekable (impl for StreamUnobtrusivePeeker and futures::stream::Peekable)
//
// Searching a thesaurus produced these suggested words:
//     unobtrusive subtle discreet inconspicuous cautious furtive
// Asking in MR review also suggested
//     quick
//
// It's awkward because "peek" already has significant connotations of not disturbing things.
// That's why it was used in Iterator::peek.
//
// But when we translate this into async context,
// we have the poll_peek method on futures::stream::Peekable,
// which doesn't remove items from the stream,
// but *does* *wait* for items and therefore engages with the async context,
// and therefore involves *mutating* the Peekable (to store the new waker).
//
// Now we end up needing a word for an *even less disturbing* kind of interaction.
//
// `quick` (and synonyms) isn't quite right either because it's not necessarily faster,
// and certainly not more performant.
#[derive(Debug)]
#[pin_project(project = PeekerProj)]
pub struct StreamUnobtrusivePeeker<S: Stream> {
    /// An item that we have peeked.
    ///
    /// (If we peeked EOF, that's represented by `None` in inner.)
    buffered: Option<S::Item>,

    /// The `Waker` from the last time we were polled and returned `Pending`
    ///
    /// "polled" includes any of our `poll_` methods
    /// but *not* `unobtrusive_peek`.
    ///
    /// `None` if we haven't been polled, or the last poll returned `Ready`.
    poll_waker: Option<Waker>,

    /// The inner stream
    ///
    /// `None if it has yielded `None` meaning EOF.  We don't require S: FusedStream.
    #[pin]
    inner: Option<S>,
}

impl<S: Stream> StreamUnobtrusivePeeker<S> {
    /// Create a new `StreamUnobtrusivePeeker` from a `Stream`
    pub fn new(inner: S) -> Self {
        StreamUnobtrusivePeeker {
            buffered: None,
            poll_waker: None,
            inner: Some(inner),
        }
    }
}

impl<S: Stream> UnobtrusivePeekableStream for StreamUnobtrusivePeeker<S> {
    fn unobtrusive_peek_mut<'s>(mut self: Pin<&'s mut Self>) -> Option<&'s mut S::Item> {
        #[allow(clippy::question_mark)] // We use explicit control flow here for clarity
        if self.as_mut().project().buffered.is_none() {
            // We don't have a buffered item, but the stream may have an item available.
            // We must poll it to find out.
            //
            // We need to pass a Context to poll_next.
            // inner may store this context, replacing one provided via poll_*.
            //
            // Despite that, we need to make sure that wakeups will happen as expected.
            // To achieve this we have retained a copy of the caller's Waker.
            //
            // When a future or stream returns Pending, it proposes to wake `waker`
            // when it wants to be polled again.
            //
            // We uphold that promise by
            // - only returning Pending from our poll methods if inner also returned Pending
            // - when one of our poll methods returns Pending, saving the caller-supplied
            //   waker, so that we can make the intermediate poll call here.
            //
            // If the inner poll returns Ready, inner no longer guarantees to wake anyone.
            // In principle, if our user is waiting (we returned Pending),
            // then inner ought to have called `wake` on the caller's `Waker`.
            // But I don't think we can guarantee that an executor won't defer a wakeup,
            // and respond to a dropped Waker by cancelling that wakeup;
            // or to put it another way, the wakeup might be "in flight" on entry,
            // but the call to inner's poll_next returning Ready
            // might somehow "cancel" the wakeup.
            //
            // So just to be sure, if we get a Ready here, we wake the stored waker.

            let mut self_ = self.as_mut().project();

            let Some(inner) = self_.inner.as_mut().as_pin_mut() else {
                return None;
            };

            let waker = if let Some(waker) = self_.poll_waker.as_ref() {
                waker
            } else {
                Waker::noop()
            };

            match inner.poll_next(&mut Context::from_waker(waker)) {
                Pending => {}
                Ready(item_or_eof) => {
                    if let Some(waker) = self_.poll_waker.take() {
                        waker.wake();
                    }
                    match item_or_eof {
                        None => self_.inner.set(None),
                        Some(item) => *self_.buffered = Some(item),
                    }
                }
            };
        }

        self.project().buffered.as_mut()
    }
}

impl<S: Stream> PeekableStream for StreamUnobtrusivePeeker<S> {
    fn poll_peek<'s>(self: Pin<&'s mut Self>, cx: &mut Context<'_>) -> Poll<Option<&'s S::Item>> {
        self.impl_poll_next_or_peek(cx, |buffered| buffered.as_ref())
    }

    fn poll_peek_mut<'s>(
        self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<&'s mut S::Item>> {
        self.impl_poll_next_or_peek(cx, |buffered| buffered.as_mut())
    }
}

impl<S: Stream> StreamUnobtrusivePeeker<S> {
    /// Implementation of `poll_{peek,next}`
    ///
    /// This takes care of
    ///   * examining the state of our buffer, and polling inner if needed
    ///   * ensuring that we store a waker, if needed
    ///   * dealing with some borrowck awkwardness
    ///
    /// The `Ready` value is always calculated from `buffer`.
    /// `return_value_obtainer` is called only if we are going to return `Ready`.
    /// It's given `buffer` and should either:
    ///   * [`take`](Option::take) the contained value (for `poll_next`)
    ///   * return a reference using [`Option::as_ref`] (for `poll_peek`)
    fn impl_poll_next_or_peek<'s, R: 's>(
        self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
        return_value_obtainer: impl FnOnce(&'s mut Option<S::Item>) -> Option<R>,
    ) -> Poll<Option<R>> {
        let mut self_ = self.project();
        let r = Self::next_or_peek_inner(&mut self_, cx);
        let r = r.map(|()| return_value_obtainer(self_.buffered));
        Self::return_from_poll(self_.poll_waker, cx, r)
    }

    /// Try to populate `buffer`, and calculate if we're `Ready`
    ///
    /// Returns `Ready` iff `poll_next` or `poll_peek` should return `Ready`.
    /// The actual `Ready` value (an `Option`) will be calculated later.
    fn next_or_peek_inner(self_: &mut PeekerProj<S>, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(_item) = self_.buffered.as_ref() {
            // `return_value_obtainer` will find `Some` in `buffered`;
            // overall, we'll return `Ready(Some(..))`.
            return Ready(());
        }
        let Some(inner) = self_.inner.as_mut().as_pin_mut() else {
            // `return_value_obtainer` will find `None` in `buffered`;
            // overall, we'll return `Ready(None)`, ie EOF.
            return Ready(());
        };
        match inner.poll_next(cx) {
            Ready(None) => {
                self_.inner.set(None);
                // `buffered` is `None`, still.
                // overall, we'll return `Ready(None)`, ie EOF.
                Ready(())
            }
            Ready(Some(item)) => {
                *self_.buffered = Some(item);
                // return_value_obtainer` will find `Some` in `buffered`
                Ready(())
            }
            Pending => {
                // `return_value_obtainer` won't be called.
                // overall, we'll return Pending
                Pending
            }
        }
    }

    /// Wait for an item to be ready, and then inspect it
    ///
    /// Equivalent to [`futures::stream::Peekable::peek`].
    ///
    /// # Tasks, waking, and calling context
    ///
    /// This should be called by the task that is reading from the stream.
    /// If it is called by another task, the reading task would miss notifications.
    //
    // This ^ docs section is triplicated for poll_peek, poll_peek_mut, and peek
    //
    // TODO this should be a method on the `PeekableStream` trait? Or a
    // `PeekableStreamExt` trait?
    // TODO should there be peek_mut ?
    #[allow(dead_code)] // TODO remove this allow if and when we make this module public
    pub fn peek(self: Pin<&mut Self>) -> PeekFuture<Self> {
        PeekFuture { peeker: Some(self) }
    }

    /// Return from a `poll_*` function, setting the stored waker appropriately
    ///
    /// Our `poll` functions always use this.
    /// The rule is that if a future returns `Pending`, it has stored the waker.
    fn return_from_poll<R>(
        poll_waker: &mut Option<Waker>,
        cx: &mut Context<'_>,
        r: Poll<R>,
    ) -> Poll<R> {
        *poll_waker = match &r {
            Ready(_) => {
                // No need to wake this task up any more.
                None
            }
            Pending => {
                // try_peek must use the same waker to poll later
                Some(cx.waker().clone())
            }
        };
        r
    }

    /// Obtain a raw reference to the inner stream
    ///
    /// ### Correctness!
    ///
    /// This method must be used with care!
    /// Whatever you do mustn't interfere with polling and peeking.
    /// Careless use can result in wrong behaviour including deadlocks.
    pub fn as_raw_inner_pin_mut<'s>(self: Pin<&'s mut Self>) -> Option<Pin<&'s mut S>> {
        self.project().inner.as_pin_mut()
    }
}

impl<S: Stream> Stream for StreamUnobtrusivePeeker<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.impl_poll_next_or_peek(cx, |buffered| buffered.take())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let buf = self.buffered.iter().count();
        let (imin, imax) = match &self.inner {
            Some(inner) => inner.size_hint(),
            None => (0, Some(0)),
        };
        (imin + buf, imax.and_then(|imap| imap.checked_add(buf)))
    }
}

impl<S: Stream> FusedStream for StreamUnobtrusivePeeker<S> {
    fn is_terminated(&self) -> bool {
        self.buffered.is_none() && self.inner.is_none()
    }
}

/// Future from [`StreamUnobtrusivePeeker::peek`]
// TODO: Move to tor_async_utils::peekable_stream.
#[derive(Educe)]
#[educe(Debug(bound("S: Debug")))]
#[must_use = "peek() return a Future, which does nothing unless awaited"]
pub struct PeekFuture<'s, S> {
    /// The underlying stream.
    ///
    /// `Some` until we have returned `Ready`, then `None`.
    /// See comment in `poll`.
    peeker: Option<Pin<&'s mut S>>,
}

impl<'s, S: PeekableStream> PeekFuture<'s, S> {
    /// Create a new `PeekFuture`.
    // TODO: replace with a trait method.
    pub fn new(stream: Pin<&'s mut S>) -> Self {
        Self {
            peeker: Some(stream),
        }
    }
}

impl<'s, S: PeekableStream> Future for PeekFuture<'s, S> {
    type Output = Option<&'s S::Item>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<&'s S::Item>> {
        let self_ = self.get_mut();
        let peeker = self_
            .peeker
            .as_mut()
            .expect("PeekFuture polled after Ready");
        match peeker.as_mut().poll_peek(cx) {
            Pending => return Pending,
            Ready(_y) => {
                // Ideally we would have returned `y` here, but it's borrowed from PeekFuture
                // not from the original StreamUnobtrusivePeeker, and there's no way
                // to get a value with the right lifetime.  (In non-async code,
                // this is usually handled by the special magic for reborrowing &mut.)
                //
                // So we must redo the poll, but this time consuming `peeker`,
                // which gets us the right lifetime.  That's why it has to be `Option`.
                // Because we own &mut ... Self, we know that repeating the poll
                // gives the same answer.
            }
        }
        let peeker = self_.peeker.take().expect("it was Some before!");
        let r = peeker.poll_peek(cx);
        assert!(r.is_ready(), "it was Ready before!");
        r
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use futures::channel::mpsc;
    use futures::{SinkExt as _, StreamExt as _};
    use std::pin::pin;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tor_rtcompat::SleepProvider as _;
    use tor_rtmock::MockRuntime;

    fn ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    #[test]
    fn wakeups() {
        MockRuntime::test_with_various(|rt| async move {
            let (mut tx, rx) = mpsc::unbounded();
            let ended = Arc::new(Mutex::new(false));

            rt.spawn_identified("rxr", {
                let rt = rt.clone();
                let ended = ended.clone();

                async move {
                    let rx = StreamUnobtrusivePeeker::new(rx);
                    let mut rx = pin!(rx);

                    let mut next = 0;
                    loop {
                        rt.sleep(ms(50)).await;
                        eprintln!("rx peek... ");
                        let peeked = rx.as_mut().unobtrusive_peek_mut();
                        eprintln!("rx peeked {peeked:?}");

                        if let Some(peeked) = peeked {
                            assert_eq!(*peeked, next);
                        }

                        rt.sleep(ms(50)).await;
                        eprintln!("rx next... ");
                        let eaten = rx.next().await;
                        eprintln!("rx eaten {eaten:?}");
                        if let Some(eaten) = eaten {
                            assert_eq!(eaten, next);
                            next += 1;
                        } else {
                            break;
                        }
                    }

                    *ended.lock().unwrap() = true;
                    eprintln!("rx ended");
                }
            });

            rt.spawn_identified("tx", {
                let rt = rt.clone();

                async move {
                    let mut numbers = 0..;
                    for wait in [125, 1, 125, 45, 1, 1, 1, 1000, 20, 1, 125, 125, 1000] {
                        eprintln!("tx sleep {wait}");
                        rt.sleep(ms(wait)).await;
                        let num = numbers.next().unwrap();
                        eprintln!("tx sending {num}");
                        tx.send(num).await.unwrap();
                    }

                    // This schedule arranges that, when we send EOF, the rx task
                    // has *peeked* rather than *polled* most recently,
                    // demonstrating that we can wake up the subsequent poll on EOF too.
                    eprintln!("tx final #1");
                    rt.sleep(ms(75)).await;
                    eprintln!("tx EOF");
                    drop(tx);
                    eprintln!("tx final #2");
                    rt.sleep(ms(10)).await;
                    assert!(!*ended.lock().unwrap());
                    eprintln!("tx final #3");
                    rt.sleep(ms(50)).await;
                    eprintln!("tx final #4");
                    assert!(*ended.lock().unwrap());
                }
            });

            rt.advance_until_stalled().await;
        });
    }

    #[test]
    fn poll_peek_paths() {
        MockRuntime::test_with_various(|rt| async move {
            let (mut tx, rx) = mpsc::unbounded();
            let ended = Arc::new(Mutex::new(false));

            rt.spawn_identified("rxr", {
                let rt = rt.clone();
                let ended = ended.clone();

                async move {
                    let rx = StreamUnobtrusivePeeker::new(rx);
                    let mut rx = pin!(rx);

                    while let Some(peeked) = rx.as_mut().peek().await.copied() {
                        eprintln!("rx peeked {peeked}");
                        let eaten = rx.next().await.unwrap();
                        eprintln!("rx eaten  {eaten}");
                        assert_eq!(peeked, eaten);
                        rt.sleep(ms(10)).await;
                        eprintln!("rx slept, peeking");
                    }
                    *ended.lock().unwrap() = true;
                    eprintln!("rx ended");
                }
            });

            rt.spawn_identified("tx", {
                let rt = rt.clone();

                async move {
                    let mut numbers = 0..;

                    // macro because we don't have proper async closures
                    macro_rules! send { {} => {
                        let num = numbers.next().unwrap();
                        eprintln!("tx send   {num}");
                        tx.send(num).await.unwrap();
                    } }

                    eprintln!("tx starting");
                    rt.sleep(ms(100)).await;
                    send!();
                    rt.sleep(ms(100)).await;
                    send!();
                    send!();
                    rt.sleep(ms(100)).await;
                    eprintln!("tx dropping");
                    drop(tx);
                    rt.sleep(ms(5)).await;
                    eprintln!("tx ending");
                    assert!(*ended.lock().unwrap());
                }
            });

            rt.advance_until_stalled().await;
        });
    }
}
