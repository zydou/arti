//! [`StreamUnobtrusivePeeker`]
//!
//! The memory tracker needs a way to look at the next item of a stream
//! (if there is one, or there can immediately be one),
//! *without* getting involved with the async tasks.
//
// TODO at some point this should probably be in tor-async-utils

#![allow(dead_code)] // TODO #351

use crate::internal_prelude::*;

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
// TODO: is this the best name?  We intend, probably:
//     struct StreamUnobtrusivePeeker
//     trait StreamUnobtrusivePeekable
//     trait StreamPeekable (impl for StreamUnobtrusivePeeker and futures::stream::Peekable)
//
// Searching a thesaurus produced these suggested words:
//     unobtrusive
//     subtle
//     discreet
//     inconspicuous
//     cautious
//     furtive
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
#[derive(Debug)]
#[pin_project(project = PeekerProj)]
pub(crate) struct StreamUnobtrusivePeeker<S: Stream> {
    /// An item that we have peeked.
    ///
    /// In some sense, represents the last value from a poll or peek of `inner`.
    /// We use a custom type because `Poll<Option<...>>`
    /// is quite confusing in practice and makes the code inscrutable.
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
    pub(crate) fn new(inner: S) -> Self {
        StreamUnobtrusivePeeker {
            buffered: None,
            poll_waker: None,
            inner: Some(inner),
        }
    }
}

impl<S: Stream> StreamUnobtrusivePeeker<S> {
    /// See if there is an item ready to read, and inspect it if so
    ///
    /// # Tasks, waking, and calling context
    ///
    /// Avoid calling this function from the task that is reading from the stream:
    /// This method is sync, and therefore when it returns `None` it
    /// does **not** arrange for the calling task to be woken
    /// when an item arrives (i.e. when `unobtrusive_peek` would start to return `Some`).
    ///
    /// Conversely, you *may* call this function in *other* tasks,
    /// without disturbing the task which is waiting for input.
    pub(crate) fn unobtrusive_peek<'s>(mut self: Pin<&'s mut Self>) -> Option<&'s S::Item> {
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

            let waker_buf;
            let waker = if let Some(waker) = self_.poll_waker.as_ref() {
                waker
            } else {
                waker_buf = Waker::from(Arc::new(NoopWaker));
                &waker_buf
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

        self.project().buffered.as_ref()
    }

    /// Poll for an item to be ready, and then inspect it
    ///
    /// Equivalent to [`futures::stream::Peekable::poll_peek`].
    ///
    /// # Tasks, waking, and calling context
    ///
    /// This should be called by the task that is reading from the stream.
    /// If it is called by another task, the reading task would miss notifications.
    //
    // This ^ docs section is triplicated for poll_peek, poll_peek_mut, and peek
    pub(crate) fn poll_peek<'s>(
        self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<&'s S::Item>> {
        self.impl_poll_next_or_peek(cx, |buffered| buffered.as_ref())
    }

    /// Poll for an item to be ready, and then inspect it mutably
    ///
    /// Equivalent to [`futures::stream::Peekable::poll_peek_mut`].
    ///
    /// # Tasks, waking, and calling context
    ///
    /// This should be called by the task that is reading from the stream.
    /// If it is called by another task, the reading task would miss notifications.
    //
    // This ^ docs section is triplicated for poll_peek, poll_peek_mut, and peek
    #[allow(dead_code)] // TODO remove this allow if and when we make this module public
    pub(crate) fn poll_peek_mut<'s>(
        self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<&'s mut S::Item>> {
        self.impl_poll_next_or_peek(cx, |buffered| buffered.as_mut())
    }

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
    // TODO this should be a trait method ?
    // TODO should there be peek_mut ?
    #[allow(dead_code)] // TODO remove this allow if and when we make this module public
    pub(crate) fn peek<'s>(self: Pin<&'s mut Self>) -> PeekFuture<'s, S> {
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
#[derive(Educe)]
#[educe(Debug(bound("StreamUnobtrusivePeeker<S>: Debug")))]
#[must_use = "peek() return a Future, which does nothing unless awaited"]
pub(crate) struct PeekFuture<'s, S: Stream> {
    /// The underlying `StreamUnobtrusivePeeker`.
    ///
    /// `Some` until we have returned `Ready`, then `None`.
    /// See comment in `poll`.
    peeker: Option<Pin<&'s mut StreamUnobtrusivePeeker<S>>>,
}

impl<'s, S: Stream> Future for PeekFuture<'s, S> {
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
