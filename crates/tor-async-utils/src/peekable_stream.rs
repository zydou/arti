//! Provides utilities for peeking at items in [`futures::Stream`].
//!
//! # Stability of peeked values
//!
//! Implementors of this trait guarantee that a peeked `Poll::Ready` result is
//! required to remain at the head of the stream until
//! [`futures::Stream::poll_next`] or another method requiring a `&mut`
//! reference (and documented to potentially change the head of the stream) is
//! called. e.g. a caller holding a `Pin<&mut Self>` that observes a Ready value
//! via [`PeekableStream::poll_peek`] is guaranteed to observe that same value
//! again on a subsequent call to [`PeekableStream::poll_peek`],
//! [`futures::Stream::poll_next`], etc.
//!
//! This property must not be relied up on to prove *soundness*, but can be
//! relied upon to prove correctness.

use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that provides the ability to peek at the next available item.
///
/// This provides an alternative to interfaces and data structure that would
/// otherwise want a [`futures::stream::Peekable<S>`], which can potentially
/// avoid multiple layers of buffering where one would do.
///
/// # Tasks, waking, and calling context
///
/// These methods should be called by the task that is reading from the stream.
/// If they are called by another task, the reading task would miss
/// notifications.
pub trait PeekableStream: futures::Stream {
    /// Poll for an item to be ready, and then inspect it.
    ///
    /// Equivalent to [`futures::stream::Peekable::poll_peek`].
    ///
    /// Guarantees that a returned `Ready` result is stable (See "Stability ..." in
    /// [`crate::peekable_stream`]).
    ///
    /// Should be called only by the task that is reading the stream (see
    /// "Tasks ..." in [`PeekableStream`]).
    fn poll_peek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<&<Self as futures::Stream>::Item>> {
        self.poll_peek_mut(cx).map(|x| x.map(|x| &*x))
    }

    /// Poll for an item to be ready, and then inspect it.
    ///
    /// Equivalent to [`futures::stream::Peekable::poll_peek_mut`].
    ///
    /// Guarantees that a returned `Ready` result is stable (See "Stability" in
    /// [`crate::peekable_stream`]).
    ///
    /// Should be called only by the task that is reading the stream (see
    /// "Tasks ..." in [`PeekableStream`]).
    fn poll_peek_mut(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<&mut <Self as futures::Stream>::Item>>;
}

impl<S> PeekableStream for futures::stream::Peekable<S>
where
    S: futures::Stream,
{
    fn poll_peek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<&<Self as futures::Stream>::Item>> {
        self.poll_peek(cx)
    }

    fn poll_peek_mut(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<&mut <Self as futures::Stream>::Item>> {
        self.poll_peek_mut(cx)
    }
}

/// A stream that supports peeking without perturbing any registered waker.
///
/// # Tasks, waking, and calling context
///
/// These functions do not register the current task to be woken when an item
/// becomes available on the stream, and ensure that the most recent task that
/// was already registered remains so (or is woken if there was an item ready).
///
/// Therefore, avoiding calling (only) these functions from the task that is
/// reading from the stream, since they will not cause the current task to be
/// woken when an item arrives.
///
/// Conversely, you *may* call these function in *other* tasks, without
/// disturbing the task which is waiting for input.
pub trait UnobtrusivePeekableStream: futures::Stream {
    /// Peek at the next available value, while not losing a previously
    /// registered waker.
    ///
    /// Guarantees that a returned `Some` result is stable (See "Stability" in
    /// [`crate::peekable_stream`]).
    ///
    /// Does not register the current task to be notified when an item becomes
    /// available (see "Tasks ..." in [`UnobtrusivePeekableStream`]).
    ///
    /// The caller of `unobtrusive_peek` can't distinguish between a pending and terminated stream.
    // To address this we could return value in a `Poll` but normally returning `Poll::Pending`
    // implies a promise of future wakeup, which is precisely contrary to this function's purpose.
    // We could address that with imprecations in the docs but people don't always read docs.
    // We could invent a new type, but that seems quite heavyweight.
    // We'll cross this bridge when we have a requirement for this feature.
    fn unobtrusive_peek(self: Pin<&mut Self>) -> Option<&<Self as futures::Stream>::Item> {
        self.unobtrusive_peek_mut().map(|x| &*x)
    }

    /// Peek at the next available value, while not losing a previously
    /// registered waker.
    ///
    /// Guarantees that a returned `Some` result is stable (See "Stability" in
    /// [`crate::peekable_stream`]).
    ///
    /// Does not register the current task to be notified when an item becomes
    /// available (see "Tasks ..." in [`UnobtrusivePeekableStream`]).
    ///
    /// The caller of `unobtrusive_peek_mut` can't distinguish between a pending and terminated stream.
    // (See comment on `unobtrusive_peek` about options if we need a caller to be able to do that.)
    fn unobtrusive_peek_mut(self: Pin<&mut Self>) -> Option<&mut <Self as futures::Stream>::Item>;
}
