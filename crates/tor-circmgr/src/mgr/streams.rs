//! Stream utilities to help implement
//! [`AbstractCircMgr`](`super::AbstractCircMgr.`)

use futures::stream::{Fuse, FusedStream, Stream, StreamExt};
use futures::task::{Context, Poll};
use pin_project::pin_project;
use std::pin::Pin;

/// Enumeration to indicate which of two streams provided a result.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum Source {
    /// Indicates a result coming from the left (preferred) stream.
    Left,
    /// Indicates a result coming from the right (secondary) stream.
    Right,
}

/// A stream returned by [`select_biased`]
///
/// See that function for more documentation.
#[pin_project]
pub(super) struct SelectBiased<S, T> {
    /// Preferred underlying stream.
    ///
    /// When results are available from both streams, we always yield them
    /// from this one.  When this stream is exhausted, the `SelectBiased`
    /// is exhausted too.
    #[pin]
    left: Fuse<S>,
    /// Secondary underlying stream.
    #[pin]
    right: Fuse<T>,
}

/// Combine two instances of [`Stream`] into one.
///
/// This function is similar to [`futures::stream::select`], but differs
/// in that it treats the two underlying streams asymmetrically.  Specifically:
///
///  * Each result is labeled with [`Source::Left`] or
///    [`Source::Right`], depending on which of the two streams it came
///    from.
///  * If both the "left" and the "right" stream are ready, we always
///    prefer the left stream.
///  * We stop iterating over this stream when there are no more
///    results on the left stream, regardless whether the right stream
///    is exhausted or not.
///
/// # Future plans
///
/// This might need a better name, especially if we use it anywhere
/// else.
///
/// If we do expose this function, we might want to split up the ways in
/// which it differs from `select`.
pub(super) fn select_biased<S, T>(left: S, right: T) -> SelectBiased<S, T>
where
    S: Stream,
    T: Stream<Item = S::Item>,
{
    SelectBiased {
        left: left.fuse(),
        right: right.fuse(),
    }
}

impl<S, T> FusedStream for SelectBiased<S, T>
where
    S: Stream,
    T: Stream<Item = S::Item>,
{
    fn is_terminated(&self) -> bool {
        // We're done if the left stream is done, whether the right stream
        // is done or not.
        self.left.is_terminated()
    }
}

impl<S, T> Stream for SelectBiased<S, T>
where
    S: Stream,
    T: Stream<Item = S::Item>,
{
    type Item = (Source, S::Item);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        // We always check the left stream first.
        match this.left.poll_next(cx) {
            Poll::Ready(Some(val)) => {
                // The left stream has an item: yield it.
                return Poll::Ready(Some((Source::Left, val)));
            }
            Poll::Ready(None) => {
                // The left stream is exhausted: don't even check the right.
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        // The left stream is pending: see whether the right stream has
        // anything to say.
        match this.right.poll_next(cx) {
            Poll::Ready(Some(val)) => {
                // The right stream has an item: yield it.
                Poll::Ready(Some((Source::Right, val)))
            }
            _ => {
                // The right stream is exhausted or pending: in either case,
                // we need to wait.
                Poll::Pending
            }
        }
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
    use futures_await_test::async_test;

    // Tests where only elements from the left stream should be yielded.
    #[async_test]
    async fn left_only() {
        use futures::stream::iter;
        use Source::Left as L;
        // If there's nothing in the right stream, we just yield the left.
        let left = vec![1_usize, 2, 3];
        let right = vec![];

        let s = select_biased(iter(left), iter(right));
        let result: Vec<_> = s.collect().await;
        assert_eq!(result, vec![(L, 1_usize), (L, 2), (L, 3)]);

        // If the left runs out (which this will), we don't yield anything
        // from the right.
        let left = vec![1_usize, 2, 3];
        let right = vec![4, 5, 6];
        let s = select_biased(iter(left), iter(right));
        let result: Vec<_> = s.collect().await;
        assert_eq!(result, vec![(L, 1_usize), (L, 2), (L, 3)]);

        // The same thing happens if the left stream is completely empty!
        let left = vec![];
        let right = vec![4_usize, 5, 6];
        let s = select_biased(iter(left), iter(right));
        let result: Vec<_> = s.collect().await;
        assert_eq!(result, vec![]);
    }

    // Tests where only elements from the right stream should be yielded.
    #[async_test]
    async fn right_only() {
        use futures::stream::{iter, pending};
        use Source::Right as R;

        // Try a forever-pending stream for the left hand side.
        let left = pending();
        let right = vec![4_usize, 5, 6];
        let mut s = select_biased(left, iter(right));
        assert_eq!(s.next().await, Some((R, 4)));
        assert_eq!(s.next().await, Some((R, 5)));
        assert_eq!(s.next().await, Some((R, 6)));
    }

    // Tests where we can find elements from both streams.
    #[async_test]
    async fn multiplex() {
        use futures::SinkExt;
        use Source::{Left as L, Right as R};

        let (mut snd_l, rcv_l) = futures::channel::mpsc::channel(5);
        let (mut snd_r, rcv_r) = futures::channel::mpsc::channel(5);
        let mut s = select_biased(rcv_l, rcv_r);

        snd_l.send(1_usize).await.unwrap();
        snd_r.send(4_usize).await.unwrap();
        snd_l.send(2_usize).await.unwrap();

        assert_eq!(s.next().await, Some((L, 1)));
        assert_eq!(s.next().await, Some((L, 2)));
        assert_eq!(s.next().await, Some((R, 4)));

        snd_r.send(5_usize).await.unwrap();
        snd_l.send(3_usize).await.unwrap();

        assert!(!s.is_terminated());
        drop(snd_r);

        assert_eq!(s.next().await, Some((L, 3)));
        assert_eq!(s.next().await, Some((R, 5)));

        drop(snd_l);
        assert_eq!(s.next().await, None);

        assert!(s.is_terminated());
    }
}
