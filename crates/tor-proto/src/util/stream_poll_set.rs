//! Provides [`StreamPollSet`]

// So that we can declare these things as if they were in their own crate.
#![allow(unreachable_pub)]

use std::{
    collections::{hash_map, BTreeMap, HashMap},
    future::Future,
    hash::Hash,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{task::noop_waker_ref, FutureExt, StreamExt as _};
use tor_async_utils::peekable_stream::PeekableStream;

use crate::util::keyed_futures_unordered::KeyedFuturesUnordered;

/// A future that wraps a [`PeekableStream`], and yields the stream
/// when an item becomes available.
struct PeekableReady<S> {
    /// The stream to be peeked.
    stream: Option<S>,
}

impl<S> PeekableReady<S> {
    /// Create a new [`PeekableReady`].
    fn new(st: S) -> Self {
        Self { stream: Some(st) }
    }

    /// Get a reference to the inner `S`.
    ///
    /// None if the future has already completed.
    fn get_ref(&self) -> Option<&S> {
        self.stream.as_ref()
    }

    /// Get a mut reference to the inner `S`.
    ///
    /// None if the future has already completed.
    fn get_mut(&mut self) -> Option<&mut S> {
        self.stream.as_mut()
    }

    /// Unwrap inner `S`.
    ///
    /// None if the future has already completed.
    fn into_inner(self) -> Option<S> {
        self.stream
    }
}

impl<S> Future for PeekableReady<S>
where
    S: PeekableStream + Unpin,
{
    type Output = S;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(stream) = &mut self.stream else {
            panic!("Polled completed future");
        };
        match Pin::new(stream).poll_peek(cx) {
            Poll::Ready(_) => Poll::Ready(self.stream.take().expect("Stream disappeared")),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Manages a dynamic set of [`futures::Stream`] with associated keys and
/// priorities.
///
/// Notable features:
///
/// * Prioritization: streams have an associated priority, and ready-streams are
///   iterated over in ascending priority order.
/// * Efficient polling: an unready stream won't be polled again until it's
///   ready or exhausted (e.g. a corresponding [`futures::Sink`] is written-to or
///   dropped). A ready stream won't be polled again until the ready item has been
///   removed.
pub struct StreamPollSet<K, P, S>
where
    S: PeekableStream + Unpin,
{
    /// Priority for each stream in the set.
    // We keep the priority for each stream here instead of bundling it together
    // with the stream, so that the priority can easily be changed even while a
    // future waiting on the stream is still pending (e.g. to support rescaling
    // priorities for EWMA).
    // Invariants:
    // * Every key is also present in exactly one of `ready_values` or `pending_streams`.
    priorities: HashMap<K, P>,
    /// Streams that have a result ready, in ascending order by priority.
    // Invariants:
    // * Keys are a (non-strict) subset of those in `priorities`.
    ready_streams: BTreeMap<(P, K), S>,
    /// Streams for which we're still waiting for the next result.
    // Invariants:
    // * Keys are a (non-strict) subset of those in `priorities`.
    pending_streams: KeyedFuturesUnordered<K, PeekableReady<S>>,
}

impl<K, P, S> StreamPollSet<K, P, S>
where
    K: Ord + Hash + Clone + Send + Sync + 'static,
    S: PeekableStream + Unpin,
    P: Ord + Clone,
{
    /// Create a new, empty, `StreamPollSet`.
    pub fn new() -> Self {
        Self {
            priorities: Default::default(),
            ready_streams: Default::default(),
            pending_streams: KeyedFuturesUnordered::new(),
        }
    }

    /// Insert a `stream`, with an associated `key` and `priority`.
    ///
    /// If the `key` is already in use, the parameters are returned without altering `self`.
    // To *replace* an existing key, we'd need to cancel any pending future and
    // ensure that the cancellation is processed before inserting the new key, to
    // ensure we don't assign a value from the previous key to the new key's
    // stream.
    pub fn try_insert(
        &mut self,
        key: K,
        priority: P,
        stream: S,
    ) -> Result<(), KeyAlreadyInsertedError<K, P, S>> {
        let hash_map::Entry::Vacant(v) = self.priorities.entry(key.clone()) else {
            // We already have an entry for this key.
            return Err(KeyAlreadyInsertedError {
                key,
                priority,
                stream,
            });
        };
        self.pending_streams
            .try_insert(key, PeekableReady::new(stream))
            // By `pending_streams` invariant that keys are a subset of those in
            // `priorities`.
            .unwrap_or_else(|_| panic!("Unexpected duplicate key"));
        v.insert(priority);
        Ok(())
    }

    /// Remove the entry for `key`, if any. This is the key, priority, buffered
    /// poll_next result, and stream.
    pub fn remove(&mut self, key: &K) -> Option<(K, P, S)> {
        let priority = self.priorities.remove(key)?;
        if let Some((key, fut)) = self.pending_streams.remove(key) {
            // Validate `priorities` invariant that keys are also present in exactly one of
            // `pending_streams` and `ready_values`.
            debug_assert!(!self
                .ready_streams
                .contains_key(&(priority.clone(), key.clone())));
            let stream = fut
                .into_inner()
                // We know the future hasn't completed, so the stream should be present.
                .expect("Missing stream");
            Some((key, priority, stream))
        } else {
            let ((_priority, key), stream) = self
                .ready_streams
                .remove_entry(&(priority.clone(), key.clone()))
                // By
                // * `pending_streams` invariant that keys are also present in
                // exactly one of `pending_streams` and `ready_values`.
                // * validated above that the key was in `pending_streams`, and
                // not in `ready_values`.
                .expect("Unexpectedly no value for key");
            Some((key, priority, stream))
        }
    }

    /// Polls streams that are ready to be polled, and returns an iterator over all streams
    /// for which we have a buffered `Poll::Ready` result, in ascending priority order.
    ///
    /// Registers the provided [`Context`] to be woken when
    /// any of the internal streams that weren't ready in the previous call to
    /// this method (and therefore wouldn't have appeared in the iterator
    /// results) become potentially ready (based on when the inner stream wakes
    /// the `Context` provided to its own `poll_next`).
    ///
    /// The same restrictions apply as for [`Self::stream_mut`].  e.g. do not
    /// directly call [`PeekableStream::poll_peek`] to see what item is
    /// available on the stream; instead use [`Self::peek_mut`]. (Or
    /// [`tor_async_utils::peekable_stream::UnobtrusivePeekableStream`] if
    /// implemented for the stream).
    ///
    /// This method does *not* drain ready items. `Some` values can be removed
    /// with [`Self::take_ready_value_and_reprioritize`]. `None` values can only
    /// be removed by removing the whole stream with [`Self::remove`].
    ///
    /// This API is meant to allow callers to find the first stream (in priority
    /// order) that is ready, and that the caller is able to process now. i.e.
    /// it's specifically to support the use-case where external factors may
    /// prevent the processing of some streams but not others.
    ///
    /// Example:
    ///
    /// ```nocompile
    /// # // We need the `nocompile` since `StreamPollSet` is non-pub.
    /// # // TODO: take away the nocompile if we make this pub or implement some
    /// # // workaround to expose it to doc-tests.
    /// # type Key=u64;
    /// # type Value=u64;
    /// # type Priority=u64;
    /// # type MyStream=Box<dyn futures::Stream<Item=Value> + Unpin>;
    /// # fn can_process(key: &Key, val: &Value) -> bool { true }
    /// # fn process(val: Value) { }
    /// # fn new_priority(priority: &Priority) -> Priority { *priority }
    /// fn process_a_ready_stream(sps: &mut StreamPollSet<Key, Value, Priority, MyStream>, cx: &mut std::task::Context) -> std::task::Poll<()> {
    ///   let mut iter = sps.poll_ready_iter(cx);
    ///   while let Some((key, priority, stream)) = iter.next() {
    ///     let Some(value) = stream.unobtrusive_peek(Pin::new(stream)) else {
    ///        // Stream exhausted. Remove the stream. We have to drop the iterator
    ///        // first, though, so that we can mutate.
    ///        let key = *key;
    ///        drop(iter);
    ///        sps.remove(&key).unwrap();
    ///        return std::task::Poll::Ready(());
    ///     };
    ///     if can_process(key, value) {
    ///        let key = *key;
    ///        let priority = new_priority(priority);
    ///        drop(iter);
    ///        let (_old_priority, value) = sps.take_ready_value_and_reprioritize(&key, priority).unwrap();
    ///        process(value);
    ///        return std::task::Poll::Ready(());
    ///     }
    ///   }
    ///   return std::task::Poll::Pending;
    /// }
    /// ```
    // In the current implementation we *could* actually permit the caller to
    // `poll_peek` a stream that we know is ready. But this may change as the
    // impl evolves further, and it's probably better to blanket disallow it
    // than to have complex rules for the caller about when it's ok.
    //
    // TODO: It would be nice if the returned iterator supported additional
    // actions, e.g. allowing the user to consume the iterator and take and
    // reprioritize the inner value, but this is tricky.
    //
    // I've sketched out a working "cursor" that holds the current position (K, P)
    // and a &mut StreamPollSet. This can't implement the Iterator interface though
    // since it needs to borrow from self. I was able to implement an Iterator-*like* interface
    // that does borrow from self, but this doesn't compose well. e.g. in StreamMap
    // we can't use the same technique again since the object would need a mut reference to the
    // StreamMap *and* to this inner cursor object, which is illegal.
    pub fn poll_ready_iter_mut<'a>(
        &'a mut self,
        cx: &mut Context,
    ) -> impl Iterator<Item = (&'a K, &'a P, &'a mut S)> + 'a {
        // First poll for ready streams
        while let Poll::Ready(Some((key, stream))) = self.pending_streams.poll_next_unpin(cx) {
            let priority = self
                .priorities
                .get(&key)
                // By `pending_streams` invariant that all keys are also in `priorities`.
                .expect("Missing priority");
            let prev = self.ready_streams.insert((priority.clone(), key), stream);
            assert!(prev.is_none());
        }
        self.ready_streams.iter_mut().map(|((p, k), s)| (k, p, s))
    }

    /// If the stream for `key` has `Some(value)` ready, take that value and set the
    /// priority for it to `new_priority`.
    ///
    /// This method doesn't register a waker with the polled stream. Use
    /// `poll_ready_iter` to ensure streams make progress.
    ///
    /// If the key doesn't exist, the stream isn't ready, or the stream's value
    /// is `None` (indicating the end of the stream), this function returns
    /// `None` without mutating anything.
    ///
    /// Ended streams should be removed using [`Self::remove`].
    pub fn take_ready_value_and_reprioritize(
        &mut self,
        key: &K,
        new_priority: P,
    ) -> Option<(P, S::Item)> {
        // Get the priority entry, but don't replace until the lookup in ready_streams is confirmed.
        let hash_map::Entry::Occupied(mut priority_entry) = self.priorities.entry(key.clone())
        else {
            // Key isn't present at all.
            return None;
        };
        let priority_mut = priority_entry.get_mut();
        let Some(((_p, key), mut stream)) = self
            .ready_streams
            .remove_entry(&(priority_mut.clone(), key.clone()))
        else {
            // This stream isn't in the ready list.
            return None;
        };
        match Pin::new(&mut stream)
            .poll_peek(&mut Context::from_waker(&futures::task::noop_waker()))
        {
            Poll::Ready(Some(_val)) => (), // Stream is ready, and has an item. Proceed.
            Poll::Ready(None) => {
                // Stream is ready, but is terminated.
                // Leave in place and return `None`.
                return None;
            }
            Poll::Pending => {
                // Stream wasn't actually ready, despite being on the ready
                // list. This should be impossible by the stability guarantees
                // of `PeekableStream` and our own internal logic, but we can
                // recover.
                tracing::error!("Stream unexpectedly unready");
                self.pending_streams
                    .try_insert(key.clone(), PeekableReady::new(stream))
                    // By invariant on `priorities` that keys are in exactly one of the ready or pending lists.
                    .unwrap_or_else(|_| {
                        unreachable!("Key unexpectedly in both ready and unready list")
                    });
                return None;
            }
        }
        let Some(Some(val)) = stream.next().now_or_never() else {
            panic!("Polling stream returned a different result than peeking");
        };
        let prev_priority = std::mem::replace(priority_mut, new_priority);
        self.pending_streams
            .try_insert(key, PeekableReady::new(stream))
            // We verified above that the key wasn't present in `priorities`,
            // and `pending_streams` has the invariant that its keys are a
            // subset of those in `priorities`.
            .unwrap_or_else(|_| panic!("Unexpected pending stream entry"));
        Some((prev_priority, val))
    }

    /// Get a mut reference to a ready value for key `key`, if one exists.
    ///
    /// This method doesn't poll the internal streams. Use `poll_ready_iter` to
    /// ensure streams make progress.
    // This will be used for packing and fragmentation, to take part of a DATA message.
    #[allow(unused)]
    pub fn peek_mut<'a>(&'a mut self, key: &K) -> Option<Poll<Option<&'a mut S::Item>>> {
        let priority = self.priorities.get(key)?;
        let Some(peekable) = self.ready_streams.get_mut(&(priority.clone(), key.clone())) else {
            return Some(Poll::Pending);
        };
        // We don't have a waker registered here, so we can just use the noop waker.
        // TODO: Create a mut future for `PeekableStream`.
        Some(Pin::new(peekable).poll_peek_mut(&mut Context::from_waker(noop_waker_ref())))
    }

    /// Get a reference to the stream for `key`.
    ///
    /// The same restrictions apply as for [`Self::stream_mut`] (e.g. using
    /// interior mutability).
    #[allow(dead_code)]
    pub fn stream(&self, key: &K) -> Option<&S> {
        if let Some(s) = self.pending_streams.get(key) {
            let s = s.get_ref();
            // Stream must be present since it's still pending.
            debug_assert!(s.is_some(), "Unexpected missing pending stream");
            return s;
        }
        let priority = self.priorities.get(key)?;
        self.ready_streams.get(&(priority.clone(), key.clone()))
    }

    /// Get a mut reference to the stream for `key`.
    ///
    /// Polling the stream through this reference, or otherwise causing its
    /// registered `Waker` to be removed without waking it, will result in
    /// unspecified (but not unsound) behavior.
    ///
    /// This is mostly intended for accessing non-`Stream` functionality of the stream
    /// object, though it *is* permitted to mutate it in a way that the stream becomes
    /// ready (potentially removing and waking its registered Waker(s)).
    //
    // In particular:
    // * Polling a stream in the pending list and getting a Pending result
    //   will overwrite our Waker, resulting in us not polling it again.
    // * Doing so with a stream on the pending list and getting a Ready result
    //   might be ok if it had already woken our waker. Otoh it could potentially
    //   result in our waker never getting woken, and hence us not polling it again.
    // * Doing so with a stream on the ready list should actually be ok, since
    //   we don't have a registered waker, and don't do our own buffering.
    pub fn stream_mut(&mut self, key: &K) -> Option<&mut S> {
        if let Some(s) = self.pending_streams.get_mut(key) {
            let s = s.get_mut();
            // Stream must be present since it's still pending.
            debug_assert!(s.is_some(), "Unexpected missing pending stream");
            return s;
        }
        let priority = self.priorities.get(key)?;
        self.ready_streams.get_mut(&(priority.clone(), key.clone()))
    }

    /// Number of streams managed by this object.
    pub fn len(&self) -> usize {
        self.priorities.len()
    }
}

/// Error returned by [`StreamPollSet::try_insert`].
#[derive(Debug, thiserror::Error)]
#[allow(clippy::exhaustive_structs)]
pub struct KeyAlreadyInsertedError<K, P, S> {
    /// Key that caller tried to insert.
    #[allow(dead_code)]
    pub key: K,
    /// Priority that caller tried to insert.
    #[allow(dead_code)]
    pub priority: P,
    /// Stream that caller tried to insert.
    #[allow(dead_code)]
    pub stream: S,
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

    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        task::Poll,
    };

    use futures::{stream::Peekable, SinkExt as _};
    use pin_project::pin_project;
    use tor_rtmock::MockRuntime;

    use super::*;

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    struct Key(u64);

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
    struct Priority(u64);

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    struct Value(u64);

    /// Test stream that we can directly manipulate and examine.
    #[derive(Debug)]
    #[pin_project]
    struct VecDequeStream<T> {
        // Ready items.
        vec: VecDeque<T>,
        // Whether any more items will be written.
        closed: bool,
        // Registered waker.
        waker: Option<std::task::Waker>,
    }
    impl<T> VecDequeStream<T> {
        fn new_open<I: IntoIterator<Item = T>>(values: I) -> Self {
            Self {
                vec: VecDeque::from_iter(values),
                waker: None,
                closed: false,
            }
        }
        fn new_closed<I: IntoIterator<Item = T>>(values: I) -> Self {
            Self {
                vec: VecDeque::from_iter(values),
                waker: None,
                closed: true,
            }
        }
        fn push(&mut self, value: T) {
            assert!(!self.closed);
            self.vec.push_back(value);
            if let Some(waker) = self.waker.take() {
                waker.wake();
            }
        }
    }
    impl<T> futures::Stream for VecDequeStream<T> {
        type Item = T;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            if let Some(val) = self.as_mut().vec.pop_front() {
                Poll::Ready(Some(val))
            } else if self.as_mut().closed {
                // No more items coming.
                Poll::Ready(None)
            } else {
                self.as_mut().waker.replace(cx.waker().clone());
                Poll::Pending
            }
        }
    }
    impl<T> PeekableStream for VecDequeStream<T> {
        fn poll_peek_mut(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<&mut <Self as futures::Stream>::Item>> {
            let s = self.project();
            if let Some(val) = s.vec.front_mut() {
                Poll::Ready(Some(val))
            } else if *s.closed {
                // No more items coming.
                Poll::Ready(None)
            } else {
                s.waker.replace(cx.waker().clone());
                Poll::Pending
            }
        }
    }
    impl<T> std::cmp::PartialEq for VecDequeStream<T>
    where
        T: std::cmp::PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            // Ignore waker, which isn't comparable
            self.vec == other.vec && self.closed == other.closed
        }
    }
    impl<T> std::cmp::Eq for VecDequeStream<T> where T: std::cmp::Eq {}

    type TestStream = VecDequeStream<Value>;

    #[test]
    fn test_empty() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Priority, TestStream>::new();
            assert_eq!(pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(), vec![]);
            Poll::Ready(())
        }));
    }

    #[test]
    fn test_one_pending() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Priority, TestStream>::new();
            pollset
                .try_insert(Key(0), Priority(0), TestStream::new_open([]))
                .unwrap();
            assert_eq!(pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(), vec![]);
            Poll::Ready(())
        }));
    }

    #[test]
    fn test_one_ready() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Priority, TestStream>::new();
            pollset
                .try_insert(
                    Key(0),
                    Priority(0),
                    TestStream::new_closed([Value(1), Value(2)]),
                )
                .unwrap();

            // We only see the first value of the one ready stream.
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![(
                    &Key(0),
                    &Priority(0),
                    &mut TestStream::new_closed([Value(1), Value(2)])
                )],
            );

            // Same result, the same value is still at the head of the stream..
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![(
                    &Key(0),
                    &Priority(0),
                    &mut TestStream::new_closed([Value(1), Value(2)])
                )]
            );

            // Take the head of the stream.
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(0), Priority(1)),
                Some((Priority(0), Value(1)))
            );

            // Should see the next value, with the new priority.
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![(
                    &Key(0),
                    &Priority(1),
                    &mut TestStream::new_closed([Value(2)])
                )]
            );

            // Take again.
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(0), Priority(2)),
                Some((Priority(1), Value(2)))
            );

            // Should see end-of-stream.
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![(&Key(0), &Priority(2), &mut TestStream::new_closed([]))]
            );

            // Remove the now-ended stream.
            assert_eq!(
                pollset.remove(&Key(0)),
                Some((Key(0), Priority(2), TestStream::new_closed([])))
            );

            // Should now be empty.
            assert_eq!(pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(), vec![]);

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_round_robin() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Priority, TestStream>::new();
            pollset
                .try_insert(
                    Key(0),
                    Priority(0),
                    TestStream::new_closed([Value(1), Value(2)]),
                )
                .unwrap();
            pollset
                .try_insert(
                    Key(1),
                    Priority(1),
                    TestStream::new_closed([Value(3), Value(4)]),
                )
                .unwrap();

            // Should see both ready streams, in priority order.
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![
                    (
                        &Key(0),
                        &Priority(0),
                        &mut TestStream::new_closed([Value(1), Value(2)])
                    ),
                    (
                        &Key(1),
                        &Priority(1),
                        &mut TestStream::new_closed([Value(3), Value(4)])
                    ),
                ]
            );

            // Take from the first stream and send it to the back via priority assignment.
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(0), Priority(2)),
                Some((Priority(0), Value(1)))
            );

            // Should see both ready streams, in the new priority order.
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![
                    (
                        &Key(1),
                        &Priority(1),
                        &mut TestStream::new_closed([Value(3), Value(4)])
                    ),
                    (
                        &Key(0),
                        &Priority(2),
                        &mut TestStream::new_closed([Value(2)])
                    ),
                ]
            );

            // Keep going ...
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(1), Priority(3)),
                Some((Priority(1), Value(3)))
            );
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![
                    (
                        &Key(0),
                        &Priority(2),
                        &mut TestStream::new_closed([Value(2)])
                    ),
                    (
                        &Key(1),
                        &Priority(3),
                        &mut TestStream::new_closed([Value(4)])
                    ),
                ]
            );
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(0), Priority(4)),
                Some((Priority(2), Value(2)))
            );
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![
                    (
                        &Key(1),
                        &Priority(3),
                        &mut TestStream::new_closed([Value(4)])
                    ),
                    (&Key(0), &Priority(4), &mut TestStream::new_closed([])),
                ]
            );
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(1), Priority(5)),
                Some((Priority(3), Value(4)))
            );
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![
                    (&Key(0), &Priority(4), &mut TestStream::new_closed([])),
                    (&Key(1), &Priority(5), &mut TestStream::new_closed([])),
                ]
            );

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_remove_and_reuse_key() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Priority, TestStream>::new();
            pollset
                .try_insert(
                    Key(0),
                    Priority(0),
                    TestStream::new_closed([Value(1), Value(2)]),
                )
                .unwrap();
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![(
                    &Key(0),
                    &Priority(0),
                    &mut TestStream::new_closed([Value(1), Value(2)])
                ),]
            );
            assert_eq!(
                pollset.remove(&Key(0)),
                Some((
                    Key(0),
                    Priority(0),
                    TestStream::new_closed([Value(1), Value(2)])
                ))
            );
            pollset
                .try_insert(
                    Key(0),
                    Priority(1),
                    TestStream::new_closed([Value(3), Value(4)]),
                )
                .unwrap();
            // Ensure we see the ready value in the new stream, and *not* anything from the previous stream at that key.
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![(
                    &Key(0),
                    &Priority(1),
                    &mut TestStream::new_closed([Value(3), Value(4)])
                ),]
            );
            Poll::Ready(())
        }));
    }

    #[test]
    fn get_ready_stream() {
        futures::executor::block_on(futures::future::poll_fn(|_ctx| {
            let mut pollset = StreamPollSet::<Key, Priority, VecDequeStream<Value>>::new();
            pollset
                .try_insert(Key(0), Priority(0), VecDequeStream::new_open([Value(1)]))
                .unwrap();
            assert_eq!(pollset.stream(&Key(0)).unwrap().vec[0], Value(1));
            Poll::Ready(())
        }));
    }

    #[test]
    fn get_pending_stream() {
        futures::executor::block_on(futures::future::poll_fn(|_ctx| {
            let mut pollset = StreamPollSet::<Key, Priority, VecDequeStream<Value>>::new();
            pollset
                .try_insert(Key(0), Priority(0), VecDequeStream::new_open([]))
                .unwrap();
            assert!(pollset.stream(&Key(0)).unwrap().vec.is_empty());
            Poll::Ready(())
        }));
    }

    #[test]
    fn mutate_pending_stream() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Priority, VecDequeStream<Value>>::new();
            pollset
                .try_insert(Key(0), Priority(0), VecDequeStream::new_open([]))
                .unwrap();
            assert_eq!(pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(), vec![]);

            // This should cause the stream to become ready.
            pollset.stream_mut(&Key(0)).unwrap().push(Value(0));

            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![(
                    &Key(0),
                    &Priority(0),
                    &mut VecDequeStream::new_open([Value(0)])
                ),]
            );

            Poll::Ready(())
        }));
    }

    #[test]
    fn mutate_ready_stream() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Priority, VecDequeStream<Value>>::new();
            pollset
                .try_insert(Key(0), Priority(0), VecDequeStream::new_open([Value(0)]))
                .unwrap();
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![(
                    &Key(0),
                    &Priority(0),
                    &mut VecDequeStream::new_open([Value(0)])
                ),]
            );

            pollset.stream_mut(&Key(0)).unwrap().push(Value(1));

            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![(
                    &Key(0),
                    &Priority(0),
                    &mut VecDequeStream::new_open([Value(0), Value(1)])
                ),]
            );

            // Consume the value that was there.
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(0), Priority(0)),
                Some((Priority(0), Value(0)))
            );

            // We should now see the value we added.
            assert_eq!(
                pollset.poll_ready_iter_mut(ctx).collect::<Vec<_>>(),
                vec![(
                    &Key(0),
                    &Priority(0),
                    &mut VecDequeStream::new_open([Value(1)])
                ),]
            );

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_async() {
        MockRuntime::test_with_various(|rt| async move {
            let mut pollset = StreamPollSet::<
                Key,
                Priority,
                Peekable<futures::channel::mpsc::Receiver<Value>>,
            >::new();

            // Create 2 mpsc channels, bounded so that we can exercise back-pressure.
            // These are analogous to Tor streams.
            for streami in 1..=2 {
                let (mut send, recv) = futures::channel::mpsc::channel::<Value>(2);
                pollset
                    .try_insert(Key(streami), Priority(streami), recv.peekable())
                    .unwrap();
                rt.spawn_identified(format!("stream{streami}"), async move {
                    for val in 0..10 {
                        send.send(Value(val * streami)).await.unwrap();
                    }
                });
            }

            let output = Arc::new(Mutex::new(Vec::new()));

            rt.spawn_identified("mux", {
                let output = output.clone();
                async move {
                    loop {
                        let (key, priority, value) = futures::future::poll_fn(|ctx| {
                            match pollset.poll_ready_iter_mut(ctx).next() {
                                Some((key, priority, stream)) => {
                                    let Poll::Ready(value) = Pin::new(stream).poll_peek(ctx) else {
                                        panic!("poll_ready_iter_mut returned non-ready stream")
                                    };
                                    Poll::Ready((*key, *priority, value.copied()))
                                }
                                // No streams ready, but there could be more items coming.
                                // The current `ctx` should be registered to wake us
                                // if and when there are.
                                None => Poll::Pending,
                            }
                        })
                        .await;
                        if let Some(value) = value {
                            // Take the value, and haphazardly set priority to push this stream "back".
                            pollset
                                .take_ready_value_and_reprioritize(&key, Priority(priority.0 + 10))
                                .unwrap();
                            output.lock().unwrap().push((key, value));
                        } else {
                            // Stream ended. Remove it.
                            let _ = pollset.remove(&key).unwrap();
                        }
                    }
                }
            });

            rt.advance_until_stalled().await;

            let output = output.lock().unwrap();

            // We can't predict exactly how the stream values will be
            // interleaved, but we should get all items from each stream, with
            // correct order within each stream.
            for streami in 1..=2 {
                let expected = (0..10).map(|val| Value(val * streami)).collect::<Vec<_>>();
                let actual = output
                    .iter()
                    .filter_map(|(k, v)| (k == &Key(streami)).then_some(*v))
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected);
            }
        });
    }
}
