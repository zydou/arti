//! Provides [`StreamPollSet`]

// So that we can declare these things as if they were in their own crate.
#![allow(unreachable_pub)]

use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    hash::Hash,
    task::Poll,
};

use futures::stream::StreamExt;

use crate::util::keyed_futures_unordered::KeyedFuturesUnordered;

/// Manages a dynamic set of [`futures::Stream`] with associated keys and
/// priorities.
///
/// Notable features:
///
/// * Prioritization: streams have an associated priority, and ready-streams are
///   iterated over in ascending priority order.
/// * Streams are effectively "peekable". Internally reads and buffers at most
///   one item from each stream. These can be inspected prior to extracting the
///   item. e.g. calling code can use this to determine whether it's actually
///   ready to process a particular item before extracting it; if not it can be
///   left in place (providing back-pressure to a corresponding `Sink` when
///   applicable) and the next ready items from other streams can still be
///   serviced.
/// * Efficient polling: an unready stream won't be polled again until it's
///   ready or exhausted (e.g. a corresponding [`futures::Sink`] is written-to or
///   dropped). A ready stream won't be polled again until the ready item has been
///   removed.
pub struct StreamPollSet<K, V, P, S>
where
    S: futures::Stream + Unpin,
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
    ready_values: BTreeMap<(P, K), (Option<V>, S)>,
    /// Streams for which we're still waiting for the next result.
    // Invariants:
    // * Keys are a (non-strict) subset of those in `priorities`.
    pending_streams: KeyedFuturesUnordered<K, futures::stream::StreamFuture<S>>,
}

impl<K, V, P, S> StreamPollSet<K, V, P, S>
where
    K: Ord + Hash + Clone + Send + Sync + 'static,
    S: futures::Stream<Item = V> + Unpin,
    P: Ord + Clone,
{
    /// Create a new, empty, `StreamPollSet`.
    pub fn new() -> Self {
        Self {
            priorities: Default::default(),
            ready_values: Default::default(),
            pending_streams: KeyedFuturesUnordered::new(),
        }
    }

    /// Insert a `stream`, with an associated `key` and `priority`.
    ///
    /// If the `key` is already in use, the parameters are returned without altering `self`.
    // To *replace* an existing key, we'd need to cancel any pending future and
    // ensure that the cancelation is processed before inserting the new key, to
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
            .try_insert(key, stream.into_future())
            // By `pending_streams` invariant that keys are a subset of those in
            // `priorities`.
            .unwrap_or_else(|_| panic!("Unexpected duplicate key"));
        v.insert(priority);
        Ok(())
    }

    /// Remove the entry `key`.
    pub fn remove(&mut self, key: &K) -> Option<(K, P)> {
        let priority = self.priorities.remove(key)?;
        if let Some((key, _stream_fut)) = self.pending_streams.remove(key) {
            // Validate `pending_streams` invariant that keys are also present in exactly one of
            // `pending_streams` and `ready_values`.
            debug_assert!(!self
                .ready_values
                .contains_key(&(priority.clone(), key.clone())));

            Some((key, priority))
        } else {
            let ((_priority, key), _value) = self
                .ready_values
                .remove_entry(&(priority.clone(), key.clone()))
                // By
                // * `pending_streams` invariant that keys are also present in
                // exactly one of `pending_streams` and `ready_values`.
                // * validated above that the key was in `pending_streams`, and
                // not in `ready_values`.
                .expect("Unexpectedly no value for key");
            Some((key, priority))
        }
    }

    /// Polls streams that are ready to be polled, and returns an iterator over all streams
    /// for which we have a buffered `Poll::Ready` result, in ascending priority order.
    ///
    /// Registers the provided [`Context`][std::task::Context] to be woken when
    /// any of the internal streams that weren't ready in the previous call to
    /// this method (and therefore wouldn't have appeared in the iterator
    /// results) become potentially ready (based on when the inner stream wakes
    /// the `Context` provided to its own `poll_next`).
    ///
    /// The iterator values include the key, priority, and the buffered
    /// [`Poll::Ready`] result from calling [`futures::Stream::poll_next`]. i.e.
    /// either `Some` value read from the stream, or a `None` indicating that
    /// the `Stream` is exhausted.
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
    ///   while let Some((key, value, priority)) = iter.next() {
    ///     let Some(value) = value else {
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
    // TODO: Alternatively we could perhaps take some sort of "Future factory"
    // when inserting a stream that, given the next item in the stream, returns
    // a future that completes when that item can actually be processed. Or
    // maybe processes the item. That seems like a fair bit of generics and
    // ownership complexity though; deferring for the moment.
    //
    // TODO: It would be nice if the returned iterator supported additional
    // actions, e.g. allowing the user to consume the iterator and take and
    // reprioritize the inner value. I *think* we'd either need to make a
    // self-referential type holding both a reference and the inner iterator, or
    // else keep a copy of the current position `(K, P)` and do O(log(N))
    // lookups on each access, though.
    pub fn poll_ready_iter<'a>(
        &'a mut self,
        cx: &mut std::task::Context,
    ) -> impl Iterator<Item = (&'a K, Option<&'a V>, &'a P)> + 'a {
        // First poll for ready streams
        while let Poll::Ready(Some((key, (value, stream)))) =
            self.pending_streams.poll_next_unpin(cx)
        {
            let priority = self
                .priorities
                .get(&key)
                // By `pending_streams` invariant that all keys are also in `priorities`.
                .expect("Missing priority");
            let prev = self
                .ready_values
                .insert((priority.clone(), key), (value, stream));
            assert!(prev.is_none());
        }
        self.ready_values
            .iter()
            .map(|((p, k), (v, _s))| (k, v.as_ref(), p))
    }

    /// If the stream for `key` has `Some(value)` ready, take that value and set the
    /// priority for it to `new_priority`.
    ///
    /// This method doesn't poll the internal streams. Use `poll_ready_iter` to
    /// ensure streams make progress.
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
    ) -> Option<(P, V)> {
        // Get the priority entry, but don't replace until the lookup in ready_streams is confirmed.
        let hash_map::Entry::Occupied(mut priority_entry) = self.priorities.entry(key.clone())
        else {
            // Key isn't present at all.
            return None;
        };
        let priority_mut = priority_entry.get_mut();
        let btree_map::Entry::Occupied(ready_stream_entry) =
            self.ready_values.entry((priority_mut.clone(), key.clone()))
        else {
            // This stream isn't ready.
            return None;
        };
        #[allow(clippy::question_mark)]
        if ready_stream_entry.get().0.is_none() {
            // The stream is ready, but it's at end-of-stream. It doesn't have a value.
            return None;
        }
        let prev_priority = std::mem::replace(priority_mut, new_priority);
        let ((_p, key), (value, stream)) = ready_stream_entry.remove_entry();
        let value = value
            // Checked above.
            .expect("Value disappeared");
        self.pending_streams
            .try_insert(key, stream.into_future())
            // We verified above that the key wasn't present in `priorities`,
            // and `pending_streams` has the invariant that its keys are a
            // subset of those in `priorities`.
            .unwrap_or_else(|_| panic!("Unexpected pending stream entry"));
        Some((prev_priority, value))
    }

    /// Get a mut reference to a ready value for key `key`, if one exists.
    ///
    /// This method doesn't poll the internal streams. Use `poll_ready_iter` to
    /// ensure streams make progress.
    // This will be used for packing and fragmentation, to take part of a DATA message.
    #[allow(unused)]
    pub fn ready_value_mut(&mut self, key: &K) -> Option<&mut V> {
        let priority = self.priorities.get(key)?;
        let value = &mut self
            .ready_values
            .get_mut(&(priority.clone(), key.clone()))?
            .0;
        value.as_mut()
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
        sync::{Arc, Mutex},
        task::Poll,
    };

    use futures::{stream, SinkExt as _};
    use tor_rtmock::MockRuntime;

    use super::*;

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    struct Key(u64);

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
    struct Priority(u64);

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    struct Value(u64);

    trait TestStreamTrait: futures::Stream<Item = Value> + Unpin + std::fmt::Debug {}
    impl<T> TestStreamTrait for T where T: futures::Stream<Item = Value> + Unpin + std::fmt::Debug {}
    type TestStream = Box<dyn TestStreamTrait>;

    #[test]
    fn test_empty() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Value, Priority, TestStream>::new();
            assert_eq!(pollset.poll_ready_iter(ctx).collect::<Vec<_>>(), vec![]);
            Poll::Ready(())
        }));
    }

    #[test]
    fn test_one_pending() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Value, Priority, TestStream>::new();
            pollset
                .try_insert(Key(0), Priority(0), Box::new(stream::pending()))
                .unwrap();
            assert_eq!(pollset.poll_ready_iter(ctx).collect::<Vec<_>>(), vec![]);
            Poll::Ready(())
        }));
    }

    #[test]
    fn test_one_ready() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Value, Priority, TestStream>::new();
            pollset
                .try_insert(
                    Key(0),
                    Priority(0),
                    Box::new(stream::iter(vec![Value(1), Value(2)])),
                )
                .unwrap();

            // We only see the first value of the one ready stream.
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![(&Key(0), Some(&Value(1)), &Priority(0))]
            );

            // Same result, the same value is still at the head of the stream..
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![(&Key(0), Some(&Value(1)), &Priority(0))]
            );

            // Take the head of the stream.
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(0), Priority(1)),
                Some((Priority(0), Value(1)))
            );

            // Should see the next value, with the new priority.
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![(&Key(0), Some(&Value(2)), &Priority(1))]
            );

            // Take again.
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(0), Priority(2)),
                Some((Priority(1), Value(2)))
            );

            // Should see end-of-stream.
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![(&Key(0), None, &Priority(2))]
            );

            // Remove the now-ended stream.
            assert_eq!(pollset.remove(&Key(0)), Some((Key(0), Priority(2))));

            // Should now be empty.
            assert_eq!(pollset.poll_ready_iter(ctx).collect::<Vec<_>>(), vec![]);

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_round_robin() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Value, Priority, TestStream>::new();
            pollset
                .try_insert(
                    Key(0),
                    Priority(0),
                    Box::new(stream::iter(vec![Value(1), Value(2)])),
                )
                .unwrap();
            pollset
                .try_insert(
                    Key(1),
                    Priority(1),
                    Box::new(stream::iter(vec![Value(3), Value(4)])),
                )
                .unwrap();

            // Should see both ready streams, in priority order.
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![
                    (&Key(0), Some(&Value(1)), &Priority(0)),
                    (&Key(1), Some(&Value(3)), &Priority(1)),
                ]
            );

            // Take from the first stream and send it to the back via priority assignment.
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(0), Priority(2)),
                Some((Priority(0), Value(1)))
            );

            // Should see both ready streams, in the new priority order.
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![
                    (&Key(1), Some(&Value(3)), &Priority(1)),
                    (&Key(0), Some(&Value(2)), &Priority(2)),
                ]
            );

            // Keep going ...
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(1), Priority(3)),
                Some((Priority(1), Value(3)))
            );
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![
                    (&Key(0), Some(&Value(2)), &Priority(2)),
                    (&Key(1), Some(&Value(4)), &Priority(3)),
                ]
            );
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(0), Priority(4)),
                Some((Priority(2), Value(2)))
            );
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![
                    (&Key(1), Some(&Value(4)), &Priority(3)),
                    (&Key(0), None, &Priority(4)),
                ]
            );
            assert_eq!(
                pollset.take_ready_value_and_reprioritize(&Key(1), Priority(5)),
                Some((Priority(3), Value(4)))
            );
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![(&Key(0), None, &Priority(4)), (&Key(1), None, &Priority(5)),]
            );

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_remove_and_reuse_key() {
        futures::executor::block_on(futures::future::poll_fn(|ctx| {
            let mut pollset = StreamPollSet::<Key, Value, Priority, TestStream>::new();
            pollset
                .try_insert(
                    Key(0),
                    Priority(0),
                    Box::new(stream::iter(vec![Value(1), Value(2)])),
                )
                .unwrap();
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![(&Key(0), Some(&Value(1)), &Priority(0)),]
            );
            assert_eq!(pollset.remove(&Key(0)), Some((Key(0), Priority(0))));
            pollset
                .try_insert(
                    Key(0),
                    Priority(1),
                    Box::new(stream::iter(vec![Value(3), Value(4)])),
                )
                .unwrap();
            // Ensure we see the ready value in the new stream, and *not* anything from the previous stream at that key.
            assert_eq!(
                pollset.poll_ready_iter(ctx).collect::<Vec<_>>(),
                vec![(&Key(0), Some(&Value(3)), &Priority(1)),]
            );
            Poll::Ready(())
        }));
    }

    #[test]
    fn test_async() {
        MockRuntime::test_with_various(|rt| async move {
            let mut pollset = StreamPollSet::<
                Key,
                Value,
                Priority,
                futures::channel::mpsc::Receiver<Value>,
            >::new();

            // Create 2 mpsc channels, bounded so that we can exercise back-pressure.
            // These are analogous to Tor streams.
            for streami in 1..=2 {
                let (mut send, recv) = futures::channel::mpsc::channel::<Value>(2);
                pollset
                    .try_insert(Key(streami), Priority(streami), recv)
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
                        let (key, value, priority) = futures::future::poll_fn(|ctx| match pollset
                            .poll_ready_iter(ctx)
                            .next()
                        {
                            Some((key, value, priority)) => {
                                Poll::Ready((*key, value.copied(), *priority))
                            }
                            // No streams ready, but there could be more items coming.
                            // The current `ctx` should be registered to wake us
                            // if and when there are.
                            None => Poll::Pending,
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
                            pollset.remove(&key).unwrap();
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
