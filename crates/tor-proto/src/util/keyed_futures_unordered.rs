//! Provides [`KeyedFuturesUnordered`]

// So that we can declare these things as if they were in their own crate.
#![allow(unreachable_pub)]

use std::{
    collections::{hash_map, HashMap},
    hash::Hash,
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use futures::future::FutureExt;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    Future,
};
use pin_project::pin_project;

/// Waker for internal use in [`KeyedFuturesUnordered`]
///
/// When woken, it notifies the parent [`KeyedFuturesUnordered`] that the future
/// for a corresponding key is ready to be polled.
struct KeyedWaker<K> {
    /// The key associated with this waker.
    key: K,
    /// Sender cloned from the parent [`KeyedFuturesUnordered`].
    sender: UnboundedSender<K>,
}

impl<K> std::task::Wake for KeyedWaker<K>
where
    K: Clone,
{
    fn wake(self: Arc<Self>) {
        self.sender
            .unbounded_send(self.key.clone())
            .unwrap_or_else(|e| {
                if e.is_disconnected() {
                    // Other side has disappeared. Can safely ignore.
                    return;
                }
                // Shouldn't happen, but probably no need to `panic`.
                tracing::error!("Unexpected send error: {e:?}");
            });
    }
}

/// Efficiently manages a dynamic set of futures as per
/// [`futures::stream::FuturesUnordered`]. Unlike `FuturesUnordered`, each future
/// has an associated key. This key is returned along with the future's output,
/// and can be used to cancel and *remove* a future from the set.
///
/// Implements [`futures::Stream`], producing a stream of completed futures and
/// their associated keys.
///
/// # Stream behavior
///
/// `Stream::poll_next` returns:
/// * `Poll::Ready(None)` if there are no futures managed by this object.
/// * `Poll::Ready(Some((key, output)))` with the key and output of a ready
///    future when there is one.
/// * `Poll::Pending` when there are futures managed by this object, but none
///    are currently ready.
///
/// Unlike for a generic `Stream`, it *is* permitted to call `poll_next` again
/// after having received `Poll::Ready(None)`. It will still behave as above
/// (i.e. returning `Pending` or `Ready` if futures have since been inserted).
#[derive(Debug)]
#[pin_project]
pub struct KeyedFuturesUnordered<K, F>
where
    F: Future,
{
    /// Receiver on which we're notified of keys that are ready to be polled.
    #[pin]
    notification_receiver: UnboundedReceiver<K>,
    /// Sender on which to notify `notifications_receiver` that keys are ready
    /// to be polled.
    // In particular, keys are sent here:
    // * When a future is inserted.
    // * In `KeyedWaker`, which is the `Waker` we register with futures when we
    //   poll them internally.
    notification_sender: UnboundedSender<K>,
    /// Map of pending futures.
    futures: HashMap<K, F>,
}

impl<K, F> KeyedFuturesUnordered<K, F>
where
    F: Future,
    K: Eq + Hash + Clone,
{
    /// Create an empty [`KeyedFuturesUnordered`].
    pub fn new() -> Self {
        let (send, recv) = futures::channel::mpsc::unbounded();
        Self {
            notification_sender: send,
            notification_receiver: recv,
            futures: Default::default(),
        }
    }

    /// Insert a future and associate it with `key`. Return an error if there is already an entry for `key`.
    pub fn try_insert(&mut self, key: K, fut: F) -> Result<(), KeyAlreadyInsertedError<K, F>> {
        let hash_map::Entry::Vacant(v) = self.futures.entry(key.clone()) else {
            // Key is already present.
            return Err(KeyAlreadyInsertedError { key, fut });
        };
        v.insert(fut);
        // Immediately "notify" ourselves, to enqueue this key to be polled.
        self.notification_sender
            .unbounded_send(key)
            // * Since the sender is unbounded, can't fail due to fullness.
            // * Since we have our own copy of the receiver, can't be disconnected.
            .expect("Unbounded send unexpectedly failed");
        Ok(())
    }

    /// Remove the entry for `key`, if any, and return the corresponding future.
    pub fn remove(&mut self, key: &K) -> Option<(K, F)> {
        self.futures.remove_entry(key)
    }

    /// Get the future corresponding to `key`, if any.
    ///
    /// As for [`Self::get_mut`], removing or replacing its [`std::task::Waker`]
    /// without waking it (e.g. using internal mutability) results in
    /// unspecified (but sound) behavior.
    #[allow(dead_code)]
    pub fn get<'a>(&'a self, key: &K) -> Option<&'a F> {
        self.futures.get(key)
    }

    /// Get the future corresponding to `key`, if any.
    ///
    /// The future should not be `poll`d, nor its registered
    /// [`std::task::Waker`] otherwise removed or replaced (unless it is also
    /// woken; see below). The result of doing either is unspecified (but
    /// sound).
    ///
    /// This method is useful primarily when the future has other functionality
    /// or data bundled with it besides its implementation of the `Future`
    /// trait, though it *is* permitted to mutate the object in a way that
    /// causes it to become ready (i.e. wakes and discards its registered
    /// [`std::task::Waker`]`), or become unready (cause its next poll result to
    /// be `Poll::Pending` when it otherwise would have been `Poll::Ready` and
    /// may have already woken its registered `Waker`).
    //
    // More specifically:
    // * If the waker is lost without being woken, we'll never
    //   poll this future again.
    // * If our waker is woken *and* the caller polls the future to completion,
    //   we could end up polling it again after completion,
    //   breaking the `Future` contract.
    #[allow(dead_code)]
    pub fn get_mut<'a>(&'a mut self, key: &K) -> Option<&'a mut F> {
        self.futures.get_mut(key)
    }
}

impl<K, F> futures::Stream for KeyedFuturesUnordered<K, F>
where
    F: Future + Unpin,
    K: Clone + Hash + Eq + Send + Sync + 'static,
{
    type Item = (K, F::Output);

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if self.futures.is_empty() {
            // Follow precedent of `FuturesUnordered` of returning None in this case.
            // TODO: Consider breaking this precedent? This behavior is a bit
            // odd, since the documentation of the Stream trait indicates that a
            // stream shouldn't be polled again after returning None.
            return Poll::Ready(None);
        }
        let mut self_ = self.project();
        loop {
            // Get the next pollable future, registering the caller's waker.
            let key = match self_.notification_receiver.as_mut().poll_next(cx) {
                Poll::Ready(key) => key.expect("Unexpected end of stream"),
                Poll::Pending => {
                    // No more keys to try.
                    return Poll::Pending;
                }
            };
            let Some(fut) = self_.futures.get_mut(&key) else {
                // No future for this key. Presumably because it was removed
                // from the map. Try the next key.
                continue;
            };
            // Poll the future itself, using our own waker that will notify us
            // that this key is ready.
            let waker = std::task::Waker::from(Arc::new(KeyedWaker {
                key: key.clone(),
                sender: self_.notification_sender.clone(),
            }));
            match fut.poll_unpin(&mut std::task::Context::from_waker(&waker)) {
                Poll::Ready(o) => {
                    // Remove and drop the future itself.
                    // We *could* return it along with the item, but this would
                    // be a departure from the interface of `FuturesUnordered`,
                    // and most futures are designed to be discarded after
                    // completion.
                    self_.futures.remove(&key);

                    return Poll::Ready(Some((key, o)));
                }
                Poll::Pending => {
                    // This future wasn't actually ready.
                    //
                    // This can happen, e.g. because:
                    // * This is our first time actually polling this future.
                    // * The futures waker was called spuriously.
                    // * This was actually a reused key, and we received the notification from
                    //   a waker for a previous future registered with this key.
                    //
                    // Move on to the next key.
                }
            }
        }
    }
}

/// Error returned by [`KeyedFuturesUnordered::try_insert`].
#[derive(Debug, thiserror::Error)]
#[allow(clippy::exhaustive_structs)]
pub struct KeyAlreadyInsertedError<K, F> {
    /// Key that caller tried to insert.
    #[allow(dead_code)]
    pub key: K,
    /// Future that caller tried to insert.
    #[allow(dead_code)]
    pub fut: F,
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::task::Waker;

    use futures::{executor::block_on, future::poll_fn, StreamExt as _};
    use oneshot_fused_workaround as oneshot;
    use tor_rtmock::MockRuntime;

    use super::*;

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    struct Key(u64);

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
    struct Value(u64);

    /// Simple future for testing. Supports comparison, and can be mutated directly to become ready.
    #[derive(Debug, Clone)]
    struct ValueFut<V> {
        /// Value that will be produced when ready.
        value: Option<V>,
        /// Whether this is ready.
        // We use a distinct flag here instead of a None value so that pending
        // instances are still unequal if they have different values.
        ready: bool,
        // Waker
        waker: Option<Waker>,
    }

    impl<V> std::cmp::PartialEq for ValueFut<V>
    where
        V: std::cmp::PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            // Ignores the waker, which isn't comparable
            self.value == other.value && self.ready == other.ready
        }
    }

    impl<V> std::cmp::Eq for ValueFut<V> where V: std::cmp::Eq {}

    impl<V> ValueFut<V> {
        fn ready(value: V) -> Self {
            Self {
                value: Some(value),
                ready: true,
                waker: None,
            }
        }
        fn pending(value: V) -> Self {
            Self {
                value: Some(value),
                ready: false,
                waker: None,
            }
        }
        fn make_ready(&mut self) {
            self.ready = true;
            if let Some(waker) = self.waker.take() {
                waker.wake();
            }
        }
    }

    impl<V> Future for ValueFut<V>
    where
        V: Unpin,
    {
        type Output = V;

        fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
            if !self.ready {
                self.waker.replace(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(self.value.take().expect("Polled future after it was ready"))
            }
        }
    }

    #[test]
    fn test_empty() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::<Key, ValueFut<Value>>::new();

            // When there are no futures in the set (ready or pending), returns
            // `Poll::Ready(None)` as for `FuturesUnordered`.
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));

            // Nothing to get.
            assert_eq!(kfu.get(&Key(0)), None);
            assert_eq!(kfu.get_mut(&Key(0)), None);

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_one_pending_future() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();

            kfu.try_insert(Key(0), ValueFut::pending(Value(0))).unwrap();

            // When there are futures in the set, but none are ready, returns
            // `Poll::Pending`, as for `FuturesUnordered`
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Pending);

            // State should be unchanged; same result if we poll again.
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Pending);

            // We should be able to get the future.
            assert_eq!(kfu.get(&Key(0)), Some(&ValueFut::pending(Value(0))));
            assert_eq!(kfu.get_mut(&Key(0)), Some(&mut ValueFut::pending(Value(0))));

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_one_ready_future() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();

            kfu.try_insert(Key(0), ValueFut::ready(Value(1))).unwrap();

            // Should be able to get the future before it's polled.
            assert_eq!(kfu.get(&Key(0)), Some(&ValueFut::ready(Value(1))));
            assert_eq!(kfu.get_mut(&Key(0)), Some(&mut ValueFut::ready(Value(1))));

            // When there is a ready future, returns it.
            assert_eq!(
                kfu.poll_next_unpin(cx),
                Poll::Ready(Some((Key(0), Value(1))))
            );

            // After having returned the ready future, should be empty again.
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));
            assert_eq!(kfu.get(&Key(0)), None);
            assert_eq!(kfu.get_mut(&Key(0)), None);

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_one_pending_then_ready_future() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();
            let (send, recv) = oneshot::channel::<Value>();
            kfu.try_insert(Key(0), recv).unwrap();

            // Nothing ready yet.
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Pending);

            // Should be able to get it.
            assert!(kfu.get(&Key(0)).is_some());
            assert!(kfu.get_mut(&Key(0)).is_some());

            send.send(Value(1)).unwrap();

            // oneshot future should be ready.
            assert_eq!(
                kfu.poll_next_unpin(cx),
                Poll::Ready(Some((Key(0), Ok(Value(1)))))
            );

            // Empty again.
            assert!(kfu.get(&Key(0)).is_none());
            assert!(kfu.get_mut(&Key(0)).is_none());
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_remove_pending() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();
            kfu.try_insert(Key(0), ValueFut::pending(Value(0))).unwrap();
            assert_eq!(
                kfu.remove(&Key(0)),
                Some((Key(0), ValueFut::pending(Value(0))))
            );
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));
            Poll::Ready(())
        }));
    }

    #[test]
    fn test_remove_ready() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();
            kfu.try_insert(Key(0), ValueFut::ready(Value(1))).unwrap();
            assert_eq!(
                kfu.remove(&Key(0)),
                Some((Key(0), ValueFut::ready(Value(1))))
            );
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));
            Poll::Ready(())
        }));
    }

    #[test]
    fn test_remove_and_reuse_ready() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();
            kfu.try_insert(Key(0), ValueFut::ready(Value(1))).unwrap();
            assert_eq!(
                kfu.remove(&Key(0)),
                Some((Key(0), ValueFut::ready(Value(1))))
            );
            kfu.try_insert(Key(0), ValueFut::ready(Value(2))).unwrap();

            // We should get back *only* the second value.
            assert_eq!(
                kfu.poll_next_unpin(cx),
                Poll::Ready(Some((Key(0), Value(2))))
            );
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_remove_and_reuse_pending_then_ready() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();
            kfu.try_insert(Key(0), ValueFut::pending(Value(1))).unwrap();
            let (_key, mut removed_value) = kfu.remove(&Key(0)).unwrap();
            kfu.try_insert(Key(0), ValueFut::pending(Value(2))).unwrap();

            // Make the *removed* future ready before polling again. This should
            // cause an internal spurious wakeup, but not be visible from the
            // user's perspective.
            removed_value.make_ready();
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Pending);

            // Make the future that we replaced it with become ready.
            kfu.get_mut(&Key(0)).unwrap().make_ready();

            // We should now get back *only* the second value.
            assert_eq!(
                kfu.poll_next_unpin(cx),
                Poll::Ready(Some((Key(0), Value(2))))
            );
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_async() {
        MockRuntime::test_with_various(|rt| async move {
            let mut kfu = KeyedFuturesUnordered::new();

            for i in 0..10 {
                let (send, recv) = oneshot::channel();
                kfu.try_insert(Key(i), recv).unwrap();
                rt.spawn_identified(format!("sender-{i}"), async move {
                    send.send(Value(i)).unwrap();
                });
            }

            let values = kfu.collect::<Vec<_>>().await;
            let mut values = values
                .into_iter()
                .map(|(k, v)| (k, v.unwrap()))
                .collect::<Vec<_>>();
            values.sort();

            let expected_values = (0..10).map(|i| (Key(i), Value(i))).collect::<Vec<_>>();
            assert_eq!(values, expected_values);
        });
    }
}
