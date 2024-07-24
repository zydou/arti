//! Provides [`KeyedFuturesUnordered`]

// So that we can declare these things as if they were in their own crate.
#![allow(unreachable_pub)]

use std::{
    collections::{hash_map, HashMap},
    hash::Hash,
    pin::Pin,
    task::Poll,
};

use futures::{
    future::abortable,
    stream::{AbortHandle, Abortable},
    Future,
};
use pin_project::pin_project;

/// Wraps a future `F` to add an associated key.
///
/// The new future will return `(K, F::Output)`.
///
/// `KeyedFuture::new(key, fut)` behaves the same as
/// `fut.map(|v| (key, v))`, except that it has a type that you can name.
// It'd be nice to just use futures::future::Map instead, but it takes a
// `FnOnce` type parameter, and there is currently no way to name a type
// implementing `FnOnce`.
#[derive(Debug)]
#[pin_project]
struct KeyedFuture<K, F> {
    /// Key
    // Invariant:
    // * Present until this future is polled to completion.
    key: Option<K>,
    /// Inner future
    #[pin]
    future: F,
}

impl<K, F> KeyedFuture<K, F> {
    /// Create a new [`KeyedFuture`].
    fn new(key: K, future: F) -> Self {
        Self {
            key: Some(key),
            future,
        }
    }
}

impl<K, F> Future for KeyedFuture<K, F>
where
    F: Future,
{
    type Output = (K, F::Output);

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let self_ = self.project();
        self_.future.poll(cx).map(|o| {
            let key = self_
                .key
                .take()
                // By:
                // * Invariant on `key` that it'll be present until polled to completion.
                // * Contract of `Future::poll` requires `poll` not called again after completion.
                .expect("Polled after completion");
            (key, o)
        })
    }
}

/// Efficiently manages a dynamic set of futures as per
/// [`futures::stream::FuturesUnordered`]. Unlike `FuturesUnordered`, each future
/// has an associated key. This key is returned along with the future's output,
/// and can be used to cancel and *remove* a future from the set.
///
/// Implements [`futures::Stream`], producing a stream of completed futures and
/// their associated keys.
#[derive(Debug)]
#[pin_project]
pub struct KeyedFuturesUnordered<K, F>
where
    F: Future,
{
    /// The futures themselves.
    // Invariants:
    // * The key for every uncanceled future has a corresponding entry in
    // `abort_handles`.
    // * Contains at most one uncanceled future for any given key `K`.
    //   (FuturesUnordered doesn't support efficient removal of individual futures).
    #[pin]
    futures_unordered: futures::stream::FuturesUnordered<Abortable<KeyedFuture<K, F>>>,
    /// Handles allowing cancellation.
    // Invariants:
    // * For every key K, there is an uncanceled future with that key in
    // `futures_unordered`.
    abort_handles: HashMap<K, AbortHandle>,
}

impl<K, F> KeyedFuturesUnordered<K, F>
where
    F: Future,
    K: Eq + Hash + Clone,
{
    /// Create an empty [`KeyedFuturesUnordered`].
    pub fn new() -> Self {
        Self {
            futures_unordered: Default::default(),
            abort_handles: Default::default(),
        }
    }

    /// Insert a future and associate it with `key`. Return an error if there is already an entry for `key`.
    pub fn try_insert(&mut self, key: K, fut: F) -> Result<(), KeyAlreadyInsertedError<K, F>> {
        let hash_map::Entry::Vacant(v) = self.abort_handles.entry(key.clone()) else {
            // Key is already present.
            return Err(KeyAlreadyInsertedError { key, fut });
        };
        let (fut, handle) = abortable(KeyedFuture::new(key, fut));
        v.insert(handle);
        self.futures_unordered.push(fut);
        Ok(())
    }

    /// Remove the entry for `key`, if any. If the corresponding future hasn't
    /// completed yet, it will be canceled. Note however that the underlying
    /// future won't be guaranteed to have been dropped until all available
    /// items have been read from this object's [`futures::Stream`]
    //
    // It'd be nice to guarantee that the future is dropped immediately, or take
    // and return it here. The inner `FuturesUnordered` doesn't support removing
    // an individual item, though, which is why we wrap the inner futures in
    // `futures::Abortable`.  Unfortunately that also doesn't provide a way to
    // immediately drop or take the inner future. If we decide we need that
    // functionality, we could do it by implementing our own alternative to
    // `Abortable` that puts the inner future inside an `Arc<Mutex<Option<_>>>`
    // shared with the abort-handle. It's more code to maintain though, and
    // probably a bit less efficient.
    pub fn remove(&mut self, key: &K) -> Option<K> {
        let (key, e) = self.abort_handles.remove_entry(key)?;
        e.abort();
        Some(key)
    }
}

impl<K, F> futures::Stream for KeyedFuturesUnordered<K, F>
where
    F: Future,
    K: Clone + Hash + Eq,
{
    type Item = (K, F::Output);

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut self_ = self.project();
        loop {
            match self_.futures_unordered.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                // End of stream (no registered futures)
                Poll::Ready(None) => return Poll::Ready(None),
                // Aborted. Silently ignore and move on to the next value.
                Poll::Ready(Some(Err(_aborted))) => continue,
                // A completed future.
                Poll::Ready(Some(Ok((key, output)))) => {
                    self_
                        .abort_handles
                        .remove(&key)
                        // By invariant on `futures_unordered`. We verified that
                        // the future wasn't canceled, so there must be an
                        // `abort_handle` entry.
                        .expect("Cancellation sender is missing");
                    return Poll::Ready(Some((key, output)));
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

    use futures::{
        executor::block_on,
        future::{self, poll_fn},
        StreamExt as _,
    };
    use tor_async_utils::oneshot;
    use tor_rtmock::MockRuntime;

    use super::*;

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    struct Key(u64);

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
    struct Value(u64);

    #[test]
    fn test_empty() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::<Key, oneshot::Receiver<Value>>::new();

            // When there are no futures in the set (ready or pending), returns
            // `Poll::Ready(None)` as for `FuturesUnordered`.
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_one_pending_future() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();

            kfu.try_insert(Key(0), future::pending::<()>()).unwrap();

            // When there are futures in the set, but none are ready, returns
            // `Poll::Pending`, as for `FuturesUnordered`
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Pending);

            // State should be unchanged; same result if we poll again.
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Pending);

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_one_ready_future() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();

            kfu.try_insert(Key(0), future::ready(Value(1))).unwrap();

            // When there is a ready future, returns it.
            assert_eq!(
                kfu.poll_next_unpin(cx),
                Poll::Ready(Some((Key(0), Value(1))))
            );

            // After having returned the ready future, should be empty again.
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));

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

            send.send(Value(1)).unwrap();

            // oneshot future should be ready.
            assert_eq!(
                kfu.poll_next_unpin(cx),
                Poll::Ready(Some((Key(0), Ok(Value(1)))))
            );

            // Empty again.
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));

            Poll::Ready(())
        }));
    }

    #[test]
    fn test_remove_pending() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();
            kfu.try_insert(Key(0), future::pending::<()>()).unwrap();
            assert_eq!(kfu.remove(&Key(0)), Some(Key(0)));
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));
            Poll::Ready(())
        }));
    }

    #[test]
    fn test_remove_ready() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();
            kfu.try_insert(Key(0), future::ready(Value(1))).unwrap();
            assert_eq!(kfu.remove(&Key(0)), Some(Key(0)));
            assert_eq!(kfu.poll_next_unpin(cx), Poll::Ready(None));
            Poll::Ready(())
        }));
    }

    #[test]
    fn test_remove_and_reuse_ready() {
        block_on(poll_fn(|cx| {
            let mut kfu = KeyedFuturesUnordered::new();
            kfu.try_insert(Key(0), future::ready(Value(1))).unwrap();
            assert_eq!(kfu.remove(&Key(0)), Some(Key(0)));
            kfu.try_insert(Key(0), future::ready(Value(2))).unwrap();

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
