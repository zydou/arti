//! Code for notifying other modules about changes in the directory.
// TODO(nickm): After we have enough experience with this code, we might want to
// make it a public interface. If we do it should probably move into another
// crate.

use std::{
    marker::PhantomData,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::Poll,
};

use futures::{stream::Stream, Future};

/// An event that a DirMgr can broadcast to indicate that a change in
/// the status of its directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirEvent {
    /// A new consensus has been received, and has enough information to be
    /// used.
    ///
    /// This event is also broadcast when a new set of consensus parameters is
    /// available, even if that set of parameters comes from a configuration
    /// change rather than from the latest consensus.
    NewConsensus,

    /// New descriptors have been received for the current consensus.
    ///
    /// (This event is _not_ broadcast when receiving new descriptors for a
    /// consensus which is not yet ready to replace the current consensus.)
    NewDescriptors,
}

/// A trait to indicate something that can be published with [`FlagPublisher`].
///
/// Since the implementation of `FlagPublisher` requires that its events be
/// represented as small integers, this trait is mainly about converting to and
/// from those integers.
pub(crate) trait FlagEvent: Sized {
    /// The maximum allowed integer value that [`FlagEvent::to_index()`] can return
    /// for this type.
    ///
    /// This is limited to u16 because the [`FlagPublisher`] uses a vector of all
    /// known flags, and sometimes iterates over the whole vector.
    const MAXIMUM: u16;
    /// Convert this event into an index.
    ///
    /// For efficiency, indices should be small and densely packed.
    fn to_index(self) -> u16;
    /// Try to reconstruct an event from its index.  Return None if the index is
    /// out-of-bounds.
    fn from_index(flag: u16) -> Option<Self>;
}

impl FlagEvent for DirEvent {
    const MAXIMUM: u16 = 1;
    fn to_index(self) -> u16 {
        match self {
            DirEvent::NewConsensus => 0,
            DirEvent::NewDescriptors => 1,
        }
    }
    fn from_index(flag: u16) -> Option<Self> {
        match flag {
            0 => Some(DirEvent::NewConsensus),
            1 => Some(DirEvent::NewDescriptors),
            _ => None,
        }
    }
}

/// A publisher that broadcasts flag-level events to multiple subscribers.
///
/// Events with the same flag value may be coalesced: that is, if the same event
/// is published ten times in a row, a subscriber may receive only a single
/// notification of the event.
///
/// FlagPublisher supports an MPMC model: cloning a Publisher creates a new handle
/// that can also broadcast events to everybody listening on the channel.
///  Dropping the last handle closes all streams subscribed to it.
pub(crate) struct FlagPublisher<F> {
    /// Inner data shared by publishers and streams.
    inner: Arc<Inner<F>>,
}

/// Shared structure to implement [`FlagPublisher`] and [`FlagListener`].
struct Inner<F> {
    /// An event that we use to broadcast whenever a new [`FlagEvent`] event has occurred.
    event: event_listener::Event,
    /// How many times has each event occurred, ever.
    ///
    /// (It is safe for this to wrap around.)
    // TODO(nickm): I wish this could be an array, but const generics don't
    // quite support that yet.
    counts: Vec<AtomicUsize>, // I wish this could be an array.
    /// How many publishers remain?
    n_publishers: AtomicUsize,
    /// Phantom member to provide correct covariance.
    ///
    /// The `fn` business is a covariance trick to include `F` without affecting
    /// this object's Send/Sync status.
    _phantom: PhantomData<fn(F) -> F>,
}

/// A [`Stream`] that returns a series of event [`FlagEvent`]s broadcast by a
/// [`FlagPublisher`].
pub(crate) struct FlagListener<F> {
    /// What value of each flag's count have we seen most recently?  
    ///
    /// Note that we count the event as "received" only once for each observed
    /// change in the flag's count, even if that count has changed by more than
    /// 1.
    my_counts: Vec<usize>,
    /// An an `EventListener` that will be notified when events are published,
    /// or when the final publisher is dropped.
    ///
    /// We must always have one of these available _before_ we check any counts
    /// in self.inner.
    listener: event_listener::EventListener,
    /// Reference to shared data.
    inner: Arc<Inner<F>>,
}

impl<F: FlagEvent> FlagPublisher<F> {
    /// Construct a new FlagPublisher.
    pub(crate) fn new() -> Self {
        // We can't use vec![AtomicUsize::new(0); F::MAXIMUM+1]: that would
        // require AtomicUsize to be Clone.
        let counts = std::iter::repeat_with(AtomicUsize::default)
            .take(F::MAXIMUM as usize + 1)
            .collect();
        FlagPublisher {
            inner: Arc::new(Inner {
                event: event_listener::Event::new(),
                counts,
                n_publishers: AtomicUsize::new(1),
                _phantom: PhantomData,
            }),
        }
    }

    /// Create a new subscription to this FlagPublisher.
    pub(crate) fn subscribe(&self) -> FlagListener<F> {
        // We need to do this event.listen before we check the counts; otherwise
        // we could have a sequence where: we check the count, then the
        // publisher increments the count, then the publisher calls
        // event.notify(), and we call event.listen(). That would cause us to
        // miss the increment.
        let listener = self.inner.event.listen();

        FlagListener {
            my_counts: self
                .inner
                .counts
                .iter()
                .map(|a| a.load(Ordering::SeqCst))
                .collect(),
            listener,
            inner: Arc::clone(&self.inner),
        }
    }

    /// Tell every listener that the provided flag has been published.
    pub(crate) fn publish(&self, flag: F) {
        self.inner.counts[flag.to_index() as usize].fetch_add(1, Ordering::SeqCst);
        self.inner.event.notify(usize::MAX);
    }
}

impl<F> Clone for FlagPublisher<F> {
    fn clone(&self) -> FlagPublisher<F> {
        self.inner.n_publishers.fetch_add(1, Ordering::SeqCst);
        FlagPublisher {
            inner: Arc::clone(&self.inner),
        }
    }
}

// We must implement Drop to keep count publishers, and so that when the last
// publisher goes away, we can wake up every listener  so that it notices that
// the stream is now ended.
impl<F> Drop for FlagPublisher<F> {
    fn drop(&mut self) {
        if self.inner.n_publishers.fetch_sub(1, Ordering::SeqCst) == 1 {
            // That was the last reference; we must notify the listeners.
            self.inner.event.notify(usize::MAX);
        }
    }
}

impl<F: FlagEvent> Stream for FlagListener<F> {
    type Item = F;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            // Notify the caller if any events are ready to fire.
            for idx in 0..F::MAXIMUM as usize + 1 {
                let cur = self.inner.counts[idx].load(Ordering::SeqCst);
                // We don't have to use < here specifically, since any change
                // indicates that the count has been modified. That lets us
                // survive usize wraparound.
                if cur != self.my_counts[idx] {
                    self.my_counts[idx] = cur;
                    return Poll::Ready(Some(F::from_index(idx as u16).expect("Internal error")));
                }
            }

            // At this point, notify the caller if there are no more publishers.
            if self.inner.n_publishers.load(Ordering::SeqCst) == 0 {
                return Poll::Ready(None);
            }

            if let Poll::Ready(()) = Pin::new(&mut self.listener).poll(cx) {
                // Got a new notification; we must create a new event and continue the loop.
                //
                // See discussion in `FlagPublisher::subscribe()` for why we must always create
                // this listener _before_ checking any flags.
                self.listener = self.inner.event.listen();
            } else {
                // Nothing to do yet: put the listener back.
                return Poll::Pending;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use futures::stream::StreamExt;
    use tor_rtcompat::test_with_all_runtimes;

    #[test]
    fn subscribe_and_publish() {
        test_with_all_runtimes!(|_rt| async {
            let publish: FlagPublisher<DirEvent> = FlagPublisher::new();
            let mut sub1 = publish.subscribe();
            publish.publish(DirEvent::NewConsensus);
            let mut sub2 = publish.subscribe();
            let ev = event_listener::Event::new();
            let lis = ev.listen();

            futures::join!(
                async {
                    // sub1 was created in time to see this event...
                    let val1 = sub1.next().await;
                    assert_eq!(val1, Some(DirEvent::NewConsensus));
                    ev.notify(1); // Tell the third task below to drop the publisher.
                    let val2 = sub1.next().await;
                    assert_eq!(val2, None);
                },
                async {
                    let val = sub2.next().await;
                    assert_eq!(val, None);
                },
                async {
                    lis.await;
                    drop(publish);
                }
            );
        });
    }

    #[test]
    fn receive_two() {
        test_with_all_runtimes!(|_rt| async {
            let publish: FlagPublisher<DirEvent> = FlagPublisher::new();

            let mut sub = publish.subscribe();
            let ev = event_listener::Event::new();
            let ev_lis = ev.listen();
            futures::join!(
                async {
                    let val1 = sub.next().await;
                    assert_eq!(val1, Some(DirEvent::NewDescriptors));
                    ev.notify(1);
                    let val2 = sub.next().await;
                    assert_eq!(val2, Some(DirEvent::NewConsensus));
                },
                async {
                    publish.publish(DirEvent::NewDescriptors);
                    ev_lis.await;
                    publish.publish(DirEvent::NewConsensus);
                }
            );
        });
    }

    #[test]
    fn two_publishers() {
        test_with_all_runtimes!(|_rt| async {
            let publish1: FlagPublisher<DirEvent> = FlagPublisher::new();
            let publish2 = publish1.clone();

            let mut sub = publish1.subscribe();
            let ev1 = event_listener::Event::new();
            let ev2 = event_listener::Event::new();
            let ev1_lis = ev1.listen();
            let ev2_lis = ev2.listen();
            futures::join!(
                async {
                    let mut count = [0_usize; 2];
                    // These awaits guarantee that we will see at least one event flag of each
                    // type, before the stream is dropped.
                    ev1_lis.await;
                    ev2_lis.await;
                    while let Some(e) = sub.next().await {
                        count[e.to_index() as usize] += 1;
                    }
                    assert!(count[0] > 0);
                    assert!(count[1] > 0);
                    assert!(count[0] <= 100);
                    assert!(count[1] <= 100);
                },
                async {
                    for _ in 0..100 {
                        publish1.publish(DirEvent::NewDescriptors);
                        ev1.notify(1);
                        tor_rtcompat::task::yield_now().await;
                    }
                    drop(publish1);
                },
                async {
                    for _ in 0..100 {
                        publish2.publish(DirEvent::NewConsensus);
                        ev2.notify(1);
                        tor_rtcompat::task::yield_now().await;
                    }
                    drop(publish2);
                }
            );
        });
    }

    #[test]
    fn receive_after_publishers_are_gone() {
        test_with_all_runtimes!(|_rt| async {
            let publish: FlagPublisher<DirEvent> = FlagPublisher::new();

            let mut sub = publish.subscribe();

            publish.publish(DirEvent::NewConsensus);
            drop(publish);
            let v = sub.next().await;
            assert_eq!(v, Some(DirEvent::NewConsensus));
            let v = sub.next().await;
            assert!(v.is_none());
        });
    }

    #[test]
    fn failed_conversion() {
        assert_eq!(DirEvent::from_index(999), None);
    }
}
