//! Code for notifying other modules about changes in the directory.

use futures::stream::Stream;
use postage::{broadcast, sink::Sink as _};

/// An event that a DirMgr can broadcast to indicate that a change in
/// the status of its directory.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DirEvent {
    /// A new consensus has been received, and has enough information
    /// to be used.
    NewConsensus,

    /// New descriptors have been received for the latest consensus.
    NewDescriptors,

    /// A dummy event that's only used when we're testing.
    #[cfg(test)]
    Dummy,
}

/// Length of the event queue to use in publishers.
///
/// Chosen arbitrarily.
const QUEUE_LEN: usize = 64;

/// A handle to use in publishing [`DirEvent`]s.
///
/// Cloning a Publisher gives a new handle to the same queue; any event sent
/// with the clone of a Publisher behaves as if it were sent with the original
/// Publisher.
///
/// This handle is implemented as a light facade around
/// [`postage::broadcast`].
///
/// TODO: Eventually we should probably move this into a more generic
/// crate, once we have a few crates that want this kind of thing.
#[derive(Clone)]
pub(crate) struct Publisher {
    /// Sender to use in publishing events.
    send: broadcast::Sender<DirEvent>,
}

impl Publisher {
    /// Create a new Publisher.
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        let (send, _recv) = broadcast::channel(QUEUE_LEN);
        Publisher { send }
    }

    /// Broadcast the provided [`DirEvent`] to every subscribed listener.
    ///
    /// If there are no subscribed listeners, just drop the event.
    ///
    /// This future can block if some subscriber isn't consuming its events
    /// quickly enough.
    pub(crate) async fn send(&self, ev: DirEvent) {
        // Clone the sender to incref it and get a mutable copy.
        // (It is an Arc internally.)
        let mut sender = self.send.clone();
        // Ignore the results of the send: it will be an error if there are
        // no subscribers, but we don't care.
        let _ignore = sender.send(ev).await;
    }

    /// Return a new [`Stream`] of events.
    ///
    /// This stream will receive every event that is sent on this publisher
    /// _after_ it was created.
    ///
    /// When the last handle for a Publisher is dropped, all Streams
    /// subscribed to that publisher will receive a close.
    ///
    pub(crate) fn subscribe(&self) -> impl Stream<Item = DirEvent> {
        self.send.subscribe()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use futures_await_test::async_test;
    //use tor_rtcompat::test_with_all_runtimes;
    use futures::stream::StreamExt;

    // Check publishing with no subscribers: events should just
    // get dropped.
    #[async_test]
    async fn drop_test() {
        let publ = Publisher::new();
        for _ in 0..100000 {
            publ.send(DirEvent::NewConsensus).await;
        }
    }

    #[async_test]
    async fn publish_test() {
        let publ = Publisher::new();
        for _ in 0..100_usize {
            // no subscribers, so these should be dropped.
            publ.send(DirEvent::Dummy).await;
        }
        // This subscribes early and sees two events.
        let sub1 = publ.subscribe();
        publ.send(DirEvent::NewConsensus).await;
        // This subscribes late and only sees one event.
        let sub2 = publ.subscribe();
        publ.send(DirEvent::NewConsensus).await;
        drop(publ);
        let lst1: Vec<_> = sub1.collect().await;
        let lst2: Vec<_> = sub2.collect().await;

        assert_eq!(lst1.len(), 2);
        assert_eq!(lst2.len(), 1);
        assert!(matches!(lst1[0], DirEvent::NewConsensus));
        assert!(matches!(lst1[1], DirEvent::NewConsensus));
        assert!(matches!(lst2[0], DirEvent::NewConsensus));
    }
}
