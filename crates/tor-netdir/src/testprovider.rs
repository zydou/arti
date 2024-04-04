//! A testing implementation of [`NetDirProvider`].

use std::sync::{Arc, Mutex};

use crate::{DirEvent, Error, NetDir, NetDirProvider, Result};

use postage::broadcast::{self, Receiver, Sender};
use postage::sink::Sink as _;

/// Helper implementation of a [`NetDirProvider`].
///
/// A [`TestNetDirProvider`] can be used to provide a netdir in a single
/// situation that requires a [`NetDirProvider`].
///
/// It notifies its owner of changes
/// by firing a [`NewConsensus`](DirEvent::NewConsensus) event
/// each time [`TestNetDirProvider::set_netdir_and_notify`] is called.
///
/// Calling [`TestNetDirProvider::set_netdir`] will **not** trigger a notification.
#[derive(Debug)]
pub struct TestNetDirProvider {
    /// The mutable inner state.
    inner: Mutex<Inner>,
}

/// The inner part of a TestNetDirProvider.
#[derive(Debug)]
struct Inner {
    /// The latest netdir that this will return.
    current: Option<Arc<NetDir>>,
    /// The event sender, which fires every time the netdir is updated.
    event_tx: Sender<DirEvent>,
    /// The event receiver.
    _event_rx: Receiver<DirEvent>,
}

#[allow(clippy::new_without_default)]
impl TestNetDirProvider {
    /// Create a new [`TestNetDirProvider`] with no netdir available.
    pub fn new() -> Self {
        let (event_tx, _event_rx) = broadcast::channel(0);
        let inner = Inner {
            current: None,
            event_tx,
            _event_rx,
        };

        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Replace the `NetDir` in this [`TestNetDirProvider`].
    pub fn set_netdir(&self, dir: impl Into<Arc<NetDir>>) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.current = Some(dir.into());
    }

    /// Replace the `NetDir` in this [`TestNetDirProvider`],
    /// firing a [`NewConsensus`](DirEvent::NewConsensus) event.
    pub async fn set_netdir_and_notify(&self, dir: impl Into<Arc<NetDir>>) {
        let mut event_tx = {
            let mut inner = self.inner.lock().expect("lock poisoned");
            inner.current = Some(dir.into());
            inner.event_tx.clone()
        };
        event_tx
            .send(DirEvent::NewConsensus)
            .await
            .expect("receivers were dropped");
    }
}

impl From<NetDir> for TestNetDirProvider {
    fn from(nd: NetDir) -> Self {
        let rv = Self::new();
        rv.set_netdir(nd);
        rv
    }
}

impl NetDirProvider for TestNetDirProvider {
    fn netdir(&self, _timeliness: crate::Timeliness) -> Result<Arc<NetDir>> {
        match self.inner.lock().expect("lock poisoned").current.as_ref() {
            Some(netdir) => Ok(Arc::clone(netdir)),
            None => Err(Error::NoInfo),
        }
    }

    fn events(&self) -> futures::stream::BoxStream<'static, DirEvent> {
        let inner = self.inner.lock().expect("lock poisoned");
        let events = inner.event_tx.subscribe();
        Box::pin(events)
    }

    fn params(&self) -> Arc<dyn AsRef<crate::params::NetParameters>> {
        if let Ok(nd) = self.netdir(crate::Timeliness::Unchecked) {
            nd
        } else {
            Arc::new(crate::params::NetParameters::default())
        }
    }
}
