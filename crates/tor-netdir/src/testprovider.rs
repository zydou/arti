//! A testing implementation of [`NetDirProvider`].

use std::sync::{Arc, Mutex};

use crate::{DirEvent, Error, NetDir, NetDirProvider, Result};

/// Helper implementation of a [`NetDirProvider`].
///
/// A [`TestNetDirProvider`] can be used to provide a netdir in a single
/// situation that requires a [`NetDirProvider`].  It does not yet notify its
/// owner of any changes; it only provides a [`NetDir`].
#[derive(Debug, Default)]
pub struct TestNetDirProvider {
    /// The latest netdir that this will return.
    current: Mutex<Option<Arc<NetDir>>>,
}

impl TestNetDirProvider {
    /// Create a new [`TestNetDirProvider`] with no netdir available.
    pub fn new() -> Self {
        Self {
            current: Mutex::new(None),
        }
    }

    /// Replace the `NetDir` in this [`TestNetDirProvider`].
    pub fn set_netdir(&self, dir: impl Into<Arc<NetDir>>) {
        *self.current.lock().expect("lock poisoned") = Some(dir.into());
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
        match self.current.lock().expect("lock poisoned").as_ref() {
            Some(netdir) => Ok(Arc::clone(netdir)),
            None => Err(Error::NoInfo),
        }
    }

    fn events(&self) -> futures::stream::BoxStream<'static, DirEvent> {
        Box::pin(futures::stream::pending())
    }

    fn params(&self) -> Arc<dyn AsRef<crate::params::NetParameters>> {
        if let Ok(nd) = self.netdir(crate::Timeliness::Unchecked) {
            nd
        } else {
            Arc::new(crate::params::NetParameters::default())
        }
    }
}
