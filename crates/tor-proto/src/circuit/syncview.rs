//! Implement synchronous views of circuit internals.

use crate::client::circuit::ClientCircSyncView;

/// An object that represents a view of a circuit's internals,
/// usable in a synchronous callback.
pub struct CircSyncView<'a>(CircSyncViewInner<'a>);

impl<'a> CircSyncView<'a> {
    /// Create a new client circuit view.
    pub(crate) fn new_client(c: ClientCircSyncView<'a>) -> Self {
        Self(c.into())
    }
}

/// The internal representation of a [`CircSyncView`].
#[derive(derive_more::From)]
pub(crate) enum CircSyncViewInner<'a> {
    /// A view of a client circuit's internals.
    Client(ClientCircSyncView<'a>),
    /// A view of a relay circuit's internals.
    #[cfg(feature = "relay")]
    #[allow(dead_code)] // TODO(relay)
    Relay(/* TODO(relay) */),
}

impl<'a> CircSyncView<'a> {
    /// Return the number of streams currently open on this circuit.
    pub fn n_open_streams(&self) -> usize {
        use CircSyncViewInner::*;

        match &self.0 {
            Client(c) => c.n_open_streams(),
            #[cfg(feature = "relay")]
            Relay() => todo!(),
        }
    }
}
