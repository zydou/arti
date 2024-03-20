//! Implement synchronous views of circuit internals.

use super::Reactor;

/// A view of a [`ClientCirc`](crate::circuit::ClientCirc)'s internals, usable in a
/// synchronous callback.
pub struct ClientCircSyncView<'a> {
    /// The circuit reactor used to implement this view.
    pub(super) reactor: &'a mut Reactor,
}

impl<'a> ClientCircSyncView<'a> {
    /// Construct a new view of a circuit, given a mutable reference to its
    /// reactor.
    pub(super) fn new(reactor: &'a mut Reactor) -> Self {
        Self { reactor }
    }

    /// Return the number of streams currently open on this circuit.
    pub fn n_open_streams(&self) -> usize {
        self.reactor
            .hops
            .iter()
            .map(|hop| hop.map.n_open_streams())
            // No need to worry about overflow; max streams per hop is U16_MAX
            .sum()
    }

    // TODO: We will eventually want to add more functionality here, but we
    // should do so judiciously.
}
