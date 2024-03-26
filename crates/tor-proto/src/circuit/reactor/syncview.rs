//! Implement synchronous views of circuit internals.

use super::CircHop;

/// A view of a [`ClientCirc`](crate::circuit::ClientCirc)'s internals, usable in a
/// synchronous callback.
//
// TODO: I would rather have this type have a mutable reference to the reactor itself,
// rather than just an immutable reference to a piece of it.
// But that creates borrow-checker problems, so instead for now,
// we only hold references to the pieces we need.
//
// If we need to hold more info in the future,
// we'll need to decide whether to create additional types for the more complex variants,
// or whether to try to stuff everything inside this type.
pub struct ClientCircSyncView<'a> {
    /// The hops of the circuit used to implement this view.
    pub(super) hops: &'a Vec<CircHop>,
}

impl<'a> ClientCircSyncView<'a> {
    /// Construct a new view of a circuit, given a mutable reference to its
    /// reactor.
    pub(super) fn new(reactor: &'a Vec<CircHop>) -> Self {
        Self { hops: reactor }
    }

    /// Return the number of streams currently open on this circuit.
    pub fn n_open_streams(&self) -> usize {
        self.hops
            .iter()
            .map(|hop| hop.map.n_open_streams())
            // No need to worry about overflow; max streams per hop is U16_MAX
            .sum()
    }

    // TODO: We will eventually want to add more functionality here, but we
    // should do so judiciously.
}
