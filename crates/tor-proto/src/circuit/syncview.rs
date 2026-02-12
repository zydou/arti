//! Implement synchronous views of circuit internals.

use crate::circuit::circhop::CircHopOutbound;

/// A view of a circuit hop's internals, usable in a synchronous callback.
//
// TODO: I would rather have this type have a mutable reference to the reactor itself,
// rather than just an immutable reference to a piece of it.
// But that creates borrow-checker problems, so instead for now,
// we only hold references to the pieces we need.
//
// If we need to hold more info in the future,
// we'll need to decide whether to create additional types for the more complex variants,
// or whether to try to stuff everything inside this type.
pub struct CircHopSyncView<'a> {
    /// The hop of the circuit used to implement this view.
    pub(super) hop: &'a CircHopOutbound,
}

impl<'a> CircHopSyncView<'a> {
    /// Construct a new view of a circuit hop, given a mutable reference to its outbound hop view.
    pub(crate) fn new(hop: &'a CircHopOutbound) -> Self {
        Self { hop }
    }

    /// Return the number of streams currently open on this circuit hop.
    pub fn n_open_streams(&self) -> usize {
        self.hop.n_open_streams()
    }
}
