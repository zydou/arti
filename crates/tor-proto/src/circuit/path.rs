//! Tracking for the path of a client circuit.

use std::sync::atomic::{AtomicU8, Ordering};

/// Helper struct that shares information
#[derive(Debug, Default)]
pub(super) struct Path {
    /// Number of hops on this circuit.
    ///
    /// This value is incremented after the circuit successfully completes extending to a new hop.
    n_hops: AtomicU8,
}

impl Path {
    /// Return the number of hops in this path
    pub(super) fn n_hops(&self) -> u8 {
        self.n_hops.load(Ordering::SeqCst)
    }

    /// Add 1 to the number of hops in this path.
    pub(super) fn inc_hops(&self) {
        self.n_hops.fetch_add(1, Ordering::SeqCst);
    }
}
