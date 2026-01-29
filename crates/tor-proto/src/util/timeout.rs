//! An estimator for various timeouts.

use std::time::Duration;

/// An object used by circuits to compute various timeouts.
///
// This is implemented for the timeout `Estimator` from tor-circmgr.
pub trait TimeoutEstimator: Send + Sync {
    /// The estimated circuit build timeout for a circuit of the specified length.
    ///
    // Used by the circuit reactor for deciding when to expire half-streams.
    fn circuit_build_timeout(&self, length: usize) -> Duration;
}
