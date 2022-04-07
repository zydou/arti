//! Code for creating and manipulating observations about clock skew.

use std::time::Instant;

use tor_proto::ClockSkew;

/// A single observation related to reported clock skew.
#[derive(Debug, Clone)]
#[allow(dead_code)] //XXXX Nothing reads these yet.
pub(crate) struct SkewObservation {
    /// The reported clock skew
    pub(crate) skew: ClockSkew,
    /// The time when we added this observation.
    pub(crate) when: Instant,
}
