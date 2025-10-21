//! Tor stream handling.
//!
//! A stream is an anonymized conversation; multiple streams can be
//! multiplexed over a single circuit.

pub(crate) mod cmdcheck;
pub(crate) mod flow_ctrl;

#[cfg(any(feature = "hs-service", feature = "relay"))]
pub(crate) mod incoming;

pub(crate) mod queue;
