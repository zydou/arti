//! XON/XOFF stream flow control.
//!
//! See <https://spec.torproject.org/proposals/324-rtt-congestion-control.html>.

pub(crate) mod reader;
#[cfg(feature = "flowctl-cc")]
pub(super) mod state;
