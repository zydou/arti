//! XON/XOFF stream flow control.
//!
//! See <https://spec.torproject.org/proposals/324-rtt-congestion-control.html>.

pub(crate) mod reader;
pub(super) mod state;
