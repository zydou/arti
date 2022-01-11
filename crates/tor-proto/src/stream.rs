//! Implements Tor's "stream"s from a client perspective
//!
//! A stream is an anonymized conversation; multiple streams can be
//! multiplexed over a single circuit.
//!
//! To create a stream, use [crate::circuit::ClientCirc::begin_stream].
//!
//! # Limitations
//!
//! There is no fairness, rate-limiting, or flow control.

mod data;
mod params;
mod raw;
mod resolve;

pub use data::{DataReader, DataStream, DataWriter};
pub use params::StreamParameters;
pub use raw::StreamReader;
pub use resolve::ResolveStream;

pub use tor_cell::relaycell::msg::IpVersionPreference;
