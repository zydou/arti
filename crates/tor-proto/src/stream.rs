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

mod cmdcheck;
mod data;
#[cfg(feature = "hs-service")]
mod incoming;
mod params;
mod raw;
mod resolve;

pub(crate) use cmdcheck::{AnyCmdChecker, CmdChecker, StreamStatus};
pub use data::{DataReader, DataStream, DataWriter};
#[cfg(feature = "hs-service")]
#[cfg_attr(docsrs, doc(cfg(feature = "hs-service")))]
pub use incoming::{IncomingStream, IncomingStreamRequest};
pub use params::StreamParameters;
pub use raw::StreamReader;
pub use resolve::ResolveStream;
pub(crate) use {data::DataCmdChecker, resolve::ResolveCmdChecker};

pub use tor_cell::relaycell::msg::IpVersionPreference;
