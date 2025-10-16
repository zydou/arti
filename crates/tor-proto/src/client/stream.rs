//! Implements Tor's "stream"s from a client perspective
//!
//! A stream is an anonymized conversation; multiple streams can be
//! multiplexed over a single circuit.
//!
//! To create a stream, use [crate::client::ClientTunnel::begin_stream].
//!
//! # Limitations
//!
//! There is no fairness, rate-limiting, or flow control.

#[cfg(feature = "stream-ctrl")]
mod ctrl;
mod data;
#[cfg(feature = "hs-service")]
mod incoming;
mod params;
pub(crate) mod queue;
mod raw;
mod resolve;

pub use data::{DataReader, DataStream, DataWriter};
#[cfg(feature = "hs-service")]
#[cfg_attr(docsrs, doc(cfg(feature = "hs-service")))]
pub(crate) use incoming::IncomingCmdChecker;
#[cfg(feature = "hs-service")]
#[cfg_attr(docsrs, doc(cfg(feature = "hs-service")))]
pub use incoming::{
    IncomingStream, IncomingStreamRequest, IncomingStreamRequestContext,
    IncomingStreamRequestDisposition, IncomingStreamRequestFilter,
};
pub use params::StreamParameters;
pub use raw::StreamReceiver;
pub use resolve::ResolveStream;
pub(crate) use {data::DataCmdChecker, resolve::ResolveCmdChecker};

pub use tor_cell::relaycell::msg::IpVersionPreference;

#[cfg(feature = "stream-ctrl")]
#[cfg_attr(docsrs, doc(cfg(feature = "stream-ctrl")))]
pub use {ctrl::ClientStreamCtrl, data::ClientDataStreamCtrl};
