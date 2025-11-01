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
mod params;
mod resolve;

#[cfg(feature = "hs-service")]
#[cfg_attr(docsrs, doc(cfg(feature = "hs-service")))]
pub(crate) use crate::stream::incoming::IncomingCmdChecker;
pub use data::{DataReader, DataStream, DataWriter};

// TODO(relay): stop reexporting these from here
#[cfg(feature = "hs-service")]
pub use crate::stream::incoming::{
    IncomingStream, IncomingStreamRequest, IncomingStreamRequestContext,
    IncomingStreamRequestDisposition, IncomingStreamRequestFilter,
};
pub use crate::stream::raw::StreamReceiver;
pub use params::StreamParameters;
pub use resolve::ResolveStream;
pub(crate) use {data::OutboundDataCmdChecker, resolve::ResolveCmdChecker};

#[cfg(feature = "hs-service")]
pub(crate) use crate::stream::incoming::InboundDataCmdChecker;

pub use tor_cell::relaycell::msg::IpVersionPreference;

#[cfg(feature = "stream-ctrl")]
pub use {ctrl::ClientStreamCtrl, data::ClientDataStreamCtrl};
