//! Functionality for incoming streams, opened from the other side of a circuit.

#![allow(
    dead_code,
    unused_variables,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)] // TODO hs remove

use super::DataStream;

/// A pending request from the other end of the circuit for us to open a new
/// stream.
///
/// Exits, directory caches, and onion services expect to receive these; others
/// do not.
///
/// On receiving one of these objects, the party handling it should accept it or
/// reject it.  If it is dropped without being explicitly handled, a reject
/// message will be sent anyway.
#[derive(Debug)]
pub struct IncomingStream {
    /// The message that the client sent us to begin the stream.
    request: IncomingStreamRequest,
    /// The information that we'll use to wire up the stream, if it is accepted.
    stream: crate::circuit::StreamTarget,
}

/// A message that can be sent to begin a stream.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IncomingStreamRequest {
    /// A begin cell, which requests a new data stream.
    Begin(tor_cell::relaycell::msg::Begin),
    // TODO: Eventually, add a BeginDir variant
    // TODO: eventually, add a Resolve variant.
}

impl IncomingStream {
    /// Return the underlying message that was used to try to begin this stream.
    pub fn request(&self) -> IncomingStreamRequest {
        todo!()
    }

    /// Accept this stream as a new [`DataStream`], and send the client a
    /// message letting them know the stream was accepted.
    pub fn accept_data(self, message: tor_cell::relaycell::msg::Connected) -> DataStream {
        todo!()
    }

    /// Reject this request and send an error message to the client.
    pub fn reject(self, message: tor_cell::relaycell::msg::End) {
        todo!() // TODO hs
    }

    /// Ignore this request without replying to the client.
    ///
    /// (If you drop an [`IncomingStream`] without calling `accept_data`,
    /// `reject`, or this method, the drop handler will cause it to be
    /// rejected.)
    pub fn discard(self) {
        todo!() // TODO hs
    }
}

// TODO hs: dropping an IncomingStream without accepting or rejecting it should
// cause it to call `reject`.
