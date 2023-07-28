//! Functionality for incoming streams, opened from the other side of a circuit.

#![allow(dead_code, unused_variables, clippy::needless_pass_by_value)] // TODO hss remove

use super::{AnyCmdChecker, DataStream, StreamReader, StreamStatus};
use crate::circuit::StreamTarget;
use crate::{Error, Result};
use tor_cell::relaycell::{msg, RelayCmd, UnparsedRelayCell};
use tor_cell::restricted_msg;

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
    stream: StreamTarget,
    /// The underlying `StreamReader`.
    reader: StreamReader,
}

/// A message that can be sent to begin a stream.
//
// TODO hss perhaps this should be made with restricted_msg!()
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IncomingStreamRequest {
    /// A begin cell, which requests a new data stream.
    Begin(msg::Begin),
    // TODO: Eventually, add a BeginDir variant
    // TODO: eventually, add a Resolve variant.
}

impl IncomingStream {
    /// Create a new `IncomingStream`.
    pub(crate) fn new(
        request: IncomingStreamRequest,
        stream: StreamTarget,
        reader: StreamReader,
    ) -> Self {
        Self {
            request,
            stream,
            reader,
        }
    }

    /// Return the underlying message that was used to try to begin this stream.
    pub fn request(&self) -> IncomingStreamRequest {
        todo!()
    }

    /// Accept this stream as a new [`DataStream`], and send the client a
    /// message letting them know the stream was accepted.
    pub fn accept_data(self, message: msg::Connected) -> DataStream {
        todo!()
    }

    /// Reject this request and send an error message to the client.
    pub fn reject(self, message: msg::End) {
        todo!() // TODO hss
    }

    /// Ignore this request without replying to the client.
    ///
    /// (If you drop an [`IncomingStream`] without calling `accept_data`,
    /// `reject`, or this method, the drop handler will cause it to be
    /// rejected.)
    pub fn discard(self) {
        todo!() // TODO hss
    }
}

// TODO hss: dropping an IncomingStream without accepting or rejecting it should
// cause it to call `reject`.

restricted_msg! {
    /// The allowed incoming messages on an `IncomingStream`.
    enum IncomingStreamMsg: RelayMsg {
        Begin, BeginDir, Resolve,
    }
}

/// A `CmdChecker` that enforces correctness for incoming commands on unrecognized streams that
/// have a non-zero stream ID.
#[derive(Debug)]
pub(crate) struct IncomingCmdChecker {
    /// The "begin" commands that can be received on this type of circuit:
    ///
    ///   * onion service circuits only accept `BEGIN`
    ///   * all relay circuits accept `BEGIN_DIR`
    ///   * exit relays additionally accept `BEGIN` or `RESOLVE` on relay circuits
    ///   * once CONNECT_UDP is implemented, relays and later onion services may accept CONNECT_UDP
    ///   as well
    allow_commands: Vec<RelayCmd>,
}

impl IncomingCmdChecker {
    /// Create a new boxed `IncomingCmdChecker`.
    pub(crate) fn new_any(allow_commands: &[RelayCmd]) -> AnyCmdChecker {
        // TODO HSS: avoid allocating a vec here
        Box::new(Self {
            allow_commands: allow_commands.to_vec(),
        })
    }
}

impl super::CmdChecker for IncomingCmdChecker {
    fn check_msg(&mut self, msg: &UnparsedRelayCell) -> Result<StreamStatus> {
        match msg.cmd() {
            cmd if self.allow_commands.contains(&cmd) => Ok(StreamStatus::Open),
            _ => Err(Error::StreamProto(format!(
                "Unexpected {} on incoming stream",
                msg.cmd()
            ))),
        }
    }

    fn consume_checked_msg(&mut self, msg: UnparsedRelayCell) -> Result<()> {
        let _ = msg
            .decode::<IncomingStreamMsg>()
            .map_err(|err| Error::from_bytes_err(err, "invalid message on incoming stream"))?;

        Ok(())
    }
}
