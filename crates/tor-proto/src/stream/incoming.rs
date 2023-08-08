//! Functionality for incoming streams, opened from the other side of a circuit.

#![allow(dead_code, unused_variables, clippy::needless_pass_by_value)] // TODO hss remove

use super::{AnyCmdChecker, DataStream, StreamReader, StreamStatus};
use crate::circuit::StreamTarget;
use crate::{Error, Result};
use tor_cell::relaycell::{msg, RelayCmd, UnparsedRelayCell};
use tor_cell::restricted_msg;
use tor_error::internal;

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
    /// The inner state, which contains the reader and writer of this stream.
    ///
    /// This is an `Option` because we need to be able to "take" the reader/writer of the stream
    /// out of the `IncomingStream` to construct a [`DataStream`] in [`IncomingStream::accept_data`].
    ///
    /// Note: we can't move the reader/writer out of `self` because `IncomingStream` implements
    /// `Drop` (so as a workaround we use [`Option::take`]).
    inner: Option<IncomingStreamInner>,
    /// Whether we have rejected the stream using [`StreamTarget::close`].
    ///
    /// If set to `true`, any attempts to use this `IncomingStream` will return an error.
    is_rejected: bool,
    /// Whether we have accepted the stream using [`StreamTarget::accept_data`].
    is_accepted: bool,
}

/// The inner state of an [`IncomingStream`], which contains its reader and writer.
#[derive(Debug)]
struct IncomingStreamInner {
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
        let inner = IncomingStreamInner { stream, reader };
        Self {
            request,
            inner: Some(inner),
            is_rejected: false,
            is_accepted: false,
        }
    }

    /// Return the underlying message that was used to try to begin this stream.
    pub fn request(&self) -> &IncomingStreamRequest {
        &self.request
    }

    /// Whether we have rejected this `IncomingStream` using [`IncomingStream::reject`].
    pub fn is_rejected(&self) -> bool {
        self.is_rejected
    }

    /// Accept this stream as a new [`DataStream`], and send the client a
    /// message letting them know the stream was accepted.
    pub async fn accept_data(mut self, message: msg::Connected) -> Result<DataStream> {
        if self.is_rejected {
            return Err(internal!("Cannot accept data on a closed stream").into());
        }

        self.is_accepted = true;
        let mut inner = self.take_inner()?;

        match self.request {
            IncomingStreamRequest::Begin(_) => {
                inner.stream.send(message.into()).await?;
                Ok(DataStream::new_connected(inner.reader, inner.stream))
            } // TODO HSS: return an error if the request was RESOLVE, or any other request that
              // we cannot respond with CONNECTED to
        }
    }

    /// Reject this request and send an error message to the client.
    pub async fn reject(&mut self, message: msg::End) -> Result<()> {
        if self.is_rejected {
            return Err(internal!("IncomingStream::reject() called twice").into());
        }

        self.is_rejected = true;
        self.mut_inner()?.stream.close(message).await
    }

    /// Like `[IncomingStream::reject`], except this uses [`StreamTarget::close_nonblocking`]
    /// instead of [`StreamTarget::close`].
    ///
    /// This is used for implementing `Drop`.
    fn reject_nonblocking(&mut self, message: msg::End) -> Result<()> {
        if self.is_rejected {
            return Err(internal!("IncomingStream::reject() called twice").into());
        }

        self.is_rejected = true;
        self.mut_inner()?.stream.close_nonblocking(message)
    }

    /// Ignore this request without replying to the client.
    ///
    /// (If you drop an [`IncomingStream`] without calling `accept_data`,
    /// `reject`, or this method, the drop handler will cause it to be
    /// rejected.)
    pub fn discard(self) {
        todo!() // TODO hss
    }

    /// Take the inner state out of `IncomingStream`.
    ///
    /// Returns an error if `inner` is `None` (this should never happen unless we have a bug in our
    /// code).
    fn take_inner(&mut self) -> Result<IncomingStreamInner> {
        let _: &mut _ = self.mut_inner()?;

        Ok(self
            .inner
            .take()
            .expect("inner None though we just checked it"))
    }

    /// Return a mutable reference to the inner state of `IncomingStream`.
    ///
    /// Returns an error if `inner` is `None` (this should never happen unless we have a bug in our
    /// code).
    fn mut_inner(&mut self) -> Result<&mut IncomingStreamInner> {
        self.inner
            .as_mut()
            .ok_or_else(|| internal!("Cannot use a stream that has already been consumed").into())
    }
}

impl Drop for IncomingStream {
    fn drop(&mut self) {
        if !self.is_rejected && !self.is_accepted {
            // Disregard any errors.
            let _ = self.reject_nonblocking(msg::End::new_misc());
        }
    }
}

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
