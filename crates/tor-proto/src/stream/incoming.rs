//! Functionality for incoming streams, opened from the other side of a circuit.

use bitvec::prelude::*;

use super::{AnyCmdChecker, DataStream, StreamReader, StreamStatus};
use crate::circuit::reactor::CloseStreamBehavior;
use crate::circuit::StreamTarget;
use crate::{Error, Result};
use tor_async_utils::oneshot;
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
    /// The information that we'll use to wire up the stream, if it is accepted.
    stream: StreamTarget,
    /// The underlying `StreamReader`.
    reader: StreamReader,
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
    pub fn request(&self) -> &IncomingStreamRequest {
        &self.request
    }

    /// Accept this stream as a new [`DataStream`], and send the client a
    /// message letting them know the stream was accepted.
    pub async fn accept_data(self, message: msg::Connected) -> Result<DataStream> {
        let Self {
            request,
            mut stream,
            reader,
        } = self;

        match request {
            IncomingStreamRequest::Begin(_) | IncomingStreamRequest::BeginDir(_) => {
                stream.send(message.into()).await?;
                Ok(DataStream::new_connected(reader, stream))
            }
            IncomingStreamRequest::Resolve(_) => {
                Err(internal!("Cannot accept data on a RESOLVE stream").into())
            }
        }
    }

    /// Reject this request and send an error message to the client.
    pub async fn reject(mut self, message: msg::End) -> Result<()> {
        let rx = self.reject_inner(CloseStreamBehavior::SendEnd(message))?;

        rx.await.map_err(|_| Error::CircuitClosed)?.map(|_| ())
    }

    /// Reject this request and possibly send an error message to the client.
    ///
    /// Returns a [`oneshot::Receiver`] that can be used to await the reactor's response.
    fn reject_inner(
        &mut self,
        message: CloseStreamBehavior,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        self.stream.close_pending(message)
    }

    /// Ignore this request without replying to the client.
    ///
    /// (If you drop an [`IncomingStream`] without calling `accept_data`,
    /// `reject`, or this method, the drop handler will cause it to be
    /// rejected.)
    pub async fn discard(mut self) -> Result<()> {
        let rx = self.reject_inner(CloseStreamBehavior::SendNothing)?;

        rx.await.map_err(|_| Error::CircuitClosed)?.map(|_| ())
    }
}

// NOTE: We do not need to `impl Drop for IncomingStream { .. }`: when its
// StreamTarget is dropped, this will drop its internal mpsc::Sender, and the
// circuit reactor will see a close on its mpsc::Receiver, and the circuit
// reactor will itself send an End.

restricted_msg! {
    /// The allowed incoming messages on an `IncomingStream`.
    #[derive(Clone, Debug)]
    #[non_exhaustive]
    pub enum IncomingStreamRequest: RelayMsg {
        /// A BEGIN message.
        Begin,
        /// A BEGIN_DIR message.
        BeginDir,
        /// A RESOLVE message.
        Resolve,
    }
}

/// Bit-vector used to represent a list of permitted commands.
///
/// This is cheaper and faster than using a vec, and avoids side-channel
/// attacks.
type RelayCmdSet = bitvec::BitArr!(for 256);

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
    allow_commands: RelayCmdSet,
}

impl IncomingCmdChecker {
    /// Create a new boxed `IncomingCmdChecker`.
    pub(crate) fn new_any(allow_commands: &[RelayCmd]) -> AnyCmdChecker {
        let mut array = BitArray::ZERO;
        for c in allow_commands {
            array.set(u8::from(*c) as usize, true);
        }
        Box::new(Self {
            allow_commands: array,
        })
    }
}

impl super::CmdChecker for IncomingCmdChecker {
    fn check_msg(&mut self, msg: &UnparsedRelayCell) -> Result<StreamStatus> {
        if self.allow_commands[u8::from(msg.cmd()) as usize] {
            Ok(StreamStatus::Open)
        } else {
            Err(Error::StreamProto(format!(
                "Unexpected {} on incoming stream",
                msg.cmd()
            )))
        }
    }

    fn consume_checked_msg(&mut self, msg: UnparsedRelayCell) -> Result<()> {
        let _ = msg
            .decode::<IncomingStreamRequest>()
            .map_err(|err| Error::from_bytes_err(err, "invalid message on incoming stream"))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use tor_cell::relaycell::{
        msg::{Begin, BeginDir, Data, Resolve},
        AnyRelayMsgOuter,
    };

    use super::*;

    #[test]
    fn incoming_cmd_checker() {
        // Convert an AnyRelayMsg to an UnparsedRelayCell.
        let u = |msg| {
            let body = AnyRelayMsgOuter::new(None, msg)
                .encode(&mut rand::thread_rng())
                .unwrap();
            UnparsedRelayCell::from_body(body)
        };
        let begin = u(Begin::new("allium.example.com", 443, 0).unwrap().into());
        let begin_dir = u(BeginDir::default().into());
        let resolve = u(Resolve::new("allium.example.com").into());
        let data = u(Data::new(&[1, 2, 3]).unwrap().into());

        {
            let mut cc_none = IncomingCmdChecker::new_any(&[]);
            for m in [&begin, &begin_dir, &resolve, &data] {
                assert!(cc_none.check_msg(m).is_err());
            }
        }

        {
            let mut cc_begin = IncomingCmdChecker::new_any(&[RelayCmd::BEGIN]);
            assert_eq!(cc_begin.check_msg(&begin).unwrap(), StreamStatus::Open);
            for m in [&begin_dir, &resolve, &data] {
                assert!(cc_begin.check_msg(m).is_err());
            }
        }

        {
            let mut cc_any = IncomingCmdChecker::new_any(&[
                RelayCmd::BEGIN,
                RelayCmd::BEGIN_DIR,
                RelayCmd::RESOLVE,
            ]);
            for m in [&begin, &begin_dir, &resolve] {
                assert_eq!(cc_any.check_msg(m).unwrap(), StreamStatus::Open);
            }
            assert!(cc_any.check_msg(&data).is_err());
        }
    }
}
