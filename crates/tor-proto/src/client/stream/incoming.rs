//! Functionality for incoming streams, opened from the other side of a circuit.

use bitvec::prelude::*;

use super::DataStream;
use crate::stream::cmdcheck::{AnyCmdChecker, StreamStatus};
use crate::client::StreamComponents;
use crate::client::circuit::ClientCircSyncView;
use crate::client::reactor::CloseStreamBehavior;
use crate::{Error, Result};
use derive_deftly::Deftly;
use oneshot_fused_workaround as oneshot;
use tor_cell::relaycell::{RelayCmd, UnparsedRelayMsg, msg};
use tor_cell::restricted_msg;
use tor_error::internal;
use tor_memquota::derive_deftly_template_HasMemoryCost;
use tor_rtcompat::DynTimeProvider;

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
    /// The runtime's time provider.
    time_provider: DynTimeProvider,
    /// The message that the client sent us to begin the stream.
    request: IncomingStreamRequest,
    /// Stream components used to assemble the [`DataStream`].
    components: StreamComponents,
}

impl IncomingStream {
    /// Create a new `IncomingStream`.
    pub(crate) fn new(
        time_provider: DynTimeProvider,
        request: IncomingStreamRequest,
        components: StreamComponents,
    ) -> Self {
        Self {
            time_provider,
            request,
            components,
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
            time_provider,
            request,
            components:
                StreamComponents {
                    mut target,
                    stream_receiver,
                    xon_xoff_reader_ctrl,
                    memquota,
                },
        } = self;

        match request {
            IncomingStreamRequest::Begin(_) | IncomingStreamRequest::BeginDir(_) => {
                target.send(message.into()).await?;
                Ok(DataStream::new_connected(
                    time_provider,
                    stream_receiver,
                    xon_xoff_reader_ctrl,
                    target,
                    memquota,
                ))
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
        self.components.target.close_pending(message)
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
    #[derive(Clone, Debug, Deftly)]
    #[derive_deftly(HasMemoryCost)]
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
    ///     as well
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

impl crate::stream::cmdcheck::CmdChecker for IncomingCmdChecker {
    fn check_msg(&mut self, msg: &UnparsedRelayMsg) -> Result<StreamStatus> {
        if self.allow_commands[u8::from(msg.cmd()) as usize] {
            Ok(StreamStatus::Open)
        } else {
            Err(Error::StreamProto(format!(
                "Unexpected {} on incoming stream",
                msg.cmd()
            )))
        }
    }

    fn consume_checked_msg(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        let _ = msg
            .decode::<IncomingStreamRequest>()
            .map_err(|err| Error::from_bytes_err(err, "invalid message on incoming stream"))?;

        Ok(())
    }
}

/// A callback that can check whether a given stream request is acceptable
/// immediately on its receipt.
///
/// This should only be used for checks that need to be done immediately, with a
/// view of the state of the circuit.  Any other checks should, if possible, be
/// done on the [`IncomingStream`] objects as they are received.
pub trait IncomingStreamRequestFilter: Send + 'static {
    /// Check an incoming stream request, and decide what to do with it.
    ///
    /// Implementations of this function should
    fn disposition(
        &mut self,
        ctx: &IncomingStreamRequestContext<'_>,
        circ: &ClientCircSyncView<'_>,
    ) -> Result<IncomingStreamRequestDisposition>;
}

/// What action to take with an incoming stream request.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum IncomingStreamRequestDisposition {
    /// Accept the request (for now) and pass it to the mpsc::Receiver
    /// that is yielding them as [`IncomingStream``
    Accept,
    /// Rejected the request, and close the circuit on which it was received.
    CloseCircuit,
    /// Reject the request and send an END message.
    RejectRequest(msg::End),
}

/// Information about a stream request, as passed to an [`IncomingStreamRequestFilter`].
pub struct IncomingStreamRequestContext<'a> {
    /// The request message itself
    pub(crate) request: &'a IncomingStreamRequest,
}

impl<'a> IncomingStreamRequestContext<'a> {
    /// Return a reference to the message used to request this stream.
    pub fn request(&self) -> &'a IncomingStreamRequest {
        self.request
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use tor_cell::relaycell::{
        AnyRelayMsgOuter, RelayCellFormat,
        msg::{Begin, BeginDir, Data, Resolve},
    };

    use super::*;

    #[test]
    fn incoming_cmd_checker() {
        // Convert an AnyRelayMsg to an UnparsedRelayCell.
        let u = |msg| {
            let body = AnyRelayMsgOuter::new(None, msg)
                .encode(RelayCellFormat::V0, &mut rand::rng())
                .unwrap();
            UnparsedRelayMsg::from_singleton_body(RelayCellFormat::V0, body).unwrap()
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
