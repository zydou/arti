//! Incoming data stream cell handlers, shared by the relay and onion service implementations.

use bitvec::prelude::*;
use derive_deftly::Deftly;
use oneshot_fused_workaround as oneshot;
use postage::watch;

use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::{RelayCellFormat, RelayCmd, StreamId, UnparsedRelayMsg, msg};
use tor_cell::restricted_msg;
use tor_error::internal;
use tor_memquota::derive_deftly_template_HasMemoryCost;
use tor_memquota::mq_queue::{self, MpscSpec};
use tor_rtcompat::DynTimeProvider;

use crate::circuit::CircSyncView;
use crate::stream::cmdcheck::{AnyCmdChecker, CmdChecker, StreamStatus};
use crate::stream::{CloseStreamBehavior, StreamComponents};
use crate::{Error, Result};

// TODO(relay): move these to a shared module
use crate::client::stream::DataStream;

use crate::memquota::StreamAccount;
use crate::stream::StreamMpscSender;
use crate::stream::flow_ctrl::state::StreamRateLimit;
use crate::stream::flow_ctrl::xon_xoff::reader::DrainRateRequest;
use crate::stream::queue::StreamQueueReceiver;
use crate::util::notify::NotifyReceiver;
use crate::{HopLocation, HopNum};

use std::mem::size_of;

/// A `CmdChecker` that enforces invariants for inbound data streams.
#[derive(Debug, Default)]
pub(crate) struct InboundDataCmdChecker;

restricted_msg! {
    /// An allowable incoming message on an incoming data stream.
    enum IncomingDataStreamMsg:RelayMsg {
        // SENDME is handled by the reactor.
        Data, End,
    }
}

impl CmdChecker for InboundDataCmdChecker {
    fn check_msg(&mut self, msg: &tor_cell::relaycell::UnparsedRelayMsg) -> Result<StreamStatus> {
        use StreamStatus::*;
        match msg.cmd() {
            RelayCmd::DATA => Ok(Open),
            RelayCmd::END => Ok(Closed),
            _ => Err(Error::StreamProto(format!(
                "Unexpected {} on an incoming data stream!",
                msg.cmd()
            ))),
        }
    }

    fn consume_checked_msg(&mut self, msg: tor_cell::relaycell::UnparsedRelayMsg) -> Result<()> {
        let _ = msg
            .decode::<IncomingDataStreamMsg>()
            .map_err(|err| Error::from_bytes_err(err, "cell on half-closed stream"))?;
        Ok(())
    }
}

impl InboundDataCmdChecker {
    /// Return a new boxed `DataCmdChecker` in a state suitable for a
    /// connection where an initial CONNECTED cell is not expected.
    ///
    /// This is used by hidden services, exit relays, and directory servers
    /// to accept streams.
    pub(crate) fn new_connected() -> AnyCmdChecker {
        Box::new(Self)
    }
}

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

impl CmdChecker for IncomingCmdChecker {
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
        circ: &CircSyncView<'_>,
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

/// Information about an incoming stream request.
#[derive(Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub(crate) struct StreamReqInfo {
    /// The [`IncomingStreamRequest`].
    pub(crate) req: IncomingStreamRequest,
    /// The ID of the stream being requested.
    pub(crate) stream_id: StreamId,
    /// The [`HopNum`].
    ///
    /// Set to `None` if we are an exit relay.
    //
    // TODO: For onion services, we might be able to enforce the HopNum earlier: we would never accept an
    // incoming stream request from two separate hops.  (There is only one that's valid.)
    pub(crate) hop: Option<HopLocation>,
    /// The format which must be used with this stream to encode messages.
    #[deftly(has_memory_cost(indirect_size = "0"))]
    pub(crate) relay_cell_format: RelayCellFormat,
    /// A channel for receiving messages from this stream.
    #[deftly(has_memory_cost(indirect_size = "0"))] // estimate
    pub(crate) receiver: StreamQueueReceiver,
    /// A channel for sending messages to be sent on this stream.
    #[deftly(has_memory_cost(indirect_size = "size_of::<AnyRelayMsg>()"))] // estimate
    pub(crate) msg_tx: StreamMpscSender<AnyRelayMsg>,
    /// A [`Stream`](futures::Stream) that provides updates to the rate limit for sending data.
    // TODO(arti#2068): we should consider making this an `Option`
    // the `watch::Sender` owns the indirect data
    #[deftly(has_memory_cost(indirect_size = "0"))]
    pub(crate) rate_limit_stream: watch::Receiver<StreamRateLimit>,
    /// A [`Stream`](futures::Stream) that provides notifications when a new drain rate is
    /// requested.
    #[deftly(has_memory_cost(indirect_size = "0"))]
    pub(crate) drain_rate_request_stream: NotifyReceiver<DrainRateRequest>,
    /// The memory quota account to be used for this stream
    #[deftly(has_memory_cost(indirect_size = "0"))] // estimate (it contains an Arc)
    pub(crate) memquota: StreamAccount,
}

/// MPSC queue containing stream requests
#[cfg(any(feature = "hs-service", feature = "relay"))]
pub(crate) type StreamReqSender = mq_queue::Sender<StreamReqInfo, MpscSpec>;

/// Data required for handling an incoming stream request.
#[derive(educe::Educe)]
#[educe(Debug)]
#[cfg(any(feature = "hs-service", feature = "relay"))]
pub(crate) struct IncomingStreamRequestHandler {
    /// A sender for sharing information about an incoming stream request.
    pub(crate) incoming_sender: StreamReqSender,
    /// The hop to expect incoming stream requests from.
    ///
    /// Set to `None` if we are a relay.
    pub(crate) hop_num: Option<HopNum>,
    /// A [`CmdChecker`] for validating incoming streams.
    pub(crate) cmd_checker: AnyCmdChecker,
    /// An [`IncomingStreamRequestFilter`] for checking whether the user wants
    /// this request, or wants to reject it immediately.
    #[educe(Debug(ignore))]
    pub(crate) filter: Box<dyn IncomingStreamRequestFilter>,
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
    #![allow(clippy::unchecked_time_subtraction)]
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
