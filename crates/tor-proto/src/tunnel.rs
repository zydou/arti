//! Tunnel module that will encompass a generic tunnel wrapping around a circuit reactor that can
//! be single or multi path.

pub mod circuit;
mod halfstream;
#[cfg(feature = "send-control-msg")]
pub(crate) mod msghandler;
pub(crate) mod reactor;
mod streammap;

use derive_deftly::Deftly;
use derive_more::Display;
use futures::SinkExt as _;
use oneshot_fused_workaround as oneshot;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::congestion::sendme::StreamRecvWindow;
use crate::crypto::cell::HopNum;
use crate::memquota::{SpecificAccount as _, StreamAccount};
use crate::stream::queue::stream_queue;
use crate::stream::xon_xoff::XonXoffReaderCtrl;
use crate::stream::{
    AnyCmdChecker, DataCmdChecker, DataStream, ResolveCmdChecker, ResolveStream, StreamParameters,
    StreamRateLimit, StreamReceiver,
};
use crate::util::notify::NotifySender;
use crate::{Error, ResolveError, Result};
use circuit::{CIRCUIT_BUFFER_SIZE, ClientCirc, Path, StreamMpscSender, UniqId};
use reactor::{
    CtrlCmd, CtrlMsg, FlowCtrlMsg, MetaCellHandler, RECV_WINDOW_INIT, STREAM_READER_BUFFER,
};

use postage::watch;
use tor_async_utils::SinkCloseChannel as _;
use tor_cell::relaycell::flow_ctrl::XonKbpsEwma;
use tor_cell::relaycell::msg::{AnyRelayMsg, Begin, Resolve, Resolved, ResolvedVal};
use tor_cell::relaycell::{RelayCellFormat, StreamId};
use tor_error::bad_api_usage;
use tor_linkspec::OwnedChanTarget;
use tor_memquota::derive_deftly_template_HasMemoryCost;
use tor_memquota::mq_queue::{ChannelSpec as _, MpscSpec};

#[cfg(feature = "hs-service")]
use {
    crate::stream::{IncomingCmdChecker, IncomingStream},
    crate::tunnel::reactor::StreamReqInfo,
};

#[cfg(feature = "send-control-msg")]
use msghandler::{MsgHandler, UserMsgHandler};

/// The unique identifier of a tunnel.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display)]
#[display("{}", _0)]
pub(crate) struct TunnelId(u64);

impl TunnelId {
    /// Create a new TunnelId.
    ///
    /// # Panics
    ///
    /// Panics if we have exhausted the possible space of u64 IDs.
    pub(crate) fn next() -> TunnelId {
        /// The next unique tunnel ID.
        static NEXT_TUNNEL_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_TUNNEL_ID.fetch_add(1, Ordering::Relaxed);
        assert!(id != 0, "Exhausted Tunnel ID space?!");
        TunnelId(id)
    }
}

/// The identifier of a circuit [`UniqId`] within a tunnel.
///
/// This type is only needed for logging purposes: a circuit's [`UniqId`] is
/// process-unique, but in the logs it's often useful to display the
/// owning tunnel's ID alongside the circuit identifier.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display)]
#[display("Circ {}.{}", tunnel_id, circ_id.display_chan_circ())]
pub(crate) struct TunnelScopedCircId {
    /// The identifier of the owning tunnel
    tunnel_id: TunnelId,
    /// The process-unique identifier of the circuit
    circ_id: UniqId,
}

impl TunnelScopedCircId {
    /// Create a new [`TunnelScopedCircId`] from the specified identifiers.
    pub(crate) fn new(tunnel_id: TunnelId, circ_id: UniqId) -> Self {
        Self { tunnel_id, circ_id }
    }

    /// Return the [`UniqId`].
    pub(crate) fn unique_id(&self) -> UniqId {
        self.circ_id
    }
}

/// Handle to use during an ongoing protocol exchange with a circuit's last hop
///
/// This is obtained from [`ClientTunnel::start_conversation`],
/// and used to send messages to the last hop relay.
//
// TODO(conflux): this should use ClientTunnel, and it should be moved into
// the tunnel module.
#[cfg(feature = "send-control-msg")]
#[cfg_attr(docsrs, doc(cfg(feature = "send-control-msg")))]
pub struct Conversation<'r>(&'r ClientTunnel);

#[cfg(feature = "send-control-msg")]
#[cfg_attr(docsrs, doc(cfg(feature = "send-control-msg")))]
impl Conversation<'_> {
    /// Send a protocol message as part of an ad-hoc exchange
    ///
    /// Responses are handled by the `UserMsgHandler` set up
    /// when the `Conversation` was created.
    pub async fn send_message(&self, msg: tor_cell::relaycell::msg::AnyRelayMsg) -> Result<()> {
        self.send_internal(Some(msg), None).await
    }

    /// Send a `SendMsgAndInstallHandler` to the reactor and wait for the outcome
    ///
    /// The guts of `start_conversation` and `Conversation::send_msg`
    pub(crate) async fn send_internal(
        &self,
        msg: Option<tor_cell::relaycell::msg::AnyRelayMsg>,
        handler: Option<Box<dyn MetaCellHandler + Send + 'static>>,
    ) -> Result<()> {
        let msg = msg.map(|msg| tor_cell::relaycell::AnyRelayMsgOuter::new(None, msg));
        let (sender, receiver) = oneshot::channel();

        let ctrl_msg = CtrlMsg::SendMsgAndInstallHandler {
            msg,
            handler,
            sender,
        };
        self.0
            .circ
            .control
            .unbounded_send(ctrl_msg)
            .map_err(|_| Error::CircuitClosed)?;

        receiver.await.map_err(|_| Error::CircuitClosed)?
    }
}

/// A low-level client tunnel API.
///
/// This is a communication channel to the tunnel reactor, which manages 1 or more circuits.
///
/// Note: the tor-circmgr crates wrap this type in specialized *Tunnel types exposing only the
/// desired subset of functionality depending on purpose and path size.
///
/// Some API calls are for single path and some for multi path. A check with the underlying reactor
/// is done preventing for instance multi path calls to be used on a single path. Top level types
/// should prevent this and thus this object should never be used directly.
#[derive(Debug)]
#[allow(dead_code)] // TODO(conflux)
pub struct ClientTunnel {
    /// The underlying handle to the reactor.
    circ: ClientCirc,
}

impl ClientTunnel {
    /// Return a handle to the `ClientCirc` of this `ClientTunnel`, if the tunnel is a single
    /// circuit tunnel.
    ///
    /// Returns an error if the tunnel has more than one circuit.
    pub fn as_single_circ(&self) -> Result<&ClientCirc> {
        if self.circ.is_multi_path {
            return Err(bad_api_usage!("Single circuit getter on multi path tunnel"))?;
        }
        Ok(&self.circ)
    }

    /// Return the channel target of the first hop.
    ///
    /// Can only be used for single path tunnel.
    pub fn first_hop(&self) -> Result<OwnedChanTarget> {
        self.as_single_circ()?.first_hop()
    }

    /// Return true if the circuit reactor is closed meaning the circuit is unusable for both
    /// receiving or sending.
    pub fn is_closed(&self) -> bool {
        self.circ.is_closing()
    }

    /// Return a [`TargetHop`] representing precisely the last hop of the circuit as in set as a
    /// HopLocation with its id and hop number.
    ///
    /// Return an error if there is no last hop.
    pub fn last_hop(&self) -> Result<TargetHop> {
        let uniq_id = self.unique_id();
        let hop_num = self
            .circ
            .mutable
            .last_hop_num(uniq_id)?
            .ok_or_else(|| bad_api_usage!("no last hop"))?;
        Ok((uniq_id, hop_num).into())
    }

    /// Return a description of the last hop of the tunnel.
    ///
    /// Return None if the last hop is virtual; return an error
    /// if the tunnel has no circuits, or all of its circuits are zero length.
    ///
    ///
    /// # Panics
    ///
    /// Panics if there is no last hop.  (This should be impossible outside of
    /// the tor-proto crate, but within the crate it's possible to have a
    /// circuit with no hops.)
    pub fn last_hop_info(&self) -> Result<Option<OwnedChanTarget>> {
        self.circ.last_hop_info()
    }

    /// Return the number of hops this tunnel as. Fail for a multi path.
    pub fn n_hops(&self) -> Result<usize> {
        self.as_single_circ()?.n_hops()
    }

    /// Return the [`Path`] objects describing all the hops
    /// of all the circuits in this tunnel.
    pub fn all_paths(&self) -> Vec<Arc<Path>> {
        self.circ.all_paths()
    }

    /// Return a process-unique identifier for this tunnel.
    ///
    /// Returns the reactor unique ID of the main reactor.
    pub fn unique_id(&self) -> UniqId {
        self.circ.unique_id()
    }

    /// Return a future that will resolve once the underlying circuit reactor has closed.
    ///
    /// Note that this method does not itself cause the tunnel to shut down.
    pub fn wait_for_close(
        self: &Arc<Self>,
    ) -> impl futures::Future<Output = ()> + Send + Sync + 'static + use<> {
        self.circ.wait_for_close()
    }

    /// Single-path tunnel only. Multi path onion service is not supported yet.
    ///
    /// Tell this tunnel to begin allowing the final hop of the tunnel to try
    /// to create new Tor streams, and to return those pending requests in an
    /// asynchronous stream.
    ///
    /// Ordinarily, these requests are rejected.
    ///
    /// There can only be one [`Stream`](futures::Stream) of this type created on a given tunnel.
    /// If a such a [`Stream`](futures::Stream) already exists, this method will return
    /// an error.
    ///
    /// After this method has been called on a tunnel, the tunnel is expected
    /// to receive requests of this type indefinitely, until it is finally closed.
    /// If the `Stream` is dropped, the next request on this tunnel will cause it to close.
    ///
    /// Only onion services (and eventually) exit relays should call this
    /// method.
    //
    // TODO: Someday, we might want to allow a stream request handler to be
    // un-registered.  However, nothing in the Tor protocol requires it.
    //
    // Any incoming request handlers installed on the other circuits
    // (which are are shutdown using CtrlCmd::ShutdownAndReturnCircuit)
    // will be discarded (along with the reactor of that circuit)
    #[cfg(feature = "hs-service")]
    #[allow(unreachable_code, unused_variables)] // TODO(conflux)
    pub async fn allow_stream_requests<'a, FILT>(
        self: &Arc<Self>,
        allow_commands: &'a [tor_cell::relaycell::RelayCmd],
        hop: TargetHop,
        filter: FILT,
    ) -> Result<impl futures::Stream<Item = IncomingStream> + use<'a, FILT>>
    where
        FILT: crate::stream::IncomingStreamRequestFilter + 'a,
    {
        use futures::stream::StreamExt;

        /// The size of the channel receiving IncomingStreamRequestContexts.
        const INCOMING_BUFFER: usize = STREAM_READER_BUFFER;

        // TODO(#2002): support onion service conflux
        let circ = self.as_single_circ().map_err(tor_error::into_internal!(
            "Cannot allow stream requests on a multi-path tunnel"
        ))?;

        let time_prov = circ.time_provider.clone();
        let cmd_checker = IncomingCmdChecker::new_any(allow_commands);
        let (incoming_sender, incoming_receiver) = MpscSpec::new(INCOMING_BUFFER)
            .new_mq(time_prov.clone(), circ.memquota.as_raw_account())?;
        let (tx, rx) = oneshot::channel();

        circ.command
            .unbounded_send(CtrlCmd::AwaitStreamRequest {
                cmd_checker,
                incoming_sender,
                hop,
                done: tx,
                filter: Box::new(filter),
            })
            .map_err(|_| Error::CircuitClosed)?;

        // Check whether the AwaitStreamRequest was processed successfully.
        rx.await.map_err(|_| Error::CircuitClosed)??;

        let allowed_hop_loc: HopLocation = match hop {
            TargetHop::Hop(loc) => Some(loc),
            _ => None,
        }
        .ok_or_else(|| bad_api_usage!("Expected TargetHop with HopLocation"))?;

        let tunnel = self.clone();
        Ok(incoming_receiver.map(move |req_ctx| {
            let StreamReqInfo {
                req,
                stream_id,
                hop,
                receiver,
                msg_tx,
                rate_limit_stream,
                drain_rate_request_stream,
                memquota,
                relay_cell_format,
            } = req_ctx;

            // We already enforce this in handle_incoming_stream_request; this
            // assertion is just here to make sure that we don't ever
            // accidentally remove or fail to enforce that check, since it is
            // security-critical.
            assert_eq!(allowed_hop_loc, hop);

            // TODO(#2002): figure out what this is going to look like
            // for onion services (perhaps we should forbid this function
            // from being called on a multipath circuit?)
            //
            // See also:
            // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3002#note_3200937
            let target = StreamTarget {
                tunnel: tunnel.clone(),
                tx: msg_tx,
                hop: allowed_hop_loc,
                stream_id,
                relay_cell_format,
                rate_limit_stream,
            };

            // can be used to build a reader that supports XON/XOFF flow control
            let xon_xoff_reader_ctrl =
                XonXoffReaderCtrl::new(drain_rate_request_stream, target.clone());

            let reader = StreamReceiver {
                target: target.clone(),
                receiver,
                recv_window: StreamRecvWindow::new(RECV_WINDOW_INIT),
                ended: false,
            };

            let components = StreamComponents {
                stream_receiver: reader,
                target,
                memquota,
                xon_xoff_reader_ctrl,
            };

            IncomingStream::new(time_prov.clone(), req, components)
        }))
    }

    /// Single and Multi path helper, used to begin a stream.
    ///
    /// This function allocates a stream ID, and sends the message
    /// (like a BEGIN or RESOLVE), but doesn't wait for a response.
    ///
    /// The caller will typically want to see the first cell in response,
    /// to see whether it is e.g. an END or a CONNECTED.
    #[allow(unreachable_code, unused_variables)] // TODO(conflux)
    async fn begin_stream_impl(
        self: &Arc<Self>,
        begin_msg: AnyRelayMsg,
        cmd_checker: AnyCmdChecker,
    ) -> Result<StreamComponents> {
        // TODO: Possibly this should take a hop, rather than just
        // assuming it's the last hop.
        let hop = TargetHop::LastHop;

        let time_prov = self.circ.time_provider.clone();

        let memquota = StreamAccount::new(self.circ.mq_account())?;
        let (sender, receiver) = stream_queue(
            #[cfg(not(feature = "flowctl-cc"))]
            STREAM_READER_BUFFER,
            &memquota,
            &time_prov,
        )?;
        let (tx, rx) = oneshot::channel();
        let (msg_tx, msg_rx) =
            MpscSpec::new(CIRCUIT_BUFFER_SIZE).new_mq(time_prov, memquota.as_raw_account())?;

        let (rate_limit_tx, rate_limit_rx) = watch::channel_with(StreamRateLimit::MAX);

        // A channel for the reactor to request a new drain rate from the reader.
        // Typically this notification will be sent after an XOFF is sent so that the reader can
        // send us a new drain rate when the stream data queue becomes empty.
        let mut drain_rate_request_tx = NotifySender::new_typed();
        let drain_rate_request_rx = drain_rate_request_tx.subscribe();

        self.circ
            .control
            .unbounded_send(CtrlMsg::BeginStream {
                hop,
                message: begin_msg,
                sender,
                rx: msg_rx,
                rate_limit_notifier: rate_limit_tx,
                drain_rate_requester: drain_rate_request_tx,
                done: tx,
                cmd_checker,
            })
            .map_err(|_| Error::CircuitClosed)?;

        let (stream_id, hop, relay_cell_format) = rx.await.map_err(|_| Error::CircuitClosed)??;

        let target = StreamTarget {
            tunnel: self.clone(),
            tx: msg_tx,
            hop,
            stream_id,
            relay_cell_format,
            rate_limit_stream: rate_limit_rx,
        };

        // can be used to build a reader that supports XON/XOFF flow control
        let xon_xoff_reader_ctrl = XonXoffReaderCtrl::new(drain_rate_request_rx, target.clone());

        let stream_receiver = StreamReceiver {
            target: target.clone(),
            receiver,
            recv_window: StreamRecvWindow::new(RECV_WINDOW_INIT),
            ended: false,
        };

        let components = StreamComponents {
            stream_receiver,
            target,
            memquota,
            xon_xoff_reader_ctrl,
        };

        Ok(components)
    }

    /// Start a DataStream (anonymized connection) to the given
    /// address and port, using a BEGIN cell.
    async fn begin_data_stream(
        self: &Arc<Self>,
        msg: AnyRelayMsg,
        optimistic: bool,
    ) -> Result<DataStream> {
        let components = self
            .begin_stream_impl(msg, DataCmdChecker::new_any())
            .await?;

        let StreamComponents {
            stream_receiver,
            target,
            memquota,
            xon_xoff_reader_ctrl,
        } = components;

        let mut stream = DataStream::new(
            self.circ.time_provider.clone(),
            stream_receiver,
            xon_xoff_reader_ctrl,
            target,
            memquota,
        );
        if !optimistic {
            stream.wait_for_connection().await?;
        }
        Ok(stream)
    }

    /// Single and multi path helper.
    ///
    /// Start a stream to the given address and port, using a BEGIN
    /// cell.
    ///
    /// The use of a string for the address is intentional: you should let
    /// the remote Tor relay do the hostname lookup for you.
    pub async fn begin_stream(
        self: &Arc<Self>,
        target: &str,
        port: u16,
        parameters: Option<StreamParameters>,
    ) -> Result<DataStream> {
        let parameters = parameters.unwrap_or_default();
        let begin_flags = parameters.begin_flags();
        let optimistic = parameters.is_optimistic();
        let target = if parameters.suppressing_hostname() {
            ""
        } else {
            target
        };
        let beginmsg = Begin::new(target, port, begin_flags)
            .map_err(|e| Error::from_cell_enc(e, "begin message"))?;
        self.begin_data_stream(beginmsg.into(), optimistic).await
    }

    /// Start a new stream to the last relay in the tunnel, using
    /// a BEGIN_DIR cell.
    pub async fn begin_dir_stream(self: Arc<Self>) -> Result<DataStream> {
        // Note that we always open begindir connections optimistically.
        // Since they are local to a relay that we've already authenticated
        // with and built a tunnel to, there should be no additional checks
        // we need to perform to see whether the BEGINDIR will succeed.
        self.begin_data_stream(AnyRelayMsg::BeginDir(Default::default()), true)
            .await
    }

    /// Perform a DNS lookup, using a RESOLVE cell with the last relay
    /// in this tunnel.
    ///
    /// Note that this function does not check for timeouts; that's
    /// the caller's responsibility.
    pub async fn resolve(self: &Arc<Self>, hostname: &str) -> Result<Vec<IpAddr>> {
        let resolve_msg = Resolve::new(hostname);

        let resolved_msg = self.try_resolve(resolve_msg).await?;

        resolved_msg
            .into_answers()
            .into_iter()
            .filter_map(|(val, _)| match resolvedval_to_result(val) {
                Ok(ResolvedVal::Ip(ip)) => Some(Ok(ip)),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .collect()
    }

    /// Perform a reverse DNS lookup, by sending a RESOLVE cell with
    /// the last relay on this tunnel.
    ///
    /// Note that this function does not check for timeouts; that's
    /// the caller's responsibility.
    pub async fn resolve_ptr(self: &Arc<Self>, addr: IpAddr) -> Result<Vec<String>> {
        let resolve_ptr_msg = Resolve::new_reverse(&addr);

        let resolved_msg = self.try_resolve(resolve_ptr_msg).await?;

        resolved_msg
            .into_answers()
            .into_iter()
            .filter_map(|(val, _)| match resolvedval_to_result(val) {
                Ok(ResolvedVal::Hostname(v)) => Some(
                    String::from_utf8(v)
                        .map_err(|_| Error::StreamProto("Resolved Hostname was not utf-8".into())),
                ),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .collect()
    }

    /// Send an ad-hoc message to a given hop on the circuit, without expecting
    /// a reply.
    ///
    /// (If you want to handle one or more possible replies, see
    /// [`ClientTunnel::start_conversation`].)
    // TODO(conflux): Change this to use the ReactorHandle for the control commands.
    #[cfg(feature = "send-control-msg")]
    pub async fn send_raw_msg(
        &self,
        msg: tor_cell::relaycell::msg::AnyRelayMsg,
        hop: TargetHop,
    ) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        let ctrl_msg = CtrlMsg::SendMsg { hop, msg, sender };
        self.circ
            .control
            .unbounded_send(ctrl_msg)
            .map_err(|_| Error::CircuitClosed)?;

        receiver.await.map_err(|_| Error::CircuitClosed)?
    }

    /// Start an ad-hoc protocol exchange to the specified hop on this tunnel.
    ///
    /// To use this:
    ///
    ///  0. Create an inter-task channel you'll use to receive
    ///     the outcome of your conversation,
    ///     and bundle it into a [`UserMsgHandler`].
    ///
    ///  1. Call `start_conversation`.
    ///     This will install a your handler, for incoming messages,
    ///     and send the outgoing message (if you provided one).
    ///     After that, each message on the circuit
    ///     that isn't handled by the core machinery
    ///     is passed to your provided `reply_handler`.
    ///
    ///  2. Possibly call `send_msg` on the [`Conversation`],
    ///     from the call site of `start_conversation`,
    ///     possibly multiple times, from time to time,
    ///     to send further desired messages to the peer.
    ///
    ///  3. In your [`UserMsgHandler`], process the incoming messages.
    ///     You may respond by
    ///     sending additional messages
    ///     When the protocol exchange is finished,
    ///     `UserMsgHandler::handle_msg` should return
    ///     [`ConversationFinished`](reactor::MetaCellDisposition::ConversationFinished).
    ///
    /// If you don't need the `Conversation` to send followup messages,
    /// you may simply drop it,
    /// and rely on the responses you get from your handler,
    /// on the channel from step 0 above.
    /// Your handler will remain installed and able to process incoming messages
    /// until it returns `ConversationFinished`.
    ///
    /// (If you don't want to accept any replies at all, it may be
    /// simpler to use [`ClientTunnel::send_raw_msg`].)
    ///
    /// Note that it is quite possible to use this function to violate the tor
    /// protocol; most users of this API will not need to call it.  It is used
    /// to implement most of the onion service handshake.
    ///
    /// # Limitations
    ///
    /// Only one conversation may be active at any one time,
    /// for any one circuit.
    /// This generally means that this function should not be called
    /// on a tunnel which might be shared with anyone else.
    ///
    /// Likewise, it is forbidden to try to extend the tunnel,
    /// while the conversation is in progress.
    ///
    /// After the conversation has finished, the tunnel may be extended.
    /// Or, `start_conversation` may be called again;
    /// but, in that case there will be a gap between the two conversations,
    /// during which no `UserMsgHandler` is installed,
    /// and unexpected incoming messages would close the tunnel.
    ///
    /// If these restrictions are violated, the tunnel will be closed with an error.
    ///
    /// ## Precise definition of the lifetime of a conversation
    ///
    /// A conversation is in progress from entry to `start_conversation`,
    /// until entry to the body of the [`UserMsgHandler::handle_msg`](MsgHandler::handle_msg)
    /// call which returns [`ConversationFinished`](reactor::MetaCellDisposition::ConversationFinished).
    /// (*Entry* since `handle_msg` is synchronously embedded
    /// into the incoming message processing.)
    /// So you may start a new conversation as soon as you have the final response
    /// via your inter-task channel from (0) above.
    ///
    /// The lifetime relationship of the [`Conversation`],
    /// vs the handler returning `ConversationFinished`
    /// is not enforced by the type system.
    // Doing so without still leaving plenty of scope for runtime errors doesn't seem possible,
    // at least while allowing sending followup messages from outside the handler.
    #[cfg(feature = "send-control-msg")]
    pub async fn start_conversation(
        &self,
        msg: Option<tor_cell::relaycell::msg::AnyRelayMsg>,
        reply_handler: impl MsgHandler + Send + 'static,
        hop: TargetHop,
    ) -> Result<Conversation<'_>> {
        // We need to resolve the TargetHop into a precise HopLocation so our msg handler can match
        // the right Leg/Hop with inbound cell.
        let (sender, receiver) = oneshot::channel();
        self.circ
            .command
            .unbounded_send(CtrlCmd::ResolveTargetHop { hop, done: sender })
            .map_err(|_| Error::CircuitClosed)?;
        let hop_location = receiver.await.map_err(|_| Error::CircuitClosed)??;
        let handler = Box::new(UserMsgHandler::new(hop_location, reply_handler));
        let conversation = Conversation(self);
        conversation.send_internal(msg, Some(handler)).await?;
        Ok(conversation)
    }

    /// Shut down this tunnel, along with all streams that are using it. Happens asynchronously
    /// (i.e. the tunnel won't necessarily be done shutting down immediately after this function
    /// returns!).
    ///
    /// Note that other references to this tunnel may exist. If they do, they will stop working
    /// after you call this function.
    ///
    /// It's not necessary to call this method if you're just done with a tunnel: the tunnel should
    /// close on its own once nothing is using it any more.
    // TODO(conflux): This should use the ReactorHandle instead.
    pub fn terminate(&self) {
        let _ = self.circ.command.unbounded_send(CtrlCmd::Shutdown);
    }

    /// Helper: Send the resolve message, and read resolved message from
    /// resolve stream.
    async fn try_resolve(self: &Arc<Self>, msg: Resolve) -> Result<Resolved> {
        let components = self
            .begin_stream_impl(msg.into(), ResolveCmdChecker::new_any())
            .await?;

        let StreamComponents {
            stream_receiver,
            target: _,
            memquota,
            xon_xoff_reader_ctrl: _,
        } = components;

        let mut resolve_stream = ResolveStream::new(stream_receiver, memquota);
        resolve_stream.read_msg().await
    }

    // TODO(conflux)
}

// TODO(conflux): We will likely need to enforce some invariants here, for example that the `circ`
// has the expected (non-zero) number of hops.
impl TryFrom<ClientCirc> for ClientTunnel {
    type Error = Error;

    fn try_from(circ: ClientCirc) -> std::result::Result<Self, Self::Error> {
        Ok(Self { circ })
    }
}

/// A collection of components that can be combined to implement a Tor stream,
/// or anything that requires a stream ID.
///
/// Not all components may be needed, depending on the purpose of the "stream".
/// For example we build `RELAY_RESOLVE` requests like we do data streams,
/// but they won't use the `StreamTarget` as they don't need to send additional
/// messages.
#[derive(Debug)]
pub(crate) struct StreamComponents {
    /// A [`Stream`](futures::Stream) of incoming relay messages for this Tor stream.
    pub(crate) stream_receiver: StreamReceiver,
    /// A handle that can communicate messages to the circuit reactor for this stream.
    pub(crate) target: StreamTarget,
    /// The memquota [account](tor_memquota::Account) to use for data on this stream.
    pub(crate) memquota: StreamAccount,
    /// The control information needed to add XON/XOFF flow control to the stream.
    pub(crate) xon_xoff_reader_ctrl: XonXoffReaderCtrl,
}

/// Convert a [`ResolvedVal`] into a Result, based on whether or not
/// it represents an error.
fn resolvedval_to_result(val: ResolvedVal) -> Result<ResolvedVal> {
    match val {
        ResolvedVal::TransientError => Err(Error::ResolveError(ResolveError::Transient)),
        ResolvedVal::NontransientError => Err(Error::ResolveError(ResolveError::Nontransient)),
        ResolvedVal::Unrecognized(_, _) => Err(Error::ResolveError(ResolveError::Unrecognized)),
        _ => Ok(val),
    }
}

/// A precise position in a tunnel.
#[derive(Debug, Deftly, Copy, Clone, PartialEq, Eq)]
#[derive_deftly(HasMemoryCost)]
#[non_exhaustive]
pub enum HopLocation {
    /// A specific position in a tunnel.
    Hop((UniqId, HopNum)),
    /// The join point of a multi-path tunnel.
    JoinPoint,
}

/// A position in a tunnel.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetHop {
    /// A specific position in a tunnel.
    Hop(HopLocation),
    /// The last hop of a tunnel.
    ///
    /// This should be used only when you don't care about what specific hop is used.
    /// Some tunnels may be extended or truncated,
    /// which means that the "last hop" may change at any time.
    LastHop,
}

impl From<(UniqId, HopNum)> for HopLocation {
    fn from(v: (UniqId, HopNum)) -> Self {
        HopLocation::Hop(v)
    }
}

impl From<(UniqId, HopNum)> for TargetHop {
    fn from(v: (UniqId, HopNum)) -> Self {
        TargetHop::Hop(v.into())
    }
}

impl HopLocation {
    /// Return the hop number if not a JointPoint.
    pub fn hop_num(&self) -> Option<HopNum> {
        match self {
            Self::Hop((_, hop_num)) => Some(*hop_num),
            Self::JoinPoint => None,
        }
    }
}

/// Internal handle, used to implement a stream on a particular tunnel.
///
/// The reader and the writer for a stream should hold a `StreamTarget` for the stream;
/// the reader should additionally hold an `mpsc::Receiver` to get
/// relay messages for the stream.
///
/// When all the `StreamTarget`s for a stream are dropped, the Reactor will
/// close the stream by sending an END message to the other side.
/// You can close a stream earlier by using [`StreamTarget::close`]
/// or [`StreamTarget::close_pending`].
#[derive(Clone, Debug)]
pub(crate) struct StreamTarget {
    /// Which hop of the circuit this stream is with.
    hop: HopLocation,
    /// Reactor ID for this stream.
    stream_id: StreamId,
    /// Encoding to use for relay cells sent on this stream.
    ///
    /// This is mostly irrelevant, except when deciding
    /// how many bytes we can pack in a DATA message.
    relay_cell_format: RelayCellFormat,
    /// A [`Stream`](futures::Stream) that provides updates to the rate limit for sending data.
    // TODO(arti#2068): we should consider making this an `Option`
    rate_limit_stream: watch::Receiver<StreamRateLimit>,
    /// Channel to send cells down.
    tx: StreamMpscSender<AnyRelayMsg>,
    /// Reference to the tunnel that this stream is on.
    tunnel: Arc<ClientTunnel>,
}

impl StreamTarget {
    /// Deliver a relay message for the stream that owns this StreamTarget.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    pub(crate) async fn send(&mut self, msg: AnyRelayMsg) -> Result<()> {
        self.tx.send(msg).await.map_err(|_| Error::CircuitClosed)?;
        Ok(())
    }

    /// Close the pending stream that owns this StreamTarget, delivering the specified
    /// END message (if any)
    ///
    /// The stream is closed by sending a [`CtrlMsg::ClosePendingStream`] message to the reactor.
    ///
    /// Returns a [`oneshot::Receiver`] that can be used to await the reactor's response.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    ///
    /// Note that in many cases, the actual contents of an END message can leak unwanted
    /// information. Please consider carefully before sending anything but an
    /// [`End::new_misc()`](tor_cell::relaycell::msg::End::new_misc) message over a `ClientTunnel`.
    /// (For onion services, we send [`DONE`](tor_cell::relaycell::msg::EndReason::DONE) )
    ///
    /// In addition to sending the END message, this function also ensures
    /// the state of the stream map entry of this stream is updated
    /// accordingly.
    ///
    /// Normally, you shouldn't need to call this function, as streams are implicitly closed by the
    /// reactor when their corresponding `StreamTarget` is dropped. The only valid use of this
    /// function is for closing pending incoming streams (a stream is said to be pending if we have
    /// received the message initiating the stream but have not responded to it yet).
    ///
    /// **NOTE**: This function should be called at most once per request.
    /// Calling it twice is an error.
    #[cfg(feature = "hs-service")]
    pub(crate) fn close_pending(
        &self,
        message: reactor::CloseStreamBehavior,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        let (tx, rx) = oneshot::channel();

        self.tunnel
            .circ
            .control
            .unbounded_send(CtrlMsg::ClosePendingStream {
                stream_id: self.stream_id,
                hop: self.hop,
                message,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        Ok(rx)
    }

    /// Queue a "close" for the stream corresponding to this StreamTarget.
    ///
    /// Unlike `close_pending`, this method does not allow the caller to provide an `END` message.
    ///
    /// Once this method has been called, no more messages may be sent with [`StreamTarget::send`],
    /// on this `StreamTarget`` or any clone of it.
    /// The reactor *will* try to flush any already-send messages before it closes the stream.
    ///
    /// You don't need to call this method if the stream is closing because all of its StreamTargets
    /// have been dropped.
    pub(crate) fn close(&mut self) {
        Pin::new(&mut self.tx).close_channel();
    }

    /// Called when a circuit-level protocol error has occurred and the
    /// tunnel needs to shut down.
    pub(crate) fn protocol_error(&mut self) {
        self.tunnel.terminate();
    }

    /// Request to send a SENDME cell for this stream.
    ///
    /// This sends a request to the circuit reactor to send a stream-level SENDME, but it does not
    /// block or wait for a response from the circuit reactor.
    /// An error is only returned if we are unable to send the request.
    /// This means that if the circuit reactor is unable to send the SENDME, we are not notified of
    /// this here and an error will not be returned.
    pub(crate) fn send_sendme(&mut self) -> Result<()> {
        self.tunnel
            .circ
            .control
            .unbounded_send(CtrlMsg::FlowCtrlUpdate {
                msg: FlowCtrlMsg::Sendme,
                stream_id: self.stream_id,
                hop: self.hop,
            })
            .map_err(|_| Error::CircuitClosed)
    }

    /// Inform the circuit reactor that there has been a change in the drain rate for this stream.
    ///
    /// Typically the circuit reactor would send this new rate in an XON message to the other end of
    /// the stream.
    /// But it may decide not to, and may discard this update.
    /// For example the stream may have a large amount of buffered data, and the reactor may not
    /// want to send an XON while the buffer is large.
    ///
    /// This sends a message to inform the circuit reactor of the new drain rate,
    /// but it does not block or wait for a response from the reactor.
    /// An error is only returned if we are unable to send the update.
    pub(crate) fn drain_rate_update(&mut self, rate: XonKbpsEwma) -> Result<()> {
        self.tunnel
            .circ
            .control
            .unbounded_send(CtrlMsg::FlowCtrlUpdate {
                msg: FlowCtrlMsg::Xon(rate),
                stream_id: self.stream_id,
                hop: self.hop,
            })
            .map_err(|_| Error::CircuitClosed)
    }

    /// Return a reference to the tunnel that this `StreamTarget` is using.
    #[cfg(any(feature = "experimental-api", feature = "stream-ctrl"))]
    pub(crate) fn tunnel(&self) -> &Arc<ClientTunnel> {
        &self.tunnel
    }

    /// Return the kind of relay cell in use on this `StreamTarget`.
    pub(crate) fn relay_cell_format(&self) -> RelayCellFormat {
        self.relay_cell_format
    }

    /// A [`Stream`](futures::Stream) that provides updates to the rate limit for sending data.
    pub(crate) fn rate_limit_stream(&self) -> &watch::Receiver<StreamRateLimit> {
        &self.rate_limit_stream
    }
}
