//! Module providing [`CtrlMsg`].

use super::circuit::extender::CircuitExtender;
use super::{
    CircuitHandshake, CloseStreamBehavior, MetaCellHandler, Reactor, ReactorResultChannel,
    RunOnceCmdInner, SendRelayCell,
};
use crate::Result;
use crate::circuit::celltypes::CreateResponse;
use crate::circuit::circhop::HopSettings;
#[cfg(feature = "circ-padding-manual")]
use crate::client::circuit::padding;
use crate::client::circuit::path;
use crate::client::reactor::{NoJoinPointError, NtorClient, ReactorError};
use crate::client::{HopLocation, TargetHop};
use crate::crypto::binding::CircuitBinding;
use crate::crypto::cell::{InboundClientLayer, OutboundClientLayer};
use crate::crypto::handshake::ntor_v3::{NtorV3Client, NtorV3PublicKey};
use crate::stream::cmdcheck::AnyCmdChecker;
use crate::stream::flow_ctrl::state::StreamRateLimit;
use crate::stream::flow_ctrl::xon_xoff::reader::DrainRateRequest;
use crate::stream::queue::StreamQueueSender;
use crate::streammap;
use crate::util::notify::NotifySender;
use crate::util::skew::ClockSkew;
use crate::util::tunnel_activity::TunnelActivity;
#[cfg(test)]
use crate::{circuit::UniqId, client::circuit::CircParameters, crypto::cell::HopNum};
use postage::watch;
use tor_cell::chancell::msg::HandshakeType;
use tor_cell::relaycell::flow_ctrl::XonKbpsEwma;
use tor_cell::relaycell::msg::{AnyRelayMsg, Sendme};
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCellFormat, StreamId};
use tor_error::{Bug, bad_api_usage, internal, into_bad_api_usage};
use tracing::{debug, trace};
#[cfg(feature = "hs-service")]
use {
    crate::client::reactor::IncomingStreamRequestHandler,
    crate::client::stream::IncomingStreamRequestFilter, crate::stream::incoming::StreamReqSender,
};

#[cfg(test)]
use tor_cell::relaycell::msg::SendmeTag;

#[cfg(feature = "conflux")]
use super::{Circuit, ConfluxLinkResultChannel};

use oneshot_fused_workaround as oneshot;

use crate::crypto::handshake::ntor::NtorPublicKey;
use crate::stream::StreamMpscReceiver;
use tor_linkspec::{EncodedLinkSpec, OwnedChanTarget};

use std::result::Result as StdResult;

/// A message telling the reactor to do something.
///
/// For each `CtrlMsg`, the reactor will send a cell on the underlying channel.
///
/// The difference between this and [`CtrlCmd`] is that `CtrlMsg`s
/// cause the reactor to send cells on the reactor's `chan_sender`,
/// whereas `CtrlCmd` do not.
#[derive(educe::Educe)]
#[educe(Debug)]
pub(crate) enum CtrlMsg {
    /// Create the first hop of this circuit.
    Create {
        /// A oneshot channel on which we'll receive the creation response.
        recv_created: oneshot::Receiver<CreateResponse>,
        /// The handshake type to use for the first hop.
        handshake: CircuitHandshake,
        /// Other parameters relevant for circuit creation.
        settings: HopSettings,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Extend a circuit by one hop, using the ntor handshake.
    ExtendNtor {
        /// The peer that we're extending to.
        ///
        /// Used to extend our record of the circuit's path.
        peer_id: OwnedChanTarget,
        /// The handshake type to use for this hop.
        public_key: NtorPublicKey,
        /// Information about how to connect to the relay we're extending to.
        linkspecs: Vec<EncodedLinkSpec>,
        /// Other parameters we are negotiating.
        settings: HopSettings,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Extend a circuit by one hop, using the ntorv3 handshake.
    ExtendNtorV3 {
        /// The peer that we're extending to.
        ///
        /// Used to extend our record of the circuit's path.
        peer_id: OwnedChanTarget,
        /// The handshake type to use for this hop.
        public_key: NtorV3PublicKey,
        /// Information about how to connect to the relay we're extending to.
        linkspecs: Vec<EncodedLinkSpec>,
        /// Other parameters we are negotiating.
        settings: HopSettings,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Begin a stream with the provided hop in this circuit.
    ///
    /// Allocates a stream ID, and sends the provided message to that hop.
    BeginStream {
        /// The hop number to begin the stream with.
        hop: TargetHop,
        /// The message to send.
        message: AnyRelayMsg,
        /// A channel to send messages on this stream down.
        ///
        /// This sender shouldn't ever block, because we use congestion control and only send
        /// SENDME cells once we've read enough out of the other end. If it *does* block, we
        /// can assume someone is trying to send us more cells than they should, and abort
        /// the stream.
        sender: StreamQueueSender,
        /// A channel to receive messages to send on this stream from.
        rx: StreamMpscReceiver<AnyRelayMsg>,
        /// A [`Stream`](futures::Stream) that provides updates to the rate limit for sending data.
        rate_limit_notifier: watch::Sender<StreamRateLimit>,
        /// Notifies the stream reader when it should send a new drain rate.
        drain_rate_requester: NotifySender<DrainRateRequest>,
        /// Oneshot channel to notify on completion, with the allocated stream ID.
        done: ReactorResultChannel<(StreamId, HopLocation, RelayCellFormat)>,
        /// A `CmdChecker` to keep track of which message types are acceptable.
        cmd_checker: AnyCmdChecker,
    },
    /// Close the specified pending incoming stream, sending the provided END message.
    ///
    /// A stream is said to be pending if the message for initiating the stream was received but
    /// not has not been responded to yet.
    ///
    /// This should be used by responders for closing pending incoming streams initiated by the
    /// other party on the circuit.
    #[cfg(feature = "hs-service")]
    ClosePendingStream {
        /// The hop number the stream is on.
        hop: HopLocation,
        /// The stream ID to send the END for.
        stream_id: StreamId,
        /// The END message to send, if any.
        message: CloseStreamBehavior,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Send a given control message on this circuit.
    #[cfg(feature = "send-control-msg")]
    SendMsg {
        /// The hop to receive this message.
        hop: TargetHop,
        /// The message to send.
        msg: AnyRelayMsg,
        /// A sender that we use to tell the caller that the message was sent
        /// and the handler installed.
        sender: oneshot::Sender<Result<()>>,
    },
    /// Send a given control message on this circuit, and install a control-message handler to
    /// receive responses.
    #[cfg(feature = "send-control-msg")]
    SendMsgAndInstallHandler {
        /// The message to send, if any
        msg: Option<AnyRelayMsgOuter>,
        /// A message handler to install.
        ///
        /// If this is `None`, there must already be a message handler installed
        #[educe(Debug(ignore))]
        handler: Option<Box<dyn MetaCellHandler + Send + 'static>>,
        /// A sender that we use to tell the caller that the message was sent
        /// and the handler installed.
        sender: oneshot::Sender<Result<()>>,
    },
    /// Inform the reactor that there's a flow control update for a given stream.
    ///
    /// The reactor will decide how to handle this update depending on the type of flow control and
    /// the current state of the stream.
    FlowCtrlUpdate {
        /// The type of flow control update, and any associated metadata.
        msg: FlowCtrlMsg,
        /// The stream ID that the update is for.
        stream_id: StreamId,
        /// The hop that the stream is on.
        hop: HopLocation,
    },
    /// Get the clock skew claimed by the first hop of the circuit.
    FirstHopClockSkew {
        /// Oneshot channel to return the clock skew.
        answer: oneshot::Sender<StdResult<ClockSkew, Bug>>,
    },
    /// Link the specified circuits into the current tunnel,
    /// to form a multi-path tunnel.
    #[cfg(feature = "conflux")]
    #[allow(unused)] // TODO(conflux)
    LinkCircuits {
        /// The circuits to link into the tunnel,
        #[educe(Debug(ignore))]
        circuits: Vec<Circuit>,
        /// Oneshot channel to notify sender when all the specified circuits have finished linking,
        /// or have failed to link.
        ///
        /// A client circuit is said to be fully linked once the `RELAY_CONFLUX_LINKED_ACK` is sent
        /// (see [set construction]).
        ///
        /// [set construction]: https://spec.torproject.org/proposals/329-traffic-splitting.html#set-construction
        answer: ConfluxLinkResultChannel,
    },
}

/// A message telling the reactor to do something.
///
/// The difference between this and [`CtrlMsg`] is that `CtrlCmd`s
/// never cause cells to sent on the channel,
/// while `CtrlMsg`s potentially do: `CtrlMsg`s are mapped to [`RunOnceCmdInner`] commands,
/// some of which instruct the reactor to send cells down the channel.
#[derive(educe::Educe)]
#[educe(Debug)]
pub(crate) enum CtrlCmd {
    /// Shut down the reactor.
    Shutdown,
    /// Extend the circuit by one hop, in response to an out-of-band handshake.
    ///
    /// (This is used for onion services, where the negotiation takes place in
    /// INTRODUCE and RENDEZVOUS messages.)
    #[cfg(feature = "hs-common")]
    ExtendVirtual {
        /// The cryptographic algorithms and keys to use when communicating with
        /// the newly added hop.
        #[educe(Debug(ignore))]
        cell_crypto: (
            Box<dyn OutboundClientLayer + Send>,
            Box<dyn InboundClientLayer + Send>,
            Option<CircuitBinding>,
        ),
        /// A set of parameters to negotiate with this hop.
        settings: HopSettings,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Resolve a given [`TargetHop`] into a precise [`HopLocation`].
    ResolveTargetHop {
        /// The target hop to resolve.
        hop: TargetHop,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<HopLocation>,
    },
    /// Begin accepting streams on this circuit.
    #[cfg(feature = "hs-service")]
    AwaitStreamRequest {
        /// A channel for sending information about an incoming stream request.
        incoming_sender: StreamReqSender,
        /// A `CmdChecker` to keep track of which message types are acceptable.
        cmd_checker: AnyCmdChecker,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
        /// The hop that is allowed to create streams.
        hop: TargetHop,
        /// A filter used to check requests before passing them on.
        #[educe(Debug(ignore))]
        #[cfg(feature = "hs-service")]
        filter: Box<dyn IncomingStreamRequestFilter>,
    },
    /// Request the binding key of a target hop.
    #[cfg(feature = "hs-service")]
    GetBindingKey {
        /// The hop for which we want the key.
        hop: TargetHop,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<Option<CircuitBinding>>,
    },
    /// (tests only) Add a hop to the list of hops on this circuit, with dummy cryptography.
    #[cfg(test)]
    AddFakeHop {
        relay_cell_format: RelayCellFormat,
        fwd_lasthop: bool,
        rev_lasthop: bool,
        peer_id: path::HopDetail,
        params: CircParameters,
        done: ReactorResultChannel<()>,
    },
    /// (tests only) Get the send window and expected tags for a given hop.
    #[cfg(test)]
    QuerySendWindow {
        hop: HopNum,
        leg: UniqId,
        done: ReactorResultChannel<(u32, Vec<SendmeTag>)>,
    },
    /// Shut down the reactor, and return the underlying [`Circuit`],
    /// if the tunnel is not multi-path.
    ///
    /// Returns an error if called on a multi-path reactor.
    #[cfg(feature = "conflux")]
    #[allow(unused)] // TODO(conflux)
    ShutdownAndReturnCircuit {
        /// Oneshot channel to return the underlying [`Circuit`],
        /// or an error if the reactor's tunnel is multi-path.
        answer: oneshot::Sender<StdResult<Circuit, Bug>>,
    },

    /// Install or remove a [`padding::CircuitPadder`] for a given hop.
    ///
    /// Any existing `CircuitPadder` at that hop is replaced.
    #[cfg(feature = "circ-padding-manual")]
    SetPadder {
        /// The hop to modify.
        hop: HopLocation,
        /// The Padder to install, or None to remove any existing padder.
        padder: Option<padding::CircuitPadder>,
        /// A sender to alert after we've changed the padding.
        sender: oneshot::Sender<Result<()>>,
    },

    /// Yield the most active [`TunnelActivity`] for any hop on any leg of this tunnel.
    GetTunnelActivity {
        /// A sender to receive the reply.
        sender: oneshot::Sender<TunnelActivity>,
    },
}

/// A flow control update message.
#[derive(Debug)]
pub(crate) enum FlowCtrlMsg {
    /// Send a SENDME message on this stream.
    Sendme,
    /// Send an XON message on this stream with the given rate.
    Xon(XonKbpsEwma),
}

/// A control message handler object. Keep a reference to the Reactor tying its lifetime to it.
///
/// Its `handle_msg` and `handle_cmd` handlers decide how messages and commands,
/// respectively, are handled.
pub(crate) struct ControlHandler<'a> {
    /// Reference to the reactor of this
    reactor: &'a mut Reactor,
}

impl<'a> ControlHandler<'a> {
    /// Constructor.
    pub(crate) fn new(reactor: &'a mut Reactor) -> Self {
        Self { reactor }
    }

    /// Handle a control message.
    pub(super) fn handle_msg(&mut self, msg: CtrlMsg) -> Result<Option<RunOnceCmdInner>> {
        trace!(
            tunnel_id = %self.reactor.tunnel_id,
            msg = ?msg,
            "reactor received control message"
        );

        match msg {
            // This is handled earlier, since it requires blocking.
            CtrlMsg::Create { done, .. } => {
                if self.reactor.circuits.len() == 1 {
                    // This should've been handled in Reactor::run_once()
                    // (ControlHandler::handle_msg() is never called before wait_for_create()).
                    debug_assert!(self.reactor.circuits.single_leg()?.has_hops());
                    // Don't care if the receiver goes away
                    let _ = done.send(Err(tor_error::bad_api_usage!(
                        "cannot create first hop twice"
                    )
                    .into()));
                } else {
                    // Don't care if the receiver goes away
                    let _ = done.send(Err(tor_error::bad_api_usage!(
                        "cannot create first hop on multipath tunnel"
                    )
                    .into()));
                }

                Ok(None)
            }
            CtrlMsg::ExtendNtor {
                peer_id,
                public_key,
                linkspecs,
                settings,
                done,
            } => {
                let Ok(circ) = self.reactor.circuits.single_leg_mut() else {
                    // Don't care if the receiver goes away
                    let _ = done.send(Err(tor_error::bad_api_usage!(
                        "cannot extend multipath tunnel"
                    )
                    .into()));

                    return Ok(None);
                };

                let (extender, cell) = CircuitExtender::<NtorClient>::begin(
                    peer_id,
                    HandshakeType::NTOR,
                    &public_key,
                    linkspecs,
                    settings,
                    &(),
                    circ,
                    done,
                )?;
                self.reactor
                    .cell_handlers
                    .set_meta_handler(Box::new(extender))?;

                Ok(Some(RunOnceCmdInner::Send {
                    leg: circ.unique_id(),
                    cell,
                    done: None,
                }))
            }
            CtrlMsg::ExtendNtorV3 {
                peer_id,
                public_key,
                linkspecs,
                settings,
                done,
            } => {
                let Ok(circ) = self.reactor.circuits.single_leg_mut() else {
                    // Don't care if the receiver goes away
                    let _ = done.send(Err(tor_error::bad_api_usage!(
                        "cannot extend multipath tunnel"
                    )
                    .into()));

                    return Ok(None);
                };

                let client_extensions = settings.circuit_request_extensions()?;

                let (extender, cell) = CircuitExtender::<NtorV3Client>::begin(
                    peer_id,
                    HandshakeType::NTOR_V3,
                    &public_key,
                    linkspecs,
                    settings,
                    &client_extensions,
                    circ,
                    done,
                )?;
                self.reactor
                    .cell_handlers
                    .set_meta_handler(Box::new(extender))?;

                Ok(Some(RunOnceCmdInner::Send {
                    leg: circ.unique_id(),
                    cell,
                    done: None,
                }))
            }
            CtrlMsg::BeginStream {
                hop,
                message,
                sender,
                rx,
                rate_limit_notifier,
                drain_rate_requester,
                done,
                cmd_checker,
            } => {
                // If resolving the hop fails,
                // we want to report an error back to the initiator and not shut down the reactor.
                let hop_location = match self.reactor.resolve_target_hop(hop) {
                    Ok(x) => x,
                    Err(e) => {
                        let e = into_bad_api_usage!("Could not resolve {hop:?}")(e);
                        // don't care if receiver goes away
                        let _ = done.send(Err(e.into()));
                        return Ok(None);
                    }
                };
                let (leg_id, hop_num) = match self.reactor.resolve_hop_location(hop_location) {
                    Ok(x) => x,
                    Err(e) => {
                        let e = into_bad_api_usage!("Could not resolve {hop_location:?}")(e);
                        // don't care if receiver goes away
                        let _ = done.send(Err(e.into()));
                        return Ok(None);
                    }
                };
                let circ = match self.reactor.circuits.leg_mut(leg_id) {
                    Some(x) => x,
                    None => {
                        let e = bad_api_usage!("Circuit leg {leg_id:?} does not exist");
                        // don't care if receiver goes away
                        let _ = done.send(Err(e.into()));
                        return Ok(None);
                    }
                };

                let cell = circ.begin_stream(
                    hop_num,
                    message,
                    sender,
                    rx,
                    rate_limit_notifier,
                    drain_rate_requester,
                    cmd_checker,
                )?;
                Ok(Some(RunOnceCmdInner::BeginStream {
                    leg: leg_id,
                    cell,
                    hop: hop_location,
                    done,
                }))
            }
            #[cfg(feature = "hs-service")]
            CtrlMsg::ClosePendingStream {
                hop,
                stream_id,
                message,
                done,
            } => Ok(Some(RunOnceCmdInner::CloseStream {
                hop,
                sid: stream_id,
                behav: message,
                reason: streammap::TerminateReason::ExplicitEnd,
                done: Some(done),
            })),
            CtrlMsg::FlowCtrlUpdate {
                msg,
                stream_id,
                hop,
            } => {
                match msg {
                    FlowCtrlMsg::Sendme => {
                        let (leg_id, hop_num) = match self.reactor.resolve_hop_location(hop) {
                            Ok(x) => x,
                            Err(NoJoinPointError) => {
                                // A stream tried to send a stream-level SENDME message to the join point of
                                // a tunnel that has never had a join point. Currently in arti, only a
                                // `StreamTarget` asks us to send a stream-level SENDME, and this tunnel
                                // originally created the `StreamTarget` to begin with. So this is a
                                // legitimate bug somewhere in the tunnel code.
                                return Err(
                                    internal!(
                                        "Could not send a stream-level SENDME to a join point on a tunnel without a join point",
                                    )
                                    .into()
                                );
                            }
                        };

                        // Congestion control decides if we can send stream level SENDMEs or not.
                        let sendme_required = match self.reactor.uses_stream_sendme(leg_id, hop_num)
                        {
                            Some(x) => x,
                            None => {
                                // The leg/hop has disappeared. This is fine since the stream may have ended
                                // and been cleaned up while this `CtrlMsg::SendSendme` message was queued.
                                // It is possible that is a bug and this is an incorrect leg/hop number, but
                                // it's not currently possible to differentiate between an incorrect leg/hop
                                // number and a circuit hop that has been closed.
                                debug!(
                                    "Could not send a stream-level SENDME on a hop that does not exist. Ignoring."
                                );
                                return Ok(None);
                            }
                        };

                        if !sendme_required {
                            // Nothing to do, so discard the SENDME.
                            return Ok(None);
                        }

                        let sendme = Sendme::new_empty();
                        let cell = AnyRelayMsgOuter::new(Some(stream_id), sendme.into());

                        let cell = SendRelayCell {
                            hop: Some(hop_num),
                            early: false,
                            cell,
                        };

                        Ok(Some(RunOnceCmdInner::Send {
                            leg: leg_id,
                            cell,
                            done: None,
                        }))
                    }
                    FlowCtrlMsg::Xon(rate) => Ok(Some(RunOnceCmdInner::MaybeSendXon {
                        rate,
                        hop,
                        stream_id,
                    })),
                }
            }
            // TODO(conflux): this should specify which leg to send the msg on
            // (currently we send it down the primary leg).
            //
            // This will involve updating ClientCIrc::send_raw_msg() to take a
            // leg id argument (which is a breaking change.
            #[cfg(feature = "send-control-msg")]
            CtrlMsg::SendMsg { hop, msg, sender } => {
                let Some((leg_id, hop_num)) = self.reactor.target_hop_to_hopnum_id(hop) else {
                    // Don't care if receiver goes away
                    let _ = sender.send(Err(bad_api_usage!("Unknown {hop:?}").into()));
                    return Ok(None);
                };

                let cell = AnyRelayMsgOuter::new(None, msg);
                let cell = SendRelayCell {
                    hop: Some(hop_num),
                    early: false,
                    cell,
                };

                Ok(Some(RunOnceCmdInner::Send {
                    leg: leg_id,
                    cell,
                    done: Some(sender),
                }))
            }
            // TODO(conflux): this should specify which leg to send the msg on
            // (currently we send it down the primary leg)
            #[cfg(feature = "send-control-msg")]
            CtrlMsg::SendMsgAndInstallHandler {
                msg,
                handler,
                sender,
            } => Ok(Some(RunOnceCmdInner::SendMsgAndInstallHandler {
                msg,
                handler,
                done: sender,
            })),
            CtrlMsg::FirstHopClockSkew { answer } => {
                Ok(Some(RunOnceCmdInner::FirstHopClockSkew { answer }))
            }
            #[cfg(feature = "conflux")]
            CtrlMsg::LinkCircuits { circuits, answer } => {
                Ok(Some(RunOnceCmdInner::Link { circuits, answer }))
            }
        }
    }

    /// Handle a control command.
    #[allow(clippy::needless_pass_by_value)] // Needed when conflux is enabled
    pub(super) fn handle_cmd(&mut self, msg: CtrlCmd) -> StdResult<(), ReactorError> {
        trace!(
            tunnel_id = %self.reactor.tunnel_id,
            msg = ?msg,
            "reactor received control command"
        );

        match msg {
            CtrlCmd::Shutdown => self.reactor.handle_shutdown().map(|_| ()),
            #[cfg(feature = "hs-common")]
            #[allow(unreachable_code)]
            CtrlCmd::ExtendVirtual {
                cell_crypto,
                settings,
                done,
            } => {
                let (outbound, inbound, binding) = cell_crypto;

                // TODO HS: Perhaps this should describe the onion service, or
                // describe why the virtual hop was added, or something?
                let peer_id = path::HopDetail::Virtual;

                let Ok(leg) = self.reactor.circuits.single_leg_mut() else {
                    // Don't care if the receiver goes away
                    let _ = done.send(Err(tor_error::bad_api_usage!(
                        "cannot extend multipath tunnel"
                    )
                    .into()));

                    return Ok(());
                };

                leg.add_hop(peer_id, outbound, inbound, binding, &settings)?;
                let _ = done.send(Ok(()));

                Ok(())
            }
            CtrlCmd::ResolveTargetHop { hop, done } => {
                let _ = done.send(
                    self.reactor
                        .resolve_target_hop(hop)
                        .map_err(|_| crate::util::err::Error::NoSuchHop),
                );
                Ok(())
            }
            #[cfg(feature = "hs-service")]
            CtrlCmd::AwaitStreamRequest {
                cmd_checker,
                incoming_sender,
                hop,
                done,
                filter,
            } => {
                let Some((_, hop_num)) = self.reactor.target_hop_to_hopnum_id(hop) else {
                    let _ = done.send(Err(crate::Error::NoSuchHop));
                    return Ok(());
                };
                // TODO: At some point we might want to add a CtrlCmd for
                // de-registering the handler.  See comments on `allow_stream_requests`.
                let handler = IncomingStreamRequestHandler {
                    incoming_sender,
                    cmd_checker,
                    hop_num: Some(hop_num),
                    filter,
                };

                let ret = self
                    .reactor
                    .cell_handlers
                    .set_incoming_stream_req_handler(handler);
                let _ = done.send(ret); // don't care if the corresponding receiver goes away.

                Ok(())
            }
            #[cfg(feature = "hs-service")]
            CtrlCmd::GetBindingKey { hop, done } => {
                let Some((leg_id, hop_num)) = self.reactor.target_hop_to_hopnum_id(hop) else {
                    let _ = done.send(Err(tor_error::internal!(
                        "Unknown TargetHop when getting binding key"
                    )
                    .into()));
                    return Ok(());
                };
                let Some(circuit) = self.reactor.circuits.leg(leg_id) else {
                    let _ = done.send(Err(tor_error::bad_api_usage!(
                        "Unknown circuit id {leg_id} when getting binding key"
                    )
                    .into()));
                    return Ok(());
                };
                // Get the binding key from the mutable state and send it back.
                let key = circuit.mutable().binding_key(hop_num);
                let _ = done.send(Ok(key));

                Ok(())
            }
            #[cfg(test)]
            CtrlCmd::AddFakeHop {
                relay_cell_format,
                fwd_lasthop,
                rev_lasthop,
                peer_id,
                params,
                done,
            } => {
                let Ok(leg) = self.reactor.circuits.single_leg_mut() else {
                    // Don't care if the receiver goes away
                    let _ = done.send(Err(tor_error::bad_api_usage!(
                        "cannot add fake hop to multipath tunnel"
                    )
                    .into()));

                    return Ok(());
                };

                leg.handle_add_fake_hop(
                    relay_cell_format,
                    fwd_lasthop,
                    rev_lasthop,
                    peer_id,
                    &params,
                    done,
                );

                Ok(())
            }
            #[cfg(test)]
            CtrlCmd::QuerySendWindow { hop, leg, done } => {
                // Immediately invoked function means that errors will be sent to the channel.
                let _ = done.send((|| {
                    let leg = self.reactor.circuits.leg_mut(leg).ok_or_else(|| {
                        bad_api_usage!("cannot query send window of non-existent circuit")
                    })?;

                    let hop = leg.hop_mut(hop).ok_or(bad_api_usage!(
                        "received QuerySendWindow for unknown hop {}",
                        hop.display()
                    ))?;

                    Ok(hop.send_window_and_expected_tags())
                })());

                Ok(())
            }
            #[cfg(feature = "conflux")]
            CtrlCmd::ShutdownAndReturnCircuit { answer } => {
                self.reactor.handle_shutdown_and_return_circuit(answer)
            }
            #[cfg(feature = "circ-padding-manual")]
            CtrlCmd::SetPadder {
                hop,
                padder,
                sender,
            } => {
                let result = self.reactor.set_padding_at_hop(hop, padder);
                let _ = sender.send(result);
                Ok(())
            }
            CtrlCmd::GetTunnelActivity { sender } => {
                let count = self.reactor.circuits.tunnel_activity();
                let _ = sender.send(count);
                Ok(())
            }
        }
    }
}
